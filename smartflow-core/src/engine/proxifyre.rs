use std::{
    collections::{hash_map::DefaultHasher, HashSet},
    hash::{Hash, Hasher},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use crate::{
    engine::{validate_clash_profile, DataPlaneBackend},
    model::{AppConfig, DataPlanePhase, DataPlaneStatus, LeakProtectionMode, Protocol, Rule},
    process::list_processes,
    routing_plan::compile_routing_plan,
};

const PROXIFYRE_EXE: &str = "ProxiFyre.exe";
const PROXIFYRE_CONFIG_FILE: &str = "app-config.json";
const FIREWALL_RULE_PREFIX: &str = "ProxyDuck";

#[derive(Debug)]
pub struct ProxifyreBackend {
    mode_label: &'static str,
    running: AtomicBool,
    desired_enabled: AtomicBool,
    rule_count: RwLock<usize>,
    firewall_rule_count: AtomicUsize,
    child: Mutex<Option<Child>>,
    proxifyre_dir: RwLock<Option<PathBuf>>,
    last_error: RwLock<Option<String>>,
    restart_needed: AtomicBool,
    restart_failures: AtomicU32,
    last_restart_attempt: Mutex<Option<Instant>>,
    proxy_reachable: AtomicU8,
    fail_closed_active: AtomicBool,
    last_connectivity_check: Mutex<Option<Instant>>,
}

impl ProxifyreBackend {
    pub fn new(mode_label: &'static str) -> Self {
        Self {
            mode_label,
            running: AtomicBool::new(false),
            desired_enabled: AtomicBool::new(false),
            rule_count: RwLock::new(0),
            firewall_rule_count: AtomicUsize::new(0),
            child: Mutex::new(None),
            proxifyre_dir: RwLock::new(None),
            last_error: RwLock::new(None),
            restart_needed: AtomicBool::new(false),
            restart_failures: AtomicU32::new(0),
            last_restart_attempt: Mutex::new(None),
            proxy_reachable: AtomicU8::new(0),
            fail_closed_active: AtomicBool::new(false),
            last_connectivity_check: Mutex::new(None),
        }
    }

    pub fn start(&self, config: &AppConfig) -> Result<()> {
        validate_clash_profile(config)?;
        self.running.store(true, Ordering::SeqCst);
        self.apply_config(config, "started")
    }

    pub fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.desired_enabled.store(false, Ordering::SeqCst);
        self.stop_child();
        self.remove_firewall_rules();
        *self.last_error.write() = None;
        self.restart_needed.store(false, Ordering::SeqCst);
        self.proxy_reachable.store(0, Ordering::SeqCst);
        self.fail_closed_active.store(false, Ordering::SeqCst);
        tracing::info!(mode = self.mode_label, "proxifyre backend stopped");
        Ok(())
    }

    pub fn reload(&self, config: &AppConfig) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("engine is not running"));
        }

        self.apply_config(config, "reloaded")
    }

    fn apply_config(&self, config: &AppConfig, action: &str) -> Result<()> {
        self.desired_enabled
            .store(config.runtime.enabled, Ordering::SeqCst);
        *self.rule_count.write() = config.rules.iter().filter(|rule| rule.enabled).count();
        *self.last_error.write() = None;
        self.restart_needed.store(false, Ordering::SeqCst);
        self.fail_closed_active.store(false, Ordering::SeqCst);

        let result: Result<()> = (|| {
            if !config.runtime.enabled {
                self.stop_child();
                self.remove_firewall_rules();
                tracing::info!(mode = self.mode_label, "runtime disabled; backend paused");
                return Ok(());
            }

            let proxy_config = self.build_runtime_config(config)?;
            if proxy_config.proxies.is_empty() {
                self.stop_child();
                self.remove_firewall_rules();
                *self.last_error.write() =
                    Some("no valid proxy mappings generated from enabled rules".to_string());
                tracing::warn!(mode = self.mode_label, "no valid proxy mappings generated");
                return Ok(());
            }

            let proxifyre_dir = self.resolve_proxifyre_dir()?;
            self.write_proxifyre_config(&proxifyre_dir, &proxy_config)?;
            self.restart_child(&proxifyre_dir)?;
            let proxy_reachable = has_reachable_proxy_endpoint(&proxy_config);
            self.proxy_reachable
                .store(encode_reachability(proxy_reachable), Ordering::SeqCst);
            let firewall_rules = if proxy_reachable {
                self.fail_closed_active.store(false, Ordering::SeqCst);
                self.apply_firewall_rules(config)?
            } else {
                match config.runtime.leak_protection_mode {
                    LeakProtectionMode::Availability => {
                        self.stop_child();
                        self.remove_firewall_rules();
                        *self.last_error.write() = Some(
                            "proxy endpoint is unreachable; data plane stopped for direct fallback"
                                .to_string(),
                        );
                        0
                    }
                    LeakProtectionMode::Strict => {
                        let added = self.apply_fail_closed_rules(config)?;
                        self.fail_closed_active.store(true, Ordering::SeqCst);
                        *self.last_error.write() = Some(
                            "proxy endpoint is unreachable; strict fail-closed rules are active"
                                .to_string(),
                        );
                        added
                    }
                }
            };
            self.firewall_rule_count
                .store(firewall_rules, Ordering::SeqCst);

            tracing::info!(
                mode = self.mode_label,
                rules = *self.rule_count.read(),
                proxy_entries = proxy_config.proxies.len(),
                action,
                "proxifyre backend configuration applied"
            );
            Ok(())
        })();

        if let Err(error) = &result {
            *self.last_error.write() = Some(error.to_string());
            self.restart_needed.store(true, Ordering::SeqCst);
        } else if self.child.lock().is_some() {
            self.restart_failures.store(0, Ordering::SeqCst);
            self.restart_needed.store(false, Ordering::SeqCst);
        }
        result
    }

    pub fn status(&self) -> DataPlaneStatus {
        let mut child = self.child.lock();
        let mut child_pid = child.as_ref().map(Child::id);
        if let Some(process) = child.as_mut() {
            match process.try_wait() {
                Ok(Some(exit)) => {
                    child.take();
                    child_pid = None;
                    *self.last_error.write() =
                        Some(format!("ProxiFyre exited unexpectedly with status {exit}"));
                    self.restart_needed.store(true, Ordering::SeqCst);
                }
                Ok(None) => {}
                Err(error) => {
                    *self.last_error.write() =
                        Some(format!("failed to inspect ProxiFyre process: {error}"));
                    self.restart_needed.store(true, Ordering::SeqCst);
                }
            }
        }

        let running = self.running.load(Ordering::SeqCst);
        let desired = self.desired_enabled.load(Ordering::SeqCst);
        let message = self.last_error.read().clone();
        let phase = if !running {
            DataPlanePhase::Stopped
        } else if !desired {
            DataPlanePhase::Paused
        } else if child_pid.is_some() && message.is_none() {
            DataPlanePhase::Running
        } else if message.is_some() {
            DataPlanePhase::Degraded
        } else {
            DataPlanePhase::Starting
        };

        DataPlaneStatus {
            phase,
            backend_name: "proxifyre".to_string(),
            child_pid,
            active_rules: *self.rule_count.read(),
            firewall_rules: self.firewall_rule_count.load(Ordering::SeqCst),
            proxy_endpoint_reachable: decode_reachability(
                self.proxy_reachable.load(Ordering::SeqCst),
            ),
            fail_closed_active: self.fail_closed_active.load(Ordering::SeqCst),
            message,
            checked_at: chrono::Utc::now(),
        }
    }

    pub fn maintain(&self, config: &AppConfig) -> Result<bool> {
        if !self.running.load(Ordering::SeqCst) || !config.runtime.enabled {
            return Ok(false);
        }

        let _ = self.status();
        if self.restart_needed.load(Ordering::SeqCst) {
            let failures = self.restart_failures.load(Ordering::SeqCst);
            let delay = Duration::from_secs((2_u64.saturating_pow(failures.min(5))).min(60));
            let mut last_attempt = self.last_restart_attempt.lock();
            if last_attempt.is_some_and(|instant| instant.elapsed() < delay) {
                return Ok(false);
            }
            *last_attempt = Some(Instant::now());
            drop(last_attempt);

            return match self.reload(config) {
                Ok(()) => {
                    self.restart_failures.store(0, Ordering::SeqCst);
                    Ok(true)
                }
                Err(error) => {
                    self.restart_failures.fetch_add(1, Ordering::SeqCst);
                    Err(error)
                }
            };
        }

        let mut last_check = self.last_connectivity_check.lock();
        if last_check.is_some_and(|instant| instant.elapsed() < Duration::from_secs(5)) {
            return Ok(false);
        }
        *last_check = Some(Instant::now());
        drop(last_check);

        let runtime = self.build_runtime_config(config)?;
        if runtime.proxies.is_empty() {
            return Ok(false);
        }
        let reachable = has_reachable_proxy_endpoint(&runtime);
        let previous = decode_reachability(self.proxy_reachable.load(Ordering::SeqCst));
        if previous == Some(reachable) {
            return Ok(false);
        }

        self.reload(config)?;
        Ok(true)
    }

    fn resolve_proxifyre_dir(&self) -> Result<PathBuf> {
        if let Some(cached) = self.proxifyre_dir.read().clone() {
            if cached.join(PROXIFYRE_EXE).exists() {
                return Ok(cached);
            }
        }

        let mut candidates: Vec<PathBuf> = Vec::new();

        if let Some(env_path) = proxyduck_common::proxifyre_dir_from_env() {
            candidates.push(env_path);
        }

        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(base) = current_exe.parent() {
                candidates.push(base.join("proxifyre"));
                candidates.push(base.to_path_buf());
            }
        }

        if let Ok(current_dir) = std::env::current_dir() {
            candidates.push(
                current_dir
                    .join("third_party")
                    .join("proxifyre")
                    .join("pkg"),
            );
            candidates.push(current_dir);
        }

        candidates.push(PathBuf::from(r"C:\tools\ProxiFyre"));

        let found = candidates
            .into_iter()
            .find(|path| path.join(PROXIFYRE_EXE).exists())
            .ok_or_else(|| {
                anyhow!(
                    "failed to locate ProxiFyre.exe; set PROXYDUCK_PROXIFYRE_DIR or place the proxifyre bundle next to proxyduck-core"
                )
            })?;

        *self.proxifyre_dir.write() = Some(found.clone());
        Ok(found)
    }

    fn write_proxifyre_config(&self, proxifyre_dir: &Path, config: &ProxifyreConfig) -> Result<()> {
        std::fs::create_dir_all(proxifyre_dir).with_context(|| {
            format!(
                "failed to create proxifyre directory: {}",
                proxifyre_dir.display()
            )
        })?;

        let path = proxifyre_dir.join(PROXIFYRE_CONFIG_FILE);
        let body =
            serde_json::to_string_pretty(config).context("failed to serialize proxifyre config")?;
        crate::config::atomic_write(&path, body.as_bytes())
            .with_context(|| format!("failed to write proxifyre config: {}", path.display()))?;
        Ok(())
    }

    fn restart_child(&self, proxifyre_dir: &Path) -> Result<()> {
        self.stop_child();

        let exe = proxifyre_dir.join(PROXIFYRE_EXE);
        let mut child = Command::new(&exe)
            .arg("run")
            .current_dir(proxifyre_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start {}", exe.display()))?;

        std::thread::sleep(std::time::Duration::from_millis(350));
        if let Some(status) = child
            .try_wait()
            .context("failed to check proxifyre process status")?
        {
            return Err(anyhow!(
                "proxifyre exited immediately with status: {status}"
            ));
        }

        *self.child.lock() = Some(child);
        Ok(())
    }

    fn stop_child(&self) {
        let mut lock = self.child.lock();
        if let Some(mut child) = lock.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn build_runtime_config(&self, config: &AppConfig) -> Result<ProxifyreConfig> {
        let running_processes = list_processes();
        let plan = compile_routing_plan(config, &running_processes)?;
        for diagnostic in &plan.diagnostics {
            tracing::warn!(plan = %plan.fingerprint, diagnostic, "routing plan diagnostic");
        }

        let proxies = plan
            .proxy_routes
            .into_iter()
            .map(|route| {
                let mut protocols = Vec::new();
                if route.protocols.contains(&Protocol::Tcp) {
                    protocols.push("TCP".to_string());
                }
                if route.protocols.contains(&Protocol::Udp)
                    || route.protocols.contains(&Protocol::Dns)
                {
                    protocols.push("UDP".to_string());
                }
                ProxifyreProxy {
                    app_names: route.patterns,
                    socks5_proxy_endpoint: route.endpoint,
                    username: route.username,
                    password: route.password,
                    supported_protocols: protocols,
                }
            })
            .collect();

        Ok(ProxifyreConfig {
            log_level: map_log_level(&config.runtime.log_level),
            bypass_lan: false,
            proxies,
            excludes: plan.direct_patterns,
        })
    }

    fn apply_firewall_rules(&self, config: &AppConfig) -> Result<usize> {
        self.remove_firewall_rules();

        if !config.runtime.enabled {
            return Ok(0);
        }

        let any_policy_enabled = config.runtime.dns_enforced
            || config.runtime.ipv6_blocked
            || config.runtime.doh_blocked;
        if !any_policy_enabled {
            return Ok(0);
        }
        let running_processes = list_processes();
        let doh_ips = resolve_doh_ips();

        let mut specs = Vec::new();
        for rule in config.rules.iter().filter(|rule| rule.enabled) {
            let paths = rule_executable_paths(rule, &running_processes);
            if paths.is_empty() {
                continue;
            }

            for path in paths {
                if config.runtime.dns_enforced && rule.force_dns {
                    specs.push(FirewallRuleSpec::new(
                        &rule_name("DNS-UDP", &path, 0),
                        &path,
                        ["protocol=UDP", "remoteport=53"],
                    ));
                    specs.push(FirewallRuleSpec::new(
                        &rule_name("DNS-TCP", &path, 0),
                        &path,
                        ["protocol=TCP", "remoteport=53"],
                    ));
                }

                if config.runtime.ipv6_blocked && rule.block_ipv6 {
                    specs.push(FirewallRuleSpec::new(
                        &rule_name("IPV6", &path, 0),
                        &path,
                        ["protocol=ANY", "remoteip=::/0"],
                    ));
                }

                if config.runtime.doh_blocked && rule.block_doh && !doh_ips.is_empty() {
                    for (index, chunk) in
                        split_remote_ip_chunks(&doh_ips, 18).into_iter().enumerate()
                    {
                        let remote = format!("remoteip={}", chunk.join(","));
                        specs.push(FirewallRuleSpec::new(
                            &rule_name("DOH", &path, index),
                            &path,
                            ["protocol=TCP", "remoteport=443", remote.as_str()],
                        ));
                    }
                }
            }
        }

        let added = apply_firewall_transaction(&specs, add_firewall_block_rule, || {
            self.delete_firewall_rules()
        })?;

        tracing::info!(
            mode = self.mode_label,
            count = added,
            "applied firewall hardening rules"
        );
        Ok(added)
    }

    fn apply_fail_closed_rules(&self, config: &AppConfig) -> Result<usize> {
        self.remove_firewall_rules();
        let mut paths = HashSet::new();
        for rule in config.rules.iter().filter(|rule| rule.enabled) {
            for path in &rule.matcher.exe_paths {
                if !path.trim().is_empty() {
                    paths.insert(path.clone());
                }
            }
        }

        let specs = paths
            .into_iter()
            .map(|path| {
                FirewallRuleSpec::new(&rule_name("FAIL-CLOSED", &path, 0), &path, ["protocol=ANY"])
            })
            .collect::<Vec<_>>();
        let added = apply_firewall_transaction(&specs, add_firewall_block_rule, || {
            self.delete_firewall_rules()
        })?;
        tracing::warn!(
            mode = self.mode_label,
            count = added,
            "strict fail-closed firewall rules applied"
        );
        Ok(added)
    }

    fn remove_firewall_rules(&self) {
        self.firewall_rule_count.store(0, Ordering::SeqCst);
        if !self.delete_firewall_rules() {
            tracing::warn!(
                mode = self.mode_label,
                "one or more firewall cleanup commands failed"
            );
        }
    }

    fn delete_firewall_rules(&self) -> bool {
        let mut successful = true;
        for prefix in [FIREWALL_RULE_PREFIX, "ProxyDock", "SmartFlow"] {
            let result = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={prefix}-*"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if !matches!(result, Ok(status) if status.success()) {
                successful = false;
            }
        }
        successful
    }
}

impl DataPlaneBackend for ProxifyreBackend {
    fn start(&self, config: &AppConfig) -> Result<()> {
        ProxifyreBackend::start(self, config)
    }

    fn stop(&self) -> Result<()> {
        ProxifyreBackend::stop(self)
    }

    fn reload(&self, config: &AppConfig) -> Result<()> {
        ProxifyreBackend::reload(self, config)
    }

    fn status(&self) -> DataPlaneStatus {
        ProxifyreBackend::status(self)
    }

    fn maintain(&self, config: &AppConfig) -> Result<bool> {
        ProxifyreBackend::maintain(self, config)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxifyreConfig {
    log_level: String,
    bypass_lan: bool,
    proxies: Vec<ProxifyreProxy>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    excludes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxifyreProxy {
    app_names: Vec<String>,
    socks5_proxy_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    supported_protocols: Vec<String>,
}

fn map_log_level(level: &str) -> String {
    match level.to_ascii_lowercase().as_str() {
        "error" => "Error",
        "warn" | "warning" => "Warning",
        "debug" => "Debug",
        "trace" | "all" => "All",
        _ => "Info",
    }
    .to_string()
}

fn rule_executable_paths(rule: &Rule, processes: &[crate::model::ProcessInfo]) -> Vec<String> {
    let mut paths: HashSet<String> = HashSet::new();

    for path in &rule.matcher.exe_paths {
        if !path.trim().is_empty() {
            paths.insert(path.clone());
        }
    }

    for pid in &rule.matcher.pids {
        if let Some(proc_info) = processes.iter().find(|entry| entry.pid == *pid) {
            if !proc_info.exe.is_empty() {
                paths.insert(proc_info.exe.clone());
            }
        }
    }

    for proc_info in processes {
        if crate::process::rule_match_kind(rule, proc_info).is_some() && !proc_info.exe.is_empty() {
            paths.insert(proc_info.exe.clone());
        }
    }

    let mut rows: Vec<String> = paths.into_iter().collect();
    rows.sort();
    rows
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirewallRuleSpec {
    name: String,
    program: String,
    extra: Vec<String>,
}

impl FirewallRuleSpec {
    fn new<I, S>(name: &str, program: &str, extra: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.to_string(),
            program: program.to_string(),
            extra: extra.into_iter().map(Into::into).collect(),
        }
    }
}

fn apply_firewall_transaction<A, R>(
    specs: &[FirewallRuleSpec],
    mut add: A,
    mut rollback: R,
) -> Result<usize>
where
    A: FnMut(&FirewallRuleSpec) -> bool,
    R: FnMut() -> bool,
{
    for (index, spec) in specs.iter().enumerate() {
        if !add(spec) {
            let rollback_succeeded = rollback();
            let rollback_note = if rollback_succeeded {
                "all rules were rolled back"
            } else {
                "rollback also failed; manual firewall cleanup may be required"
            };
            return Err(anyhow!(
                "firewall transaction failed at rule {} of {} ({}); {rollback_note}",
                index + 1,
                specs.len(),
                spec.name
            ));
        }
    }
    Ok(specs.len())
}

fn add_firewall_block_rule(spec: &FirewallRuleSpec) -> bool {
    let mut command = Command::new("netsh");
    command
        .arg("advfirewall")
        .arg("firewall")
        .arg("add")
        .arg("rule")
        .arg(format!("name={}", spec.name))
        .arg("dir=out")
        .arg("action=block")
        .arg("profile=any")
        .arg("enable=yes")
        .arg(format!("program={}", spec.program));

    for item in &spec.extra {
        command.arg(item);
    }

    match command.stdout(Stdio::null()).stderr(Stdio::null()).status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            tracing::warn!(rule = %spec.name, code = status.code().unwrap_or(-1), "failed to add firewall rule");
            false
        }
        Err(error) => {
            tracing::warn!(rule = %spec.name, error = %error, "failed to execute netsh for firewall rule");
            false
        }
    }
}

fn resolve_doh_ips() -> Vec<String> {
    vec![
        "1.1.1.1".to_string(),
        "1.0.0.1".to_string(),
        "8.8.8.8".to_string(),
        "8.8.4.4".to_string(),
        "9.9.9.9".to_string(),
        "149.112.112.112".to_string(),
        "94.140.14.14".to_string(),
        "94.140.15.15".to_string(),
        "208.67.222.222".to_string(),
        "208.67.220.220".to_string(),
    ]
}

fn has_reachable_proxy_endpoint(config: &ProxifyreConfig) -> bool {
    let timeout = Duration::from_millis(700);
    let mut unique_endpoints = HashSet::new();

    for proxy in &config.proxies {
        let endpoint = normalize_endpoint(&proxy.socks5_proxy_endpoint);
        if endpoint.is_empty() || !unique_endpoints.insert(endpoint.clone()) {
            continue;
        }

        let Ok(addrs) = endpoint.to_socket_addrs() else {
            continue;
        };

        for addr in addrs {
            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                return true;
            }
        }
    }

    false
}

fn encode_reachability(reachable: bool) -> u8 {
    if reachable {
        1
    } else {
        2
    }
}

fn decode_reachability(value: u8) -> Option<bool> {
    match value {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let without_path = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host_port = without_path.rsplit('@').next().unwrap_or(without_path);
    host_port.to_string()
}

fn split_remote_ip_chunks(items: &[String], chunk_size: usize) -> Vec<Vec<String>> {
    if items.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut index = 0usize;
    while index < items.len() {
        let end = std::cmp::min(index + chunk_size, items.len());
        chunks.push(items[index..end].to_vec());
        index = end;
    }
    chunks
}

fn rule_name(kind: &str, path: &str, index: usize) -> String {
    format!(
        "{FIREWALL_RULE_PREFIX}-{kind}-{:016x}-{index}",
        stable_hash(path)
    )
}

fn stable_hash(input: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MatchCriteria, ProxyKind, ProxyProfile};

    #[test]
    fn disabled_proxy_rule_does_not_claim_pattern_from_valid_fallback() {
        let mut config = AppConfig::default();
        config.proxies.push(ProxyProfile {
            id: "disabled".to_string(),
            name: "Disabled".to_string(),
            kind: ProxyKind::Socks5,
            endpoint: "127.0.0.1:9999".to_string(),
            username: None,
            password: None,
            enabled: false,
        });
        config.rules = vec![
            Rule::new(
                "disabled first".to_string(),
                MatchCriteria {
                    app_names: vec!["code.exe".to_string()],
                    ..Default::default()
                },
                "disabled".to_string(),
            ),
            Rule::new(
                "valid fallback".to_string(),
                MatchCriteria {
                    app_names: vec!["code.exe".to_string()],
                    ..Default::default()
                },
                "clash-socks".to_string(),
            ),
        ];

        let runtime = ProxifyreBackend::new("test")
            .build_runtime_config(&config)
            .expect("runtime config should build");

        assert_eq!(runtime.proxies.len(), 1);
        assert_eq!(runtime.proxies[0].app_names, vec!["code.exe"]);
        assert_eq!(runtime.proxies[0].socks5_proxy_endpoint, "127.0.0.1:7897");
    }

    #[test]
    fn runtime_status_distinguishes_stopped_paused_and_unconfigured() {
        let backend = ProxifyreBackend::new("test");
        assert_eq!(backend.status().phase, DataPlanePhase::Stopped);

        let mut config = AppConfig::default();
        backend.start(&config).unwrap();
        assert_eq!(backend.status().phase, DataPlanePhase::Paused);

        config.runtime.enabled = true;
        backend.reload(&config).unwrap();
        let status = backend.status();
        assert_eq!(status.phase, DataPlanePhase::Degraded);
        assert!(status.message.unwrap().contains("no valid proxy mappings"));
        assert!(!backend.maintain(&config).unwrap());
    }

    #[test]
    fn reachability_encoding_preserves_unknown_reachable_and_unreachable() {
        assert_eq!(decode_reachability(0), None);
        assert_eq!(decode_reachability(encode_reachability(true)), Some(true));
        assert_eq!(decode_reachability(encode_reachability(false)), Some(false));
    }

    #[test]
    fn firewall_transaction_rolls_back_after_the_first_failed_rule() {
        let specs = [
            FirewallRuleSpec::new("one", "one.exe", ["protocol=TCP"]),
            FirewallRuleSpec::new("two", "two.exe", ["protocol=UDP"]),
            FirewallRuleSpec::new("three", "three.exe", ["protocol=ANY"]),
        ];
        let mut attempts = Vec::new();
        let mut rolled_back = false;

        let result = apply_firewall_transaction(
            &specs,
            |spec| {
                attempts.push(spec.name.clone());
                spec.name != "two"
            },
            || {
                rolled_back = true;
                true
            },
        );

        assert!(result.is_err());
        assert_eq!(attempts, ["one", "two"]);
        assert!(rolled_back);
        assert!(result.unwrap_err().to_string().contains("rolled back"));
    }

    #[test]
    fn firewall_transaction_reports_rollback_failure() {
        let specs = [FirewallRuleSpec::new("one", "one.exe", ["protocol=TCP"])];
        let error = apply_firewall_transaction(&specs, |_| false, || false).unwrap_err();
        assert!(error.to_string().contains("manual firewall cleanup"));
    }
}
