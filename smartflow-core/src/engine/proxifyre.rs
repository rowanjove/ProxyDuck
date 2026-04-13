use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use crate::{
    engine::{validate_clash_profile, DataPlaneBackend},
    model::{AppConfig, Protocol, ProxyKind, Rule},
    process::{list_processes, rule_priority},
};

const PROXIFYRE_EXE: &str = "ProxiFyre.exe";
const PROXIFYRE_CONFIG_FILE: &str = "app-config.json";
const FIREWALL_RULE_PREFIX: &str = "SmartFlow";

#[derive(Debug)]
pub struct ProxifyreBackend {
    mode_label: &'static str,
    running: AtomicBool,
    rule_count: RwLock<usize>,
    child: Mutex<Option<Child>>,
    proxifyre_dir: RwLock<Option<PathBuf>>,
}

impl ProxifyreBackend {
    pub fn new(mode_label: &'static str) -> Self {
        Self {
            mode_label,
            running: AtomicBool::new(false),
            rule_count: RwLock::new(0),
            child: Mutex::new(None),
            proxifyre_dir: RwLock::new(None),
        }
    }

    pub fn start(&self, config: &AppConfig) -> Result<()> {
        validate_clash_profile(config)?;

        self.running.store(true, Ordering::SeqCst);
        *self.rule_count.write() = config.rules.iter().filter(|rule| rule.enabled).count();

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
            tracing::warn!(
                mode = self.mode_label,
                "no valid proxy mappings generated from rules"
            );
            return Ok(());
        }

        let proxifyre_dir = self.resolve_proxifyre_dir()?;
        self.write_proxifyre_config(&proxifyre_dir, &proxy_config)?;
        self.restart_child(&proxifyre_dir)?;
        self.apply_firewall_rules(config, &proxy_config)?;

        tracing::info!(
            mode = self.mode_label,
            rules = *self.rule_count.read(),
            proxy_entries = proxy_config.proxies.len(),
            "proxifyre backend started"
        );

        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.stop_child();
        self.remove_firewall_rules();
        tracing::info!(mode = self.mode_label, "proxifyre backend stopped");
        Ok(())
    }

    pub fn reload(&self, config: &AppConfig) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("engine is not running"));
        }

        *self.rule_count.write() = config.rules.iter().filter(|rule| rule.enabled).count();

        if !config.runtime.enabled {
            self.stop_child();
            self.remove_firewall_rules();
            tracing::info!(
                mode = self.mode_label,
                "runtime disabled on reload; backend paused"
            );
            return Ok(());
        }

        let proxy_config = self.build_runtime_config(config)?;
        if proxy_config.proxies.is_empty() {
            self.stop_child();
            self.remove_firewall_rules();
            tracing::warn!(
                mode = self.mode_label,
                "reload produced no valid proxy mappings"
            );
            return Ok(());
        }

        let proxifyre_dir = self.resolve_proxifyre_dir()?;
        self.write_proxifyre_config(&proxifyre_dir, &proxy_config)?;
        self.restart_child(&proxifyre_dir)?;
        self.apply_firewall_rules(config, &proxy_config)?;

        tracing::info!(
            mode = self.mode_label,
            rules = *self.rule_count.read(),
            proxy_entries = proxy_config.proxies.len(),
            "proxifyre backend reloaded"
        );

        Ok(())
    }

    fn resolve_proxifyre_dir(&self) -> Result<PathBuf> {
        if let Some(cached) = self.proxifyre_dir.read().clone() {
            if cached.join(PROXIFYRE_EXE).exists() {
                return Ok(cached);
            }
        }

        let mut candidates: Vec<PathBuf> = Vec::new();

        if let Ok(env_path) = std::env::var("SMARTFLOW_PROXIFYRE_DIR") {
            if !env_path.trim().is_empty() {
                candidates.push(PathBuf::from(env_path));
            }
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
                    "failed to locate ProxiFyre.exe; set SMARTFLOW_PROXIFYRE_DIR or place proxifyre bundle next to smartflow-core"
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
        std::fs::write(&path, body)
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
        let profile_map: HashMap<&str, &crate::model::ProxyProfile> = config
            .proxies
            .iter()
            .map(|profile| (profile.id.as_str(), profile))
            .collect();

        let running_processes = list_processes();
        let mut proxies = Vec::new();
        let mut excludes = HashSet::new();
        let mut claimed_patterns = HashSet::new();
        let mut sorted_rules = config
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .collect::<Vec<_>>();
        sorted_rules.sort_by_key(|rule| rule_priority(rule));

        for rule in sorted_rules {
            let patterns = rule_patterns(rule, &running_processes)
                .into_iter()
                .filter(|pattern| claimed_patterns.insert(pattern.to_ascii_lowercase()))
                .collect::<Vec<_>>();
            if patterns.is_empty() {
                continue;
            }

            let Some(profile) = profile_map.get(rule.proxy_profile.as_str()) else {
                tracing::warn!(rule = %rule.name, profile = %rule.proxy_profile, "rule references missing profile");
                continue;
            };

            if !profile.enabled {
                continue;
            }

            match profile.kind {
                ProxyKind::Socks5 => {
                    let mut protocols = Vec::new();
                    if supports_protocol(rule, Protocol::Tcp) {
                        protocols.push("TCP".to_string());
                    }
                    if supports_protocol(rule, Protocol::Udp)
                        || supports_protocol(rule, Protocol::Dns)
                    {
                        protocols.push("UDP".to_string());
                    }
                    if protocols.is_empty() {
                        protocols.push("TCP".to_string());
                        protocols.push("UDP".to_string());
                    }
                    protocols.sort();
                    protocols.dedup();

                    proxies.push(ProxifyreProxy {
                        app_names: patterns,
                        socks5_proxy_endpoint: profile.endpoint.clone(),
                        username: profile.username.clone(),
                        password: profile.password.clone(),
                        supported_protocols: protocols,
                    });
                }
                ProxyKind::Direct => {
                    for pattern in patterns {
                        excludes.insert(pattern);
                    }
                }
                ProxyKind::Http | ProxyKind::Interface | ProxyKind::Vpn => {
                    tracing::warn!(
                        rule = %rule.name,
                        profile = %profile.name,
                        kind = ?profile.kind,
                        "profile kind not supported by proxifyre backend"
                    );
                }
            }
        }

        Ok(ProxifyreConfig {
            log_level: map_log_level(&config.runtime.log_level),
            bypass_lan: false,
            proxies,
            excludes: {
                let mut rows: Vec<String> = excludes.into_iter().collect();
                rows.sort();
                rows
            },
        })
    }

    fn apply_firewall_rules(
        &self,
        config: &AppConfig,
        proxy_config: &ProxifyreConfig,
    ) -> Result<()> {
        self.remove_firewall_rules();

        if !config.runtime.enabled {
            return Ok(());
        }

        let any_policy_enabled = config.runtime.dns_enforced
            || config.runtime.ipv6_blocked
            || config.runtime.doh_blocked;
        if !any_policy_enabled {
            return Ok(());
        }
        if !has_reachable_proxy_endpoint(proxy_config) {
            tracing::warn!(
                mode = self.mode_label,
                "skipping firewall hardening: no reachable SOCKS5 endpoint"
            );
            return Ok(());
        }

        let running_processes = list_processes();
        let doh_ips = resolve_doh_ips();

        let mut added = 0usize;
        for rule in config.rules.iter().filter(|rule| rule.enabled) {
            let paths = rule_executable_paths(rule, &running_processes);
            if paths.is_empty() {
                continue;
            }

            for path in paths {
                if config.runtime.dns_enforced && rule.force_dns {
                    if add_firewall_block_rule(
                        &rule_name("DNS-UDP", &path, 0),
                        &path,
                        &["protocol=UDP", "remoteport=53"],
                    ) {
                        added += 1;
                    }
                    if add_firewall_block_rule(
                        &rule_name("DNS-TCP", &path, 0),
                        &path,
                        &["protocol=TCP", "remoteport=53"],
                    ) {
                        added += 1;
                    }
                }

                if config.runtime.ipv6_blocked && rule.block_ipv6 {
                    if add_firewall_block_rule(
                        &rule_name("IPV6", &path, 0),
                        &path,
                        &["protocol=ANY", "remoteip=::/0"],
                    ) {
                        added += 1;
                    }
                }

                if config.runtime.doh_blocked && rule.block_doh && !doh_ips.is_empty() {
                    for (index, chunk) in
                        split_remote_ip_chunks(&doh_ips, 18).into_iter().enumerate()
                    {
                        let remote = format!("remoteip={}", chunk.join(","));
                        if add_firewall_block_rule(
                            &rule_name("DOH", &path, index),
                            &path,
                            &["protocol=TCP", "remoteport=443", &remote],
                        ) {
                            added += 1;
                        }
                    }
                }
            }
        }

        tracing::info!(
            mode = self.mode_label,
            count = added,
            "applied firewall hardening rules"
        );
        Ok(())
    }

    fn remove_firewall_rules(&self) {
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={FIREWALL_RULE_PREFIX}-*"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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

fn supports_protocol(rule: &Rule, protocol: Protocol) -> bool {
    rule.protocols
        .iter()
        .any(|entry| std::mem::discriminant(entry) == std::mem::discriminant(&protocol))
}

fn rule_patterns(rule: &Rule, processes: &[crate::model::ProcessInfo]) -> Vec<String> {
    let mut patterns: HashSet<String> = HashSet::new();

    for app in &rule.matcher.app_names {
        let value = app.trim();
        if !value.is_empty() {
            patterns.insert(value.to_string());
        }
    }

    for path in &rule.matcher.exe_paths {
        let value = path.trim();
        if !value.is_empty() {
            patterns.insert(value.to_string());
        }
    }

    if let Some(wildcard) = &rule.matcher.wildcard {
        let value = wildcard.trim();
        if !value.is_empty() {
            patterns.insert(value.to_string());
        }
    }

    for pid in &rule.matcher.pids {
        if let Some(proc_info) = processes.iter().find(|entry| entry.pid == *pid) {
            if !proc_info.name.is_empty() {
                patterns.insert(proc_info.name.clone());
            }
            if !proc_info.exe.is_empty() {
                patterns.insert(proc_info.exe.clone());
            }
        }
    }

    let mut rows: Vec<String> = patterns.into_iter().collect();
    rows.sort();
    rows
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

    let mut name_patterns: Vec<String> = rule
        .matcher
        .app_names
        .iter()
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect();

    if let Some(wildcard) = &rule.matcher.wildcard {
        let value = wildcard.trim().to_ascii_lowercase();
        if !value.is_empty() {
            name_patterns.push(value);
        }
    }

    for proc_info in processes {
        let lower_name = proc_info.name.to_ascii_lowercase();
        let lower_exe = proc_info.exe.to_ascii_lowercase();

        if name_patterns.iter().any(|pattern| {
            lower_name.contains(pattern)
                || lower_exe.contains(pattern)
                || lower_exe.ends_with(pattern)
        }) {
            if !proc_info.exe.is_empty() {
                paths.insert(proc_info.exe.clone());
            }
        }
    }

    let mut rows: Vec<String> = paths.into_iter().collect();
    rows.sort();
    rows
}

fn add_firewall_block_rule(name: &str, program: &str, extra: &[&str]) -> bool {
    let mut command = Command::new("netsh");
    command
        .arg("advfirewall")
        .arg("firewall")
        .arg("add")
        .arg("rule")
        .arg(format!("name={name}"))
        .arg("dir=out")
        .arg("action=block")
        .arg("profile=any")
        .arg("enable=yes")
        .arg(format!("program={program}"));

    for item in extra {
        command.arg(item);
    }

    match command.stdout(Stdio::null()).stderr(Stdio::null()).status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            tracing::warn!(rule = %name, code = status.code().unwrap_or(-1), "failed to add firewall rule");
            false
        }
        Err(error) => {
            tracing::warn!(rule = %name, error = %error, "failed to execute netsh for firewall rule");
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
