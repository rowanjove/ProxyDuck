use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fs::OpenOptions,
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
    model::{
        AppConfig, DataPlanePhase, DataPlaneStatus, LeakProtectionMode, ProcessInfo, Protocol, Rule,
    },
    process::list_processes,
    routing_plan::compile_routing_plan,
};

const PROXIFYRE_EXE: &str = "ProxiFyre.exe";
const PROXIFYRE_CONFIG_FILE: &str = "app-config.json";
const PROXIFYRE_RUNTIME_MARKER: &str = ".proxyduck-runtime-owned";
const FIREWALL_RULE_PREFIX: &str = "ProxyDuck";

fn windows_system32_tool(name: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(name)
}

#[derive(Debug)]
pub struct ProxifyreBackend {
    mode_label: &'static str,
    running: AtomicBool,
    desired_enabled: AtomicBool,
    rule_count: RwLock<usize>,
    firewall_rule_count: AtomicUsize,
    child: Mutex<Option<Child>>,
    job: Mutex<Option<crate::engine::ProcessJobGuard>>,
    mock_child_pid: AtomicU32,
    proxifyre_dir: RwLock<Option<PathBuf>>,
    runtime_config_path: RwLock<Option<PathBuf>>,
    last_error: RwLock<Option<String>>,
    restart_needed: AtomicBool,
    restart_failures: AtomicU32,
    last_restart_attempt: Mutex<Option<Instant>>,
    proxy_reachable: AtomicU8,
    fail_closed_active: AtomicBool,
    /// Keeps strict protection refresh enabled even when no matching process
    /// currently exists. A future process may appear during restart backoff.
    strict_fail_closed_required: AtomicBool,
    direct_only_active: AtomicBool,
    firewall_process_fingerprint: RwLock<Option<u64>>,
    installed_firewall_specs: RwLock<HashMap<String, FirewallRuleSpec>>,
    /// Serializes lifecycle/configuration and process-triggered firewall
    /// reconciliation. Both paths can otherwise observe the same installed
    /// snapshot and interleave add/delete operations, leaving stale rules or
    /// losing a newly reconciled rule set.
    firewall_transaction_lock: Mutex<()>,
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
            job: Mutex::new(None),
            mock_child_pid: AtomicU32::new(0),
            proxifyre_dir: RwLock::new(None),
            runtime_config_path: RwLock::new(None),
            last_error: RwLock::new(None),
            restart_needed: AtomicBool::new(false),
            restart_failures: AtomicU32::new(0),
            last_restart_attempt: Mutex::new(None),
            proxy_reachable: AtomicU8::new(0),
            fail_closed_active: AtomicBool::new(false),
            strict_fail_closed_required: AtomicBool::new(false),
            direct_only_active: AtomicBool::new(false),
            firewall_process_fingerprint: RwLock::new(None),
            installed_firewall_specs: RwLock::new(HashMap::new()),
            firewall_transaction_lock: Mutex::new(()),
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
        let _firewall_guard = self.firewall_transaction_lock.lock();
        self.stop_child();
        self.cleanup_runtime_config();
        self.remove_firewall_rules();
        *self.last_error.write() = None;
        self.restart_needed.store(false, Ordering::SeqCst);
        self.proxy_reachable.store(0, Ordering::SeqCst);
        self.fail_closed_active.store(false, Ordering::SeqCst);
        self.strict_fail_closed_required
            .store(false, Ordering::SeqCst);
        self.direct_only_active.store(false, Ordering::SeqCst);
        *self.firewall_process_fingerprint.write() = None;
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
        let _firewall_guard = self.firewall_transaction_lock.lock();
        self.cleanup_stale_runtime_config();
        self.desired_enabled
            .store(config.runtime.enabled, Ordering::SeqCst);
        *self.rule_count.write() = config.rules.iter().filter(|rule| rule.enabled).count();
        *self.last_error.write() = None;
        self.restart_needed.store(false, Ordering::SeqCst);
        self.fail_closed_active.store(false, Ordering::SeqCst);
        self.strict_fail_closed_required
            .store(false, Ordering::SeqCst);
        self.direct_only_active.store(false, Ordering::SeqCst);

        let result: Result<()> = (|| {
            if !config.runtime.enabled {
                self.stop_child();
                self.cleanup_runtime_config();
                self.remove_firewall_rules();
                tracing::info!(mode = self.mode_label, "runtime disabled; backend paused");
                return Ok(());
            }

            let proxy_config = self.build_runtime_config(config)?;
            if proxy_config.proxies.is_empty() {
                self.stop_child();
                self.cleanup_runtime_config();
                let direct_only = !proxy_config.excludes.is_empty();
                self.direct_only_active.store(direct_only, Ordering::SeqCst);
                let firewall_rules = if direct_only {
                    self.remove_firewall_rules();
                    self.apply_firewall_rules_with_recovery(config)?
                } else {
                    self.remove_firewall_rules();
                    0
                };
                self.firewall_rule_count
                    .store(firewall_rules, Ordering::SeqCst);
                if direct_only {
                    *self.last_error.write() = None;
                    tracing::info!(mode = self.mode_label, "direct-only routing policy active");
                } else {
                    *self.last_error.write() =
                        Some("no valid proxy mappings generated from enabled rules".to_string());
                    tracing::warn!(mode = self.mode_label, "no valid proxy mappings generated");
                }
                return Ok(());
            }

            let proxifyre_dir = self.resolve_proxifyre_dir()?;
            self.write_proxifyre_config(&proxifyre_dir, &proxy_config)?;
            if let Err(error) = self.restart_child(&proxifyre_dir) {
                self.cleanup_runtime_config();
                return Err(error);
            }
            let proxy_reachable = has_reachable_proxy_endpoint(&proxy_config);
            self.proxy_reachable
                .store(encode_reachability(proxy_reachable), Ordering::SeqCst);
            let firewall_rules = if proxy_reachable {
                self.fail_closed_active.store(false, Ordering::SeqCst);
                self.remove_firewall_rules();
                self.apply_firewall_rules_with_recovery(config)?
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
                    LeakProtectionMode::Strict => self.apply_strict_fail_closed(
                        config,
                        "proxy endpoint is unreachable".to_string(),
                    )?,
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
            self.restart_needed.store(true, Ordering::SeqCst);
            let message = if config.runtime.enabled
                && matches!(
                    config.runtime.leak_protection_mode,
                    LeakProtectionMode::Strict
                ) {
                match self.apply_strict_fail_closed(config, error.to_string()) {
                    Ok(count) if count > 0 => format!(
                        "{error}; strict fail-closed rules are active ({count} rules)"
                    ),
                    Ok(_) => format!(
                        "{error}; strict fail-closed could not install an executable block for the current process set"
                    ),
                    Err(fallback_error) => format!(
                        "{error}; strict fail-closed activation failed: {fallback_error}"
                    ),
                }
            } else {
                error.to_string()
            };
            *self.last_error.write() = Some(message);
        } else if self.child.lock().is_some() {
            self.restart_failures.store(0, Ordering::SeqCst);
            self.restart_needed.store(false, Ordering::SeqCst);
        }
        result
    }

    pub fn status(&self) -> DataPlaneStatus {
        let mut child = self.child.lock();
        let mut child_pid = child.as_ref().map(Child::id).or_else(|| {
            let pid = self.mock_child_pid.load(Ordering::SeqCst);
            if pid != 0 {
                Some(pid)
            } else {
                None
            }
        });
        if let Some(process) = child.as_mut() {
            match process.try_wait() {
                Ok(Some(exit)) => {
                    child.take();
                    *self.job.lock() = None;
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
        } else if (self.direct_only_active.load(Ordering::SeqCst) || child_pid.is_some())
            && message.is_none()
        {
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
        if super::is_mock_data_plane() {
            tracing::debug!("mock data plane active; skipping write_proxifyre_config");
            return Ok(());
        }

        std::fs::create_dir_all(proxifyre_dir).with_context(|| {
            format!(
                "failed to create proxifyre directory: {}",
                proxifyre_dir.display()
            )
        })?;

        let path = proxifyre_dir.join(PROXIFYRE_CONFIG_FILE);
        let body =
            serde_json::to_string_pretty(config).context("failed to serialize proxifyre config")?;
        let marker = proxifyre_dir.join(PROXIFYRE_RUNTIME_MARKER);
        crate::config::atomic_write(&marker, b"ProxyDuck runtime-owned configuration\n")
            .with_context(|| {
                format!(
                    "failed to write proxifyre runtime marker: {}",
                    marker.display()
                )
            })?;
        if let Err(error) = crate::config::atomic_write(&path, body.as_bytes()) {
            let _ = std::fs::remove_file(&marker);
            return Err(error)
                .with_context(|| format!("failed to write proxifyre config: {}", path.display()));
        }
        *self.runtime_config_path.write() = Some(path.clone());
        if let Err(error) = proxyduck_common::harden_active_path(&path) {
            self.cleanup_runtime_config();
            return Err(error)
                .with_context(|| format!("failed to harden proxifyre config: {}", path.display()));
        }
        Ok(())
    }

    fn cleanup_runtime_config(&self) {
        if let Some(path) = self.runtime_config_path.write().take() {
            if let Err(error) = std::fs::remove_file(&path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(%error, path = %path.display(), "failed to remove proxifyre runtime config");
                }
            }
            let _ = std::fs::remove_file(path.with_file_name(PROXIFYRE_RUNTIME_MARKER));
        }
    }

    fn cleanup_stale_runtime_config(&self) {
        let Ok(directory) = self.resolve_proxifyre_dir() else {
            return;
        };
        let marker = directory.join(PROXIFYRE_RUNTIME_MARKER);
        if !marker.exists() {
            return;
        }
        let path = directory.join(PROXIFYRE_CONFIG_FILE);
        if let Err(error) = std::fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, path = %path.display(), "failed to remove stale proxifyre runtime config");
                return;
            }
        }
        if let Err(error) = std::fs::remove_file(&marker) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, path = %marker.display(), "failed to remove stale proxifyre runtime marker");
            }
        }
    }

    fn restart_child(&self, proxifyre_dir: &Path) -> Result<()> {
        self.stop_child();

        if super::is_mock_data_plane() {
            tracing::info!("mock data plane active; skipping ProxiFyre child process launch");
            self.mock_child_pid
                .store(std::process::id(), Ordering::SeqCst);
            return Ok(());
        }

        let exe = proxifyre_dir.join(PROXIFYRE_EXE);
        let stdout_log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(proxifyre_dir.join("proxyduck-proxifyre.stdout.log"))
            .context("failed to open ProxiFyre stdout log")?;
        let stderr_log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(proxifyre_dir.join("proxyduck-proxifyre.stderr.log"))
            .context("failed to open ProxiFyre stderr log")?;
        let mut child = Command::new(&exe)
            .arg("run")
            .current_dir(proxifyre_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_log))
            .stderr(Stdio::from(stderr_log))
            .spawn()
            .with_context(|| format!("failed to start {}", exe.display()))?;

        let job_guard = match crate::engine::ProcessJobGuard::assign(&child) {
            Ok(guard) => Some(guard),
            Err(error) => {
                tracing::warn!(%error, "failed to attach ProxiFyre child process to Windows JobObject");
                None
            }
        };

        if let Err(error) = wait_for_process_ready(&mut child, "proxifyre", Duration::from_secs(5))
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        *self.child.lock() = Some(child);
        *self.job.lock() = job_guard;
        Ok(())
    }

    fn stop_child(&self) {
        self.mock_child_pid.store(0, Ordering::SeqCst);
        let mut lock = self.child.lock();
        if let Some(mut child) = lock.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        *self.job.lock() = None;
    }

    fn build_runtime_config(&self, config: &AppConfig) -> Result<ProxifyreConfig> {
        let running_processes = list_processes();
        let plan = compile_routing_plan(config, &running_processes)?;
        let strict = matches!(
            config.runtime.leak_protection_mode,
            crate::model::LeakProtectionMode::Strict
        );
        for diagnostic in &plan.diagnostics {
            tracing::warn!(
                plan = %plan.fingerprint,
                code = %diagnostic.code,
                severity = ?diagnostic.severity,
                message = %diagnostic.message,
                "routing plan diagnostic"
            );
        }
        for rule in config.rules.iter().filter(|rule| rule.enabled) {
            let has_tcp = rule.protocols.is_empty()
                || rule
                    .protocols
                    .iter()
                    .any(|protocol| matches!(protocol, Protocol::Tcp));
            let has_udp = rule.protocols.is_empty()
                || rule
                    .protocols
                    .iter()
                    .any(|protocol| matches!(protocol, Protocol::Udp));
            if (!has_tcp || !has_udp) && strict {
                return Err(anyhow!(
                    "ProxiFyre cannot express per-protocol scope for rule '{}' without broadening it to all TCP/UDP traffic",
                    rule.id
                ));
            }
            if (!has_tcp || !has_udp) && !strict {
                tracing::warn!(
                    rule_id = %rule.id,
                    "compatibility mode broadens a protocol-scoped rule to the ProxiFyre route"
                );
            }
            if matches!(
                rule.action,
                crate::model::RouteAction::Block | crate::model::RouteAction::Reject
            ) {
                return Err(anyhow!(
                    "ProxiFyre cannot enforce block/reject action for rule '{}' without a native block adapter",
                    rule.id
                ));
            }
            if strict
                && plan.diagnostics.iter().any(|diagnostic| {
                    diagnostic.rule_id.as_deref() == Some(rule.id.as_str())
                        && diagnostic.blocks_strict
                })
            {
                return Err(anyhow!(
                    "ProxiFyre cannot compile policy constraints for rule '{}'",
                    rule.id
                ));
            }
            if !rule.destination.is_empty() && strict {
                return Err(anyhow!(
                    "ProxiFyre cannot express destination matching for rule '{}' without broadening it to a process-wide route",
                    rule.id
                ));
            }
            if !rule.matcher.pids.is_empty() {
                return Err(anyhow!(
                    "ProxiFyre cannot bind ephemeral PID selector for rule '{}' without a process-instance adapter",
                    rule.id
                ));
            }
            if rule
                .matcher
                .wildcard
                .as_deref()
                .is_some_and(|wildcard| !wildcard.trim().is_empty())
            {
                return Err(anyhow!(
                    "ProxiFyre cannot express wildcard process selector for rule '{}' without broadening or silently dropping it",
                    rule.id
                ));
            }
        }
        if strict {
            if let Some(route) = plan
                .proxy_routes
                .iter()
                .find(|route| !route.destination.is_empty())
            {
                return Err(anyhow!(
                    "ProxiFyre cannot express destination matching for rule '{}' without broadening it to a process-wide route",
                    route.rule_id
                ));
            }
        }
        if let Some(route) = plan.proxy_routes.iter().find(|route| {
            route.selectors.iter().any(|selector| {
                matches!(
                    selector.kind,
                    crate::routing_plan::PlannedSelectorKind::ProcessInstance
                )
            })
        }) {
            return Err(anyhow!(
                "ProxiFyre cannot bind ephemeral PID selector for rule '{}' without a process-instance adapter",
                route.rule_id
            ));
        }
        if strict {
            if let Some(rule) = config
                .rules
                .iter()
                .filter(|rule| rule.enabled)
                .find(|rule| {
                    plan.diagnostics.iter().any(|diagnostic| {
                        diagnostic.rule_id.as_deref() == Some(rule.id.as_str())
                            && diagnostic.blocks_strict
                    }) || !rule.destination.is_empty()
                        && (matches!(rule.action, crate::model::RouteAction::Direct)
                            || config
                                .proxies
                                .iter()
                                .find(|proxy| proxy.id == rule.action_target_id())
                                .is_some_and(|proxy| {
                                    matches!(proxy.kind, crate::model::ProxyKind::Direct)
                                }))
                })
            {
                return Err(anyhow!(
                    "ProxiFyre cannot compile policy or destination constraints for rule '{}'",
                    rule.id
                ));
            }
        }
        let proxies = plan
            .proxy_routes
            .into_iter()
            .map(|route| {
                let mut protocols = Vec::new();
                if route.protocols.contains(&Protocol::Tcp) {
                    protocols.push("TCP".to_string());
                }
                if route.protocols.contains(&Protocol::Udp) {
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
        let processes = list_processes();
        self.apply_firewall_rules_for_processes(config, &processes)
    }

    fn apply_firewall_rules_with_recovery(&self, config: &AppConfig) -> Result<usize> {
        match self.apply_firewall_rules(config) {
            Ok(count) => Ok(count),
            Err(error)
                if matches!(
                    config.runtime.leak_protection_mode,
                    LeakProtectionMode::Strict
                ) =>
            {
                self.apply_strict_fail_closed(config, format!("firewall hardening failed: {error}"))
            }
            Err(error) => Err(error),
        }
    }

    fn apply_firewall_rules_for_processes(
        &self,
        config: &AppConfig,
        running_processes: &[ProcessInfo],
    ) -> Result<usize> {
        if !config.runtime.enabled {
            return Ok(0);
        }

        let any_policy_enabled = config.runtime.dns_enforced
            || config.runtime.ipv6_blocked
            || config.runtime.doh_blocked;
        if !any_policy_enabled {
            return Ok(0);
        }
        let doh_ips = resolve_doh_ips();

        let mut specs = Vec::new();
        for rule in config.rules.iter().filter(|rule| rule.enabled) {
            let paths = rule_executable_paths(rule, running_processes);
            if paths.is_empty() {
                continue;
            }

            for path in paths {
                if config.runtime.dns_enforced
                    && (rule.force_dns
                        || matches!(rule.dns.mode, crate::model::DnsMode::BlockPlaintext))
                {
                    specs.push(FirewallRuleSpec::new(
                        &rule_name_for_rule("DNS-UDP", &rule.id, &path, 0),
                        &path,
                        ["protocol=UDP", "remoteport=53"],
                    ));
                    specs.push(FirewallRuleSpec::new(
                        &rule_name_for_rule("DNS-TCP", &rule.id, &path, 0),
                        &path,
                        ["protocol=TCP", "remoteport=53"],
                    ));
                }

                if config.runtime.ipv6_blocked && rule.block_ipv6 {
                    specs.push(FirewallRuleSpec::new(
                        &rule_name_for_rule("IPV6", &rule.id, &path, 0),
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
                            &rule_name_for_rule("DOH", &rule.id, &path, index),
                            &path,
                            ["protocol=TCP", "remoteport=443", remote.as_str()],
                        ));
                    }
                }
            }
        }

        let added = self.apply_firewall_delta(&specs)?;

        tracing::info!(
            mode = self.mode_label,
            count = added,
            "applied firewall hardening rules"
        );
        *self.firewall_process_fingerprint.write() =
            Some(process_fingerprint(config, running_processes));
        Ok(added)
    }

    fn apply_firewall_delta(&self, desired: &[FirewallRuleSpec]) -> Result<usize> {
        let previous = self.installed_firewall_specs.read().clone();
        let (changed, stale) = firewall_delta(&previous, desired);

        let mut applied: Vec<(FirewallRuleSpec, Option<FirewallRuleSpec>)> = Vec::new();
        for spec in &changed {
            if !add_firewall_block_rule(spec) {
                for (rollback, previous_spec) in &applied {
                    if let Some(previous_spec) = previous_spec {
                        let _ = add_firewall_block_rule(previous_spec);
                    } else {
                        let _ = delete_firewall_rule(&rollback.name);
                    }
                }
                return Err(anyhow!(
                    "failed to apply firewall rule '{}' while reconciling {} rules",
                    spec.name,
                    desired.len()
                ));
            }
            applied.push((spec.clone(), previous.get(&spec.name).cloned()));
        }

        for stale in stale {
            if !delete_firewall_rule(&stale) {
                tracing::warn!(rule = %stale, "failed to remove stale ProxyDuck firewall rule; retaining it for retry");
                return Err(anyhow!("failed to remove stale firewall rule '{stale}'"));
            }
        }

        let next = desired
            .iter()
            .cloned()
            .map(|spec| (spec.name.clone(), spec))
            .collect::<HashMap<_, _>>();
        *self.installed_firewall_specs.write() = next;
        Ok(desired.len())
    }

    fn reconcile_processes(&self, config: &AppConfig, processes: &[ProcessInfo]) -> Result<bool> {
        let _firewall_guard = self.firewall_transaction_lock.lock();
        if !self.running.load(Ordering::SeqCst) || !config.runtime.enabled {
            return Ok(false);
        }
        if self.strict_fail_closed_required.load(Ordering::SeqCst)
            || self.fail_closed_active.load(Ordering::SeqCst)
        {
            let count = self.apply_strict_fail_closed(
                config,
                "strict fail-closed rules refreshed for the current process set".to_string(),
            )?;
            self.firewall_rule_count.store(count, Ordering::SeqCst);
            return Ok(count > 0);
        }
        let policy_enabled = config.runtime.dns_enforced
            || config.runtime.ipv6_blocked
            || config.runtime.doh_blocked;
        if !policy_enabled {
            return Ok(false);
        }
        let fingerprint = process_fingerprint(config, processes);
        if self.firewall_process_fingerprint.read().as_ref() == Some(&fingerprint) {
            return Ok(false);
        }
        let count = match self.apply_firewall_rules_for_processes(config, processes) {
            Ok(count) => count,
            Err(error)
                if matches!(
                    config.runtime.leak_protection_mode,
                    LeakProtectionMode::Strict
                ) =>
            {
                self.apply_strict_fail_closed(
                    config,
                    format!("process firewall reconciliation failed: {error}"),
                )?
            }
            Err(error) => return Err(error),
        };
        self.firewall_rule_count.store(count, Ordering::SeqCst);
        Ok(true)
    }

    fn apply_strict_fail_closed(&self, config: &AppConfig, cause: String) -> Result<usize> {
        self.strict_fail_closed_required
            .store(true, Ordering::SeqCst);
        let processes = list_processes();
        let count = self.apply_fail_closed_rules_for_processes(config, &processes)?;
        self.firewall_rule_count.store(count, Ordering::SeqCst);
        self.fail_closed_active.store(count > 0, Ordering::SeqCst);
        *self.last_error.write() = Some(if count > 0 {
            format!("{cause}; strict fail-closed rules are active ({count} rules)")
        } else {
            format!("{cause}; strict fail-closed has no executable paths to block")
        });
        Ok(count)
    }

    fn apply_fail_closed_rules_for_processes(
        &self,
        config: &AppConfig,
        processes: &[crate::model::ProcessInfo],
    ) -> Result<usize> {
        let mut paths = HashSet::new();
        for rule in config.rules.iter().filter(|rule| rule.enabled) {
            for path in rule_executable_paths(rule, processes) {
                if !path.trim().is_empty() {
                    paths.insert(path);
                }
            }
        }

        let specs = paths
            .into_iter()
            .map(|path| {
                FirewallRuleSpec::new(&rule_name("FAIL-CLOSED", &path, 0), &path, ["protocol=ANY"])
            })
            .collect::<Vec<_>>();
        // Reconcile fail-closed rules with the same add-before-delete delta
        // used by normal firewall policy. This avoids a periodic unprotected
        // window while the process watcher refreshes an empty or changed set.
        let added = self.apply_firewall_delta(&specs)?;
        tracing::warn!(
            mode = self.mode_label,
            count = added,
            "strict fail-closed firewall rules applied"
        );
        Ok(added)
    }

    fn remove_firewall_rules(&self) {
        self.firewall_rule_count.store(0, Ordering::SeqCst);
        self.installed_firewall_specs.write().clear();
        if !self.delete_firewall_rules() {
            tracing::warn!(
                mode = self.mode_label,
                "one or more firewall cleanup commands failed"
            );
        }
    }

    fn delete_firewall_rules(&self) -> bool {
        if super::is_mock_data_plane() {
            tracing::debug!("mock data plane active; skipping firewall cleanup");
            return true;
        }

        let cleanup_script = r#"
$ErrorActionPreference = 'Stop'
@('ProxyDuck-*', 'ProxyDock-*', 'SmartFlow-*') |
  ForEach-Object {
    Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue |
      Remove-NetFirewallRule -ErrorAction Stop
  }
"#;
        let powershell_cleanup = Command::new(windows_system32_tool(
            "WindowsPowerShell\\v1.0\\powershell.exe",
        ))
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            cleanup_script,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
        if matches!(powershell_cleanup, Ok(status) if status.success()) {
            return true;
        }

        // Compatibility fallback for systems where the NetSecurity module is
        // unavailable. The PowerShell path above is the authoritative cleanup
        // because netsh's wildcard matching is not documented consistently.
        let mut successful = true;
        for prefix in [FIREWALL_RULE_PREFIX, "ProxyDock", "SmartFlow"] {
            let result = Command::new(windows_system32_tool("netsh.exe"))
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

fn wait_for_process_ready(child: &mut Child, name: &str, timeout: Duration) -> Result<()> {
    // A child process that merely remains alive is not proof that the driver
    // has captured traffic, but it is the only portable readiness signal
    // available before the Windows VM data-plane oracle is present.  Require
    // a short stable window so immediate startup failures are still caught;
    // the runtime status remains the place where endpoint/firewall health is
    // reported separately.
    let stable_window = Duration::from_millis(350);
    let started_at = Instant::now();
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("failed to check {name} process status"))?
        {
            return Err(anyhow!(
                "{name} exited during readiness with status: {status}"
            ));
        }
        if started_at.elapsed() >= stable_window {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "{name} did not become process-ready within {timeout:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
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

    fn reconcile_processes(&self, config: &AppConfig, processes: &[ProcessInfo]) -> Result<bool> {
        ProxifyreBackend::reconcile_processes(self, config, processes)
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
        if let Some(proc_info) = processes.iter().find(|entry| {
            entry.pid == *pid
                && rule
                    .matcher
                    .pid_creation_time
                    .is_some_and(|expected| entry.creation_time == Some(expected))
        }) {
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

fn process_fingerprint(config: &AppConfig, processes: &[ProcessInfo]) -> u64 {
    let mut hasher = DefaultHasher::new();
    let mut rows = Vec::new();
    for rule in config.rules.iter().filter(|rule| {
        let dns_policy = config.runtime.dns_enforced
            && (rule.force_dns || matches!(rule.dns.mode, crate::model::DnsMode::BlockPlaintext));
        let ipv6_policy = config.runtime.ipv6_blocked && rule.block_ipv6;
        let doh_policy = config.runtime.doh_blocked && rule.block_doh;
        rule.enabled && (dns_policy || ipv6_policy || doh_policy)
    }) {
        for path in rule_executable_paths(rule, processes) {
            rows.push((rule.id.as_str(), path));
        }
    }
    rows.sort();
    rows.hash(&mut hasher);
    hasher.finish()
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

#[cfg(test)]
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
    if super::is_mock_data_plane() {
        tracing::debug!(rule = %spec.name, "mock data plane active; skipping netsh add firewall rule");
        return true;
    }

    // Reconciliation can see paths that were already protected during the
    // previous snapshot.  Update an existing rule in place first so adding a
    // newly observed process does not fail merely because its sibling path
    // already has the same deterministic display name.
    let mut update = Command::new(windows_system32_tool("netsh.exe"));
    update
        .arg("advfirewall")
        .arg("firewall")
        .arg("set")
        .arg("rule")
        .arg(format!("name={}", spec.name))
        .arg("new")
        .arg("dir=out")
        .arg("action=block")
        .arg("profile=any")
        .arg("enable=yes")
        .arg(format!("program={}", spec.program));
    for item in &spec.extra {
        update.arg(item);
    }
    if matches!(update.stdout(Stdio::null()).stderr(Stdio::null()).status(), Ok(status) if status.success())
    {
        return true;
    }

    let mut command = Command::new(windows_system32_tool("netsh.exe"));
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

fn delete_firewall_rule(name: &str) -> bool {
    if super::is_mock_data_plane() {
        tracing::debug!(rule = %name, "mock data plane active; skipping netsh delete firewall rule");
        return true;
    }

    match Command::new(windows_system32_tool("netsh.exe"))
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={name}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) => status.success(),
        Err(error) => {
            tracing::warn!(rule = %name, error = %error, "failed to execute netsh for firewall rule cleanup");
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
    if super::is_mock_data_plane() {
        return config
            .proxies
            .iter()
            .any(|proxy| !normalize_endpoint(&proxy.socks5_proxy_endpoint).is_empty());
    }

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

fn rule_name_for_rule(kind: &str, rule_id: &str, path: &str, index: usize) -> String {
    format!(
        "{FIREWALL_RULE_PREFIX}-{kind}-{:016x}-{index}",
        stable_hash(&format!("{rule_id}\0{path}"))
    )
}

fn stable_hash(input: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn firewall_delta(
    previous: &HashMap<String, FirewallRuleSpec>,
    desired: &[FirewallRuleSpec],
) -> (Vec<FirewallRuleSpec>, Vec<String>) {
    let changed = desired
        .iter()
        .filter(|spec| previous.get(&spec.name) != Some(*spec))
        .cloned()
        .collect::<Vec<_>>();
    let desired_names = desired
        .iter()
        .map(|spec| spec.name.as_str())
        .collect::<HashSet<_>>();
    let stale = previous
        .keys()
        .filter(|name| !desired_names.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    (changed, stale)
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
            password_ref: None,
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
                "local-socks".to_string(),
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
    fn firewall_fingerprint_ignores_unrelated_process_churn() {
        let config = AppConfig {
            rules: vec![Rule::new(
                "browser protection".to_string(),
                MatchCriteria {
                    app_names: vec!["browser.exe".to_string()],
                    ..Default::default()
                },
                "local-socks".to_string(),
            )],
            ..Default::default()
        };
        let browser = ProcessInfo {
            pid: 10,
            creation_time: Some(100),
            name: "browser.exe".to_string(),
            exe: "C:\\Apps\\browser.exe".to_string(),
        };
        let unrelated_a = ProcessInfo {
            pid: 11,
            creation_time: Some(200),
            name: "helper.exe".to_string(),
            exe: "C:\\Apps\\helper.exe".to_string(),
        };
        let unrelated_b = ProcessInfo {
            creation_time: Some(300),
            ..unrelated_a.clone()
        };
        assert_eq!(
            process_fingerprint(&config, &[browser.clone(), unrelated_a]),
            process_fingerprint(&config, &[browser, unrelated_b])
        );
    }

    #[test]
    fn firewall_fingerprint_tracks_plaintext_dns_policy() {
        let mut config = AppConfig {
            runtime: crate::model::RuntimeToggles {
                dns_enforced: true,
                ..Default::default()
            },
            rules: vec![Rule::new(
                "plaintext dns protection".to_string(),
                MatchCriteria {
                    app_names: vec!["browser.exe".to_string()],
                    ..Default::default()
                },
                "local-socks".to_string(),
            )],
            ..Default::default()
        };
        config.rules[0].force_dns = false;
        config.rules[0].dns.mode = crate::model::DnsMode::BlockPlaintext;
        let browser = ProcessInfo {
            pid: 10,
            creation_time: Some(100),
            name: "browser.exe".to_string(),
            exe: "C:\\Apps\\browser.exe".to_string(),
        };
        let without_browser = process_fingerprint(&config, &[]);
        let with_browser = process_fingerprint(&config, &[browser]);
        assert_ne!(without_browser, with_browser);
    }

    #[test]
    fn fail_closed_paths_cover_name_pid_wildcard_and_explicit_exe_selectors() {
        let mut pid_rule = Rule::new(
            "pid rule".to_string(),
            MatchCriteria {
                pids: vec![42],
                pid_creation_time: Some(9001),
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        pid_rule.matcher.exe_paths = vec!["C:\\Pinned\\pinned.exe".to_string()];
        let name_rule = Rule::new(
            "name rule".to_string(),
            MatchCriteria {
                app_names: vec!["browser.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        let wildcard_rule = Rule::new(
            "wildcard rule".to_string(),
            MatchCriteria {
                wildcard: Some("*helper*".to_string()),
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        let processes = vec![
            ProcessInfo {
                pid: 42,
                creation_time: Some(9001),
                name: "worker.exe".to_string(),
                exe: "C:\\Apps\\worker.exe".to_string(),
            },
            ProcessInfo {
                pid: 7,
                creation_time: Some(10),
                name: "Browser.EXE".to_string(),
                exe: "C:\\Apps\\browser.exe".to_string(),
            },
            ProcessInfo {
                pid: 8,
                creation_time: Some(11),
                name: "helper.exe".to_string(),
                exe: "C:\\Apps\\helper.exe".to_string(),
            },
        ];

        assert_eq!(
            rule_executable_paths(&pid_rule, &processes),
            vec![
                "C:\\Apps\\worker.exe".to_string(),
                "C:\\Pinned\\pinned.exe".to_string()
            ]
        );
        assert_eq!(
            rule_executable_paths(&name_rule, &processes),
            vec!["C:\\Apps\\browser.exe".to_string()]
        );
        assert_eq!(
            rule_executable_paths(&wildcard_rule, &processes),
            vec!["C:\\Apps\\helper.exe".to_string()]
        );
    }

    #[test]
    fn fail_closed_pid_selector_rejects_reused_process_creation_time() {
        let rule = Rule::new(
            "pid rule".to_string(),
            MatchCriteria {
                pids: vec![42],
                pid_creation_time: Some(9001),
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        let reused = ProcessInfo {
            pid: 42,
            creation_time: Some(1),
            name: "reused.exe".to_string(),
            exe: "C:\\Apps\\reused.exe".to_string(),
        };

        assert!(rule_executable_paths(&rule, &[reused]).is_empty());
    }

    #[test]
    fn strict_fail_closed_resolves_process_that_appears_after_empty_snapshot() {
        let rule = Rule::new(
            "browser rule".to_string(),
            MatchCriteria {
                app_names: vec!["browser.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        assert!(rule_executable_paths(&rule, &[]).is_empty());
        let browser = ProcessInfo {
            pid: 21,
            creation_time: Some(123),
            name: "browser.exe".to_string(),
            exe: "C:\\Apps\\browser.exe".to_string(),
        };
        assert_eq!(
            rule_executable_paths(&rule, &[browser]),
            vec!["C:\\Apps\\browser.exe".to_string()]
        );
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

    #[test]
    fn firewall_delta_reuses_existing_specs_and_removes_stale_names() {
        let keep = FirewallRuleSpec::new("keep", "keep.exe", ["protocol=TCP"]);
        let changed = FirewallRuleSpec::new("changed", "changed.exe", ["protocol=UDP"]);
        let stale = FirewallRuleSpec::new("stale", "stale.exe", ["protocol=ANY"]);
        let previous = HashMap::from([
            (keep.name.clone(), keep.clone()),
            (
                changed.name.clone(),
                FirewallRuleSpec::new("changed", "old.exe", ["protocol=UDP"]),
            ),
            (stale.name.clone(), stale),
        ]);
        let (to_apply, to_remove) = firewall_delta(&previous, &[keep, changed.clone()]);
        assert_eq!(to_apply, vec![changed]);
        assert_eq!(to_remove, vec!["stale"]);
    }
}
