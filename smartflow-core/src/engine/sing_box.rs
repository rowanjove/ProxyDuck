use std::{
    fs::OpenOptions,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Value};

use crate::{
    engine::ProxyEngine,
    model::{AppConfig, DataPlanePhase, DataPlaneStatus, DestinationMatch, EngineMode, Protocol},
    process::{list_processes, rule_priority},
    routing_plan::{
        compile_routing_plan, PlannedBlockedRoute, PlannedDirectRoute, PlannedProxyRoute,
        PlannedSelector, PlannedSelectorKind,
    },
};

const CONFIG_FILE: &str = "sing-box.json";
const TUN_SUBNET_CANDIDATES: &[&str] = &[
    "172.19.0.1/30",
    "172.20.0.1/30",
    "172.21.0.1/30",
    "198.18.0.1/30",
];

pub struct SingBoxEngine {
    running: AtomicBool,
    desired_enabled: AtomicBool,
    active_rules: AtomicUsize,
    child: Mutex<Option<Child>>,
    job: Mutex<Option<crate::engine::ProcessJobGuard>>,
    mock_child_pid: AtomicU32,
    runtime_config_path: RwLock<Option<PathBuf>>,
    last_error: RwLock<Option<String>>,
}

impl Default for SingBoxEngine {
    fn default() -> Self {
        Self {
            running: AtomicBool::new(false),
            desired_enabled: AtomicBool::new(false),
            active_rules: AtomicUsize::new(0),
            child: Mutex::new(None),
            job: Mutex::new(None),
            mock_child_pid: AtomicU32::new(0),
            runtime_config_path: RwLock::new(None),
            last_error: RwLock::new(None),
        }
    }
}

impl SingBoxEngine {
    fn apply(&self, config: &AppConfig) -> Result<()> {
        let strict = matches!(
            config.runtime.leak_protection_mode,
            crate::model::LeakProtectionMode::Strict
        );
        self.desired_enabled
            .store(config.runtime.enabled, Ordering::SeqCst);
        self.active_rules.store(
            config.rules.iter().filter(|rule| rule.enabled).count(),
            Ordering::SeqCst,
        );
        self.stop_child();
        self.cleanup_runtime_config();
        *self.last_error.write() = None;

        if !config.runtime.enabled {
            return Ok(());
        }

        let executable = resolve_sing_box_executable()
            .ok_or_else(|| anyhow!("sing-box.exe was not found; set PROXYDUCK_SING_BOX_PATH"))?;
        if config.runtime.dns_enforced && strict {
            return Err(anyhow!(
                "sing-box cannot enforce the configured DNS policy; disable dns_enforced or choose an engine with DNS policy support"
            ));
        }
        if config.runtime.dns_enforced && !strict {
            tracing::warn!(
                "compatibility mode allows sing-box to run without the configured DNS enforcement"
            );
        }
        let plan = compile_routing_plan(config, &list_processes())?;
        if plan.proxy_routes.is_empty()
            && plan.direct_selectors.is_empty()
            && plan.direct_routes.is_empty()
            && plan.blocked_routes.is_empty()
        {
            let message = "routing plan contains no process routes".to_string();
            *self.last_error.write() = Some(message.clone());
            return Err(anyhow!(message));
        }
        let has_ephemeral_pid_selector = plan.proxy_routes.iter().any(|route| {
            route
                .selectors
                .iter()
                .any(|selector| matches!(selector.kind, PlannedSelectorKind::ProcessInstance))
        }) || plan.direct_routes.iter().any(|route| {
            route
                .selectors
                .iter()
                .any(|selector| matches!(selector.kind, PlannedSelectorKind::ProcessInstance))
        }) || plan.blocked_routes.iter().any(|route| {
            route
                .selectors
                .iter()
                .any(|selector| matches!(selector.kind, PlannedSelectorKind::ProcessInstance))
        });
        if has_ephemeral_pid_selector {
            return Err(anyhow!(
                "sing-box adapter cannot bind ephemeral PID selectors yet"
            ));
        }
        if let Some(rule) = config
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .find(|rule| {
                crate::routing_plan::unsupported_policy_diagnostic(rule).is_some()
                    || !matches!(rule.dns.mode, crate::model::DnsMode::Inherit)
                    || (rule.force_dns && rule.protocols.contains(&Protocol::Dns))
            })
        {
            if !strict {
                tracing::warn!(
                    rule_id = %rule.id,
                    "compatibility mode allows sing-box to apply a broader route for unsupported policy constraints"
                );
            } else {
                return Err(anyhow!(
                    "sing-box cannot compile policy constraints for rule '{}'",
                    rule.id
                ));
            }
        }

        let tun_address = choose_tun_subnet()?;
        let runtime_config = build_sing_box_config(
            &plan.proxy_routes,
            &[],
            &plan.direct_routes,
            &plan.blocked_routes,
            &ordered_rule_ids(config),
            &tun_address,
        )?;
        if super::is_mock_data_plane() {
            tracing::debug!("mock data plane active; skipping sing-box config write and check");
            self.mock_child_pid
                .store(std::process::id(), Ordering::SeqCst);
            return Ok(());
        }

        let config_path = proxyduck_common::resolve_app_dir()?.join(CONFIG_FILE);
        let body = serde_json::to_vec_pretty(&runtime_config)?;
        crate::config::atomic_write(&config_path, &body)?;
        *self.runtime_config_path.write() = Some(config_path.clone());
        if let Err(error) = proxyduck_common::harden_active_path(&config_path) {
            self.cleanup_runtime_config();
            return Err(error).with_context(|| {
                format!(
                    "failed to harden sing-box runtime config: {}",
                    config_path.display()
                )
            });
        }

        let check = match Command::new(&executable)
            .args(["check", "-c"])
            .arg(&config_path)
            .output()
            .with_context(|| {
                format!(
                    "failed to validate sing-box config with {}",
                    executable.display()
                )
            }) {
            Ok(output) => output,
            Err(error) => {
                self.cleanup_runtime_config();
                return Err(error);
            }
        };
        if !check.status.success() {
            let detail = String::from_utf8_lossy(&check.stderr).trim().to_string();
            let detail = if detail.is_empty() {
                String::from_utf8_lossy(&check.stdout).trim().to_string()
            } else {
                detail
            };
            let message = if detail.is_empty() {
                format!(
                    "sing-box config validation failed with status {}",
                    check.status
                )
            } else {
                format!("sing-box config validation failed: {detail}")
            };
            *self.last_error.write() = Some(message.clone());
            self.cleanup_runtime_config();
            return Err(anyhow!(message));
        }

        let app_dir = match proxyduck_common::resolve_app_dir() {
            Ok(path) => path,
            Err(error) => {
                self.cleanup_runtime_config();
                return Err(error);
            }
        };
        let stdout_log = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(app_dir.join("proxyduck-sing-box.stdout.log"))
            .context("failed to open sing-box stdout log")
        {
            Ok(file) => file,
            Err(error) => {
                self.cleanup_runtime_config();
                return Err(error);
            }
        };
        let stderr_log = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(app_dir.join("proxyduck-sing-box.stderr.log"))
            .context("failed to open sing-box stderr log")
        {
            Ok(file) => file,
            Err(error) => {
                self.cleanup_runtime_config();
                return Err(error);
            }
        };
        let mut child = match Command::new(&executable)
            .args(["run", "-c"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_log))
            .stderr(Stdio::from(stderr_log))
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                self.cleanup_runtime_config();
                return Err(error)
                    .with_context(|| format!("failed to start {}", executable.display()));
            }
        };
        let job_guard = match crate::engine::ProcessJobGuard::assign(&child) {
            Ok(guard) => Some(guard),
            Err(error) => {
                tracing::warn!(%error, "failed to attach sing-box child process to Windows JobObject");
                None
            }
        };
        if let Err(error) = wait_for_process_ready(&mut child, Duration::from_secs(5)) {
            let _ = child.kill();
            let _ = child.wait();
            self.cleanup_runtime_config();
            return Err(error);
        }
        *self.child.lock() = Some(child);
        *self.job.lock() = job_guard;
        Ok(())
    }

    fn stop_child(&self) {
        self.mock_child_pid.store(0, Ordering::SeqCst);
        if let Some(mut child) = self.child.lock().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        *self.job.lock() = None;
    }

    fn cleanup_runtime_config(&self) {
        let path = self.runtime_config_path.write().take().or_else(|| {
            proxyduck_common::resolve_app_dir()
                .ok()
                .map(|dir| dir.join(CONFIG_FILE))
        });
        let Some(path) = path else {
            return;
        };
        if let Err(error) = std::fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, path = %path.display(), "failed to remove sing-box runtime config");
            }
        }
    }
}

fn wait_for_process_ready(child: &mut Child, timeout: Duration) -> Result<()> {
    // Process liveness is a provisional readiness signal only; actual TUN,
    // DNS and packet-path health are reported by the runtime status and still
    // require Windows VM verification.  Catch immediate exits, then accept a
    // short stable process window instead of timing out every healthy child.
    let stable_window = Duration::from_millis(350);
    let started_at = std::time::Instant::now();
    let deadline = started_at + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(anyhow!(
                "sing-box exited during readiness with status {status}"
            ));
        }
        if started_at.elapsed() >= stable_window {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "sing-box did not become process-ready within {timeout:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

impl ProxyEngine for SingBoxEngine {
    fn mode(&self) -> EngineMode {
        EngineMode::SingBox
    }

    fn start(&self, config: &AppConfig) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);
        self.apply(config)
    }

    fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.desired_enabled.store(false, Ordering::SeqCst);
        self.stop_child();
        self.cleanup_runtime_config();
        Ok(())
    }

    fn reload_rules(&self, config: &AppConfig) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("engine is not running"));
        }
        self.apply(config)
    }

    fn status(&self) -> DataPlaneStatus {
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
                Ok(Some(status)) => {
                    child.take();
                    *self.job.lock() = None;
                    child_pid = None;
                    *self.last_error.write() =
                        Some(format!("sing-box exited unexpectedly with status {status}"));
                }
                Ok(None) => {}
                Err(error) => *self.last_error.write() = Some(error.to_string()),
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
        } else {
            DataPlanePhase::Degraded
        };
        DataPlaneStatus {
            phase,
            backend_name: "sing-box".to_string(),
            child_pid,
            active_rules: self.active_rules.load(Ordering::SeqCst),
            firewall_rules: 0,
            proxy_endpoint_reachable: None,
            fail_closed_active: false,
            message,
            checked_at: chrono::Utc::now(),
        }
    }

    fn maintain(&self, config: &AppConfig) -> Result<bool> {
        if !self.running.load(Ordering::SeqCst) || !config.runtime.enabled {
            return Ok(false);
        }
        let _ = self.status();
        if self.child.lock().is_none() {
            self.apply(config)?;
            return Ok(true);
        }
        Ok(false)
    }
}

pub fn resolve_sing_box_executable() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = proxyduck_common::sing_box_path_from_env() {
        candidates.push(path);
    }
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            candidates.push(directory.join("sing-box.exe"));
            candidates.push(directory.join("sing-box"));
        }
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            candidates.push(directory.join("sing-box.exe"));
            candidates.push(directory.join("sing-box").join("sing-box.exe"));
        }
    }
    if let Ok(directory) = std::env::current_dir() {
        candidates.push(directory.join("third_party/sing-box/sing-box.exe"));
        candidates.push(directory.join("sing-box.exe"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn build_sing_box_config(
    routes: &[PlannedProxyRoute],
    direct: &[PlannedSelector],
    direct_routes: &[PlannedDirectRoute],
    blocked: &[PlannedBlockedRoute],
    rule_order: &[String],
    tun_address: &str,
) -> Result<Value> {
    let mut outbounds = vec![json!({ "type": "direct", "tag": "direct" })];
    let mut rules = Vec::new();

    let append_blocked = |rules: &mut Vec<Value>, route: &PlannedBlockedRoute| {
        let network = networks(&route.protocols);
        for selector in &route.selectors {
            rules.push(process_block_rule(
                selector,
                &network,
                Some(&route.destination),
                route.reject,
            ));
        }
    };
    let append_direct = |rules: &mut Vec<Value>, route: &PlannedDirectRoute| {
        let network = networks(&route.protocols);
        for selector in &route.selectors {
            rules.push(process_rule(
                selector,
                "direct",
                Some(&network),
                Some(&route.destination),
            ));
        }
    };

    if rule_order.is_empty() {
        for route in blocked {
            append_blocked(&mut rules, route);
        }
        for route in direct_routes {
            append_direct(&mut rules, route);
        }
    } else {
        for rule_id in rule_order {
            if let Some(route) = blocked.iter().find(|route| route.rule_id == *rule_id) {
                append_blocked(&mut rules, route);
            }
            if let Some(route) = direct_routes.iter().find(|route| route.rule_id == *rule_id) {
                append_direct(&mut rules, route);
            }
            if let Some(route) = routes.iter().find(|route| route.rule_id == *rule_id) {
                append_proxy_route(&mut rules, &mut outbounds, route, routes)?;
            }
        }
    }
    for selector in direct {
        rules.push(process_rule(selector, "direct", None, None));
    }

    if !rule_order.is_empty() {
        // Routes not present in the config order are retained defensively so
        // a malformed/partial plan cannot silently lose a data-plane rule.
        for route in routes {
            if !rule_order.iter().any(|rule_id| rule_id == &route.rule_id) {
                append_proxy_route(&mut rules, &mut outbounds, route, routes)?;
            }
        }
    }

    if rule_order.is_empty() {
        for route in routes {
            append_proxy_route(&mut rules, &mut outbounds, route, routes)?;
        }
    }

    Ok(json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [{
            "type": "tun",
            "tag": "proxyduck-tun",
            "interface_name": "ProxyDuck",
            "address": [tun_address],
            "auto_route": true,
            "strict_route": true,
            "stack": "system"
        }],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": true,
            "rules": rules,
            "final": "direct"
        }
    }))
}

fn append_proxy_route(
    rules: &mut Vec<Value>,
    outbounds: &mut Vec<Value>,
    route: &PlannedProxyRoute,
    routes: &[PlannedProxyRoute],
) -> Result<()> {
    let index = routes
        .iter()
        .position(|candidate| std::ptr::eq(candidate, route))
        .unwrap_or_default();
    let tag = format!("proxy-{index}");
    let (server, server_port) = split_endpoint(&route.endpoint)?;
    let mut outbound = serde_json::Map::from_iter([
        ("type".to_string(), json!("socks")),
        ("tag".to_string(), json!(tag.clone())),
        ("server".to_string(), json!(server)),
        ("server_port".to_string(), json!(server_port)),
        ("version".to_string(), json!("5")),
    ]);
    if let Some(username) = &route.username {
        outbound.insert("username".to_string(), json!(username));
    }
    if let Some(password) = &route.password {
        outbound.insert("password".to_string(), json!(password));
    }
    outbounds.push(Value::Object(outbound));
    let network = networks(&route.protocols);
    for selector in &route.selectors {
        rules.push(process_rule(
            selector,
            &tag,
            Some(&network),
            Some(&route.destination),
        ));
    }
    Ok(())
}

fn ordered_rule_ids(config: &AppConfig) -> Vec<String> {
    let mut rules = config
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .collect::<Vec<_>>();
    rules.sort_by_key(|rule| rule_priority(rule));
    rules.into_iter().map(|rule| rule.id.clone()).collect()
}

fn process_block_rule(
    selector: &PlannedSelector,
    network: &[&str],
    destination: Option<&DestinationMatch>,
    reject: bool,
) -> Value {
    let mut rule = process_rule(selector, "direct", Some(&network.to_vec()), destination);
    if let Some(object) = rule.as_object_mut() {
        object.remove("outbound");
        object.insert("action".to_string(), json!("reject"));
        object.insert(
            "method".to_string(),
            json!(if reject { "default" } else { "drop" }),
        );
    }
    rule
}

fn choose_tun_subnet() -> Result<String> {
    let route_table = route_table_snapshot();
    if let Some(requested) = proxyduck_common::tun_subnet_from_env() {
        if !valid_tun_subnet(&requested) {
            return Err(anyhow!(
                "{} must be an IPv4 /30 subnet address",
                proxyduck_common::TUN_SUBNET_ENV
            ));
        }
        if tun_subnet_conflicts(&route_table, &requested) {
            return Err(anyhow!(
                "requested TUN subnet {requested} conflicts with an existing route"
            ));
        }
        return Ok(requested);
    }
    TUN_SUBNET_CANDIDATES
        .iter()
        .copied()
        .find(|candidate| !tun_subnet_conflicts(&route_table, candidate))
        .map(str::to_string)
        .ok_or_else(|| anyhow!("all ProxyDuck TUN subnet candidates conflict with existing routes"))
}

fn route_table_snapshot() -> String {
    if super::is_mock_data_plane() {
        return String::new();
    }

    #[cfg(target_os = "windows")]
    let command = (
        std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join("route.exe"),
        ["print", "-4"],
    );
    #[cfg(not(target_os = "windows"))]
    let command = (std::path::PathBuf::from("ip"), ["route"]);
    std::process::Command::new(command.0)
        .args(command.1)
        .output()
        .map(|output| {
            format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .unwrap_or_default()
}

fn valid_tun_subnet(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    prefix == "30" && address.parse::<std::net::Ipv4Addr>().is_ok()
}

fn tun_subnet_conflicts(route_table: &str, candidate: &str) -> bool {
    let Some((address, prefix)) = candidate.split_once('/') else {
        return true;
    };
    let Ok(address) = address.parse::<std::net::Ipv4Addr>() else {
        return true;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return true;
    };
    let candidate_range = ipv4_range(u32::from(address), prefix);
    parse_route_ranges(route_table)
        .into_iter()
        .any(|route_range| ranges_overlap(candidate_range, route_range))
}

fn parse_route_ranges(route_table: &str) -> Vec<(u32, u32)> {
    let mut ranges = Vec::new();
    for line in route_table.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        for token in &tokens {
            if let Some((address, prefix)) = token.split_once('/') {
                if let (Ok(address), Ok(prefix)) =
                    (address.parse::<std::net::Ipv4Addr>(), prefix.parse::<u8>())
                {
                    if prefix > 0 && prefix <= 32 {
                        ranges.push(ipv4_range(u32::from(address), prefix));
                    }
                }
            }
        }
        if tokens.len() >= 2 {
            if let (Ok(address), Ok(netmask)) = (
                tokens[0].parse::<std::net::Ipv4Addr>(),
                tokens[1].parse::<std::net::Ipv4Addr>(),
            ) {
                if let Some(prefix) = netmask_prefix(u32::from(netmask)) {
                    if prefix > 0 {
                        ranges.push(ipv4_range(u32::from(address), prefix));
                    }
                }
            }
        }
    }
    ranges
}

fn ipv4_range(address: u32, prefix: u8) -> (u32, u32) {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = address & mask;
    (start, start | !mask)
}

fn netmask_prefix(mask: u32) -> Option<u8> {
    let prefix = mask.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (mask == expected).then_some(prefix)
}

fn ranges_overlap(left: (u32, u32), right: (u32, u32)) -> bool {
    left.0 <= right.1 && right.0 <= left.1
}

fn process_rule(
    selector: &PlannedSelector,
    outbound: &str,
    network: Option<&Vec<&str>>,
    destination: Option<&DestinationMatch>,
) -> Value {
    let selector = match selector.kind {
        PlannedSelectorKind::ProcessName => json!({ "process_name": [&selector.value] }),
        PlannedSelectorKind::ProcessPath => json!({ "process_path": [&selector.value] }),
        // The adapter rejects ProcessInstance routes before generation. Keep
        // this branch impossible-but-serializable for exhaustive IR handling.
        PlannedSelectorKind::ProcessInstance => {
            json!({ "process_path": ["__proxyduck_unresolved_pid__"] })
        }
        PlannedSelectorKind::Wildcard => {
            json!({ "process_path_regex": [glob_to_regex(&selector.value)] })
        }
    };
    let mut rule = selector.as_object().cloned().unwrap_or_default();
    rule.insert("action".to_string(), json!("route"));
    rule.insert("outbound".to_string(), json!(outbound));
    if let Some(network) = network {
        rule.insert("network".to_string(), json!(network));
    }
    if let Some(destination) = destination.filter(|destination| !destination.is_empty()) {
        let (exact_domains, suffix_domains): (Vec<_>, Vec<_>) = destination
            .domains
            .iter()
            .partition(|domain| !domain.starts_with("*."));
        if !exact_domains.is_empty() {
            rule.insert("domain".to_string(), json!(exact_domains));
        }
        if !suffix_domains.is_empty() {
            let suffixes = suffix_domains
                .into_iter()
                .map(|domain| domain.strip_prefix("*.").unwrap_or(domain.as_str()))
                .collect::<Vec<_>>();
            rule.insert("domain_suffix".to_string(), json!(suffixes));
        }
        if !destination.ip_cidrs.is_empty() {
            rule.insert("ip_cidr".to_string(), json!(destination.ip_cidrs));
        }
        if !destination.ports.is_empty() {
            rule.insert("port".to_string(), json!(destination.ports));
        }
    }
    Value::Object(rule)
}

fn glob_to_regex(pattern: &str) -> String {
    let pattern = pattern.trim().replace('/', "\\");
    let path_scoped = pattern.contains('\\');
    let mut regex = if path_scoped {
        String::from("(?i)^")
    } else {
        // A basename wildcard is evaluated against the full executable path
        // by sing-box.  Keep the process matcher semantics by allowing the
        // basename at the start of a value or after a path separator, while
        // still anchoring the glob itself so `Code*.exe` cannot match
        // `OtherCode.exe` accidentally.
        String::from("(?i)(?:^|.*[\\\\/])")
    };
    for character in pattern.chars() {
        match character {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(character);
            }
            _ => regex.push(character),
        }
    }
    regex.push('$');
    regex
}

fn networks(protocols: &[Protocol]) -> Vec<&'static str> {
    let mut result = Vec::new();
    if protocols.contains(&Protocol::Tcp) {
        result.push("tcp");
    }
    if protocols.contains(&Protocol::Udp) {
        result.push("udp");
    }
    result
}

fn split_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let (host, port) = endpoint
        .trim()
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid SOCKS5 endpoint: {endpoint}"))?;
    let port = port.parse::<u16>()?;
    Ok((host.trim_matches(['[', ']']).to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing_plan::{PlannedBlockedRoute, PlannedProxyRoute};

    #[test]
    fn generates_tun_process_routes_and_unique_outbounds() {
        let routes = vec![PlannedProxyRoute {
            rule_id: "rule".into(),
            proxy_id: "proxy".into(),
            patterns: vec!["code.exe".into(), "C:\\Apps\\Code.exe".into()],
            selectors: vec![
                PlannedSelector {
                    kind: PlannedSelectorKind::ProcessName,
                    value: "code.exe".into(),
                },
                PlannedSelector {
                    kind: PlannedSelectorKind::ProcessPath,
                    value: "C:\\Apps\\Code.exe".into(),
                },
            ],
            endpoint: "127.0.0.1:7897".into(),
            username: None,
            password: None,
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            destination: DestinationMatch {
                domains: vec!["example.com".into()],
                ip_cidrs: vec!["1.1.1.0/24".into()],
                ports: vec![443],
            },
        }];
        let config = build_sing_box_config(&routes, &[], &[], &[], &[], "172.19.0.1/30").unwrap();
        assert_eq!(config["inbounds"][0]["type"], "tun");
        assert_eq!(config["outbounds"][1]["type"], "socks");
        assert_eq!(config["route"]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(config["route"]["final"], "direct");
        assert!(config["outbounds"][1].get("username").is_none());
        assert_eq!(config["route"]["rules"][0]["domain"][0], "example.com");
        assert_eq!(config["route"]["rules"][0]["port"][0], 443);
    }

    #[test]
    fn wildcard_selector_becomes_a_case_insensitive_process_regex() {
        let selector = PlannedSelector {
            kind: PlannedSelectorKind::Wildcard,
            value: "Code*.exe".into(),
        };
        let rule = process_rule(&selector, "proxy", None, None);
        assert_eq!(
            rule["process_path_regex"][0],
            "(?i)(?:^|.*[\\\\/])Code.*\\.exe$"
        );
    }

    #[test]
    fn blocked_routes_preserve_drop_vs_reject_semantics() {
        let selector = PlannedSelector {
            kind: PlannedSelectorKind::ProcessName,
            value: "browser.exe".into(),
        };
        let blocked = vec![
            PlannedBlockedRoute {
                rule_id: "block".into(),
                selectors: vec![selector.clone()],
                protocols: vec![Protocol::Tcp],
                destination: DestinationMatch::default(),
                reject: false,
            },
            PlannedBlockedRoute {
                rule_id: "reject".into(),
                selectors: vec![PlannedSelector {
                    value: "curl.exe".into(),
                    ..selector
                }],
                protocols: vec![Protocol::Tcp],
                destination: DestinationMatch::default(),
                reject: true,
            },
        ];
        let config = build_sing_box_config(&[], &[], &[], &blocked, &[], "172.19.0.1/30").unwrap();
        assert_eq!(config["route"]["rules"][0]["method"], "drop");
        assert_eq!(config["route"]["rules"][1]["method"], "default");
    }

    #[test]
    fn direct_destination_routes_keep_their_scope() {
        let direct = vec![PlannedDirectRoute {
            rule_id: "direct-example".into(),
            selectors: vec![PlannedSelector {
                kind: PlannedSelectorKind::ProcessName,
                value: "browser.exe".into(),
            }],
            protocols: vec![Protocol::Tcp],
            destination: DestinationMatch {
                domains: vec!["example.com".into()],
                ip_cidrs: Vec::new(),
                ports: vec![443],
            },
        }];
        let config = build_sing_box_config(&[], &[], &direct, &[], &[], "172.19.0.1/30").unwrap();
        assert_eq!(config["route"]["rules"][0]["domain"][0], "example.com");
        assert_eq!(config["route"]["rules"][0]["port"][0], 443);
    }

    #[test]
    fn ordered_routes_preserve_cross_action_rule_priority() {
        let direct = vec![PlannedDirectRoute {
            rule_id: "first".into(),
            selectors: vec![PlannedSelector {
                kind: PlannedSelectorKind::ProcessName,
                value: "browser.exe".into(),
            }],
            protocols: vec![Protocol::Tcp],
            destination: DestinationMatch {
                domains: vec!["first.example".into()],
                ..Default::default()
            },
        }];
        let proxy = vec![PlannedProxyRoute {
            rule_id: "second".into(),
            proxy_id: "proxy".into(),
            patterns: vec!["browser.exe".into()],
            selectors: vec![PlannedSelector {
                kind: PlannedSelectorKind::ProcessName,
                value: "browser.exe".into(),
            }],
            endpoint: "127.0.0.1:7897".into(),
            username: None,
            password: None,
            protocols: vec![Protocol::Tcp],
            destination: DestinationMatch {
                domains: vec!["second.example".into()],
                ..Default::default()
            },
        }];
        let config = build_sing_box_config(
            &proxy,
            &[],
            &direct,
            &[],
            &["first".into(), "second".into()],
            "172.19.0.1/30",
        )
        .unwrap();
        let rules = config["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outbound"], "direct");
        assert_eq!(rules[0]["domain"][0], "first.example");
        assert_eq!(rules[1]["outbound"], "proxy-0");
        assert_eq!(rules[1]["domain"][0], "second.example");
    }

    #[test]
    fn tun_subnet_selector_skips_route_conflicts() {
        let routes = "172.19.0.0 255.255.255.252 On-link\n10.0.0.0 255.0.0.0 gateway\n172.16.0.0 255.240.0.0 gateway";
        assert!(tun_subnet_conflicts(routes, "172.19.0.1/30"));
        assert!(tun_subnet_conflicts(routes, "172.20.0.1/30"));
        assert!(!tun_subnet_conflicts(routes, "198.18.0.1/30"));
        assert!(valid_tun_subnet("172.19.0.1/30"));
        assert!(!valid_tun_subnet("172.19.0.1/24"));
    }

    #[test]
    fn failed_start_can_be_recovered_by_disabling_runtime() {
        let engine = SingBoxEngine::default();
        let mut config = crate::model::AppConfig::default();
        config.runtime.enabled = true;
        config.rules.push(crate::model::Rule::new(
            "browser".into(),
            crate::model::MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        ));
        assert!(engine.start(&config).is_err());
        config.runtime.enabled = false;
        assert!(engine.reload_rules(&config).is_ok());
    }
}
