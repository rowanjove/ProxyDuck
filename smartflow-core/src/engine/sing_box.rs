use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use anyhow::{anyhow, Context, Result};
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Value};

use crate::{
    engine::ProxyEngine,
    model::{AppConfig, DataPlanePhase, DataPlaneStatus, EngineMode, Protocol},
    process::list_processes,
    routing_plan::{compile_routing_plan, PlannedProxyRoute, PlannedSelector, PlannedSelectorKind},
};

const CONFIG_FILE: &str = "sing-box.json";

pub struct SingBoxEngine {
    running: AtomicBool,
    desired_enabled: AtomicBool,
    active_rules: AtomicUsize,
    child: Mutex<Option<Child>>,
    last_error: RwLock<Option<String>>,
}

impl Default for SingBoxEngine {
    fn default() -> Self {
        Self {
            running: AtomicBool::new(false),
            desired_enabled: AtomicBool::new(false),
            active_rules: AtomicUsize::new(0),
            child: Mutex::new(None),
            last_error: RwLock::new(None),
        }
    }
}

impl SingBoxEngine {
    fn apply(&self, config: &AppConfig) -> Result<()> {
        self.desired_enabled
            .store(config.runtime.enabled, Ordering::SeqCst);
        self.active_rules.store(
            config.rules.iter().filter(|rule| rule.enabled).count(),
            Ordering::SeqCst,
        );
        self.stop_child();
        *self.last_error.write() = None;

        if !config.runtime.enabled {
            return Ok(());
        }

        let executable = resolve_sing_box_executable()
            .ok_or_else(|| anyhow!("sing-box.exe was not found; set PROXYDUCK_SING_BOX_PATH"))?;
        let plan = compile_routing_plan(config, &list_processes())?;
        if plan.proxy_routes.is_empty() {
            let message = "routing plan contains no SOCKS5 routes".to_string();
            *self.last_error.write() = Some(message.clone());
            return Err(anyhow!(message));
        }

        let runtime_config = build_sing_box_config(&plan.proxy_routes, &plan.direct_selectors)?;
        let config_path = proxyduck_common::resolve_app_dir()?.join(CONFIG_FILE);
        let body = serde_json::to_vec_pretty(&runtime_config)?;
        crate::config::atomic_write(&config_path, &body)?;

        let mut child = Command::new(&executable)
            .args(["run", "-c"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start {}", executable.display()))?;
        std::thread::sleep(std::time::Duration::from_millis(350));
        if let Some(status) = child.try_wait()? {
            let message = format!("sing-box exited immediately with status {status}");
            *self.last_error.write() = Some(message.clone());
            return Err(anyhow!(message));
        }
        *self.child.lock() = Some(child);
        Ok(())
    }

    fn stop_child(&self) {
        if let Some(mut child) = self.child.lock().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl ProxyEngine for SingBoxEngine {
    fn mode(&self) -> EngineMode {
        EngineMode::SingBox
    }

    fn start(&self, config: &AppConfig) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);
        if let Err(error) = self.apply(config) {
            self.running.store(false, Ordering::SeqCst);
            return Err(error);
        }
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.desired_enabled.store(false, Ordering::SeqCst);
        self.stop_child();
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
        let mut child_pid = child.as_ref().map(Child::id);
        if let Some(process) = child.as_mut() {
            match process.try_wait() {
                Ok(Some(status)) => {
                    child.take();
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
) -> Result<Value> {
    let mut outbounds = vec![json!({ "type": "direct", "tag": "direct" })];
    let mut rules = Vec::new();

    for selector in direct {
        rules.push(process_rule(selector, "direct", None));
    }
    for (index, route) in routes.iter().enumerate() {
        let tag = format!("proxy-{index}");
        let (server, server_port) = split_endpoint(&route.endpoint)?;
        let mut outbound = serde_json::Map::from_iter([
            ("type".to_string(), json!("socks")),
            ("tag".to_string(), json!(tag)),
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
            rules.push(process_rule(selector, &tag, Some(&network)));
        }
    }

    Ok(json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [{
            "type": "tun",
            "tag": "proxyduck-tun",
            "interface_name": "ProxyDuck",
            "address": ["172.19.0.1/30"],
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

fn process_rule(selector: &PlannedSelector, outbound: &str, network: Option<&Vec<&str>>) -> Value {
    let selector = match selector.kind {
        PlannedSelectorKind::ProcessName => json!({ "process_name": [&selector.value] }),
        PlannedSelectorKind::ProcessPath => json!({ "process_path": [&selector.value] }),
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
    Value::Object(rule)
}

fn glob_to_regex(pattern: &str) -> String {
    let mut regex = String::from("(?i).*");
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
    regex.push_str(".*");
    regex
}

fn networks(protocols: &[Protocol]) -> Vec<&'static str> {
    let mut result = Vec::new();
    if protocols.contains(&Protocol::Tcp) {
        result.push("tcp");
    }
    if protocols.contains(&Protocol::Udp) || protocols.contains(&Protocol::Dns) {
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
    use crate::routing_plan::PlannedProxyRoute;

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
        }];
        let config = build_sing_box_config(&routes, &[]).unwrap();
        assert_eq!(config["inbounds"][0]["type"], "tun");
        assert_eq!(config["outbounds"][1]["type"], "socks");
        assert_eq!(config["route"]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(config["route"]["final"], "direct");
        assert!(config["outbounds"][1].get("username").is_none());
    }

    #[test]
    fn wildcard_selector_becomes_a_case_insensitive_process_regex() {
        let selector = PlannedSelector {
            kind: PlannedSelectorKind::Wildcard,
            value: "Code*.exe".into(),
        };
        let rule = process_rule(&selector, "proxy", None);
        assert_eq!(rule["process_path_regex"][0], "(?i).*Code.*\\.exe.*");
    }
}
