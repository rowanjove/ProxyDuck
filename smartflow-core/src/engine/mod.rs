mod api_hook;
mod job;
mod proxifyre;
mod proxifyre_engine;
mod sing_box;
mod wfp;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static MOCK_DATA_PLANE: AtomicBool = AtomicBool::new(false);

pub fn is_mock_data_plane() -> bool {
    if MOCK_DATA_PLANE.load(Ordering::Relaxed) {
        return true;
    }
    if cfg!(test) {
        return true;
    }
    if std::env::var("PROXYDUCK_MOCK_DATA_PLANE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return true;
    }
    if let Ok(exe) = std::env::current_exe() {
        let exe_lossy = exe.to_string_lossy().to_ascii_lowercase();
        if exe_lossy.contains("deps\\proxyduck_") || exe_lossy.contains("deps/proxyduck_") {
            return true;
        }
    }
    false
}

pub fn set_mock_data_plane(enabled: bool) {
    MOCK_DATA_PLANE.store(enabled, Ordering::Relaxed);
}

use anyhow::{anyhow, Result};
use chrono::Utc;
use parking_lot::RwLock;

use crate::model::{
    AppConfig, DataPlanePhase, DataPlaneStatus, EngineCapability, EngineMode, ProcessInfo,
    Protocol, ProxyKind, RuntimeStats,
};

pub use api_hook::ApiHookEngine;
pub use job::ProcessJobGuard;
pub use proxifyre_engine::ProxiFyreEngine;
pub use sing_box::SingBoxEngine;
pub use wfp::WfpEngine;

pub trait DataPlaneBackend: Send + Sync {
    fn start(&self, config: &AppConfig) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn reload(&self, config: &AppConfig) -> Result<()>;
    fn status(&self) -> DataPlaneStatus;
    fn maintain(&self, config: &AppConfig) -> Result<bool>;
    fn reconcile_processes(&self, _config: &AppConfig, _processes: &[ProcessInfo]) -> Result<bool> {
        Ok(false)
    }
}

pub trait ProxyEngine: Send + Sync {
    fn mode(&self) -> EngineMode;
    fn start(&self, config: &AppConfig) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn reload_rules(&self, config: &AppConfig) -> Result<()>;
    fn status(&self) -> DataPlaneStatus;
    fn maintain(&self, config: &AppConfig) -> Result<bool>;
    fn reconcile_processes(&self, _config: &AppConfig, _processes: &[ProcessInfo]) -> Result<bool> {
        Ok(false)
    }
}

pub struct EngineManager {
    active: RwLock<Box<dyn ProxyEngine>>,
    stats: Arc<RwLock<RuntimeStats>>,
    startup_error: RwLock<Option<String>>,
}

impl EngineManager {
    pub fn new(mode: EngineMode, stats: Arc<RwLock<RuntimeStats>>) -> Self {
        let engine = create_engine(mode);
        Self {
            active: RwLock::new(engine),
            stats,
            startup_error: RwLock::new(None),
        }
    }

    pub fn mode(&self) -> EngineMode {
        self.active.read().mode()
    }

    pub fn start(&self, config: &AppConfig) -> Result<()> {
        if let Err(error) = self.active.read().start(config) {
            *self.startup_error.write() = Some(error.to_string());
            return Err(error);
        }
        *self.startup_error.write() = None;
        let mut stats = self.stats.write();
        stats.engine_mode = mode_name(self.mode());
        stats.started_at = Some(Utc::now());
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        let result = self.active.read().stop();
        if result.is_ok() {
            *self.startup_error.write() = None;
        }
        result
    }

    pub fn reload_rules(&self, config: &AppConfig) -> Result<()> {
        if let Err(error) = self.active.read().reload_rules(config) {
            *self.startup_error.write() = Some(error.to_string());
            return Err(error);
        }
        *self.startup_error.write() = None;
        self.stats.write().last_reload_at = Some(Utc::now());
        Ok(())
    }

    pub fn status(&self) -> DataPlaneStatus {
        let mut status = self.active.read().status();
        if let Some(error) = self.startup_error.read().clone() {
            status.phase = DataPlanePhase::Error;
            status.message = Some(error);
        }
        status
    }

    pub fn maintain(&self, config: &AppConfig) -> Result<bool> {
        let result = self.active.read().maintain(config);
        match &result {
            Ok(true) => *self.startup_error.write() = None,
            Err(error) => *self.startup_error.write() = Some(error.to_string()),
            Ok(false) => {}
        }
        result
    }

    pub fn reconcile_processes(
        &self,
        config: &AppConfig,
        processes: &[ProcessInfo],
    ) -> Result<bool> {
        let result = self.active.read().reconcile_processes(config, processes);
        if let Err(error) = &result {
            *self.startup_error.write() = Some(error.to_string());
        }
        result
    }

    pub fn switch_mode(
        &self,
        mode: EngineMode,
        config: &AppConfig,
        rollback_config: &AppConfig,
    ) -> Result<()> {
        let result = self.switch_mode_inner(mode, config, rollback_config);
        match &result {
            Ok(()) => *self.startup_error.write() = None,
            Err(error) => *self.startup_error.write() = Some(error.to_string()),
        }
        result
    }

    fn switch_mode_inner(
        &self,
        mode: EngineMode,
        config: &AppConfig,
        rollback_config: &AppConfig,
    ) -> Result<()> {
        let capability = capability_for(mode);
        if !capability.available {
            return Err(anyhow!(
                "engine '{}' is unavailable: {}",
                capability.display_name,
                capability
                    .unavailable_reason
                    .as_deref()
                    .unwrap_or("not implemented")
            ));
        }

        let mut active = self.active.write();
        if mode_name(active.mode()) == mode_name(mode) {
            return Ok(());
        }

        active.stop()?;

        let next = create_engine(mode);
        if let Err(error) = next.start(config) {
            let rollback = active.start(rollback_config);
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(anyhow!(
                    "engine switch failed: {error}; rollback failed: {rollback_error}"
                )),
            };
        }

        *active = next;
        drop(active);

        self.stats.write().engine_mode = mode_name(mode);
        Ok(())
    }
}

pub fn engine_capabilities() -> Vec<EngineCapability> {
    vec![
        EngineCapability {
            mode: EngineMode::ProxiFyre,
            display_name: "ProxiFyre".to_string(),
            backend_name: "proxifyre".to_string(),
            available: true,
            unavailable_reason: None,
            supported_proxy_kinds: vec![ProxyKind::Socks5, ProxyKind::Direct],
            supported_protocols: vec![Protocol::Tcp, Protocol::Udp],
            supports_child_inheritance: false,
            supports_hash_matching: false,
            supports_firewall_hardening: true,
            supports_destination_matching: false,
            supports_dns_policy: false,
            supports_dynamic_tun: false,
        },
        EngineCapability {
            mode: EngineMode::SingBox,
            display_name: "sing-box TUN".to_string(),
            backend_name: "sing-box".to_string(),
            available: sing_box::resolve_sing_box_executable().is_some(),
            unavailable_reason: sing_box::resolve_sing_box_executable().is_none().then(|| {
                "sing-box.exe was not found; set PROXYDUCK_SING_BOX_PATH or bundle it next to ProxyDuck".to_string()
            }),
            supported_proxy_kinds: vec![ProxyKind::Socks5, ProxyKind::Direct],
            supported_protocols: vec![Protocol::Tcp, Protocol::Udp],
            supports_child_inheritance: false,
            supports_hash_matching: false,
            supports_firewall_hardening: false,
            supports_destination_matching: true,
            supports_dns_policy: false,
            supports_dynamic_tun: true,
        },
        EngineCapability {
            mode: EngineMode::Wfp,
            display_name: "WFP".to_string(),
            backend_name: "native-wfp".to_string(),
            available: false,
            unavailable_reason: Some(
                "native WFP is unavailable because this build does not include a signed driver"
                    .to_string(),
            ),
            supported_proxy_kinds: Vec::new(),
            supported_protocols: Vec::new(),
            supports_child_inheritance: false,
            supports_hash_matching: false,
            supports_firewall_hardening: false,
            supports_destination_matching: false,
            supports_dns_policy: false,
            supports_dynamic_tun: false,
        },
        EngineCapability {
            mode: EngineMode::ApiHook,
            display_name: "API Hook".to_string(),
            backend_name: "api-hook".to_string(),
            available: false,
            unavailable_reason: Some(
                "API Hook backend is experimental and not implemented".to_string(),
            ),
            supported_proxy_kinds: Vec::new(),
            supported_protocols: Vec::new(),
            supports_child_inheritance: false,
            supports_hash_matching: false,
            supports_firewall_hardening: false,
            supports_destination_matching: false,
            supports_dns_policy: false,
            supports_dynamic_tun: false,
        },
    ]
}

pub fn capability_for(mode: EngineMode) -> EngineCapability {
    engine_capabilities()
        .into_iter()
        .find(|capability| capability.mode == mode)
        .expect("every engine mode must have a capability declaration")
}

fn create_engine(mode: EngineMode) -> Box<dyn ProxyEngine> {
    match mode {
        EngineMode::ProxiFyre => Box::new(ProxiFyreEngine::default()),
        EngineMode::SingBox => Box::new(SingBoxEngine::default()),
        EngineMode::Wfp => Box::new(WfpEngine::default()),
        EngineMode::ApiHook => Box::new(ApiHookEngine::default()),
    }
}

pub fn mode_name(mode: EngineMode) -> String {
    match mode {
        EngineMode::ProxiFyre => "proxifyre",
        EngineMode::SingBox => "sing_box",
        EngineMode::Wfp => "wfp",
        EngineMode::ApiHook => "api_hook",
    }
    .to_string()
}

pub fn validate_endpoint_profiles(config: &AppConfig) -> Result<()> {
    let requires_proxy = config
        .rules
        .iter()
        .any(|rule| rule.enabled && matches!(rule.action, crate::model::RouteAction::Proxy { .. }));
    let has_enabled = config.proxies.iter().any(|proxy| proxy.enabled);
    if requires_proxy && !has_enabled {
        return Err(anyhow!("no enabled proxy profiles found"));
    }
    Ok(())
}

pub use validate_endpoint_profiles as validate_clash_profile;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MatchCriteria, Rule};

    #[test]
    fn capability_registry_is_complete_and_honest() {
        let capabilities = engine_capabilities();
        assert_eq!(capabilities.len(), 4);
        assert!(capability_for(EngineMode::ProxiFyre).available);
        assert_eq!(capability_for(EngineMode::SingBox).backend_name, "sing-box");
        assert!(!capability_for(EngineMode::Wfp).available);
        assert!(!capability_for(EngineMode::ApiHook).available);
        assert_eq!(
            capability_for(EngineMode::ProxiFyre).supported_proxy_kinds,
            vec![ProxyKind::Socks5, ProxyKind::Direct]
        );
        assert!(!capability_for(EngineMode::ProxiFyre).supports_destination_matching);
        assert!(capability_for(EngineMode::SingBox).supports_destination_matching);
        assert!(capability_for(EngineMode::SingBox).supports_dynamic_tun);
    }

    #[test]
    fn failed_start_is_exposed_as_an_error_status() {
        let stats = Arc::new(RwLock::new(RuntimeStats::default()));
        let manager = EngineManager::new(EngineMode::ProxiFyre, stats);
        let mut config = AppConfig::default();
        config.runtime.enabled = true;
        config.proxies[0].enabled = false;
        config.rules.push(Rule::new(
            "requires proxy".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        ));

        assert!(manager.start(&config).is_err());
        let status = manager.status();
        assert_eq!(status.phase, DataPlanePhase::Error);
        assert!(status
            .message
            .as_deref()
            .is_some_and(|message| message.contains("no enabled proxy")));
    }
}
