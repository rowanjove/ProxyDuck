use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProfile {
    pub id: String,
    pub name: String,
    pub kind: ProxyKind,
    pub endpoint: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub enabled: bool,
}

impl ProxyProfile {
    pub fn clash_default() -> Self {
        Self {
            id: "clash-socks".to_string(),
            name: "Clash Verge".to_string(),
            kind: ProxyKind::Socks5,
            endpoint: "127.0.0.1:7897".to_string(),
            username: None,
            password: None,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    Socks5,
    Http,
    Direct,
    Interface,
    Vpn,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MatchCriteria {
    #[serde(default)]
    pub app_names: Vec<String>,
    #[serde(default)]
    pub exe_paths: Vec<String>,
    #[serde(default)]
    pub pids: Vec<u32>,
    #[serde(default)]
    pub hashes: Vec<String>,
    pub wildcard: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    #[default]
    User,
    QuickBar,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Pid,
    ExePath,
    AppName,
    Wildcard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub source: RuleSource,
    #[serde(default)]
    pub managed_by_quickbar_id: Option<String>,
    pub matcher: MatchCriteria,
    pub proxy_profile: String,
    pub protocols: Vec<Protocol>,
    pub auto_bind_children: bool,
    pub force_dns: bool,
    pub block_ipv6: bool,
    pub block_doh: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Rule {
    pub fn new(name: String, matcher: MatchCriteria, proxy_profile: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            enabled: true,
            source: RuleSource::User,
            managed_by_quickbar_id: None,
            matcher,
            proxy_profile,
            protocols: vec![Protocol::Tcp, Protocol::Udp, Protocol::Dns],
            auto_bind_children: false,
            force_dns: true,
            block_ipv6: true,
            block_doh: true,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartMode {
    StartOnly,
    BindOnly,
    StartAndBind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickBarItem {
    pub id: String,
    pub name: String,
    pub exe_path: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub work_dir: Option<String>,
    pub proxy_profile: String,
    pub start_mode: StartMode,
    pub run_as_admin: bool,
    pub auto_bind_children: bool,
}

impl QuickBarItem {
    pub fn new(name: String, exe_path: String, proxy_profile: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            exe_path,
            args: Vec::new(),
            work_dir: None,
            proxy_profile,
            start_mode: StartMode::StartAndBind,
            run_as_admin: false,
            auto_bind_children: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineMode {
    WinDivert,
    SingBox,
    Wfp,
    ApiHook,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeakProtectionMode {
    #[default]
    Availability,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeToggles {
    pub enabled: bool,
    pub dns_enforced: bool,
    pub ipv6_blocked: bool,
    pub doh_blocked: bool,
    pub log_level: String,
    #[serde(default)]
    pub leak_protection_mode: LeakProtectionMode,
}

impl Default for RuntimeToggles {
    fn default() -> Self {
        Self {
            enabled: false,
            dns_enforced: true,
            ipv6_blocked: true,
            doh_blocked: true,
            log_level: "info".to_string(),
            leak_protection_mode: LeakProtectionMode::Availability,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub version: String,
    #[serde(default)]
    pub schema_version: u32,
    pub engine_mode: EngineMode,
    pub proxies: Vec<ProxyProfile>,
    pub rules: Vec<Rule>,
    pub quick_bar: Vec<QuickBarItem>,
    pub runtime: RuntimeToggles,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: 3,
            engine_mode: EngineMode::WinDivert,
            proxies: vec![ProxyProfile::clash_default()],
            rules: Vec::new(),
            quick_bar: Vec::new(),
            runtime: RuntimeToggles::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStats {
    pub engine_mode: String,
    pub started_at: Option<DateTime<Utc>>,
    pub last_reload_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub rule_hits: HashMap<String, u64>,
    #[serde(default)]
    pub process_hits: HashMap<String, u64>,
    #[serde(default)]
    pub proxy_hits: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EngineCapability {
    pub mode: EngineMode,
    pub display_name: String,
    pub backend_name: String,
    pub available: bool,
    pub unavailable_reason: Option<String>,
    pub supported_proxy_kinds: Vec<ProxyKind>,
    pub supported_protocols: Vec<Protocol>,
    pub supports_child_inheritance: bool,
    pub supports_hash_matching: bool,
    pub supports_firewall_hardening: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataPlanePhase {
    Stopped,
    Paused,
    Starting,
    Running,
    Degraded,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataPlaneStatus {
    pub phase: DataPlanePhase,
    pub backend_name: String,
    pub child_pid: Option<u32>,
    pub active_rules: usize,
    pub firewall_rules: usize,
    pub proxy_endpoint_reachable: Option<bool>,
    pub fail_closed_active: bool,
    pub message: Option<String>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub desired_enabled: bool,
    pub engine_mode: EngineMode,
    pub data_plane: DataPlaneStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyTestResult {
    pub proxy_id: String,
    pub reachable: bool,
    pub protocol_accepted: bool,
    #[serde(default)]
    pub tcp_supported: Option<bool>,
    #[serde(default)]
    pub tcp_error: Option<String>,
    #[serde(default)]
    pub udp_supported: Option<bool>,
    #[serde(default)]
    pub udp_error: Option<String>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleEvaluationMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub proxy_id: String,
    pub match_kind: MatchKind,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleEvaluation {
    pub process: ProcessInfo,
    pub matches: Vec<RuleEvaluationMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleConflict {
    pub first_rule_id: String,
    pub first_rule_name: String,
    pub second_rule_id: String,
    pub second_rule_name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiLogEvent {
    pub ts: DateTime<Utc>,
    pub level: String,
    pub source: String,
    pub message: String,
}

impl UiLogEvent {
    pub fn new(
        level: impl Into<String>,
        source: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            ts: Utc::now(),
            level: level.into(),
            source: source.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub engine_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchEvent {
    pub ts: DateTime<Utc>,
    pub process_pid: u32,
    pub process_name: String,
    pub process_exe: String,
    pub rule_id: String,
    pub rule_name: String,
    pub proxy_id: String,
    pub proxy_name: String,
    pub source: RuleSource,
    pub match_kind: MatchKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleHitStat {
    pub rule_id: String,
    pub rule_name: String,
    pub proxy_id: String,
    pub proxy_name: String,
    pub source: RuleSource,
    pub hits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyHitStat {
    pub proxy_id: String,
    pub proxy_name: String,
    pub hits: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_profile_clash_default() {
        let default = ProxyProfile::clash_default();
        assert_eq!(default.id, "clash-socks");
        assert_eq!(default.endpoint, "127.0.0.1:7897");
        assert!(default.enabled);
    }

    #[test]
    fn test_rule_new() {
        let matcher = MatchCriteria {
            app_names: vec!["test.exe".to_string()],
            ..Default::default()
        };
        let rule = Rule::new(
            "my-rule".to_string(),
            matcher.clone(),
            "clash-socks".to_string(),
        );

        assert_eq!(rule.name, "my-rule");
        assert_eq!(rule.proxy_profile, "clash-socks");
        assert_eq!(rule.matcher.app_names.len(), 1);
        assert!(rule.enabled);
        assert!(!rule.id.is_empty());
        assert_eq!(rule.protocols.len(), 3);
        assert!(!rule.auto_bind_children);
        assert!(rule.force_dns);
        assert!(rule.block_ipv6);
        assert!(rule.block_doh);
        assert_eq!(rule.source, RuleSource::User);
        assert!(rule.managed_by_quickbar_id.is_none());
    }

    #[test]
    fn test_quick_bar_item_new() {
        let qb = QuickBarItem::new(
            "my-app".to_string(),
            "C:\\app.exe".to_string(),
            "clash-socks".to_string(),
        );
        assert_eq!(qb.name, "my-app");
        assert_eq!(qb.exe_path, "C:\\app.exe");
        assert_eq!(qb.proxy_profile, "clash-socks");
        assert!(!qb.id.is_empty());
        assert!(matches!(qb.start_mode, StartMode::StartAndBind));
        assert!(!qb.run_as_admin);
        assert!(!qb.auto_bind_children);
    }
}
