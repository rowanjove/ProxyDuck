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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_ref: Option<String>,
    /// Hydrated in memory from SecretStore; never serialized back to config or API.
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
    pub enabled: bool,
}

impl ProxyProfile {
    pub fn local_socks_default() -> Self {
        Self {
            id: "local-socks".to_string(),
            name: "本地代理 (SOCKS5)".to_string(),
            kind: ProxyKind::Socks5,
            endpoint: "127.0.0.1:7897".to_string(),
            username: None,
            password_ref: None,
            password: None,
            enabled: true,
        }
    }

    #[deprecated(note = "Use local_socks_default() instead")]
    pub fn clash_default() -> Self {
        Self {
            id: "clash-socks".to_string(),
            name: "Local SOCKS5 (Legacy)".to_string(),
            kind: ProxyKind::Socks5,
            endpoint: "127.0.0.1:7897".to_string(),
            username: None,
            password_ref: None,
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
    /// Creation time bound to a PID rule.  A PID without this value is a
    /// legacy/unsafe selector and is never treated as a stable process
    /// identity by the matcher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_creation_time: Option<u64>,
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
pub enum RouteDisposition {
    #[default]
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamilyDisposition {
    #[default]
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RouteAction {
    Proxy { proxy_id: String },
    Direct,
    Block,
    Reject,
}

impl Default for RouteAction {
    fn default() -> Self {
        Self::Proxy {
            proxy_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    #[serde(default)]
    pub tcp: RouteDisposition,
    #[serde(default)]
    pub udp: RouteDisposition,
    #[serde(default)]
    pub ipv4: AddressFamilyDisposition,
    #[serde(default)]
    pub ipv6: AddressFamilyDisposition,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            tcp: RouteDisposition::Proxy,
            udp: RouteDisposition::Proxy,
            ipv4: AddressFamilyDisposition::Proxy,
            ipv6: AddressFamilyDisposition::Proxy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    #[default]
    Inherit,
    Direct,
    Proxy,
    Hijack,
    BlockPlaintext,
    EnforceResolver {
        resolver_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DnsPolicy {
    #[serde(default)]
    pub mode: DnsMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DestinationMatch {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

impl DestinationMatch {
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ip_cidrs.is_empty() && self.ports.is_empty()
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub enabled: bool,
    #[serde(default = "default_rule_priority")]
    pub priority: i32,
    #[serde(default)]
    pub source: RuleSource,
    #[serde(default)]
    pub managed_by_quickbar_id: Option<String>,
    /// Stable, service-owned provenance for rules materialized from a built-in
    /// template.  This is intentionally not part of the rule upsert payload;
    /// matching templates by editable labels would allow a user rule to be
    /// silently overwritten on re-apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_by_template_key: Option<String>,
    pub matcher: MatchCriteria,
    #[serde(default)]
    pub action: RouteAction,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub dns: DnsPolicy,
    #[serde(default)]
    pub destination: DestinationMatch,
    pub proxy_profile: String,
    #[serde(default)]
    pub protocols: Vec<Protocol>,
    #[serde(default)]
    pub auto_bind_children: bool,
    #[serde(default)]
    pub force_dns: bool,
    #[serde(default)]
    pub block_ipv6: bool,
    #[serde(default)]
    pub block_doh: bool,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "chrono::Utc::now")]
    pub updated_at: DateTime<Utc>,
}

impl Rule {
    pub fn new(name: String, matcher: MatchCriteria, proxy_profile: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            group: None,
            tags: Vec::new(),
            enabled: true,
            priority: default_rule_priority(),
            source: RuleSource::User,
            managed_by_quickbar_id: None,
            managed_by_template_key: None,
            matcher,
            action: RouteAction::Proxy {
                proxy_id: proxy_profile.clone(),
            },
            network: NetworkPolicy::default(),
            dns: DnsPolicy {
                mode: DnsMode::BlockPlaintext,
            },
            destination: DestinationMatch::default(),
            proxy_profile,
            protocols: vec![Protocol::Tcp, Protocol::Udp, Protocol::Dns],
            auto_bind_children: false,
            force_dns: false,
            block_ipv6: false,
            block_doh: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Stable route target used by process-match telemetry.  The legacy
    /// `proxy_profile` field remains readable, while direct/block/reject
    /// actions must not be reported as if they were proxy traffic.
    pub fn action_target_id(&self) -> String {
        match &self.action {
            RouteAction::Proxy { proxy_id } if !proxy_id.trim().is_empty() => proxy_id.clone(),
            RouteAction::Proxy { .. } => self.proxy_profile.clone(),
            RouteAction::Direct => "direct".to_string(),
            RouteAction::Block => "block".to_string(),
            RouteAction::Reject => "reject".to_string(),
        }
    }
}

pub fn default_rule_priority() -> i32 {
    100
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

/// A named, restorable policy snapshot.  Proxy credentials remain global in
/// `AppConfig.proxies`; rules keep referring to stable proxy IDs so a profile
/// never duplicates or serializes secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub engine_mode: EngineMode,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub quick_bar: Vec<QuickBarItem>,
    pub runtime: RuntimeToggles,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RoutingProfile {
    pub fn from_config(
        config: &AppConfig,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            description: description.into(),
            engine_mode: config.engine_mode,
            rules: config.rules.clone(),
            quick_bar: config.quick_bar.clone(),
            runtime: config.runtime.clone(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn apply_to_config(&self, config: &mut AppConfig) {
        config.engine_mode = self.engine_mode;
        config.rules = self.rules.clone();
        config.quick_bar = self.quick_bar.clone();
        config.runtime = self.runtime.clone();
        config.active_profile_id = Some(self.id.clone());
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineMode {
    #[serde(rename = "proxifyre", alias = "win_divert", alias = "windivert")]
    ProxiFyre,
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
            dns_enforced: false,
            ipv6_blocked: false,
            doh_blocked: false,
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
    #[serde(default)]
    pub profiles: Vec<RoutingProfile>,
    #[serde(default)]
    pub active_profile_id: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: 6,
            engine_mode: EngineMode::ProxiFyre,
            proxies: vec![ProxyProfile::local_socks_default()],
            rules: Vec::new(),
            quick_bar: Vec::new(),
            runtime: RuntimeToggles::default(),
            profiles: Vec::new(),
            active_profile_id: None,
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
    #[serde(rename = "ruleProcessMatches", alias = "ruleHits")]
    pub rule_process_matches: HashMap<String, u64>,
    #[serde(default)]
    #[serde(rename = "processMatches", alias = "processHits")]
    pub process_matches: HashMap<String, u64>,
    #[serde(default)]
    #[serde(rename = "proxyProcessMatches", alias = "proxyHits")]
    pub proxy_process_matches: HashMap<String, u64>,
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
    #[serde(default)]
    pub supports_destination_matching: bool,
    #[serde(default)]
    pub supports_dns_policy: bool,
    #[serde(default)]
    pub supports_dynamic_tun: bool,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyHealthState {
    Unknown,
    Checking,
    Healthy,
    Degraded,
    Offline,
    AuthFailed,
    ProtocolError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyHealth {
    pub proxy_id: String,
    pub state: ProxyHealthState,
    pub reachable: Option<bool>,
    pub protocol_accepted: Option<bool>,
    pub tcp_supported: Option<bool>,
    pub udp_supported: Option<bool>,
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub latency_history_ms: Vec<u64>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_error: Option<String>,
    pub last_checked_at: Option<DateTime<Utc>>,
}

impl ProxyHealth {
    pub fn unknown(proxy_id: impl Into<String>) -> Self {
        Self {
            proxy_id: proxy_id.into(),
            state: ProxyHealthState::Unknown,
            reachable: None,
            protocol_accepted: None,
            tcp_supported: None,
            udp_supported: None,
            latency_ms: None,
            latency_history_ms: Vec::new(),
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_error: None,
            last_checked_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub desired_enabled: bool,
    pub engine_mode: EngineMode,
    pub data_plane: DataPlaneStatus,
    #[serde(default)]
    pub proxy_health: Vec<ProxyHealth>,
    #[serde(default)]
    pub active_plan_fingerprint: Option<String>,
    #[serde(default)]
    pub required_proxy_ids: Vec<String>,
    #[serde(default)]
    pub degraded_reasons: Vec<String>,
    /// Machine-readable compiler diagnostics for the currently effective
    /// policy.  These are intentionally exposed alongside the human-readable
    /// reasons so clients can distinguish strict blockers from compatibility
    /// degradation without parsing log text.
    #[serde(default)]
    pub compile_diagnostics: Vec<crate::routing_plan::CompileDiagnostic>,
    #[serde(default)]
    pub last_transition_at: Option<DateTime<Utc>>,
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
    #[serde(default)]
    pub event_id: Option<String>,
    pub message: String,
}

impl UiLogEvent {
    pub fn new(
        level: impl Into<String>,
        source: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let source = source.into();
        Self {
            ts: Utc::now(),
            level: level.into(),
            event_id: Some(format!("PD-{}-GENERIC", source.to_ascii_uppercase())),
            source,
            message: message.into(),
        }
    }

    pub fn with_event_id(
        level: impl Into<String>,
        source: impl Into<String>,
        event_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            ts: Utc::now(),
            level: level.into(),
            source: source.into(),
            event_id: Some(event_id.into()),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    /// Process creation time as reported by the OS/sysinfo backend. This is
    /// optional because some platforms or restricted tokens cannot expose it;
    /// PID-only matching must then remain visibly degraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<u64>,
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
pub struct RuleProcessMatchStat {
    pub rule_id: String,
    pub rule_name: String,
    pub proxy_id: String,
    pub proxy_name: String,
    pub source: RuleSource,
    #[serde(rename = "matches", alias = "hits")]
    pub matches: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProcessMatchStat {
    pub proxy_id: String,
    pub proxy_name: String,
    #[serde(rename = "matches", alias = "hits")]
    pub matches: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_mode_accepts_legacy_windivert_names_but_serializes_proxifyre() {
        for legacy in ["win_divert", "windivert"] {
            let mode: EngineMode = serde_json::from_str(&format!("\"{legacy}\""))
                .expect("legacy engine mode should remain readable");
            assert_eq!(mode, EngineMode::ProxiFyre);
        }
        assert_eq!(
            serde_json::to_string(&EngineMode::ProxiFyre).unwrap(),
            "\"proxifyre\""
        );
    }

    #[test]
    fn test_proxy_profile_local_socks_default() {
        let default = ProxyProfile::local_socks_default();
        assert_eq!(default.id, "local-socks");
        assert_eq!(default.endpoint, "127.0.0.1:7897");
        assert!(default.enabled);
    }

    #[test]
    #[allow(deprecated)]
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
            "local-socks".to_string(),
        );

        assert_eq!(rule.name, "my-rule");
        assert_eq!(rule.proxy_profile, "local-socks");
        assert_eq!(rule.matcher.app_names.len(), 1);
        assert!(rule.enabled);
        assert!(!rule.id.is_empty());
        assert_eq!(rule.protocols.len(), 3);
        assert!(!rule.auto_bind_children);
        assert!(!rule.force_dns);
        assert!(!rule.block_ipv6);
        assert!(!rule.block_doh);
        assert_eq!(rule.source, RuleSource::User);
        assert!(rule.managed_by_quickbar_id.is_none());
        assert_eq!(rule.action_target_id(), "local-socks");
    }

    #[test]
    fn action_target_id_keeps_non_proxy_routes_truthful() {
        let mut rule = Rule::new("direct".into(), MatchCriteria::default(), "legacy".into());
        rule.action = RouteAction::Direct;
        assert_eq!(rule.action_target_id(), "direct");
        rule.action = RouteAction::Block;
        assert_eq!(rule.action_target_id(), "block");
        rule.action = RouteAction::Reject;
        assert_eq!(rule.action_target_id(), "reject");
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
