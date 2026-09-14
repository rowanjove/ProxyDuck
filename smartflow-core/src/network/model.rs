use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverallStatus {
    #[default]
    Normal,
    Warning,
    Critical,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkIssue {
    pub id: String,
    pub layer: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<String>,
    pub suggested_actions: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterInfo {
    pub name: String,
    pub description: String,
    pub status: String,
    pub is_up: bool,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub dhcp_enabled: bool,
    pub apipa_detected: bool,
    pub interface_metric: Option<u32>,
    pub link_speed_mbps: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterStatus {
    pub active_adapters: Vec<AdapterInfo>,
    pub has_connected_adapter: bool,
    pub apipa_found: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteEntry {
    pub destination: String,
    pub next_hop: String,
    pub interface_alias: String,
    pub route_metric: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteStatus {
    pub default_ipv4_gateway: Option<String>,
    pub default_ipv4_interface: Option<String>,
    pub default_ipv4_metric: Option<u32>,
    pub default_ipv6_gateway: Option<String>,
    pub rival_routes_count: usize,
    pub routes: Vec<RouteEntry>,
    pub has_default_route: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatus {
    pub target: Option<String>,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub arp_resolved: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternetProbeResult {
    pub target: String,
    pub protocol: String,
    pub port: u16,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternetStatus {
    pub ip_level_connected: bool,
    pub probes: Vec<InternetProbeResult>,
    pub success_count: usize,
    pub total_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsResolveResult {
    pub query: String,
    pub success: bool,
    pub resolved_ips: Vec<String>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsStatus {
    pub configured_servers: Vec<String>,
    pub servers_reachable: Vec<String>,
    pub resolve_results: Vec<DnsResolveResult>,
    pub all_resolves_succeeded: bool,
    pub cache_service_running: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NcsiStatus {
    pub http_connect_ok: bool,
    pub payload_verified: bool,
    pub captive_portal_detected: bool,
    pub redirect_location: Option<String>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub wininet_accessible: bool,
    pub wininet_enabled: bool,
    pub wininet_server: Option<String>,
    pub wininet_override: Option<String>,
    pub auto_config_url: Option<String>,
    pub winhttp_accessible: bool,
    pub winhttp_proxy: Option<String>,
    pub env_proxies: HashMap<String, String>,
    pub pac_accessible: Option<bool>,
    pub is_proxy_configured: bool,
    pub proxy_port_reachable: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DualPathStatus {
    pub direct_internet_ok: bool,
    pub proxy_internet_ok: bool,
    pub proxy_evaluated: bool,
    pub conclusion: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WinsockStatus {
    pub catalog_entries_count: usize,
    pub catalog_accessible: bool,
    pub lsp_providers_detected: Vec<String>,
    pub is_healthy: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostsStatus {
    pub total_records: usize,
    pub custom_records_count: usize,
    pub loopback_redirects_count: usize,
    pub custom_domains: Vec<String>,
    pub file_accessible: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyDuckDiagnosticStatus {
    pub engine_running: bool,
    pub engine_mode: String,
    pub data_plane_phase: String,
    pub active_rules_count: usize,
    pub degraded: bool,
    pub bypass_test_ok: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDiagnosis {
    pub timestamp: String,
    pub status: OverallStatus,
    pub adapters: AdapterStatus,
    pub routes: RouteStatus,
    pub gateway: GatewayStatus,
    pub internet: InternetStatus,
    pub dns: DnsStatus,
    pub ncsi: NcsiStatus,
    pub proxy: ProxyStatus,
    pub dual_path: DualPathStatus,
    pub winsock: WinsockStatus,
    pub hosts: HostsStatus,
    pub proxyduck: ProxyDuckDiagnosticStatus,
    pub issues: Vec<NetworkIssue>,
}
