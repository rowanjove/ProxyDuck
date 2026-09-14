use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigFormat {
    Yaml,
    Json,
    Jsonc,
    Toml,
    Pac,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigFileSummary {
    pub id: String,
    pub file_name: String,
    pub path: PathBuf,
    pub format: ConfigFormat,
    pub fingerprint: String,
    pub size_bytes: u64,
    pub mtime_rfc3339: String,
    pub sha256: String,
    pub editable: bool,
    pub provider_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticListener {
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub bind_address: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticEndpoint {
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticConfig {
    pub inbound_listeners: Vec<SemanticListener>,
    pub outbound_endpoints: Vec<SemanticEndpoint>,
    pub routing_rules_count: usize,
    pub dns_servers: Vec<String>,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDocument {
    pub id: String,
    pub file_name: String,
    pub path: PathBuf,
    pub format: ConfigFormat,
    pub fingerprint: String,
    pub raw_content: String,
    pub semantic: SemanticConfig,
    pub sha256: String,
    pub mtime_rfc3339: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AstPatchItem {
    pub key: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigPatchRequest {
    pub expected_sha256: String,
    pub patches: Vec<AstPatchItem>,
    pub raw_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortConflictInfo {
    pub port: u16,
    pub protocol: String,
    pub in_use: bool,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub port_conflicts: Vec<PortConflictInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSaveResult {
    pub success: bool,
    pub backup_path: Option<PathBuf>,
    pub new_sha256: String,
    pub diff: String,
}
