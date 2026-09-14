use std::path::Path;

use super::model::ConfigFormat;

#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub format: ConfigFormat,
    pub fingerprint: String,
    pub provider_id: &'static str,
    pub editable: bool,
}

pub struct FingerprintDetector;

impl FingerprintDetector {
    pub fn detect(path: &Path, content: &str) -> FingerprintResult {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 1. PAC detection
        if ext == "pac" || content.contains("function FindProxyForURL") {
            return FingerprintResult {
                format: ConfigFormat::Pac,
                fingerprint: "PAC 自动代理脚本".to_string(),
                provider_id: "pac_provider",
                editable: true,
            };
        }

        // 2. YAML detection
        if ext == "yaml" || ext == "yml" {
            if content.contains("proxies:")
                || content.contains("proxy-groups:")
                || content.contains("rules:")
            {
                return FingerprintResult {
                    format: ConfigFormat::Yaml,
                    fingerprint: "YAML 网络路由配置 (Clash 风格)".to_string(),
                    provider_id: "generic_yaml_provider",
                    editable: true,
                };
            }
            return FingerprintResult {
                format: ConfigFormat::Yaml,
                fingerprint: "通用 YAML 配置文件".to_string(),
                provider_id: "generic_yaml_provider",
                editable: true,
            };
        }

        // 3. JSON / JSONC detection
        if ext == "json" || ext == "jsonc" {
            if content.contains("\"inbounds\"")
                || content.contains("\"outbounds\"")
                || content.contains("\"route\"")
            {
                return FingerprintResult {
                    format: if ext == "jsonc" {
                        ConfigFormat::Jsonc
                    } else {
                        ConfigFormat::Json
                    },
                    fingerprint: "JSON 网络路由配置 (sing-box 风格)".to_string(),
                    provider_id: "generic_json_provider",
                    editable: true,
                };
            }
            return FingerprintResult {
                format: if ext == "jsonc" {
                    ConfigFormat::Jsonc
                } else {
                    ConfigFormat::Json
                },
                fingerprint: "通用 JSON 配置文件".to_string(),
                provider_id: "generic_json_provider",
                editable: true,
            };
        }

        // 4. TOML detection
        if ext == "toml" {
            return FingerprintResult {
                format: ConfigFormat::Toml,
                fingerprint: "通用 TOML 配置文件".to_string(),
                provider_id: "generic_toml_provider",
                editable: true,
            };
        }

        // Fallback by content heuristics
        if content.trim_start().starts_with('{') {
            FingerprintResult {
                format: ConfigFormat::Json,
                fingerprint: "JSON 格式文件".to_string(),
                provider_id: "generic_json_provider",
                editable: true,
            }
        } else if content.contains(':') && !content.contains("<?xml") {
            FingerprintResult {
                format: ConfigFormat::Yaml,
                fingerprint: "YAML/文本配置".to_string(),
                provider_id: "generic_yaml_provider",
                editable: true,
            }
        } else {
            FingerprintResult {
                format: ConfigFormat::Unknown,
                fingerprint: "未知配置格式".to_string(),
                provider_id: "raw_provider",
                editable: false,
            }
        }
    }

    pub fn compute_hash(content: &str) -> String {
        let mut hash = 0xcbf29ce484222325_u64;
        for byte in content.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("{hash:016x}")
    }
}
