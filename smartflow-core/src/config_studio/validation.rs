use std::net::TcpListener;

use super::model::{ConfigFormat, ConfigValidationResult, PortConflictInfo, SemanticConfig};

pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate(
        content: &str,
        format: ConfigFormat,
        semantic: &SemanticConfig,
    ) -> ConfigValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // 1. Syntax validation
        match format {
            ConfigFormat::Yaml => {
                if let Err(e) = serde_yaml::from_str::<serde_json::Value>(content) {
                    errors.push(format!("YAML 语法错误: {e}"));
                }
            }
            ConfigFormat::Json => {
                if let Err(e) = serde_json::from_str::<serde_json::Value>(content) {
                    errors.push(format!("JSON 语法错误: {e}"));
                }
            }
            ConfigFormat::Jsonc => {
                if let Err(e) = json5::from_str::<serde_json::Value>(content) {
                    errors.push(format!("JSONC 语法错误: {e}"));
                }
            }
            ConfigFormat::Pac => {
                if !content.contains("function FindProxyForURL") {
                    warnings.push("PAC 脚本中未检测到标准的 FindProxyForURL 函数签名".to_string());
                }
            }
            _ => {}
        }

        // 2. Port conflict validation
        let mut port_conflicts = Vec::new();
        for listener in &semantic.inbound_listeners {
            if listener.port > 0 {
                let conflict = Self::check_port_in_use(listener.port, &listener.protocol);
                if conflict.in_use {
                    warnings.push(format!(
                        "监听端口 {} ({}) 已被系统其他进程占用，保存并启动该配置可能发生端口冲突",
                        listener.port, listener.name
                    ));
                }
                port_conflicts.push(conflict);
            }
        }

        let valid = errors.is_empty();

        ConfigValidationResult {
            valid,
            errors,
            warnings,
            port_conflicts,
        }
    }

    fn check_port_in_use(port: u16, protocol: &str) -> PortConflictInfo {
        let bind_addr = format!("127.0.0.1:{port}");
        match TcpListener::bind(&bind_addr) {
            Ok(_) => PortConflictInfo {
                port,
                protocol: protocol.to_string(),
                in_use: false,
                message: "端口空闲".to_string(),
            },
            Err(e) => PortConflictInfo {
                port,
                protocol: protocol.to_string(),
                in_use: true,
                message: format!("端口不可用: {e}"),
            },
        }
    }
}
