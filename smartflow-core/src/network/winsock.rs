use std::process::Command;
use tracing::warn;

use super::model::WinsockStatus;

pub struct WinsockCollector;

impl WinsockCollector {
    pub fn check_winsock() -> WinsockStatus {
        #[cfg(windows)]
        {
            let output = match Command::new("netsh")
                .args(["winsock", "show", "catalog"])
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    warn!("failed to run netsh winsock show catalog: {e}");
                    return WinsockStatus {
                        catalog_entries_count: 0,
                        catalog_accessible: false,
                        lsp_providers_detected: Vec::new(),
                        is_healthy: false,
                    };
                }
            };

            let text = String::from_utf8_lossy(&output.stdout);
            Self::parse_winsock_catalog(&text)
        }
        #[cfg(not(windows))]
        {
            WinsockStatus {
                catalog_entries_count: 10,
                catalog_accessible: true,
                lsp_providers_detected: Vec::new(),
                is_healthy: true,
            }
        }
    }

    pub fn parse_winsock_catalog(text: &str) -> WinsockStatus {
        let mut entries = 0;
        let mut providers = Vec::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.contains("Entry type:") || trimmed.contains("项目类型:") {
                entries += 1;
            }
            if trimmed.starts_with("Description :") || trimmed.starts_with("说明:") {
                let desc = trimmed
                    .split(':')
                    .skip(1)
                    .collect::<Vec<&str>>()
                    .join(":")
                    .trim()
                    .to_string();
                if !desc.is_empty() && !providers.contains(&desc) {
                    providers.push(desc);
                }
            }
        }

        // Healthy Windows has typical entries (TCP/IP, IPv6, AF_UNIX, etc.) usually >= 10
        let is_healthy = entries >= 8;

        WinsockStatus {
            catalog_entries_count: entries,
            catalog_accessible: true,
            lsp_providers_detected: providers,
            is_healthy,
        }
    }
}
