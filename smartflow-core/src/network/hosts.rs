use std::{fs, path::PathBuf};
use tracing::warn;

use super::model::HostsStatus;

pub struct HostsCollector;

impl HostsCollector {
    pub fn check_hosts() -> HostsStatus {
        let path = Self::hosts_path();
        if !path.exists() {
            return HostsStatus {
                total_records: 0,
                custom_records_count: 0,
                loopback_redirects_count: 0,
                custom_domains: Vec::new(),
                file_accessible: false,
            };
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("failed to read hosts file {}: {e}", path.display());
                return HostsStatus {
                    total_records: 0,
                    custom_records_count: 0,
                    loopback_redirects_count: 0,
                    custom_domains: Vec::new(),
                    file_accessible: false,
                };
            }
        };

        Self::parse_hosts_content(&content)
    }

    pub fn hosts_path() -> PathBuf {
        #[cfg(windows)]
        {
            if let Ok(windir) = std::env::var("SystemRoot") {
                return PathBuf::from(windir).join(r"System32\drivers\etc\hosts");
            }
            PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/etc/hosts")
        }
    }

    pub fn parse_hosts_content(content: &str) -> HostsStatus {
        let mut total_records = 0;
        let mut custom_records = 0;
        let mut loopback_redirects = 0;
        let mut custom_domains = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            total_records += 1;

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let ip = parts[0];
                let domain = parts[1];

                // Ignore default standard localhost mappings
                if (ip == "127.0.0.1" || ip == "::1")
                    && (domain == "localhost" || domain == "localhost.localdomain")
                {
                    continue;
                }

                custom_records += 1;
                if ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" {
                    loopback_redirects += 1;
                }
                if !custom_domains.contains(&domain.to_string()) {
                    custom_domains.push(domain.to_string());
                }
            }
        }

        HostsStatus {
            total_records,
            custom_records_count: custom_records,
            loopback_redirects_count: loopback_redirects,
            custom_domains,
            file_accessible: true,
        }
    }
}
