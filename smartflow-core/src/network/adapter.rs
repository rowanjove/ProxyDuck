use std::process::Command;
use tracing::warn;

use super::model::{AdapterInfo, AdapterStatus};

pub struct AdapterCollector;

impl AdapterCollector {
    pub fn collect() -> AdapterStatus {
        Self::collect_with_command()
    }

    pub fn collect_with_command() -> AdapterStatus {
        #[cfg(windows)]
        {
            // First try PowerShell JSON query
            if let Ok(status) = Self::collect_via_powershell() {
                if !status.active_adapters.is_empty() {
                    return status;
                }
            }
            // Fallback to ipconfig
            Self::collect_via_ipconfig()
        }
        #[cfg(not(windows))]
        {
            AdapterStatus::default()
        }
    }

    #[cfg(windows)]
    fn collect_via_powershell() -> anyhow::Result<AdapterStatus> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                r#"
                Get-NetIPConfiguration | ForEach-Object {
                    [PSCustomObject]@{
                        Alias = $_.InterfaceAlias
                        Description = $_.InterfaceDescription
                        Status = ($_.NetAdapter.Status -as [string])
                        IPv4 = @($_.IPv4Address | ForEach-Object { $_.IPAddress })
                        IPv6 = @($_.IPv6Address | ForEach-Object { $_.IPAddress })
                        Gateway = ($_.IPv4DefaultGateway.NextHop -as [string])
                        DNS = @($_.DNSServer | ForEach-Object { $_.ServerAddresses } | ForEach-Object { $_ })
                    }
                } | ConvertTo-Json -Compress
                "#,
            ])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("powershell exited with code {:?}", output.status.code());
        }

        let raw = String::from_utf8_lossy(&output.stdout);
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(AdapterStatus::default());
        }

        Self::parse_ps_json(trimmed)
    }

    pub fn parse_ps_json(json_str: &str) -> anyhow::Result<AdapterStatus> {
        let val: serde_json::Value = serde_json::from_str(json_str)?;
        let items: Vec<&serde_json::Value> = if let Some(arr) = val.as_array() {
            arr.iter().collect()
        } else {
            vec![&val]
        };

        let mut adapters = Vec::new();
        let mut apipa_found = false;

        for item in items {
            let name = item["Alias"].as_str().unwrap_or("Unknown").to_string();
            let description = item["Description"].as_str().unwrap_or("").to_string();
            let status = item["Status"].as_str().unwrap_or("Up").to_string();
            let is_up = status.eq_ignore_ascii_case("Up") || status.is_empty();

            let mut ipv4_addresses = Vec::new();
            if let Some(ip) = item["IPv4"].as_str() {
                ipv4_addresses.push(ip.to_string());
            } else if let Some(ips) = item["IPv4"].as_array() {
                for ip in ips {
                    if let Some(s) = ip.as_str() {
                        ipv4_addresses.push(s.to_string());
                    }
                }
            }

            let mut ipv6_addresses = Vec::new();
            if let Some(ip) = item["IPv6"].as_str() {
                ipv6_addresses.push(ip.to_string());
            } else if let Some(ips) = item["IPv6"].as_array() {
                for ip in ips {
                    if let Some(s) = ip.as_str() {
                        ipv6_addresses.push(s.to_string());
                    }
                }
            }

            let gateway = item["Gateway"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string());

            let mut dns_servers = Vec::new();
            if let Some(dns) = item["DNS"].as_str() {
                dns_servers.push(dns.to_string());
            } else if let Some(list) = item["DNS"].as_array() {
                for d in list {
                    if let Some(s) = d.as_str() {
                        dns_servers.push(s.to_string());
                    }
                }
            }

            let mut has_apipa = false;
            for ip in &ipv4_addresses {
                if ip.starts_with("169.254.") {
                    has_apipa = true;
                    apipa_found = true;
                }
            }

            adapters.push(AdapterInfo {
                name,
                description,
                status,
                is_up,
                ipv4_addresses,
                ipv6_addresses,
                gateway,
                dns_servers,
                dhcp_enabled: true,
                apipa_detected: has_apipa,
                interface_metric: None,
                link_speed_mbps: None,
            });
        }

        let has_connected = adapters
            .iter()
            .any(|a| a.is_up && !a.ipv4_addresses.is_empty());
        Ok(AdapterStatus {
            active_adapters: adapters,
            has_connected_adapter: has_connected,
            apipa_found,
        })
    }

    #[cfg(windows)]
    fn collect_via_ipconfig() -> AdapterStatus {
        let output = match Command::new("ipconfig").args(["/all"]).output() {
            Ok(o) => o,
            Err(e) => {
                warn!("failed to run ipconfig: {e}");
                return AdapterStatus::default();
            }
        };

        let raw = String::from_utf8_lossy(&output.stdout);
        Self::parse_ipconfig(&raw)
    }

    pub fn parse_ipconfig(raw: &str) -> AdapterStatus {
        let mut adapters = Vec::new();
        let mut current_adapter: Option<AdapterInfo> = None;
        let mut apipa_found = false;

        for line in raw.lines() {
            let trimmed = line.trim();
            if line.contains("adapter ") || line.contains("适配器 ") {
                if let Some(a) = current_adapter.take() {
                    adapters.push(a);
                }
                let name = line.trim_end_matches(':').trim().to_string();
                current_adapter = Some(AdapterInfo {
                    name,
                    is_up: true,
                    status: "Up".to_string(),
                    ..Default::default()
                });
            } else if let Some(ref mut a) = current_adapter {
                if trimmed.contains("IPv4") || trimmed.contains("IP Address") {
                    if let Some(val) = trimmed.split(':').nth(1) {
                        let ip = val.split('(').next().unwrap_or("").trim().to_string();
                        if !ip.is_empty() {
                            if ip.starts_with("169.254.") {
                                a.apipa_detected = true;
                                apipa_found = true;
                            }
                            a.ipv4_addresses.push(ip);
                        }
                    }
                } else if trimmed.contains("IPv6") {
                    if let Some(val) = trimmed.split(':').nth(1) {
                        let ip = val.split('(').next().unwrap_or("").trim().to_string();
                        if !ip.is_empty() {
                            a.ipv6_addresses.push(ip);
                        }
                    }
                } else if trimmed.contains("Default Gateway") || trimmed.contains("默认网关") {
                    if let Some(val) = trimmed.split(':').nth(1) {
                        let gw = val.trim().to_string();
                        if !gw.is_empty() {
                            a.gateway = Some(gw);
                        }
                    }
                } else if trimmed.contains("DNS Servers") || trimmed.contains("DNS 服务器") {
                    if let Some(val) = trimmed.split(':').nth(1) {
                        let dns = val.trim().to_string();
                        if !dns.is_empty() {
                            a.dns_servers.push(dns);
                        }
                    }
                } else if trimmed.contains("DHCP Enabled") || trimmed.contains("已启用 DHCP") {
                    a.dhcp_enabled = trimmed.contains("Yes") || trimmed.contains("是");
                }
            }
        }

        if let Some(a) = current_adapter {
            adapters.push(a);
        }

        let has_connected = adapters.iter().any(|a| !a.ipv4_addresses.is_empty());
        AdapterStatus {
            active_adapters: adapters,
            has_connected_adapter: has_connected,
            apipa_found,
        }
    }
}
