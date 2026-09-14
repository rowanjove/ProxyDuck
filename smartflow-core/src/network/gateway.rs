use std::{process::Command, time::Instant};
use tracing::debug;

use super::model::GatewayStatus;

pub struct GatewayCollector;

impl GatewayCollector {
    pub async fn check_gateway(gateway_ip: Option<&str>) -> GatewayStatus {
        let ip = match gateway_ip {
            Some(i) if !i.trim().is_empty() && i != "0.0.0.0" => i.trim(),
            _ => {
                return GatewayStatus {
                    target: None,
                    reachable: false,
                    latency_ms: None,
                    arp_resolved: false,
                    error: Some("未检测到有效默认网关 IP".to_string()),
                }
            }
        };

        let started = Instant::now();

        // 1. ICMP ping
        let ping_res = tokio::task::spawn_blocking({
            let ip_clone = ip.to_string();
            move || Self::ping_host(&ip_clone)
        })
        .await
        .unwrap_or(false);

        let latency = if ping_res {
            Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64)
        } else {
            None
        };

        // 2. ARP check
        let arp_resolved = tokio::task::spawn_blocking({
            let ip_clone = ip.to_string();
            move || Self::check_arp(&ip_clone)
        })
        .await
        .unwrap_or(false);

        let reachable = ping_res || arp_resolved;
        let error = if !reachable {
            Some("默认网关无响应且 ARP 未解析".to_string())
        } else {
            None
        };

        GatewayStatus {
            target: Some(ip.to_string()),
            reachable,
            latency_ms: latency,
            arp_resolved,
            error,
        }
    }

    fn ping_host(ip: &str) -> bool {
        #[cfg(windows)]
        {
            let output = Command::new("ping")
                .args(["-n", "1", "-w", "1000", ip])
                .output();
            if let Ok(res) = output {
                return res.status.success()
                    && String::from_utf8_lossy(&res.stdout).contains("TTL=");
            }
        }
        #[cfg(not(windows))]
        {
            let output = Command::new("ping")
                .args(["-c", "1", "-W", "1", ip])
                .output();
            if let Ok(res) = output {
                return res.status.success();
            }
        }
        false
    }

    fn check_arp(ip: &str) -> bool {
        let output = Command::new("arp").args(["-a", ip]).output();
        if let Ok(res) = output {
            let stdout = String::from_utf8_lossy(&res.stdout);
            debug!("arp query for {}: {}", ip, stdout);
            return stdout.contains(ip)
                && (stdout.contains("dynamic")
                    || stdout.contains("static")
                    || stdout.contains("动态")
                    || stdout.contains("静态"));
        }
        false
    }
}
