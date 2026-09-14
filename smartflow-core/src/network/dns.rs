use std::{
    net::SocketAddr,
    process::Command,
    time::{Duration, Instant},
};
use tokio::net::{lookup_host, UdpSocket};

use super::model::{DnsResolveResult, DnsStatus};

const DNS_TIMEOUT: Duration = Duration::from_millis(1500);

pub struct DnsCollector;

impl DnsCollector {
    pub async fn check_dns(configured_servers: Vec<String>) -> DnsStatus {
        let mut servers_reachable = Vec::new();

        // 1. Probe configured DNS servers on port 53
        for server in &configured_servers {
            if Self::probe_dns_port(server).await {
                servers_reachable.push(server.clone());
            }
        }

        // 2. Perform domain resolutions
        let test_domains = vec!["www.msftconnecttest.com", "qq.com", "bing.com"];

        let mut resolve_results = Vec::new();
        let mut all_succeeded = true;

        for domain in test_domains {
            let res = Self::resolve_domain(domain).await;
            if !res.success {
                all_succeeded = false;
            }
            resolve_results.push(res);
        }

        // 3. Dnscache service status
        let cache_service_running = tokio::task::spawn_blocking(Self::check_dnscache_service)
            .await
            .unwrap_or(true);

        DnsStatus {
            configured_servers,
            servers_reachable,
            resolve_results,
            all_resolves_succeeded: all_succeeded,
            cache_service_running,
        }
    }

    async fn probe_dns_port(server_ip: &str) -> bool {
        let clean_ip = server_ip.trim();
        let Ok(sock_addr) = format!("{clean_ip}:53").parse::<SocketAddr>() else {
            return false;
        };

        // Try UDP probe
        let bind_addr: SocketAddr = if sock_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let Ok(socket) = UdpSocket::bind(bind_addr).await else {
            return false;
        };

        // Minimal standard DNS query header for root "."
        let query: [u8; 12] = [
            0xAA, 0xAA, // Transaction ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
        ];

        if socket.send_to(&query, sock_addr).await.is_err() {
            return false;
        }

        let mut buf = [0u8; 512];
        tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut buf))
            .await
            .is_ok()
    }

    async fn resolve_domain(domain: &str) -> DnsResolveResult {
        let started = Instant::now();

        match tokio::time::timeout(DNS_TIMEOUT, lookup_host((domain, 80))).await {
            Ok(Ok(addrs)) => {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                let latency = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                if ips.is_empty() {
                    DnsResolveResult {
                        query: domain.to_string(),
                        success: false,
                        resolved_ips: Vec::new(),
                        latency_ms: Some(latency),
                        error: Some("DNS returned 0 records".to_string()),
                    }
                } else {
                    DnsResolveResult {
                        query: domain.to_string(),
                        success: true,
                        resolved_ips: ips,
                        latency_ms: Some(latency),
                        error: None,
                    }
                }
            }
            Ok(Err(e)) => DnsResolveResult {
                query: domain.to_string(),
                success: false,
                resolved_ips: Vec::new(),
                latency_ms: None,
                error: Some(e.to_string()),
            },
            Err(_) => DnsResolveResult {
                query: domain.to_string(),
                success: false,
                resolved_ips: Vec::new(),
                latency_ms: None,
                error: Some("DNS resolution timed out".to_string()),
            },
        }
    }

    fn check_dnscache_service() -> bool {
        #[cfg(windows)]
        {
            if let Ok(output) = Command::new("sc").args(["query", "dnscache"]).output() {
                let text = String::from_utf8_lossy(&output.stdout);
                return text.contains("RUNNING");
            }
        }
        true
    }
}
