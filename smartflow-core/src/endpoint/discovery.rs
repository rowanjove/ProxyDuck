use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::{ProcessInfo, ProxyKind, ProxyProfile};
use crate::observability::ConnectionCollector;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredEndpoint {
    pub endpoint: String,
    pub host: String,
    pub port: u16,
    pub kind: ProxyKind,
    pub pid: u32,
    pub process_name: String,
    pub latency_ms: u64,
    pub auth_required: bool,
    pub already_configured: bool,
}

pub struct EndpointDiscoverer;

impl EndpointDiscoverer {
    /// Discovers candidate proxy endpoints by scanning local listening ports and performing protocol probes.
    pub async fn discover(
        processes: &[ProcessInfo],
        existing_proxies: &[ProxyProfile],
        own_port: u16,
    ) -> Vec<DiscoveredEndpoint> {
        let listening_entries = Self::collect_listening_candidates(own_port);
        let existing_endpoints = existing_proxies
            .iter()
            .map(|p| p.endpoint.trim().to_ascii_lowercase())
            .collect::<HashSet<_>>();

        let proc_map = processes
            .iter()
            .map(|p| (p.pid, p.name.clone()))
            .collect::<std::collections::HashMap<_, _>>();

        let mut discovered = Vec::new();

        for candidate in listening_entries {
            let endpoint_str = format!("127.0.0.1:{}", candidate.port);
            let already_configured =
                existing_endpoints.contains(&endpoint_str.to_ascii_lowercase());

            // Probe SOCKS5 first, then HTTP proxy
            if let Some(probe_res) = Self::probe_socks5(&endpoint_str).await {
                let process_name = proc_map
                    .get(&candidate.pid)
                    .cloned()
                    .unwrap_or_else(|| format!("PID {}", candidate.pid));

                discovered.push(DiscoveredEndpoint {
                    endpoint: endpoint_str,
                    host: "127.0.0.1".to_string(),
                    port: candidate.port,
                    kind: ProxyKind::Socks5,
                    pid: candidate.pid,
                    process_name,
                    latency_ms: probe_res.latency_ms,
                    auth_required: probe_res.auth_required,
                    already_configured,
                });
            } else if let Some(probe_res) = Self::probe_http(&endpoint_str).await {
                let process_name = proc_map
                    .get(&candidate.pid)
                    .cloned()
                    .unwrap_or_else(|| format!("PID {}", candidate.pid));

                discovered.push(DiscoveredEndpoint {
                    endpoint: endpoint_str,
                    host: "127.0.0.1".to_string(),
                    port: candidate.port,
                    kind: ProxyKind::Http,
                    pid: candidate.pid,
                    process_name,
                    latency_ms: probe_res.latency_ms,
                    auth_required: probe_res.auth_required,
                    already_configured,
                });
            }
        }

        discovered
    }

    fn collect_listening_candidates(own_port: u16) -> Vec<ListeningCandidate> {
        #[cfg(windows)]
        {
            if let Ok(output) = std::process::Command::new("netstat")
                .args(["-ano", "-p", "tcp"])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout);
                let entries = ConnectionCollector::parse_netstat_tcp(&text);

                let mut candidates = Vec::new();
                let mut seen_ports = HashSet::new();

                for e in entries {
                    if e.status == crate::observability::ConnectionStatus::Listening {
                        // Candidate must be loopback or 0.0.0.0
                        if (e.local_ip == "127.0.0.1" || e.local_ip == "0.0.0.0")
                            && e.local_port > 1024
                            && e.local_port != own_port
                            && !is_system_port(e.local_port)
                            && seen_ports.insert(e.local_port)
                        {
                            candidates.push(ListeningCandidate {
                                port: e.local_port,
                                pid: e.pid,
                            });
                        }
                    }
                }
                return candidates;
            }
        }

        let _ = own_port;
        Vec::new()
    }

    /// Non-blocking probe for SOCKS5 greeting: sends `[0x05, 0x01, 0x00]`
    pub async fn probe_socks5(endpoint: &str) -> Option<ProbeSuccess> {
        let start = std::time::Instant::now();
        let mut stream = timeout(Duration::from_millis(300), TcpStream::connect(endpoint))
            .await
            .ok()?
            .ok()?;

        // SOCKS5 greeting request: VER=5, NMETHODS=1, METHOD=0 (NO AUTH)
        let req = [0x05, 0x01, 0x00];
        stream.write_all(&req).await.ok()?;

        let mut resp = [0u8; 2];
        timeout(Duration::from_millis(300), stream.read_exact(&mut resp))
            .await
            .ok()?
            .ok()?;

        let elapsed = start.elapsed().as_millis() as u64;

        if resp[0] == 0x05 {
            let auth_required = resp[1] != 0x00;
            return Some(ProbeSuccess {
                latency_ms: elapsed.max(1),
                auth_required,
            });
        }

        None
    }

    /// Non-blocking probe for HTTP proxy: sends a simple HTTP CONNECT request
    pub async fn probe_http(endpoint: &str) -> Option<ProbeSuccess> {
        let start = std::time::Instant::now();
        let mut stream = timeout(Duration::from_millis(300), TcpStream::connect(endpoint))
            .await
            .ok()?
            .ok()?;

        let req = b"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n";
        stream.write_all(req).await.ok()?;

        let mut buf = [0u8; 128];
        let n = timeout(Duration::from_millis(300), stream.read(&mut buf))
            .await
            .ok()?
            .ok()?;

        let elapsed = start.elapsed().as_millis() as u64;

        if n > 0 {
            let resp_text = String::from_utf8_lossy(&buf[..n]);
            if resp_text.starts_with("HTTP/1.1 200")
                || resp_text.starts_with("HTTP/1.0 200")
                || resp_text.starts_with("HTTP/1.1 407")
            {
                let auth_required = resp_text.contains("407");
                return Some(ProbeSuccess {
                    latency_ms: elapsed.max(1),
                    auth_required,
                });
            }
        }

        None
    }
}

pub struct ProbeSuccess {
    pub latency_ms: u64,
    pub auth_required: bool,
}

struct ListeningCandidate {
    port: u16,
    pid: u32,
}

fn is_system_port(port: u16) -> bool {
    matches!(port, 135 | 445 | 5040 | 5357 | 49664..=49670)
}
