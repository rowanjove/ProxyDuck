use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::net::TcpStream;

use super::model::{InternetProbeResult, InternetStatus};

const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

pub struct InternetCollector;

impl InternetCollector {
    pub async fn check_internet() -> InternetStatus {
        let targets = vec![
            // Target IP, protocol, port
            ("223.5.5.5", "TCP", 80),
            ("223.5.5.5", "TCP", 443),
            ("119.29.29.29", "TCP", 80),
            ("1.1.1.1", "TCP", 80),
            ("8.8.8.8", "TCP", 53),
        ];

        let mut tasks = Vec::new();
        for (ip, proto, port) in targets {
            tasks.push(tokio::spawn(async move {
                Self::probe_target(ip, proto, port).await
            }));
        }

        let mut results = Vec::new();
        let mut success_count = 0;

        for task in tasks {
            if let Ok(res) = task.await {
                if res.success {
                    success_count += 1;
                }
                results.push(res);
            }
        }

        let total = results.len();
        let ip_level_connected = success_count > 0;

        InternetStatus {
            ip_level_connected,
            probes: results,
            success_count,
            total_count: total,
        }
    }

    async fn probe_target(ip: &'static str, proto: &'static str, port: u16) -> InternetProbeResult {
        let addr_str = format!("{ip}:{port}");
        let Ok(sock_addr) = addr_str.parse::<SocketAddr>() else {
            return InternetProbeResult {
                target: ip.to_string(),
                protocol: proto.to_string(),
                port,
                success: false,
                latency_ms: None,
                error: Some("Invalid socket address".to_string()),
            };
        };

        let started = Instant::now();
        match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(sock_addr)).await {
            Ok(Ok(_stream)) => {
                let latency = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                InternetProbeResult {
                    target: ip.to_string(),
                    protocol: proto.to_string(),
                    port,
                    success: true,
                    latency_ms: Some(latency),
                    error: None,
                }
            }
            Ok(Err(e)) => InternetProbeResult {
                target: ip.to_string(),
                protocol: proto.to_string(),
                port,
                success: false,
                latency_ms: None,
                error: Some(e.to_string()),
            },
            Err(_) => InternetProbeResult {
                target: ip.to_string(),
                protocol: proto.to_string(),
                port,
                success: false,
                latency_ms: None,
                error: Some("Connection timed out".to_string()),
            },
        }
    }
}
