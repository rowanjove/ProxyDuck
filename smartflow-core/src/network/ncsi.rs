use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::model::NcsiStatus;

const NCSI_TIMEOUT: Duration = Duration::from_millis(2500);

pub struct NcsiCollector;

impl NcsiCollector {
    pub async fn check_ncsi() -> NcsiStatus {
        let started = Instant::now();
        // Probe Microsoft NCSI standard endpoint
        let host = "www.msftconnecttest.com";
        let port = 80;

        let stream_res =
            tokio::time::timeout(NCSI_TIMEOUT, TcpStream::connect(format!("{host}:{port}"))).await;
        let mut stream = match stream_res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return NcsiStatus {
                    http_connect_ok: false,
                    payload_verified: false,
                    captive_portal_detected: false,
                    redirect_location: None,
                    latency_ms: None,
                    error: Some(format!("Failed to connect to NCSI server: {e}")),
                };
            }
            Err(_) => {
                return NcsiStatus {
                    http_connect_ok: false,
                    payload_verified: false,
                    captive_portal_detected: false,
                    redirect_location: None,
                    latency_ms: None,
                    error: Some("NCSI connection timed out".to_string()),
                };
            }
        };

        let request = format!(
            "GET /connecttest.txt HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Microsoft NCSI\r\nConnection: close\r\n\r\n"
        );

        if let Err(e) = stream.write_all(request.as_bytes()).await {
            return NcsiStatus {
                http_connect_ok: true,
                payload_verified: false,
                captive_portal_detected: false,
                redirect_location: None,
                latency_ms: Some(started.elapsed().as_millis() as u64),
                error: Some(format!("Failed to send HTTP request: {e}")),
            };
        }

        let mut buf = vec![0u8; 4096];
        let read_res = tokio::time::timeout(NCSI_TIMEOUT, stream.read_to_end(&mut buf)).await;
        let latency = started.elapsed().as_millis() as u64;

        match read_res {
            Ok(Ok(_)) => {
                let response = String::from_utf8_lossy(&buf);
                let first_line = response.lines().next().unwrap_or("");

                // Check for redirect (Captive Portal)
                if first_line.contains("301")
                    || first_line.contains("302")
                    || first_line.contains("307")
                {
                    let mut location = None;
                    for line in response.lines() {
                        if line.to_lowercase().starts_with("location:") {
                            location = Some(
                                line.split(':')
                                    .skip(1)
                                    .collect::<Vec<&str>>()
                                    .join(":")
                                    .trim()
                                    .to_string(),
                            );
                            break;
                        }
                    }
                    return NcsiStatus {
                        http_connect_ok: true,
                        payload_verified: false,
                        captive_portal_detected: true,
                        redirect_location: location,
                        latency_ms: Some(latency),
                        error: Some("Captive portal redirection detected".to_string()),
                    };
                }

                if response.contains("Microsoft Connect Test") {
                    NcsiStatus {
                        http_connect_ok: true,
                        payload_verified: true,
                        captive_portal_detected: false,
                        redirect_location: None,
                        latency_ms: Some(latency),
                        error: None,
                    }
                } else {
                    // Body returned but not the expected NCSI token -> likely captive portal intercept
                    NcsiStatus {
                        http_connect_ok: true,
                        payload_verified: false,
                        captive_portal_detected: true,
                        redirect_location: None,
                        latency_ms: Some(latency),
                        error: Some("NCSI response payload mismatched; possibly captive portal or web filter".to_string()),
                    }
                }
            }
            Ok(Err(e)) => NcsiStatus {
                http_connect_ok: true,
                payload_verified: false,
                captive_portal_detected: false,
                redirect_location: None,
                latency_ms: Some(latency),
                error: Some(format!("Failed to read NCSI response: {e}")),
            },
            Err(_) => NcsiStatus {
                http_connect_ok: true,
                payload_verified: false,
                captive_portal_detected: false,
                redirect_location: None,
                latency_ms: Some(latency),
                error: Some("Timeout reading NCSI response".to_string()),
            },
        }
    }
}
