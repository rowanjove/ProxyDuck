use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

use crate::model::{ProxyKind, ProxyProfile, ProxyTestResult};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
const IO_TIMEOUT: Duration = Duration::from_millis(1500);

pub fn test_proxy(profile: &ProxyProfile) -> ProxyTestResult {
    let started = Instant::now();
    let outcome = match profile.kind {
        ProxyKind::Direct => Ok(Socks5Probe::default()),
        ProxyKind::Socks5 => test_socks5(profile),
        kind => Err(format!(
            "proxy type '{kind:?}' is not supported by the active backend"
        )),
    };

    let (reachable, protocol_accepted, tcp_supported, tcp_error, udp_supported, udp_error, error) =
        match outcome {
            Ok(probe) => (
                true,
                true,
                probe.tcp_supported,
                probe.tcp_error,
                probe.udp_supported,
                probe.udp_error,
                None,
            ),
            Err(error) => (false, false, None, None, None, None, Some(error)),
        };

    ProxyTestResult {
        proxy_id: profile.id.clone(),
        reachable,
        protocol_accepted,
        tcp_supported,
        tcp_error,
        udp_supported,
        udp_error,
        latency_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        error,
    }
}

#[derive(Debug, Default)]
struct Socks5Probe {
    tcp_supported: Option<bool>,
    tcp_error: Option<String>,
    udp_supported: Option<bool>,
    udp_error: Option<String>,
}

fn test_socks5(profile: &ProxyProfile) -> Result<Socks5Probe, String> {
    let addrs = profile
        .endpoint
        .to_socket_addrs()
        .map_err(|error| format!("invalid proxy endpoint: {error}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err("proxy endpoint resolved to no addresses".to_string());
    }

    let mut last_error = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(mut stream) => {
                configure_stream(&stream)?;
                negotiate_socks5(&mut stream, profile)?;
                let udp = probe_socks5_udp(&mut stream);
                let tcp = probe_socks5_tcp(profile, &addrs);
                return Ok(Socks5Probe {
                    tcp_supported: Some(tcp.is_ok()),
                    tcp_error: tcp.err(),
                    udp_supported: Some(udp.is_ok()),
                    udp_error: udp.err(),
                });
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }

    Err(format!(
        "failed to connect to proxy endpoint: {}",
        last_error.unwrap_or_else(|| "unknown connection error".to_string())
    ))
}

fn configure_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("failed to set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("failed to set write timeout: {error}"))?;
    Ok(())
}

fn probe_socks5_tcp(profile: &ProxyProfile, addrs: &[std::net::SocketAddr]) -> Result<(), String> {
    let mut last_error = "proxy endpoint resolved to no addresses".to_string();
    for addr in addrs {
        let result = (|| {
            let mut stream = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT)
                .map_err(|error| format!("TCP probe could not connect to proxy: {error}"))?;
            configure_stream(&stream)?;
            negotiate_socks5(&mut stream, profile)?;
            // Probing a public HTTPS endpoint proves that the proxy can establish
            // a TCP egress tunnel rather than merely answer a SOCKS greeting.
            stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb])
                .map_err(|error| format!("SOCKS5 TCP CONNECT request failed: {error}"))?;
            read_socks5_command_reply(&mut stream, "TCP CONNECT")
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn probe_socks5_udp(stream: &mut TcpStream) -> Result<(), String> {
    // UDP ASSOCIATE with 0.0.0.0:0 asks the proxy to choose the relay endpoint.
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|error| format!("SOCKS5 UDP ASSOCIATE request failed: {error}"))?;

    read_socks5_command_reply(stream, "UDP ASSOCIATE")
}

fn read_socks5_command_reply(stream: &mut TcpStream, command: &str) -> Result<(), String> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| format!("SOCKS5 {command} response failed: {error}"))?;
    if header[0] != 0x05 {
        return Err(format!("SOCKS5 {command} returned version {}", header[0]));
    }
    if header[1] != 0x00 {
        return Err(format!(
            "SOCKS5 {command} was rejected with status 0x{:02x}",
            header[1]
        ));
    }
    if header[2] != 0x00 {
        return Err(format!(
            "SOCKS5 {command} returned an invalid reserved byte"
        ));
    }

    let address_length = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .map_err(|error| format!("SOCKS5 {command} domain length failed: {error}"))?;
            usize::from(length[0])
        }
        kind => {
            return Err(format!(
                "SOCKS5 {command} used unknown address type 0x{kind:02x}"
            ))
        }
    };
    let mut address_and_port = vec![0_u8; address_length + 2];
    stream
        .read_exact(&mut address_and_port)
        .map_err(|error| format!("SOCKS5 {command} bound address failed: {error}"))?;
    Ok(())
}

fn negotiate_socks5(stream: &mut TcpStream, profile: &ProxyProfile) -> Result<(), String> {
    let use_credentials = profile.username.is_some() || profile.password.is_some();
    let greeting: &[u8] = if use_credentials {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream
        .write_all(greeting)
        .map_err(|error| format!("SOCKS5 greeting failed: {error}"))?;

    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("SOCKS5 greeting response failed: {error}"))?;
    if response[0] != 0x05 {
        return Err(format!("unexpected SOCKS version: {}", response[0]));
    }
    match response[1] {
        0x00 => Ok(()),
        0x02 if use_credentials => authenticate_socks5(stream, profile),
        0xff => Err("SOCKS5 server rejected all authentication methods".to_string()),
        method => Err(format!(
            "SOCKS5 server selected unsupported method 0x{method:02x}"
        )),
    }
}

fn authenticate_socks5(stream: &mut TcpStream, profile: &ProxyProfile) -> Result<(), String> {
    let username = profile.username.as_deref().unwrap_or("").as_bytes();
    let password = profile.password.as_deref().unwrap_or("").as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err("SOCKS5 username or password exceeds 255 bytes".to_string());
    }

    let mut request = Vec::with_capacity(username.len() + password.len() + 3);
    request.extend_from_slice(&[0x01, username.len() as u8]);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream
        .write_all(&request)
        .map_err(|error| format!("SOCKS5 authentication request failed: {error}"))?;

    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("SOCKS5 authentication response failed: {error}"))?;
    if response == [0x01, 0x00] {
        Ok(())
    } else {
        Err("SOCKS5 username/password authentication failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    fn serve_no_auth_command(listener: &TcpListener, command: u8, status: u8) {
        let (mut stream, _) = listener.accept().unwrap();
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        stream.write_all(&[0x05, 0x00]).unwrap();
        let mut request = [0_u8; 10];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request[0], 0x05);
        assert_eq!(request[1], command);
        stream
            .write_all(&[0x05, status, 0x00, 0x01, 127, 0, 0, 1, 0x30, 0x39])
            .unwrap();
    }

    fn serve_authenticated_command(listener: &TcpListener, command: u8) {
        let (mut stream, _) = listener.accept().unwrap();
        let mut greeting = [0_u8; 4];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
        stream.write_all(&[0x05, 0x02]).unwrap();
        let mut authentication = [0_u8; 13];
        stream.read_exact(&mut authentication).unwrap();
        assert_eq!(authentication, *b"\x01\x05alice\x05s3crt");
        stream.write_all(&[0x01, 0x00]).unwrap();
        let mut request = [0_u8; 10];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request[1], command);
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x30, 0x39])
            .unwrap();
    }

    #[test]
    fn verifies_a_real_socks5_greeting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            serve_no_auth_command(&listener, 0x03, 0x00);
            serve_no_auth_command(&listener, 0x01, 0x00);
        });

        let result = test_proxy(&ProxyProfile {
            id: "test".to_string(),
            name: "Test".to_string(),
            kind: ProxyKind::Socks5,
            endpoint,
            username: None,
            password: None,
            enabled: true,
        });
        server.join().unwrap();
        assert!(result.reachable);
        assert!(result.protocol_accepted);
        assert_eq!(result.tcp_supported, Some(true));
        assert_eq!(result.udp_supported, Some(true));
        assert!(result.error.is_none());
    }

    #[test]
    fn rejects_a_non_socks_service() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            stream.write_all(b"HT").unwrap();
        });

        let mut profile = ProxyProfile::clash_default();
        profile.endpoint = endpoint;
        let result = test_proxy(&profile);
        server.join().unwrap();
        assert!(!result.protocol_accepted);
        assert!(result.error.unwrap().contains("unexpected SOCKS version"));
    }

    #[test]
    fn verifies_username_password_authentication_before_udp_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            serve_authenticated_command(&listener, 0x03);
            serve_authenticated_command(&listener, 0x01);
        });

        let result = test_proxy(&ProxyProfile {
            id: "authenticated".to_string(),
            name: "Authenticated".to_string(),
            kind: ProxyKind::Socks5,
            endpoint,
            username: Some("alice".to_string()),
            password: Some("s3crt".to_string()),
            enabled: true,
        });
        server.join().unwrap();
        assert!(result.protocol_accepted);
        assert_eq!(result.tcp_supported, Some(true));
        assert_eq!(result.udp_supported, Some(true));
        assert!(result.udp_error.is_none());
    }

    #[test]
    fn reports_udp_rejection_without_hiding_a_valid_socks_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            serve_no_auth_command(&listener, 0x03, 0x07);
            serve_no_auth_command(&listener, 0x01, 0x00);
        });

        let mut profile = ProxyProfile::clash_default();
        profile.endpoint = endpoint;
        let result = test_proxy(&profile);
        server.join().unwrap();
        assert!(result.protocol_accepted);
        assert_eq!(result.tcp_supported, Some(true));
        assert_eq!(result.udp_supported, Some(false));
        assert!(result.udp_error.unwrap().contains("status 0x07"));
        assert!(result.error.is_none());
    }
}
