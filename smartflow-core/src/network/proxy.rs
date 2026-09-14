use std::{collections::HashMap, net::SocketAddr, process::Command, time::Duration};
use tokio::net::TcpStream;
use tracing::debug;

use super::model::ProxyStatus;

const PROXY_PORT_TIMEOUT: Duration = Duration::from_millis(800);

#[cfg(windows)]
pub(crate) fn open_target_internet_settings(
    access: windows::Win32::System::Registry::REG_SAM_FLAGS,
) -> anyhow::Result<windows::Win32::System::Registry::HKEY> {
    use windows::{
        core::PCWSTR,
        Win32::System::Registry::{RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_USERS},
    };

    let configured_sid = std::env::var(proxyduck_common::INSTALLER_USER_SID_ENV)
        .ok()
        .filter(|sid| !sid.trim().is_empty());
    let (root, subkey) = if let Some(sid) = configured_sid {
        if !sid.starts_with("S-1-")
            || !sid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            anyhow::bail!("configured installer user SID is invalid");
        }
        (
            HKEY_USERS,
            format!(
                "{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0",
                sid
            ),
        )
    } else {
        (
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0".to_string(),
        )
    };
    let subkey: Vec<u16> = subkey.encode_utf16().collect();
    let mut hkey = HKEY::default();
    unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR::from_raw(subkey.as_ptr()),
            None,
            access,
            &mut hkey,
        )
        .ok()?;
    }
    Ok(hkey)
}

pub struct ProxyCollector;

impl ProxyCollector {
    pub async fn check_proxy() -> ProxyStatus {
        let (
            wininet_accessible,
            wininet_enabled,
            wininet_server,
            wininet_override,
            auto_config_url,
        ) = Self::query_wininet_registry();

        let (winhttp_accessible, winhttp_proxy) = Self::query_winhttp_proxy();
        let env_proxies = Self::query_env_proxies();

        let is_proxy_configured = wininet_enabled
            || wininet_server.is_some()
            || auto_config_url.is_some()
            || winhttp_proxy.is_some()
            || !env_proxies.is_empty();

        // If WinINET proxy server is enabled, test if the port is reachable
        let mut proxy_port_reachable = None;
        if wininet_enabled {
            if let Some(ref srv) = wininet_server {
                proxy_port_reachable = Some(Self::probe_proxy_endpoint(srv).await);
            }
        }

        // Check PAC accessibility if configured
        let pac_accessible = if let Some(ref pac) = auto_config_url {
            Some(Self::probe_pac_url(pac).await)
        } else {
            None
        };

        ProxyStatus {
            wininet_accessible,
            wininet_enabled,
            wininet_server,
            wininet_override,
            auto_config_url,
            winhttp_accessible,
            winhttp_proxy,
            env_proxies,
            pac_accessible,
            is_proxy_configured,
            proxy_port_reachable,
        }
    }

    fn query_wininet_registry() -> (bool, bool, Option<String>, Option<String>, Option<String>) {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::Registry::{
                RegCloseKey, RegQueryValueExW, KEY_READ, REG_DWORD, REG_SZ,
            };

            unsafe {
                let Ok(hkey) = open_target_internet_settings(KEY_READ) else {
                    return (false, false, None, None, None);
                };

                let query_dword = |name: &str| -> Option<u32> {
                    let name_w: Vec<u16> = format!("{name}\0").encode_utf16().collect();
                    let mut val_type = REG_DWORD;
                    let mut data = 0u32;
                    let mut data_len = std::mem::size_of::<u32>() as u32;
                    if RegQueryValueExW(
                        hkey,
                        PCWSTR::from_raw(name_w.as_ptr()),
                        None,
                        Some(&mut val_type),
                        Some(&mut data as *mut _ as *mut u8),
                        Some(&mut data_len),
                    )
                    .is_ok()
                    {
                        Some(data)
                    } else {
                        None
                    }
                };

                let query_string = |name: &str| -> Option<String> {
                    let name_w: Vec<u16> = format!("{name}\0").encode_utf16().collect();
                    let mut val_type = REG_SZ;
                    let mut data_len = 0u32;
                    if RegQueryValueExW(
                        hkey,
                        PCWSTR::from_raw(name_w.as_ptr()),
                        None,
                        Some(&mut val_type),
                        None,
                        Some(&mut data_len),
                    )
                    .is_err()
                        || data_len == 0
                    {
                        return None;
                    }

                    let mut buf: Vec<u16> = vec![0; (data_len as usize / 2) + 1];
                    if RegQueryValueExW(
                        hkey,
                        PCWSTR::from_raw(name_w.as_ptr()),
                        None,
                        Some(&mut val_type),
                        Some(buf.as_mut_ptr() as *mut u8),
                        Some(&mut data_len),
                    )
                    .is_ok()
                    {
                        let s = String::from_utf16_lossy(&buf);
                        let clean = s.trim_matches('\0').trim().to_string();
                        if clean.is_empty() {
                            None
                        } else {
                            Some(clean)
                        }
                    } else {
                        None
                    }
                };

                let enabled = query_dword("ProxyEnable").unwrap_or(0) == 1;
                let server = query_string("ProxyServer");
                let override_str = query_string("ProxyOverride");
                let auto_config_url = query_string("AutoConfigURL");

                let _ = RegCloseKey(hkey);
                (true, enabled, server, override_str, auto_config_url)
            }
        }
        #[cfg(not(windows))]
        {
            (false, false, None, None, None)
        }
    }

    fn query_winhttp_proxy() -> (bool, Option<String>) {
        #[cfg(windows)]
        {
            let Ok(output) = Command::new(system_command("netsh.exe"))
                .args(["winhttp", "show", "proxy"])
                .output()
            else {
                return (false, None);
            };
            if !output.status.success() {
                return (false, None);
            }
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if (trimmed.starts_with("Proxy Server(s) :") || trimmed.starts_with("代理服务器:"))
                    && !trimmed.contains("Direct access")
                    && !trimmed.contains("直接访问")
                {
                    let val = trimmed
                        .split(':')
                        .skip(1)
                        .collect::<Vec<&str>>()
                        .join(":")
                        .trim()
                        .to_string();
                    if !val.is_empty() {
                        return (true, Some(val));
                    }
                }
            }
            if text.contains("Direct access") || text.contains("直接访问") {
                return (true, None);
            }
            (false, None)
        }
        #[cfg(not(windows))]
        (false, None)
    }

    fn query_env_proxies() -> HashMap<String, String> {
        let keys = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ];
        let mut map = HashMap::new();
        for key in keys {
            if let Ok(val) = std::env::var(key) {
                if !val.trim().is_empty() {
                    map.insert(key.to_string(), val);
                }
            }
        }
        map
    }

    async fn probe_proxy_endpoint(server_str: &str) -> bool {
        // e.g., "127.0.0.1:7890" or "http=127.0.0.1:7890;https=127.0.0.1:7890"
        let endpoint = server_str
            .split(';')
            .next()
            .unwrap_or("")
            .split('=')
            .next_back()
            .unwrap_or("")
            .trim();

        if endpoint.is_empty() {
            return false;
        }

        let sock_addr = if let Ok(addr) = endpoint.parse::<SocketAddr>() {
            addr
        } else if let Ok(addr) = format!("127.0.0.1:{endpoint}").parse::<SocketAddr>() {
            addr
        } else {
            return false;
        };

        tokio::time::timeout(PROXY_PORT_TIMEOUT, TcpStream::connect(sock_addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }

    async fn probe_pac_url(pac_url: &str) -> bool {
        // Simple probe to check if PAC host/port is reachable
        debug!("probing PAC url: {}", pac_url);
        if let Some(host_port) = pac_url
            .strip_prefix("http://")
            .or_else(|| pac_url.strip_prefix("https://"))
            .and_then(|s| s.split('/').next())
        {
            let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
                (h, p.parse::<u16>().unwrap_or(80))
            } else {
                (host_port, 80)
            };
            if let Ok(mut addrs) = tokio::net::lookup_host((host, port)).await {
                if let Some(addr) = addrs.next() {
                    return tokio::time::timeout(PROXY_PORT_TIMEOUT, TcpStream::connect(addr))
                        .await
                        .map(|r| r.is_ok())
                        .unwrap_or(false);
                }
            }
        }
        false
    }
}

fn system_command(name: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join(name)
    }
    #[cfg(not(windows))]
    std::path::PathBuf::from(name)
}
