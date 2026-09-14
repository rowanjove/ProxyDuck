use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, process::Command};
use tracing::info;

use super::{
    adapter::AdapterCollector, hosts::HostsCollector, proxy::ProxyCollector, route::RouteCollector,
};

const MAX_SNAPSHOTS_RETAINED: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotManifest {
    pub id: String,
    pub created_at: String,
    pub reason: String,
    pub items: Vec<String>,
    pub fully_reversible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WininetSnapshotData {
    pub enabled: bool,
    pub server: Option<String>,
    pub override_str: Option<String>,
    pub auto_config_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WinhttpSnapshotData {
    proxy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackItemResult {
    pub name: String,
    pub status: String, // "restored", "skipped", "failed"
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackReport {
    pub snapshot_id: String,
    pub success: bool,
    pub items: Vec<RollbackItemResult>,
}

pub struct SnapshotManager;

impl SnapshotManager {
    pub fn snapshots_dir() -> Result<PathBuf> {
        let dir = proxyduck_common::resolve_app_dir()?.join("snapshots");
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(dir)
    }

    pub async fn create_snapshot(reason: &str) -> Result<SnapshotManifest> {
        let timestamp_str = Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string();
        let id = format!("snap_{timestamp_str}_{}", uuid::Uuid::new_v4().simple());
        let base_dir = Self::snapshots_dir()?.join(&id);

        // 1. Save WinINET Proxy settings
        let proxy_status = ProxyCollector::check_proxy().await;
        if !proxy_status.wininet_accessible {
            anyhow::bail!("target user's WinINET registry hive is not accessible");
        }
        let wininet_data = WininetSnapshotData {
            enabled: proxy_status.wininet_enabled,
            server: proxy_status.wininet_server.clone(),
            override_str: proxy_status.wininet_override.clone(),
            auto_config_url: proxy_status.auto_config_url.clone(),
        };
        // 2. Save WinHTTP Proxy settings
        if !proxy_status.winhttp_accessible {
            anyhow::bail!("WinHTTP proxy state is not accessible or could not be parsed");
        }

        // Do not leave an empty recovery point behind when either system
        // proxy surface could not be captured reliably.
        fs::create_dir_all(&base_dir)?;
        let mut saved_items = Vec::new();

        let wininet_path = base_dir.join("wininet.json");
        fs::write(&wininet_path, serde_json::to_string_pretty(&wininet_data)?)?;
        saved_items.push("wininet".to_string());

        let winhttp_path = base_dir.join("winhttp.json");
        let winhttp_data = WinhttpSnapshotData {
            proxy: proxy_status.winhttp_proxy.clone(),
        };
        fs::write(&winhttp_path, serde_json::to_string_pretty(&winhttp_data)?)?;
        saved_items.push("winhttp".to_string());

        // 3. Save Hosts file
        let hosts_path = HostsCollector::hosts_path();
        if hosts_path.exists() {
            if let Ok(content) = fs::read_to_string(&hosts_path) {
                let hosts_backup = base_dir.join("hosts");
                fs::write(&hosts_backup, content)?;
                saved_items.push("hosts".to_string());
            }
        }

        // 4. Save Adapters & Routes metadata
        let adapters = AdapterCollector::collect();
        let adapters_path = base_dir.join("adapters.json");
        let _ = fs::write(&adapters_path, serde_json::to_string_pretty(&adapters)?);
        saved_items.push("adapters".to_string());

        let routes = RouteCollector::collect();
        let routes_path = base_dir.join("routes.json");
        let _ = fs::write(&routes_path, serde_json::to_string_pretty(&routes)?);
        saved_items.push("routes".to_string());

        let manifest = SnapshotManifest {
            id: id.clone(),
            created_at: Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            items: saved_items,
            // Adapter and route captures are diagnostic metadata; destructive
            // Winsock/TCP-IP resets cannot be completely reversed here.
            fully_reversible: false,
        };

        let manifest_path = base_dir.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

        info!(snapshot_id = %id, reason = %reason, "network snapshot created successfully");

        // Cleanup older snapshots if exceeding retention limit
        Self::cleanup_old_snapshots(MAX_SNAPSHOTS_RETAINED);

        Ok(manifest)
    }

    pub fn list_snapshots() -> Result<Vec<SnapshotManifest>> {
        let dir = Self::snapshots_dir()?;
        let mut list = Vec::new();

        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let manifest_file = entry.path().join("manifest.json");
                    if manifest_file.exists() {
                        if let Ok(content) = fs::read_to_string(&manifest_file) {
                            if let Ok(manifest) = serde_json::from_str::<SnapshotManifest>(&content)
                            {
                                list.push(manifest);
                            }
                        }
                    }
                }
            }
        }

        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(list)
    }

    pub fn rollback(snapshot_id: &str) -> Result<RollbackReport> {
        if snapshot_id.is_empty()
            || snapshot_id.len() > 64
            || !snapshot_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            anyhow::bail!("Invalid snapshot ID: {}", snapshot_id);
        }

        let dir = Self::snapshots_dir()?.join(snapshot_id);
        if !dir.exists() {
            anyhow::bail!("Snapshot {} not found", snapshot_id);
        }

        let mut item_results = Vec::new();
        let mut overall_success = true;

        // 1. Restore WinINET
        let wininet_path = dir.join("wininet.json");
        if wininet_path.exists() {
            match fs::read_to_string(&wininet_path)
                .and_then(|s| serde_json::from_str::<WininetSnapshotData>(&s).map_err(|e| e.into()))
            {
                Ok(data) => {
                    let res = Self::restore_wininet(&data);
                    if res.is_err() {
                        overall_success = false;
                    }
                    item_results.push(RollbackItemResult {
                        name: "wininet".to_string(),
                        status: if res.is_ok() {
                            "restored".to_string()
                        } else {
                            "failed".to_string()
                        },
                        message: res.err().map(|e| e.to_string()),
                    });
                }
                Err(e) => {
                    overall_success = false;
                    item_results.push(RollbackItemResult {
                        name: "wininet".to_string(),
                        status: "failed".to_string(),
                        message: Some(format!("Failed to parse wininet snapshot: {e}")),
                    });
                }
            }
        }

        // 2. Restore WinHTTP
        let winhttp_path = dir.join("winhttp.json");
        let legacy_winhttp_path = dir.join("winhttp.txt");
        if winhttp_path.exists() {
            match fs::read_to_string(&winhttp_path).and_then(|content| {
                serde_json::from_str::<WinhttpSnapshotData>(&content).map_err(Into::into)
            }) {
                Ok(data) => {
                    let res = Self::restore_winhttp(data.proxy.as_deref().unwrap_or_default());
                    if res.is_err() {
                        overall_success = false;
                    }
                    item_results.push(RollbackItemResult {
                        name: "winhttp".to_string(),
                        status: if res.is_ok() {
                            "restored".to_string()
                        } else {
                            "failed".to_string()
                        },
                        message: res.err().map(|e| e.to_string()),
                    });
                }
                Err(error) => {
                    overall_success = false;
                    item_results.push(RollbackItemResult {
                        name: "winhttp".to_string(),
                        status: "failed".to_string(),
                        message: Some(format!("Failed to parse WinHTTP snapshot: {error}")),
                    });
                }
            }
        } else if legacy_winhttp_path.exists() {
            if let Ok(server_str) = fs::read_to_string(&legacy_winhttp_path) {
                let res = Self::restore_winhttp(server_str.trim());
                if res.is_err() {
                    overall_success = false;
                }
                item_results.push(RollbackItemResult {
                    name: "winhttp".to_string(),
                    status: if res.is_ok() {
                        "restored".to_string()
                    } else {
                        "failed".to_string()
                    },
                    message: res.err().map(|e| e.to_string()),
                });
            } else {
                overall_success = false;
                item_results.push(RollbackItemResult {
                    name: "winhttp".to_string(),
                    status: "failed".to_string(),
                    message: Some("Failed to read WinHTTP snapshot".to_string()),
                });
            }
        } else {
            overall_success = false;
            item_results.push(RollbackItemResult {
                name: "winhttp".to_string(),
                status: "not-captured".to_string(),
                message: Some(
                    "Snapshot did not capture WinHTTP state; no system change was attempted"
                        .to_string(),
                ),
            });
        }

        // 3. Restore Hosts
        let hosts_backup = dir.join("hosts");
        if hosts_backup.exists() {
            let hosts_target = HostsCollector::hosts_path();
            match fs::copy(&hosts_backup, &hosts_target) {
                Ok(_) => {
                    item_results.push(RollbackItemResult {
                        name: "hosts".to_string(),
                        status: "restored".to_string(),
                        message: None,
                    });
                }
                Err(e) => {
                    overall_success = false;
                    item_results.push(RollbackItemResult {
                        name: "hosts".to_string(),
                        status: "failed".to_string(),
                        message: Some(format!(
                            "Failed to write hosts file: {e} (requires admin privileges)"
                        )),
                    });
                }
            }
        }

        // 4. Flush DNS Cache as post-rollback hygiene
        let _ = Command::new(system_command("ipconfig.exe"))
            .args(["/flushdns"])
            .output();

        info!(snapshot_id = %snapshot_id, "snapshot rollback execution completed");

        Ok(RollbackReport {
            snapshot_id: snapshot_id.to_string(),
            success: overall_success,
            items: item_results,
        })
    }

    fn restore_wininet(data: &WininetSnapshotData) -> Result<()> {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::Registry::{
                RegCloseKey, RegSetValueExW, KEY_SET_VALUE, REG_DWORD, REG_SZ,
            };

            unsafe {
                let hkey = super::proxy::open_target_internet_settings(KEY_SET_VALUE)?;

                let dword_val = if data.enabled { 1u32 } else { 0u32 };
                let enable_name: Vec<u16> = "ProxyEnable\0".encode_utf16().collect();
                let dword_bytes = dword_val.to_ne_bytes();
                RegSetValueExW(
                    hkey,
                    PCWSTR::from_raw(enable_name.as_ptr()),
                    None,
                    REG_DWORD,
                    Some(&dword_bytes),
                )
                .ok()?;

                for (name, value) in [
                    ("ProxyServer", data.server.as_deref()),
                    ("ProxyOverride", data.override_str.as_deref()),
                    ("AutoConfigURL", data.auto_config_url.as_deref()),
                ] {
                    let value_name: Vec<u16> = format!("{name}\0").encode_utf16().collect();
                    let value: Vec<u16> = format!("{}\0", value.unwrap_or_default())
                        .encode_utf16()
                        .collect();
                    let value_bytes =
                        std::slice::from_raw_parts(value.as_ptr() as *const u8, value.len() * 2);
                    RegSetValueExW(
                        hkey,
                        PCWSTR::from_raw(value_name.as_ptr()),
                        None,
                        REG_SZ,
                        Some(value_bytes),
                    )
                    .ok()?;
                }

                RegCloseKey(hkey).ok()?;
            }
        }
        Ok(())
    }

    fn restore_winhttp(server: &str) -> Result<()> {
        let output = if server.is_empty() {
            Command::new(system_command("netsh.exe"))
                .args(["winhttp", "reset", "proxy"])
                .output()?
        } else {
            Command::new(system_command("netsh.exe"))
                .args(["winhttp", "set", "proxy", server])
                .output()?
        };
        if !output.status.success() {
            anyhow::bail!(
                "netsh failed to restore WinHTTP proxy: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    fn cleanup_old_snapshots(keep_count: usize) {
        if let Ok(snapshots) = Self::list_snapshots() {
            if snapshots.len() > keep_count {
                if let Ok(dir) = Self::snapshots_dir() {
                    for snap in snapshots.iter().skip(keep_count) {
                        let snap_path = dir.join(&snap.id);
                        if snap_path.exists() {
                            let _ = fs::remove_dir_all(&snap_path);
                            info!(snapshot_id = %snap.id, "cleaned up old network snapshot");
                        }
                    }
                }
            }
        }
    }
}

fn system_command(name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join(name)
    }
    #[cfg(not(windows))]
    PathBuf::from(name)
}
