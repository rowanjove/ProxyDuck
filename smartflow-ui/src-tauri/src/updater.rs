use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DEFAULT_REPO: &str = "rowanjove/ProxyDuck";
const MAX_INSTALLER_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    pub has_update: bool,
    pub current_version: String,
    pub latest_version: String,
    pub release_name: String,
    pub release_notes: String,
    pub published_at: String,
    pub download_url: Option<String>,
    pub asset_name: Option<String>,
    pub asset_size: Option<u64>,
}

fn parse_semver(s: &str) -> (u32, u32, u32) {
    let clean = s.trim().trim_start_matches('v').trim_start_matches('V');
    let mut parts = clean.split('.');
    let major = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    let patch = parts
        .next()
        .and_then(|p| p.split('-').next())
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor, patch)
}

fn is_newer_version(latest: &str, current: &str) -> bool {
    parse_semver(latest) > parse_semver(current)
}

fn is_official_release_url(value: &str) -> bool {
    value.starts_with(&format!(
        "https://github.com/{DEFAULT_REPO}/releases/download/"
    ))
}

pub fn check_for_updates(custom_endpoint: Option<String>) -> anyhow::Result<UpdateCheckResult> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let url = custom_endpoint
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("https://api.github.com/repos/{DEFAULT_REPO}/releases/latest"));

    let client = reqwest::blocking::Client::builder()
        .user_agent("ProxyDuck-Desktop-App")
        .timeout(Duration::from_secs(10))
        .build()?;

    let res = client.get(&url).send()?;
    if !res.status().is_success() {
        anyhow::bail!("update check failed with status: {}", res.status());
    }

    let release: Value = res.json()?;
    let tag_name = release
        .get("tag_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let release_name = release
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(&tag_name)
        .to_string();
    let release_notes = release
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let published_at = release
        .get("published_at")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let clean_latest = tag_name.trim_start_matches('v').to_string();
    let has_update = is_newer_version(&clean_latest, &current_version);

    let mut download_url = None;
    let mut asset_name = None;
    let mut asset_size = None;

    let expected_asset = format!("ProxyDuck-{clean_latest}-setup.exe");
    if let Some(assets) = release.get("assets").and_then(Value::as_array) {
        for asset in assets {
            let name = asset.get("name").and_then(Value::as_str).unwrap_or("");
            if name.eq_ignore_ascii_case(&expected_asset) {
                download_url = asset
                    .get("browser_download_url")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                asset_name = Some(name.to_string());
                asset_size = asset.get("size").and_then(Value::as_u64);
                break;
            }
        }
    }

    Ok(UpdateCheckResult {
        has_update,
        current_version,
        latest_version: clean_latest,
        release_name,
        release_notes,
        published_at,
        download_url,
        asset_name,
        asset_size,
    })
}

pub fn download_and_install_update(
    download_url: &str,
    app: &tauri::AppHandle,
) -> anyhow::Result<()> {
    let clean_url = download_url.trim();
    if !clean_url.starts_with("https://") {
        anyhow::bail!("update download URL must use secure HTTPS protocol");
    }

    let allowed_prefix = format!("https://github.com/{DEFAULT_REPO}/releases/download/");
    let is_official_release = is_official_release_url(clean_url);
    let allow_custom = std::env::var("PROXYDUCK_ALLOW_CUSTOM_UPDATE_URL")
        .map(|v| v == "1")
        .unwrap_or(false);

    if !is_official_release && !allow_custom {
        anyhow::bail!(
            "untrusted update source; updates must come from official repository: {}",
            allowed_prefix
        );
    }

    let client = reqwest::blocking::Client::builder()
        .user_agent("ProxyDuck-Desktop-App")
        .timeout(Duration::from_secs(300))
        .build()?;

    let mut response = client.get(clean_url).send()?;
    if !response.status().is_success() {
        anyhow::bail!("failed to download installer: HTTP {}", response.status());
    }

    if response
        .content_length()
        .is_some_and(|length| length > MAX_INSTALLER_BYTES)
    {
        anyhow::bail!("installer exceeds the maximum allowed size");
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let installer_path: PathBuf = env::temp_dir().join(format!(
        "ProxyDuck-Update-{}-{nonce}-Setup.exe",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&installer_path)?;

    let mut bounded = Read::by_ref(&mut response).take(MAX_INSTALLER_BYTES + 1);
    let copied = match std::io::copy(&mut bounded, &mut file) {
        Ok(copied) => copied,
        Err(e) => {
            let _ = fs::remove_file(&installer_path);
            return Err(e.into());
        }
    };
    if copied > MAX_INSTALLER_BYTES {
        let _ = fs::remove_file(&installer_path);
        anyhow::bail!("installer exceeds the maximum allowed size");
    }
    file.flush()?;
    drop(file);

    #[cfg(target_os = "windows")]
    if let Err(error) = verify_matching_authenticode_signature(&installer_path) {
        let _ = fs::remove_file(&installer_path);
        return Err(error);
    }

    // Launch Inno Setup installer silently
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new(&installer_path);
        cmd.args(["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"]);
        cmd.creation_flags(CREATE_NO_WINDOW);
        if let Err(e) = cmd.spawn() {
            let _ = fs::remove_file(&installer_path);
            return Err(e.into());
        }
    }

    // Exit current app so Inno Setup can safely replace executable files
    let handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        handle.exit(0);
    });

    Ok(())
}

#[cfg(target_os = "windows")]
fn verify_matching_authenticode_signature(installer_path: &std::path::Path) -> anyhow::Result<()> {
    let current_exe = env::current_exe()?;
    let powershell = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let script = r#"
$ErrorActionPreference='Stop'
$candidate=Get-AuthenticodeSignature -LiteralPath $env:PROXYDUCK_UPDATE_CANDIDATE
$current=Get-AuthenticodeSignature -LiteralPath $env:PROXYDUCK_UPDATE_CURRENT
if ($candidate.Status -ne 'Valid' -or $current.Status -ne 'Valid') { exit 10 }
if ($null -eq $candidate.SignerCertificate -or $null -eq $current.SignerCertificate) { exit 11 }
if ($candidate.SignerCertificate.Thumbprint -ne $current.SignerCertificate.Thumbprint) { exit 12 }
"#;
    let status = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("PROXYDUCK_UPDATE_CANDIDATE", installer_path)
        .env("PROXYDUCK_UPDATE_CURRENT", current_exe)
        .creation_flags(CREATE_NO_WINDOW)
        .status()?;
    if !status.success() {
        anyhow::bail!(
            "installer Authenticode signature is invalid or does not match the installed ProxyDuck publisher"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_versions_are_compared_numerically() {
        assert!(is_newer_version("1.10.0", "1.9.9"));
        assert!(!is_newer_version("1.0.0", "1.0.0"));
    }

    #[test]
    fn only_the_official_repository_release_path_is_accepted() {
        assert!(is_official_release_url(
            "https://github.com/rowanjove/ProxyDuck/releases/download/v1.0.1/ProxyDuck-1.0.1-setup.exe"
        ));
        assert!(!is_official_release_url(
            "https://objects.githubusercontent.com/untrusted/installer.exe"
        ));
        assert!(!is_official_release_url(
            "https://github.com/rowanjove/ProxyDuck.evil/releases/download/v1/a.exe"
        ));
    }
}
