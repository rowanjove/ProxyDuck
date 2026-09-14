use std::{
    backtrace::Backtrace,
    fs::{self, OpenOptions},
    io::Write,
    panic,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use uuid::Uuid;

pub mod ipc;

pub const PRODUCT_NAME: &str = "ProxyDuck";
pub const PREVIOUS_PRODUCT_NAME: &str = "ProxyDock";
pub const LEGACY_PRODUCT_NAME: &str = "SmartFlow";
pub const DEFAULT_CORE_URL: &str = "http://127.0.0.1:46666";
pub const AUTH_HEADER: &str = "X-ProxyDuck-Token";
pub const PREVIOUS_AUTH_HEADER: &str = "X-ProxyDock-Token";
pub const LEGACY_AUTH_HEADER: &str = "X-SmartFlow-Token";
pub const CORE_URL_ENV: &str = "PROXYDUCK_CORE_URL";
pub const INSTALLER_USER_SID_ENV: &str = "PROXYDUCK_INSTALLER_USER_SID";
pub const SERVICE_SECRET_SCOPE_ENV: &str = "PROXYDUCK_SERVICE_SECRET_SCOPE";
pub const PREVIOUS_CORE_URL_ENV: &str = "PROXYDOCK_CORE_URL";
pub const LEGACY_CORE_URL_ENV: &str = "SMARTFLOW_CORE_URL";
pub const PROXIFYRE_DIR_ENV: &str = "PROXYDUCK_PROXIFYRE_DIR";
pub const PREVIOUS_PROXIFYRE_DIR_ENV: &str = "PROXYDOCK_PROXIFYRE_DIR";
pub const SING_BOX_PATH_ENV: &str = "PROXYDUCK_SING_BOX_PATH";
pub const TUN_SUBNET_ENV: &str = "PROXYDUCK_TUN_SUBNET";
pub const PREVIOUS_SING_BOX_PATH_ENV: &str = "PROXYDOCK_SING_BOX_PATH";
pub const LEGACY_PROXIFYRE_DIR_ENV: &str = "SMARTFLOW_PROXIFYRE_DIR";

#[cfg(target_os = "windows")]
fn windows_system32_tool(name: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(name)
}

const TOKEN_FILE: &str = "token";
#[cfg(target_os = "windows")]
const DPAPI_PREFIX: &str = "dpapi:v1:";

/// Local secret storage for credentials that must not be written to the JSON
/// configuration. Windows uses the current user's DPAPI scope; a non-Windows
/// build keeps a clearly marked plaintext fallback for development only.
pub struct SecretStore {
    directory: PathBuf,
    machine_scope: bool,
}

impl SecretStore {
    pub fn new() -> Result<Self> {
        if std::env::var(SERVICE_SECRET_SCOPE_ENV)
            .ok()
            .is_some_and(|scope| scope.eq_ignore_ascii_case("machine"))
        {
            return Self::for_service();
        }
        let directory = resolve_app_dir()?.join("secrets");
        Self::from_directory(directory)
    }

    /// Creates a store rooted at an explicit directory. This is primarily
    /// useful for isolated integration tests and portable deployments.
    pub fn from_directory(directory: impl Into<PathBuf>) -> Result<Self> {
        Self::from_directory_with_scope(directory, false)
    }

    /// Creates the machine-scoped store used by the LocalSystem service.
    pub fn for_service() -> Result<Self> {
        let directory = if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
            PathBuf::from(program_data)
                .join(PRODUCT_NAME)
                .join("secrets")
        } else {
            resolve_app_dir()?.join("service-secrets")
        };
        Self::from_directory_with_scope(directory, true)
    }

    fn from_directory_with_scope(
        directory: impl Into<PathBuf>,
        machine_scope: bool,
    ) -> Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory).with_context(|| {
            format!("failed to create secret directory {}", directory.display())
        })?;
        if machine_scope {
            harden_service_path(&directory)?;
        } else {
            harden_windows_path(&directory)?;
        }
        Ok(Self {
            directory,
            machine_scope,
        })
    }

    pub fn proxy_password_ref(proxy_id: &str) -> String {
        format!("secret://proxy/{:016x}", stable_secret_key(proxy_id))
    }

    pub fn put(&self, secret_ref: &str, value: &str) -> Result<()> {
        let path = self.path_for(secret_ref)?;
        let encrypted = protect_secret(value.as_bytes(), self.machine_scope)?;
        fs::write(&path, encrypted)
            .with_context(|| format!("failed to write secret {secret_ref}"))?;
        let harden = if self.machine_scope {
            harden_service_path(&path)
        } else {
            harden_windows_path(&path)
        };
        if let Err(error) = harden {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(())
    }

    pub fn get(&self, secret_ref: &str) -> Result<Option<String>> {
        let path = self.path_for(secret_ref)?;
        if !path.exists() {
            return Ok(None);
        }
        let encoded = fs::read_to_string(&path)
            .with_context(|| format!("failed to read secret {secret_ref}"))?;
        Ok(Some(unprotect_secret(encoded.trim())?))
    }

    pub fn delete(&self, secret_ref: &str) -> Result<()> {
        let path = self.path_for(secret_ref)?;
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("failed to delete secret {secret_ref}"))?;
        }
        Ok(())
    }

    fn path_for(&self, secret_ref: &str) -> Result<PathBuf> {
        let key = secret_ref
            .strip_prefix("secret://")
            .filter(|value| {
                let mut parts = value.split('/');
                matches!(
                    (parts.next(), parts.next(), parts.next()),
                    (Some("proxy"), Some(hash), None)
                        if hash.len() == 16 && hash.chars().all(|ch| ch.is_ascii_hexdigit())
                )
            })
            .ok_or_else(|| anyhow::anyhow!("invalid secret reference"))?;
        Ok(self
            .directory
            .join(format!("{}.secret", key.replace('/', "_"))))
    }
}

fn stable_secret_key(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn protect_secret(data: &[u8], machine_scope: bool) -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        Ok(format!(
            "{DPAPI_PREFIX}{}",
            hex_encode(&protect_secret_token(data, machine_scope)?)
        ))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = machine_scope;
        Ok(format!("plain:v1:{}", storage_hex_encode(data)))
    }
}

fn unprotect_secret(encoded: &str) -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        let payload = encoded
            .strip_prefix(DPAPI_PREFIX)
            .context("secret is not a DPAPI v1 value")?;
        unprotect_token(payload)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let payload = encoded
            .strip_prefix("plain:v1:")
            .context("secret is not a development secret value")?;
        String::from_utf8(storage_hex_decode(payload)?).context("secret is not UTF-8")
    }
}

#[cfg(not(target_os = "windows"))]
fn storage_hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(not(target_os = "windows"))]
fn storage_hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        anyhow::bail!("secret has an invalid encoded length");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .with_context(|| "secret is not valid hex")
        })
        .collect()
}

/// Installs a process-wide panic hook that appends a local crash record before
/// delegating to Rust's normal panic reporter.
pub fn install_panic_hook(component: &'static str) -> Result<()> {
    let crash_path = resolve_app_dir()?.join("crash.log");
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("non-string panic payload");
        let location = info
            .location()
            .map(|location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            })
            .unwrap_or_else(|| "unknown".to_string());
        let backtrace = Backtrace::force_capture();
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&crash_path)
        {
            let _ = writeln!(
                file,
                "unix_time={timestamp} component={component} version={} location={location}\npanic={payload}\n{backtrace}\n---",
                env!("CARGO_PKG_VERSION")
            );
        }
        previous(info);
    }));
    Ok(())
}

pub fn resolve_app_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("io", PRODUCT_NAME, PRODUCT_NAME)
        .context("unable to resolve ProxyDuck data directory")?;
    let config_dir = dirs.config_dir();
    fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create data directory {}", config_dir.display()))?;
    harden_windows_path(config_dir)?;
    Ok(config_dir.to_path_buf())
}

pub fn resolve_app_file(file_name: &str) -> Result<PathBuf> {
    let destination = resolve_app_dir()?.join(file_name);
    if destination.exists() {
        harden_windows_path(&destination)?;
        return Ok(destination);
    }

    if let Some((source_product, source)) = legacy_file(file_name) {
        fs::copy(&source, &destination).with_context(|| {
            format!(
                "failed to migrate {} data from {} to {}",
                source_product,
                source.display(),
                destination.display()
            )
        })?;
    }

    Ok(destination)
}

pub fn load_or_create_token() -> Result<String> {
    let path = resolve_app_file(TOKEN_FILE)?;
    if path.exists() {
        let stored = fs::read_to_string(&path)
            .with_context(|| format!("failed to read auth token: {}", path.display()))?;
        #[cfg(target_os = "windows")]
        let token = if let Some(encoded) = stored.trim().strip_prefix(DPAPI_PREFIX) {
            unprotect_token(encoded).context("failed to decrypt auth token with Windows DPAPI")?
        } else {
            let plaintext = stored.trim().to_string();
            write_protected_token(&path, &plaintext)?;
            plaintext
        };
        #[cfg(not(target_os = "windows"))]
        let token = stored;
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    #[cfg(target_os = "windows")]
    write_protected_token(&path, &token)?;
    #[cfg(not(target_os = "windows"))]
    fs::write(&path, &token)
        .with_context(|| format!("failed to write auth token: {}", path.display()))?;
    Ok(token)
}

#[cfg(target_os = "windows")]
fn write_protected_token(path: &std::path::Path, token: &str) -> Result<()> {
    let encrypted = protect_token(token.as_bytes())?;
    fs::write(path, format!("{DPAPI_PREFIX}{}", hex_encode(&encrypted)))
        .with_context(|| format!("failed to write protected auth token: {}", path.display()))?;
    harden_windows_path(path)
}

#[cfg(target_os = "windows")]
fn protect_token(data: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).context("auth token is too large")?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )?;
        let encrypted = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
        Ok(encrypted)
    }
}

#[cfg(target_os = "windows")]
fn protect_secret_token(data: &[u8], machine_scope: bool) -> Result<Vec<u8>> {
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CRYPT_INTEGER_BLOB,
        },
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).context("secret is too large")?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let flags = CRYPTPROTECT_UI_FORBIDDEN
        | if machine_scope {
            CRYPTPROTECT_LOCAL_MACHINE
        } else {
            0
        };
    unsafe {
        CryptProtectData(&input, None, None, None, None, flags, &mut output)?;
        let encrypted = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
        Ok(encrypted)
    }
}

#[cfg(target_os = "windows")]
fn unprotect_token(encoded: &str) -> Result<String> {
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let encrypted = hex_decode(encoded)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(encrypted.len()).context("protected auth token is too large")?,
        pbData: encrypted.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )?;
        let plaintext = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
        String::from_utf8(plaintext).context("decrypted auth token is not UTF-8")
    }
}

#[cfg(target_os = "windows")]
fn harden_windows_path(path: &Path) -> Result<()> {
    let identity = Command::new(windows_system32_tool("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .context("failed to resolve the current Windows user SID")?;
    if !identity.status.success() {
        anyhow::bail!("whoami failed while resolving the current Windows user SID");
    }
    let identity_text = String::from_utf8_lossy(&identity.stdout);
    let sid = identity_text
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
        .find(|value| value.starts_with("S-1-"))
        .ok_or_else(|| anyhow::anyhow!("whoami did not return a Windows user SID"))?;
    let current_identity = Command::new(windows_system32_tool("whoami.exe"))
        .output()
        .context("failed to resolve the current Windows account")?;
    let account = String::from_utf8_lossy(&current_identity.stdout)
        .trim()
        .to_string();
    for principal in [sid.to_string(), account] {
        if principal.is_empty() {
            continue;
        }
        let grant = format!("{principal}:F");
        let status = Command::new(windows_system32_tool("icacls.exe"))
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(grant)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("failed to harden ACL for {}", path.display()))?;
        if status.success() {
            return Ok(());
        }
    }
    anyhow::bail!("icacls failed while hardening {}", path.display())
}

#[cfg(target_os = "windows")]
pub fn harden_service_path(path: &Path) -> Result<()> {
    let status = Command::new(windows_system32_tool("icacls.exe"))
        .arg(path)
        .args(["/inheritance:r", "/grant:r", "SYSTEM:F", "Administrators:F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to harden service secret ACL for {}", path.display()))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "icacls failed while hardening service secret {}",
            path.display()
        )
    }
}

#[cfg(not(target_os = "windows"))]
fn harden_windows_path(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn harden_service_path(_path: &Path) -> Result<()> {
    Ok(())
}

/// Restricts a runtime or secret file to the current Windows user. On
/// non-Windows development builds this is intentionally a no-op.
pub fn harden_current_user_path(path: &Path) -> Result<()> {
    harden_windows_path(path)
}

/// Hardens a file using the ACL scope of the active host. The LocalSystem
/// service sets `SERVICE_SECRET_SCOPE_ENV=machine`; its atomic config writes
/// must retain the shared SYSTEM/Administrators ACL instead of replacing the
/// file with a current-user-only descriptor.
pub fn harden_active_path(path: &Path) -> Result<()> {
    if std::env::var(SERVICE_SECRET_SCOPE_ENV)
        .ok()
        .is_some_and(|scope| scope.eq_ignore_ascii_case("machine"))
    {
        harden_service_path(path)
    } else {
        harden_current_user_path(path)
    }
}

#[cfg(target_os = "windows")]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(target_os = "windows")]
fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        anyhow::bail!("protected auth token has an invalid length");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .with_context(|| "protected auth token is not valid hex")
        })
        .collect()
}

pub fn core_url_from_env() -> String {
    let candidate = std::env::var(CORE_URL_ENV)
        .or_else(|_| std::env::var(PREVIOUS_CORE_URL_ENV))
        .or_else(|_| std::env::var(LEGACY_CORE_URL_ENV))
        .unwrap_or_default();
    if is_local_core_url(&candidate) {
        candidate.trim_end_matches('/').to_string()
    } else {
        DEFAULT_CORE_URL.to_string()
    }
}

fn is_local_core_url(value: &str) -> bool {
    let Some((scheme, remainder)) = value.trim().split_once("://") else {
        return false;
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return false;
    }

    if remainder
        .chars()
        .any(|character| matches!(character, '/' | '?' | '#'))
    {
        return false;
    }
    let authority = remainder;
    if authority.is_empty() || authority.contains('@') {
        return false;
    }

    if let Some((host, suffix)) = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']'))
    {
        if !matches!(host, "::1" | "0:0:0:0:0:0:0:1") {
            return false;
        }
        return suffix.is_empty() || suffix.starts_with(':');
    }

    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or_default();
    let _port = parts.next();
    if parts.next().is_some() {
        return false;
    }
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1"
}

pub fn proxifyre_dir_from_env() -> Option<PathBuf> {
    std::env::var(PROXIFYRE_DIR_ENV)
        .or_else(|_| std::env::var(PREVIOUS_PROXIFYRE_DIR_ENV))
        .or_else(|_| std::env::var(LEGACY_PROXIFYRE_DIR_ENV))
        .ok()
        .map(PathBuf::from)
}

pub fn sing_box_path_from_env() -> Option<PathBuf> {
    std::env::var(SING_BOX_PATH_ENV)
        .or_else(|_| std::env::var(PREVIOUS_SING_BOX_PATH_ENV))
        .ok()
        .map(PathBuf::from)
}

pub fn tun_subnet_from_env() -> Option<String> {
    std::env::var(TUN_SUBNET_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn legacy_file(file_name: &str) -> Option<(&'static str, PathBuf)> {
    let candidates = [
        (
            PREVIOUS_PRODUCT_NAME,
            ProjectDirs::from("io", PREVIOUS_PRODUCT_NAME, PREVIOUS_PRODUCT_NAME),
        ),
        (
            LEGACY_PRODUCT_NAME,
            ProjectDirs::from("com", LEGACY_PRODUCT_NAME, LEGACY_PRODUCT_NAME),
        ),
    ];
    candidates.into_iter().find_map(|(product, directories)| {
        let path = directories?.config_dir().join(file_name);
        path.exists().then_some((product, path))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_format_is_stable() {
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn product_constants_use_new_brand() {
        assert_eq!(PRODUCT_NAME, "ProxyDuck");
        assert_eq!(AUTH_HEADER, "X-ProxyDuck-Token");
        assert_eq!(CORE_URL_ENV, "PROXYDUCK_CORE_URL");
        assert_eq!(PREVIOUS_PRODUCT_NAME, "ProxyDock");
        assert_eq!(PREVIOUS_AUTH_HEADER, "X-ProxyDock-Token");
    }

    #[test]
    fn core_url_allows_only_loopback_hosts() {
        for value in [
            "http://127.0.0.1:46666",
            "https://localhost",
            "http://[::1]:46666",
        ] {
            assert!(is_local_core_url(value), "expected local URL: {value}");
        }
        for value in [
            "http://192.168.1.10:46666",
            "http://attacker.example/collect",
            "http://user:pass@127.0.0.1:46666",
            "file:///tmp/core",
        ] {
            assert!(!is_local_core_url(value), "expected non-local URL: {value}");
        }
    }

    #[test]
    fn secret_store_round_trip_and_delete() {
        let directory = std::env::temp_dir().join(format!("proxyduck-secrets-{}", Uuid::new_v4()));
        let store = SecretStore::from_directory(&directory).unwrap();
        let secret_ref = SecretStore::proxy_password_ref("proxy-1");
        store.put(&secret_ref, "pässword").unwrap();
        assert_eq!(store.get(&secret_ref).unwrap().as_deref(), Some("pässword"));
        store.delete(&secret_ref).unwrap();
        assert_eq!(store.get(&secret_ref).unwrap(), None);
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dpapi_round_trip_uses_current_user_scope() {
        let token = "0123456789abcdef";
        let encrypted = protect_token(token.as_bytes()).unwrap();
        assert_ne!(encrypted, token.as_bytes());
        assert_eq!(unprotect_token(&hex_encode(&encrypted)).unwrap(), token);
    }
}
