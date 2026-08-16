use std::{
    backtrace::Backtrace,
    fs::{self, OpenOptions},
    io::Write,
    panic,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use uuid::Uuid;

pub const PRODUCT_NAME: &str = "ProxyDuck";
pub const PREVIOUS_PRODUCT_NAME: &str = "ProxyDock";
pub const LEGACY_PRODUCT_NAME: &str = "SmartFlow";
pub const DEFAULT_CORE_URL: &str = "http://127.0.0.1:46666";
pub const AUTH_HEADER: &str = "X-ProxyDuck-Token";
pub const PREVIOUS_AUTH_HEADER: &str = "X-ProxyDock-Token";
pub const LEGACY_AUTH_HEADER: &str = "X-SmartFlow-Token";
pub const CORE_URL_ENV: &str = "PROXYDUCK_CORE_URL";
pub const PREVIOUS_CORE_URL_ENV: &str = "PROXYDOCK_CORE_URL";
pub const LEGACY_CORE_URL_ENV: &str = "SMARTFLOW_CORE_URL";
pub const PROXIFYRE_DIR_ENV: &str = "PROXYDUCK_PROXIFYRE_DIR";
pub const PREVIOUS_PROXIFYRE_DIR_ENV: &str = "PROXYDOCK_PROXIFYRE_DIR";
pub const SING_BOX_PATH_ENV: &str = "PROXYDUCK_SING_BOX_PATH";
pub const PREVIOUS_SING_BOX_PATH_ENV: &str = "PROXYDOCK_SING_BOX_PATH";
pub const LEGACY_PROXIFYRE_DIR_ENV: &str = "SMARTFLOW_PROXIFYRE_DIR";

const TOKEN_FILE: &str = "token";
#[cfg(target_os = "windows")]
const DPAPI_PREFIX: &str = "dpapi:v1:";

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
    Ok(config_dir.to_path_buf())
}

pub fn resolve_app_file(file_name: &str) -> Result<PathBuf> {
    let destination = resolve_app_dir()?.join(file_name);
    if destination.exists() {
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
        .with_context(|| format!("failed to write protected auth token: {}", path.display()))
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
    std::env::var(CORE_URL_ENV)
        .or_else(|_| std::env::var(PREVIOUS_CORE_URL_ENV))
        .or_else(|_| std::env::var(LEGACY_CORE_URL_ENV))
        .unwrap_or_else(|_| DEFAULT_CORE_URL.to_string())
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

    #[cfg(target_os = "windows")]
    #[test]
    fn dpapi_round_trip_uses_current_user_scope() {
        let token = "0123456789abcdef";
        let encrypted = protect_token(token.as_bytes()).unwrap();
        assert_ne!(encrypted, token.as_bytes());
        assert_eq!(unprotect_token(&hex_encode(&encrypted)).unwrap(), token);
    }
}
