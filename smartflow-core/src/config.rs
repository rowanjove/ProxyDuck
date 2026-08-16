use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::model::{AppConfig, EngineMode, ProxyKind};
use anyhow::{anyhow, bail, Context, Result};

const CONFIG_FILE: &str = "config.json5";
pub const CURRENT_SCHEMA_VERSION: u32 = 3;

pub fn resolve_config_path() -> Result<PathBuf> {
    proxyduck_common::resolve_app_file(CONFIG_FILE)
}

pub fn load_or_init(path: &Path) -> Result<AppConfig> {
    if !path.exists() {
        let config = AppConfig::default();
        save(path, &config)?;
        return Ok(config);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;

    let (mut parsed, recovered) = match parse_config(&raw, path) {
        Ok(config) => (config, false),
        Err(primary_error) => {
            let backup = backup_path(path);
            let backup_raw = fs::read_to_string(&backup).with_context(|| {
                format!(
                    "{primary_error}; failed to read configuration backup: {}",
                    backup.display()
                )
            })?;
            let recovered = parse_config(&backup_raw, &backup).with_context(|| {
                format!(
                    "{primary_error}; configuration backup is also invalid: {}",
                    backup.display()
                )
            })?;
            tracing::warn!(
                config = %path.display(),
                backup = %backup.display(),
                "recovered invalid configuration from backup"
            );
            (recovered, true)
        }
    };
    let migrated = migrate_schema(&mut parsed)?;
    let normalized = normalize_legacy_capabilities(&mut parsed);
    if parsed.version != env!("CARGO_PKG_VERSION") || recovered || migrated || normalized {
        parsed.version = env!("CARGO_PKG_VERSION").to_string();
        write_config(path, &parsed, !recovered)?;
    }
    Ok(parsed)
}

fn parse_config(raw: &str, path: &Path) -> Result<AppConfig> {
    if raw.trim().is_empty() {
        return Err(anyhow!("configuration is empty: {}", path.display()));
    }
    json5::from_str(raw)
        .with_context(|| format!("failed to parse JSON5 config: {}", path.display()))
}

fn migrate_schema(config: &mut AppConfig) -> Result<bool> {
    if config.schema_version > CURRENT_SCHEMA_VERSION {
        bail!(
            "configuration schema {} is newer than supported schema {}",
            config.schema_version,
            CURRENT_SCHEMA_VERSION
        );
    }

    let mut changed = false;
    while config.schema_version < CURRENT_SCHEMA_VERSION {
        match config.schema_version {
            0 => {
                config.schema_version = 1;
                changed = true;
            }
            1 => {
                config.schema_version = 2;
                changed = true;
            }
            2 => {
                config.schema_version = 3;
                changed = true;
            }
            version => bail!("no migration path from configuration schema {version}"),
        }
    }
    Ok(changed)
}

fn normalize_legacy_capabilities(config: &mut AppConfig) -> bool {
    let mut changed = false;
    if matches!(config.engine_mode, EngineMode::Wfp | EngineMode::ApiHook) {
        tracing::warn!(
            previous = ?config.engine_mode,
            "configured engine is not implemented; falling back to WinDivert/ProxiFyre"
        );
        config.engine_mode = EngineMode::WinDivert;
        changed = true;
    }

    for proxy in &mut config.proxies {
        if proxy.enabled && !matches!(proxy.kind, ProxyKind::Socks5 | ProxyKind::Direct) {
            tracing::warn!(
                proxy = %proxy.name,
                kind = ?proxy.kind,
                "disabling proxy type unsupported by the active backend"
            );
            proxy.enabled = false;
            changed = true;
        }
    }

    for rule in &mut config.rules {
        if rule.auto_bind_children {
            rule.auto_bind_children = false;
            changed = true;
        }
        if rule.enabled && !rule.matcher.hashes.is_empty() {
            tracing::warn!(
                rule = %rule.name,
                "disabling rule because the active backend does not support hash matching"
            );
            rule.enabled = false;
            changed = true;
        }
    }
    for item in &mut config.quick_bar {
        if item.auto_bind_children {
            item.auto_bind_children = false;
            changed = true;
        }
    }

    changed
}

pub fn save(path: &Path, config: &AppConfig) -> Result<()> {
    write_config(path, config, true)
}

fn write_config(path: &Path, config: &AppConfig, backup_existing: bool) -> Result<()> {
    let body = serde_json::to_string_pretty(config).context("failed to serialize config")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create config directory before save: {}",
                parent.display()
            )
        })?;
    }

    if backup_existing && path.exists() {
        let backup = backup_path(path);
        fs::copy(path, &backup).with_context(|| {
            format!(
                "failed to update configuration backup: {}",
                backup.display()
            )
        })?;
    }
    atomic_write(path, body.as_bytes())?;

    Ok(())
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory: {}", parent.display()))?;
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.tmp"))
        .unwrap_or_else(|| "tmp".to_string());
    let mut tmp_path = path.to_path_buf();
    tmp_path.set_extension(extension);
    fs::write(&tmp_path, contents)
        .with_context(|| format!("failed to write temp file: {}", tmp_path.display()))?;
    replace_file(&tmp_path, path)
}

fn backup_path(path: &Path) -> PathBuf {
    let mut backup = path.to_path_buf();
    backup.set_extension("json5.bak");
    backup
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    use std::{iter, os::windows::ffi::OsStrExt};

    use windows::{
        core::PCWSTR,
        Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        },
    };

    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let destination_wide = destination
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();

    unsafe {
        MoveFileExW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .with_context(|| format!("failed to replace config file: {}", destination.display()))?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)
        .with_context(|| format!("failed to rename temp file to: {}", destination.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load_config() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let config = AppConfig::default();
        save(&path, &config).unwrap();

        let mut updated = config.clone();
        updated.runtime.enabled = true;
        save(&path, &updated).unwrap();

        // Assert atomic temp file is missing, meaning it was renamed
        let tmp_path = path.with_extension("json5.tmp");
        assert!(!tmp_path.exists());

        // Load it back
        let loaded = load_or_init(&path).unwrap();
        assert_eq!(loaded.version, updated.version);
        assert!(loaded.runtime.enabled);
    }

    #[test]
    fn test_load_migrates_config_version() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let config = AppConfig {
            version: "0.1.0".to_string(),
            ..AppConfig::default()
        };
        save(&path, &config).unwrap();

        let loaded = load_or_init(&path).unwrap();
        assert_eq!(loaded.version, env!("CARGO_PKG_VERSION"));
        assert!(std::fs::read_to_string(path)
            .unwrap()
            .contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn test_save_creates_missing_parent_directory() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("nested")
            .join("config.json5");

        save(&path, &AppConfig::default()).unwrap();

        assert!(path.exists());
        assert!(load_or_init(&path).is_ok());
    }

    #[test]
    fn load_normalizes_capabilities_that_were_previously_only_labels() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let mut config = AppConfig {
            engine_mode: EngineMode::Wfp,
            ..Default::default()
        };
        config.proxies[0].kind = ProxyKind::Http;
        save(&path, &config).unwrap();

        let loaded = load_or_init(&path).unwrap();
        assert_eq!(loaded.engine_mode, EngineMode::WinDivert);
        assert!(!loaded.proxies[0].enabled);
    }

    #[test]
    fn load_migrates_legacy_schema_and_rejects_future_schema() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let legacy = AppConfig {
            schema_version: 0,
            ..Default::default()
        };
        save(&path, &legacy).unwrap();
        assert_eq!(
            load_or_init(&path).unwrap().schema_version,
            CURRENT_SCHEMA_VERSION
        );

        let future = AppConfig {
            schema_version: CURRENT_SCHEMA_VERSION + 1,
            ..Default::default()
        };
        save(&path, &future).unwrap();
        assert!(load_or_init(&path).is_err());
    }

    #[test]
    fn load_recovers_corrupt_primary_from_last_known_good_backup() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let original = AppConfig::default();
        save(&path, &original).unwrap();
        let mut updated = original.clone();
        updated.runtime.log_level = "debug".to_string();
        save(&path, &updated).unwrap();
        std::fs::write(&path, "{ definitely not valid json5").unwrap();

        let recovered = load_or_init(&path).unwrap();
        assert_eq!(recovered.runtime.log_level, original.runtime.log_level);
        assert!(parse_config(&std::fs::read_to_string(&path).unwrap(), &path).is_ok());
    }
}
