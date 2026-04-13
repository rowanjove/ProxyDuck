use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;

use crate::model::AppConfig;

const APP_VENDOR: &str = "SmartFlow";
const APP_NAME: &str = "SmartFlow";
const CONFIG_FILE: &str = "config.json5";

pub fn resolve_app_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("com", APP_VENDOR, APP_NAME)
        .context("unable to resolve app data directory")?;
    let config_dir = dirs.config_dir();
    fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create config dir {}", config_dir.display()))?;
    Ok(config_dir.to_path_buf())
}

pub fn resolve_config_path() -> Result<PathBuf> {
    Ok(resolve_app_dir()?.join(CONFIG_FILE))
}

pub fn load_or_init(path: &PathBuf) -> Result<AppConfig> {
    if !path.exists() {
        let config = AppConfig::default();
        save(path, &config)?;
        return Ok(config);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;

    if raw.trim().is_empty() {
        let config = AppConfig::default();
        save(path, &config)?;
        return Ok(config);
    }

    let parsed: AppConfig = json5::from_str(&raw)
        .with_context(|| format!("failed to parse JSON5 config: {}", path.display()))?;
    Ok(parsed)
}

pub fn save(path: &PathBuf, config: &AppConfig) -> Result<()> {
    let body = serde_json::to_string_pretty(config).context("failed to serialize config")?;

    let mut tmp_path = path.clone();
    tmp_path.set_extension("json5.tmp");

    fs::write(&tmp_path, body)
        .with_context(|| format!("failed to write config temp file: {}", tmp_path.display()))?;
    replace_file(&tmp_path, path)?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn replace_file(source: &PathBuf, destination: &PathBuf) -> Result<()> {
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
fn replace_file(source: &PathBuf, destination: &PathBuf) -> Result<()> {
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
}
