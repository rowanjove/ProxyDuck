use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::model::{AppConfig, DnsMode, EngineMode, ProxyKind, ProxyProfile, RouteAction};
use anyhow::{anyhow, bail, Context, Result};

const CONFIG_FILE: &str = "config.json5";
pub const CURRENT_SCHEMA_VERSION: u32 = 6;

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
    let secrets = hydrate_proxy_secrets(&mut parsed)?;
    let normalized = normalize_legacy_capabilities(&mut parsed);
    if parsed.version != env!("CARGO_PKG_VERSION") || recovered || migrated || normalized || secrets
    {
        parsed.version = env!("CARGO_PKG_VERSION").to_string();
        // A legacy file may still contain a plaintext password.  Never copy
        // that raw payload into the last-known-good backup before the
        // migration has moved the credential into SecretStore.
        write_config(path, &parsed, !recovered && !secrets)?;
        if secrets {
            write_sanitized_backup(path, &parsed)?;
        }
    }
    Ok(parsed)
}

/// Migrates an already decoded config payload, such as an API import, using
/// the same compatibility rules as file loading. The caller still owns the
/// transaction and validation step.
pub fn migrate_import(config: &mut AppConfig) -> Result<bool> {
    let mut changed = prepare_import_preview(config)?;
    let secrets = hydrate_proxy_secrets(config)?;
    changed |= secrets;
    Ok(changed)
}

/// Applies only the deterministic, in-memory part of import migration.
///
/// This is deliberately separate from [`migrate_import`]: a preview must not
/// hydrate or persist proxy credentials in the platform secret store merely
/// because a user opened the import confirmation dialog.
pub fn prepare_import_preview(config: &mut AppConfig) -> Result<bool> {
    let migrated = migrate_schema(config)?;
    let normalized = normalize_legacy_capabilities(config);
    let version_changed = config.version != env!("CARGO_PKG_VERSION");
    if migrated || normalized || version_changed {
        config.version = env!("CARGO_PKG_VERSION").to_string();
    }
    Ok(migrated || normalized || version_changed)
}

/// Moves an in-memory proxy password into the platform secret store and keeps
/// only a stable reference in the serializable configuration. The password is
/// intentionally retained in memory for the active data-plane session.
pub fn persist_proxy_secret(proxy: &mut ProxyProfile) -> Result<bool> {
    let Some(password) = proxy.password.as_deref() else {
        return Ok(false);
    };
    let secret_ref = proxy
        .password_ref
        .clone()
        .unwrap_or_else(|| proxyduck_common::SecretStore::proxy_password_ref(&proxy.id));
    proxyduck_common::SecretStore::new()?.put(&secret_ref, password)?;
    let changed = proxy.password_ref.as_deref() != Some(secret_ref.as_str());
    proxy.password_ref = Some(secret_ref);
    Ok(changed)
}

/// Hydrates password values for active use and migrates any legacy plaintext
/// values found in an imported/old config. Missing secret files remain absent
/// in memory so the proxy health layer can report the actual failure.
pub fn hydrate_proxy_secrets(config: &mut AppConfig) -> Result<bool> {
    let store = proxyduck_common::SecretStore::new()?;
    let mut changed = false;
    for proxy in &mut config.proxies {
        if proxy.password.is_some() {
            persist_proxy_secret_with_store(proxy, &store)?;
            // Even when a legacy payload already supplied a reference, the
            // plaintext password must be rewritten out of the JSON file.
            changed = true;
            continue;
        }
        if let Some(secret_ref) = proxy.password_ref.as_deref() {
            match store.get(secret_ref)? {
                Some(password) => proxy.password = Some(password),
                None => tracing::warn!(proxy = %proxy.id, "proxy password secret is unavailable"),
            }
        }
    }
    Ok(changed)
}

fn persist_proxy_secret_with_store(
    proxy: &mut ProxyProfile,
    store: &proxyduck_common::SecretStore,
) -> Result<()> {
    let Some(password) = proxy.password.as_deref() else {
        return Ok(());
    };
    let secret_ref = proxy
        .password_ref
        .clone()
        .unwrap_or_else(|| proxyduck_common::SecretStore::proxy_password_ref(&proxy.id));
    store.put(&secret_ref, password)?;
    proxy.password_ref = Some(secret_ref);
    Ok(())
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
            3 => {
                migrate_rule_policy_fields(config);
                config.schema_version = 4;
                changed = true;
            }
            4 => {
                // Profiles are additive snapshots.  Older configurations do
                // not need synthetic entries; serde defaults the new fields
                // to an empty profile list and no active profile.
                config.schema_version = 5;
                changed = true;
            }
            5 => {
                migrate_to_v6_debranding(config);
                config.schema_version = 6;
                changed = true;
            }
            version => bail!("no migration path from configuration schema {version}"),
        }
    }
    Ok(changed)
}

fn migrate_to_v6_debranding(config: &mut AppConfig) {
    let old_id = "clash-socks";
    let new_id = "local-socks";

    let has_old = config.proxies.iter().any(|p| p.id == old_id);
    let has_new = config.proxies.iter().any(|p| p.id == new_id);

    if has_old && !has_new {
        for p in &mut config.proxies {
            if p.id == old_id {
                p.id = new_id.to_string();
                if p.name == "Clash Verge" || p.name == "Clash SOCKS5" || p.name.contains("Clash") {
                    p.name = "本地代理 (SOCKS5)".to_string();
                }
            }
        }
    }

    let has_new_now = config.proxies.iter().any(|p| p.id == new_id);
    let has_old_now = config.proxies.iter().any(|p| p.id == old_id);
    if has_new_now && !has_old_now {
        for rule in &mut config.rules {
            if rule.proxy_profile == old_id {
                rule.proxy_profile = new_id.to_string();
            }
            if let RouteAction::Proxy { ref mut proxy_id } = rule.action {
                if proxy_id == old_id {
                    *proxy_id = new_id.to_string();
                }
            }
        }
        for profile in &mut config.profiles {
            for rule in &mut profile.rules {
                if rule.proxy_profile == old_id {
                    rule.proxy_profile = new_id.to_string();
                }
                if let RouteAction::Proxy { ref mut proxy_id } = rule.action {
                    if proxy_id == old_id {
                        *proxy_id = new_id.to_string();
                    }
                }
            }
        }
    }
}

/// Materialize the policy fields introduced in schema 4 while retaining the
/// legacy fields for one compatibility line. The old `dns` protocol flag was
/// never an independent DNS data plane; the closest truthful migration is a
/// plaintext-DNS block marker when the old firewall flag was enabled.
fn migrate_rule_policy_fields(config: &mut AppConfig) {
    let proxy_kinds = config
        .proxies
        .iter()
        .map(|proxy| (proxy.id.as_str(), proxy.kind))
        .collect::<std::collections::HashMap<_, _>>();

    for rule in &mut config.rules {
        if matches!(rule.action, RouteAction::Proxy { ref proxy_id } if proxy_id.is_empty()) {
            rule.action = match proxy_kinds.get(rule.proxy_profile.as_str()) {
                Some(ProxyKind::Direct) => RouteAction::Direct,
                _ => RouteAction::Proxy {
                    proxy_id: rule.proxy_profile.clone(),
                },
            };
        }
        if matches!(rule.dns.mode, DnsMode::Inherit)
            && rule.force_dns
            && rule.protocols.contains(&crate::model::Protocol::Dns)
        {
            rule.dns.mode = DnsMode::BlockPlaintext;
        }
    }
}

fn normalize_legacy_capabilities(config: &mut AppConfig) -> bool {
    let mut changed = false;
    if matches!(config.engine_mode, EngineMode::Wfp | EngineMode::ApiHook) {
        tracing::warn!(
            previous = ?config.engine_mode,
            "configured engine is not implemented; falling back to ProxiFyre"
        );
        config.engine_mode = EngineMode::ProxiFyre;
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
        proxyduck_common::harden_active_path(&backup).with_context(|| {
            format!(
                "failed to harden configuration backup: {}",
                backup.display()
            )
        })?;
    }
    atomic_write(path, body.as_bytes())?;

    Ok(())
}

fn write_sanitized_backup(path: &Path, config: &AppConfig) -> Result<()> {
    let backup = backup_path(path);
    let body = serde_json::to_string_pretty(config).context("failed to serialize config backup")?;
    atomic_write(&backup, body.as_bytes())?;
    proxyduck_common::harden_active_path(&backup).with_context(|| {
        format!(
            "failed to harden sanitized configuration backup: {}",
            backup.display()
        )
    })?;
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
    if let Err(error) = fs::write(&tmp_path, contents)
        .with_context(|| format!("failed to write temp file: {}", tmp_path.display()))
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    if let Err(error) = proxyduck_common::harden_active_path(&tmp_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error).with_context(|| {
            format!(
                "failed to harden temp file before replace: {}",
                tmp_path.display()
            )
        });
    }
    if let Err(error) = replace_file(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(())
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
        assert_eq!(loaded.engine_mode, EngineMode::ProxiFyre);
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
    fn schema_four_migration_materializes_action_and_truthful_dns_policy() {
        let mut config = AppConfig {
            schema_version: 3,
            ..Default::default()
        };
        let mut rule = crate::model::Rule::new(
            "legacy browser".to_string(),
            crate::model::MatchCriteria {
                app_names: vec!["browser.exe".to_string()],
                ..Default::default()
            },
            "clash-socks".to_string(),
        );
        rule.action = RouteAction::default();
        rule.dns.mode = DnsMode::Inherit;
        rule.force_dns = true;
        config.rules.push(rule);

        assert!(migrate_schema(&mut config).unwrap());
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(
            config.rules[0].action,
            RouteAction::Proxy {
                proxy_id: "local-socks".to_string()
            }
        );
        assert_eq!(config.rules[0].dns.mode, DnsMode::BlockPlaintext);
    }

    #[test]
    fn schema_five_to_six_migration_debrands_clash() {
        let mut config = AppConfig {
            schema_version: 5,
            proxies: vec![ProxyProfile {
                id: "clash-socks".to_string(),
                name: "Clash Verge".to_string(),
                kind: ProxyKind::Socks5,
                endpoint: "127.0.0.1:7897".to_string(),
                username: None,
                password_ref: None,
                password: None,
                enabled: true,
            }],
            rules: vec![crate::model::Rule::new(
                "browser".to_string(),
                crate::model::MatchCriteria {
                    app_names: vec!["browser.exe".to_string()],
                    ..Default::default()
                },
                "clash-socks".to_string(),
            )],
            ..Default::default()
        };

        assert!(migrate_schema(&mut config).unwrap());
        assert_eq!(config.schema_version, 6);
        assert_eq!(config.proxies[0].id, "local-socks");
        assert_eq!(config.proxies[0].name, "本地代理 (SOCKS5)");
        assert_eq!(config.rules[0].proxy_profile, "local-socks");
        assert_eq!(
            config.rules[0].action,
            RouteAction::Proxy {
                proxy_id: "local-socks".to_string()
            }
        );
    }

    #[test]
    fn import_normalizes_stale_product_version_without_other_migrations() {
        let mut config = AppConfig {
            version: "0.1.0".to_string(),
            schema_version: CURRENT_SCHEMA_VERSION,
            ..Default::default()
        };

        assert!(migrate_import(&mut config).unwrap());
        assert_eq!(config.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn load_rewrites_legacy_plaintext_password_even_with_existing_reference() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let proxy_id = format!("legacy-{}", uuid::Uuid::new_v4());
        let mut config = AppConfig {
            proxies: vec![ProxyProfile {
                id: proxy_id.clone(),
                name: "Legacy".into(),
                kind: ProxyKind::Socks5,
                endpoint: "127.0.0.1:1080".into(),
                username: None,
                password_ref: Some(proxyduck_common::SecretStore::proxy_password_ref(&proxy_id)),
                password: None,
                enabled: true,
            }],
            ..Default::default()
        };
        let mut raw = serde_json::to_value(&config).unwrap();
        raw["proxies"][0]["password"] = serde_json::json!("legacy-plaintext");
        std::fs::write(&path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();

        config = load_or_init(&path).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        let backup = std::fs::read_to_string(backup_path(&path)).unwrap();
        assert!(!saved.contains("legacy-plaintext"));
        assert!(!backup.contains("legacy-plaintext"));
        assert_eq!(
            config.proxies[0].password.as_deref(),
            Some("legacy-plaintext")
        );
        proxyduck_common::SecretStore::new()
            .unwrap()
            .delete(config.proxies[0].password_ref.as_deref().unwrap())
            .unwrap();
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
