//! Import proxy endpoints from common local client JSON formats.
//!
//! The importer is intentionally limited to endpoint metadata.  It never
//! executes a remote subscription, follows a URL, or guesses unsupported
//! protocols into a broader route.  Passwords stay in memory until the user
//! confirms the merge and the normal config transaction persists them through
//! SecretStore.

use std::fmt::Write as _;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::model::{AppConfig, EngineMode, ProxyKind, ProxyProfile};

#[derive(Debug, Clone)]
pub struct ImportedProxy {
    pub profile: ProxyProfile,
    pub format: &'static str,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ImportBatch {
    pub format: &'static str,
    pub proxies: Vec<ImportedProxy>,
    pub skipped: Vec<String>,
}

pub fn parse(source: &Value, engine: EngineMode) -> Result<ImportBatch> {
    if let Some(items) = source.get("proxies").and_then(Value::as_array) {
        return parse_clash(items, engine);
    }
    if let Some(items) = source.get("outbounds").and_then(Value::as_array) {
        return parse_sing_box(items, engine);
    }
    bail!("unsupported proxy import format: expected Clash 'proxies' or sing-box 'outbounds'")
}

pub fn merge_config(current: &AppConfig, imported: &[ImportedProxy]) -> AppConfig {
    let mut next = current.clone();
    for item in imported {
        let incoming = &item.profile;
        if let Some(existing) = next
            .proxies
            .iter_mut()
            .find(|proxy| proxy.id == incoming.id)
        {
            let previous_password = existing.password.clone();
            let previous_ref = existing.password_ref.clone();
            *existing = incoming.clone();
            if existing.password.is_none() {
                existing.password = previous_password;
                existing.password_ref = previous_ref;
            }
        } else {
            next.proxies.push(incoming.clone());
        }
    }
    next
}

fn parse_clash(items: &[Value], engine: EngineMode) -> Result<ImportBatch> {
    let mut proxies = Vec::new();
    let mut skipped = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match parse_clash_proxy(item, engine) {
            Ok(proxy) => proxies.push(proxy),
            Err(error) => skipped.push(format!("proxies[{index}]: {error}")),
        }
    }
    if proxies.is_empty() && skipped.is_empty() {
        bail!("Clash proxy list is empty")
    }
    Ok(ImportBatch {
        format: "clash",
        proxies,
        skipped,
    })
}

fn parse_sing_box(items: &[Value], engine: EngineMode) -> Result<ImportBatch> {
    let mut proxies = Vec::new();
    let mut skipped = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match parse_sing_box_proxy(item, engine) {
            Ok(proxy) => proxies.push(proxy),
            Err(error) => skipped.push(format!("outbounds[{index}]: {error}")),
        }
    }
    if proxies.is_empty() && skipped.is_empty() {
        bail!("sing-box outbound list is empty")
    }
    Ok(ImportBatch {
        format: "sing-box",
        proxies,
        skipped,
    })
}

fn parse_clash_proxy(value: &Value, engine: EngineMode) -> Result<ImportedProxy> {
    let name = required_string(value, "name")?;
    let kind = clash_kind(value.get("type").and_then(Value::as_str))?;
    let server = required_string(value, "server")?;
    let port = required_port(value.get("port"))?;
    let endpoint = format_endpoint(&server, port);
    let username = optional_string(value, "username");
    let password = optional_string(value, "password");
    Ok(build_imported_proxy(
        name, kind, endpoint, username, password, engine, "clash",
    ))
}

fn parse_sing_box_proxy(value: &Value, engine: EngineMode) -> Result<ImportedProxy> {
    let outbound_type = required_string(value, "type")?;
    let kind = match outbound_type.to_ascii_lowercase().as_str() {
        "socks" => ProxyKind::Socks5,
        "http" => ProxyKind::Http,
        unsupported => bail!("unsupported outbound type '{unsupported}'"),
    };
    let name = value
        .get("tag")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(outbound_type.as_str())
        .trim()
        .to_string();
    let server = required_string(value, "server")?;
    let port = required_port(value.get("server_port"))?;
    let endpoint = format_endpoint(&server, port);
    let username = optional_string(value, "username");
    let password = optional_string(value, "password");
    Ok(build_imported_proxy(
        name, kind, endpoint, username, password, engine, "sing-box",
    ))
}

fn build_imported_proxy(
    name: String,
    kind: ProxyKind,
    endpoint: String,
    username: Option<String>,
    password: Option<String>,
    engine: EngineMode,
    format: &'static str,
) -> ImportedProxy {
    let id = stable_id(&name, kind, &endpoint);
    let supported = crate::engine::capability_for(engine)
        .supported_proxy_kinds
        .contains(&kind);
    let mut warnings = Vec::new();
    if !supported {
        warnings.push(format!(
            "proxy type '{kind:?}' is not supported by engine '{engine:?}'; imported disabled"
        ));
    }
    ImportedProxy {
        profile: ProxyProfile {
            id,
            name,
            kind,
            endpoint,
            username,
            password,
            password_ref: None,
            enabled: supported,
        },
        format,
        warnings,
    }
}

fn clash_kind(value: Option<&str>) -> Result<ProxyKind> {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "socks5" | "socks5h" | "socks" => Ok(ProxyKind::Socks5),
        "http" | "https" => Ok(ProxyKind::Http),
        unsupported => bail!("unsupported Clash proxy type '{unsupported}'"),
    }
}

fn required_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .with_context(|| format!("missing non-empty '{key}'"))
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required_port(value: Option<&Value>) -> Result<u16> {
    let port = value
        .and_then(|value| {
            value.as_u64().or_else(|| {
                value
                    .as_str()
                    .and_then(|text| text.trim().parse::<u64>().ok())
            })
        })
        .with_context(|| "missing numeric proxy port".to_string())?;
    u16::try_from(port)
        .ok()
        .filter(|port| *port > 0)
        .with_context(|| format!("proxy port {port} is outside 1..=65535"))
}

fn format_endpoint(server: &str, port: u16) -> String {
    if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    }
}

fn stable_id(name: &str, kind: ProxyKind, endpoint: &str) -> String {
    let mut input = String::new();
    let _ = write!(
        input,
        "{}|{:?}|{}",
        name.trim().to_ascii_lowercase(),
        kind,
        endpoint
    );
    let mut hash = 2_166_136_261_u32;
    for byte in input.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    format!("imported-{hash:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clash_and_disables_unsupported_http_for_proxifyre() {
        let value = serde_json::json!({
            "proxies": [
                {"name": "Office SOCKS", "type": "socks5", "server": "127.0.0.1", "port": 1080, "password": "secret"},
                {"name": "Office HTTP", "type": "http", "server": "proxy.example", "port": 8080}
            ]
        });
        let batch = parse(&value, EngineMode::ProxiFyre).unwrap();
        assert_eq!(batch.format, "clash");
        assert_eq!(batch.proxies.len(), 2);
        assert!(batch.proxies[0].profile.enabled);
        assert_eq!(batch.proxies[0].profile.password.as_deref(), Some("secret"));
        assert!(!batch.proxies[1].profile.enabled);
        assert_eq!(batch.proxies[1].warnings.len(), 1);
    }

    #[test]
    fn parses_sing_box_ipv6_and_preserves_existing_secret_on_merge() {
        let value = serde_json::json!({
            "outbounds": [{"type": "socks", "tag": "Lab", "server": "::1", "server_port": 1080}]
        });
        let batch = parse(&value, EngineMode::SingBox).unwrap();
        assert_eq!(batch.proxies[0].profile.endpoint, "[::1]:1080");

        let mut current = AppConfig::default();
        let imported = batch.proxies[0].clone();
        current.proxies.push(ProxyProfile {
            password: Some("old-secret".into()),
            password_ref: Some("proxy-password-existing".into()),
            ..imported.profile.clone()
        });
        let merged = merge_config(&current, &[imported]);
        let proxy = merged
            .proxies
            .iter()
            .find(|proxy| proxy.id == batch.proxies[0].profile.id)
            .unwrap();
        assert_eq!(proxy.password.as_deref(), Some("old-secret"));
        assert_eq!(
            proxy.password_ref.as_deref(),
            Some("proxy-password-existing")
        );
    }

    #[test]
    fn rejects_unknown_root_and_invalid_port() {
        assert!(parse(&serde_json::json!({"servers": []}), EngineMode::ProxiFyre).is_err());
        let value = serde_json::json!({
            "proxies": [{"name": "bad", "type": "socks5", "server": "localhost", "port": 0}]
        });
        let batch = parse(&value, EngineMode::ProxiFyre).unwrap();
        assert!(batch.proxies.is_empty());
        assert_eq!(batch.skipped.len(), 1);
    }
}
