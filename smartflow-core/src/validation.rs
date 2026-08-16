use std::collections::HashSet;

use anyhow::{bail, Result};

use crate::{
    engine::capability_for,
    model::{AppConfig, LeakProtectionMode, ProxyKind},
};

pub fn validate_config(config: &AppConfig) -> Result<()> {
    if config.schema_version != crate::config::CURRENT_SCHEMA_VERSION {
        bail!(
            "configuration schema {} is not supported; expected {}",
            config.schema_version,
            crate::config::CURRENT_SCHEMA_VERSION
        );
    }
    let capability = capability_for(config.engine_mode);
    if !capability.available {
        bail!(
            "engine '{}' is unavailable: {}",
            capability.display_name,
            capability
                .unavailable_reason
                .as_deref()
                .unwrap_or("not implemented")
        );
    }
    if config.runtime.leak_protection_mode == LeakProtectionMode::Strict
        && !capability.supports_firewall_hardening
    {
        bail!(
            "strict leak protection is unsupported by engine '{}'",
            capability.display_name
        );
    }

    let mut proxy_ids = HashSet::new();
    for proxy in &config.proxies {
        if proxy.id.trim().is_empty() {
            bail!("proxy id cannot be empty");
        }
        if !proxy_ids.insert(proxy.id.as_str()) {
            bail!("duplicate proxy id: {}", proxy.id);
        }
        if proxy.name.trim().is_empty() {
            bail!("proxy name cannot be empty");
        }
        if proxy.enabled && !capability.supported_proxy_kinds.contains(&proxy.kind) {
            bail!(
                "proxy '{}' uses unsupported type '{:?}' for engine '{}'",
                proxy.name,
                proxy.kind,
                capability.display_name
            );
        }
        if matches!(proxy.kind, ProxyKind::Socks5 | ProxyKind::Http) {
            validate_host_port(&proxy.endpoint)?;
        }
    }

    for rule in &config.rules {
        if rule.name.trim().is_empty() {
            bail!("rule name cannot be empty");
        }
        let matcher = &rule.matcher;
        if matcher.app_names.is_empty()
            && matcher.exe_paths.is_empty()
            && matcher.pids.is_empty()
            && matcher.wildcard.as_deref().is_none_or(str::is_empty)
        {
            bail!("rule '{}' needs at least one matcher", rule.name);
        }
        if !proxy_ids.contains(rule.proxy_profile.as_str()) {
            bail!(
                "rule '{}' references missing proxy '{}'",
                rule.name,
                rule.proxy_profile
            );
        }
        if rule.enabled && !capability.supports_hash_matching && !rule.matcher.hashes.is_empty() {
            bail!(
                "rule '{}' uses file hash matching, which is unsupported by engine '{}'",
                rule.name,
                capability.display_name
            );
        }
        if rule.enabled && !capability.supports_child_inheritance && rule.auto_bind_children {
            bail!(
                "rule '{}' enables child inheritance, which is unsupported by engine '{}'",
                rule.name,
                capability.display_name
            );
        }
        if config.runtime.leak_protection_mode == LeakProtectionMode::Strict
            && rule.enabled
            && rule.matcher.exe_paths.is_empty()
        {
            bail!(
                "strict leak protection requires executable-path matching; rule '{}' has no executable path",
                rule.name
            );
        }
    }

    for item in &config.quick_bar {
        if item.name.trim().is_empty() {
            bail!("quick launch name cannot be empty");
        }
        if item.exe_path.trim().is_empty() {
            bail!("quick launch '{}' needs an executable path", item.name);
        }
        if !proxy_ids.contains(item.proxy_profile.as_str()) {
            bail!(
                "quick launch '{}' references missing proxy '{}'",
                item.name,
                item.proxy_profile
            );
        }
        if !capability.supports_child_inheritance && item.auto_bind_children {
            bail!(
                "quick launch '{}' enables child inheritance, which is unsupported by engine '{}'",
                item.name,
                capability.display_name
            );
        }
    }

    Ok(())
}

fn validate_host_port(endpoint: &str) -> Result<()> {
    let endpoint = endpoint.trim();
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        bail!("proxy endpoint must use host:port format");
    };
    if host.trim_matches(['[', ']']).trim().is_empty() {
        bail!("proxy endpoint host cannot be empty");
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("proxy endpoint port is invalid"))?;
    if port == 0 {
        bail!("proxy endpoint port must be greater than zero");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MatchCriteria, Rule};

    #[test]
    fn default_config_is_valid() {
        validate_config(&AppConfig::default()).unwrap();
    }

    #[test]
    fn rejects_rule_with_missing_proxy() {
        let mut config = AppConfig::default();
        config.rules.push(Rule::new(
            "Node".to_string(),
            MatchCriteria {
                app_names: vec!["node.exe".to_string()],
                ..Default::default()
            },
            "missing".to_string(),
        ));
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_malformed_proxy_endpoint() {
        let mut config = AppConfig::default();
        config.proxies[0].endpoint = "localhost".to_string();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_unavailable_engine() {
        let config = AppConfig {
            engine_mode: crate::model::EngineMode::Wfp,
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_enabled_unsupported_proxy_kind() {
        let mut config = AppConfig::default();
        config.proxies[0].kind = ProxyKind::Http;
        assert!(validate_config(&config).is_err());

        config.proxies[0].enabled = false;
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn strict_leak_protection_requires_executable_paths() {
        let mut config = AppConfig::default();
        config.runtime.leak_protection_mode = LeakProtectionMode::Strict;
        config.rules.push(Rule::new(
            "name only".to_string(),
            MatchCriteria {
                app_names: vec!["browser.exe".to_string()],
                ..Default::default()
            },
            "clash-socks".to_string(),
        ));
        assert!(validate_config(&config).is_err());

        config.rules[0].matcher.app_names.clear();
        config.rules[0].matcher.exe_paths = vec!["C:\\Apps\\browser.exe".to_string()];
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn rejects_configuration_with_wrong_schema() {
        let config = AppConfig {
            schema_version: crate::config::CURRENT_SCHEMA_VERSION + 1,
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }
}
