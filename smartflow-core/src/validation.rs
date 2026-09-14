use std::collections::HashSet;

use anyhow::{bail, Result};

use crate::{
    engine::capability_for,
    model::{AppConfig, DestinationMatch, LeakProtectionMode, ProxyKind, RouteAction},
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

    let mut rule_ids = HashSet::new();
    for rule in &config.rules {
        if rule.id.trim().is_empty() {
            bail!("rule id cannot be empty");
        }
        if !rule_ids.insert(rule.id.as_str()) {
            bail!("duplicate rule id: {}", rule.id);
        }
        if rule.name.trim().is_empty() {
            bail!("rule name cannot be empty");
        }
        validate_rule_labels(rule.group.as_deref(), &rule.tags, &rule.name)?;
        let matcher = &rule.matcher;
        if matcher.pids.len() > 1 && matcher.pid_creation_time.is_some() {
            bail!(
                "rule '{}' must bind one PID to one creation time; multiple PID values are ambiguous",
                rule.name
            );
        }
        if matcher.app_names.is_empty()
            && matcher.exe_paths.is_empty()
            && matcher.pids.is_empty()
            && matcher.wildcard.as_deref().is_none_or(str::is_empty)
        {
            bail!("rule '{}' needs at least one matcher", rule.name);
        }
        validate_destination(&rule.destination, &rule.name)?;
        if let RouteAction::Proxy { proxy_id } = &rule.action {
            let target = if proxy_id.trim().is_empty() {
                rule.proxy_profile.as_str()
            } else {
                proxy_id.as_str()
            };
            if target.trim().is_empty() {
                bail!("rule '{}' has an empty proxy action target", rule.name);
            }
            if !proxy_ids.contains(target) {
                bail!(
                    "rule '{}' action references missing proxy '{}'",
                    rule.name,
                    target
                );
            }
        }
        if !(0..=1000).contains(&rule.priority) {
            bail!(
                "rule '{}' priority must be between 0 and 1000 (got {})",
                rule.name,
                rule.priority
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

    let mut profile_ids = HashSet::new();
    let mut profile_names = HashSet::new();
    for profile in &config.profiles {
        if profile.id.trim().is_empty() {
            bail!("profile id cannot be empty");
        }
        if !profile_ids.insert(profile.id.as_str()) {
            bail!("duplicate profile id: {}", profile.id);
        }
        if profile.name.trim().is_empty() {
            bail!("profile name cannot be empty");
        }
        if !profile_names.insert(profile.name.to_ascii_lowercase()) {
            bail!("duplicate profile name: {}", profile.name);
        }
        let mut profile_rule_ids = HashSet::new();
        for rule in &profile.rules {
            if rule.id.trim().is_empty() {
                bail!(
                    "profile '{}' contains a rule with an empty id",
                    profile.name
                );
            }
            if !profile_rule_ids.insert(rule.id.as_str()) {
                bail!(
                    "profile '{}' contains duplicate rule id: {}",
                    profile.name,
                    rule.id
                );
            }
            if rule.name.trim().is_empty() {
                bail!(
                    "profile '{}' contains a rule with an empty name",
                    profile.name
                );
            }
            validate_rule_labels(rule.group.as_deref(), &rule.tags, &rule.name)?;
            validate_destination(&rule.destination, &rule.name)?;
            if let RouteAction::Proxy { proxy_id } = &rule.action {
                let target = if proxy_id.trim().is_empty() {
                    rule.proxy_profile.as_str()
                } else {
                    proxy_id.as_str()
                };
                if !proxy_ids.contains(target) {
                    bail!(
                        "profile '{}' rule '{}' references missing proxy '{}'",
                        profile.name,
                        rule.name,
                        target
                    );
                }
            }
        }
        for item in &profile.quick_bar {
            if item.name.trim().is_empty() || item.exe_path.trim().is_empty() {
                bail!(
                    "profile '{}' contains a quick launch item without a name or executable",
                    profile.name
                );
            }
            if !proxy_ids.contains(item.proxy_profile.as_str()) {
                bail!(
                    "profile '{}' quick launch '{}' references missing proxy '{}'",
                    profile.name,
                    item.name,
                    item.proxy_profile
                );
            }
        }
    }
    if let Some(active_id) = config.active_profile_id.as_deref() {
        if !profile_ids.contains(active_id) {
            bail!("active profile '{}' does not exist", active_id);
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

fn validate_destination(destination: &DestinationMatch, rule_name: &str) -> Result<()> {
    if destination
        .domains
        .iter()
        .any(|domain| domain.trim().is_empty())
    {
        bail!("rule '{}' contains an empty destination domain", rule_name);
    }
    if destination.ip_cidrs.iter().any(|cidr| {
        let Some((address, prefix)) = cidr.trim().split_once('/') else {
            return true;
        };
        let Ok(prefix) = prefix.parse::<u8>() else {
            return true;
        };
        match address.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => prefix > 32,
            Ok(std::net::IpAddr::V6(_)) => prefix > 128,
            Err(_) => true,
        }
    }) {
        bail!("rule '{}' contains an invalid destination CIDR", rule_name);
    }
    if destination.ports.contains(&0) {
        bail!("rule '{}' contains an invalid destination port", rule_name);
    }
    if destination.domains.len() + destination.ip_cidrs.len() > 256 {
        bail!("rule '{}' has too many destination entries", rule_name);
    }
    Ok(())
}

fn validate_rule_labels(group: Option<&str>, tags: &[String], rule_name: &str) -> Result<()> {
    if let Some(group) = group {
        let group = group.trim();
        if group.is_empty() {
            bail!("rule '{}' has an empty group", rule_name);
        }
        if group.chars().count() > 128 {
            bail!("rule '{}' group is too long", rule_name);
        }
    }
    if tags.len() > 32 {
        bail!("rule '{}' has too many tags", rule_name);
    }
    let mut normalized = HashSet::new();
    for tag in tags {
        let tag = tag.trim();
        if tag.is_empty() {
            bail!("rule '{}' contains an empty tag", rule_name);
        }
        if tag.chars().count() > 64 {
            bail!("rule '{}' contains an overlong tag", rule_name);
        }
        if !normalized.insert(tag.to_ascii_lowercase()) {
            bail!("rule '{}' contains duplicate tag '{}'", rule_name, tag);
        }
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
            "local-socks".to_string(),
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

    #[test]
    fn rejects_invalid_destination_policy() {
        let mut config = AppConfig::default();
        let mut rule = Rule::new(
            "destination".to_string(),
            MatchCriteria {
                app_names: vec!["browser.exe".to_string()],
                ..Default::default()
            },
            "clash-socks".to_string(),
        );
        rule.destination.ip_cidrs = vec!["not-an-ip/24".to_string()];
        config.rules.push(rule);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_ipv4_cidr_with_ipv6_prefix_length() {
        let mut config = AppConfig::default();
        let mut rule = Rule::new(
            "invalid cidr".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "clash-socks".into(),
        );
        rule.destination.ip_cidrs = vec!["10.0.0.0/64".into()];
        config.rules.push(rule);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_multiple_pids_with_one_creation_time() {
        let mut config = AppConfig::default();
        config.rules.push(Rule::new(
            "ambiguous pid rule".into(),
            MatchCriteria {
                pids: vec![10, 11],
                pid_creation_time: Some(1234),
                ..Default::default()
            },
            "clash-socks".into(),
        ));

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_empty_and_duplicate_rule_ids() {
        let mut config = AppConfig::default();
        let mut first = Rule::new(
            "first".into(),
            MatchCriteria {
                app_names: vec!["one.exe".into()],
                ..Default::default()
            },
            "clash-socks".into(),
        );
        first.id.clear();
        config.rules.push(first);
        assert!(validate_config(&config).is_err());

        let mut config = AppConfig::default();
        let first = Rule::new(
            "first".into(),
            MatchCriteria {
                app_names: vec!["one.exe".into()],
                ..Default::default()
            },
            "clash-socks".into(),
        );
        let mut second = first.clone();
        second.name = "second".into();
        config.rules.extend([first, second]);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_duplicate_profile_rule_ids() {
        let mut config = AppConfig::default();
        let first = Rule::new(
            "first".into(),
            MatchCriteria {
                app_names: vec!["one.exe".into()],
                ..Default::default()
            },
            "clash-socks".into(),
        );
        let mut second = first.clone();
        second.name = "second".into();
        config.profiles.push(crate::model::RoutingProfile {
            id: "profile-a".into(),
            name: "Profile A".into(),
            description: String::new(),
            engine_mode: crate::model::EngineMode::ProxiFyre,
            rules: vec![first, second],
            quick_bar: Vec::new(),
            runtime: crate::model::RuntimeToggles::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_invalid_rule_labels() {
        let mut config = AppConfig::default();
        let mut rule = Rule::new(
            "labels".into(),
            MatchCriteria {
                app_names: vec!["one.exe".into()],
                ..Default::default()
            },
            "clash-socks".into(),
        );
        rule.group = Some(" ".into());
        config.rules.push(rule);
        assert!(validate_config(&config).is_err());

        let mut config = AppConfig::default();
        let mut rule = Rule::new(
            "duplicate tags".into(),
            MatchCriteria {
                app_names: vec!["one.exe".into()],
                ..Default::default()
            },
            "clash-socks".into(),
        );
        rule.tags = vec!["Browser".into(), "browser".into()];
        config.rules.push(rule);
        assert!(validate_config(&config).is_err());
    }
}
