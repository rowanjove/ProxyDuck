use std::collections::{HashMap, HashSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    model::{AppConfig, ProcessInfo, Protocol, ProxyKind, Rule},
    process::rule_priority,
};

pub const ROUTING_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutingPlan {
    pub schema_version: u32,
    pub fingerprint: String,
    pub proxy_routes: Vec<PlannedProxyRoute>,
    pub direct_patterns: Vec<String>,
    pub direct_selectors: Vec<PlannedSelector>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedProxyRoute {
    pub rule_id: String,
    pub proxy_id: String,
    pub patterns: Vec<String>,
    pub selectors: Vec<PlannedSelector>,
    pub endpoint: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub protocols: Vec<Protocol>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlannedSelectorKind {
    ProcessName,
    ProcessPath,
    Wildcard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedSelector {
    pub kind: PlannedSelectorKind,
    pub value: String,
}

pub fn compile_routing_plan(config: &AppConfig, processes: &[ProcessInfo]) -> Result<RoutingPlan> {
    let profiles = config
        .proxies
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect::<HashMap<_, _>>();
    let mut routes = Vec::new();
    let mut direct_patterns = HashSet::new();
    let mut direct_selectors = Vec::new();
    let mut claimed_patterns = HashSet::new();
    let mut diagnostics = Vec::new();
    let mut rules = config
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .collect::<Vec<_>>();
    rules.sort_by_key(|rule| rule_priority(rule));

    for rule in rules {
        let Some(profile) = profiles.get(rule.proxy_profile.as_str()) else {
            diagnostics.push(format!("rule '{}' references a missing proxy", rule.name));
            continue;
        };
        if !profile.enabled {
            diagnostics.push(format!("rule '{}' references a disabled proxy", rule.name));
            continue;
        }

        let selectors = rule_selectors(rule, processes)
            .into_iter()
            .filter(|selector| claimed_patterns.insert(selector.value.to_ascii_lowercase()))
            .collect::<Vec<_>>();
        if selectors.is_empty() {
            diagnostics.push(format!(
                "rule '{}' has no unclaimed runtime selectors",
                rule.name
            ));
            continue;
        }

        match profile.kind {
            ProxyKind::Socks5 => routes.push(PlannedProxyRoute {
                rule_id: rule.id.clone(),
                proxy_id: profile.id.clone(),
                patterns: selectors
                    .iter()
                    .map(|selector| selector.value.clone())
                    .collect(),
                selectors,
                endpoint: profile.endpoint.clone(),
                username: profile.username.clone(),
                password: profile.password.clone(),
                protocols: normalized_protocols(rule),
            }),
            ProxyKind::Direct => {
                direct_patterns.extend(selectors.iter().map(|selector| selector.value.clone()));
                direct_selectors.extend(selectors);
            }
            unsupported => diagnostics.push(format!(
                "rule '{}' uses unsupported proxy kind '{unsupported:?}'",
                rule.name
            )),
        }
    }

    let mut direct_patterns = direct_patterns.into_iter().collect::<Vec<_>>();
    direct_patterns.sort();
    direct_selectors.sort_by(|left, right| left.value.cmp(&right.value));
    let mut plan = RoutingPlan {
        schema_version: ROUTING_PLAN_SCHEMA_VERSION,
        fingerprint: String::new(),
        proxy_routes: routes,
        direct_patterns,
        direct_selectors,
        diagnostics,
    };
    let encoded = serde_json::to_vec(&plan)?;
    plan.fingerprint = fnv1a_hex(&encoded);
    Ok(plan)
}

fn normalized_protocols(rule: &Rule) -> Vec<Protocol> {
    let mut protocols = rule.protocols.clone();
    if protocols.is_empty() {
        protocols = vec![Protocol::Tcp, Protocol::Udp, Protocol::Dns];
    }
    protocols.sort_by_key(|protocol| match protocol {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        Protocol::Dns => 2,
    });
    protocols.dedup();
    protocols
}

fn rule_selectors(rule: &Rule, processes: &[ProcessInfo]) -> Vec<PlannedSelector> {
    let mut patterns = HashMap::new();
    for value in rule.matcher.app_names.iter().filter_map(|v| non_empty(v)) {
        patterns.insert(value, PlannedSelectorKind::ProcessName);
    }
    for value in rule.matcher.exe_paths.iter().filter_map(|v| non_empty(v)) {
        patterns.insert(value, PlannedSelectorKind::ProcessPath);
    }
    for value in rule.matcher.wildcard.iter().filter_map(|v| non_empty(v)) {
        patterns.insert(value, PlannedSelectorKind::Wildcard);
    }
    for pid in &rule.matcher.pids {
        if let Some(process) = processes.iter().find(|process| process.pid == *pid) {
            if !process.name.is_empty() {
                patterns.insert(process.name.clone(), PlannedSelectorKind::ProcessName);
            }
            if !process.exe.is_empty() {
                patterns.insert(process.exe.clone(), PlannedSelectorKind::ProcessPath);
            }
        }
    }
    let mut patterns = patterns
        .into_iter()
        .map(|(value, kind)| PlannedSelector { kind, value })
        .collect::<Vec<_>>();
    patterns.sort_by(|left, right| left.value.cmp(&right.value));
    patterns
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MatchCriteria, ProxyProfile, Rule};

    #[test]
    fn plan_is_deterministic_and_preserves_rule_priority() {
        let config = AppConfig {
            rules: vec![
                Rule::new(
                    "name fallback".into(),
                    MatchCriteria {
                        app_names: vec!["app.exe".into()],
                        ..Default::default()
                    },
                    "clash-socks".into(),
                ),
                Rule::new(
                    "path winner".into(),
                    MatchCriteria {
                        exe_paths: vec!["app.exe".into()],
                        ..Default::default()
                    },
                    "clash-socks".into(),
                ),
            ],
            ..Default::default()
        };

        let first = compile_routing_plan(&config, &[]).unwrap();
        let second = compile_routing_plan(&config, &[]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.proxy_routes.len(), 1);
        assert_eq!(first.proxy_routes[0].rule_id, config.rules[1].id);
        assert!(!first.fingerprint.is_empty());
    }

    #[test]
    fn disabled_proxy_does_not_claim_a_fallback_selector() {
        let mut config = AppConfig::default();
        config.proxies.push(ProxyProfile {
            id: "disabled".into(),
            name: "disabled".into(),
            kind: ProxyKind::Socks5,
            endpoint: "127.0.0.1:1".into(),
            username: None,
            password: None,
            enabled: false,
        });
        config.rules = vec![
            Rule::new(
                "disabled".into(),
                MatchCriteria {
                    app_names: vec!["app.exe".into()],
                    ..Default::default()
                },
                "disabled".into(),
            ),
            Rule::new(
                "fallback".into(),
                MatchCriteria {
                    app_names: vec!["app.exe".into()],
                    ..Default::default()
                },
                "clash-socks".into(),
            ),
        ];

        let plan = compile_routing_plan(&config, &[]).unwrap();
        assert_eq!(plan.proxy_routes.len(), 1);
        assert_eq!(plan.proxy_routes[0].proxy_id, "clash-socks");
    }
}
