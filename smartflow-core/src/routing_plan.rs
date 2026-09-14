use std::collections::{HashMap, HashSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    model::{
        AppConfig, EngineMode, LeakProtectionMode, ProcessInfo, Protocol, ProxyKind, RouteAction,
        Rule,
    },
    process::rule_priority,
};

pub const ROUTING_PLAN_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompileDiagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    pub blocks_strict: bool,
}

impl CompileDiagnostic {
    fn new(
        code: &str,
        severity: DiagnosticSeverity,
        rule: Option<&Rule>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.to_string(),
            severity,
            message: message.into(),
            rule_id: rule.map(|rule| rule.id.clone()),
            engine: None,
            field_path: None,
            expected: None,
            effective: None,
            remediation: None,
            blocks_strict: matches!(severity, DiagnosticSeverity::Error),
        }
    }

    fn warning(code: &str, rule: Option<&Rule>, message: impl Into<String>) -> Self {
        Self::new(code, DiagnosticSeverity::Warning, rule, message)
    }

    fn error(code: &str, rule: Option<&Rule>, message: impl Into<String>) -> Self {
        Self::new(code, DiagnosticSeverity::Error, rule, message)
    }

    fn with_field(mut self, field_path: &str) -> Self {
        self.field_path = Some(field_path.to_string());
        self
    }

    fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutingPlan {
    pub schema_version: u32,
    pub fingerprint: String,
    pub proxy_routes: Vec<PlannedProxyRoute>,
    pub direct_patterns: Vec<String>,
    pub direct_selectors: Vec<PlannedSelector>,
    #[serde(default)]
    pub direct_routes: Vec<PlannedDirectRoute>,
    #[serde(default)]
    pub blocked_routes: Vec<PlannedBlockedRoute>,
    pub diagnostics: Vec<CompileDiagnostic>,
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
    #[serde(skip_serializing)]
    pub password: Option<String>,
    pub protocols: Vec<Protocol>,
    #[serde(default)]
    pub destination: crate::model::DestinationMatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PlannedSelectorKind {
    ProcessName,
    ProcessPath,
    ProcessInstance,
    Wildcard,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SelectorKey {
    kind: PlannedSelectorKind,
    normalized_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedSelector {
    pub kind: PlannedSelectorKind,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedBlockedRoute {
    pub rule_id: String,
    pub selectors: Vec<PlannedSelector>,
    pub protocols: Vec<Protocol>,
    pub destination: crate::model::DestinationMatch,
    pub reject: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedDirectRoute {
    pub rule_id: String,
    pub selectors: Vec<PlannedSelector>,
    pub protocols: Vec<Protocol>,
    pub destination: crate::model::DestinationMatch,
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
    let mut direct_routes = Vec::new();
    let mut blocked_routes = Vec::new();
    let mut claimed_selectors = HashSet::new();
    let mut diagnostics = Vec::<CompileDiagnostic>::new();
    let mut rules = config
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .collect::<Vec<_>>();
    rules.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| rule_priority(a).cmp(&rule_priority(b)))
    });

    for rule in rules {
        append_policy_diagnostics(rule, config.engine_mode, &mut diagnostics);
        for pid in &rule.matcher.pids {
            let Some(expected_creation_time) = rule.matcher.pid_creation_time else {
                diagnostics.push(
                    CompileDiagnostic::error(
                        "PD-RULE-PID-CREATION-TIME-REQUIRED",
                        Some(rule),
                        format!(
                            "rule '{}' references PID {} without an expected process creation time; refusing PID-only matching",
                            rule.name, pid
                        ),
                    )
                    .with_field("matcher.pidCreationTime")
                    .with_remediation(
                        "create the rule from a live process snapshot or use a persistent path/name selector",
                    ),
                );
                continue;
            };

            let process = processes.iter().find(|process| process.pid == *pid);
            if process.is_none() {
                diagnostics.push(
                    CompileDiagnostic::warning(
                        "PD-RULE-PID-UNRESOLVED",
                        Some(rule),
                        format!(
                            "rule '{}' references PID {} but that process instance is not present",
                            rule.name, pid
                        ),
                    )
                    .with_field("matcher.pids")
                    .with_remediation(
                        "wait for the process to start or use a persistent path/name selector",
                    ),
                );
            } else if process
                .is_some_and(|process| process.creation_time != Some(expected_creation_time))
            {
                diagnostics.push(
                    CompileDiagnostic::warning(
                        "PD-RULE-PID-INSTANCE-MISMATCH",
                        Some(rule),
                        format!(
                            "rule '{}' expects PID {} creation time {}, but the current process instance differs",
                            rule.name, pid, expected_creation_time
                        ),
                    )
                    .with_field("matcher.pidCreationTime")
                    .with_remediation(
                        "wait for the expected process instance or recreate the rule from the current process",
                    ),
                );
            }
        }
        let block_action = match rule.action {
            RouteAction::Block => Some(false),
            RouteAction::Reject => Some(true),
            _ => None,
        };
        let profile_id = match &rule.action {
            RouteAction::Proxy { proxy_id } if !proxy_id.trim().is_empty() => Some(proxy_id),
            RouteAction::Proxy { .. } => Some(&rule.proxy_profile),
            RouteAction::Direct => None,
            RouteAction::Block | RouteAction::Reject => None,
        };
        let profile = profile_id.and_then(|id| profiles.get(id.as_str()));
        if let Some(profile) = profile {
            if !profile.enabled {
                diagnostics.push(
                    CompileDiagnostic::error(
                        "PD-RULE-PROXY-DISABLED",
                        Some(rule),
                        format!("rule '{}' references a disabled proxy", rule.name),
                    )
                    .with_field("action.proxyId")
                    .with_remediation("enable the proxy or choose another route action"),
                );
                continue;
            }
        } else if let Some(profile_id) = profile_id {
            diagnostics.push(
                CompileDiagnostic::error(
                    "PD-RULE-PROXY-MISSING",
                    Some(rule),
                    format!(
                        "rule '{}' references a missing proxy '{}'",
                        rule.name, profile_id
                    ),
                )
                .with_field("action.proxyId")
                .with_remediation("create the referenced proxy or change the rule action"),
            );
            continue;
        }

        let selectors = rule_selectors(rule, processes)
            .into_iter()
            .filter(|selector| {
                let key = SelectorKey {
                    kind: selector.kind,
                    normalized_value: normalize_selector_value(selector),
                };
                !rule.destination.is_empty() || claimed_selectors.insert(key)
            })
            .collect::<Vec<_>>();
        if selectors.is_empty() {
            diagnostics.push(
                CompileDiagnostic::warning(
                    "PD-RULE-SELECTOR-UNCLAIMED",
                    Some(rule),
                    format!("rule '{}' has no unclaimed runtime selectors", rule.name),
                )
                .with_field("matcher")
                .with_remediation("adjust rule priority or use a non-overlapping selector"),
            );
            continue;
        }

        if let Some(reject) = block_action {
            blocked_routes.push(PlannedBlockedRoute {
                rule_id: rule.id.clone(),
                selectors,
                protocols: normalized_protocols(rule),
                destination: rule.destination.clone(),
                reject,
            });
            continue;
        }

        let Some(profile) = profile else {
            direct_patterns.extend(selectors.iter().map(|selector| selector.value.clone()));
            direct_selectors.extend(selectors.clone());
            direct_routes.push(PlannedDirectRoute {
                rule_id: rule.id.clone(),
                selectors,
                protocols: normalized_protocols(rule),
                destination: rule.destination.clone(),
            });
            continue;
        };

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
                destination: rule.destination.clone(),
            }),
            ProxyKind::Direct => {
                direct_patterns.extend(selectors.iter().map(|selector| selector.value.clone()));
                direct_selectors.extend(selectors.clone());
                direct_routes.push(PlannedDirectRoute {
                    rule_id: rule.id.clone(),
                    selectors,
                    protocols: normalized_protocols(rule),
                    destination: rule.destination.clone(),
                });
            }
            unsupported => diagnostics.push(
                CompileDiagnostic::error(
                    "PD-RULE-PROXY-KIND-UNSUPPORTED",
                    Some(rule),
                    format!(
                        "rule '{}' uses unsupported proxy kind '{unsupported:?}'",
                        rule.name
                    ),
                )
                .with_field("action")
                .with_remediation("choose a proxy kind supported by the selected engine"),
            ),
        }
    }

    let mut direct_patterns = direct_patterns.into_iter().collect::<Vec<_>>();
    direct_patterns.sort();
    direct_selectors.sort_by(|left, right| left.value.cmp(&right.value));
    downgrade_compatibility_diagnostics(config, &mut diagnostics);
    let mut plan = RoutingPlan {
        schema_version: ROUTING_PLAN_SCHEMA_VERSION,
        fingerprint: String::new(),
        proxy_routes: routes,
        direct_patterns,
        direct_selectors,
        direct_routes,
        blocked_routes,
        diagnostics,
    };
    let encoded = serde_json::to_vec(&plan)?;
    plan.fingerprint = fnv1a_hex(&encoded);
    Ok(plan)
}

/// In availability/compatibility mode, capability gaps may be applied as a
/// broader route, but they must remain visible to the caller and must never be
/// mistaken for a fully supported policy.  Structural and identity errors are
/// intentionally left as hard errors so a missing proxy or an unsafe PID can
/// never be widened silently.
fn downgrade_compatibility_diagnostics(config: &AppConfig, diagnostics: &mut [CompileDiagnostic]) {
    if matches!(
        config.runtime.leak_protection_mode,
        LeakProtectionMode::Strict
    ) {
        return;
    }

    for diagnostic in diagnostics {
        if !is_compatibility_diagnostic(&diagnostic.code) {
            continue;
        }
        diagnostic.severity = DiagnosticSeverity::Warning;
        diagnostic.blocks_strict = false;
        diagnostic.effective = Some(
            "compatibility mode: the backend may apply a broader process/protocol route"
                .to_string(),
        );
        if !diagnostic.message.starts_with("compatibility mode:") {
            diagnostic.message = format!("compatibility mode: {}", diagnostic.message);
        }
    }
}

fn is_compatibility_diagnostic(code: &str) -> bool {
    matches!(
        code,
        "PD-RULE-NETWORK-UNSUPPORTED"
            | "PD-RULE-DNS-UNSUPPORTED"
            | "PD-RULE-DNS-SCOPE-UNSUPPORTED"
            | "PD-RULE-DESTINATION-UNSUPPORTED"
    )
}

fn append_policy_diagnostics(
    rule: &Rule,
    engine: EngineMode,
    diagnostics: &mut Vec<CompileDiagnostic>,
) {
    if let Some(diagnostic) = unsupported_policy_diagnostic(rule) {
        diagnostics.push(diagnostic);
    }
    if engine == EngineMode::ProxiFyre && !rule.destination.is_empty() {
        diagnostics.push(
            CompileDiagnostic::error(
                "PD-RULE-DESTINATION-UNSUPPORTED",
                Some(rule),
                format!(
                    "rule '{}' contains destination conditions that ProxiFyre cannot express",
                    rule.name
                ),
            )
            .with_field("destination")
            .with_remediation("switch to sing-box or remove the destination condition"),
        );
    }
}

/// Returns a diagnostic for policy fields that are represented in the public
/// model but are not yet compiled into either current backend. Adapters use
/// the same predicate as a fail-closed guard so these policies cannot silently
/// widen a route to all TCP/UDP traffic.
pub fn unsupported_policy_diagnostic(rule: &Rule) -> Option<CompileDiagnostic> {
    if !rule.protocols.is_empty() && normalized_protocols(rule).is_empty() {
        return Some(
            CompileDiagnostic::error(
                "PD-RULE-DNS-SCOPE-UNSUPPORTED",
                Some(rule),
                format!(
                    "rule '{}' only selects the legacy DNS compatibility flag; DNS is not an independent route protocol",
                    rule.name
                ),
            )
            .with_field("protocols")
            .with_remediation("select TCP and/or UDP and configure dns.mode separately"),
        );
    }
    if !matches!(rule.network.tcp, crate::model::RouteDisposition::Proxy)
        || !matches!(rule.network.udp, crate::model::RouteDisposition::Proxy)
        || !matches!(
            rule.network.ipv4,
            crate::model::AddressFamilyDisposition::Proxy
        )
        || !matches!(
            rule.network.ipv6,
            crate::model::AddressFamilyDisposition::Proxy
        )
    {
        return Some(
            CompileDiagnostic::error(
                "PD-RULE-NETWORK-UNSUPPORTED",
                Some(rule),
                format!(
                    "rule '{}' has network dispositions that require backend-specific compilation",
                    rule.name
                ),
            )
            .with_field("network")
            .with_remediation(
                "use the default proxy dispositions or select an engine with network policy support",
            ),
        );
    }
    if !matches!(
        rule.dns.mode,
        crate::model::DnsMode::Inherit | crate::model::DnsMode::BlockPlaintext
    ) {
        return Some(
            CompileDiagnostic::error(
                "PD-RULE-DNS-UNSUPPORTED",
                Some(rule),
                format!(
                    "rule '{}' uses DNS mode '{:?}' that is not compiled by the current backend",
                    rule.name, rule.dns.mode
                ),
            )
            .with_field("dns.mode")
            .with_remediation(
                "use inherit/block_plaintext or select a backend with DNS policy support",
            ),
        );
    }
    None
}

fn normalized_protocols(rule: &Rule) -> Vec<Protocol> {
    let mut protocols = rule.protocols.clone();
    if protocols.is_empty() {
        protocols = vec![Protocol::Tcp, Protocol::Udp];
    }
    // `dns` remains readable for one compatibility line, but it is a legacy
    // firewall marker rather than an independently matchable data-plane
    // protocol.  DnsPolicy/force_dns carries the actual DNS intent.
    protocols.retain(|protocol| !matches!(protocol, Protocol::Dns));
    protocols.sort_by_key(|protocol| match protocol {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        Protocol::Dns => 2,
    });
    protocols.dedup();
    protocols
}

fn rule_selectors(rule: &Rule, processes: &[ProcessInfo]) -> Vec<PlannedSelector> {
    let mut patterns = HashMap::<SelectorKey, String>::new();
    for value in rule.matcher.app_names.iter().filter_map(|v| non_empty(v)) {
        patterns.insert(
            SelectorKey {
                kind: PlannedSelectorKind::ProcessName,
                normalized_value: value.to_ascii_lowercase(),
            },
            value,
        );
    }
    for value in rule.matcher.exe_paths.iter().filter_map(|v| non_empty(v)) {
        patterns.insert(
            SelectorKey {
                kind: PlannedSelectorKind::ProcessPath,
                normalized_value: normalize_path(&value),
            },
            value,
        );
    }
    for value in rule.matcher.wildcard.iter().filter_map(|v| non_empty(v)) {
        patterns.insert(
            SelectorKey {
                kind: PlannedSelectorKind::Wildcard,
                normalized_value: value.to_ascii_lowercase(),
            },
            value,
        );
    }
    for pid in &rule.matcher.pids {
        if let Some(expected_creation_time) = rule.matcher.pid_creation_time {
            if let Some(process) = processes.iter().find(|process| {
                process.pid == *pid && process.creation_time == Some(expected_creation_time)
            }) {
                let value = format!("pid:{}:start:{}", process.pid, expected_creation_time);
                patterns.insert(
                    SelectorKey {
                        kind: PlannedSelectorKind::ProcessInstance,
                        normalized_value: value.clone(),
                    },
                    value,
                );
            }
        }
    }
    let mut patterns = patterns
        .into_iter()
        .map(|(key, value)| PlannedSelector {
            kind: key.kind,
            value,
        })
        .collect::<Vec<_>>();
    patterns.sort_by(|left, right| {
        selector_kind_order(left.kind)
            .cmp(&selector_kind_order(right.kind))
            .then_with(|| normalize_selector_value(left).cmp(&normalize_selector_value(right)))
            .then_with(|| left.value.cmp(&right.value))
    });
    patterns
}

fn normalize_selector_value(selector: &PlannedSelector) -> String {
    match selector.kind {
        PlannedSelectorKind::ProcessName => selector.value.trim().to_ascii_lowercase(),
        PlannedSelectorKind::ProcessPath => normalize_path(&selector.value),
        PlannedSelectorKind::ProcessInstance => selector.value.trim().to_ascii_lowercase(),
        PlannedSelectorKind::Wildcard => selector
            .value
            .trim()
            .to_ascii_lowercase()
            .replace('/', "\\"),
    }
}

fn normalize_path(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn selector_kind_order(kind: PlannedSelectorKind) -> u8 {
    match kind {
        PlannedSelectorKind::ProcessName => 0,
        PlannedSelectorKind::ProcessPath => 1,
        PlannedSelectorKind::ProcessInstance => 2,
        PlannedSelectorKind::Wildcard => 3,
    }
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
                    "local-socks".into(),
                ),
                Rule::new(
                    "path winner".into(),
                    MatchCriteria {
                        exe_paths: vec!["app.exe".into()],
                        ..Default::default()
                    },
                    "local-socks".into(),
                ),
            ],
            ..Default::default()
        };

        let first = compile_routing_plan(&config, &[]).unwrap();
        let second = compile_routing_plan(&config, &[]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.proxy_routes.len(), 2);
        assert_eq!(first.proxy_routes[0].rule_id, config.rules[1].id);
        assert_eq!(first.proxy_routes[1].rule_id, config.rules[0].id);
        assert!(!first.fingerprint.is_empty());
    }

    #[test]
    fn selector_claims_include_kind_to_avoid_name_path_collisions() {
        let config = AppConfig {
            rules: vec![Rule::new(
                "mixed".into(),
                MatchCriteria {
                    app_names: vec!["App.exe".into()],
                    exe_paths: vec!["C:/Apps/App.exe".into()],
                    ..Default::default()
                },
                "local-socks".into(),
            )],
            ..Default::default()
        };

        let plan = compile_routing_plan(&config, &[]).unwrap();
        let selectors = &plan.proxy_routes[0].selectors;
        assert_eq!(selectors.len(), 2);
        assert!(selectors
            .iter()
            .any(|selector| selector.kind == PlannedSelectorKind::ProcessName));
        assert!(selectors
            .iter()
            .any(|selector| selector.kind == PlannedSelectorKind::ProcessPath));
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
            password_ref: None,
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
                "local-socks".into(),
            ),
        ];

        let plan = compile_routing_plan(&config, &[]).unwrap();
        assert_eq!(plan.proxy_routes.len(), 1);
        assert_eq!(plan.proxy_routes[0].proxy_id, "local-socks");
    }

    #[test]
    fn direct_action_does_not_require_a_proxy_profile() {
        let config = AppConfig {
            rules: vec![Rule {
                action: RouteAction::Direct,
                proxy_profile: String::new(),
                ..Rule::new(
                    "direct browser".into(),
                    MatchCriteria {
                        app_names: vec!["browser.exe".into()],
                        ..Default::default()
                    },
                    "local-socks".into(),
                )
            }],
            ..Default::default()
        };

        let plan = compile_routing_plan(&config, &[]).unwrap();
        assert!(plan.proxy_routes.is_empty());
        assert_eq!(plan.direct_patterns, vec!["browser.exe"]);
        crate::validation::validate_config(&config).unwrap();
    }

    #[test]
    fn direct_destination_is_kept_as_a_scoped_route() {
        let mut rule = Rule::new(
            "direct example".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        );
        rule.action = RouteAction::Direct;
        rule.destination.domains = vec!["example.com".into()];
        rule.destination.ports = vec![443];
        let plan = compile_routing_plan(
            &AppConfig {
                rules: vec![rule],
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        assert_eq!(plan.direct_selectors.len(), 1);
        assert_eq!(plan.direct_routes.len(), 1);
        assert_eq!(plan.direct_routes[0].destination.ports, vec![443]);
    }

    #[test]
    fn destination_scoped_rules_can_share_a_process_selector() {
        let matcher = MatchCriteria {
            app_names: vec!["browser.exe".into()],
            ..Default::default()
        };
        let mut first = Rule::new(
            "first destination".into(),
            matcher.clone(),
            "local-socks".into(),
        );
        first.destination.domains = vec!["first.example".into()];
        let mut second = Rule::new("second destination".into(), matcher, "local-socks".into());
        second.destination.domains = vec!["second.example".into()];

        let plan = compile_routing_plan(
            &AppConfig {
                rules: vec![first, second],
                ..Default::default()
            },
            &[],
        )
        .unwrap();

        assert_eq!(plan.proxy_routes.len(), 2);
        assert!(plan
            .proxy_routes
            .iter()
            .all(|route| route.selectors.len() == 1));
    }

    #[test]
    fn block_and_reject_actions_compile_to_typed_blocked_routes() {
        let mut block = Rule::new(
            "block browser".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            String::new(),
        );
        block.action = RouteAction::Block;
        block.destination.ports = vec![443];
        let mut reject = Rule::new(
            "reject curl".into(),
            MatchCriteria {
                app_names: vec!["curl.exe".into()],
                ..Default::default()
            },
            String::new(),
        );
        reject.action = RouteAction::Reject;
        let config = AppConfig {
            rules: vec![block, reject],
            ..Default::default()
        };

        let plan = compile_routing_plan(&config, &[]).unwrap();
        assert_eq!(plan.blocked_routes.len(), 2);
        assert!(!plan.blocked_routes[0].reject);
        assert_eq!(plan.blocked_routes[0].destination.ports, vec![443]);
        assert!(plan.blocked_routes[1].reject);
        assert!(plan.proxy_routes.is_empty());
    }

    #[test]
    fn pid_selector_remains_an_ephemeral_process_instance() {
        let config = AppConfig {
            rules: vec![Rule::new(
                "pid route".into(),
                MatchCriteria {
                    pids: vec![42],
                    pid_creation_time: Some(1234),
                    ..Default::default()
                },
                "local-socks".into(),
            )],
            ..Default::default()
        };
        let plan = compile_routing_plan(
            &config,
            &[ProcessInfo {
                pid: 42,
                creation_time: Some(1234),
                name: "browser.exe".into(),
                exe: "C:\\Apps\\browser.exe".into(),
            }],
        )
        .unwrap();
        assert_eq!(
            plan.proxy_routes[0].selectors[0].kind,
            PlannedSelectorKind::ProcessInstance
        );
        assert_eq!(plan.proxy_routes[0].selectors[0].value, "pid:42:start:1234");
        assert!(plan.diagnostics.is_empty());
    }

    #[test]
    fn pid_only_selector_is_rejected_without_widening() {
        let config = AppConfig {
            rules: vec![Rule::new(
                "pid route".into(),
                MatchCriteria {
                    pids: vec![42],
                    ..Default::default()
                },
                "local-socks".into(),
            )],
            ..Default::default()
        };
        let plan = compile_routing_plan(
            &config,
            &[ProcessInfo {
                pid: 42,
                creation_time: None,
                name: "browser.exe".into(),
                exe: "C:\\Apps\\browser.exe".into(),
            }],
        )
        .unwrap();
        assert!(plan.proxy_routes.is_empty());
        assert!(plan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "PD-RULE-PID-CREATION-TIME-REQUIRED"));
    }

    #[test]
    fn unsupported_policy_is_reported_without_widening_the_route() {
        let mut rule = Rule::new(
            "tcp direct policy".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        );
        rule.network.tcp = crate::model::RouteDisposition::Direct;
        let diagnostic = unsupported_policy_diagnostic(&rule).unwrap();
        assert!(diagnostic.message.contains("network dispositions"));
    }

    #[test]
    fn availability_mode_downgrades_capability_gaps_but_strict_mode_blocks_them() {
        let mut rule = Rule::new(
            "tcp direct policy".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        );
        rule.network.tcp = crate::model::RouteDisposition::Direct;

        let availability = AppConfig {
            rules: vec![rule.clone()],
            ..Default::default()
        };
        let plan = compile_routing_plan(&availability, &[]).unwrap();
        let diagnostic = plan
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "PD-RULE-NETWORK-UNSUPPORTED")
            .expect("network capability diagnostic");
        assert_eq!(diagnostic.severity, DiagnosticSeverity::Warning);
        assert!(!diagnostic.blocks_strict);
        assert!(diagnostic
            .effective
            .as_deref()
            .is_some_and(|text| text.contains("broader")));

        let mut strict = availability;
        strict.runtime.leak_protection_mode = crate::model::LeakProtectionMode::Strict;
        let plan = compile_routing_plan(&strict, &[]).unwrap();
        let diagnostic = plan
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "PD-RULE-NETWORK-UNSUPPORTED")
            .expect("strict network capability diagnostic");
        assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
        assert!(diagnostic.blocks_strict);
    }

    #[test]
    fn proxifyre_destination_gap_is_explicit_and_mode_aware() {
        let mut rule = Rule::new(
            "destination policy".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        );
        rule.destination.domains = vec!["example.com".into()];
        let plan = compile_routing_plan(
            &AppConfig {
                rules: vec![rule.clone()],
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let diagnostic = plan
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "PD-RULE-DESTINATION-UNSUPPORTED")
            .expect("destination capability diagnostic");
        assert_eq!(diagnostic.severity, DiagnosticSeverity::Warning);
        assert!(!diagnostic.blocks_strict);

        let mut strict = AppConfig {
            rules: vec![rule],
            ..Default::default()
        };
        strict.runtime.leak_protection_mode = crate::model::LeakProtectionMode::Strict;
        let strict_plan = compile_routing_plan(&strict, &[]).unwrap();
        let diagnostic = strict_plan
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "PD-RULE-DESTINATION-UNSUPPORTED")
            .expect("strict destination capability diagnostic");
        assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
        assert!(diagnostic.blocks_strict);
    }

    #[test]
    fn legacy_dns_flag_is_not_compiled_as_udp_scope() {
        let mut rule = Rule::new(
            "dns marker".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        );
        rule.protocols = vec![Protocol::Dns];
        let plan = compile_routing_plan(
            &AppConfig {
                rules: vec![rule],
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        assert_eq!(plan.proxy_routes.len(), 1);
        assert!(plan.proxy_routes[0].protocols.is_empty());
        assert!(plan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "PD-RULE-DNS-SCOPE-UNSUPPORTED"));
    }
}
