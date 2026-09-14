use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::model::{AppConfig, Protocol, ProxyProfile, RouteAction, Rule};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyIssueSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyIssueKind {
    Shadowed,
    Duplicate,
    Overlap,
    DeadRule,
    MissingEndpoint,
    DisabledEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyIssue {
    pub kind: PolicyIssueKind,
    pub severity: PolicyIssueSeverity,
    pub primary_rule_id: String,
    pub primary_rule_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_rule_name: Option<String>,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAnalysisReport {
    pub total_rules: usize,
    pub active_rules: usize,
    pub issues: Vec<PolicyIssue>,
    pub healthy: bool,
}

/// Perform comprehensive static analysis on a set of rules and proxies.
pub fn analyze_policies(rules: &[Rule], proxies: &[ProxyProfile]) -> PolicyAnalysisReport {
    let mut issues = Vec::new();
    let proxy_map = proxies
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect::<std::collections::HashMap<_, _>>();

    let enabled_rules = rules.iter().filter(|r| r.enabled).collect::<Vec<_>>();

    // 1. Check individual rule sanity (Dead rules, missing endpoints)
    for rule in rules {
        if !rule.enabled {
            continue;
        }

        // Dead rule: completely empty matcher
        if rule.matcher.app_names.is_empty()
            && rule.matcher.exe_paths.is_empty()
            && rule.matcher.pids.is_empty()
            && rule
                .matcher
                .wildcard
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            issues.push(PolicyIssue {
                kind: PolicyIssueKind::DeadRule,
                severity: PolicyIssueSeverity::Error,
                primary_rule_id: rule.id.clone(),
                primary_rule_name: rule.name.clone(),
                related_rule_id: None,
                related_rule_name: None,
                message: format!(
                    "规则 '{}' 已启用但匹配条件为空，无法匹配任何进程",
                    rule.name
                ),
                remediation: "配置至少一个进程名、执行文件路径或通配符".to_string(),
            });
        }

        // Protocol sanity: if rule specifies only Dns protocol, warn that DNS is not separately routable
        if !rule.protocols.is_empty() && rule.protocols.iter().all(|p| matches!(p, Protocol::Dns)) {
            issues.push(PolicyIssue {
                kind: PolicyIssueKind::DeadRule,
                severity: PolicyIssueSeverity::Warning,
                primary_rule_id: rule.id.clone(),
                primary_rule_name: rule.name.clone(),
                related_rule_id: None,
                related_rule_name: None,
                message: format!(
                    "规则 '{}' 仅包含 DNS 协议，当前数据平面引擎无法作为独立路由分流",
                    rule.name
                ),
                remediation: "添加 TCP 或 UDP 协议，或使用全局 DNS 策略".to_string(),
            });
        }

        // Endpoint check
        if let RouteAction::Proxy { ref proxy_id } = rule.action {
            let target = if proxy_id.trim().is_empty() {
                rule.proxy_profile.as_str()
            } else {
                proxy_id.as_str()
            };

            if let Some(proxy) = proxy_map.get(target) {
                if !proxy.enabled {
                    issues.push(PolicyIssue {
                        kind: PolicyIssueKind::DisabledEndpoint,
                        severity: PolicyIssueSeverity::Warning,
                        primary_rule_id: rule.id.clone(),
                        primary_rule_name: rule.name.clone(),
                        related_rule_id: None,
                        related_rule_name: None,
                        message: format!(
                            "规则 '{}' 引用的出口代理节点 '{}' 当前处于停用状态",
                            rule.name, proxy.name
                        ),
                        remediation: "启用该代理节点或将规则出口切换到其他可用节点".to_string(),
                    });
                }
            } else if !target.trim().is_empty() {
                issues.push(PolicyIssue {
                    kind: PolicyIssueKind::MissingEndpoint,
                    severity: PolicyIssueSeverity::Error,
                    primary_rule_id: rule.id.clone(),
                    primary_rule_name: rule.name.clone(),
                    related_rule_id: None,
                    related_rule_name: None,
                    message: format!(
                        "规则 '{}' 引用的出口代理节点 '{}' 不存在",
                        rule.name, target
                    ),
                    remediation: "检查并重新选择存在的代理节点".to_string(),
                });
            }
        }
    }

    // 2. Pairwise rule analysis (Duplicate, Shadowed, Overlapping)
    for (i, rule_a) in enabled_rules.iter().enumerate() {
        for rule_b in enabled_rules.iter().skip(i + 1) {
            // Check Duplicate
            if is_duplicate_rule(rule_a, rule_b) {
                issues.push(PolicyIssue {
                    kind: PolicyIssueKind::Duplicate,
                    severity: PolicyIssueSeverity::Warning,
                    primary_rule_id: rule_b.id.clone(),
                    primary_rule_name: rule_b.name.clone(),
                    related_rule_id: Some(rule_a.id.clone()),
                    related_rule_name: Some(rule_a.name.clone()),
                    message: format!(
                        "规则 '{}' 与前置规则 '{}' 的匹配条件和路由动作完全相同（冗余重复）",
                        rule_b.name, rule_a.name
                    ),
                    remediation: "删除冗余规则或合并标签".to_string(),
                });
                continue;
            }

            // Check Shadowed: Rule A shadows Rule B if A has higher/equal precedence and A strictly subsumes B
            if is_shadowing(rule_a, rule_b) {
                issues.push(PolicyIssue {
                    kind: PolicyIssueKind::Shadowed,
                    severity: PolicyIssueSeverity::Warning,
                    primary_rule_id: rule_b.id.clone(),
                    primary_rule_name: rule_b.name.clone(),
                    related_rule_id: Some(rule_a.id.clone()),
                    related_rule_name: Some(rule_a.name.clone()),
                    message: format!(
                        "规则 '{}' 被更高优先级的规则 '{}' 完全覆盖（永远不会命中）",
                        rule_b.name, rule_a.name
                    ),
                    remediation: format!(
                        "提高 '{}' 的优先级数值，或细化 '{}' 的匹配范围",
                        rule_b.name, rule_a.name
                    ),
                });
            } else if is_shadowing(rule_b, rule_a) && rule_b.priority > rule_a.priority {
                issues.push(PolicyIssue {
                    kind: PolicyIssueKind::Shadowed,
                    severity: PolicyIssueSeverity::Warning,
                    primary_rule_id: rule_a.id.clone(),
                    primary_rule_name: rule_a.name.clone(),
                    related_rule_id: Some(rule_b.id.clone()),
                    related_rule_name: Some(rule_b.name.clone()),
                    message: format!(
                        "规则 '{}' 被更高优先级的后置规则 '{}' 完全覆盖",
                        rule_a.name, rule_b.name
                    ),
                    remediation: format!(
                        "调整 '{}' 与 '{}' 的优先级关系",
                        rule_a.name, rule_b.name
                    ),
                });
            } else if has_matcher_overlap(rule_a, rule_b) {
                // Overlapping with different actions
                if rule_a.action != rule_b.action {
                    issues.push(PolicyIssue {
                        kind: PolicyIssueKind::Overlap,
                        severity: PolicyIssueSeverity::Info,
                        primary_rule_id: rule_a.id.clone(),
                        primary_rule_name: rule_a.name.clone(),
                        related_rule_id: Some(rule_b.id.clone()),
                        related_rule_name: Some(rule_b.name.clone()),
                        message: format!(
                            "规则 '{}' 与规则 '{}' 存在重叠的进程匹配条件，但路由目标不同",
                            rule_a.name, rule_b.name
                        ),
                        remediation: "通过优先级或明确的目标域名/端口区分两者".to_string(),
                    });
                }
            }
        }
    }

    let healthy = issues
        .iter()
        .all(|i| i.severity != PolicyIssueSeverity::Error);

    PolicyAnalysisReport {
        total_rules: rules.len(),
        active_rules: enabled_rules.len(),
        issues,
        healthy,
    }
}

pub fn analyze_config(config: &AppConfig) -> PolicyAnalysisReport {
    analyze_policies(&config.rules, &config.proxies)
}

fn is_duplicate_rule(a: &Rule, b: &Rule) -> bool {
    if a.action != b.action {
        return false;
    }
    if a.protocols != b.protocols {
        return false;
    }
    if a.destination != b.destination {
        return false;
    }

    let a_names = normalize_set(&a.matcher.app_names);
    let b_names = normalize_set(&b.matcher.app_names);
    if a_names != b_names {
        return false;
    }

    let a_paths = normalize_paths(&a.matcher.exe_paths);
    let b_paths = normalize_paths(&b.matcher.exe_paths);
    if a_paths != b_paths {
        return false;
    }

    let a_pids = a.matcher.pids.iter().copied().collect::<HashSet<_>>();
    let b_pids = b.matcher.pids.iter().copied().collect::<HashSet<_>>();
    if a_pids != b_pids {
        return false;
    }

    let a_wc = a
        .matcher
        .wildcard
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let b_wc = b
        .matcher
        .wildcard
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    a_wc == b_wc
}

/// Returns true if rule `a` precedes and completely covers rule `b`.
fn is_shadowing(a: &Rule, b: &Rule) -> bool {
    // A must have higher or equal priority
    if a.priority < b.priority {
        return false;
    }

    // A's protocols must subsume B's protocols (if A has protocols specified)
    if !a.protocols.is_empty() && !b.protocols.iter().all(|p| a.protocols.contains(p)) {
        return false;
    }

    // A's destinations must subsume B's destinations
    // If A has destination constraints, B must be equal or a subset
    if !a.destination.is_empty() {
        if b.destination.is_empty() {
            // A has constraints, but B matches everything -> A cannot subsume B
            return false;
        }
        // If A has domains, B must have domains and all must match A
        if !a.destination.domains.is_empty() {
            let a_domains = normalize_set(&a.destination.domains);
            let b_domains = normalize_set(&b.destination.domains);
            if !b_domains
                .iter()
                .all(|bd| domain_is_covered_by(bd, &a_domains))
            {
                return false;
            }
        }
        // If A has ports, all B ports must be in A
        if !a.destination.ports.is_empty()
            && !b
                .destination
                .ports
                .iter()
                .all(|bp| a.destination.ports.contains(bp))
        {
            return false;
        }
    }

    // A's process matchers must subsume B's process matchers
    // Case 1: A has wildcard "*" -> matches everything
    if let Some(ref wc) = a.matcher.wildcard {
        let wc = wc.trim();
        if wc == "*" || wc == "*.*" {
            return true;
        }
    }

    // Case 2: A has wildcard "*.exe" and B is an app_name ending in .exe
    if let Some(ref wc) = a.matcher.wildcard {
        let wc = wc.trim().to_ascii_lowercase();
        if wc == "*.exe" && b.matcher.wildcard.is_none() && b.matcher.pids.is_empty() {
            let b_names = normalize_set(&b.matcher.app_names);
            if !b_names.is_empty() && b_names.iter().all(|name| name.ends_with(".exe")) {
                return true;
            }
        }
    }

    // Case 3: A has exact same process name or exe path as B, but A has no destination constraints
    let a_names = normalize_set(&a.matcher.app_names);
    let b_names = normalize_set(&b.matcher.app_names);
    let a_paths = normalize_paths(&a.matcher.exe_paths);
    let b_paths = normalize_paths(&b.matcher.exe_paths);

    let name_subsumed = !b_names.is_empty() && b_names.is_subset(&a_names);
    let path_subsumed = !b_paths.is_empty() && b_paths.is_subset(&a_paths);

    if (name_subsumed || path_subsumed) && b.matcher.wildcard.is_none() && b.matcher.pids.is_empty()
    {
        return true;
    }

    false
}

fn has_matcher_overlap(a: &Rule, b: &Rule) -> bool {
    let a_names = normalize_set(&a.matcher.app_names);
    let b_names = normalize_set(&b.matcher.app_names);
    if !a_names.is_disjoint(&b_names) {
        return true;
    }

    let a_paths = normalize_paths(&a.matcher.exe_paths);
    let b_paths = normalize_paths(&b.matcher.exe_paths);
    if !a_paths.is_disjoint(&b_paths) {
        return true;
    }

    if let (Some(left), Some(right)) = (&a.matcher.wildcard, &b.matcher.wildcard) {
        let l = left.trim().to_ascii_lowercase();
        let r = right.trim().to_ascii_lowercase();
        if !l.is_empty() && !r.is_empty() && (l == r || l.contains(&r) || r.contains(&l)) {
            return true;
        }
    }

    false
}

fn domain_is_covered_by(domain: &str, candidates: &HashSet<String>) -> bool {
    let d = domain.trim().to_ascii_lowercase();
    if candidates.contains(&d) {
        return true;
    }
    for candidate in candidates {
        if let Some(suffix) = candidate.strip_prefix("*.") {
            if d == suffix || d.ends_with(&format!(".{suffix}")) {
                return true;
            }
        }
    }
    false
}

fn normalize_set(items: &[String]) -> HashSet<String> {
    items
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_paths(items: &[String]) -> HashSet<String> {
    items
        .iter()
        .map(|s| s.replace('\\', "/").trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}
