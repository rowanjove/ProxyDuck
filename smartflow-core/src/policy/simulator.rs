use serde::{Deserialize, Serialize};

use crate::model::{Protocol, ProxyProfile, RouteAction, Rule};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationInput {
    pub process_name: String,
    #[serde(default)]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub parent_process: Option<String>,
    #[serde(default = "default_sim_protocol")]
    pub protocol: Protocol,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub network_interface: Option<String>,
}

fn default_sim_protocol() -> Protocol {
    Protocol::Tcp
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationStatus {
    Matched,
    Rejected,
    Skipped,
    Shadowed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConditionCheck {
    pub field: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSimulationEvaluation {
    pub rule_id: String,
    pub rule_name: String,
    pub priority: i32,
    pub status: EvaluationStatus,
    pub checks: Vec<ConditionCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub miss_reason: Option<String>,
    pub action: RouteAction,
    pub action_target_id: String,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteTraceStep {
    pub title: String,
    pub detail: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteTrace {
    pub steps: Vec<RouteTraceStep>,
    pub final_action: RouteAction,
    pub final_target: String,
    pub is_fallback: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySimulationResponse {
    pub input: SimulationInput,
    pub evaluations: Vec<RuleSimulationEvaluation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_rule: Option<RuleSimulationEvaluation>,
    pub route_trace: RouteTrace,
    pub effective_action: RouteAction,
    pub effective_target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explain_miss: Option<String>,
}

/// Simulate policy evaluation for a given network traffic context.
pub fn simulate_policy(
    rules: &[Rule],
    proxies: &[ProxyProfile],
    input: &SimulationInput,
) -> PolicySimulationResponse {
    let mut sorted_rules = rules.to_vec();
    // Sort rules by priority descending, then by original index
    sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    let mut evaluations = Vec::new();
    let mut selected: Option<RuleSimulationEvaluation> = None;

    let proxy_names = proxies
        .iter()
        .map(|p| (p.id.as_str(), p.name.as_str()))
        .collect::<std::collections::HashMap<_, _>>();

    for rule in &sorted_rules {
        if !rule.enabled {
            evaluations.push(RuleSimulationEvaluation {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                status: EvaluationStatus::Skipped,
                checks: vec![],
                miss_reason: Some("规则已被手动停用".to_string()),
                action: rule.action.clone(),
                action_target_id: rule.action_target_id(),
                selected: false,
            });
            continue;
        }

        let mut checks = Vec::new();

        // 1. Process Check
        let (proc_passed, proc_expected, proc_actual, proc_detail) =
            check_process_match(rule, input);
        checks.push(ConditionCheck {
            field: "process".to_string(),
            expected: proc_expected,
            actual: proc_actual,
            passed: proc_passed,
            detail: proc_detail,
        });

        // 2. Protocol Check
        let (proto_passed, proto_expected, proto_actual, proto_detail) =
            check_protocol_match(rule, input);
        checks.push(ConditionCheck {
            field: "protocol".to_string(),
            expected: proto_expected,
            actual: proto_actual,
            passed: proto_passed,
            detail: proto_detail,
        });

        // 3. Destination Check
        let (dest_passed, dest_checks) = check_destination_match(rule, input);
        checks.extend(dest_checks);

        let all_passed = proc_passed && proto_passed && dest_passed;

        if all_passed {
            if let Some(winner) = &selected {
                evaluations.push(RuleSimulationEvaluation {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    priority: rule.priority,
                    status: EvaluationStatus::Shadowed,
                    checks,
                    miss_reason: Some(format!(
                        "条件全部符合，但优先级 (P{}) 低于已命中的规则 '{}' (P{})",
                        rule.priority, winner.rule_name, winner.priority
                    )),
                    action: rule.action.clone(),
                    action_target_id: rule.action_target_id(),
                    selected: false,
                });
            } else {
                let eval = RuleSimulationEvaluation {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    priority: rule.priority,
                    status: EvaluationStatus::Matched,
                    checks,
                    miss_reason: None,
                    action: rule.action.clone(),
                    action_target_id: rule.action_target_id(),
                    selected: true,
                };
                selected = Some(eval.clone());
                evaluations.push(eval);
            }
        } else {
            let failed_fields = checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.field.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            evaluations.push(RuleSimulationEvaluation {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                priority: rule.priority,
                status: EvaluationStatus::Rejected,
                checks,
                miss_reason: Some(format!("条件未完全匹配 (不匹配项: {failed_fields})")),
                action: rule.action.clone(),
                action_target_id: rule.action_target_id(),
                selected: false,
            });
        }
    }

    // Build RouteTrace
    let mut steps = Vec::new();
    steps.push(RouteTraceStep {
        title: "流量上下文输入".to_string(),
        detail: format!(
            "进程: {} (PID: {}) | 协议: {:?} | 目标: {}:{}",
            input.process_name,
            input
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            input.protocol,
            input
                .domain
                .as_deref()
                .or(input.ip.as_deref())
                .unwrap_or("*"),
            input
                .port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "*".to_string())
        ),
        status: "info".to_string(),
    });

    let (final_action, final_target, is_fallback, trace_summary, explain_miss) = match &selected {
        Some(winner) => {
            let target_display = match &winner.action {
                RouteAction::Proxy { proxy_id } => proxy_names
                    .get(proxy_id.as_str())
                    .copied()
                    .unwrap_or(proxy_id.as_str()),
                RouteAction::Direct => "DIRECT (直连)",
                RouteAction::Block => "BLOCK (拦截)",
                RouteAction::Reject => "REJECT (拒绝)",
            };

            steps.push(RouteTraceStep {
                title: format!("命中最高优先级规则: {}", winner.rule_name),
                detail: format!(
                    "优先级: P{} | 目标动作: {}",
                    winner.priority, target_display
                ),
                status: "match".to_string(),
            });

            steps.push(RouteTraceStep {
                title: "路由决策确定".to_string(),
                detail: format!("出口分配 -> {target_display}"),
                status: "match".to_string(),
            });

            (
                winner.action.clone(),
                winner.action_target_id.clone(),
                false,
                format!("匹配规则 '{}' -> 出口 {}", winner.rule_name, target_display),
                None,
            )
        }
        None => {
            steps.push(RouteTraceStep {
                title: "未命中任何已启用规则".to_string(),
                detail: format!("已评估 {} 条规则，均不满足条件", evaluations.len()),
                status: "warning".to_string(),
            });

            steps.push(RouteTraceStep {
                title: "触发全局 Fallback 兜底".to_string(),
                detail: "默认采用 DIRECT 直连出口".to_string(),
                status: "fallback".to_string(),
            });

            let miss_reasons = evaluations
                .iter()
                .filter(|e| e.status == EvaluationStatus::Rejected)
                .take(3)
                .map(|e| {
                    format!(
                        "- 规则 '{}': {}",
                        e.rule_name,
                        e.miss_reason.as_deref().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");

            let diagnosis = if miss_reasons.is_empty() {
                "当前没有启用的路由规则。".to_string()
            } else {
                format!("所有候选规则均未命中，前列原因如下:\n{miss_reasons}")
            };

            (
                RouteAction::Direct,
                "direct".to_string(),
                true,
                "无规则命中 -> 全局兜底 DIRECT (直连)".to_string(),
                Some(diagnosis),
            )
        }
    };

    let route_trace = RouteTrace {
        steps,
        final_action: final_action.clone(),
        final_target: final_target.clone(),
        is_fallback,
        summary: trace_summary,
    };

    PolicySimulationResponse {
        input: input.clone(),
        evaluations,
        selected_rule: selected,
        route_trace,
        effective_action: final_action,
        effective_target: final_target,
        explain_miss,
    }
}

fn check_process_match(
    rule: &Rule,
    input: &SimulationInput,
) -> (bool, String, String, Option<String>) {
    let proc_lower = input.process_name.trim().to_ascii_lowercase();
    let exe_lower = input
        .exe_path
        .as_deref()
        .map(|p| p.replace('\\', "/").trim().to_ascii_lowercase());

    // 1. PID match
    if !rule.matcher.pids.is_empty() {
        if let Some(pid) = input.pid {
            if rule.matcher.pids.contains(&pid) {
                return (
                    true,
                    format!("PID in {:?}", rule.matcher.pids),
                    format!("PID {pid}"),
                    Some("PID 精确匹配".to_string()),
                );
            }
        }
    }

    // 2. Exe path match
    if !rule.matcher.exe_paths.is_empty() {
        if let Some(ref actual_exe) = exe_lower {
            for expected in &rule.matcher.exe_paths {
                let exp_norm = expected.replace('\\', "/").trim().to_ascii_lowercase();
                if actual_exe == &exp_norm {
                    return (
                        true,
                        expected.clone(),
                        input.exe_path.clone().unwrap_or_default(),
                        Some("可执行路径完全匹配".to_string()),
                    );
                }
            }
        }
    }

    // 3. App name match
    if !rule.matcher.app_names.is_empty() {
        for expected in &rule.matcher.app_names {
            if proc_lower == expected.trim().to_ascii_lowercase() {
                return (
                    true,
                    expected.clone(),
                    input.process_name.clone(),
                    Some("进程名匹配".to_string()),
                );
            }
        }
    }

    // 4. Wildcard match
    if let Some(ref wc) = rule.matcher.wildcard {
        let wc_clean = wc.trim().to_ascii_lowercase();
        if glob_match(&wc_clean, &proc_lower)
            || exe_lower
                .as_ref()
                .is_some_and(|exe| glob_match(&wc_clean, exe))
        {
            return (
                true,
                wc.clone(),
                input.process_name.clone(),
                Some("通配符模式匹配".to_string()),
            );
        }
    }

    // 5. Child process inheritance check
    if rule.auto_bind_children {
        if let Some(ref parent) = input.parent_process {
            let parent_lower = parent.trim().to_ascii_lowercase();
            let parent_matches = rule
                .matcher
                .app_names
                .iter()
                .any(|name| name.trim().to_ascii_lowercase() == parent_lower);
            if parent_matches {
                return (
                    true,
                    format!("父进程包含于 {:?}", rule.matcher.app_names),
                    format!("父进程: {parent}"),
                    Some(format!("继承自父进程 '{parent}'")),
                );
            }
        }
    }

    let expected = if !rule.matcher.app_names.is_empty() {
        rule.matcher.app_names.join(", ")
    } else if !rule.matcher.exe_paths.is_empty() {
        rule.matcher.exe_paths.join(", ")
    } else if let Some(ref wc) = rule.matcher.wildcard {
        wc.clone()
    } else {
        "(空匹配器)".to_string()
    };

    (
        false,
        expected,
        input.process_name.clone(),
        Some(format!(
            "进程名 '{}' 未在规则进程列表中",
            input.process_name
        )),
    )
}

fn check_protocol_match(
    rule: &Rule,
    input: &SimulationInput,
) -> (bool, String, String, Option<String>) {
    if rule.protocols.is_empty() {
        return (
            true,
            "ANY".to_string(),
            format!("{:?}", input.protocol),
            None,
        );
    }

    let passed = rule.protocols.contains(&input.protocol);
    let expected = rule
        .protocols
        .iter()
        .map(|p| format!("{p:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let actual = format!("{:?}", input.protocol);

    (
        passed,
        expected,
        actual,
        if !passed {
            Some(format!("协议 {:?} 不在规则支持协议中", input.protocol))
        } else {
            None
        },
    )
}

fn check_destination_match(rule: &Rule, input: &SimulationInput) -> (bool, Vec<ConditionCheck>) {
    let mut checks = Vec::new();
    let mut all_passed = true;

    // Domain check
    if !rule.destination.domains.is_empty() {
        let expected = rule.destination.domains.join(", ");
        let actual = input
            .domain
            .clone()
            .unwrap_or_else(|| "(未提供域名)".to_string());
        let passed = if let Some(ref actual_domain) = input.domain {
            let d = actual_domain.trim().to_ascii_lowercase();
            rule.destination.domains.iter().any(|candidate| {
                let c = candidate.trim().to_ascii_lowercase();
                if let Some(suffix) = c.strip_prefix("*.") {
                    d == suffix || d.ends_with(&format!(".{suffix}"))
                } else {
                    d == c
                }
            })
        } else {
            false
        };

        if !passed {
            all_passed = false;
        }

        checks.push(ConditionCheck {
            field: "domain".to_string(),
            expected,
            actual,
            passed,
            detail: if !passed {
                Some("域名未命中规则所限制的域名列表".to_string())
            } else {
                None
            },
        });
    }

    // IP CIDR check
    if !rule.destination.ip_cidrs.is_empty() {
        let expected = rule.destination.ip_cidrs.join(", ");
        let actual = input.ip.clone().unwrap_or_else(|| "(未提供IP)".to_string());
        let passed = if let Some(ref actual_ip) = input.ip {
            rule.destination
                .ip_cidrs
                .iter()
                .any(|cidr| ip_matches_cidr(actual_ip, cidr))
        } else {
            false
        };

        if !passed {
            all_passed = false;
        }

        checks.push(ConditionCheck {
            field: "ip".to_string(),
            expected,
            actual,
            passed,
            detail: if !passed {
                Some("目标 IP 不在规则 CIDR 范围内".to_string())
            } else {
                None
            },
        });
    }

    // Port check
    if !rule.destination.ports.is_empty() {
        let expected = rule
            .destination
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let actual = input
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "(未提供端口)".to_string());
        let passed = input
            .port
            .is_some_and(|p| rule.destination.ports.contains(&p));

        if !passed {
            all_passed = false;
        }

        checks.push(ConditionCheck {
            field: "port".to_string(),
            expected,
            actual,
            passed,
            detail: if !passed {
                Some("目标端口不在规则允许的端口列表中".to_string())
            } else {
                None
            },
        });
    }

    (all_passed, checks)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" || pattern == "*.*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }
    pattern == text
}

fn ip_matches_cidr(ip_text: &str, cidr_text: &str) -> bool {
    let Ok(ip) = ip_text.trim().parse::<std::net::IpAddr>() else {
        return false;
    };
    let cidr = cidr_text.trim();
    let (network_text, prefix) = cidr
        .split_once('/')
        .map(|(network, prefix)| (network.trim(), prefix.trim().parse::<u8>().ok()))
        .unwrap_or((cidr, None));
    let Ok(network) = network_text.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (ip, network) {
        (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(network)) => {
            let prefix = prefix.unwrap_or(32).min(32);
            let mask = if prefix == 0 {
                0
            } else {
                !((1u32 << (32 - prefix)) - 1)
            };
            (u32::from(ip) & mask) == (u32::from(network) & mask)
        }
        (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(network)) => {
            let prefix = prefix.unwrap_or(128).min(128);
            let mask = if prefix == 0 {
                0
            } else {
                !((1u128 << (128 - prefix)) - 1)
            };
            (u128::from(ip) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}
