pub mod analysis;
pub mod simulator;

pub use analysis::{
    analyze_config, analyze_policies, PolicyAnalysisReport, PolicyIssue, PolicyIssueKind,
    PolicyIssueSeverity,
};
pub use simulator::{
    simulate_policy, ConditionCheck, EvaluationStatus, PolicySimulationResponse, RouteTrace,
    RouteTraceStep, RuleSimulationEvaluation, SimulationInput,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DestinationMatch, MatchCriteria, Protocol, ProxyProfile, Rule};

    #[test]
    fn test_simulator_matched_and_shadowed() {
        let proxies = vec![ProxyProfile::local_socks_default()];
        let mut high_rule = Rule::new(
            "Browser Rule".to_string(),
            MatchCriteria {
                app_names: vec!["chrome.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        high_rule.priority = 200;

        let mut low_rule = Rule::new(
            "General Web Rule".to_string(),
            MatchCriteria {
                wildcard: Some("*.exe".to_string()),
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        low_rule.priority = 50;

        let input = SimulationInput {
            process_name: "chrome.exe".to_string(),
            exe_path: Some("C:\\Program Files\\Google\\Chrome\\chrome.exe".to_string()),
            pid: Some(1234),
            parent_process: None,
            protocol: Protocol::Tcp,
            domain: Some("github.com".to_string()),
            ip: None,
            port: Some(443),
            network_interface: None,
        };

        let res = simulate_policy(&[high_rule.clone(), low_rule.clone()], &proxies, &input);
        assert!(res.selected_rule.is_some());
        let selected = res.selected_rule.unwrap();
        assert_eq!(selected.rule_id, high_rule.id);
        assert_eq!(selected.priority, 200);

        // Check low_rule evaluation status
        let low_eval = res
            .evaluations
            .iter()
            .find(|e| e.rule_id == low_rule.id)
            .unwrap();
        assert_eq!(low_eval.status, EvaluationStatus::Shadowed);
        assert!(!res.route_trace.steps.is_empty());
    }

    #[test]
    fn test_analysis_detects_dead_and_shadowed_rules() {
        let proxies = vec![ProxyProfile::local_socks_default()];
        let dead_rule = Rule::new(
            "Empty Dead Rule".to_string(),
            MatchCriteria::default(),
            "local-socks".to_string(),
        );

        let mut wild_rule = Rule::new(
            "Catch All".to_string(),
            MatchCriteria {
                wildcard: Some("*".to_string()),
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        wild_rule.priority = 100;

        let mut app_rule = Rule::new(
            "Specific App".to_string(),
            MatchCriteria {
                app_names: vec!["app.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        app_rule.priority = 50;

        let report = analyze_policies(&[dead_rule, wild_rule, app_rule], &proxies);
        assert!(!report.healthy);

        let has_dead = report
            .issues
            .iter()
            .any(|i| i.kind == PolicyIssueKind::DeadRule);
        let has_shadowed = report
            .issues
            .iter()
            .any(|i| i.kind == PolicyIssueKind::Shadowed);

        assert!(has_dead, "Should detect empty matcher as dead rule");
        assert!(
            has_shadowed,
            "Catch all with higher priority should shadow specific app with lower priority"
        );
    }

    #[test]
    fn test_simulator_explain_miss_on_port_mismatch() {
        let proxies = vec![ProxyProfile::local_socks_default()];
        let mut rule = Rule::new(
            "HTTPS Only".to_string(),
            MatchCriteria {
                app_names: vec!["curl.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        rule.destination = DestinationMatch {
            domains: vec![],
            ip_cidrs: vec![],
            ports: vec![443],
        };

        let input = SimulationInput {
            process_name: "curl.exe".to_string(),
            exe_path: None,
            pid: None,
            parent_process: None,
            protocol: Protocol::Tcp,
            domain: Some("example.com".to_string()),
            ip: None,
            port: Some(80), // HTTP port 80 != 443
            network_interface: None,
        };

        let res = simulate_policy(&[rule], &proxies, &input);
        assert!(res.selected_rule.is_none());
        assert!(res.route_trace.is_fallback);
        assert!(res.explain_miss.is_some());
    }
}
