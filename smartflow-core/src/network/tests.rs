use crate::network::{
    adapter::AdapterCollector, hosts::HostsCollector, model::*, route::RouteCollector,
    winsock::WinsockCollector,
};

#[test]
fn test_adapter_apipa_detection() {
    let sample_json = r#"[
            {
                "Alias": "Ethernet",
                "Description": "Intel(R) Ethernet Connection",
                "Status": "Up",
                "IPv4": ["169.254.120.45"],
                "IPv6": [],
                "Gateway": null,
                "DNS": []
            }
        ]"#;

    let status = AdapterCollector::parse_ps_json(sample_json).expect("should parse");
    assert!(status.apipa_found, "APIPA address should be flagged");
    assert_eq!(status.active_adapters.len(), 1);
    assert!(status.active_adapters[0].apipa_detected);
}

#[test]
fn test_adapter_normal_detection() {
    let sample_json = r#"[
            {
                "Alias": "Wi-Fi",
                "Description": "Wi-Fi 6 Adapter",
                "Status": "Up",
                "IPv4": ["192.168.1.100"],
                "IPv6": ["fe80::1"],
                "Gateway": "192.168.1.1",
                "DNS": ["192.168.1.1", "223.5.5.5"]
            }
        ]"#;

    let status = AdapterCollector::parse_ps_json(sample_json).expect("should parse");
    assert!(!status.apipa_found);
    assert_eq!(status.active_adapters.len(), 1);
    assert_eq!(
        status.active_adapters[0].gateway.as_deref(),
        Some("192.168.1.1")
    );
    assert_eq!(status.active_adapters[0].dns_servers.len(), 2);
}

#[test]
fn test_route_collector_parsing() {
    let sample_json = r#"[
            {
                "Destination": "0.0.0.0/0",
                "NextHop": "192.168.1.1",
                "InterfaceAlias": "Wi-Fi",
                "RouteMetric": 25
            },
            {
                "Destination": "0.0.0.0/0",
                "NextHop": "192.168.2.1",
                "InterfaceAlias": "Ethernet",
                "RouteMetric": 35
            }
        ]"#;

    let status = RouteCollector::parse_ps_json(sample_json).expect("should parse");
    assert!(status.has_default_route);
    assert_eq!(status.default_ipv4_gateway.as_deref(), Some("192.168.1.1"));
    assert_eq!(status.rival_routes_count, 1);
}

#[test]
fn test_hosts_parser() {
    let sample_hosts = r#"
        # Sample hosts file
        127.0.0.1 localhost
        ::1 localhost

        # Custom blocks
        0.0.0.0 telemetry.example.com
        127.0.0.1 adservice.google.com
        1.2.3.4 internal.corp
        "#;

    let status = HostsCollector::parse_hosts_content(sample_hosts);
    assert_eq!(status.custom_records_count, 3);
    assert_eq!(status.loopback_redirects_count, 2);
    assert!(status
        .custom_domains
        .contains(&"telemetry.example.com".to_string()));
    assert!(status
        .custom_domains
        .contains(&"adservice.google.com".to_string()));
    assert!(status.custom_domains.contains(&"internal.corp".to_string()));
}

#[test]
fn test_winsock_catalog_parser() {
    let catalog_text = r#"
        Winsock Catalog Provider Entry
        --------------------------------------------------
        Entry type:                             Base Service Provider
        Description :                           MSAFD Tcpip [TCP/IP]
        
        Winsock Catalog Provider Entry
        --------------------------------------------------
        Entry type:                             Base Service Provider
        Description :                           MSAFD Tcpip [UDP/IP]
        "#;

    let status = WinsockCollector::parse_winsock_catalog(catalog_text);
    assert_eq!(status.catalog_entries_count, 2);
    assert!(status
        .lsp_providers_detected
        .contains(&"MSAFD Tcpip [TCP/IP]".to_string()));
}

#[test]
fn test_issue_correlation_proxy_dead_port() {
    let mut diagnosis = NetworkDiagnosis::default();
    diagnosis.proxy.wininet_enabled = true;
    diagnosis.proxy.wininet_server = Some("127.0.0.1:7897".to_string());
    diagnosis.proxy.proxy_port_reachable = Some(false);
    diagnosis.internet.ip_level_connected = true;

    let mut issues = Vec::new();
    if diagnosis.proxy.wininet_enabled && diagnosis.proxy.proxy_port_reachable == Some(false) {
        issues.push(NetworkIssue {
            id: "proxy_dead_port".to_string(),
            layer: "Layer 7: 系统代理".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: "系统代理指向不可访问的本地端口".to_string(),
            explanation: "代理端口未监听".to_string(),
            evidence: vec!["127.0.0.1:7897".to_string()],
            suggested_actions: vec!["关闭系统代理开关".to_string()],
        });
    }

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].id, "proxy_dead_port");
    assert_eq!(issues[0].severity, Severity::Critical);
    assert_eq!(issues[0].confidence, Confidence::High);
}

#[test]
fn test_repair_planner_proxy_dead_port() {
    use crate::network::repair::{RepairLevel, RepairPlanner};

    let mut diagnosis = NetworkDiagnosis {
        status: OverallStatus::Critical,
        ..Default::default()
    };
    diagnosis.issues.push(NetworkIssue {
        id: "proxy_dead_port".to_string(),
        layer: "Layer 7: 系统代理".to_string(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        title: "系统代理指向不可访问的本地端口".to_string(),
        explanation: "代理端口未监听".to_string(),
        evidence: vec!["127.0.0.1:7897".to_string()],
        suggested_actions: vec!["重置系统代理至直连模式".to_string()],
    });

    let plan = RepairPlanner::build_plan(&diagnosis);
    assert_eq!(plan.target_issues_count, 1);
    assert!(plan
        .recommended_actions
        .iter()
        .any(|a| a.id == "reset_system_proxy"));
    assert!(plan
        .recommended_actions
        .iter()
        .any(|a| a.id == "reset_winhttp"));

    let reset_proxy_action = plan
        .recommended_actions
        .iter()
        .find(|a| a.id == "reset_system_proxy")
        .unwrap();
    assert_eq!(reset_proxy_action.level, RepairLevel::Level1Safe);
    assert!(!reset_proxy_action.requires_admin);
    assert!(reset_proxy_action.reversible);
}

#[test]
fn test_repair_planner_dhcp_apipa() {
    use crate::network::repair::{RepairLevel, RepairPlanner};

    let mut diagnosis = NetworkDiagnosis {
        status: OverallStatus::Critical,
        ..Default::default()
    };
    diagnosis.issues.push(NetworkIssue {
        id: "dhcp_apipa_failure".to_string(),
        layer: "Layer 1: 网络接口 (DHCP)".to_string(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        title: "DHCP 获取 IP 地址失败".to_string(),
        explanation: "APIPA".to_string(),
        evidence: vec!["169.254.x.x".to_string()],
        suggested_actions: vec!["Renew DHCP".to_string()],
    });

    let plan = RepairPlanner::build_plan(&diagnosis);
    assert!(plan
        .recommended_actions
        .iter()
        .any(|a| a.id == "renew_dhcp"));
    assert!(plan
        .recommended_actions
        .iter()
        .any(|a| a.id == "restart_adapter"));

    let restart_action = plan
        .recommended_actions
        .iter()
        .find(|a| a.id == "restart_adapter")
        .unwrap();
    assert_eq!(restart_action.level, RepairLevel::Level2Privileged);
    assert!(restart_action.requires_admin);
}

#[test]
fn test_snapshot_manifest_serialization() {
    use crate::network::snapshot::{SnapshotManifest, WininetSnapshotData};

    let manifest = SnapshotManifest {
        id: "snap_20260913_203000".to_string(),
        created_at: "2026-09-13T20:30:00Z".to_string(),
        reason: "Auto-snapshot before repair".to_string(),
        items: vec!["wininet".to_string(), "hosts".to_string()],
        fully_reversible: true,
    };

    let json = serde_json::to_string(&manifest).expect("serialize");
    let deserialized: SnapshotManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.id, "snap_20260913_203000");
    assert_eq!(deserialized.items.len(), 2);

    let wininet = WininetSnapshotData {
        enabled: true,
        server: Some("127.0.0.1:7890".to_string()),
        override_str: Some("<-loopback>".to_string()),
        auto_config_url: None,
    };
    let wininet_json = serde_json::to_string(&wininet).expect("serialize wininet");
    let deserialized_wininet: WininetSnapshotData =
        serde_json::from_str(&wininet_json).expect("deserialize wininet");
    assert!(deserialized_wininet.enabled);
    assert_eq!(
        deserialized_wininet.server.as_deref(),
        Some("127.0.0.1:7890")
    );
}

#[test]
fn test_rollback_rejects_malicious_snapshot_id() {
    use crate::network::SnapshotManager;

    assert!(SnapshotManager::rollback("../../../etc/passwd").is_err());
    assert!(SnapshotManager::rollback("..\\..\\windows").is_err());
    assert!(SnapshotManager::rollback("").is_err());
    assert!(SnapshotManager::rollback("snap/with/slashes").is_err());
}
