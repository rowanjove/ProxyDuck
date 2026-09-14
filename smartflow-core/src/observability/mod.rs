pub mod collector;
pub mod model;

pub use collector::{ConnectionCollector, RawConnectionEntry};
pub use model::{
    ConnectionFilter, ConnectionRecord, ConnectionStatus, ProcessTrafficSummary, TrafficSummary,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;

    #[test]
    fn test_parse_netstat_tcp_lines() {
        let sample = r#"
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:7897         0.0.0.0:0              LISTENING       560
  TCP    192.168.2.233:50376    4.145.79.80:443        ESTABLISHED     5952
  TCP    127.0.0.1:52291        127.0.0.1:7897         CLOSE_WAIT      3704
"#;

        let entries = ConnectionCollector::parse_netstat_tcp(sample);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].protocol, Protocol::Tcp);
        assert_eq!(entries[0].local_ip, "127.0.0.1");
        assert_eq!(entries[0].local_port, 7897);
        assert_eq!(entries[0].status, ConnectionStatus::Listening);
        assert_eq!(entries[0].pid, 560);

        assert_eq!(entries[1].remote_ip, "4.145.79.80");
        assert_eq!(entries[1].remote_port, 443);
        assert_eq!(entries[1].status, ConnectionStatus::Established);
        assert_eq!(entries[1].pid, 5952);
    }

    #[test]
    fn test_parse_netstat_udp_lines() {
        let sample = r#"
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  UDP    0.0.0.0:5353           *:*                                    1234
  UDP    127.0.0.1:5355         *:*                                    5678
"#;

        let entries = ConnectionCollector::parse_netstat_udp(sample);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol, Protocol::Udp);
        assert_eq!(entries[0].local_port, 5353);
        assert_eq!(entries[0].pid, 1234);
    }

    #[test]
    fn test_traffic_summarize() {
        let records = vec![
            ConnectionRecord {
                id: "1".to_string(),
                pid: 100,
                process_name: "chrome.exe".to_string(),
                exe_path: None,
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1".to_string(),
                local_port: 50000,
                remote_addr: "1.1.1.1".to_string(),
                remote_port: 443,
                domain: None,
                status: ConnectionStatus::Established,
                rule_id: None,
                rule_name: None,
                route_action: crate::model::RouteAction::Direct,
                action_target: "direct".to_string(),
                timestamp: chrono::Utc::now(),
            },
            ConnectionRecord {
                id: "2".to_string(),
                pid: 100,
                process_name: "chrome.exe".to_string(),
                exe_path: None,
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1".to_string(),
                local_port: 50001,
                remote_addr: "8.8.8.8".to_string(),
                remote_port: 443,
                domain: None,
                status: ConnectionStatus::Established,
                rule_id: None,
                rule_name: None,
                route_action: crate::model::RouteAction::Proxy {
                    proxy_id: "local-socks".to_string(),
                },
                action_target: "local-socks".to_string(),
                timestamp: chrono::Utc::now(),
            },
            ConnectionRecord {
                id: "3".to_string(),
                pid: 200,
                process_name: "code.exe".to_string(),
                exe_path: None,
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1".to_string(),
                local_port: 50002,
                remote_addr: "0.0.0.0".to_string(),
                remote_port: 0,
                domain: None,
                status: ConnectionStatus::Listening,
                rule_id: None,
                rule_name: None,
                route_action: crate::model::RouteAction::Direct,
                action_target: "direct".to_string(),
                timestamp: chrono::Utc::now(),
            },
        ];

        let summary = ConnectionCollector::summarize(&records);
        assert_eq!(summary.total_connections, 3);
        assert_eq!(summary.established_connections, 2);
        assert_eq!(summary.listening_ports, 1);
        assert_eq!(summary.top_processes[0].process_name, "chrome.exe");
        assert_eq!(summary.top_processes[0].total_connections, 2);
        assert_eq!(summary.route_distribution.get("direct"), Some(&2));
        assert_eq!(summary.route_distribution.get("local-socks"), Some(&1));
    }
}
