pub mod discovery;
pub mod group;

pub use discovery::{DiscoveredEndpoint, EndpointDiscoverer};
pub use group::{CircuitBreaker, CircuitState, EndpointGroup, FailMode, GroupStrategy};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProxyKind, ProxyProfile};

    #[test]
    fn test_endpoint_group_primary_backup_failover() {
        let p1 = ProxyProfile {
            id: "p1".to_string(),
            name: "Primary".to_string(),
            kind: ProxyKind::Socks5,
            endpoint: "127.0.0.1:1080".to_string(),
            username: None,
            password_ref: None,
            password: None,
            enabled: true,
        };
        let p2 = ProxyProfile {
            id: "p2".to_string(),
            name: "Backup".to_string(),
            kind: ProxyKind::Socks5,
            endpoint: "127.0.0.1:1081".to_string(),
            username: None,
            password_ref: None,
            password: None,
            enabled: true,
        };

        let group = EndpointGroup {
            id: "g1".to_string(),
            name: "Default Group".to_string(),
            strategy: GroupStrategy::PrimaryBackup,
            endpoints: vec!["p1".to_string(), "p2".to_string()],
            fail_mode: FailMode::FailOpen,
        };

        let proxies = vec![p1.clone(), p2.clone()];
        let latency_map = std::collections::HashMap::new();
        let mut failed = std::collections::HashMap::new();

        // 1. Initially p1 is selected
        let selected = group
            .select_endpoint(&proxies, &latency_map, &failed, 0)
            .unwrap();
        assert_eq!(selected.id, "p1");

        // 2. When p1 fails, automatically failover to p2
        failed.insert("p1".to_string(), true);
        let selected = group
            .select_endpoint(&proxies, &latency_map, &failed, 0)
            .unwrap();
        assert_eq!(selected.id, "p2");

        // 3. When both fail, returns fail_mode
        failed.insert("p2".to_string(), true);
        let err = group
            .select_endpoint(&proxies, &latency_map, &failed, 0)
            .unwrap_err();
        assert_eq!(err, FailMode::FailOpen);
    }

    #[test]
    fn test_circuit_breaker_transitions() {
        let mut cb = CircuitBreaker::new("p1");
        assert!(cb.can_attempt());
        assert_eq!(cb.state, CircuitState::Closed);

        // Record 4 failures: still closed
        for _ in 0..4 {
            cb.record_failure();
        }
        assert_eq!(cb.state, CircuitState::Closed);
        assert!(cb.can_attempt());

        // 5th failure trips the circuit
        cb.record_failure();
        assert!(matches!(cb.state, CircuitState::Open { .. }));
        assert!(!cb.can_attempt());

        // Force expiration of cooldown
        cb.state = CircuitState::Open {
            tripped_at: chrono::Utc::now() - chrono::Duration::seconds(60),
            cool_down_until: chrono::Utc::now() - chrono::Duration::seconds(10),
        };

        // Attempting now transitions to HalfOpen
        assert!(cb.can_attempt());
        assert!(matches!(cb.state, CircuitState::HalfOpen { .. }));

        // Two successful trials recover to Closed
        cb.record_success();
        assert!(matches!(cb.state, CircuitState::HalfOpen { .. }));
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
    }
}
