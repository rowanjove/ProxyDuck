use std::time::Duration;

use chrono::Utc;
use tokio::{task::JoinSet, time};

use crate::{
    model::{ProxyHealth, ProxyHealthState, ProxyKind, ProxyProfile, ProxyTestResult},
    proxy_test::test_proxy,
    state::CoreState,
};

const HEALTH_INTERVAL: Duration = Duration::from_secs(15);
const MAX_LATENCY_SAMPLES: usize = 30;

/// Runs lightweight per-proxy protocol probes in the background. The probe
/// implementation is blocking, so every profile is isolated in a blocking
/// task and cannot stall the Core HTTP or process watcher loops.
pub fn start_health_supervisor(state: CoreState) {
    tokio::spawn(async move {
        let mut ticker = time::interval(HEALTH_INTERVAL);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            probe_enabled_profiles(&state).await;
        }
    });
}

async fn probe_enabled_profiles(state: &CoreState) {
    let profiles = state
        .config_snapshot()
        .proxies
        .into_iter()
        // A Direct profile has no endpoint or proxy protocol to probe.  Do
        // not manufacture a successful SOCKS result for it; the route
        // compiler already treats direct actions as outside proxy health.
        .filter(|profile| profile.enabled && !matches!(profile.kind, ProxyKind::Direct))
        .collect::<Vec<_>>();

    let active_ids = profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<std::collections::HashSet<_>>();
    state
        .proxy_health
        .write()
        .retain(|proxy_id, _| active_ids.contains(proxy_id));

    let mut tasks = JoinSet::new();
    for profile in profiles {
        mark_checking(state, &profile);
        tasks.spawn(async move {
            let proxy_id = profile.id.clone();
            let result = tokio::task::spawn_blocking(move || test_proxy(&profile)).await;
            (proxy_id, result)
        });
    }

    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((proxy_id, Ok(result))) => record_probe(state, &proxy_id, result),
            Ok((proxy_id, Err(error))) => record_probe_failure(state, &proxy_id, error.to_string()),
            Err(error) => tracing::warn!(%error, "proxy health probe task failed"),
        }
    }
}

fn mark_checking(state: &CoreState, profile: &ProxyProfile) {
    let mut health = state.proxy_health.write();
    let entry = health
        .entry(profile.id.clone())
        .or_insert_with(|| ProxyHealth::unknown(profile.id.clone()));
    if matches!(entry.state, ProxyHealthState::Unknown) {
        entry.state = ProxyHealthState::Checking;
    }
    entry.last_error = None;
}

fn record_probe(state: &CoreState, proxy_id: &str, result: ProxyTestResult) {
    let mut health = state.proxy_health.write();
    let entry = health
        .entry(proxy_id.to_string())
        .or_insert_with(|| ProxyHealth::unknown(proxy_id));
    let probe_error = result.error.clone().or_else(|| {
        result
            .tcp_error
            .clone()
            .or_else(|| result.udp_error.clone())
    });
    let successful = result.reachable && result.protocol_accepted;
    let partial =
        successful && (result.tcp_supported == Some(false) || result.udp_supported == Some(false));

    let candidate_state = if !result.reachable {
        classify_failure(result.error.as_deref().unwrap_or("proxy is offline"))
    } else if !result.protocol_accepted {
        ProxyHealthState::ProtocolError
    } else if partial {
        ProxyHealthState::Degraded
    } else {
        ProxyHealthState::Healthy
    };
    let previous_state = entry.state;
    entry.reachable = Some(result.reachable);
    entry.protocol_accepted = Some(result.protocol_accepted);
    entry.tcp_supported = result.tcp_supported;
    entry.udp_supported = result.udp_supported;
    entry.latency_ms = Some(result.latency_ms);
    entry.latency_history_ms.push(result.latency_ms);
    if entry.latency_history_ms.len() > MAX_LATENCY_SAMPLES {
        let excess = entry.latency_history_ms.len() - MAX_LATENCY_SAMPLES;
        entry.latency_history_ms.drain(0..excess);
    }
    entry.last_error = probe_error;
    entry.last_checked_at = Some(Utc::now());
    if successful {
        entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
        entry.consecutive_failures = 0;
    } else {
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.consecutive_successes = 0;
    }
    entry.state = stabilized_state(
        previous_state,
        candidate_state,
        entry.consecutive_successes,
        entry.consecutive_failures,
    );
}

fn record_probe_failure(state: &CoreState, proxy_id: &str, error: String) {
    let mut health = state.proxy_health.write();
    let entry = health
        .entry(proxy_id.to_string())
        .or_insert_with(|| ProxyHealth::unknown(proxy_id));
    let candidate_state = classify_failure(&error);
    entry.reachable = Some(false);
    entry.protocol_accepted = Some(false);
    entry.last_error = Some(error);
    entry.last_checked_at = Some(Utc::now());
    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    entry.consecutive_successes = 0;
    entry.state = stabilized_state(
        entry.state,
        candidate_state,
        entry.consecutive_successes,
        entry.consecutive_failures,
    );
}

fn stabilized_state(
    previous: ProxyHealthState,
    candidate: ProxyHealthState,
    consecutive_successes: u32,
    consecutive_failures: u32,
) -> ProxyHealthState {
    if matches!(candidate, ProxyHealthState::Healthy)
        && matches!(
            previous,
            ProxyHealthState::Offline | ProxyHealthState::AuthFailed
        )
        && consecutive_successes < 2
    {
        return ProxyHealthState::Degraded;
    }
    if matches!(
        candidate,
        ProxyHealthState::Offline | ProxyHealthState::AuthFailed
    ) && matches!(previous, ProxyHealthState::Healthy)
        && consecutive_failures < 2
    {
        return ProxyHealthState::Degraded;
    }
    candidate
}

fn classify_failure(error: &str) -> ProxyHealthState {
    let lower = error.to_ascii_lowercase();
    if lower.contains("authentication") || lower.contains("auth") {
        ProxyHealthState::AuthFailed
    } else if lower.contains("socks") || lower.contains("protocol") {
        ProxyHealthState::ProtocolError
    } else {
        ProxyHealthState::Offline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_probe_failures_without_hiding_auth_errors() {
        assert_eq!(
            classify_failure("SOCKS5 username/password authentication failed"),
            ProxyHealthState::AuthFailed
        );
        assert_eq!(
            classify_failure("SOCKS5 command rejected"),
            ProxyHealthState::ProtocolError
        );
        assert_eq!(
            classify_failure("connection timed out"),
            ProxyHealthState::Offline
        );
    }

    #[test]
    fn health_state_requires_two_samples_to_leave_healthy_or_recover() {
        assert_eq!(
            stabilized_state(ProxyHealthState::Healthy, ProxyHealthState::Offline, 0, 1),
            ProxyHealthState::Degraded
        );
        assert_eq!(
            stabilized_state(ProxyHealthState::Offline, ProxyHealthState::Healthy, 1, 0),
            ProxyHealthState::Degraded
        );
        assert_eq!(
            stabilized_state(ProxyHealthState::Offline, ProxyHealthState::Healthy, 2, 0),
            ProxyHealthState::Healthy
        );
    }

    #[test]
    fn latency_history_is_bounded_and_keeps_newest_samples() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        let state = CoreState::new(
            path,
            "test-token".to_string(),
            crate::model::AppConfig::default(),
        );
        for latency_ms in 0..(MAX_LATENCY_SAMPLES as u64 + 5) {
            record_probe(
                &state,
                "clash-socks",
                ProxyTestResult {
                    proxy_id: "clash-socks".to_string(),
                    reachable: true,
                    protocol_accepted: true,
                    tcp_supported: Some(true),
                    tcp_error: None,
                    udp_supported: Some(true),
                    udp_error: None,
                    latency_ms,
                    error: None,
                },
            );
        }
        let health = state
            .proxy_health_snapshot()
            .into_iter()
            .find(|health| health.proxy_id == "clash-socks")
            .expect("probe should create health state");
        assert_eq!(health.latency_history_ms.len(), MAX_LATENCY_SAMPLES);
        assert_eq!(health.latency_history_ms.first(), Some(&5));
        assert_eq!(health.latency_history_ms.last(), Some(&34));
    }
}
