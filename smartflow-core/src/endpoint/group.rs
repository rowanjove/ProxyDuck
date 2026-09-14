use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::ProxyProfile;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupStrategy {
    #[default]
    PrimaryBackup,
    LowestLatency,
    RoundRobin,
    Sticky,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    #[default]
    FailOpen, // Fallback to Direct
    FailClosed, // Fallback to Block
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointGroup {
    pub id: String,
    pub name: String,
    pub strategy: GroupStrategy,
    pub endpoints: Vec<String>,
    pub fail_mode: FailMode,
}

impl EndpointGroup {
    pub fn select_endpoint<'a>(
        &self,
        proxies: &'a [ProxyProfile],
        latency_map: &HashMap<String, u64>,
        failed_endpoints: &HashMap<String, bool>,
        round_robin_counter: usize,
    ) -> Result<&'a ProxyProfile, FailMode> {
        let proxy_lookup = proxies
            .iter()
            .map(|p| (p.id.as_str(), p))
            .collect::<HashMap<_, _>>();

        // Available healthy candidates in group
        let candidates = self
            .endpoints
            .iter()
            .filter_map(|id| proxy_lookup.get(id.as_str()))
            .filter(|p| p.enabled && !failed_endpoints.get(&p.id).copied().unwrap_or(false))
            .copied()
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Err(self.fail_mode);
        }

        match self.strategy {
            GroupStrategy::PrimaryBackup | GroupStrategy::Sticky => {
                // Primary is the first available healthy candidate in defined order
                Ok(candidates[0])
            }
            GroupStrategy::LowestLatency => {
                let best = candidates
                    .into_iter()
                    .min_by_key(|p| latency_map.get(&p.id).copied().unwrap_or(u64::MAX));
                best.ok_or(self.fail_mode)
            }
            GroupStrategy::RoundRobin => {
                let idx = round_robin_counter % candidates.len();
                Ok(candidates[idx])
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    Closed,
    Open {
        tripped_at: DateTime<Utc>,
        cool_down_until: DateTime<Utc>,
    },
    HalfOpen {
        trial_successes: u32,
        required: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreaker {
    pub endpoint_id: String,
    pub failure_threshold: u32,
    pub cool_down_duration_secs: u64,
    pub state: CircuitState,
    pub consecutive_failures: u32,
}

impl CircuitBreaker {
    pub fn new(endpoint_id: impl Into<String>) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            failure_threshold: 5,
            cool_down_duration_secs: 30,
            state: CircuitState::Closed,
            consecutive_failures: 0,
        }
    }

    pub fn can_attempt(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open {
                cool_down_until, ..
            } => {
                if Utc::now() >= cool_down_until {
                    // Transition to HalfOpen to allow canary trial
                    self.state = CircuitState::HalfOpen {
                        trial_successes: 0,
                        required: 2,
                    };
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen { .. } => true,
        }
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        match &mut self.state {
            CircuitState::Closed => {}
            CircuitState::Open { .. } => {
                self.state = CircuitState::Closed;
            }
            CircuitState::HalfOpen {
                trial_successes,
                required,
            } => {
                *trial_successes += 1;
                if *trial_successes >= *required {
                    self.state = CircuitState::Closed;
                }
            }
        }
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        match self.state {
            CircuitState::Closed => {
                if self.consecutive_failures >= self.failure_threshold {
                    self.trip();
                }
            }
            CircuitState::HalfOpen { .. } => {
                // Any failure in half-open immediately re-trips the circuit
                self.trip();
            }
            CircuitState::Open { .. } => {}
        }
    }

    fn trip(&mut self) {
        let now = Utc::now();
        let until = now + chrono::Duration::seconds(self.cool_down_duration_secs as i64);
        self.state = CircuitState::Open {
            tripped_at: now,
            cool_down_until: until,
        };
    }
}
