use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use chrono::Utc;
use tokio::time;

use crate::{
    events::id as event_id,
    model::{MatchEvent, ProcessInfo, UiLogEvent},
    process::{resolve_matching_rule, ProcessScanner},
    state::CoreState,
};

pub fn start_process_watcher(state: CoreState) {
    tokio::spawn(async move {
        let mut observed_matches: HashMap<ProcessIdentity, String> = HashMap::new();
        let mut observed_processes: HashMap<ProcessIdentity, ProcessInfo> = HashMap::new();
        let mut lifecycle_initialized = false;
        let mut scanner = ProcessScanner::new();
        let mut ticker = time::interval(Duration::from_secs(2));

        loop {
            ticker.tick().await;

            let processes = scanner.scan();
            let current_processes = processes
                .iter()
                .map(ProcessIdentity::from)
                .collect::<HashSet<_>>();
            let current_stable_processes = processes
                .iter()
                .filter(|process| process.creation_time.is_some())
                .map(|process| (ProcessIdentity::from(process), process.clone()))
                .collect::<HashMap<_, _>>();
            if lifecycle_initialized {
                for (identity, process) in current_stable_processes.iter() {
                    if !observed_processes.contains_key(identity) {
                        state.add_log(UiLogEvent::with_event_id(
                            "info",
                            "process",
                            event_id::PROCESS_START,
                            format!(
                                "process started: {} (pid={}, creation_time={})",
                                process.name,
                                process.pid,
                                identity.creation_time.unwrap_or_default()
                            ),
                        ));
                    }
                }
                for (identity, process) in observed_processes.iter() {
                    if !current_stable_processes.contains_key(identity) {
                        state.add_log(UiLogEvent::with_event_id(
                            "info",
                            "process",
                            event_id::PROCESS_STOP,
                            format!(
                                "process stopped: {} (pid={}, creation_time={})",
                                process.name,
                                process.pid,
                                identity.creation_time.unwrap_or_default()
                            ),
                        ));
                    }
                }
            }
            observed_processes = current_stable_processes;
            lifecycle_initialized = true;
            observed_matches.retain(|identity, _| current_processes.contains(identity));
            state.update_processes(processes.clone());
            let config = state.config_snapshot();
            match state.engine.maintain(&config) {
                Ok(true) => state.add_log(UiLogEvent::new(
                    "info",
                    "supervisor",
                    "data plane recovered after an unexpected stop",
                )),
                Ok(false) => {}
                Err(error) => state.add_log(UiLogEvent::new(
                    "error",
                    "supervisor",
                    format!("data plane recovery failed: {error}"),
                )),
            }
            if let Err(error) = state.engine.reconcile_processes(&config, &processes) {
                state.add_log(UiLogEvent::new(
                    "error",
                    "supervisor",
                    format!("firewall process reconciliation failed: {error}"),
                ));
            }
            let rules = config.rules;
            let proxies = config.proxies;

            for process in processes {
                let Some(matched) = resolve_matching_rule(&rules, &process) else {
                    observed_matches.remove(&ProcessIdentity::from(&process));
                    continue;
                };
                if !should_record_match(
                    &mut observed_matches,
                    ProcessIdentity::from(&process),
                    matched.rule.id.as_str(),
                ) {
                    continue;
                }

                let target_id = matched.rule.action_target_id();
                let proxy_name = proxies
                    .iter()
                    .find(|proxy| proxy.id == target_id)
                    .map(|proxy| proxy.name.clone())
                    .unwrap_or_else(|| target_id.clone());

                state.record_match(MatchEvent {
                    ts: Utc::now(),
                    process_pid: process.pid,
                    process_name: process.name.clone(),
                    process_exe: process.exe.clone(),
                    rule_id: matched.rule.id.clone(),
                    rule_name: matched.rule.name.clone(),
                    proxy_id: target_id,
                    proxy_name: proxy_name.clone(),
                    source: matched.rule.source,
                    match_kind: matched.match_kind,
                });

                state.add_log(UiLogEvent::new(
                    "info",
                    "watcher",
                    format!(
                        "rule '{}' matched process {} (pid={}) via {:?}",
                        matched.rule.name, process.name, process.pid, matched.match_kind
                    ),
                ));
            }
        }
    });
}

#[cfg(test)]
fn reconcile_lifecycle(
    previous: &HashMap<ProcessIdentity, ProcessInfo>,
    current: &HashMap<ProcessIdentity, ProcessInfo>,
) -> (Vec<ProcessIdentity>, Vec<ProcessIdentity>) {
    let started = current
        .keys()
        .filter(|identity| !previous.contains_key(identity))
        .copied()
        .collect::<Vec<_>>();
    let stopped = previous
        .keys()
        .filter(|identity| !current.contains_key(identity))
        .copied()
        .collect::<Vec<_>>();
    (started, stopped)
}

fn should_record_match(
    observed_matches: &mut HashMap<ProcessIdentity, String>,
    identity: ProcessIdentity,
    rule_id: &str,
) -> bool {
    // Without a creation time the PID is not a trustworthy process identity:
    // retaining it across scans could suppress a later process that reused the
    // same PID.  Do not emit a process-match event in this degraded case; the
    // compiler/API diagnostics remain the explicit signal that identity data
    // is unavailable.
    if identity.creation_time.is_none() {
        return false;
    }
    if observed_matches
        .get(&identity)
        .is_some_and(|seen| seen == rule_id)
    {
        return false;
    }
    observed_matches.insert(identity, rule_id.to_string());
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ProcessIdentity {
    pid: u32,
    creation_time: Option<u64>,
}

impl From<&ProcessInfo> for ProcessIdentity {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid,
            creation_time: process.creation_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_when_an_existing_process_gets_a_new_matching_rule() {
        let mut observed = HashMap::new();
        let identity = ProcessIdentity {
            pid: 42,
            creation_time: Some(100),
        };

        assert!(should_record_match(&mut observed, identity, "rule-a"));
        assert!(!should_record_match(&mut observed, identity, "rule-a"));
        assert!(should_record_match(&mut observed, identity, "rule-b"));

        observed.remove(&identity);
        assert!(should_record_match(&mut observed, identity, "rule-b"));
    }

    #[test]
    fn pid_reuse_is_a_new_process_identity() {
        let mut observed = HashMap::new();
        let first = ProcessIdentity {
            pid: 42,
            creation_time: Some(100),
        };
        let reused = ProcessIdentity {
            pid: 42,
            creation_time: Some(200),
        };

        assert!(should_record_match(&mut observed, first, "rule-a"));
        assert!(should_record_match(&mut observed, reused, "rule-a"));
    }

    #[test]
    fn missing_creation_time_is_not_treated_as_a_stable_identity() {
        let mut observed = HashMap::new();
        let identity = ProcessIdentity {
            pid: 42,
            creation_time: None,
        };

        assert!(!should_record_match(&mut observed, identity, "rule-a"));
        assert!(observed.is_empty());
    }

    #[test]
    fn lifecycle_reconciliation_uses_pid_and_creation_time() {
        let previous = HashMap::from([(
            ProcessIdentity {
                pid: 42,
                creation_time: Some(100),
            },
            ProcessInfo {
                pid: 42,
                creation_time: Some(100),
                name: "old.exe".to_string(),
                exe: "C:\\old.exe".to_string(),
            },
        )]);
        let current = HashMap::from([(
            ProcessIdentity {
                pid: 42,
                creation_time: Some(200),
            },
            ProcessInfo {
                pid: 42,
                creation_time: Some(200),
                name: "new.exe".to_string(),
                exe: "C:\\new.exe".to_string(),
            },
        )]);
        let (started, stopped) = reconcile_lifecycle(&previous, &current);
        assert_eq!(started.len(), 1);
        assert_eq!(stopped.len(), 1);
        assert_eq!(started[0].creation_time, Some(200));
        assert_eq!(stopped[0].creation_time, Some(100));
    }
}
