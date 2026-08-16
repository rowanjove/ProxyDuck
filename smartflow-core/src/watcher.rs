use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use chrono::Utc;
use tokio::time;

use crate::{
    model::{MatchEvent, UiLogEvent},
    process::{resolve_matching_rule, ProcessScanner},
    state::CoreState,
};

pub fn start_process_watcher(state: CoreState) {
    tokio::spawn(async move {
        let mut observed_matches: HashMap<u32, String> = HashMap::new();
        let mut scanner = ProcessScanner::new();
        let mut ticker = time::interval(Duration::from_secs(2));

        loop {
            ticker.tick().await;

            let processes = scanner.scan();
            let current_pids = processes
                .iter()
                .map(|process| process.pid)
                .collect::<HashSet<_>>();
            observed_matches.retain(|pid, _| current_pids.contains(pid));
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
            let rules = config.rules;
            let proxies = config.proxies;

            for process in processes {
                let Some(matched) = resolve_matching_rule(&rules, &process) else {
                    observed_matches.remove(&process.pid);
                    continue;
                };
                if !should_record_match(
                    &mut observed_matches,
                    process.pid,
                    matched.rule.id.as_str(),
                ) {
                    continue;
                }

                let proxy_name = proxies
                    .iter()
                    .find(|proxy| proxy.id == matched.rule.proxy_profile)
                    .map(|proxy| proxy.name.clone())
                    .unwrap_or_else(|| matched.rule.proxy_profile.clone());

                state.record_match(MatchEvent {
                    ts: Utc::now(),
                    process_pid: process.pid,
                    process_name: process.name.clone(),
                    process_exe: process.exe.clone(),
                    rule_id: matched.rule.id.clone(),
                    rule_name: matched.rule.name.clone(),
                    proxy_id: matched.rule.proxy_profile.clone(),
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

fn should_record_match(
    observed_matches: &mut HashMap<u32, String>,
    pid: u32,
    rule_id: &str,
) -> bool {
    if observed_matches
        .get(&pid)
        .is_some_and(|seen| seen == rule_id)
    {
        return false;
    }
    observed_matches.insert(pid, rule_id.to_string());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_when_an_existing_process_gets_a_new_matching_rule() {
        let mut observed = HashMap::new();

        assert!(should_record_match(&mut observed, 42, "rule-a"));
        assert!(!should_record_match(&mut observed, 42, "rule-a"));
        assert!(should_record_match(&mut observed, 42, "rule-b"));

        observed.remove(&42);
        assert!(should_record_match(&mut observed, 42, "rule-b"));
    }
}
