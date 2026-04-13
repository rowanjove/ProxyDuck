use std::{collections::HashSet, time::Duration};

use chrono::Utc;
use tokio::time;

use crate::{
    model::{MatchEvent, UiLogEvent},
    process::{list_processes, resolve_matching_rule},
    state::CoreState,
};

pub fn start_process_watcher(state: CoreState) {
    tokio::spawn(async move {
        let mut seen: HashSet<u32> = HashSet::new();
        let mut ticker = time::interval(Duration::from_secs(2));

        loop {
            ticker.tick().await;

            let processes = list_processes();
            let config = state.config_snapshot();
            let rules = config.rules;
            let proxies = config.proxies;

            for process in processes {
                if !seen.insert(process.pid) {
                    continue;
                }

                let Some(matched) = resolve_matching_rule(&rules, &process) else {
                    continue;
                };

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
                    source: matched.rule.source.clone(),
                    match_kind: matched.match_kind.clone(),
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
