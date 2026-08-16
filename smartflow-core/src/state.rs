use std::{collections::VecDeque, path::PathBuf, sync::Arc};

use anyhow::Result;
use parking_lot::{Mutex, RwLock};

use crate::{
    config,
    engine::{mode_name, EngineManager},
    model::{
        AppConfig, MatchEvent, ProcessInfo, ProxyHitStat, RuleHitStat, RuntimeStats, RuntimeStatus,
        UiLogEvent,
    },
};

const MAX_LOGS: usize = 500;
const MAX_MATCH_EVENTS: usize = 200;

#[derive(Clone)]
pub struct CoreState {
    pub config_path: PathBuf,
    pub auth_token: Arc<String>,
    pub config: Arc<RwLock<AppConfig>>,
    pub stats: Arc<RwLock<RuntimeStats>>,
    pub logs: Arc<RwLock<VecDeque<UiLogEvent>>>,
    pub recent_matches: Arc<RwLock<VecDeque<MatchEvent>>>,
    pub processes: Arc<RwLock<Vec<ProcessInfo>>>,
    pub engine: Arc<EngineManager>,
    config_transaction: Arc<Mutex<()>>,
}

impl CoreState {
    pub fn new(config_path: PathBuf, auth_token: String, config_data: AppConfig) -> Self {
        let stats = Arc::new(RwLock::new(RuntimeStats {
            engine_mode: mode_name(config_data.engine_mode),
            ..RuntimeStats::default()
        }));

        let engine = Arc::new(EngineManager::new(config_data.engine_mode, stats.clone()));

        Self {
            config_path,
            auth_token: Arc::new(auth_token),
            config: Arc::new(RwLock::new(config_data)),
            stats,
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_LOGS))),
            recent_matches: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_MATCH_EVENTS))),
            processes: Arc::new(RwLock::new(Vec::new())),
            engine,
            config_transaction: Arc::new(Mutex::new(())),
        }
    }

    pub fn add_log(&self, event: UiLogEvent) {
        let mut logs = self.logs.write();
        logs.push_back(event);
        while logs.len() > MAX_LOGS {
            logs.pop_front();
        }
    }

    pub fn list_logs(&self) -> Vec<UiLogEvent> {
        self.logs.read().iter().cloned().collect()
    }

    pub fn record_match(&self, event: MatchEvent) {
        {
            let mut stats = self.stats.write();
            *stats.rule_hits.entry(event.rule_id.clone()).or_insert(0) += 1;
            *stats
                .process_hits
                .entry(event.process_name.clone())
                .or_insert(0) += 1;
            *stats.proxy_hits.entry(event.proxy_id.clone()).or_insert(0) += 1;
        }

        let mut recent = self.recent_matches.write();
        recent.push_back(event);
        while recent.len() > MAX_MATCH_EVENTS {
            recent.pop_front();
        }
    }

    pub fn list_recent_matches(&self) -> Vec<MatchEvent> {
        self.recent_matches.read().iter().cloned().collect()
    }

    pub fn update_processes(&self, processes: Vec<ProcessInfo>) {
        *self.processes.write() = processes;
    }

    pub fn list_processes(&self) -> Vec<ProcessInfo> {
        self.processes.read().clone()
    }

    pub fn list_rule_hit_stats(&self) -> Vec<RuleHitStat> {
        let config = self.config.read();
        let stats = self.stats.read();
        let mut rows = stats
            .rule_hits
            .iter()
            .map(|(rule_id, hits)| {
                let rule = config.rules.iter().find(|rule| &rule.id == rule_id);
                let (rule_name, proxy_id, source) = match rule {
                    Some(rule) => (rule.name.clone(), rule.proxy_profile.clone(), rule.source),
                    None => (
                        "<deleted rule>".to_string(),
                        "<unknown proxy>".to_string(),
                        Default::default(),
                    ),
                };
                let proxy_name = config
                    .proxies
                    .iter()
                    .find(|proxy| proxy.id == proxy_id)
                    .map(|proxy| proxy.name.clone())
                    .unwrap_or_else(|| proxy_id.clone());

                RuleHitStat {
                    rule_id: rule_id.clone(),
                    rule_name,
                    proxy_id,
                    proxy_name,
                    source,
                    hits: *hits,
                }
            })
            .collect::<Vec<_>>();

        rows.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| left.rule_name.cmp(&right.rule_name))
        });
        rows
    }

    pub fn list_proxy_hit_stats(&self) -> Vec<ProxyHitStat> {
        let config = self.config.read();
        let stats = self.stats.read();
        let mut rows = stats
            .proxy_hits
            .iter()
            .map(|(proxy_id, hits)| {
                let proxy_name = config
                    .proxies
                    .iter()
                    .find(|proxy| &proxy.id == proxy_id)
                    .map(|proxy| proxy.name.clone())
                    .unwrap_or_else(|| proxy_id.clone());

                ProxyHitStat {
                    proxy_id: proxy_id.clone(),
                    proxy_name,
                    hits: *hits,
                }
            })
            .collect::<Vec<_>>();

        rows.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| left.proxy_name.cmp(&right.proxy_name))
        });
        rows
    }

    pub fn config_snapshot(&self) -> AppConfig {
        self.config.read().clone()
    }

    pub fn stats_snapshot(&self) -> RuntimeStats {
        self.stats.read().clone()
    }

    pub fn runtime_status(&self) -> RuntimeStatus {
        let config = self.config_snapshot();
        RuntimeStatus {
            desired_enabled: config.runtime.enabled,
            engine_mode: config.engine_mode,
            data_plane: self.engine.status(),
        }
    }

    pub fn mutate_config<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut AppConfig) -> T,
    {
        let _transaction = self.config_transaction.lock();
        let previous = self.config_snapshot();
        let mut next = previous.clone();
        let output = f(&mut next);
        self.apply_config(&previous, &next)?;
        *self.config.write() = next;
        Ok(output)
    }

    pub fn replace_config(&self, next: AppConfig) -> Result<AppConfig> {
        let _transaction = self.config_transaction.lock();
        let previous = self.config_snapshot();
        self.apply_config(&previous, &next)?;
        *self.config.write() = next.clone();
        Ok(next)
    }

    fn apply_config(&self, previous: &AppConfig, next: &AppConfig) -> Result<()> {
        crate::validation::validate_config(next)?;
        let mode_changed = mode_name(previous.engine_mode) != mode_name(next.engine_mode);

        let engine_result = if mode_changed {
            self.engine.switch_mode(next.engine_mode, next)
        } else {
            self.engine.reload_rules(next)
        };

        engine_result?;

        if let Err(error) = config::save(&self.config_path, next) {
            if mode_changed {
                let _ = self.engine.switch_mode(previous.engine_mode, previous);
            } else {
                let _ = self.engine.reload_rules(previous);
            }
            return Err(error);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::{MatchKind, RuleSource};

    #[test]
    fn test_record_match_updates_recent_items_and_stats() {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let state = CoreState::new(path, "test-token".to_string(), AppConfig::default());
        state.record_match(MatchEvent {
            ts: Utc::now(),
            process_pid: 100,
            process_name: "node.exe".to_string(),
            process_exe: "C:\\node.exe".to_string(),
            rule_id: "rule-1".to_string(),
            rule_name: "Node".to_string(),
            proxy_id: "clash-socks".to_string(),
            proxy_name: "Clash Verge Default".to_string(),
            source: RuleSource::User,
            match_kind: MatchKind::AppName,
        });

        let stats = state.stats_snapshot();
        assert_eq!(stats.rule_hits.get("rule-1"), Some(&1));
        assert_eq!(stats.process_hits.get("node.exe"), Some(&1));
        assert_eq!(stats.proxy_hits.get("clash-socks"), Some(&1));
        assert_eq!(state.list_recent_matches().len(), 1);
    }
}
