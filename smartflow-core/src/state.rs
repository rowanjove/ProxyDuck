use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use parking_lot::{Mutex, RwLock};

use crate::{
    config,
    engine::{mode_name, EngineManager},
    model::{
        AppConfig, DataPlanePhase, MatchEvent, ProcessInfo, ProxyHealth, ProxyHealthState,
        ProxyProcessMatchStat, RuleProcessMatchStat, RuntimeStats, RuntimeStatus, UiLogEvent,
    },
    routing_plan::CompileDiagnostic,
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
    pub proxy_health: Arc<RwLock<HashMap<String, ProxyHealth>>>,
    pub last_transition_at: Arc<RwLock<Option<chrono::DateTime<chrono::Utc>>>>,
    pub last_apply_diagnostics: Arc<RwLock<Vec<CompileDiagnostic>>>,
    pub engine: Arc<EngineManager>,
    pub timeline: Arc<crate::timeline::TimelineManager>,
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
            proxy_health: Arc::new(RwLock::new(HashMap::new())),
            last_transition_at: Arc::new(RwLock::new(None)),
            last_apply_diagnostics: Arc::new(RwLock::new(Vec::new())),
            engine,
            timeline: Arc::new(crate::timeline::TimelineManager::new(500)),
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
        let config = self.config_snapshot();
        let counts_as_proxy_match = config
            .rules
            .iter()
            .find(|rule| rule.id == event.rule_id.as_str())
            .and_then(|rule| match &rule.action {
                crate::model::RouteAction::Proxy { proxy_id } => {
                    let target = if proxy_id.trim().is_empty() {
                        &rule.proxy_profile
                    } else {
                        proxy_id
                    };
                    config
                        .proxies
                        .iter()
                        .find(|proxy| proxy.id == target.as_str())
                        .map(|proxy| matches!(proxy.kind, crate::model::ProxyKind::Socks5))
                }
                crate::model::RouteAction::Direct
                | crate::model::RouteAction::Block
                | crate::model::RouteAction::Reject => Some(false),
            })
            // A stale event can arrive after its rule was deleted; retain the
            // historical proxy counter for that unknown event rather than
            // silently dropping telemetry.
            .unwrap_or(true);
        {
            let mut stats = self.stats.write();
            *stats
                .rule_process_matches
                .entry(event.rule_id.clone())
                .or_insert(0) += 1;
            *stats
                .process_matches
                .entry(event.process_name.clone())
                .or_insert(0) += 1;
            if counts_as_proxy_match {
                *stats
                    .proxy_process_matches
                    .entry(event.proxy_id.clone())
                    .or_insert(0) += 1;
            }
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

    pub fn list_rule_process_match_stats(&self) -> Vec<RuleProcessMatchStat> {
        let config = self.config.read();
        let stats = self.stats.read();
        let mut rows = stats
            .rule_process_matches
            .iter()
            .map(|(rule_id, hits)| {
                let rule = config.rules.iter().find(|rule| &rule.id == rule_id);
                let (rule_name, proxy_id, source) = match rule {
                    Some(rule) => (rule.name.clone(), rule.action_target_id(), rule.source),
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

                RuleProcessMatchStat {
                    rule_id: rule_id.clone(),
                    rule_name,
                    proxy_id,
                    proxy_name,
                    source,
                    matches: *hits,
                }
            })
            .collect::<Vec<_>>();

        rows.sort_by(|left, right| {
            right
                .matches
                .cmp(&left.matches)
                .then_with(|| left.rule_name.cmp(&right.rule_name))
        });
        rows
    }

    pub fn list_proxy_process_match_stats(&self) -> Vec<ProxyProcessMatchStat> {
        let config = self.config.read();
        let stats = self.stats.read();
        let mut rows = stats
            .proxy_process_matches
            .iter()
            .map(|(proxy_id, hits)| {
                let proxy_name = config
                    .proxies
                    .iter()
                    .find(|proxy| &proxy.id == proxy_id)
                    .map(|proxy| proxy.name.clone())
                    .unwrap_or_else(|| proxy_id.clone());

                ProxyProcessMatchStat {
                    proxy_id: proxy_id.clone(),
                    proxy_name,
                    matches: *hits,
                }
            })
            .collect::<Vec<_>>();

        rows.sort_by(|left, right| {
            right
                .matches
                .cmp(&left.matches)
                .then_with(|| left.proxy_name.cmp(&right.proxy_name))
        });
        rows
    }

    pub fn config_snapshot(&self) -> AppConfig {
        self.config.read().clone()
    }

    /// Delete a secret only while holding the same transaction lock used by
    /// config mutations.  API cleanup runs after a successful mutation, so
    /// taking this lock prevents a concurrent create/update from recreating
    /// the same deterministic proxy secret between the reference check and
    /// the delete.
    pub fn delete_secret_if_unreferenced(&self, secret_ref: &str) -> Result<()> {
        let _transaction = self.config_transaction.lock();
        if self
            .config
            .read()
            .proxies
            .iter()
            .any(|proxy| proxy.password_ref.as_deref() == Some(secret_ref))
        {
            return Ok(());
        }
        proxyduck_common::SecretStore::new()?.delete(secret_ref)
    }

    /// Restore a secret written by a failed proxy update only if the config
    /// still describes the pre-update value.  If another update committed in
    /// the meantime, its credential must not be overwritten by rollback.
    pub fn restore_secret_after_failed_proxy_update(
        &self,
        proxy_id: &str,
        previous: &crate::model::ProxyProfile,
        candidate_secret_ref: &str,
    ) -> Result<()> {
        let _transaction = self.config_transaction.lock();
        let still_previous = {
            let config = self.config.read();
            config
                .proxies
                .iter()
                .find(|proxy| proxy.id == proxy_id)
                .is_some_and(|current| {
                    current.password_ref == previous.password_ref
                        && current.password == previous.password
                })
        };
        if !still_previous {
            return Ok(());
        }

        let store = proxyduck_common::SecretStore::new()?;
        if let Some(old_ref) = previous.password_ref.as_deref() {
            let restore = previous
                .password
                .as_deref()
                .map(|password| store.put(old_ref, password))
                .unwrap_or_else(|| store.delete(old_ref));
            restore?;
        }
        if previous.password_ref.as_deref() != Some(candidate_secret_ref) {
            store.delete(candidate_secret_ref)?;
        }
        Ok(())
    }

    pub fn stats_snapshot(&self) -> RuntimeStats {
        self.stats.read().clone()
    }

    pub fn last_apply_diagnostics(&self) -> Vec<CompileDiagnostic> {
        self.last_apply_diagnostics.read().clone()
    }

    pub fn runtime_status(&self) -> RuntimeStatus {
        let config = self.config_snapshot();
        let proxy_health = self.proxy_health_snapshot();
        let mut data_plane = self.engine.status();
        let mut degraded_reasons = Vec::new();
        let (active_plan_fingerprint, plan_diagnostics) =
            match crate::routing_plan::compile_routing_plan(&config, &self.list_processes()) {
                Ok(plan) => (Some(plan.fingerprint), plan.diagnostics),
                Err(error) => {
                    degraded_reasons.push(format!("routing plan compile failed: {error}"));
                    (None, Vec::new())
                }
            };
        degraded_reasons.extend(
            plan_diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.clone()),
        );
        let required_proxy_ids = config
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .filter_map(|rule| match &rule.action {
                crate::model::RouteAction::Proxy { proxy_id } if !proxy_id.trim().is_empty() => {
                    Some(proxy_id.clone())
                }
                crate::model::RouteAction::Proxy { .. } => Some(rule.proxy_profile.clone()),
                crate::model::RouteAction::Direct
                | crate::model::RouteAction::Block
                | crate::model::RouteAction::Reject => None,
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if config.runtime.enabled && data_plane.phase == DataPlanePhase::Running {
            let health_by_id = proxy_health
                .iter()
                .map(|health| (health.proxy_id.as_str(), health))
                .collect::<HashMap<_, _>>();
            let required = config
                .rules
                .iter()
                .filter(|rule| rule.enabled)
                .filter_map(|rule| match &rule.action {
                    crate::model::RouteAction::Proxy { proxy_id }
                        if !proxy_id.trim().is_empty() =>
                    {
                        Some(proxy_id.as_str())
                    }
                    crate::model::RouteAction::Proxy { .. } => Some(rule.proxy_profile.as_str()),
                    crate::model::RouteAction::Direct
                    | crate::model::RouteAction::Block
                    | crate::model::RouteAction::Reject => None,
                })
                .collect::<std::collections::HashSet<_>>();
            if let Some(proxy_id) = required.iter().find(|proxy_id| {
                !matches!(
                    health_by_id.get(*proxy_id).map(|health| health.state),
                    Some(ProxyHealthState::Healthy)
                )
            }) {
                data_plane.phase = DataPlanePhase::Degraded;
                let reason = format!("required proxy '{proxy_id}' is not healthy");
                data_plane.message = Some(reason.clone());
                degraded_reasons.push(reason);
            }
            if !degraded_reasons.is_empty() {
                data_plane.phase = DataPlanePhase::Degraded;
                if data_plane.message.is_none() {
                    data_plane.message = degraded_reasons.first().cloned();
                }
            }
        }
        RuntimeStatus {
            desired_enabled: config.runtime.enabled,
            engine_mode: config.engine_mode,
            data_plane,
            proxy_health,
            active_plan_fingerprint,
            required_proxy_ids,
            degraded_reasons,
            compile_diagnostics: plan_diagnostics,
            last_transition_at: *self.last_transition_at.read(),
        }
    }

    pub fn proxy_health_snapshot(&self) -> Vec<ProxyHealth> {
        let mut health = self
            .proxy_health
            .read()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        health.sort_by(|left, right| left.proxy_id.cmp(&right.proxy_id));
        health
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

    pub fn try_mutate_config<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut AppConfig) -> Result<T>,
    {
        let _transaction = self.config_transaction.lock();
        let previous = self.config_snapshot();
        let mut next = previous.clone();
        let output = f(&mut next)?;
        self.apply_config(&previous, &next)?;
        *self.config.write() = next;
        Ok(output)
    }

    /// Import a config while keeping migration, SecretStore hydration and the
    /// engine/config swap under the same transaction lock.  This prevents two
    /// concurrent PUT /config requests from interleaving secret writes and
    /// leaving the persisted config pointing at the wrong credential.
    pub fn replace_imported_config(&self, mut next: AppConfig) -> Result<AppConfig> {
        let _transaction = self.config_transaction.lock();
        let previous = self.config_snapshot();
        let previous_secrets = secret_values(&previous);

        sanitize_template_provenance(&previous, &mut next);

        if let Err(error) = config::migrate_import(&mut next) {
            if let Err(rollback_error) = restore_secret_values(&previous_secrets, &next) {
                tracing::error!(%rollback_error, "failed to restore secrets after import migration failure");
            }
            return Err(error);
        }

        if let Err(error) = self.apply_config(&previous, &next) {
            if let Err(rollback_error) = restore_secret_values(&previous_secrets, &next) {
                tracing::error!(%rollback_error, "failed to restore secrets after config import rollback");
            }
            return Err(error);
        }

        *self.config.write() = next.clone();
        if let Err(error) = remove_obsolete_secrets(&previous_secrets, &next) {
            tracing::warn!(%error, "failed to remove obsolete secrets after config import");
        }
        Ok(next)
    }

    fn apply_config(&self, previous: &AppConfig, next: &AppConfig) -> Result<()> {
        // Compile before validation so a rejected Strict/Compatibility apply
        // still exposes machine-readable capability gaps and remediation to
        // the caller. Structural validation remains authoritative and may
        // reject the config before the engine is touched.
        let diagnostics = crate::routing_plan::compile_routing_plan(next, &self.list_processes())
            .map(|plan| plan.diagnostics)
            .unwrap_or_default();
        *self.last_apply_diagnostics.write() = diagnostics;
        crate::validation::validate_config(next)?;
        let mode_changed = mode_name(previous.engine_mode) != mode_name(next.engine_mode);

        let engine_result = if mode_changed {
            self.engine.switch_mode(next.engine_mode, next, previous)
        } else {
            self.engine.reload_rules(next)
        };

        if let Err(error) = engine_result {
            let rollback = if mode_changed {
                Ok(())
            } else {
                self.engine.reload_rules(previous)
            };
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(anyhow!(
                    "configuration apply failed: {error}; engine rollback failed: {rollback_error}"
                )),
            };
        }

        if let Err(error) = config::save(&self.config_path, next) {
            let rollback = if mode_changed {
                self.engine
                    .switch_mode(previous.engine_mode, previous, next)
            } else {
                self.engine.reload_rules(previous)
            };
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(anyhow!(
                    "configuration save failed: {error}; engine rollback failed: {rollback_error}"
                )),
            };
        }

        if previous.runtime.enabled != next.runtime.enabled
            || previous.engine_mode != next.engine_mode
        {
            *self.last_transition_at.write() = Some(chrono::Utc::now());
        }
        self.reset_changed_proxy_health(previous, next);

        Ok(())
    }

    fn reset_changed_proxy_health(&self, previous: &AppConfig, next: &AppConfig) {
        let changed = next
            .proxies
            .iter()
            .filter(|candidate| {
                let Some(old) = previous
                    .proxies
                    .iter()
                    .find(|proxy| proxy.id == candidate.id)
                else {
                    return true;
                };
                old.name != candidate.name
                    || old.kind != candidate.kind
                    || old.endpoint != candidate.endpoint
                    || old.username != candidate.username
                    || old.password_ref != candidate.password_ref
                    || old.password != candidate.password
                    || old.enabled != candidate.enabled
            })
            .map(|proxy| proxy.id.clone())
            .collect::<Vec<_>>();
        if changed.is_empty() {
            let active = next
                .proxies
                .iter()
                .filter(|proxy| proxy.enabled)
                .map(|proxy| proxy.id.as_str())
                .collect::<std::collections::HashSet<_>>();
            self.proxy_health
                .write()
                .retain(|proxy_id, _| active.contains(proxy_id.as_str()));
            return;
        }
        let mut health = self.proxy_health.write();
        let active = next
            .proxies
            .iter()
            .filter(|proxy| proxy.enabled)
            .map(|proxy| proxy.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        health.retain(|proxy_id, _| active.contains(proxy_id.as_str()));
        for proxy_id in changed {
            if active.contains(proxy_id.as_str()) {
                health.insert(proxy_id.clone(), ProxyHealth::unknown(proxy_id));
            }
        }
    }
}

/// Template provenance is service-owned state.  A full config import may
/// contain the field because it came from `/config`, but an import must not be
/// able to mint provenance for a new rule or change which existing rule is
/// managed.  Preserve only an exact id/key pair already held by the service.
pub(crate) fn sanitize_template_provenance(previous: &AppConfig, next: &mut AppConfig) {
    for rule in &mut next.rules {
        let Some(previous_rule) = previous
            .rules
            .iter()
            .find(|candidate| candidate.id == rule.id)
        else {
            rule.managed_by_template_key = None;
            continue;
        };
        if previous_rule.managed_by_template_key != rule.managed_by_template_key {
            rule.managed_by_template_key = previous_rule.managed_by_template_key.clone();
        }
    }
}

fn secret_values(config: &AppConfig) -> HashMap<String, Option<String>> {
    config
        .proxies
        .iter()
        .filter_map(|proxy| {
            proxy
                .password_ref
                .as_ref()
                .map(|secret_ref| (secret_ref.clone(), proxy.password.clone()))
        })
        .collect()
}

fn restore_secret_values(
    previous: &HashMap<String, Option<String>>,
    imported: &AppConfig,
) -> Result<()> {
    let store = proxyduck_common::SecretStore::new()?;
    let after = secret_values(imported);
    for secret_ref in after
        .keys()
        .filter(|secret_ref| !previous.contains_key(*secret_ref))
    {
        store.delete(secret_ref)?;
    }
    for (secret_ref, value) in previous {
        match value {
            Some(value) => store.put(secret_ref, value)?,
            None => store.delete(secret_ref)?,
        }
    }
    Ok(())
}

fn remove_obsolete_secrets(
    previous: &HashMap<String, Option<String>>,
    imported: &AppConfig,
) -> Result<()> {
    let store = proxyduck_common::SecretStore::new()?;
    let after = secret_values(imported);
    for secret_ref in previous
        .keys()
        .filter(|secret_ref| !after.contains_key(*secret_ref))
    {
        store.delete(secret_ref)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::{MatchCriteria, MatchKind, RouteAction, Rule, RuleSource};

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
        assert_eq!(stats.rule_process_matches.get("rule-1"), Some(&1));
        assert_eq!(stats.process_matches.get("node.exe"), Some(&1));
        assert_eq!(stats.proxy_process_matches.get("clash-socks"), Some(&1));
        assert_eq!(state.list_recent_matches().len(), 1);
    }

    #[test]
    fn changed_proxy_configuration_invalidates_cached_health() {
        crate::set_mock_data_plane(true);
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let state = CoreState::new(path, "test-token".to_string(), AppConfig::default());
        state.engine.start(&state.config_snapshot()).unwrap();
        let proxy_id = state.config_snapshot().proxies[0].id.clone();
        state.proxy_health.write().insert(
            proxy_id.clone(),
            ProxyHealth {
                state: ProxyHealthState::Healthy,
                ..ProxyHealth::unknown(proxy_id.clone())
            },
        );
        state
            .mutate_config(|config| {
                config.proxies[0].endpoint = "127.0.0.1:7898".to_string();
            })
            .unwrap();

        assert_eq!(
            state
                .proxy_health_snapshot()
                .into_iter()
                .find(|health| health.proxy_id == proxy_id)
                .map(|health| health.state),
            Some(ProxyHealthState::Unknown)
        );
    }

    #[test]
    fn failed_engine_apply_restores_previous_runtime_plan() {
        crate::set_mock_data_plane(true);
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let state = CoreState::new(path, "test-token".to_string(), AppConfig::default());
        state.engine.start(&state.config_snapshot()).unwrap();
        let mut next = state.config_snapshot();
        next.runtime.enabled = true;
        let mut blocked = Rule::new(
            "unsupported block".to_string(),
            MatchCriteria {
                app_names: vec!["blocked.exe".to_string()],
                ..Default::default()
            },
            "clash-socks".to_string(),
        );
        blocked.action = RouteAction::Block;
        next.rules.push(blocked);

        assert!(state.replace_imported_config(next).is_err());
        assert!(state.config_snapshot().rules.is_empty());
        assert!(!matches!(
            state.engine.status().phase,
            DataPlanePhase::Error
        ));
    }

    #[test]
    fn imported_config_cannot_mint_or_reassign_template_provenance() {
        let mut previous = AppConfig::default();
        let mut managed = Rule::new(
            "Browser: Chrome".to_string(),
            MatchCriteria {
                app_names: vec!["chrome.exe".to_string()],
                ..Default::default()
            },
            "clash-socks".to_string(),
        );
        managed.managed_by_template_key = Some("browser:Browser: Chrome".to_string());
        previous.rules.push(managed.clone());

        let mut imported = previous.clone();
        imported.rules[0].managed_by_template_key = Some("gaming:forged".to_string());
        sanitize_template_provenance(&previous, &mut imported);
        assert_eq!(
            imported.rules[0].managed_by_template_key,
            previous.rules[0].managed_by_template_key
        );

        let mut forged = Rule::new(
            "Browser: Edge".to_string(),
            MatchCriteria::default(),
            "clash-socks".to_string(),
        );
        forged.managed_by_template_key = Some("browser:Browser: Edge".to_string());
        imported.rules.push(forged);
        sanitize_template_provenance(&previous, &mut imported);
        assert!(imported.rules[1].managed_by_template_key.is_none());
    }
}
