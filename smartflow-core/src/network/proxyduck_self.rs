use crate::{engine::mode_name, model::DataPlanePhase, state::CoreState};

use super::model::ProxyDuckDiagnosticStatus;

pub struct ProxyDuckCollector;

impl ProxyDuckCollector {
    pub fn check(state: Option<&CoreState>) -> ProxyDuckDiagnosticStatus {
        let Some(st) = state else {
            return ProxyDuckDiagnosticStatus {
                engine_running: false,
                engine_mode: "unknown".to_string(),
                data_plane_phase: "stopped".to_string(),
                active_rules_count: 0,
                degraded: false,
                bypass_test_ok: true,
            };
        };

        let config = st.config_snapshot();
        let mode = mode_name(config.engine_mode).to_string();
        let engine_status = st.engine.status();

        let phase_str = match engine_status.phase {
            DataPlanePhase::Stopped => "stopped",
            DataPlanePhase::Paused => "paused",
            DataPlanePhase::Starting => "starting",
            DataPlanePhase::Running => "running",
            DataPlanePhase::Degraded => "degraded",
            DataPlanePhase::Error => "error",
        }
        .to_string();

        let running = engine_status.phase == DataPlanePhase::Running;
        let degraded = engine_status.phase == DataPlanePhase::Degraded
            || engine_status.phase == DataPlanePhase::Error;

        let active_rules = config.rules.iter().filter(|r| r.enabled).count();

        ProxyDuckDiagnosticStatus {
            engine_running: running,
            engine_mode: mode,
            data_plane_phase: phase_str,
            active_rules_count: active_rules,
            degraded,
            bypass_test_ok: !degraded,
        }
    }
}
