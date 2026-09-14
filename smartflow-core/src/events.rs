//! Stable structured event identifiers emitted by the Core.
//!
//! Event IDs are part of diagnostics and support tooling. Keep the registry
//! small and explicit: human-readable messages may change, while an ID must
//! remain stable across a minor release.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct EventDefinition {
    pub id: &'static str,
    pub component: &'static str,
    pub severity: &'static str,
    pub summary: &'static str,
}

pub mod id {
    pub const CONFIG_RECOVERY: &str = "PD-CONFIG-RECOVERY";
    pub const CORE_START: &str = "PD-CORE-START";
    pub const ENGINE_START_FAILED: &str = "PD-ENGINE-START-FAILED";
    pub const PROFILE_CREATED: &str = "PD-PROFILE-CREATED";
    pub const PROFILE_ACTIVATED: &str = "PD-PROFILE-ACTIVATED";
    pub const PROCESS_START: &str = "PD-PROCESS-START";
    pub const PROCESS_STOP: &str = "PD-PROCESS-STOP";
}

pub const REGISTRY: &[EventDefinition] = &[
    EventDefinition {
        id: id::CONFIG_RECOVERY,
        component: "bootstrap",
        severity: "warn",
        summary: "configuration recovery control plane is active",
    },
    EventDefinition {
        id: id::CORE_START,
        component: "bootstrap",
        severity: "info",
        summary: "core service starting",
    },
    EventDefinition {
        id: id::ENGINE_START_FAILED,
        component: "engine",
        severity: "error",
        summary: "data plane startup failed",
    },
    EventDefinition {
        id: id::PROFILE_CREATED,
        component: "profiles",
        severity: "info",
        summary: "routing profile created",
    },
    EventDefinition {
        id: id::PROFILE_ACTIVATED,
        component: "profiles",
        severity: "info",
        summary: "routing profile activated",
    },
    EventDefinition {
        id: id::PROCESS_START,
        component: "process",
        severity: "info",
        summary: "matched process started",
    },
    EventDefinition {
        id: id::PROCESS_STOP,
        component: "process",
        severity: "info",
        summary: "matched process stopped",
    },
];

pub fn definition(id: &str) -> Option<&'static EventDefinition> {
    REGISTRY.iter().find(|definition| definition.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_are_unique_and_have_stable_shape() {
        for (index, definition) in REGISTRY.iter().enumerate() {
            assert!(definition.id.starts_with("PD-"));
            assert!(!definition.component.is_empty());
            assert!(!definition.severity.is_empty());
            assert!(!definition.summary.is_empty());
            assert!(
                REGISTRY[index + 1..]
                    .iter()
                    .all(|other| other.id != definition.id),
                "duplicate event id: {}",
                definition.id
            );
        }
    }

    #[test]
    fn every_public_event_constant_is_registered() {
        for id in [
            id::CONFIG_RECOVERY,
            id::CORE_START,
            id::ENGINE_START_FAILED,
            id::PROFILE_CREATED,
            id::PROFILE_ACTIVATED,
            id::PROCESS_START,
            id::PROCESS_STOP,
        ] {
            assert!(definition(id).is_some(), "missing registry entry for {id}");
        }
    }
}
