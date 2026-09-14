pub mod adapter;
pub mod diagnosis;
pub mod dns;
pub mod dual_path;
pub mod gateway;
pub mod history;
pub mod hosts;
pub mod internet;
pub mod model;
pub mod ncsi;
pub mod proxy;
pub mod proxyduck_self;
pub mod repair;
pub mod route;
pub mod snapshot;
pub mod winsock;

pub use diagnosis::DiagnosticOrchestrator;
pub use history::{DiagnosticHistory, GLOBAL_HISTORY};
pub use model::{Confidence, NetworkDiagnosis, NetworkIssue, OverallStatus, Severity};
pub use repair::{
    RepairAction, RepairExecutionReport, RepairExecutor, RepairLevel, RepairPlan, RepairPlanner,
};
pub use snapshot::{RollbackReport, SnapshotManager, SnapshotManifest};

#[cfg(test)]
mod tests;
