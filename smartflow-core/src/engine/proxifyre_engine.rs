use anyhow::Result;

use crate::{
    engine::{proxifyre::ProxifyreBackend, DataPlaneBackend, ProxyEngine},
    model::{AppConfig, DataPlaneStatus, EngineMode, ProcessInfo},
};

/// ProxyDuck's default application-routing engine backed by ProxiFyre/WinpkFilter.
pub struct ProxiFyreEngine {
    backend: Box<dyn DataPlaneBackend>,
}

impl Default for ProxiFyreEngine {
    fn default() -> Self {
        Self {
            backend: Box::new(ProxifyreBackend::new("proxifyre")),
        }
    }
}

impl ProxyEngine for ProxiFyreEngine {
    fn mode(&self) -> EngineMode {
        EngineMode::ProxiFyre
    }

    fn start(&self, config: &AppConfig) -> Result<()> {
        self.backend.start(config)
    }

    fn stop(&self) -> Result<()> {
        self.backend.stop()
    }

    fn reload_rules(&self, config: &AppConfig) -> Result<()> {
        self.backend.reload(config)
    }

    fn status(&self) -> DataPlaneStatus {
        self.backend.status()
    }

    fn maintain(&self, config: &AppConfig) -> Result<bool> {
        self.backend.maintain(config)
    }

    fn reconcile_processes(&self, config: &AppConfig, processes: &[ProcessInfo]) -> Result<bool> {
        self.backend.reconcile_processes(config, processes)
    }
}
