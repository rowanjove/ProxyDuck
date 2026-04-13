use anyhow::Result;

use crate::{
    engine::{proxifyre::ProxifyreBackend, DataPlaneBackend, ProxyEngine},
    model::{AppConfig, EngineMode},
};

pub struct WinDivertEngine {
    backend: Box<dyn DataPlaneBackend>,
}

impl Default for WinDivertEngine {
    fn default() -> Self {
        Self {
            backend: Box::new(ProxifyreBackend::new("windivert")),
        }
    }
}

impl ProxyEngine for WinDivertEngine {
    fn mode(&self) -> EngineMode {
        EngineMode::WinDivert
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
}
