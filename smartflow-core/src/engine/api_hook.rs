use anyhow::Result;

use crate::{
    engine::{proxifyre::ProxifyreBackend, DataPlaneBackend, ProxyEngine},
    model::{AppConfig, EngineMode},
};

pub struct ApiHookEngine {
    backend: Box<dyn DataPlaneBackend>,
}

impl Default for ApiHookEngine {
    fn default() -> Self {
        Self {
            backend: Box::new(ProxifyreBackend::new("api_hook")),
        }
    }
}

impl ProxyEngine for ApiHookEngine {
    fn mode(&self) -> EngineMode {
        EngineMode::ApiHook
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
