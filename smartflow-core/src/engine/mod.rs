mod api_hook;
mod proxifyre;
mod wfp;
mod windivert;

use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::Utc;
use parking_lot::RwLock;

use crate::model::{AppConfig, EngineMode, RuntimeStats};

pub use api_hook::ApiHookEngine;
pub use wfp::WfpEngine;
pub use windivert::WinDivertEngine;

pub trait DataPlaneBackend: Send + Sync {
    fn start(&self, config: &AppConfig) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn reload(&self, config: &AppConfig) -> Result<()>;
}

pub trait ProxyEngine: Send + Sync {
    fn mode(&self) -> EngineMode;
    fn start(&self, config: &AppConfig) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn reload_rules(&self, config: &AppConfig) -> Result<()>;
}

pub struct EngineManager {
    active: RwLock<Box<dyn ProxyEngine>>,
    stats: Arc<RwLock<RuntimeStats>>,
}

impl EngineManager {
    pub fn new(mode: EngineMode, stats: Arc<RwLock<RuntimeStats>>) -> Self {
        let engine = create_engine(mode);
        Self {
            active: RwLock::new(engine),
            stats,
        }
    }

    pub fn mode(&self) -> EngineMode {
        self.active.read().mode()
    }

    pub fn start(&self, config: &AppConfig) -> Result<()> {
        self.active.read().start(config)?;
        let mut stats = self.stats.write();
        stats.engine_mode = mode_name(self.mode());
        stats.started_at = Some(Utc::now());
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        self.active.read().stop()
    }

    pub fn reload_rules(&self, config: &AppConfig) -> Result<()> {
        self.active.read().reload_rules(config)?;
        self.stats.write().last_reload_at = Some(Utc::now());
        Ok(())
    }

    pub fn switch_mode(&self, mode: EngineMode, config: &AppConfig) -> Result<()> {
        if mode_name(self.mode()) == mode_name(mode.clone()) {
            return Ok(());
        }

        self.active.read().stop()?;

        let next = create_engine(mode.clone());
        next.start(config)?;

        {
            let mut active = self.active.write();
            *active = next;
        }

        self.stats.write().engine_mode = mode_name(mode);
        Ok(())
    }
}

fn create_engine(mode: EngineMode) -> Box<dyn ProxyEngine> {
    match mode {
        EngineMode::WinDivert => Box::new(WinDivertEngine::default()),
        EngineMode::Wfp => Box::new(WfpEngine::default()),
        EngineMode::ApiHook => Box::new(ApiHookEngine::default()),
    }
}

pub fn mode_name(mode: EngineMode) -> String {
    match mode {
        EngineMode::WinDivert => "windivert",
        EngineMode::Wfp => "wfp",
        EngineMode::ApiHook => "api_hook",
    }
    .to_string()
}

pub fn validate_clash_profile(config: &AppConfig) -> Result<()> {
    let has_enabled = config.proxies.iter().any(|proxy| proxy.enabled);
    if !has_enabled {
        return Err(anyhow!("no enabled proxy profiles found"));
    }
    Ok(())
}
