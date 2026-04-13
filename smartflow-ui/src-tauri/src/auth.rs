use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use uuid::Uuid;

const TOKEN_FILE: &str = "token";

pub fn load_or_create_token() -> Result<String> {
    let path = resolve_token_path()?;
    if path.exists() {
        let token = fs::read_to_string(&path)
            .with_context(|| format!("failed to read auth token: {}", path.display()))?;
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    fs::write(&path, &token)
        .with_context(|| format!("failed to write auth token: {}", path.display()))?;
    Ok(token)
}

fn resolve_token_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("com", "SmartFlow", "SmartFlow")
        .context("unable to resolve SmartFlow data directory")?;
    let config_dir = dirs.config_dir();
    fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create config dir {}", config_dir.display()))?;
    Ok(config_dir.join(TOKEN_FILE))
}
