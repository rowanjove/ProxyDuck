use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::config;

const TOKEN_FILE: &str = "token";

pub fn resolve_token_path() -> Result<PathBuf> {
    Ok(config::resolve_app_dir()?.join(TOKEN_FILE))
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_is_hex_and_expected_length() {
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|ch| ch.is_ascii_hexdigit()));
    }
}
