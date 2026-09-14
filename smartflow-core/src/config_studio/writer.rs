use anyhow::{bail, Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::info;

use super::{
    fingerprint::FingerprintDetector,
    model::{ConfigFormat, ConfigSaveResult},
    patch::AstPatcher,
    semantic::SemanticExtractor,
    validation::ConfigValidator,
};

pub struct SafeConfigWriter;

impl SafeConfigWriter {
    pub fn save(
        path: &Path,
        expected_sha256: &str,
        new_content: &str,
        format: ConfigFormat,
    ) -> Result<ConfigSaveResult> {
        if !path.exists() {
            bail!(
                "Target configuration file {} does not exist",
                path.display()
            );
        }

        // 1. Concurrency conflict check
        let current_raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let current_sha256 = FingerprintDetector::compute_hash(&current_raw);

        if !expected_sha256.is_empty() && current_sha256 != expected_sha256 {
            bail!(
                "并发修改冲突：文件在您编辑期间已被外部程序修改（哈希不匹配）。为防丢失外部改动，已阻止自动覆盖。"
            );
        }

        // 2. Validate proposed new content syntax
        let semantic = SemanticExtractor::extract(new_content, format);
        let validation = ConfigValidator::validate(new_content, format, &semantic);
        if !validation.valid {
            bail!("配置语法校验失败: {}", validation.errors.join("; "));
        }

        // 3. Create .bak backup
        let backup_path = Self::create_backup(path, &current_raw)?;

        // 4. Atomically replace using platform-aware write
        crate::config::atomic_write(path, new_content.as_bytes())
            .context("原子写入配置文件失败")?;

        let new_sha256 = FingerprintDetector::compute_hash(new_content);
        let diff = AstPatcher::generate_line_diff(&current_raw, new_content);

        info!(file = %path.display(), "safe atomic save completed");

        Ok(ConfigSaveResult {
            success: true,
            backup_path: Some(backup_path),
            new_sha256,
            diff,
        })
    }

    fn create_backup(path: &Path, content: &str) -> Result<PathBuf> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("config");

        let backup_file_name = format!("{file_name}.bak");
        let backup_path = parent.join(backup_file_name);

        fs::write(&backup_path, content)?;
        Ok(backup_path)
    }
}
