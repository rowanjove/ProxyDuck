use chrono::{DateTime, Utc};
use std::{
    fs,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};
use tracing::info;

use super::{fingerprint::FingerprintDetector, model::ConfigFileSummary};

const MAX_SEARCH_DEPTH: usize = 4;
const MAX_FILE_SIZE_BYTES: u64 = 5 * 1024 * 1024; // 5 MB
const MAX_DISCOVERED_FILES: usize = 100;

pub fn validate_safe_config_path(path: &Path) -> anyhow::Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str.trim().is_empty() {
        anyhow::bail!("配置路径不能为空");
    }

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    if !matches!(
        ext.as_str(),
        "yaml" | "yml" | "json" | "jsonc" | "json5" | "toml" | "pac" | "conf"
    ) {
        anyhow::bail!("不受支持的配置文件扩展名: .{ext}");
    }

    if path.is_dir() {
        anyhow::bail!("指定路径是目录而非配置文件");
    }

    let canonical = if path.exists() {
        fs::canonicalize(path)?
    } else if let Some(parent) = path.parent() {
        if parent.exists() {
            fs::canonicalize(parent)?.join(path.file_name().unwrap_or_default())
        } else {
            path.to_path_buf()
        }
    } else {
        path.to_path_buf()
    };

    let canonical_lower = canonical.to_string_lossy().to_lowercase();

    #[cfg(target_os = "windows")]
    {
        let win_dir = std::env::var("SystemRoot")
            .unwrap_or_else(|_| "c:\\windows".to_string())
            .to_lowercase();
        if canonical_lower.starts_with(&win_dir) {
            anyhow::bail!("禁止访问 Windows 系统目录中的文件: {}", canonical.display());
        }
        if canonical_lower.contains("programdata\\microsoft")
            || canonical_lower.contains("system32")
            || canonical_lower.contains("syswow64")
        {
            anyhow::bail!("禁止访问系统关键目录: {}", canonical.display());
        }
    }

    Ok(canonical)
}

pub struct ConfigDiscoveryScanner;

impl ConfigDiscoveryScanner {
    pub fn discover_all(custom_paths: &[PathBuf]) -> Vec<ConfigFileSummary> {
        let mut search_roots = Vec::new();

        let known_proxy_dirs = [
            "v2rayN",
            "clash",
            "clash-verge",
            "clash-verge-rev",
            "clash-nyanpasu",
            "clash_win",
            "sing-box",
            "nekoray",
            "nekobox",
            "mihomo",
            "flclash",
            "Hiddify",
            "ProxyDuck",
            "ProxyDock",
            "SmartFlow",
        ];

        // 1. Windows AppData & LocalAppData - target known directories first
        if let Ok(appdata) = std::env::var("APPDATA") {
            let base = PathBuf::from(&appdata);
            for dir in known_proxy_dirs {
                let candidate = base.join(dir);
                if candidate.exists() {
                    search_roots.push(candidate);
                }
            }
        }
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let base = PathBuf::from(&local_appdata);
            for dir in known_proxy_dirs {
                let candidate = base.join(dir);
                if candidate.exists() {
                    search_roots.push(candidate);
                }
            }
        }

        // 2. User home .config
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let dot_config = PathBuf::from(userprofile).join(".config");
            if dot_config.exists() {
                search_roots.push(dot_config);
            }
        }

        // 3. Custom paths
        for p in custom_paths {
            if p.exists() && !search_roots.contains(p) {
                search_roots.push(p.clone());
            }
        }

        let mut discovered = Vec::new();
        for root in search_roots {
            Self::scan_directory(&root, 0, &mut discovered);
            if discovered.len() >= MAX_DISCOVERED_FILES {
                break;
            }
        }

        info!(count = discovered.len(), "config discovery scan completed");
        discovered
    }

    fn scan_directory(dir: &Path, depth: usize, results: &mut Vec<ConfigFileSummary>) {
        if depth > MAX_SEARCH_DEPTH || results.len() >= MAX_DISCOVERED_FILES {
            return;
        }

        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            if results.len() >= MAX_DISCOVERED_FILES {
                return;
            }
            let path = entry.path();
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            // Skip ignored directories & files
            if Self::is_ignored_name(&file_name) {
                continue;
            }

            if path.is_dir() {
                Self::scan_directory(&path, depth + 1, results);
            } else if path.is_file() {
                if let Some(summary) = Self::probe_candidate_file(&path) {
                    results.push(summary);
                }
            }
        }
    }

    fn is_ignored_name(name: &str) -> bool {
        matches!(
            name,
            "node_modules"
                | ".git"
                | ".svn"
                | "cache"
                | "code cache"
                | "gpucache"
                | "crashpad"
                | "logs"
                | "temp"
                | "tmp"
                | "package.json"
                | "package-lock.json"
                | "tsconfig.json"
        ) || name.ends_with(".log")
            || name.ends_with(".lock")
            || name.ends_with(".exe")
            || name.ends_with(".dll")
    }

    fn probe_candidate_file(path: &Path) -> Option<ConfigFileSummary> {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !matches!(
            ext.as_str(),
            "yaml" | "yml" | "json" | "jsonc" | "toml" | "pac"
        ) {
            return None;
        }

        let metadata = fs::metadata(path).ok()?;
        let size = metadata.len();
        if size == 0 || size > MAX_FILE_SIZE_BYTES {
            return None;
        }

        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .and_then(|d| DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos()))
            .map(|dt: DateTime<Utc>| dt.to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339());

        // Read sample content for fingerprinting
        let content = fs::read_to_string(path).ok()?;
        let fp = FingerprintDetector::detect(path, &content);

        // Filter out completely generic unrelated JSONs unless they match routing or are in config directories
        if fp.format == super::model::ConfigFormat::Unknown {
            return None;
        }

        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("config")
            .to_string();

        let sha256 = FingerprintDetector::compute_hash(&content);
        let id = format!("cfg_{}", &sha256[..12]);

        Some(ConfigFileSummary {
            id,
            file_name,
            path: path.to_path_buf(),
            format: fp.format,
            fingerprint: fp.fingerprint,
            size_bytes: size,
            mtime_rfc3339: mtime,
            sha256,
            editable: fp.editable,
            provider_id: fp.provider_id.to_string(),
        })
    }
}
