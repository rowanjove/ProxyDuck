use std::process::Command;

use anyhow::{anyhow, Context, Result};
use sysinfo::System;

use crate::model::{ProcessInfo, QuickBarItem, Rule, StartMode};

pub fn list_processes() -> Vec<ProcessInfo> {
    let mut system = System::new_all();
    system.refresh_all();

    let mut rows: Vec<ProcessInfo> = system
        .processes()
        .iter()
        .map(|(pid, process)| ProcessInfo {
            pid: pid.as_u32(),
            name: process.name().to_string_lossy().to_string(),
            exe: process
                .exe()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
        })
        .collect();

    rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    rows
}

pub fn launch_quick_bar_item(item: &QuickBarItem) -> Result<()> {
    match item.start_mode {
        StartMode::BindOnly => {
            tracing::info!(item = %item.name, "bind_only mode selected; no process launch performed");
            return Ok(());
        }
        StartMode::StartOnly | StartMode::StartAndBind => {}
    }

    if item.run_as_admin {
        launch_as_admin(item)
    } else {
        launch_normal(item)
    }
}

fn launch_normal(item: &QuickBarItem) -> Result<()> {
    let mut cmd = Command::new(&item.exe_path);
    cmd.args(&item.args);

    if let Some(work_dir) = item.work_dir.as_deref() {
        cmd.current_dir(work_dir);
    }

    cmd.spawn()
        .with_context(|| format!("failed to launch {}", item.exe_path))?;

    Ok(())
}

fn launch_as_admin(item: &QuickBarItem) -> Result<()> {
    if cfg!(windows) {
        let args = item.args.join(" ");
        let work_dir = item.work_dir.clone().unwrap_or_else(|| ".".to_string());

        let escaped_file = item.exe_path.replace("'", "''");
        let escaped_args = args.replace("'", "''");
        let escaped_dir = work_dir.replace("'", "''");

        let script = format!(
            "Start-Process -FilePath '{}' -ArgumentList '{}' -WorkingDirectory '{}' -Verb RunAs",
            escaped_file, escaped_args, escaped_dir
        );

        let status = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(script)
            .status()
            .context("failed to request admin launch")?;

        if !status.success() {
            return Err(anyhow!("admin launch failed"));
        }

        return Ok(());
    }

    Err(anyhow!("run_as_admin is only supported on Windows"))
}

pub fn rule_matches_process(rule: &Rule, process: &ProcessInfo) -> bool {
    if !rule.enabled {
        return false;
    }

    let lower_name = process.name.to_lowercase();
    let lower_exe = process.exe.to_lowercase();

    if rule
        .matcher
        .app_names
        .iter()
        .any(|name| lower_name.contains(&name.to_lowercase()))
    {
        return true;
    }

    if rule
        .matcher
        .exe_paths
        .iter()
        .any(|path| lower_exe.contains(&path.to_lowercase()))
    {
        return true;
    }

    if rule.matcher.pids.contains(&process.pid) {
        return true;
    }

    if let Some(wildcard) = &rule.matcher.wildcard {
        let w = wildcard.to_lowercase();
        if lower_name.contains(&w) || lower_exe.contains(&w) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MatchCriteria;

    #[test]
    fn test_rule_matches_process() {
        let mut matcher = MatchCriteria::default();
        matcher.app_names = vec!["node.exe".to_string()];

        let mut rule = Rule::new("test".to_string(), matcher, "p".to_string());

        let p1 = ProcessInfo {
            pid: 100,
            name: "node.exe".to_string(),
            exe: "C:\\Program Files\\nodejs\\node.exe".to_string(),
        };
        assert!(rule_matches_process(&rule, &p1));

        let p2 = ProcessInfo {
            pid: 101,
            name: "NoDe.ExE".to_string(),
            exe: "C:\\node.exe".to_string(),
        };
        assert!(rule_matches_process(&rule, &p2));

        let p3 = ProcessInfo {
            pid: 102,
            name: "python.exe".to_string(),
            exe: "C:\\python.exe".to_string(),
        };
        assert!(!rule_matches_process(&rule, &p3));

        rule.enabled = false;
        assert!(!rule_matches_process(&rule, &p1));

        rule.enabled = true;
        rule.matcher.app_names.clear();
        rule.matcher.exe_paths = vec!["python.exe".to_string()];
        assert!(rule_matches_process(&rule, &p3));

        rule.matcher.exe_paths.clear();
        rule.matcher.wildcard = Some("python".to_string());
        assert!(rule_matches_process(&rule, &p3));

        rule.matcher.wildcard = None;
        rule.matcher.pids = vec![100];
        assert!(rule_matches_process(&rule, &p1));
        assert!(!rule_matches_process(&rule, &p2));
    }
}
