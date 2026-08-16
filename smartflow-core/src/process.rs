use std::process::Command;

use anyhow::{anyhow, Context, Result};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::model::{
    MatchKind, ProcessInfo, QuickBarItem, Rule, RuleConflict, RuleEvaluation, RuleEvaluationMatch,
    StartMode,
};

pub struct ResolvedRuleMatch<'a> {
    pub rule: &'a Rule,
    pub match_kind: MatchKind,
}

pub struct ProcessScanner {
    system: System,
}

impl ProcessScanner {
    pub fn new() -> Self {
        Self {
            system: System::new(),
        }
    }

    pub fn scan(&mut self) -> Vec<ProcessInfo> {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
        );

        let mut rows: Vec<ProcessInfo> = self
            .system
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
}

impl Default for ProcessScanner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn list_processes() -> Vec<ProcessInfo> {
    ProcessScanner::new().scan()
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

#[cfg(test)]
pub fn rule_matches_process(rule: &Rule, process: &ProcessInfo) -> bool {
    rule_match_kind(rule, process).is_some()
}

pub fn resolve_matching_rule<'a>(
    rules: &'a [Rule],
    process: &ProcessInfo,
) -> Option<ResolvedRuleMatch<'a>> {
    let mut best: Option<ResolvedRuleMatch<'a>> = None;

    for rule in rules.iter().filter(|rule| rule.enabled) {
        let Some(match_kind) = rule_match_kind(rule, process) else {
            continue;
        };

        let replace = match &best {
            Some(current) => match_kind < current.match_kind,
            None => true,
        };

        if replace {
            best = Some(ResolvedRuleMatch { rule, match_kind });
        }
    }

    best
}

pub fn evaluate_rules(rules: &[Rule], process: &ProcessInfo) -> RuleEvaluation {
    let mut matches = rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            rule_match_kind(rule, process).map(|match_kind| (index, rule, match_kind))
        })
        .collect::<Vec<_>>();
    matches.sort_by_key(|(index, _, match_kind)| (*match_kind, *index));

    RuleEvaluation {
        process: process.clone(),
        matches: matches
            .into_iter()
            .enumerate()
            .map(|(index, (_, rule, match_kind))| RuleEvaluationMatch {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                proxy_id: rule.proxy_profile.clone(),
                match_kind,
                selected: index == 0,
            })
            .collect(),
    }
}

pub fn detect_rule_conflicts(rules: &[Rule]) -> Vec<RuleConflict> {
    let enabled = rules.iter().filter(|rule| rule.enabled).collect::<Vec<_>>();
    let mut conflicts = Vec::new();
    for (index, first) in enabled.iter().enumerate() {
        for second in enabled.iter().skip(index + 1) {
            if let Some(reason) = overlap_reason(first, second) {
                conflicts.push(RuleConflict {
                    first_rule_id: first.id.clone(),
                    first_rule_name: first.name.clone(),
                    second_rule_id: second.id.clone(),
                    second_rule_name: second.name.clone(),
                    reason,
                });
            }
        }
    }
    conflicts
}

fn overlap_reason(first: &Rule, second: &Rule) -> Option<String> {
    if first
        .matcher
        .pids
        .iter()
        .any(|pid| second.matcher.pids.contains(pid))
    {
        return Some("same PID matcher".to_string());
    }
    if patterns_overlap(&first.matcher.exe_paths, &second.matcher.exe_paths) {
        return Some("overlapping executable-path matcher".to_string());
    }
    if patterns_overlap(&first.matcher.app_names, &second.matcher.app_names) {
        return Some("overlapping process-name matcher".to_string());
    }
    match (&first.matcher.wildcard, &second.matcher.wildcard) {
        (Some(left), Some(right)) if text_patterns_overlap(left, right) => {
            Some("overlapping wildcard matcher".to_string())
        }
        _ => None,
    }
}

fn patterns_overlap(first: &[String], second: &[String]) -> bool {
    first.iter().any(|left| {
        second
            .iter()
            .any(|right| text_patterns_overlap(left, right))
    })
}

fn text_patterns_overlap(first: &str, second: &str) -> bool {
    let first = first.trim().to_ascii_lowercase();
    let second = second.trim().to_ascii_lowercase();
    !first.is_empty()
        && !second.is_empty()
        && (first == second || glob_matches(&first, &second) || glob_matches(&second, &first))
}

pub fn rule_priority(rule: &Rule) -> MatchKind {
    if !rule.matcher.pids.is_empty() {
        MatchKind::Pid
    } else if !rule.matcher.exe_paths.is_empty() {
        MatchKind::ExePath
    } else if !rule.matcher.app_names.is_empty() {
        MatchKind::AppName
    } else {
        MatchKind::Wildcard
    }
}

pub fn rule_match_kind(rule: &Rule, process: &ProcessInfo) -> Option<MatchKind> {
    if !rule.enabled {
        return None;
    }

    let lower_name = process.name.trim().to_ascii_lowercase();
    let lower_exe = normalize_executable_path(&process.exe);

    if rule.matcher.pids.contains(&process.pid) {
        return Some(MatchKind::Pid);
    }

    if rule
        .matcher
        .exe_paths
        .iter()
        .any(|path| lower_exe == normalize_executable_path(path))
    {
        return Some(MatchKind::ExePath);
    }

    if rule
        .matcher
        .app_names
        .iter()
        .any(|name| lower_name == name.trim().to_ascii_lowercase())
    {
        return Some(MatchKind::AppName);
    }

    if let Some(wildcard) = &rule.matcher.wildcard {
        let pattern = wildcard.trim().to_ascii_lowercase().replace('/', "\\");
        if !pattern.is_empty()
            && (glob_matches(&pattern, &lower_name) || glob_matches(&pattern, &lower_exe))
        {
            return Some(MatchKind::Wildcard);
        }
    }

    None
}

fn normalize_executable_path(path: &str) -> String {
    let mut normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    if let Some(stripped) = normalized.strip_prefix("\\\\?\\") {
        normalized = stripped.to_string();
    }
    while normalized.len() > 3 && normalized.ends_with('\\') {
        normalized.pop();
    }
    normalized
}

/// Matches a complete string using the two portable glob tokens supported by the
/// configuration format: `*` for any sequence and `?` for one character.
fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0usize, 0usize);
    let (mut star_index, mut star_value_index) = (None, 0usize);

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MatchCriteria;

    #[test]
    fn test_rule_matches_process() {
        let matcher = MatchCriteria {
            app_names: vec!["node.exe".to_string()],
            ..MatchCriteria::default()
        };

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
        rule.matcher.exe_paths = vec!["C:/python.exe".to_string()];
        assert!(rule_matches_process(&rule, &p3));

        rule.matcher.exe_paths.clear();
        rule.matcher.wildcard = Some("*python*".to_string());
        assert!(rule_matches_process(&rule, &p3));

        rule.matcher.wildcard = None;
        rule.matcher.pids = vec![100];
        assert!(rule_matches_process(&rule, &p1));
        assert!(!rule_matches_process(&rule, &p2));
    }

    #[test]
    fn pid_match_has_higher_priority_than_name_match() {
        let process = ProcessInfo {
            pid: 42,
            name: "node.exe".to_string(),
            exe: "C:\\Program Files\\nodejs\\node.exe".to_string(),
        };

        let name_rule = Rule::new(
            "name".to_string(),
            MatchCriteria {
                app_names: vec!["node.exe".to_string()],
                ..Default::default()
            },
            "proxy-a".to_string(),
        );

        let pid_rule = Rule::new(
            "pid".to_string(),
            MatchCriteria {
                pids: vec![42],
                ..Default::default()
            },
            "proxy-b".to_string(),
        );

        let rules = vec![name_rule, pid_rule];
        let matched = resolve_matching_rule(&rules, &process).unwrap();
        assert_eq!(matched.rule.name, "pid");
        assert_eq!(matched.match_kind, MatchKind::Pid);
    }

    #[test]
    fn evaluation_explains_the_full_match_chain() {
        let process = ProcessInfo {
            pid: 42,
            name: "node.exe".to_string(),
            exe: "C:\\Node\\node.exe".to_string(),
        };
        let name = Rule::new(
            "name".to_string(),
            MatchCriteria {
                app_names: vec!["node.exe".to_string()],
                ..Default::default()
            },
            "a".to_string(),
        );
        let pid = Rule::new(
            "pid".to_string(),
            MatchCriteria {
                pids: vec![42],
                ..Default::default()
            },
            "b".to_string(),
        );
        let evaluation = evaluate_rules(&[name, pid], &process);
        assert_eq!(evaluation.matches.len(), 2);
        assert_eq!(evaluation.matches[0].rule_name, "pid");
        assert!(evaluation.matches[0].selected);
        assert!(!evaluation.matches[1].selected);
    }

    #[test]
    fn exact_name_match_does_not_treat_substrings_as_overlaps() {
        let first = Rule::new(
            "broad".to_string(),
            MatchCriteria {
                app_names: vec!["code".to_string()],
                ..Default::default()
            },
            "a".to_string(),
        );
        let second = Rule::new(
            "specific".to_string(),
            MatchCriteria {
                app_names: vec!["code.exe".to_string()],
                ..Default::default()
            },
            "b".to_string(),
        );
        let conflicts = detect_rule_conflicts(&[first, second]);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn path_and_name_matchers_are_exact_and_case_insensitive() {
        let process = ProcessInfo {
            pid: 7,
            name: "Code.EXE".to_string(),
            exe: "C:\\Apps\\Code.exe".to_string(),
        };
        let exact = Rule::new(
            "exact".to_string(),
            MatchCriteria {
                exe_paths: vec!["c:/apps/code.EXE".to_string()],
                app_names: vec!["code.exe".to_string()],
                ..Default::default()
            },
            "proxy".to_string(),
        );
        assert_eq!(rule_match_kind(&exact, &process), Some(MatchKind::ExePath));

        let substring = Rule::new(
            "substring".to_string(),
            MatchCriteria {
                exe_paths: vec!["Code.exe".to_string()],
                app_names: vec!["code".to_string()],
                ..Default::default()
            },
            "proxy".to_string(),
        );
        assert!(!rule_matches_process(&substring, &process));
    }

    #[test]
    fn wildcard_matcher_uses_anchored_glob_semantics() {
        let process = ProcessInfo {
            pid: 7,
            name: "code.exe".to_string(),
            exe: "C:\\Apps\\code.exe".to_string(),
        };
        for pattern in ["*.exe", "code.?xe", "C:/Apps/*"] {
            let rule = Rule::new(
                pattern.to_string(),
                MatchCriteria {
                    wildcard: Some(pattern.to_string()),
                    ..Default::default()
                },
                "proxy".to_string(),
            );
            assert!(rule_matches_process(&rule, &process), "pattern: {pattern}");
        }

        let literal = Rule::new(
            "literal".to_string(),
            MatchCriteria {
                wildcard: Some("code".to_string()),
                ..Default::default()
            },
            "proxy".to_string(),
        );
        assert!(!rule_matches_process(&literal, &process));
    }
}
