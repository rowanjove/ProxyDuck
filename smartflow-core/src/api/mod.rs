use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    process::{Command, Stdio},
};

use anyhow::Result;
use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

use crate::{
    model::{
        AppConfig, EngineCapability, EngineMode, HealthStatus, MatchCriteria, MatchEvent,
        ProcessInfo, ProxyHitStat, ProxyProfile, ProxyTestResult, QuickBarItem, Rule, RuleHitStat,
        RuleSource, RuntimeStats, RuntimeStatus, StartMode, UiLogEvent,
    },
    process::launch_quick_bar_item,
    state::CoreState,
};

pub async fn run_http(state: CoreState, bind: SocketAddr) -> Result<()> {
    let app = router(state.clone());
    tracing::info!(addr = %bind, "proxyduck-core api listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = state.engine.stop();
            }
        })
        .await?;
    Ok(())
}

fn router(state: CoreState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/capabilities", get(get_capabilities))
        .route("/snapshot", get(get_live_snapshot))
        .route("/config", get(get_config).put(put_config))
        .route("/stats", get(get_stats))
        .route("/stats/rules", get(get_rule_stats))
        .route("/stats/proxies", get(get_proxy_stats))
        .route("/stats/hits", get(get_recent_hits))
        .route("/logs", get(get_logs))
        .route("/icon/exe", get(get_exe_icon))
        .route("/processes", get(get_processes))
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/conflicts", get(get_rule_conflicts))
        .route("/rules/reorder", post(reorder_rules))
        .route("/rules/evaluate/:pid", get(evaluate_rules_for_process))
        .route("/rules/:id/duplicate", post(duplicate_rule))
        .route("/rules/:id", put(update_rule).delete(delete_rule))
        .route("/quickbar", get(list_quickbar).post(create_quickbar))
        .route(
            "/quickbar/:id",
            put(update_quickbar).delete(delete_quickbar),
        )
        .route("/quickbar/:id/launch", post(launch_quickbar))
        .route("/proxies", get(list_proxies).post(create_proxy))
        .route("/proxies/:id", put(update_proxy).delete(delete_proxy))
        .route("/proxies/:id/test", post(test_proxy_endpoint))
        .route("/engine/mode", post(change_engine_mode))
        .route("/runtime", post(update_runtime))
        .route("/runtime/status", get(get_runtime_status))
        .route("/templates/ai-dev", post(apply_ai_dev_template))
        .route("/lifecycle/shutdown", post(shutdown))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin, _| {
                    is_allowed_local_origin(origin)
                }))
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn require_auth(
    State(state): State<CoreState>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ApiErrorBody>)> {
    if request.method() == Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    let token = request
        .headers()
        .get(proxyduck_common::AUTH_HEADER)
        .or_else(|| {
            request
                .headers()
                .get(proxyduck_common::PREVIOUS_AUTH_HEADER)
        })
        .or_else(|| request.headers().get(proxyduck_common::LEGACY_AUTH_HEADER))
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    if token == Some(state.auth_token.as_str()) {
        return Ok(next.run(request).await);
    }

    Err(err(
        StatusCode::UNAUTHORIZED,
        "missing or invalid X-ProxyDuck-Token",
    ))
}

fn is_allowed_local_origin(origin: &HeaderValue) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };

    let normalized = origin.trim().trim_end_matches('/').to_ascii_lowercase();
    if normalized == "tauri://localhost" {
        return true;
    }

    let Some((scheme, remainder)) = normalized.split_once("://") else {
        return false;
    };

    if !matches!(scheme, "http" | "https") {
        return false;
    }

    let authority = remainder.split('/').next().unwrap_or(remainder);
    let host = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .unwrap_or(authority)
            .trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or(authority)
    };

    matches!(host, "localhost" | "127.0.0.1" | "::1" | "tauri.localhost")
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiResponse<T> {
    ok: bool,
    data: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    ok: bool,
    error: String,
}

fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse { ok: true, data })
}

fn err(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<ApiErrorBody>) {
    (
        status,
        Json(ApiErrorBody {
            ok: false,
            error: message.into(),
        }),
    )
}

async fn health(State(state): State<CoreState>) -> Json<ApiResponse<HealthStatus>> {
    let cfg = state.config_snapshot();
    ok(HealthStatus {
        status: "ok".to_string(),
        version: cfg.version,
        engine_mode: crate::engine::mode_name(cfg.engine_mode),
    })
}

async fn get_capabilities() -> Json<ApiResponse<Vec<EngineCapability>>> {
    ok(crate::engine::engine_capabilities())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LiveSnapshot {
    health: HealthStatus,
    runtime_status: RuntimeStatus,
    stats: RuntimeStats,
    rule_stats: Vec<RuleHitStat>,
    proxy_stats: Vec<ProxyHitStat>,
    recent_hits: Vec<MatchEvent>,
    logs: Vec<UiLogEvent>,
}

async fn get_live_snapshot(State(state): State<CoreState>) -> Json<ApiResponse<LiveSnapshot>> {
    let config = state.config_snapshot();
    ok(LiveSnapshot {
        health: HealthStatus {
            status: "ok".to_string(),
            version: config.version,
            engine_mode: crate::engine::mode_name(config.engine_mode),
        },
        runtime_status: state.runtime_status(),
        stats: state.stats_snapshot(),
        rule_stats: state.list_rule_hit_stats(),
        proxy_stats: state.list_proxy_hit_stats(),
        recent_hits: state.list_recent_matches(),
        logs: state.list_logs(),
    })
}

async fn get_config(State(state): State<CoreState>) -> Json<ApiResponse<AppConfig>> {
    ok(state.config_snapshot())
}

async fn put_config(
    State(state): State<CoreState>,
    Json(payload): Json<AppConfig>,
) -> impl IntoResponse {
    match state.replace_config(payload) {
        Ok(cfg) => {
            state.add_log(UiLogEvent::new("info", "api", "config updated"));
            ok(cfg).into_response()
        }
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn get_stats(State(state): State<CoreState>) -> Json<ApiResponse<RuntimeStats>> {
    ok(state.stats_snapshot())
}

async fn get_runtime_status(State(state): State<CoreState>) -> Json<ApiResponse<RuntimeStatus>> {
    ok(state.runtime_status())
}

async fn get_rule_stats(State(state): State<CoreState>) -> Json<ApiResponse<Vec<RuleHitStat>>> {
    ok(state.list_rule_hit_stats())
}

async fn get_proxy_stats(State(state): State<CoreState>) -> Json<ApiResponse<Vec<ProxyHitStat>>> {
    ok(state.list_proxy_hit_stats())
}

async fn get_recent_hits(State(state): State<CoreState>) -> Json<ApiResponse<Vec<MatchEvent>>> {
    ok(state.list_recent_matches())
}

async fn get_logs(State(state): State<CoreState>) -> Json<ApiResponse<Vec<UiLogEvent>>> {
    ok(state.list_logs())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExeIconQuery {
    exe_path: String,
}

async fn get_exe_icon(Query(query): Query<ExeIconQuery>) -> impl IntoResponse {
    match extract_exe_icon_data_url(&query.exe_path) {
        Ok(icon_data_url) => ok(icon_data_url).into_response(),
        Err(message) => err(StatusCode::BAD_REQUEST, message).into_response(),
    }
}

fn extract_exe_icon_data_url(exe_path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let normalized_path = exe_path.trim();
        if normalized_path.is_empty() {
            return Err("exe path is empty".to_string());
        }

        let script = r#"
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$p=$env:PROXYDUCK_ICON_PATH
if ([string]::IsNullOrWhiteSpace($p)) { throw 'empty exe path' }
if (!(Test-Path -LiteralPath $p)) { throw 'exe path not found' }
$icon=[System.Drawing.Icon]::ExtractAssociatedIcon($p)
if ($null -eq $icon) { throw 'icon not found' }
$bmp=$icon.ToBitmap()
$ms=New-Object System.IO.MemoryStream
try {
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
  [Convert]::ToBase64String($ms.ToArray())
} finally {
  $ms.Dispose()
  $bmp.Dispose()
  $icon.Dispose()
}
"#;

        let output = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(script)
            .env("PROXYDUCK_ICON_PATH", normalized_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|error| format!("failed to resolve icon: {error}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("icon extract failed: {}", stderr.trim()));
        }

        let icon_base64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if icon_base64.is_empty() {
            return Err("icon extract returned empty output".to_string());
        }

        Ok(format!("data:image/png;base64,{icon_base64}"))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = exe_path;
        Err("exe icon extraction is only supported on Windows".to_string())
    }
}

async fn get_processes(State(state): State<CoreState>) -> Json<ApiResponse<Vec<ProcessInfo>>> {
    ok(state.list_processes())
}

async fn list_rules(State(state): State<CoreState>) -> Json<ApiResponse<Vec<Rule>>> {
    ok(state.config.read().rules.clone())
}

async fn get_rule_conflicts(
    State(state): State<CoreState>,
) -> Json<ApiResponse<Vec<crate::model::RuleConflict>>> {
    ok(crate::process::detect_rule_conflicts(
        &state.config.read().rules,
    ))
}

async fn evaluate_rules_for_process(
    State(state): State<CoreState>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    let process = state
        .list_processes()
        .into_iter()
        .find(|process| process.pid == pid);
    let Some(process) = process else {
        return err(
            StatusCode::NOT_FOUND,
            "process not found in the latest snapshot",
        )
        .into_response();
    };
    ok(crate::process::evaluate_rules(
        &state.config.read().rules,
        &process,
    ))
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleReorderRequest {
    rule_ids: Vec<String>,
}

async fn reorder_rules(
    State(state): State<CoreState>,
    Json(payload): Json<RuleReorderRequest>,
) -> impl IntoResponse {
    let current_ids = state
        .config
        .read()
        .rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<HashSet<_>>();
    let requested_ids = payload.rule_ids.iter().cloned().collect::<HashSet<_>>();
    if payload.rule_ids.len() != requested_ids.len() || current_ids != requested_ids {
        return err(
            StatusCode::BAD_REQUEST,
            "ruleIds must contain every rule exactly once",
        )
        .into_response();
    }

    let positions = payload
        .rule_ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| (id, index))
        .collect::<HashMap<_, _>>();
    match state.mutate_config(|cfg| {
        cfg.rules
            .sort_by_key(|rule| positions.get(&rule.id).copied().unwrap_or(usize::MAX));
        cfg.rules.clone()
    }) {
        Ok(rules) => ok(rules).into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn duplicate_rule(
    State(state): State<CoreState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let source = state
        .config
        .read()
        .rules
        .iter()
        .find(|rule| rule.id == id)
        .cloned();
    let Some(mut duplicate) = source else {
        return err(StatusCode::NOT_FOUND, "rule not found").into_response();
    };
    let now = Utc::now();
    duplicate.id = uuid::Uuid::new_v4().to_string();
    duplicate.name = format!("{} Copy", duplicate.name);
    duplicate.source = RuleSource::User;
    duplicate.managed_by_quickbar_id = None;
    duplicate.created_at = now;
    duplicate.updated_at = now;

    match state.mutate_config(|cfg| {
        cfg.rules.push(duplicate.clone());
        duplicate.clone()
    }) {
        Ok(rule) => ok(rule).into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleUpsert {
    name: String,
    matcher: MatchCriteria,
    proxy_profile: String,
    protocols: Option<Vec<crate::model::Protocol>>,
    auto_bind_children: Option<bool>,
    force_dns: Option<bool>,
    block_ipv6: Option<bool>,
    block_doh: Option<bool>,
    enabled: Option<bool>,
}

async fn create_rule(
    State(state): State<CoreState>,
    Json(payload): Json<RuleUpsert>,
) -> impl IntoResponse {
    let mut rule = Rule::new(payload.name, payload.matcher, payload.proxy_profile);

    if let Some(protocols) = payload.protocols {
        rule.protocols = protocols;
    }
    if let Some(auto_bind_children) = payload.auto_bind_children {
        rule.auto_bind_children = auto_bind_children;
    }
    if let Some(force_dns) = payload.force_dns {
        rule.force_dns = force_dns;
    }
    if let Some(block_ipv6) = payload.block_ipv6 {
        rule.block_ipv6 = block_ipv6;
    }
    if let Some(block_doh) = payload.block_doh {
        rule.block_doh = block_doh;
    }
    if let Some(enabled) = payload.enabled {
        rule.enabled = enabled;
    }

    let result = state.mutate_config(|cfg| {
        cfg.rules.push(rule.clone());
        rule.clone()
    });

    match result {
        Ok(saved) => {
            state.add_log(UiLogEvent::new(
                "info",
                "rule",
                format!("rule created: {}", saved.name),
            ));
            ok(saved).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn update_rule(
    State(state): State<CoreState>,
    Path(id): Path<String>,
    Json(payload): Json<RuleUpsert>,
) -> impl IntoResponse {
    if is_quickbar_managed_rule(&state, &id) {
        return err(
            StatusCode::BAD_REQUEST,
            "quick bar managed rules must be edited via /quickbar",
        )
        .into_response();
    }

    let result = state.mutate_config(|cfg| {
        cfg.rules.iter_mut().find(|rule| rule.id == id).map(|rule| {
            rule.name = payload.name;
            rule.matcher = payload.matcher;
            rule.proxy_profile = payload.proxy_profile;
            if let Some(protocols) = payload.protocols {
                rule.protocols = protocols;
            }
            if let Some(auto_bind_children) = payload.auto_bind_children {
                rule.auto_bind_children = auto_bind_children;
            }
            if let Some(force_dns) = payload.force_dns {
                rule.force_dns = force_dns;
            }
            if let Some(block_ipv6) = payload.block_ipv6 {
                rule.block_ipv6 = block_ipv6;
            }
            if let Some(block_doh) = payload.block_doh {
                rule.block_doh = block_doh;
            }
            if let Some(enabled) = payload.enabled {
                rule.enabled = enabled;
            }
            rule.updated_at = Utc::now();
            rule.clone()
        })
    });

    match result {
        Ok(Some(saved)) => {
            state.add_log(UiLogEvent::new(
                "info",
                "rule",
                format!("rule updated: {}", saved.name),
            ));
            ok(saved).into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "rule not found").into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn delete_rule(State(state): State<CoreState>, Path(id): Path<String>) -> impl IntoResponse {
    if is_quickbar_managed_rule(&state, &id) {
        return err(
            StatusCode::BAD_REQUEST,
            "quick bar managed rules must be removed via /quickbar",
        )
        .into_response();
    }

    let result = state.mutate_config(|cfg| {
        let before = cfg.rules.len();
        cfg.rules.retain(|rule| rule.id != id);
        before != cfg.rules.len()
    });

    match result {
        Ok(true) => {
            state.add_log(UiLogEvent::new(
                "info",
                "rule",
                format!("rule deleted: {id}"),
            ));
            ok("deleted").into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "rule not found").into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn list_quickbar(State(state): State<CoreState>) -> Json<ApiResponse<Vec<QuickBarItem>>> {
    ok(state.config.read().quick_bar.clone())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuickBarUpsert {
    name: String,
    exe_path: String,
    args: Option<Vec<String>>,
    work_dir: Option<String>,
    proxy_profile: String,
    start_mode: Option<StartMode>,
    run_as_admin: Option<bool>,
    auto_bind_children: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TemplateApplyRequest {
    proxy_profile: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TemplateApplyResult {
    template_id: String,
    added_rules: usize,
    updated_rules: usize,
}

fn is_quickbar_managed_rule(state: &CoreState, rule_id: &str) -> bool {
    state
        .config
        .read()
        .rules
        .iter()
        .any(|rule| rule.id == rule_id && rule.source == RuleSource::QuickBar)
}

fn should_manage_quickbar_rule(item: &QuickBarItem) -> bool {
    !matches!(item.start_mode, StartMode::StartOnly)
}

fn build_quickbar_managed_rule(item: &QuickBarItem) -> Rule {
    let mut rule = Rule::new(
        format!("Quick Bar: {}", item.name),
        MatchCriteria {
            exe_paths: vec![item.exe_path.clone()],
            ..Default::default()
        },
        item.proxy_profile.clone(),
    );
    rule.source = RuleSource::QuickBar;
    rule.managed_by_quickbar_id = Some(item.id.clone());
    rule.auto_bind_children = item.auto_bind_children;
    rule
}

fn sync_quickbar_managed_rule(cfg: &mut AppConfig, item: &QuickBarItem) {
    if !should_manage_quickbar_rule(item) {
        remove_quickbar_managed_rule(cfg, &item.id);
        return;
    }

    if let Some(rule) = cfg.rules.iter_mut().find(|rule| {
        rule.source == RuleSource::QuickBar
            && rule.managed_by_quickbar_id.as_deref() == Some(item.id.as_str())
    }) {
        rule.name = format!("Quick Bar: {}", item.name);
        rule.matcher = MatchCriteria {
            exe_paths: vec![item.exe_path.clone()],
            ..Default::default()
        };
        rule.proxy_profile = item.proxy_profile.clone();
        rule.auto_bind_children = item.auto_bind_children;
        rule.updated_at = Utc::now();
        return;
    }

    cfg.rules.push(build_quickbar_managed_rule(item));
}

fn remove_quickbar_managed_rule(cfg: &mut AppConfig, quickbar_id: &str) -> bool {
    let before = cfg.rules.len();
    cfg.rules.retain(|rule| {
        !(rule.source == RuleSource::QuickBar
            && rule.managed_by_quickbar_id.as_deref() == Some(quickbar_id))
    });
    before != cfg.rules.len()
}

fn ai_dev_template_rules(proxy_profile: &str) -> Vec<Rule> {
    [
        ("AI IDE: VS Code", vec!["code.exe"]),
        ("AI IDE: Code - Insiders", vec!["code - insiders.exe"]),
        ("AI IDE: Cursor", vec!["cursor.exe"]),
        ("AI IDE: Windsurf", vec!["windsurf.exe"]),
        ("AI IDE: Node Toolchain", vec!["node.exe"]),
        ("AI IDE: Chrome", vec!["chrome.exe"]),
        ("AI IDE: Edge", vec!["msedge.exe"]),
    ]
    .into_iter()
    .map(|(name, app_names)| {
        Rule::new(
            name.to_string(),
            MatchCriteria {
                app_names: app_names.into_iter().map(str::to_string).collect(),
                ..Default::default()
            },
            proxy_profile.to_string(),
        )
    })
    .collect()
}

async fn create_quickbar(
    State(state): State<CoreState>,
    Json(payload): Json<QuickBarUpsert>,
) -> impl IntoResponse {
    let path_trim = payload.exe_path.trim().to_string();
    if path_trim.is_empty() {
        return err(StatusCode::BAD_REQUEST, "exe_path cannot be empty").into_response();
    }

    let mut item = QuickBarItem::new(payload.name, path_trim, payload.proxy_profile);
    if let Some(args) = payload.args {
        item.args = args;
    }
    item.work_dir = payload.work_dir;
    if let Some(start_mode) = payload.start_mode {
        item.start_mode = start_mode;
    }
    if let Some(run_as_admin) = payload.run_as_admin {
        item.run_as_admin = run_as_admin;
    }
    if let Some(auto_bind_children) = payload.auto_bind_children {
        item.auto_bind_children = auto_bind_children;
    }

    let result = state.mutate_config(|cfg| {
        cfg.quick_bar.push(item.clone());
        sync_quickbar_managed_rule(cfg, &item);
        item.clone()
    });

    match result {
        Ok(saved) => {
            state.add_log(UiLogEvent::new(
                "info",
                "quickbar",
                format!("quickbar item created: {}", saved.name),
            ));
            ok(saved).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn update_quickbar(
    State(state): State<CoreState>,
    Path(id): Path<String>,
    Json(payload): Json<QuickBarUpsert>,
) -> impl IntoResponse {
    let path_trim = payload.exe_path.trim().to_string();
    if path_trim.is_empty() {
        return err(StatusCode::BAD_REQUEST, "exe_path cannot be empty").into_response();
    }

    let result = state.mutate_config(|cfg| {
        let saved = cfg
            .quick_bar
            .iter_mut()
            .find(|item| item.id == id)
            .map(|item| {
                item.name = payload.name;
                item.exe_path = path_trim.clone();
                item.proxy_profile = payload.proxy_profile;
                if let Some(args) = payload.args {
                    item.args = args;
                }
                item.work_dir = payload.work_dir;
                if let Some(start_mode) = payload.start_mode {
                    item.start_mode = start_mode;
                }
                if let Some(run_as_admin) = payload.run_as_admin {
                    item.run_as_admin = run_as_admin;
                }
                if let Some(auto_bind_children) = payload.auto_bind_children {
                    item.auto_bind_children = auto_bind_children;
                }
                item.clone()
            });

        if let Some(item) = saved.as_ref() {
            sync_quickbar_managed_rule(cfg, item);
        }

        saved
    });

    match result {
        Ok(Some(saved)) => {
            state.add_log(UiLogEvent::new(
                "info",
                "quickbar",
                format!("quickbar item updated: {}", saved.name),
            ));
            ok(saved).into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "quickbar item not found").into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn delete_quickbar(
    State(state): State<CoreState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let result = state.mutate_config(|cfg| {
        let before = cfg.quick_bar.len();
        cfg.quick_bar.retain(|item| item.id != id);
        remove_quickbar_managed_rule(cfg, &id);
        before != cfg.quick_bar.len()
    });

    match result {
        Ok(true) => {
            state.add_log(UiLogEvent::new(
                "info",
                "quickbar",
                format!("quickbar item deleted: {id}"),
            ));
            ok("deleted").into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "quickbar item not found").into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn launch_quickbar(
    State(state): State<CoreState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let ensured = state.mutate_config(|cfg| {
        let item = cfg.quick_bar.iter().find(|item| item.id == id).cloned();
        if let Some(item) = item.as_ref() {
            sync_quickbar_managed_rule(cfg, item);
        }
        item
    });

    let item = match ensured {
        Ok(Some(item)) => item,
        Ok(None) => return err(StatusCode::NOT_FOUND, "quickbar item not found").into_response(),
        Err(error) => {
            return err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };

    match launch_quick_bar_item(&item) {
        Ok(()) => {
            state.add_log(UiLogEvent::new(
                "info",
                "quickbar",
                format!("quickbar launched: {}", item.name),
            ));
            ok("launched").into_response()
        }
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn list_proxies(State(state): State<CoreState>) -> Json<ApiResponse<Vec<ProxyProfile>>> {
    ok(state.config.read().proxies.clone())
}

async fn test_proxy_endpoint(
    State(state): State<CoreState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let profile = state
        .config
        .read()
        .proxies
        .iter()
        .find(|profile| profile.id == id)
        .cloned();
    let Some(profile) = profile else {
        return err(StatusCode::NOT_FOUND, "proxy not found").into_response();
    };

    match tokio::task::spawn_blocking(move || crate::proxy_test::test_proxy(&profile)).await {
        Ok(result) => ok::<ProxyTestResult>(result).into_response(),
        Err(error) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proxy test task failed: {error}"),
        )
        .into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyUpsert {
    id: Option<String>,
    name: String,
    kind: crate::model::ProxyKind,
    endpoint: String,
    username: Option<String>,
    password: Option<String>,
    enabled: Option<bool>,
}

async fn create_proxy(
    State(state): State<CoreState>,
    Json(payload): Json<ProxyUpsert>,
) -> impl IntoResponse {
    let proxy = ProxyProfile {
        id: payload
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: payload.name,
        kind: payload.kind,
        endpoint: payload.endpoint,
        username: payload.username,
        password: payload.password,
        enabled: payload.enabled.unwrap_or(true),
    };

    let result = state.mutate_config(|cfg| {
        cfg.proxies.push(proxy.clone());
        proxy.clone()
    });

    match result {
        Ok(saved) => {
            state.add_log(UiLogEvent::new(
                "info",
                "proxy",
                format!("proxy created: {}", saved.name),
            ));
            ok(saved).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn update_proxy(
    State(state): State<CoreState>,
    Path(id): Path<String>,
    Json(payload): Json<ProxyUpsert>,
) -> impl IntoResponse {
    let result = state.mutate_config(|cfg| {
        cfg.proxies
            .iter_mut()
            .find(|proxy| proxy.id == id)
            .map(|proxy| {
                proxy.name = payload.name;
                proxy.kind = payload.kind;
                proxy.endpoint = payload.endpoint;
                proxy.username = payload.username;
                proxy.password = payload.password;
                if let Some(enabled) = payload.enabled {
                    proxy.enabled = enabled;
                }
                proxy.clone()
            })
    });

    match result {
        Ok(Some(saved)) => {
            state.add_log(UiLogEvent::new(
                "info",
                "proxy",
                format!("proxy updated: {}", saved.name),
            ));
            ok(saved).into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "proxy not found").into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn delete_proxy(State(state): State<CoreState>, Path(id): Path<String>) -> impl IntoResponse {
    let result = state.mutate_config(|cfg| {
        let before = cfg.proxies.len();
        cfg.proxies.retain(|proxy| proxy.id != id);
        before != cfg.proxies.len()
    });

    match result {
        Ok(true) => {
            state.add_log(UiLogEvent::new(
                "info",
                "proxy",
                format!("proxy deleted: {id}"),
            ));
            ok("deleted").into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "proxy not found").into_response(),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EngineModeChange {
    mode: EngineMode,
}

async fn change_engine_mode(
    State(state): State<CoreState>,
    Json(payload): Json<EngineModeChange>,
) -> impl IntoResponse {
    let result = state.mutate_config(|cfg| {
        cfg.engine_mode = payload.mode;
    });

    match result {
        Ok(()) => {
            state.add_log(UiLogEvent::new("info", "engine", "engine mode switched"));
            ok("switched").into_response()
        }
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeUpdate {
    enabled: Option<bool>,
    dns_enforced: Option<bool>,
    ipv6_blocked: Option<bool>,
    doh_blocked: Option<bool>,
    log_level: Option<String>,
    leak_protection_mode: Option<crate::model::LeakProtectionMode>,
}

async fn update_runtime(
    State(state): State<CoreState>,
    Json(payload): Json<RuntimeUpdate>,
) -> impl IntoResponse {
    let result = state.mutate_config(|cfg| {
        if let Some(enabled) = payload.enabled {
            cfg.runtime.enabled = enabled;
        }
        if let Some(dns_enforced) = payload.dns_enforced {
            cfg.runtime.dns_enforced = dns_enforced;
        }
        if let Some(ipv6_blocked) = payload.ipv6_blocked {
            cfg.runtime.ipv6_blocked = ipv6_blocked;
        }
        if let Some(doh_blocked) = payload.doh_blocked {
            cfg.runtime.doh_blocked = doh_blocked;
        }
        if let Some(log_level) = payload.log_level {
            cfg.runtime.log_level = log_level;
        }
        if let Some(leak_protection_mode) = payload.leak_protection_mode {
            cfg.runtime.leak_protection_mode = leak_protection_mode;
        }
        cfg.runtime.clone()
    });

    match result {
        Ok(runtime) => {
            state.add_log(UiLogEvent::new(
                "info",
                "runtime",
                "runtime toggles updated",
            ));
            ok(runtime).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn apply_ai_dev_template(
    State(state): State<CoreState>,
    Json(payload): Json<TemplateApplyRequest>,
) -> impl IntoResponse {
    let proxy_exists = state
        .config
        .read()
        .proxies
        .iter()
        .any(|proxy| proxy.id == payload.proxy_profile);
    if !proxy_exists {
        return err(StatusCode::BAD_REQUEST, "proxy profile not found").into_response();
    }

    let result = state.mutate_config(|cfg| {
        let mut added_rules = 0usize;
        let mut updated_rules = 0usize;

        for template_rule in ai_dev_template_rules(&payload.proxy_profile) {
            if let Some(existing) = cfg
                .rules
                .iter_mut()
                .find(|rule| rule.source == RuleSource::User && rule.name == template_rule.name)
            {
                existing.matcher = template_rule.matcher.clone();
                existing.proxy_profile = template_rule.proxy_profile.clone();
                existing.protocols = template_rule.protocols.clone();
                existing.auto_bind_children = template_rule.auto_bind_children;
                existing.force_dns = template_rule.force_dns;
                existing.block_ipv6 = template_rule.block_ipv6;
                existing.block_doh = template_rule.block_doh;
                existing.enabled = true;
                existing.updated_at = Utc::now();
                updated_rules += 1;
            } else {
                cfg.rules.push(template_rule);
                added_rules += 1;
            }
        }

        TemplateApplyResult {
            template_id: "ai-dev".to_string(),
            added_rules,
            updated_rules,
        }
    });

    match result {
        Ok(summary) => {
            state.add_log(UiLogEvent::new(
                "info",
                "template",
                format!(
                    "applied ai-dev template: {} added, {} updated",
                    summary.added_rules, summary.updated_rules
                ),
            ));
            ok(summary).into_response()
        }
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn shutdown(State(state): State<CoreState>) -> impl IntoResponse {
    if let Err(error) = state.engine.stop() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }

    state.add_log(UiLogEvent::new(
        "info",
        "lifecycle",
        "core service shutting down",
    ));
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        std::process::exit(0);
    });
    ok("shutting_down").into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    use super::*;
    use crate::model::AppConfig;

    #[tokio::test]
    async fn test_health_handler() {
        let cfg = AppConfig::default();
        let state = CoreState::new(
            std::env::temp_dir().join("test_health_handler.json5"),
            "test-token".to_string(),
            cfg,
        );

        let response = health(State(state)).await;
        assert!(response.0.ok);
        assert_eq!(response.0.data.status, "ok");
    }

    #[test]
    fn test_ok_err_wrappers() {
        let success = ok("test");
        assert!(success.0.ok);
        assert_eq!(success.0.data, "test");

        let (status, failure) = err(StatusCode::BAD_REQUEST, "invalid_input");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!failure.0.ok);
        assert_eq!(failure.0.error, "invalid_input");
    }

    #[test]
    fn test_allowed_local_origins() {
        let allowed = [
            "http://localhost:3000",
            "https://127.0.0.1:8443",
            "http://tauri.localhost:1420",
            "tauri://localhost",
        ];

        for origin in allowed {
            assert!(
                is_allowed_local_origin(&origin.parse().unwrap()),
                "{origin}"
            );
        }

        let blocked = [
            "https://example.com",
            "http://evil.localhost.example",
            "file://local",
        ];

        for origin in blocked {
            assert!(
                !is_allowed_local_origin(&origin.parse().unwrap()),
                "{origin}"
            );
        }
    }

    fn integration_state() -> CoreState {
        let path = std::env::temp_dir()
            .join(uuid::Uuid::new_v4().to_string())
            .join("config.json5");
        let state = CoreState::new(path, "integration-token".to_string(), AppConfig::default());
        state.engine.start(&state.config_snapshot()).unwrap();
        state
    }

    fn api_request(method: Method, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(proxyduck_common::AUTH_HEADER, "integration-token")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn integration_auth_and_snapshot_contract() {
        let state = integration_state();
        let app = router(state);
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let previous_brand_authorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/snapshot")
                    .header(proxyduck_common::PREVIOUS_AUTH_HEADER, "integration-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(previous_brand_authorized.status(), StatusCode::OK);

        let authorized = app
            .oneshot(api_request(Method::GET, "/snapshot", serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
        let bytes = to_bytes(authorized.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(
            body["data"]["runtimeStatus"]["dataPlane"]["phase"],
            "paused"
        );
    }

    #[tokio::test]
    async fn integration_concurrent_rule_creates_do_not_overwrite_each_other() {
        let state = integration_state();
        let app = router(state.clone());
        let payload = |name: &str| {
            serde_json::json!({
                "name": name,
                "matcher": { "appNames": [format!("{name}.exe")], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                "proxyProfile": "clash-socks",
                "protocols": ["tcp"],
                "enabled": true
            })
        };
        let first = app
            .clone()
            .oneshot(api_request(Method::POST, "/rules", payload("first")));
        let second = app.oneshot(api_request(Method::POST, "/rules", payload("second")));
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap().status(), StatusCode::OK);
        assert_eq!(second.unwrap().status(), StatusCode::OK);
        assert_eq!(state.config_snapshot().rules.len(), 2);
    }

    #[tokio::test]
    async fn integration_invalid_import_preserves_current_config() {
        let state = integration_state();
        let original = state.config_snapshot();
        let mut invalid = original.clone();
        invalid.schema_version = crate::config::CURRENT_SCHEMA_VERSION + 1;
        let response = router(state.clone())
            .oneshot(api_request(
                Method::PUT,
                "/config",
                serde_json::to_value(invalid).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            state.config_snapshot().schema_version,
            original.schema_version
        );
        assert_eq!(state.config_snapshot().rules.len(), original.rules.len());
    }

    #[tokio::test]
    async fn integration_proxy_and_rule_crud_reorder_duplicate_contract() {
        let state = integration_state();
        let app = router(state.clone());

        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/proxies",
                serde_json::json!({
                    "id": "integration-proxy",
                    "name": "Integration proxy",
                    "kind": "socks5",
                    "endpoint": "127.0.0.1:1080",
                    "username": "test",
                    "password": "secret",
                    "enabled": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["data"]["id"], "integration-proxy");

        let response = app
            .clone()
            .oneshot(api_request(
                Method::PUT,
                "/proxies/integration-proxy",
                serde_json::json!({
                    "name": "Updated proxy",
                    "kind": "socks5",
                    "endpoint": "127.0.0.1:1081",
                    "username": null,
                    "password": null,
                    "enabled": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await["data"]["endpoint"],
            "127.0.0.1:1081"
        );

        let rule_payload = |name: &str| {
            serde_json::json!({
                "name": name,
                "matcher": { "appNames": [format!("{name}.exe")], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                "proxyProfile": "integration-proxy",
                "protocols": ["tcp", "udp"],
                "enabled": true,
                "autoBindChildren": false,
                "forceDns": false,
                "blockIpv6": false,
                "blockDoh": false
            })
        };
        let first = app
            .clone()
            .oneshot(api_request(Method::POST, "/rules", rule_payload("first")))
            .await
            .unwrap();
        let first_id = json_body(first).await["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let second = app
            .clone()
            .oneshot(api_request(Method::POST, "/rules", rule_payload("second")))
            .await
            .unwrap();
        let second_id = json_body(second).await["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let duplicate = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                &format!("/rules/{first_id}/duplicate"),
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        let duplicate_id = json_body(duplicate).await["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/rules/reorder",
                serde_json::json!({ "ruleIds": [&duplicate_id, &second_id, &first_id] }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.config_snapshot().rules[0].id, duplicate_id);

        let response = app
            .clone()
            .oneshot(api_request(
                Method::PUT,
                &format!("/rules/{first_id}"),
                serde_json::json!({
                    "name": "renamed",
                    "matcher": { "appNames": ["renamed.exe"], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                    "proxyProfile": "integration-proxy",
                    "protocols": ["tcp"],
                    "enabled": false
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["data"]["enabled"], false);

        for id in [&duplicate_id, &second_id, &first_id] {
            let response = app
                .clone()
                .oneshot(api_request(
                    Method::DELETE,
                    &format!("/rules/{id}"),
                    serde_json::json!({}),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = app
            .oneshot(api_request(
                Method::DELETE,
                "/proxies/integration-proxy",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.config_snapshot().rules.is_empty());
        assert!(state
            .config_snapshot()
            .proxies
            .iter()
            .all(|proxy| proxy.id != "integration-proxy"));
    }
}
