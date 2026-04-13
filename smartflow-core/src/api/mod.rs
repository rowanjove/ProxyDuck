use std::{
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
        AppConfig, EngineMode, HealthStatus, MatchCriteria, MatchEvent, ProcessInfo, ProxyHitStat,
        ProxyProfile, QuickBarItem, Rule, RuleHitStat, RuleSource, RuntimeStats, StartMode,
        UiLogEvent,
    },
    process::{launch_quick_bar_item, list_processes},
    state::CoreState,
};

pub async fn run_http(state: CoreState, bind: SocketAddr) -> Result<()> {
    let app = router(state);
    tracing::info!(addr = %bind, "smartflow-core api listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(state: CoreState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/config", get(get_config).put(put_config))
        .route("/stats", get(get_stats))
        .route("/stats/rules", get(get_rule_stats))
        .route("/stats/proxies", get(get_proxy_stats))
        .route("/stats/hits", get(get_recent_hits))
        .route("/logs", get(get_logs))
        .route("/icon/exe", get(get_exe_icon))
        .route("/processes", get(get_processes))
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/:id", put(update_rule).delete(delete_rule))
        .route("/quickbar", get(list_quickbar).post(create_quickbar))
        .route(
            "/quickbar/:id",
            put(update_quickbar).delete(delete_quickbar),
        )
        .route("/quickbar/:id/launch", post(launch_quickbar))
        .route("/proxies", get(list_proxies).post(create_proxy))
        .route("/proxies/:id", put(update_proxy).delete(delete_proxy))
        .route("/engine/mode", post(change_engine_mode))
        .route("/runtime", post(update_runtime))
        .route("/templates/ai-dev", post(apply_ai_dev_template))
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
    state: CoreState,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ApiErrorBody>)> {
    if request.method() == Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    let token = request
        .headers()
        .get("x-smartflow-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    if token == Some(state.auth_token.as_str()) {
        return Ok(next.run(request).await);
    }

    Err(err(
        StatusCode::UNAUTHORIZED,
        "missing or invalid X-SmartFlow-Token",
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

async fn get_config(State(state): State<CoreState>) -> Json<ApiResponse<AppConfig>> {
    ok(state.config_snapshot())
}

async fn put_config(
    State(state): State<CoreState>,
    Json(payload): Json<AppConfig>,
) -> impl IntoResponse {
    let mode = payload.engine_mode.clone();
    let mut lock = state.config.write();
    *lock = payload;
    let cfg = lock.clone();
    drop(lock);

    if let Err(error) = state.engine.switch_mode(mode, &cfg) {
        return err(StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }

    if let Err(error) = state.persist_config() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }

    state.add_log(UiLogEvent::new("info", "api", "config updated"));
    ok(cfg).into_response()
}

async fn get_stats(State(state): State<CoreState>) -> Json<ApiResponse<RuntimeStats>> {
    ok(state.stats_snapshot())
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
$p=$env:SMARTFLOW_ICON_PATH
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
            .env("SMARTFLOW_ICON_PATH", normalized_path)
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

        return Ok(format!("data:image/png;base64,{icon_base64}"));
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = exe_path;
        Err("exe icon extraction is only supported on Windows".to_string())
    }
}

async fn get_processes() -> Json<ApiResponse<Vec<ProcessInfo>>> {
    ok(list_processes())
}

async fn list_rules(State(state): State<CoreState>) -> Json<ApiResponse<Vec<Rule>>> {
    ok(state.config.read().rules.clone())
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
    let mode = payload.mode;

    let mut cfg = state.config.write();
    cfg.engine_mode = mode.clone();
    let snapshot = cfg.clone();
    drop(cfg);

    if let Err(error) = state.engine.switch_mode(mode, &snapshot) {
        return err(StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }

    if let Err(error) = state.persist_config() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }

    state.add_log(UiLogEvent::new("info", "engine", "engine mode switched"));
    ok("switched").into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeUpdate {
    enabled: Option<bool>,
    dns_enforced: Option<bool>,
    ipv6_blocked: Option<bool>,
    doh_blocked: Option<bool>,
    log_level: Option<String>,
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

#[cfg(test)]
mod tests {
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
}
