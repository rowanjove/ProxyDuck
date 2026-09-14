use std::future::Future;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{Cursor, Read, Write},
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use chrono::Utc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const MAX_DIAGNOSTIC_TEXT_BYTES: usize = 256 * 1024;

#[cfg(target_os = "windows")]
fn windows_system32_tool(relative_path: &str) -> PathBuf {
    env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(relative_path)
}

use crate::{
    model::{
        AppConfig, DestinationMatch, DnsPolicy, EngineCapability, EngineMode, HealthStatus,
        MatchCriteria, MatchEvent, NetworkPolicy, ProcessInfo, Protocol, ProxyKind,
        ProxyProcessMatchStat, ProxyProfile, ProxyTestResult, QuickBarItem, RouteAction,
        RoutingProfile, Rule, RuleEvaluation, RuleProcessMatchStat, RuleSource, RuntimeStats,
        RuntimeStatus, StartMode, UiLogEvent,
    },
    process::launch_quick_bar_item,
    proxy_import::{self, ImportBatch},
    routing_plan::{
        compile_routing_plan, CompileDiagnostic, PlannedBlockedRoute, PlannedDirectRoute,
        PlannedProxyRoute,
    },
    state::{sanitize_template_provenance, CoreState},
};

pub async fn run_http(state: CoreState, bind: SocketAddr) -> Result<()> {
    run_http_with_shutdown(state, bind, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

pub async fn run_http_with_shutdown<F>(
    state: CoreState,
    bind: SocketAddr,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let app = router(state.clone());
    tracing::info!(addr = %bind, "proxyduck-core api listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.await;
            let _ = state.engine.stop();
        })
        .await?;
    Ok(())
}

pub(crate) fn router(state: CoreState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/capabilities", get(get_capabilities))
        .route("/snapshot", get(get_live_snapshot))
        .route("/diagnostics", get(get_diagnostics))
        .route("/diagnostics/bundle", post(get_diagnostics_bundle))
        .route("/network/status", get(get_network_status))
        .route("/network/diagnose", post(run_network_diagnose))
        .route("/network/history", get(get_network_history))
        .route("/network/repair/plan", post(get_network_repair_plan))
        .route("/network/repair/run", post(run_network_repair))
        .route("/network/snapshots", get(list_network_snapshots))
        .route("/network/snapshot", post(create_network_snapshot))
        .route("/network/restore", post(restore_network_snapshot))
        .route("/configs", get(list_discovered_configs))
        .route("/configs/discover", post(trigger_config_discovery))
        .route("/configs/inspect", post(inspect_config_document))
        .route("/configs/validate", post(validate_config_document))
        .route("/configs/patch", post(preview_config_patch))
        .route("/configs/save", post(save_config_document))
        .route("/config", get(get_config).put(put_config))
        .route("/config/import/preview", post(preview_config_import))
        .route("/stats", get(get_stats))
        .route("/stats/rules", get(get_rule_stats))
        .route("/stats/proxies", get(get_proxy_stats))
        .route("/stats/hits", get(get_recent_hits))
        .route("/logs", get(get_logs))
        .route("/icon/exe", get(get_exe_icon))
        .route("/processes", get(get_processes))
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/conflicts", get(get_rule_conflicts))
        .route(
            "/rules/analyze",
            get(get_rule_analysis).post(post_rule_analysis),
        )
        .route("/rules/reorder", post(reorder_rules))
        .route("/rules/batch-enabled", post(batch_enable_rules))
        .route("/rules/compile", post(compile_current_plan))
        .route("/rules/simulate", post(simulate_rule))
        .route("/rules/evaluate/:pid", get(evaluate_rules_for_process))
        .route("/rules/:id/effective-plan", get(get_effective_plan))
        .route("/rules/:id/duplicate", post(duplicate_rule))
        .route("/rules/:id", put(update_rule).delete(delete_rule))
        .route("/profiles", get(list_profiles).post(create_profile))
        .route("/profiles/:id", get(get_profile).delete(delete_profile))
        .route("/profiles/:id/clone", post(clone_profile))
        .route("/profiles/:id/activate", post(activate_profile))
        .route("/profiles/:id/diff", get(profile_diff))
        .route("/quickbar", get(list_quickbar).post(create_quickbar))
        .route(
            "/quickbar/:id",
            put(update_quickbar).delete(delete_quickbar),
        )
        .route("/quickbar/:id/launch", post(launch_quickbar))
        .route("/proxies", get(list_proxies).post(create_proxy))
        .route("/proxies/import/preview", post(preview_proxy_import))
        .route("/proxies/import", post(apply_proxy_import))
        .route("/proxies/:id", put(update_proxy).delete(delete_proxy))
        .route("/proxies/:id/test", post(test_proxy_endpoint))
        .route("/engine/mode", post(change_engine_mode))
        .route("/runtime", post(update_runtime))
        .route("/runtime/status", get(get_runtime_status))
        .route("/health/proxies", get(get_proxy_health))
        .route("/connections", get(list_connections))
        .route("/connections/summary", get(get_connections_summary))
        .route("/endpoints/discover", post(discover_endpoints))
        .route("/endpoints/discover/add", post(add_discovered_endpoint))
        .route("/timeline", get(list_timeline_events))
        .route("/timeline/clear", post(clear_timeline_events))
        .route("/templates", get(list_templates))
        .route("/templates/:id", post(apply_template))
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    diagnostics: Option<Vec<CompileDiagnostic>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    ok: bool,
    error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    diagnostics: Option<Vec<CompileDiagnostic>>,
}

fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        ok: true,
        data,
        diagnostics: None,
    })
}

fn ok_with_diagnostics<T: Serialize>(
    data: T,
    diagnostics: Vec<CompileDiagnostic>,
) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        ok: true,
        data,
        diagnostics: (!diagnostics.is_empty()).then_some(diagnostics),
    })
}

fn err(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<ApiErrorBody>) {
    err_with_diagnostics(status, message, Vec::new())
}

fn err_with_diagnostics(
    status: StatusCode,
    message: impl Into<String>,
    diagnostics: Vec<CompileDiagnostic>,
) -> (StatusCode, Json<ApiErrorBody>) {
    (
        status,
        Json(ApiErrorBody {
            ok: false,
            error: message.into(),
            diagnostics: (!diagnostics.is_empty()).then_some(diagnostics),
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
    rule_stats: Vec<RuleProcessMatchStat>,
    proxy_stats: Vec<ProxyProcessMatchStat>,
    recent_hits: Vec<MatchEvent>,
    logs: Vec<UiLogEvent>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticsBundle {
    generated_at: chrono::DateTime<Utc>,
    events: Vec<crate::events::EventDefinition>,
    config: AppConfig,
    capabilities: Vec<EngineCapability>,
    runtime_status: RuntimeStatus,
    stats: RuntimeStats,
    rule_stats: Vec<RuleProcessMatchStat>,
    proxy_stats: Vec<ProxyProcessMatchStat>,
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
        rule_stats: state.list_rule_process_match_stats(),
        proxy_stats: state.list_proxy_process_match_stats(),
        recent_hits: state.list_recent_matches(),
        logs: state.list_logs(),
    })
}

async fn get_diagnostics(State(state): State<CoreState>) -> Json<ApiResponse<DiagnosticsBundle>> {
    ok(build_diagnostics_bundle(&state))
}

async fn get_diagnostics_bundle(State(state): State<CoreState>) -> Response {
    match build_diagnostics_zip(&state) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/zip")
            .header(
                "content-disposition",
                "attachment; filename=ProxyDuck-Diagnostics.zip",
            )
            .body(Body::from(bytes))
            .expect("diagnostics response should be valid"),
        Err(error) => err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn get_network_status(
    State(_state): State<CoreState>,
) -> Json<ApiResponse<Option<crate::network::NetworkDiagnosis>>> {
    ok(crate::network::GLOBAL_HISTORY.latest())
}

async fn run_network_diagnose(
    State(state): State<CoreState>,
) -> Json<ApiResponse<crate::network::NetworkDiagnosis>> {
    let diagnosis = crate::network::DiagnosticOrchestrator::run_diagnostics(Some(&state)).await;
    crate::network::GLOBAL_HISTORY.record(diagnosis.clone());
    ok(diagnosis)
}

async fn get_network_history(
    State(_state): State<CoreState>,
) -> Json<ApiResponse<Vec<crate::network::history::DiagnosticHistorySummary>>> {
    ok(crate::network::GLOBAL_HISTORY.list_summaries())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunRepairRequest {
    plan_id: String,
    actions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSnapshotRequest {
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RestoreSnapshotRequest {
    snapshot_id: String,
}

async fn get_network_repair_plan(
    State(state): State<CoreState>,
) -> Json<ApiResponse<crate::network::RepairPlan>> {
    let diagnosis = match crate::network::GLOBAL_HISTORY.latest() {
        Some(d) => d,
        None => crate::network::DiagnosticOrchestrator::run_diagnostics(Some(&state)).await,
    };
    let plan = crate::network::RepairPlanner::build_plan(&diagnosis);
    ok(plan)
}

async fn run_network_repair(
    State(_state): State<CoreState>,
    Json(payload): Json<RunRepairRequest>,
) -> Response {
    match crate::network::RepairExecutor::execute_actions(&payload.plan_id, &payload.actions).await
    {
        Ok(report) => ok(report).into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn list_network_snapshots(State(_state): State<CoreState>) -> Response {
    match crate::network::SnapshotManager::list_snapshots() {
        Ok(list) => ok(list).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn create_network_snapshot(
    State(_state): State<CoreState>,
    body: axum::body::Bytes,
) -> Response {
    let req: CreateSnapshotRequest = serde_json::from_slice(&body).unwrap_or_default();
    let reason = req
        .reason
        .unwrap_or_else(|| "Manual user snapshot".to_string());
    match crate::network::SnapshotManager::create_snapshot(&reason).await {
        Ok(manifest) => ok(manifest).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn restore_network_snapshot(
    State(_state): State<CoreState>,
    Json(payload): Json<RestoreSnapshotRequest>,
) -> Response {
    match crate::network::SnapshotManager::rollback(&payload.snapshot_id) {
        Ok(report) => ok(report).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InspectConfigRequest {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateConfigRequest {
    content: String,
    format: crate::config_studio::ConfigFormat,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchConfigRequest {
    content: String,
    patches: Vec<crate::config_studio::AstPatchItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PatchConfigResponse {
    patched_content: String,
    diff: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveConfigRequest {
    path: String,
    expected_sha256: String,
    content: String,
    format: crate::config_studio::ConfigFormat,
}

async fn list_discovered_configs() -> Response {
    let configs = tokio::task::spawn_blocking(|| {
        crate::config_studio::ConfigDiscoveryScanner::discover_all(&[])
    })
    .await
    .unwrap_or_default();
    ok(configs).into_response()
}

async fn trigger_config_discovery() -> Response {
    let configs = tokio::task::spawn_blocking(|| {
        crate::config_studio::ConfigDiscoveryScanner::discover_all(&[])
    })
    .await
    .unwrap_or_default();
    ok(configs).into_response()
}

async fn inspect_config_document(Json(payload): Json<InspectConfigRequest>) -> Response {
    let raw_path = std::path::PathBuf::from(&payload.path);
    let path = match crate::config_studio::validate_safe_config_path(&raw_path) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::FORBIDDEN, format!("非法配置路径: {e}")).into_response(),
    };
    if !path.exists() {
        return err(StatusCode::NOT_FOUND, "File does not exist").into_response();
    }
    let Ok(content) = std::fs::read_to_string(&path) else {
        return err(
            StatusCode::BAD_REQUEST,
            "Failed to read file content as UTF-8",
        )
        .into_response();
    };

    let fp = crate::config_studio::FingerprintDetector::detect(&path, &content);
    let semantic = crate::config_studio::SemanticExtractor::extract(&content, fp.format);
    let sha256 = crate::config_studio::FingerprintDetector::compute_hash(&content);
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config")
        .to_string();

    let doc = crate::config_studio::ConfigDocument {
        id: format!("cfg_{}", &sha256[..12]),
        file_name,
        path,
        format: fp.format,
        fingerprint: fp.fingerprint,
        raw_content: content,
        semantic,
        sha256,
        mtime_rfc3339: chrono::Utc::now().to_rfc3339(),
    };

    ok(doc).into_response()
}

async fn validate_config_document(Json(payload): Json<ValidateConfigRequest>) -> Response {
    let semantic =
        crate::config_studio::SemanticExtractor::extract(&payload.content, payload.format);
    let res = crate::config_studio::ConfigValidator::validate(
        &payload.content,
        payload.format,
        &semantic,
    );
    ok(res).into_response()
}

async fn preview_config_patch(Json(payload): Json<PatchConfigRequest>) -> Response {
    let (patched_content, diff) =
        crate::config_studio::AstPatcher::apply_patches(&payload.content, &payload.patches);
    ok(PatchConfigResponse {
        patched_content,
        diff,
    })
    .into_response()
}

async fn save_config_document(Json(payload): Json<SaveConfigRequest>) -> Response {
    let raw_path = std::path::PathBuf::from(&payload.path);
    let path = match crate::config_studio::validate_safe_config_path(&raw_path) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::FORBIDDEN, format!("非法配置路径: {e}")).into_response(),
    };
    match crate::config_studio::SafeConfigWriter::save(
        &path,
        &payload.expected_sha256,
        &payload.content,
        payload.format,
    ) {
        Ok(res) => ok(res).into_response(),
        Err(e) => err(StatusCode::CONFLICT, e.to_string()).into_response(),
    }
}

fn build_diagnostics_bundle(state: &CoreState) -> DiagnosticsBundle {
    let mut config = state.config_snapshot();
    let sensitive_values = config
        .proxies
        .iter()
        .flat_map(|proxy| [proxy.password.clone(), proxy.username.clone()])
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    for proxy in &mut config.proxies {
        proxy.password = None;
        proxy.password_ref = None;
        proxy.username = None;
    }
    redact_config_paths(&mut config);
    let logs = state
        .list_logs()
        .into_iter()
        .map(|mut log| {
            log.message = redact_diagnostic_text(&log.message, &sensitive_values);
            log
        })
        .collect();
    let recent_hits = state
        .list_recent_matches()
        .into_iter()
        .map(|mut hit| {
            hit.process_exe = redact_user_path(&redact_values(&hit.process_exe, &sensitive_values));
            hit
        })
        .collect();
    DiagnosticsBundle {
        generated_at: Utc::now(),
        events: crate::events::REGISTRY.to_vec(),
        config,
        capabilities: crate::engine::engine_capabilities(),
        runtime_status: state.runtime_status(),
        stats: state.stats_snapshot(),
        rule_stats: state.list_rule_process_match_stats(),
        proxy_stats: state.list_proxy_process_match_stats(),
        recent_hits,
        logs,
    }
}

fn build_diagnostics_zip(state: &CoreState) -> Result<Vec<u8>> {
    use zip::write::SimpleFileOptions;

    let bundle = build_diagnostics_bundle(state);
    let mut cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(&mut cursor);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut manifest = serde_json::Map::new();

    add_json_entry(
        &mut archive,
        &mut manifest,
        "events.json",
        &bundle.events,
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "config.json",
        &bundle.config,
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "proxyduck.json",
        &bundle.config,
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "rules-redacted.json",
        &bundle.config.rules,
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "capabilities.json",
        &bundle.capabilities,
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "runtime.json",
        &bundle.runtime_status,
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "stats.json",
        &bundle.stats,
        options,
    )?;
    let routing_plan = compile_routing_plan_for_diagnostics(state)?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "routing-plan.json",
        &routing_plan,
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "logs.json",
        &bundle.logs,
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "system.json",
        &diagnostic_system_info(),
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "engine.json",
        &serde_json::json!({
            "capabilities": bundle.capabilities,
            "runtimeStatus": bundle.runtime_status,
        }),
        options,
    )?;
    add_json_entry(
        &mut archive,
        &mut manifest,
        "runtime-lock.json",
        &read_runtime_lock(),
        options,
    )?;

    for (name, program, args) in diagnostic_commands() {
        let capture = run_diagnostic_command(program, args);
        add_json_entry(&mut archive, &mut manifest, name, &capture, options)?;
    }
    add_text_entry(
        &mut archive,
        &mut manifest,
        "core.log",
        &diagnostic_log_file(proxyduck_common::resolve_app_dir()?.join("proxyduck-core.log")),
        options,
    )?;
    add_text_entry(
        &mut archive,
        &mut manifest,
        "engine.log",
        &diagnostic_engine_logs()?,
        options,
    )?;
    add_text_entry(
        &mut archive,
        &mut manifest,
        "crash.log",
        &diagnostic_log_file(proxyduck_common::resolve_app_dir()?.join("crash.log")),
        options,
    )?;
    let manifest_document = serde_json::json!({
        "formatVersion": 1,
        "generatedAt": bundle.generated_at,
        "redaction": "passwords, secret references, tokens, credentials and known user paths redacted",
        "entries": manifest.clone(),
    });
    add_json_entry(
        &mut archive,
        &mut manifest,
        "manifest.json",
        &manifest_document,
        options,
    )?;
    archive.finish()?;
    Ok(cursor.into_inner())
}

fn diagnostic_system_info() -> serde_json::Value {
    serde_json::json!({
        "product": proxyduck_common::PRODUCT_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "os": env::consts::OS,
        "arch": env::consts::ARCH,
        "family": env::consts::FAMILY,
        "debug": cfg!(debug_assertions),
    })
}

fn read_runtime_lock() -> serde_json::Value {
    let mut candidates = Vec::new();
    if let Ok(path) = env::var("PROXYDUCK_RUNTIME_LOCK") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("RUNTIME-LOCK.json"));
        }
    }
    for path in candidates {
        if let Ok(body) = read_bounded_file(&path) {
            return serde_json::json!({
                "available": true,
                "source": "bundled",
                "content": redact_diagnostic_text(&body, &[]),
            });
        }
    }
    serde_json::json!({
        "available": false,
        "reason": "RUNTIME-LOCK.json was not found next to the running core",
    })
}

fn diagnostic_commands() -> [(&'static str, &'static str, &'static [&'static str]); 5] {
    if cfg!(target_os = "windows") {
        [
            ("drivers.json", "pnputil", &["/enum-drivers"]),
            ("network-adapters.json", "ipconfig", &["/all"]),
            ("routes.json", "route", &["print"]),
            ("dns.json", "ipconfig", &["/all"]),
            (
                "firewall.json",
                "netsh",
                &["advfirewall", "show", "allprofiles"],
            ),
        ]
    } else {
        [
            ("drivers.json", "uname", &["-a"]),
            ("network-adapters.json", "ip", &["address"]),
            ("routes.json", "ip", &["route"]),
            ("dns.json", "cat", &["/etc/resolv.conf"]),
            (
                "firewall.json",
                "sh",
                &[
                    "-c",
                    "command -v nft >/dev/null && nft list ruleset || true",
                ],
            ),
        ]
    }
}

fn run_diagnostic_command(program: &str, args: &[&str]) -> serde_json::Value {
    #[cfg(target_os = "windows")]
    let program_path = match program {
        "pnputil" => windows_system32_tool("pnputil.exe"),
        "ipconfig" => windows_system32_tool("ipconfig.exe"),
        "route" => windows_system32_tool("route.exe"),
        "netsh" => windows_system32_tool("netsh.exe"),
        _ => PathBuf::from(program),
    };
    #[cfg(not(target_os = "windows"))]
    let program_path = PathBuf::from(program);

    let mut command = Command::new(program_path);
    command.args(args).stdin(Stdio::null());
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);
    match command.output() {
        Ok(output) => serde_json::json!({
            "available": true,
            "command": format!("{} {}", program, args.join(" ")),
            "exitCode": output.status.code(),
            "stdout": redact_diagnostic_text(&String::from_utf8_lossy(&output.stdout), &[]),
            "stderr": redact_diagnostic_text(&String::from_utf8_lossy(&output.stderr), &[]),
        }),
        Err(error) => serde_json::json!({
            "available": false,
            "command": format!("{} {}", program, args.join(" ")),
            "reason": error.to_string(),
        }),
    }
}

fn diagnostic_log_file(path: PathBuf) -> String {
    match read_bounded_file(&path) {
        Ok(body) => redact_diagnostic_text(&body, &[]),
        Err(error) => format!(
            "[unavailable] failed to read {}: {error}",
            redact_user_path(&path.display().to_string())
        ),
    }
}

fn read_bounded_file(path: &FsPath) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open diagnostic file {}", path.display()))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_DIAGNOSTIC_TEXT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read diagnostic file {}", path.display()))?;
    let truncated = bytes.len() > MAX_DIAGNOSTIC_TEXT_BYTES;
    if truncated {
        bytes.truncate(MAX_DIAGNOSTIC_TEXT_BYTES);
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        text.push_str("\n[TRUNCATED]");
    }
    Ok(text)
}

fn diagnostic_engine_logs() -> Result<String> {
    let root = proxyduck_common::resolve_app_dir()?;
    let names = [
        "proxyduck-proxifyre.stdout.log",
        "proxyduck-proxifyre.stderr.log",
        "proxyduck-sing-box.stdout.log",
        "proxyduck-sing-box.stderr.log",
    ];
    let mut sections = Vec::new();
    for name in names {
        let path = root.join(name);
        if path.exists() {
            sections.push(format!("===== {name} =====\n{}", diagnostic_log_file(path)));
        }
    }
    if sections.is_empty() {
        Ok("[unavailable] no engine log files were found".to_string())
    } else {
        Ok(sections.join("\n"))
    }
}

fn redact_config_paths(config: &mut AppConfig) {
    redact_rule_paths(&mut config.rules);
    redact_quick_bar_paths(&mut config.quick_bar);
    for profile in &mut config.profiles {
        redact_rule_paths(&mut profile.rules);
        redact_quick_bar_paths(&mut profile.quick_bar);
    }
}

fn redact_rule_paths(rules: &mut [Rule]) {
    for rule in rules {
        rule.matcher.exe_paths = rule
            .matcher
            .exe_paths
            .iter()
            .map(|path| redact_user_path(path))
            .collect();
    }
}

fn redact_quick_bar_paths(items: &mut [QuickBarItem]) {
    for item in items {
        item.exe_path = redact_user_path(&item.exe_path);
        item.work_dir = item.work_dir.as_deref().map(redact_user_path);
    }
}

fn redact_values(value: &str, sensitive_values: &[String]) -> String {
    sensitive_values
        .iter()
        .fold(value.to_string(), |current, secret| {
            current.replace(secret, "[REDACTED]")
        })
}

fn redact_user_path(value: &str) -> String {
    let mut result = value.to_string();
    for key in ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOME"] {
        if let Ok(path) = env::var(key) {
            if !path.is_empty() {
                result = result.replace(&path, "[USER_PATH]");
            }
        }
    }
    if let (Ok(drive), Ok(path)) = (env::var("HOMEDRIVE"), env::var("HOMEPATH")) {
        let home = format!("{drive}{path}");
        if !home.is_empty() {
            result = result.replace(&home, "[USER_PATH]");
        }
    }
    result
}

fn redact_diagnostic_text(value: &str, sensitive_values: &[String]) -> String {
    let mut redacted = redact_user_path(&redact_values(value, sensitive_values));
    let mut output = String::with_capacity(redacted.len().min(MAX_DIAGNOSTIC_TEXT_BYTES));
    for line in redacted.lines() {
        let lower = line.to_ascii_lowercase();
        if [
            "password",
            "passwd",
            "token",
            "secret",
            "authorization",
            "username",
        ]
        .iter()
        .any(|key| lower.contains(key))
        {
            if let Some(index) = line.find(['=', ':']) {
                output.push_str(&line[..=index]);
                output.push_str("[REDACTED]");
            } else {
                output.push_str("[REDACTED]");
            }
        } else {
            output.push_str(line);
        }
        output.push('\n');
        if output.len() >= MAX_DIAGNOSTIC_TEXT_BYTES {
            break;
        }
    }
    redacted = output;
    if redacted.len() > MAX_DIAGNOSTIC_TEXT_BYTES {
        let boundary = redacted
            .char_indices()
            .find(|(index, _)| *index >= MAX_DIAGNOSTIC_TEXT_BYTES)
            .map(|(index, _)| index)
            .unwrap_or(redacted.len());
        redacted.truncate(boundary);
        redacted.push_str("\n[TRUNCATED]");
    }
    redacted
}

fn add_json_entry<T: Serialize>(
    archive: &mut zip::ZipWriter<&mut Cursor<Vec<u8>>>,
    manifest: &mut serde_json::Map<String, serde_json::Value>,
    name: &str,
    value: &T,
    options: zip::write::SimpleFileOptions,
) -> Result<()> {
    let value = redact_json_value(serde_json::to_value(value)?, &[]);
    let body = serde_json::to_vec_pretty(&value)?;
    archive.start_file(name, options)?;
    archive.write_all(&body)?;
    let available = value.get("available").and_then(serde_json::Value::as_bool);
    let mut entry = serde_json::json!({ "ok": available.unwrap_or(true), "bytes": body.len() });
    if available == Some(false) {
        if let Some(reason) = value.get("reason") {
            entry["reason"] = reason.clone();
        }
    }
    manifest.insert(name.to_string(), entry);
    Ok(())
}

fn redact_json_value(value: serde_json::Value, sensitive_values: &[String]) -> serde_json::Value {
    match value {
        serde_json::Value::Object(mut object) => {
            for (key, item) in &mut object {
                let lower = key.to_ascii_lowercase();
                if [
                    "password",
                    "passwd",
                    "token",
                    "secret",
                    "authorization",
                    "username",
                ]
                .iter()
                .any(|needle| lower.contains(needle))
                {
                    *item = serde_json::Value::String("[REDACTED]".to_string());
                } else {
                    *item = redact_json_value(item.take(), sensitive_values);
                }
            }
            serde_json::Value::Object(object)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .map(|item| redact_json_value(item, sensitive_values))
                .collect(),
        ),
        serde_json::Value::String(text) => {
            serde_json::Value::String(redact_user_path(&redact_values(&text, sensitive_values)))
        }
        other => other,
    }
}

fn add_text_entry(
    archive: &mut zip::ZipWriter<&mut Cursor<Vec<u8>>>,
    manifest: &mut serde_json::Map<String, serde_json::Value>,
    name: &str,
    body: &str,
    options: zip::write::SimpleFileOptions,
) -> Result<()> {
    let body = if body.len() > MAX_DIAGNOSTIC_TEXT_BYTES {
        let truncated = body
            .char_indices()
            .take_while(|(index, _)| *index < MAX_DIAGNOSTIC_TEXT_BYTES)
            .map(|(_, ch)| ch)
            .collect::<String>();
        format!("{truncated}\n[TRUNCATED]")
    } else {
        body.to_string()
    };
    archive.start_file(name, options)?;
    archive.write_all(body.as_bytes())?;
    let available = !body.starts_with("[unavailable]");
    manifest.insert(
        name.to_string(),
        if available {
            serde_json::json!({ "ok": true, "bytes": body.len(), "kind": "text" })
        } else {
            serde_json::json!({
                "ok": false,
                "bytes": body.len(),
                "kind": "text",
                "reason": body.trim(),
            })
        },
    );
    Ok(())
}

fn compile_routing_plan_for_diagnostics(
    state: &CoreState,
) -> Result<crate::routing_plan::RoutingPlan> {
    let mut plan = compile_routing_plan(&state.config_snapshot(), &state.list_processes())?;
    redact_plan_credentials(&mut plan);
    Ok(plan)
}

fn redact_plan_credentials(plan: &mut crate::routing_plan::RoutingPlan) {
    for route in &mut plan.proxy_routes {
        route.username = None;
        route.password = None;
    }
}

async fn get_config(State(state): State<CoreState>) -> Json<ApiResponse<AppConfig>> {
    ok(state.config_snapshot())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigImportSummary {
    schema_version: u32,
    version: String,
    engine_mode: EngineMode,
    proxy_count: usize,
    rule_count: usize,
    profile_count: usize,
    quick_bar_count: usize,
}

impl ConfigImportSummary {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            schema_version: config.schema_version,
            version: config.version.clone(),
            engine_mode: config.engine_mode,
            proxy_count: config.proxies.len(),
            rule_count: config.rules.len(),
            profile_count: config.profiles.len(),
            quick_bar_count: config.quick_bar.len(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigImportPreview {
    /// The current importer replaces the complete config; it does not merge
    /// individual records. Keep that distinction explicit in the API.
    operation: &'static str,
    valid: bool,
    migrated: bool,
    validation_error: Option<String>,
    changed_sections: Vec<&'static str>,
    current: ConfigImportSummary,
    proposed: ConfigImportSummary,
}

fn config_section_changed(current: &AppConfig, proposed: &AppConfig, section: &str) -> bool {
    match section {
        "schema" => {
            current.schema_version != proposed.schema_version || current.version != proposed.version
        }
        "engine" => current.engine_mode != proposed.engine_mode,
        "proxies" => proxies_changed(current, proposed),
        "rules" => {
            serde_json::to_value(&current.rules).ok() != serde_json::to_value(&proposed.rules).ok()
        }
        "profiles" => {
            serde_json::to_value(&current.profiles).ok()
                != serde_json::to_value(&proposed.profiles).ok()
        }
        "quick_bar" => {
            serde_json::to_value(&current.quick_bar).ok()
                != serde_json::to_value(&proposed.quick_bar).ok()
        }
        "runtime" => {
            serde_json::to_value(&current.runtime).ok()
                != serde_json::to_value(&proposed.runtime).ok()
        }
        _ => false,
    }
}

fn proxies_changed(current: &AppConfig, proposed: &AppConfig) -> bool {
    if current.proxies.len() != proposed.proxies.len() {
        return true;
    }
    current
        .proxies
        .iter()
        .zip(&proposed.proxies)
        .any(|(left, right)| {
            serde_json::to_value(left).ok() != serde_json::to_value(right).ok()
                || (right.password.is_some() && left.password != right.password)
        })
}

async fn preview_config_import(
    State(state): State<CoreState>,
    Json(mut payload): Json<AppConfig>,
) -> impl IntoResponse {
    let current = state.config_snapshot();
    sanitize_template_provenance(&current, &mut payload);
    let migrated = match crate::config::prepare_import_preview(&mut payload) {
        Ok(changed) => changed,
        Err(error) => {
            return err_with_diagnostics(StatusCode::BAD_REQUEST, error.to_string(), Vec::new())
                .into_response();
        }
    };
    let validation_error = crate::validation::validate_config(&payload)
        .err()
        .map(|error| error.to_string());
    let diagnostics = compile_routing_plan(&payload, &state.list_processes())
        .map(|plan| plan.diagnostics)
        .unwrap_or_default();
    let validation_error = validation_error.or_else(|| {
        (payload.runtime.leak_protection_mode == crate::model::LeakProtectionMode::Strict)
            .then(|| {
                diagnostics
                    .iter()
                    .find(|diagnostic| diagnostic.blocks_strict)
                    .map(|diagnostic| diagnostic.message.clone())
            })
            .flatten()
    });
    let changed_sections = [
        "schema",
        "engine",
        "proxies",
        "rules",
        "profiles",
        "quick_bar",
        "runtime",
    ]
    .into_iter()
    .filter(|section| config_section_changed(&current, &payload, section))
    .collect::<Vec<_>>();
    ok_with_diagnostics(
        ConfigImportPreview {
            operation: "replace",
            valid: validation_error.is_none(),
            migrated,
            validation_error,
            changed_sections,
            current: ConfigImportSummary::from_config(&current),
            proposed: ConfigImportSummary::from_config(&payload),
        },
        diagnostics,
    )
    .into_response()
}

async fn put_config(
    State(state): State<CoreState>,
    Json(payload): Json<AppConfig>,
) -> impl IntoResponse {
    let proposed_diagnostics = compile_routing_plan(&payload, &state.list_processes())
        .map(|plan| plan.diagnostics)
        .unwrap_or_default();
    let result = state.replace_imported_config(payload);
    match result {
        Ok(cfg) => {
            state.add_log(UiLogEvent::new("info", "api", "config updated"));
            ok_with_diagnostics(cfg, state.runtime_status().compile_diagnostics).into_response()
        }
        Err(error) => err_with_diagnostics(
            StatusCode::BAD_REQUEST,
            error.to_string(),
            // Migration can fail before `apply_config` runs.  Do not fall
            // back to the state-wide last-apply diagnostics here: that value
            // may belong to an earlier request and would make a schema or
            // import error appear to have an unrelated routing cause.
            proposed_diagnostics,
        )
        .into_response(),
    }
}

async fn get_stats(State(state): State<CoreState>) -> Json<ApiResponse<RuntimeStats>> {
    ok(state.stats_snapshot())
}

async fn get_runtime_status(State(state): State<CoreState>) -> Json<ApiResponse<RuntimeStatus>> {
    ok(state.runtime_status())
}

async fn get_proxy_health(
    State(state): State<CoreState>,
) -> Json<ApiResponse<Vec<crate::model::ProxyHealth>>> {
    ok(state.proxy_health_snapshot())
}

async fn get_rule_stats(
    State(state): State<CoreState>,
) -> Json<ApiResponse<Vec<RuleProcessMatchStat>>> {
    ok(state.list_rule_process_match_stats())
}

async fn get_proxy_stats(
    State(state): State<CoreState>,
) -> Json<ApiResponse<Vec<ProxyProcessMatchStat>>> {
    ok(state.list_proxy_process_match_stats())
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

static ICON_CACHE: once_cell::sync::Lazy<dashmap::DashMap<String, String>> =
    once_cell::sync::Lazy::new(dashmap::DashMap::new);

fn extract_exe_icon_data_url(exe_path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let raw_path = exe_path.trim();
        if raw_path.is_empty() {
            return Err("exe path is empty".to_string());
        }
        let cache_key = raw_path.to_ascii_lowercase();
        if let Some(cached) = ICON_CACHE.get(&cache_key) {
            return Ok(cached.clone());
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

        let output = Command::new(windows_system32_tool(
            r"WindowsPowerShell\v1.0\powershell.exe",
        ))
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(script)
        .env("PROXYDUCK_ICON_PATH", raw_path)
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

        let data_url = format!("data:image/png;base64,{icon_base64}");
        if ICON_CACHE.len() >= 500 {
            ICON_CACHE.clear();
        }
        ICON_CACHE.insert(cache_key, data_url.clone());
        Ok(data_url)
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

async fn get_rule_analysis(
    State(state): State<CoreState>,
) -> Json<ApiResponse<crate::policy::PolicyAnalysisReport>> {
    let config = state.config_snapshot();
    ok(crate::policy::analyze_config(&config))
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnalyzeRequestPayload {
    Config(crate::model::AppConfig),
    Rules(Vec<crate::model::Rule>),
}

async fn post_rule_analysis(
    State(state): State<CoreState>,
    Json(payload): Json<AnalyzeRequestPayload>,
) -> Json<ApiResponse<crate::policy::PolicyAnalysisReport>> {
    let report = match payload {
        AnalyzeRequestPayload::Config(cfg) => crate::policy::analyze_config(&cfg),
        AnalyzeRequestPayload::Rules(rules) => {
            let proxies = state.config.read().proxies.clone();
            crate::policy::analyze_policies(&rules, &proxies)
        }
    };
    ok(report)
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
struct RuleSimulationRequest {
    #[serde(default)]
    process: Option<ProcessInfo>,
    #[serde(default)]
    process_name: Option<String>,
    #[serde(default)]
    exe_path: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    parent_process: Option<String>,
    #[serde(default = "default_simulation_protocol")]
    protocol: Protocol,
    #[serde(default)]
    destination: Option<SimulationDestination>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimulationDestination {
    domain: Option<String>,
    ip: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleSimulationResult {
    evaluation: RuleEvaluation,
    selected_action: Option<RouteAction>,
    route: Option<PlannedProxyRoute>,
    blocked: Option<PlannedBlockedRoute>,
    direct_route: Option<PlannedDirectRoute>,
    direct: bool,
    destination_matched: bool,
    diagnostics: Vec<CompileDiagnostic>,
    fingerprint: String,
    evidence_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_simulation: Option<crate::policy::PolicySimulationResponse>,
}

fn default_simulation_protocol() -> Protocol {
    Protocol::Tcp
}

async fn simulate_rule(
    State(state): State<CoreState>,
    Json(payload): Json<RuleSimulationRequest>,
) -> impl IntoResponse {
    let config = state.config_snapshot();

    let (proc_info, sim_input) = if let Some(ref p) = payload.process {
        let domain = payload
            .destination
            .as_ref()
            .and_then(|d| d.domain.clone())
            .or_else(|| payload.domain.clone());
        let ip = payload
            .destination
            .as_ref()
            .and_then(|d| d.ip.clone())
            .or_else(|| payload.ip.clone());
        let port = payload
            .destination
            .as_ref()
            .and_then(|d| d.port)
            .or(payload.port);

        let sim = crate::policy::SimulationInput {
            process_name: p.name.clone(),
            exe_path: Some(p.exe.clone()),
            pid: Some(p.pid),
            parent_process: payload.parent_process.clone(),
            protocol: payload.protocol,
            domain,
            ip,
            port,
            network_interface: None,
        };
        (p.clone(), sim)
    } else {
        let name = payload.process_name.clone().unwrap_or_default();
        let exe = payload.exe_path.clone().unwrap_or_default();
        let pid = payload.pid.unwrap_or(0);
        let p = ProcessInfo {
            pid,
            name: name.clone(),
            exe: exe.clone(),
            creation_time: None,
        };
        let domain = payload
            .destination
            .as_ref()
            .and_then(|d| d.domain.clone())
            .or_else(|| payload.domain.clone());
        let ip = payload
            .destination
            .as_ref()
            .and_then(|d| d.ip.clone())
            .or_else(|| payload.ip.clone());
        let port = payload
            .destination
            .as_ref()
            .and_then(|d| d.port)
            .or(payload.port);

        let sim = crate::policy::SimulationInput {
            process_name: name,
            exe_path: Some(exe),
            pid: Some(pid),
            parent_process: payload.parent_process.clone(),
            protocol: payload.protocol,
            domain,
            ip,
            port,
            network_interface: None,
        };
        (p, sim)
    };

    let mut evaluation = crate::process::evaluate_rules(&config.rules, &proc_info);

    let plan = match compile_routing_plan(&config, std::slice::from_ref(&proc_info)) {
        Ok(plan) => plan,
        Err(error) => return err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let dest_ref = payload.destination.as_ref();
    let sim_dest = SimulationDestination {
        domain: sim_input.domain.clone(),
        ip: sim_input.ip.clone(),
        port: sim_input.port,
    };
    let selected_id = evaluation.matches.iter().find_map(|candidate| {
        config
            .rules
            .iter()
            .find(|rule| rule.id == candidate.rule_id)
            .filter(|rule| {
                destination_matches(rule, dest_ref.or(Some(&sim_dest)), payload.protocol)
                    && plan_has_rule(&plan, &rule.id)
            })
            .map(|rule| rule.id.clone())
    });
    for candidate in &mut evaluation.matches {
        candidate.selected = selected_id.as_deref() == Some(candidate.rule_id.as_str());
    }

    let selected_rule = selected_id
        .as_deref()
        .and_then(|rule_id| config.rules.iter().find(|rule| rule.id == rule_id));
    let selected_action = selected_rule.map(|rule| rule.action.clone());
    let destination_matched = selected_rule.is_some();
    let route = selected_id.as_deref().and_then(|rule_id| {
        plan.proxy_routes
            .iter()
            .find(|route| route.rule_id == rule_id)
            .cloned()
    });
    let blocked = selected_id.as_deref().and_then(|rule_id| {
        plan.blocked_routes
            .iter()
            .find(|route| route.rule_id == rule_id)
            .cloned()
    });
    let direct_route = selected_id.as_deref().and_then(|rule_id| {
        plan.direct_routes
            .iter()
            .find(|route| route.rule_id == rule_id)
            .cloned()
    });
    let direct = selected_rule.is_some_and(|rule| matches!(rule.action, RouteAction::Direct));

    let policy_sim = crate::policy::simulate_policy(&config.rules, &config.proxies, &sim_input);

    ok(RuleSimulationResult {
        evaluation,
        selected_action,
        route,
        blocked,
        direct_route,
        direct,
        destination_matched,
        diagnostics: plan.diagnostics,
        fingerprint: plan.fingerprint,
        evidence_kind: "inferred",
        policy_simulation: Some(policy_sim),
    })
    .into_response()
}

fn plan_has_rule(plan: &crate::routing_plan::RoutingPlan, rule_id: &str) -> bool {
    plan.proxy_routes
        .iter()
        .any(|route| route.rule_id == rule_id)
        || plan
            .direct_routes
            .iter()
            .any(|route| route.rule_id == rule_id)
        || plan
            .blocked_routes
            .iter()
            .any(|route| route.rule_id == rule_id)
}

fn destination_matches(
    rule: &Rule,
    destination: Option<&SimulationDestination>,
    protocol: Protocol,
) -> bool {
    if matches!(protocol, Protocol::Dns) {
        // DNS is retained only as a legacy compatibility marker; it is not a
        // separately routable protocol in the current data-plane adapters.
        return false;
    }
    if !rule.protocols.is_empty() && !rule.protocols.contains(&protocol) {
        return false;
    }
    let Some(destination) = destination else {
        return rule.destination.is_empty();
    };
    let criteria = &rule.destination;
    if !criteria.domains.is_empty()
        && !destination.domain.as_deref().is_some_and(|domain| {
            let domain = domain.trim().to_ascii_lowercase();
            criteria.domains.iter().any(|candidate| {
                let candidate = candidate.trim().to_ascii_lowercase();
                if let Some(suffix) = candidate.strip_prefix("*.") {
                    domain == suffix || domain.ends_with(&format!(".{suffix}"))
                } else {
                    domain == candidate
                }
            })
        })
    {
        return false;
    }
    if !criteria.ip_cidrs.is_empty()
        && !destination.ip.as_deref().is_some_and(|ip| {
            criteria
                .ip_cidrs
                .iter()
                .any(|candidate| ip_matches_cidr(ip, candidate))
        })
    {
        return false;
    }
    if !criteria.ports.is_empty()
        && !destination
            .port
            .is_some_and(|port| criteria.ports.contains(&port))
    {
        return false;
    }
    true
}

fn ip_matches_cidr(ip_text: &str, cidr_text: &str) -> bool {
    let Ok(ip) = ip_text.trim().parse::<std::net::IpAddr>() else {
        return false;
    };
    let cidr = cidr_text.trim();
    let (network_text, prefix) = cidr
        .split_once('/')
        .map(|(network, prefix)| (network.trim(), prefix.trim().parse::<u8>().ok()))
        .unwrap_or((cidr, None));
    let Ok(network) = network_text.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (ip, network) {
        (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(network)) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(ip) & mask) == (u32::from(network) & mask)
        }
        (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(network)) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(ip) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EffectiveRulePlan {
    rule_id: String,
    rule_name: String,
    engine: EngineMode,
    route: Option<PlannedProxyRoute>,
    blocked: Option<PlannedBlockedRoute>,
    direct_route: Option<PlannedDirectRoute>,
    direct: bool,
    diagnostics: Vec<CompileDiagnostic>,
    fingerprint: String,
}

async fn compile_current_plan(State(state): State<CoreState>) -> impl IntoResponse {
    match compile_routing_plan(&state.config_snapshot(), &state.list_processes()) {
        Ok(mut plan) => {
            redact_plan_credentials(&mut plan);
            ok(plan).into_response()
        }
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn get_effective_plan(
    State(state): State<CoreState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let config = state.config_snapshot();
    let Some(rule) = config.rules.iter().find(|rule| rule.id == id) else {
        return err(StatusCode::NOT_FOUND, "rule not found").into_response();
    };
    let plan = match compile_routing_plan(&config, &state.list_processes()) {
        Ok(plan) => plan,
        Err(error) => return err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let mut plan = plan;
    redact_plan_credentials(&mut plan);
    let route = plan
        .proxy_routes
        .iter()
        .find(|route| route.rule_id == id)
        .cloned();
    let blocked = plan
        .blocked_routes
        .iter()
        .find(|blocked| blocked.rule_id == id)
        .cloned();
    let direct_route = plan
        .direct_routes
        .iter()
        .find(|route| route.rule_id == id)
        .cloned();
    let direct = matches!(rule.action, RouteAction::Direct)
        || config
            .proxies
            .iter()
            .find(|proxy| proxy.id == rule.action_target_id())
            .is_some_and(|proxy| matches!(proxy.kind, crate::model::ProxyKind::Direct));
    ok(EffectiveRulePlan {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        engine: config.engine_mode,
        route,
        blocked,
        direct_route,
        direct,
        diagnostics: plan.diagnostics,
        fingerprint: plan.fingerprint,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleReorderRequest {
    rule_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleBatchEnabledRequest {
    rule_ids: Vec<String>,
    enabled: bool,
}

async fn batch_enable_rules(
    State(state): State<CoreState>,
    Json(payload): Json<RuleBatchEnabledRequest>,
) -> impl IntoResponse {
    let requested_ids = payload.rule_ids.iter().collect::<HashSet<_>>();
    if payload.rule_ids.is_empty() || requested_ids.len() != payload.rule_ids.len() {
        return err(
            StatusCode::BAD_REQUEST,
            "ruleIds must contain at least one unique rule id",
        )
        .into_response();
    }

    let result = state.try_mutate_config(|cfg| {
        let mut updated = Vec::with_capacity(payload.rule_ids.len());
        for id in &payload.rule_ids {
            let Some(rule) = cfg.rules.iter_mut().find(|rule| rule.id == id.as_str()) else {
                return Err(anyhow::anyhow!("rule not found: {id}"));
            };
            if rule.source == RuleSource::QuickBar {
                return Err(anyhow::anyhow!(
                    "quick bar managed rule '{}' must be edited via /quickbar",
                    rule.name
                ));
            }
            rule.enabled = payload.enabled;
            rule.updated_at = Utc::now();
            updated.push(rule.clone());
        }
        Ok(updated)
    });

    match result {
        Ok(rules) => {
            state.add_log(UiLogEvent::new(
                "info",
                "rule",
                format!(
                    "batch rule state updated: {} rules {}",
                    rules.len(),
                    if payload.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ),
            ));
            ok(rules).into_response()
        }
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
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
    duplicate.managed_by_template_key = None;
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
    #[serde(default, deserialize_with = "deserialize_nullable_field")]
    group: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_field")]
    tags: Option<Option<Vec<String>>>,
    matcher: MatchCriteria,
    #[serde(default)]
    proxy_profile: Option<String>,
    #[serde(default)]
    action: Option<RouteAction>,
    #[serde(default)]
    network: Option<NetworkPolicy>,
    #[serde(default)]
    dns: Option<DnsPolicy>,
    #[serde(default)]
    destination: Option<DestinationMatch>,
    protocols: Option<Vec<crate::model::Protocol>>,
    #[serde(default)]
    priority: Option<i32>,
    auto_bind_children: Option<bool>,
    force_dns: Option<bool>,
    block_ipv6: Option<bool>,
    block_doh: Option<bool>,
    enabled: Option<bool>,
}

fn deserialize_nullable_field<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: DeserializeOwned,
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(Some(None));
    }
    serde_json::from_value(value)
        .map(|parsed| Some(Some(parsed)))
        .map_err(serde::de::Error::custom)
}

async fn create_rule(
    State(state): State<CoreState>,
    Json(payload): Json<RuleUpsert>,
) -> impl IntoResponse {
    let mut rule = Rule::new(
        payload.name,
        payload.matcher,
        payload.proxy_profile.unwrap_or_default(),
    );

    rule.group = payload.group.flatten();
    if let Some(tags) = payload.tags.flatten() {
        rule.tags = tags;
    }

    if let Some(action) = payload.action {
        rule.action = action;
    }
    if let Some(network) = payload.network {
        rule.network = network;
    }
    if let Some(dns) = payload.dns {
        rule.dns = dns;
    }
    if let Some(destination) = payload.destination {
        rule.destination = destination;
    }

    if let Some(protocols) = payload.protocols {
        rule.protocols = protocols;
    }
    if let Some(priority) = payload.priority {
        rule.priority = priority;
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
            state.timeline.record(
                crate::timeline::EventCategory::Policy,
                crate::timeline::EventSeverity::Info,
                "rule",
                "Rule Created",
                format!("rule created: {}", saved.name),
                Some(saved.id.clone()),
            );
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
            if let Some(group) = payload.group {
                rule.group = group;
            }
            if let Some(tags) = payload.tags {
                rule.tags = tags.unwrap_or_default();
            }
            rule.matcher = payload.matcher;
            if let Some(proxy_profile) = payload.proxy_profile {
                rule.proxy_profile = proxy_profile.clone();
                if payload.action.is_none() && matches!(rule.action, RouteAction::Proxy { .. }) {
                    rule.action = RouteAction::Proxy {
                        proxy_id: proxy_profile,
                    };
                }
            }
            if let Some(action) = payload.action {
                rule.action = action;
            } else if matches!(
                &rule.action,
                RouteAction::Proxy { ref proxy_id } if proxy_id.trim().is_empty()
            ) {
                rule.action = RouteAction::Proxy {
                    proxy_id: rule.proxy_profile.clone(),
                };
            }
            if let Some(network) = payload.network {
                rule.network = network;
            }
            if let Some(dns) = payload.dns {
                rule.dns = dns;
            }
            if let Some(destination) = payload.destination {
                rule.destination = destination;
            }
            if let Some(protocols) = payload.protocols {
                rule.protocols = protocols;
            }
            if let Some(priority) = payload.priority {
                rule.priority = priority;
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
            state.timeline.record(
                crate::timeline::EventCategory::Policy,
                crate::timeline::EventSeverity::Info,
                "rule",
                "Rule Deleted",
                format!("rule deleted: {id}"),
                Some(id.clone()),
            );
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileCreateRequest {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileCloneRequest {
    name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileDiff {
    profile_id: String,
    profile_name: String,
    active: bool,
    changed_sections: Vec<String>,
    profile_rule_count: usize,
    current_rule_count: usize,
    profile_quick_bar_count: usize,
    current_quick_bar_count: usize,
}

async fn list_profiles(State(state): State<CoreState>) -> Json<ApiResponse<Vec<RoutingProfile>>> {
    ok(state.config.read().profiles.clone())
}

async fn get_profile(State(state): State<CoreState>, Path(id): Path<String>) -> impl IntoResponse {
    let profile = state
        .config
        .read()
        .profiles
        .iter()
        .find(|profile| profile.id == id)
        .cloned();
    match profile {
        Some(profile) => ok(profile).into_response(),
        None => err(StatusCode::NOT_FOUND, "profile not found").into_response(),
    }
}

async fn create_profile(
    State(state): State<CoreState>,
    Json(payload): Json<ProfileCreateRequest>,
) -> impl IntoResponse {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return err(StatusCode::BAD_REQUEST, "profile name cannot be empty").into_response();
    }
    let description = payload.description.trim().to_string();
    let result = state.mutate_config(|cfg| {
        if cfg
            .profiles
            .iter()
            .any(|profile| profile.name.eq_ignore_ascii_case(&name))
        {
            return Err(anyhow::anyhow!("profile name already exists: {name}"));
        }
        let profile = RoutingProfile::from_config(cfg, name.clone(), description.clone());
        cfg.profiles.push(profile.clone());
        Ok(profile)
    });
    match result {
        Ok(Ok(profile)) => {
            state.add_log(UiLogEvent::with_event_id(
                "info",
                "profile",
                crate::events::id::PROFILE_CREATED,
                format!("profile created: {}", profile.name),
            ));
            ok(profile).into_response()
        }
        Ok(Err(error)) => err(StatusCode::CONFLICT, error.to_string()).into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn clone_profile(
    State(state): State<CoreState>,
    Path(id): Path<String>,
    Json(payload): Json<ProfileCloneRequest>,
) -> impl IntoResponse {
    let result = state.mutate_config(|cfg| {
        let Some(source) = cfg
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .cloned()
        else {
            return Ok::<Option<RoutingProfile>, anyhow::Error>(None);
        };
        let mut clone = source;
        clone.id = uuid::Uuid::new_v4().to_string();
        clone.name = payload
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{} Copy", clone.name));
        if cfg
            .profiles
            .iter()
            .any(|profile| profile.name.eq_ignore_ascii_case(&clone.name))
        {
            return Err(anyhow::anyhow!(
                "profile name already exists: {}",
                clone.name
            ));
        }
        let now = Utc::now();
        clone.created_at = now;
        clone.updated_at = now;
        cfg.profiles.push(clone.clone());
        Ok(Some(clone))
    });
    match result {
        Ok(Ok(Some(profile))) => ok(profile).into_response(),
        Ok(Ok(None)) => err(StatusCode::NOT_FOUND, "profile not found").into_response(),
        Ok(Err(error)) => err(StatusCode::CONFLICT, error.to_string()).into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn activate_profile(
    State(state): State<CoreState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let result = state.mutate_config(|cfg| {
        let Some(profile) = cfg
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .cloned()
        else {
            return Ok::<Option<RoutingProfile>, anyhow::Error>(None);
        };
        profile.apply_to_config(cfg);
        Ok(Some(profile))
    });
    match result {
        Ok(Ok(Some(profile))) => {
            state.add_log(UiLogEvent::with_event_id(
                "info",
                "profile",
                crate::events::id::PROFILE_ACTIVATED,
                format!("profile activated: {}", profile.name),
            ));
            ok(profile).into_response()
        }
        Ok(Ok(None)) => err(StatusCode::NOT_FOUND, "profile not found").into_response(),
        Ok(Err(error)) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn delete_profile(
    State(state): State<CoreState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let result = state.mutate_config(|cfg| {
        let before = cfg.profiles.len();
        cfg.profiles.retain(|profile| profile.id != id);
        if cfg.active_profile_id.as_deref() == Some(id.as_str()) {
            cfg.active_profile_id = None;
        }
        before != cfg.profiles.len()
    });
    match result {
        Ok(true) => ok("deleted").into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn profile_diff(State(state): State<CoreState>, Path(id): Path<String>) -> impl IntoResponse {
    let config = state.config_snapshot();
    let Some(profile) = config.profiles.iter().find(|profile| profile.id == id) else {
        return err(StatusCode::NOT_FOUND, "profile not found").into_response();
    };
    let mut changed_sections = Vec::new();
    if profile.engine_mode != config.engine_mode {
        changed_sections.push("engine".to_string());
    }
    if serde_json::to_value(&profile.runtime).ok() != serde_json::to_value(&config.runtime).ok() {
        changed_sections.push("runtime".to_string());
    }
    if serde_json::to_value(&profile.rules).ok() != serde_json::to_value(&config.rules).ok() {
        changed_sections.push("rules".to_string());
    }
    if serde_json::to_value(&profile.quick_bar).ok() != serde_json::to_value(&config.quick_bar).ok()
    {
        changed_sections.push("quickBar".to_string());
    }
    ok(ProfileDiff {
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        active: config.active_profile_id.as_deref() == Some(profile.id.as_str()),
        changed_sections,
        profile_rule_count: profile.rules.len(),
        current_rule_count: config.rules.len(),
        profile_quick_bar_count: profile.quick_bar.len(),
        current_quick_bar_count: config.quick_bar.len(),
    })
    .into_response()
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TemplateSummary {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    rule_count: usize,
}

struct TemplateRuleSpec {
    name: &'static str,
    app_names: &'static [&'static str],
}

struct TemplateSpec {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    rules: &'static [TemplateRuleSpec],
}

const TEMPLATE_REGISTRY: &[TemplateSpec] = &[
    TemplateSpec {
        id: "ai-dev",
        name: "AI development",
        description: "Editors, runtimes, and browser tooling",
        rules: &[
            TemplateRuleSpec {
                name: "AI IDE: VS Code",
                app_names: &["code.exe"],
            },
            TemplateRuleSpec {
                name: "AI IDE: Code - Insiders",
                app_names: &["code - insiders.exe"],
            },
            TemplateRuleSpec {
                name: "AI IDE: Cursor",
                app_names: &["cursor.exe"],
            },
            TemplateRuleSpec {
                name: "AI IDE: Windsurf",
                app_names: &["windsurf.exe"],
            },
            TemplateRuleSpec {
                name: "AI IDE: Node Toolchain",
                app_names: &["node.exe"],
            },
            TemplateRuleSpec {
                name: "AI IDE: Chrome",
                app_names: &["chrome.exe"],
            },
            TemplateRuleSpec {
                name: "AI IDE: Edge",
                app_names: &["msedge.exe"],
            },
        ],
    },
    TemplateSpec {
        id: "browser",
        name: "Web browsers",
        description: "Chrome, Edge, and Firefox",
        rules: &[
            TemplateRuleSpec {
                name: "Browser: Chrome",
                app_names: &["chrome.exe"],
            },
            TemplateRuleSpec {
                name: "Browser: Edge",
                app_names: &["msedge.exe"],
            },
            TemplateRuleSpec {
                name: "Browser: Firefox",
                app_names: &["firefox.exe"],
            },
        ],
    },
    TemplateSpec {
        id: "gaming",
        name: "Gaming",
        description: "Steam and common game launchers",
        rules: &[
            TemplateRuleSpec {
                name: "Gaming: Steam",
                app_names: &["steam.exe"],
            },
            TemplateRuleSpec {
                name: "Gaming: Steam Web Helper",
                app_names: &["steamwebhelper.exe"],
            },
            TemplateRuleSpec {
                name: "Gaming: Epic Games Launcher",
                app_names: &["epicgameslauncher.exe"],
            },
        ],
    },
    TemplateSpec {
        id: "meetings",
        name: "Meetings",
        description: "Teams, Zoom, and Discord",
        rules: &[
            TemplateRuleSpec {
                name: "Meetings: Teams",
                app_names: &["ms-teams.exe", "teams.exe"],
            },
            TemplateRuleSpec {
                name: "Meetings: Zoom",
                app_names: &["zoom.exe"],
            },
            TemplateRuleSpec {
                name: "Meetings: Discord",
                app_names: &["discord.exe"],
            },
        ],
    },
];

fn template_summaries() -> Vec<TemplateSummary> {
    TEMPLATE_REGISTRY
        .iter()
        .map(|template| TemplateSummary {
            id: template.id,
            name: template.name,
            description: template.description,
            rule_count: template.rules.len(),
        })
        .collect()
}

async fn list_templates() -> Json<ApiResponse<Vec<TemplateSummary>>> {
    ok(template_summaries())
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
        rule.action = RouteAction::Proxy {
            proxy_id: item.proxy_profile.clone(),
        };
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

fn template_rules(template_id: &str, proxy_profile: &str) -> Option<Vec<Rule>> {
    let template = TEMPLATE_REGISTRY
        .iter()
        .find(|template| template.id == template_id)?;

    Some(
        template
            .rules
            .iter()
            .map(|spec| {
                let mut rule = Rule::new(
                    spec.name.to_string(),
                    MatchCriteria {
                        app_names: spec
                            .app_names
                            .iter()
                            .map(|name| (*name).to_string())
                            .collect(),
                        ..Default::default()
                    },
                    proxy_profile.to_string(),
                );
                rule.group = Some(template_id.to_string());
                rule.tags = vec!["template".to_string(), template_id.to_string()];
                rule.managed_by_template_key = Some(format!("{}:{}", template_id, spec.name));
                rule
            })
            .collect(),
    )
}

fn is_template_rule(rule: &Rule, template_id: &str, name: &str) -> bool {
    rule.source == RuleSource::User
        && rule.managed_by_template_key.as_deref()
            == Some(format!("{}:{}", template_id, name).as_str())
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyImportPreviewItem {
    id: String,
    name: String,
    kind: crate::model::ProxyKind,
    endpoint: String,
    enabled: bool,
    action: &'static str,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyImportPreview {
    operation: &'static str,
    format: &'static str,
    valid: bool,
    validation_error: Option<String>,
    added: usize,
    updated: usize,
    skipped: usize,
    current_proxy_count: usize,
    proposed_proxy_count: usize,
    items: Vec<ProxyImportPreviewItem>,
    skipped_items: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyImportApplyResult {
    format: &'static str,
    added: usize,
    updated: usize,
    skipped: usize,
    proxies: Vec<ProxyProfile>,
}

fn proxy_import_preview_data(
    current: &AppConfig,
    batch: &ImportBatch,
    proposed: &AppConfig,
    validation_error: Option<String>,
) -> ProxyImportPreview {
    let updated = batch
        .proxies
        .iter()
        .filter(|item| {
            current
                .proxies
                .iter()
                .any(|proxy| proxy.id == item.profile.id)
        })
        .count();
    let items = batch
        .proxies
        .iter()
        .map(|item| ProxyImportPreviewItem {
            id: item.profile.id.clone(),
            name: item.profile.name.clone(),
            kind: item.profile.kind,
            endpoint: item.profile.endpoint.clone(),
            enabled: item.profile.enabled,
            action: if current
                .proxies
                .iter()
                .any(|proxy| proxy.id == item.profile.id)
            {
                "update"
            } else {
                "add"
            },
            warnings: item.warnings.clone(),
        })
        .collect();
    ProxyImportPreview {
        operation: "merge",
        format: batch.format,
        valid: validation_error.is_none(),
        validation_error,
        added: batch.proxies.len().saturating_sub(updated),
        updated,
        skipped: batch.skipped.len(),
        current_proxy_count: current.proxies.len(),
        proposed_proxy_count: proposed.proxies.len(),
        items,
        skipped_items: batch.skipped.clone(),
    }
}

fn proxy_import_validation(
    proposed: &AppConfig,
    batch: &ImportBatch,
    state: &CoreState,
) -> (Option<String>, Vec<CompileDiagnostic>) {
    let diagnostics = compile_routing_plan(proposed, &state.list_processes())
        .map(|plan| plan.diagnostics)
        .unwrap_or_default();
    let validation_error = crate::validation::validate_config(proposed)
        .err()
        .map(|error| error.to_string())
        .or_else(|| {
            if batch.proxies.is_empty() && !batch.skipped.is_empty() {
                return Some("no valid proxy endpoints were found in the import".to_string());
            }
            (proposed.runtime.leak_protection_mode == crate::model::LeakProtectionMode::Strict)
                .then(|| {
                    diagnostics
                        .iter()
                        .find(|diagnostic| diagnostic.blocks_strict)
                        .map(|diagnostic| diagnostic.message.clone())
                })
                .flatten()
        });
    (validation_error, diagnostics)
}

async fn preview_proxy_import(
    State(state): State<CoreState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let current = state.config_snapshot();
    let batch = match proxy_import::parse(&payload, current.engine_mode) {
        Ok(batch) => batch,
        Err(error) => return err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let proposed = proxy_import::merge_config(&current, &batch.proxies);
    let (validation_error, diagnostics) = proxy_import_validation(&proposed, &batch, &state);
    ok_with_diagnostics(
        proxy_import_preview_data(&current, &batch, &proposed, validation_error),
        diagnostics,
    )
    .into_response()
}

async fn apply_proxy_import(
    State(state): State<CoreState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let current = state.config_snapshot();
    let batch = match proxy_import::parse(&payload, current.engine_mode) {
        Ok(batch) => batch,
        Err(error) => return err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let proposed = proxy_import::merge_config(&current, &batch.proxies);
    let (validation_error, proposed_diagnostics) =
        proxy_import_validation(&proposed, &batch, &state);
    if let Some(error) = validation_error {
        return err_with_diagnostics(StatusCode::BAD_REQUEST, error, proposed_diagnostics)
            .into_response();
    }
    let updated = batch
        .proxies
        .iter()
        .filter(|item| {
            current
                .proxies
                .iter()
                .any(|proxy| proxy.id == item.profile.id)
        })
        .count();
    match state.replace_imported_config(proposed) {
        Ok(config) => {
            state.add_log(UiLogEvent::new(
                "info",
                "proxy",
                format!("proxy endpoints imported: {}", batch.format),
            ));
            ok_with_diagnostics(
                ProxyImportApplyResult {
                    format: batch.format,
                    added: batch.proxies.len().saturating_sub(updated),
                    updated,
                    skipped: batch.skipped.len(),
                    proxies: config.proxies,
                },
                state.runtime_status().compile_diagnostics,
            )
            .into_response()
        }
        Err(error) => err_with_diagnostics(
            StatusCode::BAD_REQUEST,
            error.to_string(),
            proposed_diagnostics,
        )
        .into_response(),
    }
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
    /// `None` means the field was omitted (preserve on update); `Some(None)`
    /// is an explicit JSON null and clears the username.
    #[serde(default, deserialize_with = "deserialize_nullable_field")]
    username: Option<Option<String>>,
    password: Option<String>,
    #[serde(default)]
    clear_password: bool,
    enabled: Option<bool>,
}

async fn create_proxy(
    State(state): State<CoreState>,
    Json(payload): Json<ProxyUpsert>,
) -> impl IntoResponse {
    let mut proxy = ProxyProfile {
        id: payload
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: payload.name,
        kind: payload.kind,
        endpoint: payload.endpoint,
        username: payload.username.flatten(),
        password_ref: None,
        password: payload.password,
        enabled: payload.enabled.unwrap_or(true),
    };
    if payload.clear_password {
        return err(
            StatusCode::BAD_REQUEST,
            "clearPassword cannot be used while creating a proxy",
        )
        .into_response();
    }
    let mut created_secret_ref = None;
    let result = state.try_mutate_config(|cfg| {
        if cfg.proxies.iter().any(|existing| existing.id == proxy.id) {
            return Err(anyhow::anyhow!("proxy id '{}' already exists", proxy.id));
        }
        crate::config::persist_proxy_secret(&mut proxy)?;
        created_secret_ref = proxy.password_ref.clone();
        cfg.proxies.push(proxy.clone());
        Ok(proxy.clone())
    });

    match result {
        Ok(saved) => {
            state.timeline.record(
                crate::timeline::EventCategory::Proxy,
                crate::timeline::EventSeverity::Info,
                "proxy",
                "Proxy Created",
                format!("proxy created: {}", saved.name),
                Some(saved.id.clone()),
            );
            state.add_log(UiLogEvent::new(
                "info",
                "proxy",
                format!("proxy created: {}", saved.name),
            ));
            ok(saved).into_response()
        }
        Err(error) => {
            if created_secret_ref.is_some() {
                if let Err(cleanup_error) = state.delete_secret_if_unreferenced(
                    created_secret_ref.as_deref().unwrap_or_default(),
                ) {
                    tracing::warn!(%cleanup_error, proxy = %proxy.id, "failed to clean up proxy secret after create rollback");
                }
            }
            err(StatusCode::BAD_REQUEST, error.to_string()).into_response()
        }
    }
}

async fn update_proxy(
    State(state): State<CoreState>,
    Path(id): Path<String>,
    Json(payload): Json<ProxyUpsert>,
) -> impl IntoResponse {
    let mut previous = None;
    let mut candidate_secret_ref = None;
    let clear_password = payload.clear_password;
    let result = state.try_mutate_config(|cfg| {
        let Some(proxy) = cfg.proxies.iter_mut().find(|proxy| proxy.id == id) else {
            return Ok(None);
        };

        let existing = proxy.clone();
        previous = Some(existing.clone());
        let mut candidate = existing;
        candidate.name = payload.name.clone();
        candidate.kind = payload.kind;
        candidate.endpoint = payload.endpoint.clone();
        if let Some(username) = payload.username.clone() {
            candidate.username = username;
        }
        if clear_password {
            candidate.password = None;
            candidate.password_ref = None;
        } else if payload.password.is_some() {
            candidate.password = payload.password.clone();
        }
        if let Some(enabled) = payload.enabled {
            candidate.enabled = enabled;
        }
        if !clear_password && candidate.password.is_some() {
            crate::config::persist_proxy_secret(&mut candidate)?;
            candidate_secret_ref = candidate.password_ref.clone();
        }
        *proxy = candidate.clone();
        Ok(Some(candidate))
    });

    if let Err(error) = &result {
        if let (Some(previous), Some(candidate_secret_ref)) =
            (previous.as_ref(), candidate_secret_ref.as_deref())
        {
            if let Err(restore_error) =
                state.restore_secret_after_failed_proxy_update(&id, previous, candidate_secret_ref)
            {
                tracing::warn!(%restore_error, proxy = %id, "failed to restore proxy secret after update rollback");
            }
        }
        return err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }

    match result.unwrap() {
        Some(saved) => {
            if clear_password {
                if let Some(previous) = previous.as_ref() {
                    if let Some(secret_ref) = previous.password_ref.as_deref() {
                        let cleanup_result = state.delete_secret_if_unreferenced(secret_ref);
                        if let Err(error) = cleanup_result {
                            tracing::warn!(%error, proxy = %id, "failed to remove cleared proxy secret");
                        }
                    }
                }
            }
            state.add_log(UiLogEvent::new(
                "info",
                "proxy",
                format!("proxy updated: {}", saved.name),
            ));
            ok(saved).into_response()
        }
        None => err(StatusCode::NOT_FOUND, "proxy not found").into_response(),
    }
}

async fn delete_proxy(State(state): State<CoreState>, Path(id): Path<String>) -> impl IntoResponse {
    let old_proxy = state
        .config_snapshot()
        .proxies
        .iter()
        .find(|proxy| proxy.id == id)
        .cloned();
    let result = state.try_mutate_config(|cfg| {
        if let Some(profile) = cfg.profiles.iter().find(|profile| {
            profile.rules.iter().any(|rule| {
                if let crate::model::RouteAction::Proxy { proxy_id } = &rule.action {
                    let target = if proxy_id.trim().is_empty() {
                        rule.proxy_profile.as_str()
                    } else {
                        proxy_id.as_str()
                    };
                    target == id
                } else {
                    false
                }
            }) || profile
                .quick_bar
                .iter()
                .any(|item| item.proxy_profile == id)
        }) {
            return Err(anyhow::anyhow!(
                "proxy '{}' is referenced by profile '{}' and cannot be deleted",
                id,
                profile.name
            ));
        }
        let before = cfg.proxies.len();
        cfg.proxies.retain(|proxy| proxy.id != id);
        Ok(before != cfg.proxies.len())
    });

    match result {
        Ok(true) => {
            if let Some(proxy) = old_proxy.as_ref() {
                if let Some(secret_ref) = proxy.password_ref.as_deref() {
                    if let Err(error) = state.delete_secret_if_unreferenced(secret_ref) {
                        tracing::warn!(%error, proxy = %id, "failed to remove deleted proxy secret");
                    }
                }
            }
            state.timeline.record(
                crate::timeline::EventCategory::Proxy,
                crate::timeline::EventSeverity::Info,
                "proxy",
                "Proxy Deleted",
                format!("proxy deleted: {id}"),
                Some(id.clone()),
            );
            state.add_log(UiLogEvent::new(
                "info",
                "proxy",
                format!("proxy deleted: {id}"),
            ));
            ok("deleted").into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "proxy not found").into_response(),
        Err(error) => err(StatusCode::CONFLICT, error.to_string()).into_response(),
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
    let mode_desc = format!("{:?}", payload.mode);
    let result = state.mutate_config(|cfg| {
        cfg.engine_mode = payload.mode;
    });

    match result {
        Ok(()) => {
            state.timeline.record(
                crate::timeline::EventCategory::Engine,
                crate::timeline::EventSeverity::Info,
                "engine",
                "Engine Mode Switched",
                format!("engine mode switched to {mode_desc}"),
                None,
            );
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

async fn apply_template(
    State(state): State<CoreState>,
    Path(template_id): Path<String>,
    Json(payload): Json<TemplateApplyRequest>,
) -> impl IntoResponse {
    if template_rules(&template_id, &payload.proxy_profile).is_none() {
        return err(StatusCode::NOT_FOUND, "template not found").into_response();
    }
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

        for template_rule in
            template_rules(&template_id, &payload.proxy_profile).unwrap_or_default()
        {
            if let Some(existing) = cfg
                .rules
                .iter_mut()
                .find(|rule| is_template_rule(rule, &template_id, &template_rule.name))
            {
                existing.matcher = template_rule.matcher.clone();
                existing.proxy_profile = template_rule.proxy_profile.clone();
                existing.action = RouteAction::Proxy {
                    proxy_id: template_rule.proxy_profile.clone(),
                };
                existing.protocols = template_rule.protocols.clone();
                existing.auto_bind_children = template_rule.auto_bind_children;
                existing.force_dns = template_rule.force_dns;
                existing.block_ipv6 = template_rule.block_ipv6;
                existing.block_doh = template_rule.block_doh;
                existing.group = template_rule.group.clone();
                existing.tags = template_rule.tags.clone();
                existing.enabled = true;
                existing.updated_at = Utc::now();
                updated_rules += 1;
            } else {
                cfg.rules.push(template_rule);
                added_rules += 1;
            }
        }

        TemplateApplyResult {
            template_id: template_id.clone(),
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
                    "applied {} template: {} added, {} updated",
                    summary.template_id, summary.added_rules, summary.updated_rules
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

async fn list_connections(
    State(state): State<CoreState>,
    Query(filter): Query<crate::observability::ConnectionFilter>,
) -> impl IntoResponse {
    let processes = state.list_processes();
    let config = state.config_snapshot();
    let records = crate::observability::ConnectionCollector::collect(
        &processes,
        &config.rules,
        &config.proxies,
        Some(&filter),
    );
    ok(records).into_response()
}

async fn get_connections_summary(State(state): State<CoreState>) -> impl IntoResponse {
    let processes = state.list_processes();
    let config = state.config_snapshot();
    let records = crate::observability::ConnectionCollector::collect(
        &processes,
        &config.rules,
        &config.proxies,
        None,
    );
    let summary = crate::observability::ConnectionCollector::summarize(&records);
    ok(summary).into_response()
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DiscoverEndpointsRequest {
    #[serde(default)]
    own_port: Option<u16>,
}

async fn discover_endpoints(
    State(state): State<CoreState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let payload: Option<DiscoverEndpointsRequest> = if body.is_empty() {
        None
    } else {
        serde_json::from_slice(&body).ok()
    };
    let processes = state.list_processes();
    let config = state.config_snapshot();
    let own_port = payload.and_then(|p| p.own_port).unwrap_or(0);
    let discovered =
        crate::endpoint::EndpointDiscoverer::discover(&processes, &config.proxies, own_port).await;
    ok(discovered).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddDiscoveredEndpointRequest {
    endpoint: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_discovered_proxy_kind")]
    kind: ProxyKind,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

fn default_discovered_proxy_kind() -> ProxyKind {
    ProxyKind::Socks5
}

async fn add_discovered_endpoint(
    State(state): State<CoreState>,
    Json(payload): Json<AddDiscoveredEndpointRequest>,
) -> impl IntoResponse {
    let mut proxy = ProxyProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name: payload
            .name
            .unwrap_or_else(|| format!("Discovered {}", payload.endpoint)),
        kind: payload.kind,
        endpoint: payload.endpoint.clone(),
        username: payload.username,
        password_ref: None,
        password: payload.password,
        enabled: true,
    };

    let result = state.try_mutate_config(|cfg| {
        if cfg.proxies.iter().any(|existing| {
            existing
                .endpoint
                .trim()
                .eq_ignore_ascii_case(proxy.endpoint.trim())
        }) {
            return Err(anyhow::anyhow!(
                "proxy with endpoint '{}' already exists",
                proxy.endpoint
            ));
        }
        crate::config::persist_proxy_secret(&mut proxy)?;
        cfg.proxies.push(proxy.clone());
        Ok(proxy.clone())
    });

    match result {
        Ok(saved) => {
            state.timeline.record(
                crate::timeline::EventCategory::Endpoint,
                crate::timeline::EventSeverity::Info,
                "endpoint_discoverer",
                "Discovered Endpoint Added",
                format!("endpoint {} added to proxies", saved.endpoint),
                Some(saved.id.clone()),
            );
            state.add_log(UiLogEvent::new(
                "info",
                "proxy",
                format!(
                    "discovered endpoint added: {} ({})",
                    saved.name, saved.endpoint
                ),
            ));
            ok(saved).into_response()
        }
        Err(error) => err(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn list_timeline_events(
    State(state): State<CoreState>,
    Query(filter): Query<crate::timeline::TimelineFilter>,
) -> impl IntoResponse {
    let events = state.timeline.query(Some(&filter));
    ok(events).into_response()
}

async fn clear_timeline_events(State(state): State<CoreState>) -> impl IntoResponse {
    state.timeline.clear();
    ok(true).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    use super::*;
    use crate::model::{AppConfig, LeakProtectionMode, MatchCriteria, Rule};

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

    #[test]
    fn simulation_destination_matching_supports_wildcards_and_cidrs() {
        let mut rule = Rule::new(
            "destination".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        );
        rule.destination.domains = vec!["*.example.com".into()];
        rule.destination.ip_cidrs = vec!["10.0.0.0/8".into()];
        rule.destination.ports = vec![443];

        let destination = SimulationDestination {
            domain: Some("example.com".into()),
            ip: Some("10.42.1.9".into()),
            port: Some(443),
        };
        assert!(destination_matches(
            &rule,
            Some(&destination),
            Protocol::Tcp
        ));

        let outside = SimulationDestination {
            domain: Some("evil.example.net".into()),
            ip: Some("192.0.2.9".into()),
            port: Some(443),
        };
        assert!(!destination_matches(&rule, Some(&outside), Protocol::Tcp));
    }

    #[test]
    fn diagnostics_redact_secrets_paths_and_truncate_text() {
        let secret = "fixture-secret".to_string();
        let source = format!(
            "password={secret}\npath={}\\ProxyDuck\\config.json\nregular=kept",
            std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\fixture".to_string())
        );
        let redacted = redact_diagnostic_text(&source, &[secret]);
        assert!(!redacted.contains("fixture-secret"));
        assert!(!redacted.contains("USERPROFILE"));
        assert!(redacted.contains("regular=kept"));

        let oversized = "x".repeat(MAX_DIAGNOSTIC_TEXT_BYTES + 1024);
        let truncated = redact_diagnostic_text(&oversized, &[]);
        assert!(truncated.len() <= MAX_DIAGNOSTIC_TEXT_BYTES + "\n[TRUNCATED]".len());
        assert!(truncated.contains("[TRUNCATED]"));

        let unicode_oversized = "诊断".repeat(MAX_DIAGNOSTIC_TEXT_BYTES);
        let unicode_truncated = redact_diagnostic_text(&unicode_oversized, &[]);
        assert!(unicode_truncated.contains("[TRUNCATED]"));

        let nested = serde_json::json!({
            "outer": [{ "password": "nested-secret", "safe": "value" }],
            "tokenValue": "another-secret"
        });
        let nested = redact_json_value(nested, &["nested-secret".to_string()]);
        assert_eq!(nested["outer"][0]["password"], "[REDACTED]");
        assert_eq!(nested["outer"][0]["safe"], "value");
        assert_eq!(nested["tokenValue"], "[REDACTED]");
    }

    #[test]
    fn diagnostics_redact_paths_inside_saved_profiles() {
        let user_profile = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| "C:\\Users\\fixture".to_string());
        let sensitive_path = format!(r#"{user_profile}\AppData\Local\ProxyDuck\private.exe"#);
        let mut config = AppConfig::default();
        let mut rule = Rule::new(
            "profile path".to_string(),
            MatchCriteria {
                exe_paths: vec![sensitive_path.clone()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        rule.enabled = false;
        config.rules.push(rule);
        let profile = RoutingProfile::from_config(&config, "Private", "fixture");
        config.profiles.push(profile);

        redact_config_paths(&mut config);
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains(&sensitive_path));
        assert!(serialized.contains("[USER_PATH]"));
    }

    fn integration_state() -> CoreState {
        crate::set_mock_data_plane(true);
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
    async fn integration_diagnostics_bundle_is_a_redacted_zip() {
        let state = integration_state();
        let response = router(state)
            .oneshot(api_request(
                Method::POST,
                "/diagnostics/bundle",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/zip");
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..2], b"PK");
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut names = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect::<Vec<_>>();
        names.sort();
        assert!(names.contains(&"manifest.json".to_string()));
        assert!(names.contains(&"routing-plan.json".to_string()));
        for required in [
            "events.json",
            "system.json",
            "proxyduck.json",
            "engine.json",
            "rules-redacted.json",
            "drivers.json",
            "network-adapters.json",
            "routes.json",
            "dns.json",
            "firewall.json",
            "core.log",
            "engine.log",
            "crash.log",
            "runtime-lock.json",
        ] {
            assert!(names.contains(&required.to_string()), "missing {required}");
        }
    }

    #[tokio::test]
    async fn integration_concurrent_rule_creates_do_not_overwrite_each_other() {
        let state = integration_state();
        let app = router(state.clone());
        let payload = |name: &str| {
            serde_json::json!({
                "name": name,
                "matcher": { "appNames": [format!("{name}.exe")], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                "proxyProfile": "local-socks",
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
    async fn integration_rule_labels_and_batch_enable_are_atomic() {
        let state = integration_state();
        let app = router(state.clone());
        let payload = |name: &str| {
            serde_json::json!({
                "name": name,
                "group": "Browsers",
                "tags": ["Browser", "Managed"],
                "matcher": { "appNames": [format!("{name}.exe")], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                "proxyProfile": "local-socks",
                "protocols": ["tcp"],
                "enabled": true
            })
        };
        let first = app
            .clone()
            .oneshot(api_request(Method::POST, "/rules", payload("browser-one")))
            .await
            .unwrap();
        let second = app
            .clone()
            .oneshot(api_request(Method::POST, "/rules", payload("browser-two")))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        let first_body = json_body(first).await;
        assert_eq!(first_body["data"]["group"], "Browsers");
        assert_eq!(
            first_body["data"]["tags"],
            serde_json::json!(["Browser", "Managed"])
        );
        let ids = state
            .config_snapshot()
            .rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>();

        let disabled = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/rules/batch-enabled",
                serde_json::json!({ "ruleIds": ids, "enabled": false }),
            ))
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::OK);
        assert!(state
            .config_snapshot()
            .rules
            .iter()
            .all(|rule| !rule.enabled));

        let invalid = app
            .oneshot(api_request(
                Method::POST,
                "/rules/batch-enabled",
                serde_json::json!({ "ruleIds": ["missing"], "enabled": true }),
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert!(state
            .config_snapshot()
            .rules
            .iter()
            .all(|rule| !rule.enabled));
    }

    #[tokio::test]
    async fn integration_rule_labels_can_be_explicitly_cleared() {
        let state = integration_state();
        let app = router(state.clone());
        let created = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/rules",
                serde_json::json!({
                    "name": "Clear labels",
                    "group": "Browsers",
                    "tags": ["Browser", "Managed"],
                    "matcher": { "appNames": ["clear-labels.exe"], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                    "proxyProfile": "local-socks",
                    "protocols": ["tcp"],
                    "enabled": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created_body = json_body(created).await;
        let rule_id = created_body["data"]["id"].as_str().unwrap().to_string();

        let cleared = app
            .oneshot(api_request(
                Method::PUT,
                &format!("/rules/{rule_id}"),
                serde_json::json!({
                    "name": "Clear labels",
                    "group": null,
                    "tags": null,
                    "matcher": { "appNames": ["clear-labels.exe"], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                    "proxyProfile": "local-socks",
                    "protocols": ["tcp"],
                    "enabled": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(cleared.status(), StatusCode::OK);
        let cleared_body = json_body(cleared).await;
        assert!(cleared_body["data"]["group"].is_null());
        assert_eq!(cleared_body["data"]["tags"], serde_json::json!([]));
        let saved = state
            .config_snapshot()
            .rules
            .into_iter()
            .find(|rule| rule.id == rule_id)
            .unwrap();
        assert_eq!(saved.group, None);
        assert!(saved.tags.is_empty());
    }

    #[tokio::test]
    async fn integration_templates_are_listed_and_applied_with_labels() {
        let state = integration_state();
        let app = router(state.clone());
        let listed = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                "/templates",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed_body = json_body(listed).await;
        assert_eq!(listed_body["data"].as_array().unwrap().len(), 4);

        let applied = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/templates/browser",
                serde_json::json!({ "proxyProfile": "local-socks" }),
            ))
            .await
            .unwrap();
        assert_eq!(applied.status(), StatusCode::OK);
        let applied_body = json_body(applied).await;
        assert_eq!(applied_body["data"]["templateId"], "browser");
        assert_eq!(applied_body["data"]["addedRules"], 3);
        assert!(state
            .config_snapshot()
            .rules
            .iter()
            .all(|rule| rule.group.as_deref() == Some("browser")));
        assert!(state.config_snapshot().rules.iter().all(|rule| {
            rule.managed_by_template_key
                .as_deref()
                .is_some_and(|key| key.starts_with("browser:"))
        }));

        for (template_id, expected_rules) in [("gaming", 3usize), ("meetings", 3usize)] {
            let applied = app
                .clone()
                .oneshot(api_request(
                    Method::POST,
                    &format!("/templates/{template_id}"),
                    serde_json::json!({ "proxyProfile": "local-socks" }),
                ))
                .await
                .unwrap();
            assert_eq!(applied.status(), StatusCode::OK);
            let body = json_body(applied).await;
            assert_eq!(body["data"]["templateId"], template_id);
            assert_eq!(body["data"]["addedRules"], expected_rules);
        }

        let reapplied = app
            .oneshot(api_request(
                Method::POST,
                "/templates/browser",
                serde_json::json!({ "proxyProfile": "local-socks" }),
            ))
            .await
            .unwrap();
        assert_eq!(reapplied.status(), StatusCode::OK);
        let reapplied_body = json_body(reapplied).await;
        assert_eq!(reapplied_body["data"]["addedRules"], 0);
        assert_eq!(reapplied_body["data"]["updatedRules"], 3);
    }

    #[tokio::test]
    async fn integration_template_does_not_overwrite_same_name_user_rule() {
        let state = integration_state();
        let app = router(state.clone());
        let created = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/rules",
                serde_json::json!({
                    "name": "Browser: Chrome",
                    "group": "browser",
                    "tags": ["template", "browser"],
                    "matcher": { "appNames": ["custom-browser.exe"], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                    "proxyProfile": "local-socks",
                    "protocols": ["tcp"],
                    "enabled": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);

        let applied = app
            .oneshot(api_request(
                Method::POST,
                "/templates/browser",
                serde_json::json!({ "proxyProfile": "local-socks" }),
            ))
            .await
            .unwrap();
        assert_eq!(applied.status(), StatusCode::OK);
        assert_eq!(json_body(applied).await["data"]["addedRules"], 3);

        let user_rule = state
            .config_snapshot()
            .rules
            .into_iter()
            .find(|rule| {
                rule.name == "Browser: Chrome"
                    && rule.matcher.app_names == vec!["custom-browser.exe"]
            })
            .unwrap();
        assert_eq!(user_rule.matcher.app_names, vec!["custom-browser.exe"]);
        assert_eq!(user_rule.group.as_deref(), Some("browser"));
        assert_eq!(user_rule.tags, vec!["template", "browser"]);
        assert!(user_rule.managed_by_template_key.is_none());
    }

    #[tokio::test]
    async fn integration_compile_and_effective_plan_are_read_only_and_redacted() {
        let state = integration_state();
        let app = router(state.clone());
        let created = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/rules",
                serde_json::json!({
                    "name": "Compiler test",
                    "matcher": { "appNames": ["compiler.exe"], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
                    "proxyProfile": "local-socks",
                    "protocols": ["tcp"],
                    "enabled": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created_body = json_body(created).await;
        let rule_id = created_body["data"]["id"].as_str().unwrap().to_string();

        let compiled = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/rules/compile",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(compiled.status(), StatusCode::OK);
        let compiled_body = json_body(compiled).await;
        assert_eq!(compiled_body["data"]["schemaVersion"], 3);
        assert!(compiled_body["data"]["proxyRoutes"][0]
            .get("password")
            .is_none());

        let effective = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                &format!("/rules/{rule_id}/effective-plan"),
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(effective.status(), StatusCode::OK);
        let effective_body = json_body(effective).await;
        assert_eq!(effective_body["data"]["ruleId"], rule_id);
        assert_eq!(effective_body["data"]["engine"], "proxifyre");

        let simulated = app
            .oneshot(api_request(
                Method::POST,
                "/rules/simulate",
                serde_json::json!({
                    "process": { "pid": 4242, "name": "compiler.exe", "exe": "C:\\Apps\\compiler.exe" },
                    "protocol": "tcp",
                    "destination": { "domain": "example.com", "port": 443 }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(simulated.status(), StatusCode::OK);
        let simulated_body = json_body(simulated).await;
        assert_eq!(simulated_body["data"]["destinationMatched"], true);
        assert_eq!(simulated_body["data"]["selectedAction"]["type"], "proxy");
        assert_eq!(simulated_body["data"]["evidenceKind"], "inferred");
    }

    #[tokio::test]
    async fn integration_profiles_snapshot_clone_diff_and_activate() {
        let state = integration_state();
        let app = router(state.clone());
        let created = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/profiles",
                serde_json::json!({
                    "name": "Work",
                    "description": "Office routing"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let profile = json_body(created).await["data"].clone();
        let profile_id = profile["id"].as_str().unwrap().to_string();
        assert_eq!(profile["name"], "Work");
        assert_eq!(profile["rules"].as_array().unwrap().len(), 0);

        let mut rule = Rule::new(
            "Work browser".into(),
            MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        );
        rule.protocols = vec![Protocol::Tcp];
        state.mutate_config(|cfg| cfg.rules.push(rule)).unwrap();

        let diff = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                &format!("/profiles/{profile_id}/diff"),
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(diff.status(), StatusCode::OK);
        let diff_body = json_body(diff).await;
        assert!(diff_body["data"]["changedSections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| section == "rules"));

        let cloned = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                &format!("/profiles/{profile_id}/clone"),
                serde_json::json!({ "name": "Work Copy" }),
            ))
            .await
            .unwrap();
        assert_eq!(cloned.status(), StatusCode::OK);
        let clone_id = json_body(cloned).await["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let activated = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                &format!("/profiles/{profile_id}/activate"),
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(activated.status(), StatusCode::OK);
        assert_eq!(
            state.config_snapshot().active_profile_id.as_deref(),
            Some(profile_id.as_str())
        );
        assert_eq!(state.config_snapshot().rules.len(), 0);

        let deleted = app
            .oneshot(api_request(
                Method::DELETE,
                &format!("/profiles/{clone_id}"),
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn integration_invalid_import_preserves_current_config() {
        let state = integration_state();
        let original = state.config_snapshot();
        // Prime the state with an unrelated routing diagnostic. A later
        // migration failure must not leak this previous request's details.
        let mut strict = original.clone();
        strict.runtime.enabled = true;
        strict.runtime.leak_protection_mode = LeakProtectionMode::Strict;
        let mut strict_rule = Rule::new(
            "Strict diagnostic seed".to_string(),
            MatchCriteria {
                exe_paths: vec!["C:\\Apps\\browser.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        strict_rule.destination.domains = vec!["*.example.com".to_string()];
        strict.rules = vec![strict_rule];
        let priming = router(state.clone())
            .oneshot(api_request(
                Method::PUT,
                "/config",
                serde_json::to_value(strict).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(priming.status(), StatusCode::BAD_REQUEST);

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
        let body = json_body(response).await;
        assert!(body["diagnostics"].as_array().is_none_or(Vec::is_empty));
    }

    #[tokio::test]
    async fn integration_config_import_preview_is_read_only_and_truthful() {
        let state = integration_state();
        let mut managed_rule = Rule::new(
            "Managed browser".to_string(),
            MatchCriteria {
                app_names: vec!["browser.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        managed_rule.enabled = false;
        managed_rule.managed_by_template_key = Some("browser:Managed browser".to_string());
        state
            .mutate_config(|config| config.rules.push(managed_rule))
            .unwrap();
        let original = state.config_snapshot();
        let mut proposed = serde_json::to_value(&original).unwrap();
        proposed["runtime"]["enabled"] = serde_json::json!(true);
        proposed["runtime"]["logLevel"] = serde_json::json!("debug");
        proposed["proxies"][0]["password"] = serde_json::json!("preview-only-secret");
        proposed["rules"][0]["managedByTemplateKey"] = serde_json::json!("forged:key");

        let response = router(state.clone())
            .oneshot(api_request(
                Method::POST,
                "/config/import/preview",
                proposed,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["data"]["operation"], "replace");
        assert_eq!(body["data"]["valid"], true);
        assert!(body["data"]["changedSections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| section == "runtime"));
        assert!(body["data"]["changedSections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| section == "proxies"));
        assert!(!body["data"]["changedSections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| section == "rules"));
        assert_eq!(body["data"]["proposed"]["proxyCount"], 1);
        assert!(!serde_json::to_string(&body)
            .unwrap()
            .contains("preview-only-secret"));
        assert_eq!(
            state.config_snapshot().runtime.enabled,
            original.runtime.enabled
        );
        assert_eq!(
            state.config_snapshot().runtime.log_level,
            original.runtime.log_level
        );
    }

    #[tokio::test]
    async fn integration_proxy_import_preview_and_apply_merge_without_secret_leak() {
        let state = integration_state();
        let app = router(state.clone());
        let source_with_secret = serde_json::json!({
            "proxies": [
                {"name": "Office SOCKS", "type": "socks5", "server": "127.0.0.1", "port": 1080, "password": "preview-only-secret"},
                {"name": "Office HTTP", "type": "http", "server": "proxy.example", "port": 8080}
            ]
        });

        let original_count = state.config_snapshot().proxies.len();
        let preview = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/proxies/import/preview",
                source_with_secret,
            ))
            .await
            .unwrap();
        assert_eq!(preview.status(), StatusCode::OK);
        let preview_body = json_body(preview).await;
        assert_eq!(preview_body["data"]["operation"], "merge");
        assert_eq!(preview_body["data"]["format"], "clash");
        assert_eq!(preview_body["data"]["added"], 2);
        assert_eq!(preview_body["data"]["updated"], 0);
        assert_eq!(preview_body["data"]["valid"], true);
        assert_eq!(preview_body["data"]["items"][1]["enabled"], false);
        assert!(!serde_json::to_string(&preview_body)
            .unwrap()
            .contains("preview-only-secret"));
        assert_eq!(state.config_snapshot().proxies.len(), original_count);

        let apply = app
            .oneshot(api_request(
                Method::POST,
                "/proxies/import",
                serde_json::json!({
                    "proxies": [
                        {"name": "Office SOCKS", "type": "socks5", "server": "127.0.0.1", "port": 1080},
                        {"name": "Office HTTP", "type": "http", "server": "proxy.example", "port": 8080}
                    ]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(apply.status(), StatusCode::OK);
        let apply_body = json_body(apply).await;
        assert_eq!(apply_body["data"]["added"], 2);
        assert_eq!(apply_body["data"]["updated"], 0);
        assert_eq!(state.config_snapshot().proxies.len(), original_count + 2);
        assert!(state
            .config_snapshot()
            .proxies
            .iter()
            .any(|proxy| proxy.name == "Office HTTP" && !proxy.enabled));
    }

    #[tokio::test]
    async fn integration_apply_error_exposes_structured_diagnostics() {
        let state = integration_state();
        let mut invalid = state.config_snapshot();
        invalid.runtime.enabled = true;
        invalid.runtime.leak_protection_mode = LeakProtectionMode::Strict;
        let mut rule = Rule::new(
            "Domain strict rule".to_string(),
            MatchCriteria {
                exe_paths: vec!["C:\\Apps\\browser.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        rule.destination.domains = vec!["*.example.com".to_string()];
        invalid.rules = vec![rule];

        let response = router(state)
            .oneshot(api_request(
                Method::PUT,
                "/config",
                serde_json::to_value(invalid).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        let diagnostic = body["diagnostics"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item["code"] == "PD-RULE-DESTINATION-UNSUPPORTED")
            })
            .expect("strict apply error should include destination diagnostic");
        assert_eq!(diagnostic["severity"], "error");
        assert_eq!(diagnostic["blocksStrict"], true);
        assert!(diagnostic["remediation"].as_str().is_some());
    }

    #[tokio::test]
    async fn integration_compatibility_apply_returns_non_blocking_diagnostics() {
        let state = integration_state();
        let mut compatible = state.config_snapshot();
        compatible.runtime.enabled = true;
        compatible.runtime.leak_protection_mode = LeakProtectionMode::Availability;
        let mut rule = Rule::new(
            "Domain compatibility rule".to_string(),
            MatchCriteria {
                app_names: vec!["browser.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        rule.destination.domains = vec!["*.example.com".to_string()];
        compatible.rules = vec![rule];

        let response = router(state)
            .oneshot(api_request(
                Method::PUT,
                "/config",
                serde_json::to_value(compatible).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let diagnostic = body["diagnostics"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item["code"] == "PD-RULE-DESTINATION-UNSUPPORTED")
            })
            .expect("compatibility apply should include destination diagnostic");
        assert_eq!(diagnostic["severity"], "warning");
        assert_eq!(diagnostic["blocksStrict"], false);
        assert!(diagnostic["effective"].as_str().is_some());
    }

    #[tokio::test]
    async fn integration_legacy_import_is_migrated_before_apply() {
        let state = integration_state();
        let app = router(state.clone());
        let mut legacy = serde_json::to_value(state.config_snapshot()).unwrap();
        legacy["schemaVersion"] = serde_json::json!(3);
        legacy["engineMode"] = serde_json::json!("win_divert");
        legacy["rules"] = serde_json::json!([{
            "id": "legacy-rule",
            "name": "Legacy",
            "enabled": true,
            "matcher": { "appNames": ["legacy.exe"], "exePaths": [], "pids": [], "hashes": [], "wildcard": null },
            "proxyProfile": "clash-socks",
            "protocols": ["tcp", "udp", "dns"],
            "autoBindChildren": false,
            "forceDns": true,
            "blockIpv6": true,
            "blockDoh": true,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z"
        }]);

        let response = app
            .oneshot(api_request(Method::PUT, "/config", legacy))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["data"]["schemaVersion"], 6);
        assert_eq!(body["data"]["engineMode"], "proxifyre");
        assert_eq!(body["data"]["rules"][0]["action"]["type"], "proxy");
        assert_eq!(body["data"]["rules"][0]["proxyProfile"], "local-socks");
        assert_eq!(body["data"]["rules"][0]["dns"]["mode"], "block_plaintext");
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

        let duplicate = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/proxies",
                serde_json::json!({
                    "id": "integration-proxy",
                    "name": "Duplicate proxy",
                    "kind": "socks5",
                    "endpoint": "127.0.0.1:1090",
                    "password": "replacement-secret",
                    "enabled": true
                }),
            ))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            state
                .config_snapshot()
                .proxies
                .iter()
                .find(|proxy| proxy.id == "integration-proxy")
                .and_then(|proxy| proxy.password.as_deref()),
            Some("secret")
        );

        let mut invalid_import = serde_json::to_value(state.config_snapshot()).unwrap();
        let imported_proxy = invalid_import["proxies"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|proxy| proxy["id"] == "integration-proxy")
            .unwrap();
        imported_proxy["password"] = serde_json::json!("replacement-secret");
        imported_proxy["endpoint"] = serde_json::json!("invalid-endpoint");
        let import_response = app
            .clone()
            .oneshot(api_request(Method::PUT, "/config", invalid_import))
            .await
            .unwrap();
        assert_eq!(import_response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            state
                .config_snapshot()
                .proxies
                .iter()
                .find(|proxy| proxy.id == "integration-proxy")
                .and_then(|proxy| proxy.password.as_deref()),
            Some("secret")
        );

        let response = app
            .clone()
            .oneshot(api_request(
                Method::PUT,
                "/proxies/integration-proxy",
                serde_json::json!({
                    "name": "Updated proxy",
                    "kind": "socks5",
                    "endpoint": "127.0.0.1:1081",
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
        assert_eq!(
            state
                .config_snapshot()
                .proxies
                .iter()
                .find(|proxy| proxy.id == "integration-proxy")
                .and_then(|proxy| proxy.password.as_deref()),
            Some("secret")
        );
        assert_eq!(
            state
                .config_snapshot()
                .proxies
                .iter()
                .find(|proxy| proxy.id == "integration-proxy")
                .and_then(|proxy| proxy.username.as_deref()),
            Some("test")
        );

        let cleared_username = app
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
        assert_eq!(cleared_username.status(), StatusCode::OK);
        assert_eq!(
            state
                .config_snapshot()
                .proxies
                .iter()
                .find(|proxy| proxy.id == "integration-proxy")
                .and_then(|proxy| proxy.username.as_deref()),
            None
        );

        let diagnostics = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                "/diagnostics",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(diagnostics.status(), StatusCode::OK);
        let diagnostics_body = json_body(diagnostics).await;
        let diagnostic_proxy = diagnostics_body["data"]["config"]["proxies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|proxy| proxy["id"] == "integration-proxy")
            .unwrap();
        assert!(diagnostic_proxy.get("password").is_none());
        assert!(diagnostic_proxy.get("passwordRef").is_none());
        assert!(diagnostic_proxy.get("username").is_none());

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

    #[tokio::test]
    async fn integration_rules_analyze_and_simulate() {
        let state = integration_state();
        let app = router(state.clone());

        // 1. Test GET /rules/analyze
        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                "/rules/analyze",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body["data"]["totalRules"].is_number());
        assert!(body["data"]["issues"].is_array());

        // 2. Test POST /rules/analyze with draft rules containing a dead rule and a shadowed rule
        let dead = Rule::new(
            "Dead Empty Rule".to_string(),
            MatchCriteria::default(),
            "local-socks".to_string(),
        );
        let mut wild = Rule::new(
            "Catch All".to_string(),
            MatchCriteria {
                wildcard: Some("*".to_string()),
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        wild.priority = 200;
        let mut shadowed = Rule::new(
            "Chrome App".to_string(),
            MatchCriteria {
                app_names: vec!["chrome.exe".to_string()],
                ..Default::default()
            },
            "local-socks".to_string(),
        );
        shadowed.priority = 50;

        let draft_rules = serde_json::to_value(vec![dead, wild, shadowed]).unwrap();

        let response = app
            .clone()
            .oneshot(api_request(Method::POST, "/rules/analyze", draft_rules))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let issues = body["data"]["issues"].as_array().unwrap();
        assert!(issues.iter().any(|i| i["kind"] == "dead_rule"));
        assert!(issues.iter().any(|i| i["kind"] == "shadowed"));

        // 3. Test POST /rules/simulate
        let sim_payload = serde_json::json!({
            "processName": "chrome.exe",
            "exePath": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "domain": "github.com",
            "port": 443,
            "protocol": "tcp"
        });

        let response = app
            .oneshot(api_request(Method::POST, "/rules/simulate", sim_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body["data"]["policySimulation"].is_object());
        assert!(body["data"]["policySimulation"]["routeTrace"]["steps"].is_array());
    }

    #[tokio::test]
    async fn integration_observability_endpoints_and_timeline() {
        let state = integration_state();
        let app = router(state.clone());

        // 1. Test GET /connections
        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                "/connections",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body["data"].is_array());

        // 2. Test GET /connections/summary
        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                "/connections/summary",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body["data"]["totalConnections"].is_number());
        assert!(body["data"]["topProcesses"].is_array());

        // 3. Test POST /endpoints/discover
        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/endpoints/discover",
                serde_json::json!({ "ownPort": 60000 }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body["data"].is_array());

        // 4. Test POST /endpoints/discover/add
        let add_payload = serde_json::json!({
            "endpoint": "127.0.0.1:20808",
            "name": "Auto Discovered Proxy",
            "kind": "socks5"
        });
        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/endpoints/discover/add",
                add_payload,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["data"]["endpoint"], "127.0.0.1:20808");
        assert_eq!(body["data"]["name"], "Auto Discovered Proxy");

        // Verify it was added to state config
        assert!(state
            .config_snapshot()
            .proxies
            .iter()
            .any(|p| p.endpoint == "127.0.0.1:20808"));

        // 5. Test GET /timeline - should contain the event from adding discovered endpoint
        let response = app
            .clone()
            .oneshot(api_request(Method::GET, "/timeline", serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let events = body["data"].as_array().unwrap();
        assert!(!events.is_empty());
        assert!(events
            .iter()
            .any(|e| e["title"] == "Discovered Endpoint Added"));

        // 6. Test POST /timeline/clear
        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/timeline/clear",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify timeline is now empty
        let response = app
            .oneshot(api_request(Method::GET, "/timeline", serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let events = body["data"].as_array().unwrap();
        assert!(events.is_empty());
    }
}
