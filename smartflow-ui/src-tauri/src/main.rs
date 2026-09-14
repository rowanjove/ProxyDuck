#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod autostart;
mod updater;

use std::{
    env,
    fs::OpenOptions,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use single_instance::SingleInstance;
use tauri::{
    api::dialog::blocking::FileDialogBuilder, AppHandle, CustomMenuItem, Manager, State,
    SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem, WindowEvent,
};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const INSTANCE_ID: &str = "proxyduck-desktop-main-instance";
const TRAY_TOGGLE_ID: &str = "toggle";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreTransport {
    Http,
    NamedPipe,
    Unavailable,
}

impl CoreTransport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::NamedPipe => "named_pipe",
            Self::Unavailable => "unavailable",
        }
    }
}

struct RuntimeState {
    core_url: String,
    token: String,
    transport: Mutex<CoreTransport>,
    enabled: Mutex<bool>,
    owns_core: AtomicBool,
    last_core_spawn: Mutex<Option<std::time::Instant>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreSession {
    core_url: String,
    token: String,
    transport: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemPreflight {
    platform: &'static str,
    desktop_bridge: bool,
    webview_ready: bool,
    elevated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiEnvelope<T> {
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppConfigSnapshot {
    runtime: RuntimeSnapshot,
}

#[derive(Debug, Deserialize)]
struct RuntimeSnapshot {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpcCommandPayload {
    method: String,
    path: String,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    deadline_ms: Option<u32>,
}

#[tauri::command]
fn get_core_session(state: State<'_, RuntimeState>) -> CoreSession {
    CoreSession {
        core_url: state.core_url.clone(),
        token: state.token.clone(),
        transport: current_transport(&state).as_str(),
    }
}

#[tauri::command]
fn refresh_core_session(state: State<'_, RuntimeState>) -> CoreSession {
    let mut transport = resolve_transport_now(&state.core_url);
    if transport == CoreTransport::Http
        && state.core_url == proxyduck_common::DEFAULT_CORE_URL
        && !check_core_health(&state.core_url, &state.token)
    {
        let should_attempt = state
            .last_core_spawn
            .lock()
            .map(|mut last| {
                if last.is_some_and(|instant| instant.elapsed() < Duration::from_secs(5)) {
                    false
                } else {
                    *last = Some(std::time::Instant::now());
                    true
                }
            })
            .unwrap_or(false);
        if should_attempt && spawn_core_if_needed(&state.core_url, &state.token) {
            state.owns_core.store(true, Ordering::Relaxed);
        }
        // The transport remains HTTP for portable mode; connectWithRetry will
        // probe the newly spawned core on its next attempt.
        transport = CoreTransport::Http;
    }
    if let Ok(mut current) = state.transport.lock() {
        *current = transport;
    }
    CoreSession {
        core_url: state.core_url.clone(),
        token: state.token.clone(),
        transport: transport.as_str(),
    }
}

fn current_transport(state: &RuntimeState) -> CoreTransport {
    state
        .transport
        .lock()
        .map(|transport| *transport)
        .unwrap_or(CoreTransport::Unavailable)
}

#[tauri::command]
fn core_ipc_request(
    request: IpcCommandPayload,
) -> Result<proxyduck_common::ipc::IpcResponse, String> {
    core_ipc_request_inner(request).map_err(|error| error.to_string())
}

#[tauri::command]
fn get_system_preflight() -> SystemPreflight {
    SystemPreflight {
        platform: std::env::consts::OS,
        desktop_bridge: true,
        // Reaching this command proves that the WebView and Tauri IPC bridge are ready.
        webview_ready: true,
        elevated: process_is_elevated(),
    }
}

#[cfg(target_os = "windows")]
fn process_is_elevated() -> bool {
    use windows::Win32::UI::Shell::IsUserAnAdmin;

    unsafe { IsUserAnAdmin().as_bool() }
}

#[cfg(not(target_os = "windows"))]
fn process_is_elevated() -> bool {
    false
}

#[tauri::command]
fn sync_runtime_enabled(
    enabled: bool,
    app: AppHandle,
    state: State<'_, RuntimeState>,
) -> Result<(), String> {
    *state.enabled.lock().map_err(|_| "runtime mutex poisoned")? = enabled;
    update_tray_toggle_title(&app, enabled);
    Ok(())
}

#[tauri::command]
fn choose_executable() -> Option<String> {
    FileDialogBuilder::new()
        .add_filter("Windows application", &["exe"])
        .pick_file()
        .map(|path| path.display().to_string())
}

#[tauri::command]
fn launch_desktop_process(
    exe_path: String,
    args: Vec<String>,
    work_dir: Option<String>,
    run_as_admin: bool,
) -> Result<(), String> {
    launch_desktop_process_inner(&exe_path, &args, work_dir.as_deref(), run_as_admin)
        .map_err(|error| error.to_string())
}

fn launch_desktop_process_inner(
    exe_path: &str,
    args: &[String],
    work_dir: Option<&str>,
    run_as_admin: bool,
) -> anyhow::Result<()> {
    if exe_path.trim().is_empty() {
        anyhow::bail!("executable path is empty");
    }

    #[cfg(target_os = "windows")]
    if run_as_admin && !process_is_elevated() {
        use windows::core::PCWSTR;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

        let op: Vec<u16> = "runas\0".encode_utf16().collect();
        let file: Vec<u16> = format!("{exe_path}\0").encode_utf16().collect();
        let params: Option<Vec<u16>> = if args.is_empty() {
            None
        } else {
            let joined = args
                .iter()
                .map(|arg| quote_windows_command_line_arg(arg))
                .collect::<Vec<_>>()
                .join(" ");
            Some(format!("{joined}\0").encode_utf16().collect())
        };
        let dir: Option<Vec<u16>> = work_dir
            .filter(|d| !d.trim().is_empty())
            .map(|d| format!("{d}\0").encode_utf16().collect());

        let instance = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(op.as_ptr()),
                PCWSTR(file.as_ptr()),
                params
                    .as_ref()
                    .map_or(PCWSTR::null(), |p| PCWSTR(p.as_ptr())),
                dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
                SW_SHOW,
            )
        };
        if (instance.0 as usize) <= 32 {
            anyhow::bail!(
                "failed to launch application with administrator elevation (ShellExecute code {})",
                instance.0 as usize
            );
        }
        return Ok(());
    }

    let mut cmd = Command::new(exe_path);
    cmd.args(args);
    if let Some(dir) = work_dir {
        if !dir.trim().is_empty() {
            cmd.current_dir(dir);
        }
    }
    cmd.spawn()
        .map_err(|error| anyhow::anyhow!("failed to launch {exe_path}: {error}"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn quote_windows_command_line_arg(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'"'))
    {
        return value.to_string();
    }

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            quoted.push(character);
        }
        backslashes = 0;
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[tauri::command]
fn get_autostart_status() -> autostart::AutostartStatus {
    autostart::check_autostart()
}

#[tauri::command]
fn set_autostart_config(enabled: bool, silent: bool) -> Result<(), String> {
    autostart::set_autostart(enabled, silent).map_err(|e| e.to_string())
}

#[tauri::command]
fn check_update(custom_url: Option<String>) -> Result<updater::UpdateCheckResult, String> {
    updater::check_for_updates(custom_url).map_err(|e| e.to_string())
}

#[tauri::command]
fn install_update(download_url: String, app: AppHandle) -> Result<(), String> {
    updater::download_and_install_update(&download_url, &app).map_err(|e| e.to_string())
}

fn core_ipc_request_inner(
    request: IpcCommandPayload,
) -> anyhow::Result<proxyduck_common::ipc::IpcResponse> {
    use proxyduck_common::ipc::{IpcRequest, IPC_DEFAULT_DEADLINE_MS};

    let deadline_ms = request
        .deadline_ms
        .unwrap_or(IPC_DEFAULT_DEADLINE_MS)
        .clamp(1, proxyduck_common::ipc::IPC_MAX_DEADLINE_MS);
    let mut ipc_request =
        IpcRequest::new(request.method, request.path).with_deadline_ms(deadline_ms);
    if let Some(body) = request.body {
        ipc_request = ipc_request.with_body(body);
    }
    ipc_request.validate()?;

    #[cfg(target_os = "windows")]
    {
        named_pipe_request(ipc_request)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = ipc_request;
        anyhow::bail!("Named Pipe IPC is only supported on Windows")
    }
}

#[cfg(target_os = "windows")]
fn named_pipe_request(
    request: proxyduck_common::ipc::IpcRequest,
) -> anyhow::Result<proxyduck_common::ipc::IpcResponse> {
    proxyduck_common::ipc::request_named_pipe(request)
}

fn service_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        let sc_path = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join("sc.exe");
        Command::new(sc_path)
            .args(["query", "ProxyDuckCore"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

fn named_pipe_available() -> bool {
    #[cfg(target_os = "windows")]
    {
        core_ipc_request_inner(IpcCommandPayload {
            method: "GET".to_string(),
            path: "/health".to_string(),
            body: None,
            deadline_ms: Some(800),
        })
        .map(|response| (200..500).contains(&response.status))
        .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

fn resolve_transport(core_url: &str) -> CoreTransport {
    resolve_transport_with_wait(core_url, true)
}

fn resolve_transport_now(core_url: &str) -> CoreTransport {
    resolve_transport_with_wait(core_url, false)
}

fn resolve_transport_with_wait(core_url: &str, wait_for_service: bool) -> CoreTransport {
    if core_url != proxyduck_common::DEFAULT_CORE_URL {
        return CoreTransport::Http;
    }
    #[cfg(target_os = "windows")]
    {
        // An installed service is authoritative: do not silently start a
        // second unelevated core if the service is still starting or failed.
        if service_installed() {
            let attempts = if wait_for_service { 20 } else { 1 };
            for _ in 0..attempts {
                if named_pipe_available() {
                    return CoreTransport::NamedPipe;
                }
                if wait_for_service {
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
            return CoreTransport::Unavailable;
        }
        if named_pipe_available() {
            return CoreTransport::NamedPipe;
        }
    }
    CoreTransport::Http
}

fn http_client(timeout: Duration) -> anyhow::Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()?)
}

fn ipc_json_request(method: &str, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
    let response = core_ipc_request_inner(IpcCommandPayload {
        method: method.to_string(),
        path: path.to_string(),
        body,
        deadline_ms: None,
    })?;
    if !(200..300).contains(&response.status) {
        let message = response
            .error
            .map(|error| error.message)
            .unwrap_or_else(|| format!("core IPC request failed: {}", response.status));
        anyhow::bail!(message);
    }
    response
        .body
        .ok_or_else(|| anyhow::anyhow!("core IPC response did not contain JSON"))
}

fn post_runtime_toggle_for_state(state: &RuntimeState, enabled: bool) -> anyhow::Result<()> {
    match current_transport(state) {
        CoreTransport::NamedPipe => {
            let _ = ipc_json_request("POST", "/runtime", Some(json!({ "enabled": enabled })))?;
            Ok(())
        }
        CoreTransport::Http => post_runtime_toggle(&state.core_url, &state.token, enabled),
        CoreTransport::Unavailable => {
            anyhow::bail!("ProxyDuck Core service is unavailable")
        }
    }
}

fn post_runtime_toggle(core_url: &str, token: &str, enabled: bool) -> anyhow::Result<()> {
    let response = http_client(Duration::from_secs(3))?
        .post(format!("{core_url}/runtime"))
        .header(proxyduck_common::AUTH_HEADER, token)
        .json(&json!({ "enabled": enabled }))
        .send()?;

    if response.status() != StatusCode::OK {
        anyhow::bail!("core runtime API failed: {}", response.status());
    }
    Ok(())
}

fn fetch_runtime_enabled(core_url: &str, token: &str) -> anyhow::Result<bool> {
    let response = http_client(Duration::from_secs(2))?
        .get(format!("{core_url}/config"))
        .header(proxyduck_common::AUTH_HEADER, token)
        .send()?
        .error_for_status()?;
    let payload: ApiEnvelope<AppConfigSnapshot> = response.json()?;
    payload
        .data
        .map(|config| config.runtime.enabled)
        .ok_or_else(|| anyhow::anyhow!("missing config payload"))
}

fn fetch_runtime_enabled_for_state(state: &RuntimeState) -> anyhow::Result<bool> {
    match current_transport(state) {
        CoreTransport::NamedPipe => {
            let payload = ipc_json_request("GET", "/config", None)?;
            let config: AppConfigSnapshot = serde_json::from_value(
                payload
                    .get("data")
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing config payload"))?,
            )?;
            Ok(config.runtime.enabled)
        }
        CoreTransport::Http => fetch_runtime_enabled(&state.core_url, &state.token),
        CoreTransport::Unavailable => anyhow::bail!("ProxyDuck Core service is unavailable"),
    }
}

fn check_core_health(core_url: &str, token: &str) -> bool {
    http_client(Duration::from_millis(800))
        .and_then(|client| {
            Ok(client
                .get(format!("{core_url}/health"))
                .header(proxyduck_common::AUTH_HEADER, token)
                .send()?
                .status()
                .is_success())
        })
        .unwrap_or(false)
}

fn spawn_core_if_needed(core_url: &str, token: &str) -> bool {
    if check_core_health(core_url, token) {
        return false;
    }

    let Ok(exe) = env::current_exe() else {
        return false;
    };
    let Some(base_dir) = exe.parent() else {
        return false;
    };

    let core_candidates = [
        base_dir.join("proxyduck-core.exe"),
        base_dir.join("proxyduck-core"),
        base_dir.join("proxydock-core.exe"),
        base_dir.join("smartflow-core.exe"),
    ];
    let Some(core_path) = core_candidates.iter().find(|path| path.exists()) else {
        return false;
    };

    let bind = core_url
        .strip_prefix("http://")
        .or_else(|| core_url.strip_prefix("https://"))
        .unwrap_or("127.0.0.1:46666");

    let mut command = Command::new(core_path);
    command
        .arg("--bind")
        .arg(bind)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    if let Ok(directory) = proxyduck_common::resolve_app_dir() {
        if let Ok(stdout) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(directory.join("core.log"))
        {
            if let Ok(stderr) = stdout.try_clone() {
                command
                    .stdout(Stdio::from(stdout))
                    .stderr(Stdio::from(stderr));
            }
        }
    }

    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);

    command.spawn().is_ok()
}

fn stop_owned_core(state: &RuntimeState) {
    if !state.owns_core.load(Ordering::Relaxed) {
        return;
    }
    if let Ok(client) = http_client(Duration::from_secs(2)) {
        let _ = client
            .post(format!("{}/lifecycle/shutdown", state.core_url))
            .header(proxyduck_common::AUTH_HEADER, &state.token)
            .send();
    }
}

fn update_tray_toggle_title(app: &AppHandle, enabled: bool) {
    let title = if enabled {
        "暂停 ProxyDuck"
    } else {
        "恢复 ProxyDuck"
    };
    let _ = app.tray_handle().get_item(TRAY_TOGGLE_ID).set_title(title);
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(target_os = "windows")]
fn focus_existing_instance() {
    use windows::{
        core::w,
        Win32::UI::WindowsAndMessaging::{
            FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE,
        },
    };

    if let Ok(window) = unsafe { FindWindowW(None, w!("ProxyDuck")) } {
        unsafe {
            let _ = ShowWindow(window, SW_RESTORE);
            let _ = SetForegroundWindow(window);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn focus_existing_instance() {}

fn main() {
    if let Err(error) = proxyduck_common::install_panic_hook("desktop") {
        eprintln!("failed to initialize crash logging: {error}");
    }
    let single_instance = match SingleInstance::new(INSTANCE_ID) {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("failed to initialize single-instance guard: {error}");
            return;
        }
    };

    if !single_instance.is_single() {
        focus_existing_instance();
        return;
    }

    let core_url = proxyduck_common::core_url_from_env();
    let transport = resolve_transport(&core_url);
    let token = match proxyduck_common::load_or_create_token() {
        Ok(token) => token,
        Err(error) => {
            eprintln!("failed to initialize ProxyDuck auth token: {error}");
            return;
        }
    };

    let tray_menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("open", "打开控制台"))
        .add_item(CustomMenuItem::new(TRAY_TOGGLE_ID, "暂停 ProxyDuck"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("quit", "退出 ProxyDuck"));

    let runtime_state = RuntimeState {
        core_url: core_url.clone(),
        token,
        transport: Mutex::new(transport),
        enabled: Mutex::new(false),
        owns_core: AtomicBool::new(false),
        last_core_spawn: Mutex::new(None),
    };

    tauri::Builder::default()
        .manage(runtime_state)
        .invoke_handler(tauri::generate_handler![
            get_core_session,
            refresh_core_session,
            core_ipc_request,
            get_system_preflight,
            sync_runtime_enabled,
            choose_executable,
            launch_desktop_process,
            get_autostart_status,
            set_autostart_config,
            check_update,
            install_update
        ])
        .setup(move |app| {
            let is_silent = env::args()
                .any(|arg| arg == "--silent" || arg == "--minimized" || arg == "--autostart");
            if is_silent {
                if let Some(window) = app.get_window("main") {
                    let _ = window.hide();
                }
            }

            let state = app.state::<RuntimeState>();
            let spawned = if current_transport(&state) != CoreTransport::Http {
                false
            } else {
                spawn_core_if_needed(&core_url, &state.token)
            };
            state.owns_core.store(spawned, Ordering::Relaxed);

            let handle = app.handle();
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let state = handle.state::<RuntimeState>();
                    if let Ok(enabled) = fetch_runtime_enabled_for_state(&state) {
                        if let Ok(mut current) = state.enabled.lock() {
                            *current = enabled;
                        }
                        update_tray_toggle_title(&handle, enabled);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            });
            Ok(())
        })
        .system_tray(SystemTray::new().with_menu(tray_menu))
        .on_window_event(|event| {
            if let WindowEvent::CloseRequested { api, .. } = event.event() {
                api.prevent_close();
                let _ = event.window().hide();
            }
        })
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { .. } => show_main_window(app),
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "open" => show_main_window(app),
                TRAY_TOGGLE_ID => {
                    let state = app.state::<RuntimeState>();
                    let Ok(mut enabled) = state.enabled.lock() else {
                        return;
                    };
                    let next = !*enabled;
                    if post_runtime_toggle_for_state(&state, next).is_ok() {
                        *enabled = next;
                        update_tray_toggle_title(app, next);
                    }
                }
                "quit" => {
                    let state = app.state::<RuntimeState>();
                    stop_owned_core(&state);
                    app.exit(0);
                }
                _ => {}
            },
            _ => {}
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| eprintln!("failed to run ProxyDuck UI: {error}"));

    drop(single_instance);
}
