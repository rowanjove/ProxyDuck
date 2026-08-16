#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::{
    env,
    fs::OpenOptions,
    path::PathBuf,
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
use serde_json::json;
use single_instance::SingleInstance;
use tauri::{
    api::dialog::blocking::FileDialogBuilder, AppHandle, CustomMenuItem, Manager, State,
    SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem, WindowEvent,
};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const INSTANCE_ID: &str = "proxyduck-desktop-main-instance";
const TRAY_TOGGLE_ID: &str = "toggle";

struct RuntimeState {
    core_url: String,
    token: String,
    enabled: Mutex<bool>,
    owns_core: AtomicBool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreSession {
    core_url: String,
    token: String,
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

#[tauri::command]
fn get_core_session(state: State<'_, RuntimeState>) -> CoreSession {
    CoreSession {
        core_url: state.core_url.clone(),
        token: state.token.clone(),
    }
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

fn http_client(timeout: Duration) -> anyhow::Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()?)
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
        PathBuf::from("proxyduck-core.exe"),
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
        enabled: Mutex::new(false),
        owns_core: AtomicBool::new(false),
    };

    tauri::Builder::default()
        .manage(runtime_state)
        .invoke_handler(tauri::generate_handler![
            get_core_session,
            get_system_preflight,
            sync_runtime_enabled,
            choose_executable
        ])
        .setup(move |app| {
            let state = app.state::<RuntimeState>();
            let spawned = spawn_core_if_needed(&core_url, &state.token);
            state.owns_core.store(spawned, Ordering::Relaxed);

            let handle = app.handle();
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let state = handle.state::<RuntimeState>();
                    if let Ok(enabled) = fetch_runtime_enabled(&state.core_url, &state.token) {
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
                    if post_runtime_toggle(&state.core_url, &state.token, next).is_ok() {
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
