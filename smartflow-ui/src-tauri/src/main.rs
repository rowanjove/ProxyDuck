#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod auth;

use std::{
    env,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Mutex,
    time::Duration,
};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use reqwest::StatusCode;
use serde::Serialize;
use serde_json::json;
use single_instance::SingleInstance;
use tauri::{
    CustomMenuItem, Manager, State, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem, WindowEvent,
};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

struct RuntimeState {
    core_url: String,
    token: String,
    enabled: Mutex<bool>,
}

#[tauri::command]
fn get_core_url(state: State<'_, RuntimeState>) -> String {
    state.core_url.clone()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreSession {
    core_url: String,
    token: String,
}

#[tauri::command]
fn get_core_session(state: State<'_, RuntimeState>) -> CoreSession {
    CoreSession {
        core_url: state.core_url.clone(),
        token: state.token.clone(),
    }
}

#[tauri::command]
fn get_runtime_enabled(state: State<'_, RuntimeState>) -> Result<bool, String> {
    match state.enabled.lock() {
        Ok(guard) => Ok(*guard),
        Err(_) => Err("runtime mutex poisoned".to_string()),
    }
}

#[tauri::command]
fn set_runtime_enabled(enabled: bool, state: State<'_, RuntimeState>) -> Result<(), String> {
    post_runtime_toggle(&state.core_url, &state.token, enabled)
        .map_err(|error| error.to_string())?;
    *state.enabled.lock().map_err(|_| "runtime mutex poisoned")? = enabled;
    Ok(())
}

fn post_runtime_toggle(core_url: &str, token: &str, enabled: bool) -> anyhow::Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;

    let response = client
        .post(format!("{core_url}/runtime"))
        .header("X-SmartFlow-Token", token)
        .json(&json!({ "enabled": enabled }))
        .send()?;

    if response.status() != StatusCode::OK {
        anyhow::bail!("core runtime API failed: {}", response.status());
    }

    Ok(())
}

fn check_core_health(core_url: &str, token: &str) -> bool {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };

    match client
        .get(format!("{core_url}/health"))
        .header("X-SmartFlow-Token", token)
        .send()
    {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

fn spawn_core_if_needed(core_url: &str, token: &str) {
    if check_core_health(core_url, token) {
        return;
    }

    let exe = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("failed to resolve current exe: {error}");
            return;
        }
    };

    let base_dir = match exe.parent() {
        Some(path) => path.to_path_buf(),
        None => {
            eprintln!("failed to resolve exe directory");
            return;
        }
    };

    let core_candidates = [
        base_dir.join("smartflow-core.exe"),
        base_dir.join("smartflow-core"),
        PathBuf::from("smartflow-core.exe"),
    ];

    let Some(core_path) = core_candidates.iter().find(|path| path.exists()) else {
        eprintln!("smartflow-core executable not found near ui binary");
        return;
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

    #[cfg(target_os = "windows")]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }

    if let Err(error) = command.spawn() {
        eprintln!("failed to spawn smartflow-core: {error}");
    }
}

fn main() {
    let single_instance = match SingleInstance::new("smartflow-ui-main-instance") {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("failed to initialize single-instance guard: {error}");
            return;
        }
    };

    if !single_instance.is_single() {
        return;
    }

    let core_url =
        env::var("SMARTFLOW_CORE_URL").unwrap_or_else(|_| "http://127.0.0.1:46666".to_string());

    let open_item = CustomMenuItem::new("open", "打开面板");
    let toggle_item = CustomMenuItem::new("toggle", "暂停 SmartFlow");
    let quit_item = CustomMenuItem::new("quit", "退出");

    let tray_menu = SystemTrayMenu::new()
        .add_item(open_item)
        .add_item(toggle_item)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit_item);

    let token = match auth::load_or_create_token() {
        Ok(token) => token,
        Err(error) => {
            eprintln!("failed to initialize SmartFlow auth token: {error}");
            return;
        }
    };

    let runtime_state = RuntimeState {
        core_url: core_url.clone(),
        token,
        enabled: Mutex::new(true),
    };

    tauri::Builder::default()
        .manage(runtime_state)
        .invoke_handler(tauri::generate_handler![
            get_core_url,
            get_core_session,
            get_runtime_enabled,
            set_runtime_enabled
        ])
        .setup(move |app| {
            let state = app.state::<RuntimeState>();
            spawn_core_if_needed(&core_url, &state.token);
            Ok(())
        })
        .system_tray(SystemTray::new().with_menu(tray_menu))
        .on_window_event(|event| {
            if let WindowEvent::CloseRequested { api, .. } = event.event() {
                api.prevent_close();
                if let Err(error) = event.window().hide() {
                    eprintln!("failed to hide window: {error}");
                }
            }
        })
        .on_system_tray_event(|app, event| {
            if let SystemTrayEvent::MenuItemClick { id, .. } = event {
                match id.as_str() {
                    "open" => {
                        if let Some(window) = app.get_window("main") {
                            if let Err(error) = window.show() {
                                eprintln!("failed to show window: {error}");
                            }
                            if let Err(error) = window.set_focus() {
                                eprintln!("failed to focus window: {error}");
                            }
                        }
                    }
                    "toggle" => {
                        let state = app.state::<RuntimeState>();
                        let mut lock = match state.enabled.lock() {
                            Ok(lock) => lock,
                            Err(_) => return,
                        };

                        let next = !*lock;
                        if post_runtime_toggle(&state.core_url, &state.token, next).is_ok() {
                            *lock = next;
                            let title = if next {
                                "暂停 SmartFlow"
                            } else {
                                "恢复 SmartFlow"
                            };
                            let _ = app.tray_handle().get_item("toggle").set_title(title);
                        }
                    }
                    "quit" => {
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| eprintln!("failed to run SmartFlow UI: {error}"));
}
