use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const TASK_NAME: &str = "ProxyDuck-AutoStart";
const REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const REG_VALUE: &str = "ProxyDuck";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutostartStatus {
    pub enabled: bool,
    pub silent: bool,
    pub method: String, // "task_scheduler" | "registry" | "none"
    pub is_elevated: bool,
}

pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::UI::Shell::IsUserAnAdmin;
        unsafe { IsUserAnAdmin().as_bool() }
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub fn get_current_exe() -> anyhow::Result<PathBuf> {
    let exe = env::current_exe()?;
    Ok(exe)
}

pub fn check_autostart() -> AutostartStatus {
    let elevated = is_elevated();

    #[cfg(target_os = "windows")]
    {
        // 1. Check Task Scheduler
        let mut cmd = Command::new("schtasks.exe");
        cmd.args(["/query", "/tn", TASK_NAME]);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        if let Ok(output) = cmd.output() {
            if output.status.success() {
                let out_str = String::from_utf8_lossy(&output.stdout);
                let silent = out_str.contains("--silent") || out_str.contains("--autostart");
                return AutostartStatus {
                    enabled: true,
                    silent,
                    method: "task_scheduler".to_string(),
                    is_elevated: elevated,
                };
            }
        }

        // 2. Check Registry Run key
        let mut reg_cmd = Command::new("reg.exe");
        reg_cmd.args(["query", REG_KEY, "/v", REG_VALUE]);
        reg_cmd.creation_flags(CREATE_NO_WINDOW);
        reg_cmd.stdout(Stdio::piped());
        reg_cmd.stderr(Stdio::null());

        if let Ok(output) = reg_cmd.output() {
            if output.status.success() {
                let out_str = String::from_utf8_lossy(&output.stdout);
                let silent = out_str.contains("--silent") || out_str.contains("--autostart");
                return AutostartStatus {
                    enabled: true,
                    silent,
                    method: "registry".to_string(),
                    is_elevated: elevated,
                };
            }
        }
    }

    AutostartStatus {
        enabled: false,
        silent: true,
        method: "none".to_string(),
        is_elevated: elevated,
    }
}

pub fn set_autostart(enabled: bool, silent: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        let exe = get_current_exe()?;
        let exe_str = exe.to_string_lossy();
        let arg = if silent { " --silent" } else { "" };
        let run_cmd = format!("\"{exe_str}\"{arg}");

        if is_elevated() {
            if enabled {
                // Remove existing registry entry to prevent duplicate launches
                let mut clean_reg = Command::new("reg.exe");
                clean_reg.args(["delete", REG_KEY, "/v", REG_VALUE, "/f"]);
                clean_reg.creation_flags(CREATE_NO_WINDOW);
                clean_reg.stdout(Stdio::null());
                clean_reg.stderr(Stdio::null());
                let _ = clean_reg.status();

                // Create Task Scheduler with HighestAvailable (No UAC prompt at boot)
                let mut cmd = Command::new("schtasks.exe");
                cmd.args([
                    "/create", "/f", "/tn", TASK_NAME, "/tr", &run_cmd, "/sc", "onlogon", "/rl",
                    "highest",
                ]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                let status = cmd.status()?;
                if !status.success() {
                    anyhow::bail!("schtasks failed with exit code {:?}", status.code());
                }
            } else {
                let mut cmd = Command::new("schtasks.exe");
                cmd.args(["/delete", "/f", "/tn", TASK_NAME]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());
                let _ = cmd.status();

                let mut clean_reg = Command::new("reg.exe");
                clean_reg.args(["delete", REG_KEY, "/v", REG_VALUE, "/f"]);
                clean_reg.creation_flags(CREATE_NO_WINDOW);
                clean_reg.stdout(Stdio::null());
                clean_reg.stderr(Stdio::null());
                let _ = clean_reg.status();
            }
        } else {
            // Standard user mode: use Registry Run key
            if enabled {
                let mut cmd = Command::new("reg.exe");
                cmd.args([
                    "add", REG_KEY, "/v", REG_VALUE, "/t", "REG_SZ", "/d", &run_cmd, "/f",
                ]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                let status = cmd.status()?;
                if !status.success() {
                    anyhow::bail!("reg add failed with exit code {:?}", status.code());
                }
            } else {
                let mut cmd = Command::new("reg.exe");
                cmd.args(["delete", REG_KEY, "/v", REG_VALUE, "/f"]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());
                let _ = cmd.status();
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (enabled, silent);
        anyhow::bail!("Auto-start is only supported on Windows")
    }
}
