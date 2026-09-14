use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    process::Command,
    sync::Mutex,
};
use tracing::info;
use uuid::Uuid;

use super::{model::NetworkDiagnosis, snapshot::SnapshotManager};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairLevel {
    Level1Safe,
    Level2Privileged,
    Level3Advanced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairAction {
    pub id: String,
    pub title: String,
    pub description: String,
    pub level: RepairLevel,
    pub requires_admin: bool,
    pub reversible: bool,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairPlan {
    pub plan_id: String,
    pub created_at: String,
    pub target_issues_count: usize,
    pub target_issues: Vec<String>,
    pub recommended_actions: Vec<RepairAction>,
    pub snapshot_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairActionResult {
    pub action_id: String,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairExecutionReport {
    pub plan_id: String,
    pub snapshot_id: Option<String>,
    pub executed_actions: Vec<RepairActionResult>,
    pub all_succeeded: bool,
}

pub struct RepairPlanner;

const MAX_REGISTERED_REPAIR_PLANS: usize = 64;
static REGISTERED_REPAIR_PLANS: Lazy<Mutex<HashMap<String, RepairPlan>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

impl RepairPlanner {
    pub fn build_plan(diagnosis: &NetworkDiagnosis) -> RepairPlan {
        let mut actions = Vec::new();
        let mut target_issues = Vec::new();

        for issue in &diagnosis.issues {
            target_issues.push(issue.title.clone());

            match issue.id.as_str() {
                "dhcp_apipa_failure" => {
                    Self::add_action_if_missing(&mut actions, Self::action_renew_dhcp());
                    Self::add_action_if_missing(&mut actions, Self::action_restart_adapter());
                }
                "proxy_dead_port" | "proxy_blocking_traffic" => {
                    Self::add_action_if_missing(&mut actions, Self::action_reset_system_proxy());
                    Self::add_action_if_missing(&mut actions, Self::action_reset_winhttp());
                }
                "dns_resolution_failed" | "dns_resolution_partial_failure" => {
                    Self::add_action_if_missing(&mut actions, Self::action_flush_dns());
                }
                "gateway_unreachable" => {
                    Self::add_action_if_missing(&mut actions, Self::action_flush_arp());
                    Self::add_action_if_missing(&mut actions, Self::action_restart_adapter());
                }
                "winsock_catalog_anomalous" => {
                    Self::add_action_if_missing(&mut actions, Self::action_reset_winsock());
                }
                _ => {}
            }
        }

        // Always suggest safe DNS flush if there are any DNS/Internet issues
        if diagnosis.status != super::model::OverallStatus::Normal && actions.is_empty() {
            actions.push(Self::action_flush_dns());
        }

        let plan = RepairPlan {
            plan_id: format!("plan_{}", Uuid::new_v4().simple()),
            created_at: Utc::now().to_rfc3339(),
            target_issues_count: target_issues.len(),
            target_issues,
            recommended_actions: actions,
            snapshot_required: true,
        };
        let mut plans = REGISTERED_REPAIR_PLANS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if plans.len() >= MAX_REGISTERED_REPAIR_PLANS {
            plans.clear();
        }
        plans.insert(plan.plan_id.clone(), plan.clone());
        plan
    }

    fn add_action_if_missing(actions: &mut Vec<RepairAction>, action: RepairAction) {
        if !actions.iter().any(|a| a.id == action.id) {
            actions.push(action);
        }
    }

    pub fn action_flush_dns() -> RepairAction {
        RepairAction {
            id: "flush_dns".to_string(),
            title: "刷新 DNS 缓存 (Flush DNS)".to_string(),
            description:
                "清空 Windows 本地 DNS 客户端解析缓存，重新向 DNS 服务器发起最新地址解析。"
                    .to_string(),
            level: RepairLevel::Level1Safe,
            requires_admin: false,
            reversible: true,
            impact: "无负面影响，不影响已建立的网络连接。".to_string(),
        }
    }

    pub fn action_renew_dhcp() -> RepairAction {
        RepairAction {
            id: "renew_dhcp".to_string(),
            title: "重新获取 DHCP 租约 (Renew DHCP)".to_string(),
            description: "向本地路由器释放并重新请求 IPv4 地址租约，解决 169.254.x.x 等地址冲突。"
                .to_string(),
            level: RepairLevel::Level1Safe,
            requires_admin: false,
            reversible: true,
            impact: "重新协商 IP 时网络可能会短暂闪断 1-3 秒。".to_string(),
        }
    }

    pub fn action_reset_system_proxy() -> RepairAction {
        RepairAction {
            id: "reset_system_proxy".to_string(),
            title: "重置系统代理至直连模式 (Reset System Proxy)".to_string(),
            description: "关闭 WinINET 系统代理开关并清除残留的本地代理端口，恢复浏览器直连上网。"
                .to_string(),
            level: RepairLevel::Level1Safe,
            requires_admin: false,
            reversible: true,
            impact: "原本需要通过代理访问的内网或特殊站点在重新配置代理前将无法连接。".to_string(),
        }
    }

    pub fn action_flush_arp() -> RepairAction {
        RepairAction {
            id: "flush_arp".to_string(),
            title: "刷新 ARP 缓存表 (Flush ARP)".to_string(),
            description: "清空局域网 MAC 地址映射缓存，促使系统重新向网关广播探测正确硬件地址。"
                .to_string(),
            level: RepairLevel::Level1Safe,
            requires_admin: false,
            reversible: true,
            impact: "无负面影响，系统会自动广播重建网关 ARP。".to_string(),
        }
    }

    pub fn action_reset_winhttp() -> RepairAction {
        RepairAction {
            id: "reset_winhttp".to_string(),
            title: "重置 WinHTTP 代理设置 (Reset WinHTTP)".to_string(),
            description: "清除 Windows 后台服务及命令行工具使用的全局 WinHTTP 代理残留配置。"
                .to_string(),
            level: RepairLevel::Level2Privileged,
            requires_admin: true,
            reversible: true,
            impact: "清除系统后台组件代理，恢复直接访问。".to_string(),
        }
    }

    pub fn action_restart_adapter() -> RepairAction {
        RepairAction {
            id: "restart_adapter".to_string(),
            title: "软重启网络适配器 (Restart Adapter)".to_string(),
            description: "禁用并重新启用主活动网卡，重新初始化硬件驱动状态与网络配置。".to_string(),
            level: RepairLevel::Level2Privileged,
            requires_admin: true,
            reversible: true,
            impact: "网卡会短暂断开 3-5 秒后重新连通。".to_string(),
        }
    }

    pub fn action_reset_winsock() -> RepairAction {
        RepairAction {
            id: "reset_winsock".to_string(),
            title: "重置 Winsock 目录 (Reset Winsock)".to_string(),
            description: "重置 Windows 套接字目录至系统默认干净状态，清除第三方 LSP 注入冲突。"
                .to_string(),
            level: RepairLevel::Level2Privileged,
            requires_admin: true,
            reversible: false,
            impact: "可能需要重启计算机才能完全生效；部分网络加速器驱动可能需要重新安装。"
                .to_string(),
        }
    }

    pub fn action_reset_tcpip() -> RepairAction {
        RepairAction {
            id: "reset_tcpip".to_string(),
            title: "重置 TCP/IP 网络协议栈 (Reset TCP/IP)".to_string(),
            description: "重置 TCP/IP 注册表堆栈至初始默认状态，彻底消除网络协议损坏。".to_string(),
            level: RepairLevel::Level2Privileged,
            requires_admin: true,
            reversible: false,
            impact: "可能清除自定义静态 IP 与高级路由配置，需要重启计算机。".to_string(),
        }
    }
}

pub struct RepairExecutor;

impl RepairExecutor {
    pub async fn execute_actions(
        plan_id: &str,
        action_ids: &[String],
    ) -> anyhow::Result<RepairExecutionReport> {
        info!(plan_id = %plan_id, actions = ?action_ids, "starting repair execution");

        let plan = REGISTERED_REPAIR_PLANS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(plan_id)
            .ok_or_else(|| anyhow::anyhow!("repair plan is unknown, expired, or already used"))?;
        if action_ids.is_empty() {
            anyhow::bail!("repair plan execution requires at least one action");
        }
        let allowed = plan
            .recommended_actions
            .iter()
            .map(|action| action.id.as_str())
            .collect::<HashSet<_>>();
        let mut requested = HashSet::new();
        for action_id in action_ids {
            if !requested.insert(action_id.as_str()) {
                anyhow::bail!("repair action is duplicated: {action_id}");
            }
            if !allowed.contains(action_id.as_str()) {
                anyhow::bail!("repair action was not recommended by plan {plan_id}: {action_id}");
            }
        }

        // Fail closed: no repair may run unless its recovery point exists.
        let snapshot = SnapshotManager::create_snapshot(&format!(
            "Auto-snapshot before executing plan {plan_id}"
        ))
        .await?;
        let snapshot_id = Some(snapshot.id);

        let mut results = Vec::new();
        let mut all_succeeded = true;

        for id in action_ids {
            let res = tokio::task::spawn_blocking({
                let action_id = id.clone();
                move || Self::run_single_action(&action_id)
            })
            .await
            .unwrap_or_else(|e| RepairActionResult {
                action_id: id.clone(),
                success: false,
                output: String::new(),
                error: Some(format!("Task execution panicked: {e}")),
            });

            if !res.success {
                all_succeeded = false;
            }
            results.push(res);
        }

        Ok(RepairExecutionReport {
            plan_id: plan_id.to_string(),
            snapshot_id,
            executed_actions: results,
            all_succeeded,
        })
    }

    fn run_single_action(action_id: &str) -> RepairActionResult {
        match action_id {
            "flush_dns" => Self::exec_cmd("ipconfig", &["/flushdns"], action_id),
            "renew_dhcp" => Self::exec_cmd("ipconfig", &["/renew"], action_id),
            "reset_system_proxy" => {
                let wininet_res = Self::disable_wininet_proxy();
                RepairActionResult {
                    action_id: action_id.to_string(),
                    success: wininet_res.is_ok(),
                    output: "系统代理开关已关闭并恢复直连模式".to_string(),
                    error: wininet_res.err().map(|e| e.to_string()),
                }
            }
            "flush_arp" => Self::exec_cmd("netsh", &["interface", "ip", "delete", "arpcache"], action_id),
            "reset_winhttp" => Self::exec_cmd("netsh", &["winhttp", "reset", "proxy"], action_id),
            "restart_adapter" => Self::exec_powershell(
                "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Restart-NetAdapter -Confirm:$false",
                action_id,
            ),
            "reset_winsock" => Self::exec_cmd("netsh", &["winsock", "reset"], action_id),
            "reset_tcpip" => Self::exec_cmd("netsh", &["int", "ip", "reset"], action_id),
            other => RepairActionResult {
                action_id: other.to_string(),
                success: false,
                output: String::new(),
                error: Some(format!("Unknown repair action: {other}")),
            },
        }
    }

    fn exec_cmd(program: &str, args: &[&str], action_id: &str) -> RepairActionResult {
        let program_path = system_command(program);
        match Command::new(program_path).args(args).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let success = output.status.success();
                RepairActionResult {
                    action_id: action_id.to_string(),
                    success,
                    output: stdout,
                    error: if success { None } else { Some(stderr) },
                }
            }
            Err(e) => RepairActionResult {
                action_id: action_id.to_string(),
                success: false,
                output: String::new(),
                error: Some(format!("Failed to execute command '{program}': {e}")),
            },
        }
    }

    fn exec_powershell(script: &str, action_id: &str) -> RepairActionResult {
        match Command::new(system_command(r"WindowsPowerShell\v1.0\powershell.exe"))
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let success = output.status.success();
                RepairActionResult {
                    action_id: action_id.to_string(),
                    success,
                    output: stdout,
                    error: if success { None } else { Some(stderr) },
                }
            }
            Err(e) => RepairActionResult {
                action_id: action_id.to_string(),
                success: false,
                output: String::new(),
                error: Some(format!("Failed to execute powershell: {e}")),
            },
        }
    }

    fn disable_wininet_proxy() -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::Registry::{
                RegCloseKey, RegSetValueExW, KEY_SET_VALUE, REG_DWORD,
            };

            unsafe {
                let hkey = super::proxy::open_target_internet_settings(KEY_SET_VALUE)?;

                let dword_val = 0u32;
                let enable_name: Vec<u16> = "ProxyEnable\0".encode_utf16().collect();
                let dword_bytes = dword_val.to_ne_bytes();
                RegSetValueExW(
                    hkey,
                    PCWSTR::from_raw(enable_name.as_ptr()),
                    None,
                    REG_DWORD,
                    Some(&dword_bytes),
                )
                .ok()?;

                RegCloseKey(hkey).ok()?;
            }
        }
        Ok(())
    }
}

fn system_command(name: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join(name)
    }
    #[cfg(not(windows))]
    std::path::PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{NetworkDiagnosis, OverallStatus};

    #[tokio::test]
    async fn execution_rejects_unknown_or_unrecommended_actions_before_snapshot() {
        let unknown = RepairExecutor::execute_actions(
            "plan_that_was_never_registered",
            &["flush_dns".to_string()],
        )
        .await;
        assert!(unknown.is_err());

        let diagnosis = NetworkDiagnosis {
            status: OverallStatus::Warning,
            ..NetworkDiagnosis::default()
        };
        let plan = RepairPlanner::build_plan(&diagnosis);
        let result =
            RepairExecutor::execute_actions(&plan.plan_id, &["reset_tcpip".to_string()]).await;
        assert!(result.is_err());
    }

    #[test]
    fn repair_plan_uses_the_public_camel_case_contract() {
        let plan = RepairPlanner::build_plan(&NetworkDiagnosis::default());
        let value = serde_json::to_value(plan).unwrap();
        assert!(value.get("planId").is_some());
        assert!(value.get("recommendedActions").is_some());
        assert!(value.get("plan_id").is_none());
    }
}
