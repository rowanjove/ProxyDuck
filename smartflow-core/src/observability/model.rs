use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{Protocol, RouteAction};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Established,
    Listening,
    TimeWait,
    CloseWait,
    SynSent,
    FinWait,
    Closed,
    Other,
}

impl ConnectionStatus {
    pub fn from_netstat_str(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "ESTABLISHED" => Self::Established,
            "LISTENING" => Self::Listening,
            "TIME_WAIT" => Self::TimeWait,
            "CLOSE_WAIT" => Self::CloseWait,
            "SYN_SENT" => Self::SynSent,
            "FIN_WAIT_1" | "FIN_WAIT_2" => Self::FinWait,
            "CLOSED" => Self::Closed,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRecord {
    pub id: String,
    pub pid: u32,
    pub process_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub status: ConnectionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    pub route_action: RouteAction,
    pub action_target: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionFilter {
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub status: Option<String>,
    pub search: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTrafficSummary {
    pub process_name: String,
    pub active_connections: usize,
    pub total_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSummary {
    pub total_connections: usize,
    pub established_connections: usize,
    pub listening_ports: usize,
    pub top_processes: Vec<ProcessTrafficSummary>,
    pub route_distribution: HashMap<String, usize>,
}
