use std::collections::HashMap;
#[cfg(windows)]
use std::process::Command;

use chrono::Utc;
use uuid::Uuid;

use super::model::{
    ConnectionFilter, ConnectionRecord, ConnectionStatus, ProcessTrafficSummary, TrafficSummary,
};
use crate::model::{ProcessInfo, Protocol, ProxyProfile, Rule};
use crate::policy::{simulate_policy, PolicySimulationResponse, SimulationInput};

pub struct ConnectionCollector;

impl ConnectionCollector {
    /// Collect current live network connections and correlate with processes and rules.
    pub fn collect(
        processes: &[ProcessInfo],
        rules: &[Rule],
        proxies: &[ProxyProfile],
        filter: Option<&ConnectionFilter>,
    ) -> Vec<ConnectionRecord> {
        let raw_entries = Self::collect_raw();
        let proc_map = processes
            .iter()
            .map(|p| (p.pid, p))
            .collect::<HashMap<_, _>>();

        let mut records = Vec::with_capacity(raw_entries.len());

        for raw in raw_entries {
            let (process_name, exe_path) = if let Some(proc) = proc_map.get(&raw.pid) {
                (proc.name.clone(), Some(proc.exe.clone()))
            } else if raw.pid == 0 {
                ("System Idle".to_string(), None)
            } else if raw.pid == 4 {
                ("System".to_string(), None)
            } else {
                (format!("PID {}", raw.pid), None)
            };

            // Evaluate route for this connection
            let sim_input = SimulationInput {
                process_name: process_name.clone(),
                exe_path: exe_path.clone(),
                pid: Some(raw.pid),
                parent_process: None,
                protocol: raw.protocol,
                domain: None,
                ip: Some(raw.remote_ip.clone()),
                port: Some(raw.remote_port),
                network_interface: None,
            };

            let sim_res = simulate_policy(rules, proxies, &sim_input);
            let (matched_rule_id, matched_rule_name) =
                if let Some(ref winner) = sim_res.selected_rule {
                    (Some(winner.rule_id.clone()), Some(winner.rule_name.clone()))
                } else {
                    (None, None)
                };

            let record = ConnectionRecord {
                id: Uuid::new_v4().to_string(),
                pid: raw.pid,
                process_name,
                exe_path,
                protocol: raw.protocol,
                local_addr: raw.local_ip,
                local_port: raw.local_port,
                remote_addr: raw.remote_ip,
                remote_port: raw.remote_port,
                domain: None,
                status: raw.status,
                rule_id: matched_rule_id,
                rule_name: matched_rule_name,
                route_action: sim_res.effective_action,
                action_target: sim_res.effective_target,
                timestamp: Utc::now(),
            };

            // Apply filters
            if let Some(f) = filter {
                if let Some(pid) = f.pid {
                    if record.pid != pid {
                        continue;
                    }
                }
                if let Some(ref name) = f.process_name {
                    if !record
                        .process_name
                        .to_ascii_lowercase()
                        .contains(&name.to_ascii_lowercase())
                    {
                        continue;
                    }
                }
                if let Some(ref search) = f.search {
                    let s = search.to_ascii_lowercase();
                    let matches_search = record.process_name.to_ascii_lowercase().contains(&s)
                        || record.remote_addr.contains(&s)
                        || record.action_target.to_ascii_lowercase().contains(&s)
                        || record
                            .rule_name
                            .as_deref()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .contains(&s);
                    if !matches_search {
                        continue;
                    }
                }
                if let Some(ref status_str) = f.status {
                    let expected_status = ConnectionStatus::from_netstat_str(status_str);
                    if record.status != expected_status {
                        continue;
                    }
                }
            }

            records.push(record);
        }

        if let Some(f) = filter {
            if let Some(limit) = f.limit {
                records.truncate(limit);
            }
        }

        records
    }

    /// Explain why a specific connection was routed in this manner.
    pub fn explain(
        record: &ConnectionRecord,
        rules: &[Rule],
        proxies: &[ProxyProfile],
    ) -> PolicySimulationResponse {
        let sim_input = SimulationInput {
            process_name: record.process_name.clone(),
            exe_path: record.exe_path.clone(),
            pid: Some(record.pid),
            parent_process: None,
            protocol: record.protocol,
            domain: record.domain.clone(),
            ip: Some(record.remote_addr.clone()),
            port: Some(record.remote_port),
            network_interface: None,
        };
        simulate_policy(rules, proxies, &sim_input)
    }

    /// Aggregate traffic overview metrics from records.
    pub fn summarize(records: &[ConnectionRecord]) -> TrafficSummary {
        let mut established = 0;
        let mut listening = 0;
        let mut proc_counts: HashMap<String, (usize, usize)> = HashMap::new(); // (active, total)
        let mut route_dist: HashMap<String, usize> = HashMap::new();

        for r in records {
            let is_est = r.status == ConnectionStatus::Established;
            let is_listen = r.status == ConnectionStatus::Listening;

            if is_est {
                established += 1;
            }
            if is_listen {
                listening += 1;
            }

            let entry = proc_counts.entry(r.process_name.clone()).or_insert((0, 0));
            entry.1 += 1;
            if is_est {
                entry.0 += 1;
            }

            *route_dist.entry(r.action_target.clone()).or_insert(0) += 1;
        }

        let mut top_processes = proc_counts
            .into_iter()
            .map(|(name, (active, total))| ProcessTrafficSummary {
                process_name: name,
                active_connections: active,
                total_connections: total,
            })
            .collect::<Vec<_>>();

        top_processes.sort_by(|a, b| b.total_connections.cmp(&a.total_connections));
        top_processes.truncate(10);

        TrafficSummary {
            total_connections: records.len(),
            established_connections: established,
            listening_ports: listening,
            top_processes,
            route_distribution: route_dist,
        }
    }

    fn collect_raw() -> Vec<RawConnectionEntry> {
        #[cfg(windows)]
        {
            Self::collect_windows_netstat()
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    #[cfg(windows)]
    fn collect_windows_netstat() -> Vec<RawConnectionEntry> {
        let output = match Command::new("netstat").args(["-ano", "-p", "tcp"]).output() {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut entries = Self::parse_netstat_tcp(&text);

        // Also capture UDP endpoints
        if let Ok(udp_output) = Command::new("netstat").args(["-ano", "-p", "udp"]).output() {
            let udp_text = String::from_utf8_lossy(&udp_output.stdout);
            entries.extend(Self::parse_netstat_udp(&udp_text));
        }

        entries
    }

    pub fn parse_netstat_tcp(text: &str) -> Vec<RawConnectionEntry> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            // Format: TCP  local_addr:port  remote_addr:port  STATE  PID
            if parts.len() >= 5 && parts[0].eq_ignore_ascii_case("TCP") {
                let (local_ip, local_port) = parse_host_port(parts[1]);
                let (remote_ip, remote_port) = parse_host_port(parts[2]);
                let status = ConnectionStatus::from_netstat_str(parts[3]);
                let pid = parts[4].parse::<u32>().unwrap_or(0);

                entries.push(RawConnectionEntry {
                    protocol: Protocol::Tcp,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    status,
                    pid,
                });
            }
        }
        entries
    }

    pub fn parse_netstat_udp(text: &str) -> Vec<RawConnectionEntry> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            // Format: UDP  local_addr:port  *:*  PID
            if parts.len() >= 4 && parts[0].eq_ignore_ascii_case("UDP") {
                let (local_ip, local_port) = parse_host_port(parts[1]);
                let (remote_ip, remote_port) = parse_host_port(parts[2]);
                let pid = parts[3].parse::<u32>().unwrap_or(0);

                entries.push(RawConnectionEntry {
                    protocol: Protocol::Udp,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    status: ConnectionStatus::Listening,
                    pid,
                });
            }
        }
        entries
    }
}

#[derive(Debug, Clone)]
pub struct RawConnectionEntry {
    pub protocol: Protocol,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub status: ConnectionStatus,
    pub pid: u32,
}

fn parse_host_port(s: &str) -> (String, u16) {
    if let Some(pos) = s.rfind(':') {
        let host = &s[..pos];
        let port = s[pos + 1..].parse::<u16>().unwrap_or(0);
        let host_clean = host.trim_matches(|c| c == '[' || c == ']').to_string();
        (host_clean, port)
    } else {
        (s.to_string(), 0)
    }
}
