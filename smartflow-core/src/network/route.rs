use std::process::Command;
use tracing::warn;

use super::model::{RouteEntry, RouteStatus};

pub struct RouteCollector;

impl RouteCollector {
    pub fn collect() -> RouteStatus {
        #[cfg(windows)]
        {
            if let Ok(status) = Self::collect_via_powershell() {
                if status.has_default_route {
                    return status;
                }
            }
            Self::collect_via_route_print()
        }
        #[cfg(not(windows))]
        {
            RouteStatus::default()
        }
    }

    #[cfg(windows)]
    fn collect_via_powershell() -> anyhow::Result<RouteStatus> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                r#"
                Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | ForEach-Object {
                    [PSCustomObject]@{
                        Destination = $_.DestinationPrefix
                        NextHop = $_.NextHop
                        InterfaceAlias = $_.InterfaceAlias
                        RouteMetric = $_.RouteMetric
                    }
                } | ConvertTo-Json -Compress
                "#,
            ])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("powershell Get-NetRoute failed");
        }

        let raw = String::from_utf8_lossy(&output.stdout);
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(RouteStatus::default());
        }

        Self::parse_ps_json(trimmed)
    }

    pub fn parse_ps_json(json_str: &str) -> anyhow::Result<RouteStatus> {
        let val: serde_json::Value = serde_json::from_str(json_str)?;
        let items: Vec<&serde_json::Value> = if let Some(arr) = val.as_array() {
            arr.iter().collect()
        } else {
            vec![&val]
        };

        let mut routes = Vec::new();
        for item in items {
            let destination = item["Destination"]
                .as_str()
                .unwrap_or("0.0.0.0/0")
                .to_string();
            let next_hop = item["NextHop"].as_str().unwrap_or("").to_string();
            let interface_alias = item["InterfaceAlias"].as_str().unwrap_or("").to_string();
            let route_metric = item["RouteMetric"].as_u64().unwrap_or(0) as u32;

            routes.push(RouteEntry {
                destination,
                next_hop,
                interface_alias,
                route_metric,
            });
        }

        routes.sort_by_key(|r| r.route_metric);

        let best_default = routes.first().cloned();
        let default_ipv4_gateway = best_default.as_ref().map(|r| r.next_hop.clone());
        let default_ipv4_interface = best_default.as_ref().map(|r| r.interface_alias.clone());
        let default_ipv4_metric = best_default.as_ref().map(|r| r.route_metric);
        let has_default_route = best_default.is_some();
        let rival_routes_count = if routes.len() > 1 {
            routes.len() - 1
        } else {
            0
        };

        Ok(RouteStatus {
            default_ipv4_gateway,
            default_ipv4_interface,
            default_ipv4_metric,
            default_ipv6_gateway: None,
            rival_routes_count,
            routes,
            has_default_route,
        })
    }

    #[cfg(windows)]
    fn collect_via_route_print() -> RouteStatus {
        let output = match Command::new("route").args(["print", "0.0.0.0"]).output() {
            Ok(o) => o,
            Err(e) => {
                warn!("failed to run route print: {e}");
                return RouteStatus::default();
            }
        };

        let raw = String::from_utf8_lossy(&output.stdout);
        Self::parse_route_print(&raw)
    }

    pub fn parse_route_print(raw: &str) -> RouteStatus {
        let mut routes = Vec::new();
        let mut in_active_routes = false;

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.contains("Active Routes:") || trimmed.contains("活动路由:") {
                in_active_routes = true;
                continue;
            }
            if in_active_routes && trimmed.starts_with("0.0.0.0") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 5 {
                    let next_hop = parts[2].to_string();
                    let interface_alias = parts[3].to_string();
                    let route_metric = parts[4].parse::<u32>().unwrap_or(0);
                    routes.push(RouteEntry {
                        destination: "0.0.0.0/0".to_string(),
                        next_hop,
                        interface_alias,
                        route_metric,
                    });
                }
            }
        }

        routes.sort_by_key(|r| r.route_metric);
        let best_default = routes.first().cloned();
        let has_default_route = best_default.is_some();
        let rival_routes_count = if routes.len() > 1 {
            routes.len() - 1
        } else {
            0
        };

        RouteStatus {
            default_ipv4_gateway: best_default.as_ref().map(|r| r.next_hop.clone()),
            default_ipv4_interface: best_default.as_ref().map(|r| r.interface_alias.clone()),
            default_ipv4_metric: best_default.as_ref().map(|r| r.route_metric),
            default_ipv6_gateway: None,
            rival_routes_count,
            routes,
            has_default_route,
        }
    }
}
