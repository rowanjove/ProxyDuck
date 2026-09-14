use serde_json::Value;

use super::model::{ConfigFormat, SemanticConfig, SemanticEndpoint, SemanticListener};

pub struct SemanticExtractor;

impl SemanticExtractor {
    pub fn extract(content: &str, format: ConfigFormat) -> SemanticConfig {
        match format {
            ConfigFormat::Yaml => Self::extract_from_yaml(content),
            ConfigFormat::Json | ConfigFormat::Jsonc => Self::extract_from_json(content),
            _ => SemanticConfig::default(),
        }
    }

    fn extract_from_yaml(content: &str) -> SemanticConfig {
        let val: Value = match serde_yaml::from_str(content) {
            Ok(v) => v,
            Err(_) => return SemanticConfig::default(),
        };

        let mut listeners = Vec::new();
        let mut endpoints = Vec::new();
        let mut dns_servers = Vec::new();

        // 1. Listeners
        if let Some(port) = val.get("mixed-port").and_then(Value::as_u64) {
            listeners.push(SemanticListener {
                name: "mixed-port".to_string(),
                protocol: "HTTP/SOCKS5".to_string(),
                port: port as u16,
                bind_address: val
                    .get("bind-address")
                    .and_then(Value::as_str)
                    .map(|s| s.to_string()),
            });
        }
        if let Some(port) = val.get("port").and_then(Value::as_u64) {
            listeners.push(SemanticListener {
                name: "http-port".to_string(),
                protocol: "HTTP".to_string(),
                port: port as u16,
                bind_address: None,
            });
        }
        if let Some(port) = val.get("socks-port").and_then(Value::as_u64) {
            listeners.push(SemanticListener {
                name: "socks-port".to_string(),
                protocol: "SOCKS5".to_string(),
                port: port as u16,
                bind_address: None,
            });
        }

        // 2. Proxies / Endpoints
        if let Some(proxies) = val.get("proxies").and_then(Value::as_array) {
            for p in proxies {
                let name = p
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed")
                    .to_string();
                let protocol = p
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let server = p
                    .get("server")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let port = p.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;

                endpoints.push(SemanticEndpoint {
                    name,
                    protocol,
                    server,
                    port,
                });
            }
        }

        // 3. DNS
        if let Some(dns) = val.get("dns") {
            if let Some(nameservers) = dns.get("nameserver").and_then(Value::as_array) {
                for ns in nameservers {
                    if let Some(s) = ns.as_str() {
                        dns_servers.push(s.to_string());
                    }
                }
            }
        }

        // 4. Rules
        let rules_count = val
            .get("rules")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);

        SemanticConfig {
            inbound_listeners: listeners,
            outbound_endpoints: endpoints,
            routing_rules_count: rules_count,
            dns_servers,
            features: vec!["Clash YAML profile".to_string()],
        }
    }

    fn extract_from_json(content: &str) -> SemanticConfig {
        let val: Value = match serde_json::from_str(content).or_else(|_| json5::from_str(content)) {
            Ok(v) => v,
            Err(_) => return SemanticConfig::default(),
        };

        let mut listeners = Vec::new();
        let mut endpoints = Vec::new();
        let mut dns_servers = Vec::new();

        // 1. Inbounds
        if let Some(inbounds) = val.get("inbounds").and_then(Value::as_array) {
            for inb in inbounds {
                let name = inb
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or("inbound")
                    .to_string();
                let protocol = inb
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("mixed")
                    .to_string();
                let port = inb.get("listen_port").and_then(Value::as_u64).unwrap_or(0) as u16;

                listeners.push(SemanticListener {
                    name,
                    protocol,
                    port,
                    bind_address: inb
                        .get("listen")
                        .and_then(Value::as_str)
                        .map(|s| s.to_string()),
                });
            }
        }

        // 2. Outbounds
        if let Some(outbounds) = val.get("outbounds").and_then(Value::as_array) {
            for out in outbounds {
                let name = out
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or("outbound")
                    .to_string();
                let protocol = out
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("direct")
                    .to_string();
                let server = out
                    .get("server")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let port = out.get("server_port").and_then(Value::as_u64).unwrap_or(0) as u16;

                endpoints.push(SemanticEndpoint {
                    name,
                    protocol,
                    server,
                    port,
                });
            }
        }

        // 3. DNS
        if let Some(dns) = val.get("dns") {
            if let Some(servers) = dns.get("servers").and_then(Value::as_array) {
                for srv in servers {
                    if let Some(s) = srv.get("address").and_then(Value::as_str) {
                        dns_servers.push(s.to_string());
                    } else if let Some(s) = srv.as_str() {
                        dns_servers.push(s.to_string());
                    }
                }
            }
        }

        let rules_count = val
            .get("route")
            .and_then(|r| r.get("rules"))
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);

        SemanticConfig {
            inbound_listeners: listeners,
            outbound_endpoints: endpoints,
            routing_rules_count: rules_count,
            dns_servers,
            features: vec!["sing-box JSON profile".to_string()],
        }
    }
}
