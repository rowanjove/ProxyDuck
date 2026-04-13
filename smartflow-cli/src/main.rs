use std::{collections::BTreeMap, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use reqwest::blocking::{Client, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Parser)]
#[command(author, version, about = "SmartFlow command line client")]
struct Cli {
    #[arg(
        long,
        env = "SMARTFLOW_CORE_URL",
        default_value = "http://127.0.0.1:46666"
    )]
    core_url: String,

    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status,
    Config,
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Mode {
        #[command(subcommand)]
        command: ModeCommand,
    },
    Proxies {
        #[command(subcommand)]
        command: ProxyCommand,
    },
    Rules {
        #[command(subcommand)]
        command: RuleCommand,
    },
    Quickbar {
        #[command(subcommand)]
        command: QuickBarCommand,
    },
    Processes {
        #[command(subcommand)]
        command: ProcessCommand,
    },
    Logs(LogsArgs),
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    Status,
    On,
    Off,
    Set(RuntimeSetArgs),
}

#[derive(Debug, Args)]
struct RuntimeSetArgs {
    #[arg(long)]
    enabled: Option<SwitchState>,
    #[arg(long)]
    dns_enforced: Option<SwitchState>,
    #[arg(long)]
    ipv6_blocked: Option<SwitchState>,
    #[arg(long)]
    doh_blocked: Option<SwitchState>,
    #[arg(long)]
    log_level: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ModeCommand {
    Get,
    Set { mode: EngineModeArg },
}

#[derive(Debug, Subcommand)]
enum ProxyCommand {
    List,
    Add(ProxyAddArgs),
    Update(ProxyUpdateArgs),
    Remove { target: String },
}

#[derive(Debug, Args)]
struct ProxyAddArgs {
    #[arg(long)]
    id: Option<String>,
    #[arg(long)]
    name: String,
    #[arg(long)]
    kind: ProxyKindArg,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    enabled: Option<SwitchState>,
}

#[derive(Debug, Args)]
struct ProxyUpdateArgs {
    target: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    kind: Option<ProxyKindArg>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    clear_username: bool,
    #[arg(long)]
    clear_password: bool,
    #[arg(long)]
    enabled: Option<SwitchState>,
}

#[derive(Debug, Subcommand)]
enum RuleCommand {
    List,
    Add(RuleAddArgs),
    Remove { target: String },
}

#[derive(Debug, Args)]
struct RuleAddArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    proxy: String,
    #[arg(long = "app")]
    app_names: Vec<String>,
    #[arg(long = "path")]
    exe_paths: Vec<String>,
    #[arg(long = "pid")]
    pids: Vec<u32>,
    #[arg(long)]
    wildcard: Option<String>,
    #[arg(long = "protocol")]
    protocols: Vec<ProtocolArg>,
    #[arg(long)]
    enabled: Option<SwitchState>,
    #[arg(long)]
    auto_bind_children: Option<SwitchState>,
    #[arg(long)]
    force_dns: Option<SwitchState>,
    #[arg(long)]
    block_ipv6: Option<SwitchState>,
    #[arg(long)]
    block_doh: Option<SwitchState>,
}

#[derive(Debug, Subcommand)]
enum QuickBarCommand {
    List,
    Launch { target: String },
}

#[derive(Debug, Subcommand)]
enum ProcessCommand {
    List(ProcessListArgs),
}

#[derive(Debug, Args)]
struct ProcessListArgs {
    #[arg(long, default_value_t = 50)]
    limit: usize,
    #[arg(long)]
    filter: Option<String>,
}

#[derive(Debug, Args)]
struct LogsArgs {
    #[arg(long, default_value_t = 20)]
    tail: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SwitchState {
    On,
    Off,
}

impl SwitchState {
    fn as_bool(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EngineModeArg {
    WinDivert,
    Wfp,
    ApiHook,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProxyKindArg {
    Socks5,
    Http,
    Direct,
    Interface,
    Vpn,
}

impl ProxyKindArg {
    fn api_value(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
            Self::Direct => "direct",
            Self::Interface => "interface",
            Self::Vpn => "vpn",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProtocolArg {
    Tcp,
    Udp,
    Dns,
}

impl ProtocolArg {
    fn api_value(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Dns => "dns",
        }
    }
}

impl EngineModeArg {
    fn api_value(self) -> &'static str {
        match self {
            Self::WinDivert => "win_divert",
            Self::Wfp => "wfp",
            Self::ApiHook => "api_hook",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiEnvelope<T> {
    ok: bool,
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthStatus {
    status: String,
    version: String,
    engine_mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeToggles {
    enabled: bool,
    dns_enforced: bool,
    ipv6_blocked: bool,
    doh_blocked: bool,
    log_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyProfile {
    id: String,
    name: String,
    kind: String,
    endpoint: String,
    username: Option<String>,
    password: Option<String>,
    enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct MatchCriteria {
    #[serde(default)]
    app_names: Vec<String>,
    #[serde(default)]
    exe_paths: Vec<String>,
    #[serde(default)]
    pids: Vec<u32>,
    wildcard: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    name: String,
    enabled: bool,
    matcher: MatchCriteria,
    proxy_profile: String,
    #[serde(default)]
    protocols: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuickBarItem {
    id: String,
    name: String,
    exe_path: String,
    proxy_profile: String,
    start_mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppConfig {
    version: String,
    engine_mode: String,
    proxies: Vec<ProxyProfile>,
    rules: Vec<Rule>,
    quick_bar: Vec<QuickBarItem>,
    runtime: RuntimeToggles,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RuntimeStats {
    engine_mode: String,
    started_at: Option<String>,
    last_reload_at: Option<String>,
    #[serde(default)]
    rule_hits: BTreeMap<String, u64>,
    #[serde(default)]
    process_hits: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UiLogEvent {
    ts: String,
    level: String,
    source: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProcessInfo {
    pid: u32,
    name: String,
    exe: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusReport {
    core_url: String,
    health: HealthStatus,
    runtime: RuntimeToggles,
    proxy_count: usize,
    enabled_proxy_count: usize,
    rule_count: usize,
    enabled_rule_count: usize,
    quickbar_count: usize,
    stats: RuntimeStats,
}

struct ApiClient {
    base_url: String,
    http: Client,
}

impl ApiClient {
    fn new(base_url: String) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(4))
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .http
            .get(self.url(path))
            .send()
            .with_context(|| format!("request failed: GET {path}"))?;
        self.decode(response, path)
    }

    fn post<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        let response = self
            .http
            .post(self.url(path))
            .json(&body)
            .send()
            .with_context(|| format!("request failed: POST {path}"))?;
        self.decode(response, path)
    }

    fn put<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        let response = self
            .http
            .put(self.url(path))
            .json(&body)
            .send()
            .with_context(|| format!("request failed: PUT {path}"))?;
        self.decode(response, path)
    }

    fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .http
            .delete(self.url(path))
            .send()
            .with_context(|| format!("request failed: DELETE {path}"))?;
        self.decode(response, path)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn decode<T: DeserializeOwned>(&self, response: Response, path: &str) -> Result<T> {
        let status = response.status();
        let payload: ApiEnvelope<T> = response
            .json()
            .with_context(|| format!("invalid response body for {path}"))?;

        if status.is_success() && payload.ok {
            return payload
                .data
                .ok_or_else(|| anyhow!("missing response data for {path}"));
        }

        let error = payload
            .error
            .unwrap_or_else(|| format!("request failed with status {status}"));
        bail!("{error}");
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = ApiClient::new(cli.core_url.clone())?;

    match cli.command {
        Command::Status => show_status(&client, cli.json),
        Command::Config => show_config(&client),
        Command::Runtime { command } => handle_runtime(&client, command, cli.json),
        Command::Mode { command } => handle_mode(&client, command, cli.json),
        Command::Proxies { command } => handle_proxies(&client, command, cli.json),
        Command::Rules { command } => handle_rules(&client, command, cli.json),
        Command::Quickbar { command } => handle_quickbar(&client, command, cli.json),
        Command::Processes { command } => handle_processes(&client, command, cli.json),
        Command::Logs(args) => show_logs(&client, args.tail, cli.json),
    }
}

fn show_status(client: &ApiClient, json_output: bool) -> Result<()> {
    let health: HealthStatus = client.get("/health")?;
    let config: AppConfig = client.get("/config")?;
    let stats: RuntimeStats = client.get("/stats")?;

    let report = StatusReport {
        core_url: client.base_url.clone(),
        health,
        runtime: config.runtime,
        proxy_count: config.proxies.len(),
        enabled_proxy_count: config.proxies.iter().filter(|proxy| proxy.enabled).count(),
        rule_count: config.rules.len(),
        enabled_rule_count: config.rules.iter().filter(|rule| rule.enabled).count(),
        quickbar_count: config.quick_bar.len(),
        stats,
    };

    if json_output {
        return print_json(&report);
    }

    println!("SmartFlow");
    println!("  Core URL: {}", report.core_url);
    println!("  Version: {}", report.health.version);
    println!("  Status: {}", report.health.status);
    println!("  Engine Mode: {}", report.stats.engine_mode);
    println!("  Runtime Enabled: {}", yes_no(report.runtime.enabled));
    println!(
        "  Runtime Policies: DNS={} IPv6={} DoH={}",
        yes_no(report.runtime.dns_enforced),
        yes_no(report.runtime.ipv6_blocked),
        yes_no(report.runtime.doh_blocked)
    );
    println!(
        "  Proxies: {} total / {} enabled",
        report.proxy_count, report.enabled_proxy_count
    );
    println!(
        "  Rules: {} total / {} enabled",
        report.rule_count, report.enabled_rule_count
    );
    println!("  Quick Bar Items: {}", report.quickbar_count);
    println!(
        "  Last Reload: {}",
        report.stats.last_reload_at.as_deref().unwrap_or("never")
    );
    Ok(())
}

fn show_config(client: &ApiClient) -> Result<()> {
    let config: AppConfig = client.get("/config")?;
    print_json(&config)
}

fn handle_runtime(client: &ApiClient, command: RuntimeCommand, json_output: bool) -> Result<()> {
    match command {
        RuntimeCommand::Status => {
            let config: AppConfig = client.get("/config")?;
            if json_output {
                return print_json(&config.runtime);
            }

            println!("Runtime");
            println!("  Enabled: {}", yes_no(config.runtime.enabled));
            println!("  DNS Enforced: {}", yes_no(config.runtime.dns_enforced));
            println!("  IPv6 Blocked: {}", yes_no(config.runtime.ipv6_blocked));
            println!("  DoH Blocked: {}", yes_no(config.runtime.doh_blocked));
            println!("  Log Level: {}", config.runtime.log_level);
            Ok(())
        }
        RuntimeCommand::On => set_runtime_enabled(client, true, json_output),
        RuntimeCommand::Off => set_runtime_enabled(client, false, json_output),
        RuntimeCommand::Set(args) => {
            let body = json!({
                "enabled": args.enabled.map(SwitchState::as_bool),
                "dnsEnforced": args.dns_enforced.map(SwitchState::as_bool),
                "ipv6Blocked": args.ipv6_blocked.map(SwitchState::as_bool),
                "dohBlocked": args.doh_blocked.map(SwitchState::as_bool),
                "logLevel": args.log_level,
            });

            let runtime: RuntimeToggles = client.post("/runtime", body)?;
            if json_output {
                return print_json(&runtime);
            }

            println!("Runtime updated");
            println!("  Enabled: {}", yes_no(runtime.enabled));
            println!("  DNS Enforced: {}", yes_no(runtime.dns_enforced));
            println!("  IPv6 Blocked: {}", yes_no(runtime.ipv6_blocked));
            println!("  DoH Blocked: {}", yes_no(runtime.doh_blocked));
            println!("  Log Level: {}", runtime.log_level);
            Ok(())
        }
    }
}

fn set_runtime_enabled(client: &ApiClient, enabled: bool, json_output: bool) -> Result<()> {
    let runtime: RuntimeToggles = client.post("/runtime", json!({ "enabled": enabled }))?;
    if json_output {
        return print_json(&runtime);
    }

    println!("Runtime {}", if enabled { "enabled" } else { "disabled" });
    Ok(())
}

fn handle_mode(client: &ApiClient, command: ModeCommand, json_output: bool) -> Result<()> {
    match command {
        ModeCommand::Get => {
            let config: AppConfig = client.get("/config")?;
            if json_output {
                return print_json(&json!({ "mode": config.engine_mode }));
            }

            println!("{}", config.engine_mode);
            Ok(())
        }
        ModeCommand::Set { mode } => {
            let _: String = client.post("/engine/mode", json!({ "mode": mode.api_value() }))?;
            if json_output {
                return print_json(&json!({ "mode": mode.api_value() }));
            }

            println!("Engine mode set to {}", mode.api_value());
            Ok(())
        }
    }
}

fn handle_proxies(client: &ApiClient, command: ProxyCommand, json_output: bool) -> Result<()> {
    match command {
        ProxyCommand::List => {
            let proxies: Vec<ProxyProfile> = client.get("/proxies")?;
            if json_output {
                return print_json(&proxies);
            }

            if proxies.is_empty() {
                println!("No proxy profiles.");
                return Ok(());
            }

            println!(
                "{:<36}  {:<24}  {:<10}  {:<22}  {}",
                "ID", "NAME", "KIND", "ENDPOINT", "ENABLED"
            );
            for proxy in proxies {
                println!(
                    "{:<36}  {:<24}  {:<10}  {:<22}  {}",
                    proxy.id,
                    truncate(&proxy.name, 24),
                    proxy.kind,
                    truncate(&proxy.endpoint, 22),
                    yes_no(proxy.enabled)
                );
            }
            Ok(())
        }
        ProxyCommand::Add(args) => {
            let proxies: Vec<ProxyProfile> = client.get("/proxies")?;
            let requested_id = args
                .id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if let Some(requested_id) = requested_id {
                if proxies.iter().any(|proxy| proxy.id == requested_id) {
                    bail!("proxy id '{requested_id}' already exists");
                }
            }

            let body = json!({
                "id": args.id.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()),
                "name": trimmed_non_empty(&args.name, "proxy name")?,
                "kind": args.kind.api_value(),
                "endpoint": trimmed_non_empty(&args.endpoint, "proxy endpoint")?,
                "username": normalize_optional_string(args.username),
                "password": normalize_optional_string(args.password),
                "enabled": args.enabled.map(SwitchState::as_bool),
            });

            let proxy: ProxyProfile = client.post("/proxies", body)?;
            if json_output {
                return print_json(&proxy);
            }

            println!("Proxy created: {} ({})", proxy.name, proxy.id);
            Ok(())
        }
        ProxyCommand::Update(args) => {
            validate_proxy_update_args(&args)?;

            let proxies: Vec<ProxyProfile> = client.get("/proxies")?;
            let proxy = resolve_proxy_target(&proxies, &args.target)?;

            let username = if args.clear_username {
                None
            } else {
                normalize_optional_string(args.username).or_else(|| proxy.username.clone())
            };

            let password = if args.clear_password {
                None
            } else {
                normalize_optional_string(args.password).or_else(|| proxy.password.clone())
            };

            let body = json!({
                "name": args.name.as_deref().map(|value| trimmed_non_empty(value, "proxy name")).transpose()?.unwrap_or_else(|| proxy.name.clone()),
                "kind": args.kind.map(ProxyKindArg::api_value).unwrap_or(proxy.kind.as_str()),
                "endpoint": args.endpoint.as_deref().map(|value| trimmed_non_empty(value, "proxy endpoint")).transpose()?.unwrap_or_else(|| proxy.endpoint.clone()),
                "username": username,
                "password": password,
                "enabled": Some(args.enabled.map(SwitchState::as_bool).unwrap_or(proxy.enabled)),
            });

            let updated: ProxyProfile = client.put(&format!("/proxies/{}", proxy.id), body)?;
            if json_output {
                return print_json(&updated);
            }

            println!("Proxy updated: {} ({})", updated.name, updated.id);
            Ok(())
        }
        ProxyCommand::Remove { target } => {
            let proxies: Vec<ProxyProfile> = client.get("/proxies")?;
            let proxy = resolve_proxy_target(&proxies, &target)?;
            let _: String = client.delete(&format!("/proxies/{}", proxy.id))?;

            if json_output {
                return print_json(
                    &json!({ "id": &proxy.id, "name": &proxy.name, "status": "deleted" }),
                );
            }

            println!("Proxy removed: {}", proxy.name);
            Ok(())
        }
    }
}

fn handle_rules(client: &ApiClient, command: RuleCommand, json_output: bool) -> Result<()> {
    match command {
        RuleCommand::List => {
            let rules: Vec<Rule> = client.get("/rules")?;
            if json_output {
                return print_json(&rules);
            }

            if rules.is_empty() {
                println!("No rules.");
                return Ok(());
            }

            println!(
                "{:<36}  {:<24}  {:<10}  {:<16}  {}",
                "ID", "NAME", "ENABLED", "PROXY", "MATCHER"
            );
            for rule in rules {
                println!(
                    "{:<36}  {:<24}  {:<10}  {:<16}  {}",
                    rule.id,
                    truncate(&rule.name, 24),
                    yes_no(rule.enabled),
                    truncate(&rule.proxy_profile, 16),
                    truncate(&matcher_summary(&rule.matcher), 64)
                );
            }
            Ok(())
        }
        RuleCommand::Add(args) => {
            let matcher = build_rule_matcher(&args)?;
            let proxies: Vec<ProxyProfile> = client.get("/proxies")?;
            let proxy = resolve_proxy_target(&proxies, &args.proxy)?;
            let body = json!({
                "name": trimmed_non_empty(&args.name, "rule name")?,
                "proxyProfile": &proxy.id,
                "matcher": matcher,
                "protocols": if args.protocols.is_empty() {
                    None::<Vec<String>>
                } else {
                    Some(args.protocols.iter().copied().map(ProtocolArg::api_value).map(str::to_string).collect::<Vec<_>>())
                },
                "enabled": args.enabled.map(SwitchState::as_bool),
                "autoBindChildren": args.auto_bind_children.map(SwitchState::as_bool),
                "forceDns": args.force_dns.map(SwitchState::as_bool),
                "blockIpv6": args.block_ipv6.map(SwitchState::as_bool),
                "blockDoh": args.block_doh.map(SwitchState::as_bool),
            });

            let rule: Rule = client.post("/rules", body)?;
            if json_output {
                return print_json(&rule);
            }

            println!("Rule created: {} ({})", rule.name, rule.id);
            Ok(())
        }
        RuleCommand::Remove { target } => {
            let rules: Vec<Rule> = client.get("/rules")?;
            let rule = resolve_rule_target(&rules, &target)?;
            let _: String = client.delete(&format!("/rules/{}", rule.id))?;

            if json_output {
                return print_json(
                    &json!({ "id": &rule.id, "name": &rule.name, "status": "deleted" }),
                );
            }

            println!("Rule removed: {}", rule.name);
            Ok(())
        }
    }
}

fn handle_quickbar(client: &ApiClient, command: QuickBarCommand, json_output: bool) -> Result<()> {
    match command {
        QuickBarCommand::List => {
            let items: Vec<QuickBarItem> = client.get("/quickbar")?;
            if json_output {
                return print_json(&items);
            }

            if items.is_empty() {
                println!("No quick bar items.");
                return Ok(());
            }

            println!(
                "{:<36}  {:<24}  {:<18}  {:<16}  {}",
                "ID", "NAME", "MODE", "PROXY", "EXE"
            );
            for item in items {
                println!(
                    "{:<36}  {:<24}  {:<18}  {:<16}  {}",
                    item.id,
                    truncate(&item.name, 24),
                    item.start_mode,
                    truncate(&item.proxy_profile, 16),
                    truncate(&item.exe_path, 60)
                );
            }
            Ok(())
        }
        QuickBarCommand::Launch { target } => {
            let items: Vec<QuickBarItem> = client.get("/quickbar")?;
            let item = resolve_quickbar_target(&items, &target)?;
            let _: String = client.post(&format!("/quickbar/{}/launch", item.id), json!({}))?;

            if json_output {
                return print_json(
                    &json!({ "id": &item.id, "name": &item.name, "status": "launched" }),
                );
            }

            println!("Launched quick bar item: {}", item.name);
            Ok(())
        }
    }
}

fn handle_processes(client: &ApiClient, command: ProcessCommand, json_output: bool) -> Result<()> {
    match command {
        ProcessCommand::List(args) => {
            let mut processes: Vec<ProcessInfo> = client.get("/processes")?;
            if let Some(filter) = args.filter {
                let filter = filter.to_ascii_lowercase();
                processes.retain(|proc_info| {
                    proc_info.name.to_ascii_lowercase().contains(&filter)
                        || proc_info.exe.to_ascii_lowercase().contains(&filter)
                });
            }

            let limit = args.limit.max(1);
            if processes.len() > limit {
                processes.truncate(limit);
            }

            if json_output {
                return print_json(&processes);
            }

            if processes.is_empty() {
                println!("No matching processes.");
                return Ok(());
            }

            println!("{:<8}  {:<28}  {}", "PID", "NAME", "EXE");
            for proc_info in processes {
                println!(
                    "{:<8}  {:<28}  {}",
                    proc_info.pid,
                    truncate(&proc_info.name, 28),
                    truncate(&proc_info.exe, 90)
                );
            }
            Ok(())
        }
    }
}

fn show_logs(client: &ApiClient, tail: usize, json_output: bool) -> Result<()> {
    let mut logs: Vec<UiLogEvent> = client.get("/logs")?;
    let tail = tail.max(1);
    if logs.len() > tail {
        logs = logs.split_off(logs.len() - tail);
    }

    if json_output {
        return print_json(&logs);
    }

    if logs.is_empty() {
        println!("No logs.");
        return Ok(());
    }

    for log in logs {
        println!(
            "[{}] [{}] [{}] {}",
            log.ts, log.level, log.source, log.message
        );
    }
    Ok(())
}

fn resolve_quickbar_target<'a>(
    items: &'a [QuickBarItem],
    target: &str,
) -> Result<&'a QuickBarItem> {
    if let Some(item) = items.iter().find(|item| item.id == target) {
        return Ok(item);
    }

    let lower_target = target.to_ascii_lowercase();

    if let Some(item) = items
        .iter()
        .find(|item| item.name.eq_ignore_ascii_case(target))
    {
        return Ok(item);
    }

    let matches: Vec<&QuickBarItem> = items
        .iter()
        .filter(|item| item.name.to_ascii_lowercase().contains(&lower_target))
        .collect();

    match matches.as_slice() {
        [item] => Ok(item),
        [] => bail!("no quick bar item matched '{target}'"),
        _ => bail!("multiple quick bar items matched '{target}'; use the item id"),
    }
}

fn resolve_proxy_target<'a>(items: &'a [ProxyProfile], target: &str) -> Result<&'a ProxyProfile> {
    resolve_named_target(
        items,
        target,
        |item| item.id.as_str(),
        |item| item.name.as_str(),
        "proxy",
    )
}

fn resolve_rule_target<'a>(items: &'a [Rule], target: &str) -> Result<&'a Rule> {
    resolve_named_target(
        items,
        target,
        |item| item.id.as_str(),
        |item| item.name.as_str(),
        "rule",
    )
}

fn resolve_named_target<'a, T, FId, FName>(
    items: &'a [T],
    target: &str,
    id_fn: FId,
    name_fn: FName,
    label: &str,
) -> Result<&'a T>
where
    FId: Fn(&T) -> &str,
    FName: Fn(&T) -> &str,
{
    if let Some(item) = items.iter().find(|item| id_fn(item) == target) {
        return Ok(item);
    }

    if let Some(item) = items
        .iter()
        .find(|item| name_fn(item).eq_ignore_ascii_case(target))
    {
        return Ok(item);
    }

    let lower_target = target.to_ascii_lowercase();
    let matches: Vec<&T> = items
        .iter()
        .filter(|item| name_fn(item).to_ascii_lowercase().contains(&lower_target))
        .collect();

    match matches.as_slice() {
        [item] => Ok(item),
        [] => bail!("no {label} matched '{target}'"),
        _ => bail!("multiple {label}s matched '{target}'; use the item id"),
    }
}

fn validate_proxy_update_args(args: &ProxyUpdateArgs) -> Result<()> {
    if args.username.is_some() && args.clear_username {
        bail!("cannot use --username and --clear-username together");
    }
    if args.password.is_some() && args.clear_password {
        bail!("cannot use --password and --clear-password together");
    }
    Ok(())
}

fn build_rule_matcher(args: &RuleAddArgs) -> Result<Value> {
    let app_names = trim_string_list(&args.app_names);
    let exe_paths = trim_string_list(&args.exe_paths);
    let wildcard = normalize_optional_string(args.wildcard.clone());

    if app_names.is_empty() && exe_paths.is_empty() && args.pids.is_empty() && wildcard.is_none() {
        bail!("at least one matcher is required: --app, --path, --pid, or --wildcard");
    }

    Ok(json!({
        "appNames": app_names,
        "exePaths": exe_paths,
        "pids": args.pids.clone(),
        "wildcard": wildcard,
    }))
}

fn matcher_summary(matcher: &MatchCriteria) -> String {
    let mut parts = Vec::new();

    if !matcher.app_names.is_empty() {
        parts.push(format!("apps={}", matcher.app_names.join(",")));
    }
    if !matcher.exe_paths.is_empty() {
        parts.push(format!("paths={}", matcher.exe_paths.join(",")));
    }
    if !matcher.pids.is_empty() {
        let pids = matcher
            .pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        parts.push(format!("pids={pids}"));
    }
    if let Some(wildcard) = matcher.wildcard.as_deref() {
        if !wildcard.trim().is_empty() {
            parts.push(format!("wildcard={wildcard}"));
        }
    }

    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    let mut chars = value.chars();
    let taken = chars.by_ref().take(max_len).collect::<String>();
    if chars.next().is_some() && max_len > 1 {
        format!("{}...", taken.chars().take(max_len - 3).collect::<String>())
    } else {
        taken
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).context("failed to serialize JSON output")?
    );
    Ok(())
}

fn trimmed_non_empty(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} cannot be empty");
    }
    Ok(trimmed.to_string())
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn trim_string_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_summary() {
        let matcher = MatchCriteria {
            app_names: vec!["node.exe".to_string()],
            exe_paths: vec!["C:\\node.exe".to_string()],
            pids: vec![42],
            wildcard: Some("node".to_string()),
        };

        assert_eq!(
            matcher_summary(&matcher),
            "apps=node.exe paths=C:\\node.exe pids=42 wildcard=node"
        );
    }

    #[test]
    fn test_resolve_quickbar_target_prefers_exact_match() {
        let items = vec![
            QuickBarItem {
                id: "abc".to_string(),
                name: "Cursor Stable".to_string(),
                exe_path: "C:\\Cursor.exe".to_string(),
                proxy_profile: "clash-socks".to_string(),
                start_mode: "start_and_bind".to_string(),
            },
            QuickBarItem {
                id: "def".to_string(),
                name: "Cursor Nightly".to_string(),
                exe_path: "C:\\CursorNightly.exe".to_string(),
                proxy_profile: "clash-socks".to_string(),
                start_mode: "start_and_bind".to_string(),
            },
        ];

        assert_eq!(resolve_quickbar_target(&items, "abc").unwrap().id, "abc");
        assert_eq!(
            resolve_quickbar_target(&items, "cursor stable").unwrap().id,
            "abc"
        );
        assert!(resolve_quickbar_target(&items, "cursor").is_err());
    }

    #[test]
    fn test_build_rule_matcher_requires_selector() {
        let args = RuleAddArgs {
            name: "rule".to_string(),
            proxy: "clash-socks".to_string(),
            app_names: Vec::new(),
            exe_paths: Vec::new(),
            pids: Vec::new(),
            wildcard: None,
            protocols: Vec::new(),
            enabled: None,
            auto_bind_children: None,
            force_dns: None,
            block_ipv6: None,
            block_doh: None,
        };

        assert!(build_rule_matcher(&args).is_err());
    }

    #[test]
    fn test_resolve_proxy_target_matches_by_name() {
        let items = vec![
            ProxyProfile {
                id: "proxy-1".to_string(),
                name: "Clash Main".to_string(),
                kind: "socks5".to_string(),
                endpoint: "127.0.0.1:7897".to_string(),
                username: None,
                password: None,
                enabled: true,
            },
            ProxyProfile {
                id: "proxy-2".to_string(),
                name: "Office".to_string(),
                kind: "http".to_string(),
                endpoint: "10.0.0.8:8080".to_string(),
                username: None,
                password: None,
                enabled: true,
            },
        ];

        assert_eq!(
            resolve_proxy_target(&items, "clash main").unwrap().id,
            "proxy-1"
        );
    }
}
