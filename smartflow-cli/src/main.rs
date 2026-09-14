use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::{Args, Parser, Subcommand, ValueEnum};
use reqwest::blocking::{Client, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Parser)]
#[command(author, version, about = "ProxyDuck command line client")]
struct Cli {
    #[arg(long, default_value_t = proxyduck_common::core_url_from_env())]
    core_url: String,

    #[arg(long, global = true, conflicts_with = "format")]
    json: bool,

    #[arg(long, global = true, value_enum)]
    format: Option<OutputFormat>,

    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn json_output(&self) -> bool {
        self.json || matches!(self.format, Some(OutputFormat::Json))
    }
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
    #[command(alias = "policy")]
    Rules {
        #[command(subcommand)]
        command: RuleCommand,
    },
    Quickbar {
        #[command(subcommand)]
        command: QuickBarCommand,
    },
    Profiles {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Processes {
        #[command(subcommand)]
        command: ProcessCommand,
    },
    Logs(LogsArgs),
    Diagnostics {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    #[command(name = "studio", alias = "configs", alias = "config-studio")]
    Studio {
        #[command(subcommand)]
        command: StudioCommand,
    },
    #[command(alias = "conns")]
    Connections {
        #[command(subcommand)]
        command: Option<ConnectionCommand>,
    },
    Timeline {
        #[command(subcommand)]
        command: Option<TimelineCommand>,
    },
}

#[derive(Debug, Subcommand)]
enum NetworkCommand {
    Status,
    Diagnose,
    History,
    Repair(NetworkRepairArgs),
    Snapshot(NetworkSnapshotArgs),
    Snapshots,
    Restore {
        #[arg(long, short)]
        id: String,
    },
}

#[derive(Debug, Args)]
struct NetworkRepairArgs {
    #[arg(long)]
    action: Option<String>,
    #[arg(long, default_value_t = true)]
    auto_snapshot: bool,
}

#[derive(Debug, Args)]
struct NetworkSnapshotArgs {
    #[arg(long, default_value = "manual-cli")]
    label: String,
}

#[derive(Debug, Subcommand)]
enum StudioCommand {
    Discover,
    List,
    Inspect {
        #[arg(long, short)]
        path: String,
    },
    Validate {
        #[arg(long, short)]
        path: String,
    },
    Diff {
        #[arg(long, short)]
        path: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        value: String,
    },
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
    Remove {
        target: String,
    },
    Import {
        file: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    Discover {
        #[arg(long)]
        own_port: Option<u16>,
        #[arg(long, default_value_t = false)]
        auto_add: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConnectionCommand {
    List(ConnectionListArgs),
    Summary,
}

#[derive(Debug, Args, Default)]
struct ConnectionListArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    process: Option<String>,
    #[arg(long)]
    status: Option<String>,
    #[arg(long)]
    search: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Debug, Subcommand)]
enum TimelineCommand {
    List(TimelineListArgs),
    Clear,
}

#[derive(Debug, Args, Default)]
struct TimelineListArgs {
    #[arg(long)]
    category: Option<String>,
    #[arg(long)]
    severity: Option<String>,
    #[arg(long)]
    source: Option<String>,
    #[arg(long)]
    search: Option<String>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
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
    Remove {
        target: String,
    },
    Compile,
    EffectivePlan {
        target: String,
    },
    Analyze,
    #[command(alias = "test")]
    Simulate(RuleSimulateArgs),
}

#[derive(Debug, Args)]
struct RuleAddArgs {
    #[arg(long)]
    name: String,
    #[arg(long, value_enum, default_value = "proxy")]
    action: RuleActionArg,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    priority: Option<i32>,
    #[arg(long = "app")]
    app_names: Vec<String>,
    #[arg(long = "path")]
    exe_paths: Vec<String>,
    #[arg(long = "pid")]
    pids: Vec<u32>,
    #[arg(long = "pid-creation-time", alias = "pid-start")]
    pid_creation_time: Option<u64>,
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

#[derive(Debug, Args)]
struct RuleSimulateArgs {
    #[arg(long = "name", alias = "app")]
    process_name: Option<String>,
    #[arg(long = "exe", alias = "path")]
    exe_path: Option<String>,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long = "parent")]
    parent_process: Option<String>,
    #[arg(long, default_value = "tcp")]
    protocol: String,
    #[arg(long)]
    domain: Option<String>,
    #[arg(long)]
    ip: Option<String>,
    #[arg(long)]
    port: Option<u16>,
}

#[derive(Debug, Subcommand)]
enum QuickBarCommand {
    List,
    Launch { target: String },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    List,
    Create(ProfileCreateArgs),
    Clone {
        target: String,
        #[arg(long)]
        name: Option<String>,
    },
    Activate {
        target: String,
    },
    Diff {
        target: String,
    },
    Remove {
        target: String,
    },
}

#[derive(Debug, Args)]
struct ProfileCreateArgs {
    #[arg(long)]
    name: String,
    #[arg(long, default_value = "")]
    description: String,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

impl SwitchState {
    fn as_bool(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EngineModeArg {
    #[value(
        name = "proxifyre",
        alias = "win-divert",
        alias = "windivert",
        alias = "win_divert"
    )]
    ProxiFyre,
    SingBox,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RuleActionArg {
    Proxy,
    Direct,
    Block,
    Reject,
}

impl RuleActionArg {
    fn api_value(self, proxy_id: Option<&str>) -> Value {
        match self {
            Self::Proxy => json!({ "type": "proxy", "proxyId": proxy_id.unwrap_or_default() }),
            Self::Direct => json!({ "type": "direct" }),
            Self::Block => json!({ "type": "block" }),
            Self::Reject => json!({ "type": "reject" }),
        }
    }
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
            Self::ProxiFyre => "proxifyre",
            Self::SingBox => "sing_box",
            Self::Wfp => "wfp",
            Self::ApiHook => "api_hook",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiEnvelope<T> {
    ok: bool,
    data: Option<T>,
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
    #[serde(default = "default_leak_protection_mode")]
    leak_protection_mode: String,
}

fn default_leak_protection_mode() -> String {
    "availability".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyProfile {
    id: String,
    name: String,
    kind: String,
    endpoint: String,
    username: Option<String>,
    #[serde(default)]
    password_ref: Option<String>,
    #[serde(default)]
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
    #[serde(default)]
    pid_creation_time: Option<u64>,
    wildcard: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    name: String,
    enabled: bool,
    #[serde(default = "default_rule_source")]
    source: String,
    matcher: MatchCriteria,
    proxy_profile: String,
    #[serde(default)]
    action: Option<Value>,
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
    #[serde(alias = "ruleHits")]
    rule_process_matches: BTreeMap<String, u64>,
    #[serde(default)]
    #[serde(alias = "processHits")]
    process_matches: BTreeMap<String, u64>,
    #[serde(default)]
    #[serde(alias = "proxyHits")]
    proxy_process_matches: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataPlaneStatus {
    phase: String,
    backend_name: String,
    child_pid: Option<u32>,
    active_rules: usize,
    firewall_rules: usize,
    proxy_endpoint_reachable: Option<bool>,
    fail_closed_active: bool,
    message: Option<String>,
    checked_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeStatus {
    desired_enabled: bool,
    engine_mode: String,
    data_plane: DataPlaneStatus,
    #[serde(default)]
    active_plan_fingerprint: Option<String>,
    #[serde(default)]
    required_proxy_ids: Vec<String>,
    #[serde(default)]
    degraded_reasons: Vec<String>,
    #[serde(default)]
    compile_diagnostics: Vec<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveSnapshot {
    health: HealthStatus,
    runtime_status: RuntimeStatus,
    stats: RuntimeStats,
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
    #[serde(default)]
    creation_time: Option<u64>,
    name: String,
    exe: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusReport {
    core_url: String,
    health: HealthStatus,
    runtime: RuntimeToggles,
    runtime_status: RuntimeStatus,
    proxy_count: usize,
    enabled_proxy_count: usize,
    rule_count: usize,
    enabled_rule_count: usize,
    quickbar_count: usize,
    stats: RuntimeStats,
}

struct ApiClient {
    base_url: String,
    token: String,
    http: Client,
    transport: CliTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliTransport {
    Http,
    NamedPipe,
}

impl ApiClient {
    fn new(base_url: String, force_http: bool) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(4))
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: proxyduck_common::load_or_create_token()?,
            http,
            transport: if !force_http && service_installed() {
                CliTransport::NamedPipe
            } else {
                CliTransport::Http
            },
        })
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        if self.transport == CliTransport::NamedPipe {
            return self.decode_ipc(self.ipc_call("GET", path, None)?, path);
        }
        let response = self
            .http
            .get(self.url(path))
            .header(proxyduck_common::AUTH_HEADER, &self.token)
            .send()
            .with_context(|| format!("request failed: GET {path}"))?;
        self.decode(response, path)
    }

    fn post<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        if self.transport == CliTransport::NamedPipe {
            return self.decode_ipc(self.ipc_call("POST", path, Some(body))?, path);
        }
        let response = self
            .http
            .post(self.url(path))
            .header(proxyduck_common::AUTH_HEADER, &self.token)
            .json(&body)
            .send()
            .with_context(|| format!("request failed: POST {path}"))?;
        self.decode(response, path)
    }

    fn put<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        if self.transport == CliTransport::NamedPipe {
            return self.decode_ipc(self.ipc_call("PUT", path, Some(body))?, path);
        }
        let response = self
            .http
            .put(self.url(path))
            .header(proxyduck_common::AUTH_HEADER, &self.token)
            .json(&body)
            .send()
            .with_context(|| format!("request failed: PUT {path}"))?;
        self.decode(response, path)
    }

    fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        if self.transport == CliTransport::NamedPipe {
            return self.decode_ipc(self.ipc_call("DELETE", path, None)?, path);
        }
        let response = self
            .http
            .delete(self.url(path))
            .header(proxyduck_common::AUTH_HEADER, &self.token)
            .send()
            .with_context(|| format!("request failed: DELETE {path}"))?;
        self.decode(response, path)
    }

    fn download(&self, path: &str) -> Result<Vec<u8>> {
        if self.transport == CliTransport::NamedPipe {
            let response = self.ipc_response("POST", path, None)?;
            if !(200..300).contains(&response.status) {
                let message = response
                    .error
                    .map(|error| error.message)
                    .unwrap_or_else(|| format!("request failed with status {}", response.status));
                bail!("{message}");
            }
            let encoded = response
                .binary_base64
                .ok_or_else(|| anyhow!("missing binary response for {path}"))?;
            return base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .context("invalid base64 diagnostic response");
        }
        let response = self
            .http
            .post(self.url(path))
            .header(proxyduck_common::AUTH_HEADER, &self.token)
            .send()
            .with_context(|| format!("request failed: POST {path}"))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .with_context(|| format!("failed to read response body for {path}"))?;
        if status.is_success() {
            return Ok(bytes.to_vec());
        }
        if let Ok(payload) = serde_json::from_slice::<ApiEnvelope<()>>(&bytes) {
            bail!(
                "{}",
                payload
                    .error
                    .unwrap_or_else(|| format!("request failed with status {status}"))
            );
        }
        bail!("request failed with status {status}");
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn ipc_call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let response = self.ipc_response(method, path, body)?;
        if !(200..300).contains(&response.status) {
            let message = response
                .error
                .map(|error| error.message)
                .unwrap_or_else(|| format!("request failed with status {}", response.status));
            bail!("{message}");
        }
        response
            .body
            .ok_or_else(|| anyhow!("missing JSON response body for {path}"))
    }

    fn ipc_response(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<proxyduck_common::ipc::IpcResponse> {
        let mut request = proxyduck_common::ipc::IpcRequest::new(method, path);
        if let Some(body) = body {
            request = request.with_body(body);
        }
        proxyduck_common::ipc::request_named_pipe(request)
            .context("request failed through ProxyDuck Core Named Pipe")
    }

    fn decode_ipc<T: DeserializeOwned>(&self, value: Value, path: &str) -> Result<T> {
        let payload: ApiEnvelope<T> = serde_json::from_value(value)
            .with_context(|| format!("invalid IPC response body for {path}"))?;
        if payload.ok {
            return payload
                .data
                .ok_or_else(|| anyhow!("missing response data for {path}"));
        }
        bail!(
            "{}",
            payload
                .error
                .unwrap_or_else(|| format!("request failed for {path}"))
        )
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

fn service_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        let sc_path = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join("sc.exe");
        std::process::Command::new(sc_path)
            .args(["query", "ProxyDuckCore"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

fn main() -> Result<()> {
    if let Err(error) = proxyduck_common::install_panic_hook("cli") {
        eprintln!("failed to initialize crash logging: {error}");
    }
    let cli = Cli::parse();
    let force_http = cli.core_url != proxyduck_common::DEFAULT_CORE_URL;
    let client = ApiClient::new(cli.core_url.clone(), force_http)?;
    let json_output = cli.json_output();

    match cli.command {
        Command::Status => show_status(&client, json_output),
        Command::Config => show_config(&client),
        Command::Runtime { command } => handle_runtime(&client, command, json_output),
        Command::Mode { command } => handle_mode(&client, command, json_output),
        Command::Proxies { command } => handle_proxies(&client, command, json_output),
        Command::Rules { command } => handle_rules(&client, command, json_output),
        Command::Quickbar { command } => handle_quickbar(&client, command, json_output),
        Command::Profiles { command } => handle_profiles(&client, command, json_output),
        Command::Processes { command } => handle_processes(&client, command, json_output),
        Command::Logs(args) => show_logs(&client, args.tail, json_output),
        Command::Diagnostics { output } => save_diagnostics(&client, output, json_output),
        Command::Network { command } => handle_network(&client, command, json_output),
        Command::Studio { command } => handle_studio(&client, command, json_output),
        Command::Connections { command } => handle_connections(&client, command, json_output),
        Command::Timeline { command } => handle_timeline(&client, command, json_output),
    }
}

fn save_diagnostics(client: &ApiClient, output: Option<PathBuf>, json_output: bool) -> Result<()> {
    let bytes = client.download("/diagnostics/bundle")?;
    let path = output.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(format!(
                "ProxyDuck-Diagnostics-{}.zip",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or_default()
            ))
    });
    fs::write(&path, &bytes)
        .with_context(|| format!("failed to write diagnostics bundle: {}", path.display()))?;
    if json_output {
        return print_json(&json!({ "path": path, "bytes": bytes.len() }));
    }
    println!(
        "Diagnostics bundle written: {} ({} bytes)",
        path.display(),
        bytes.len()
    );
    Ok(())
}

fn handle_network(client: &ApiClient, command: NetworkCommand, json_output: bool) -> Result<()> {
    match command {
        NetworkCommand::Status => {
            let res: Value = client.get("/network/status")?;
            if json_output {
                return print_json(&res);
            }
            println!("Network Status:");
            if let Some(adapters) = res
                .pointer("/adapters/activeAdapters")
                .and_then(Value::as_array)
            {
                println!("  Adapters ({}):", adapters.len());
                for a in adapters {
                    let name = a.get("name").and_then(Value::as_str).unwrap_or("unknown");
                    let status = a.get("status").and_then(Value::as_str).unwrap_or("unknown");
                    let ipv4 = a
                        .get("ipv4Addresses")
                        .and_then(Value::as_array)
                        .and_then(|values| values.first())
                        .and_then(Value::as_str)
                        .unwrap_or("none");
                    println!("    - {name}: {status} ({ipv4})");
                }
            }
            if let Some(gateway) = res.pointer("/gateway/target").and_then(Value::as_str) {
                let reachable = res
                    .pointer("/gateway/reachable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                println!("  Gateway: {gateway} (reachable={reachable})");
            }
            if let Some(dns) = res
                .pointer("/dns/configuredServers")
                .and_then(Value::as_array)
            {
                let dns_servers: Vec<&str> = dns.iter().filter_map(Value::as_str).collect();
                println!("  DNS Servers: {}", dns_servers.join(", "));
            }
            if let Some(proxy) = res.get("proxy") {
                let enabled = proxy
                    .get("wininetEnabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let server = proxy
                    .get("wininetServer")
                    .and_then(Value::as_str)
                    .unwrap_or("none");
                println!("  System Proxy: {} ({server})", yes_no(enabled));
            }
            Ok(())
        }
        NetworkCommand::Diagnose => {
            println!("Running 10-layer network diagnosis...");
            let res: Value = client.post("/network/diagnose", json!({}))?;
            if json_output {
                return print_json(&res);
            }
            let status = res
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            println!("Diagnostic Status: {status}");
            if let Some(issues) = res.get("issues").and_then(Value::as_array) {
                if issues.is_empty() {
                    println!("\nNo network issues detected.");
                } else {
                    println!("\nDetected Issues ({}):", issues.len());
                    for issue in issues {
                        let sev = issue
                            .get("severity")
                            .and_then(Value::as_str)
                            .unwrap_or("info");
                        let title = issue.get("title").and_then(Value::as_str).unwrap_or("");
                        let explanation = issue
                            .get("explanation")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        println!("  - [{sev}] {title}");
                        println!("    {explanation}");
                    }
                }
            }
            Ok(())
        }
        NetworkCommand::History => {
            let res: Value = client.get("/network/history")?;
            if json_output {
                return print_json(&res);
            }
            if let Some(records) = res.as_array() {
                println!("Network Diagnostic History ({} events):", records.len());
                for r in records {
                    let ts = r.get("timestamp").and_then(Value::as_str).unwrap_or("");
                    let status = r.get("status").and_then(Value::as_str).unwrap_or("");
                    let issues_cnt = r.get("issuesCount").and_then(Value::as_u64).unwrap_or(0);
                    println!("  [{ts}] Status: {status} | Issues: {issues_cnt}");
                }
            }
            Ok(())
        }
        NetworkCommand::Repair(args) => {
            if !args.auto_snapshot {
                bail!("network repairs require a recovery snapshot; --auto-snapshot=false is not supported");
            }
            let plan: Value = client.post("/network/repair/plan", json!({}))?;
            let plan_id = plan
                .get("planId")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("repair plan did not include planId"))?;
            let recommended = plan
                .get("recommendedActions")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("repair plan did not include recommendedActions"))?;
            let actions = recommended
                .iter()
                .filter_map(|action| action.get("id").and_then(Value::as_str))
                .filter(|id| {
                    args.action
                        .as_deref()
                        .is_none_or(|requested| requested == *id)
                })
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if actions.is_empty() {
                bail!("the repair plan contains no matching actions");
            }
            println!("Executing validated repair plan {plan_id} with snapshot...");
            let body = json!({
                "planId": plan_id,
                "actions": actions,
            });
            let res: Value = client.post("/network/repair/run", body)?;
            if json_output {
                return print_json(&res);
            }
            let success = res
                .get("allSucceeded")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            println!("Repair finished: success={success}");
            if let Some(actions) = res.get("executedActions").and_then(Value::as_array) {
                for act in actions {
                    println!(
                        "  - {}: {}",
                        act.get("actionId")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                        if act.get("success").and_then(Value::as_bool).unwrap_or(false) {
                            "ok"
                        } else {
                            "failed"
                        }
                    );
                }
            }
            Ok(())
        }
        NetworkCommand::Snapshot(args) => {
            let body = json!({ "reason": args.label });
            let res: Value = client.post("/network/snapshot", body)?;
            if json_output {
                return print_json(&res);
            }
            let id = res.get("id").and_then(Value::as_str).unwrap_or("unknown");
            println!("Network snapshot created: {id}");
            Ok(())
        }
        NetworkCommand::Snapshots => {
            let res: Value = client.get("/network/snapshots")?;
            if json_output {
                return print_json(&res);
            }
            if let Some(snapshots) = res.as_array() {
                println!("Network Snapshots ({}):", snapshots.len());
                for s in snapshots {
                    let id = s.get("id").and_then(Value::as_str).unwrap_or("");
                    let label = s.get("reason").and_then(Value::as_str).unwrap_or("");
                    let created = s.get("createdAt").and_then(Value::as_str).unwrap_or("");
                    println!("  [{id}] {label} ({created})");
                }
            }
            Ok(())
        }
        NetworkCommand::Restore { id } => {
            println!("Restoring network snapshot {id}...");
            let body = json!({ "snapshotId": id });
            let res: Value = client.post("/network/restore", body)?;
            if json_output {
                return print_json(&res);
            }
            let success = res.get("success").and_then(Value::as_bool).unwrap_or(false);
            let message = res.get("message").and_then(Value::as_str).unwrap_or("");
            println!("Restore completed: success={} | {message}", success);
            Ok(())
        }
    }
}

fn handle_studio(client: &ApiClient, command: StudioCommand, json_output: bool) -> Result<()> {
    match command {
        StudioCommand::Discover => {
            println!("Discovering client configurations...");
            let res: Value = client.post("/configs/discover", json!({}))?;
            if json_output {
                return print_json(&res);
            }
            if let Some(list) = res.as_array() {
                println!("Discovered configs ({}):", list.len());
                for item in list {
                    let path = item.get("path").and_then(Value::as_str).unwrap_or("");
                    let kind = item
                        .get("kind")
                        .or_else(|| item.get("format"))
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let client_name = item
                        .get("client")
                        .and_then(Value::as_str)
                        .unwrap_or("generic");
                    println!("  [{client_name} - {kind}] {path}");
                }
            }
            Ok(())
        }
        StudioCommand::List => {
            let res: Value = client.get("/configs")?;
            if json_output {
                return print_json(&res);
            }
            if let Some(list) = res.as_array() {
                println!("Configs ({}):", list.len());
                for item in list {
                    let path = item.get("path").and_then(Value::as_str).unwrap_or("");
                    let kind = item
                        .get("format")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    println!("  [{kind}] {path}");
                }
            }
            Ok(())
        }
        StudioCommand::Inspect { path } => {
            let res: Value = client.post("/configs/inspect", json!({ "path": path }))?;
            if json_output {
                return print_json(&res);
            }
            println!("Config Document [{path}]");
            if let Some(format) = res.get("format").and_then(Value::as_str) {
                println!("  Format: {format}");
            }
            if let Some(sha) = res.get("sha256").and_then(Value::as_str) {
                println!("  SHA256: {sha}");
            }
            if let Some(semantic) = res.get("semantic") {
                println!("  Semantic: {}", serde_json::to_string_pretty(semantic)?);
            }
            Ok(())
        }
        StudioCommand::Validate { path } => {
            let doc: Value = client.post("/configs/inspect", json!({ "path": path }))?;
            let res: Value = client.post(
                "/configs/validate",
                json!({
                    "content": doc.get("rawContent").and_then(Value::as_str).unwrap_or_default(),
                    "format": doc.get("format").cloned().unwrap_or(Value::Null)
                }),
            )?;
            if json_output {
                return print_json(&res);
            }
            let valid = res.get("valid").and_then(Value::as_bool).unwrap_or(false);
            println!(
                "Validation for {path}: {}",
                if valid { "PASSED" } else { "FAILED" }
            );
            if let Some(errors) = res.get("errors").and_then(Value::as_array) {
                for err in errors {
                    let msg = err.as_str().unwrap_or("");
                    println!("  - ERROR: {msg}");
                }
            }
            if let Some(conflicts) = res.get("portConflicts").and_then(Value::as_array) {
                for c in conflicts {
                    let port = c.get("port").and_then(Value::as_u64).unwrap_or(0);
                    let message = c.get("message").and_then(Value::as_str).unwrap_or("in use");
                    if c.get("inUse").and_then(Value::as_bool).unwrap_or(false) {
                        println!("  - PORT CONFLICT: Port {port}: {message}");
                    }
                }
            }
            Ok(())
        }
        StudioCommand::Diff { path, key, value } => {
            let doc: Value = client.post("/configs/inspect", json!({ "path": path }))?;
            let patches = json!([{ "key": key, "oldValue": "", "newValue": value }]);
            let res: Value = client.post(
                "/configs/patch",
                json!({
                    "content": doc.get("rawContent").and_then(Value::as_str).unwrap_or_default(),
                    "patches": patches
                }),
            )?;
            if json_output {
                return print_json(&res);
            }
            if let Some(diff) = res.get("diff").and_then(Value::as_str) {
                println!("AST Diff for {path}:\n{diff}");
            } else {
                println!("No diff produced.");
            }
            Ok(())
        }
    }
}

fn show_status(client: &ApiClient, json_output: bool) -> Result<()> {
    let snapshot: LiveSnapshot = client.get("/snapshot")?;
    let config: AppConfig = client.get("/config")?;

    let report = StatusReport {
        core_url: client.base_url.clone(),
        health: snapshot.health,
        runtime: config.runtime,
        runtime_status: snapshot.runtime_status,
        proxy_count: config.proxies.len(),
        enabled_proxy_count: config.proxies.iter().filter(|proxy| proxy.enabled).count(),
        rule_count: config.rules.len(),
        enabled_rule_count: config.rules.iter().filter(|rule| rule.enabled).count(),
        quickbar_count: config.quick_bar.len(),
        stats: snapshot.stats,
    };

    if json_output {
        return print_json(&report);
    }

    println!("ProxyDuck");
    println!("  Core URL: {}", report.core_url);
    println!("  Version: {}", report.health.version);
    println!("  Status: {}", report.health.status);
    println!("  Engine Mode: {}", report.stats.engine_mode);
    println!("  Runtime Enabled: {}", yes_no(report.runtime.enabled));
    println!("  Data Plane: {}", report.runtime_status.data_plane.phase);
    println!(
        "  Backend: {}",
        report.runtime_status.data_plane.backend_name
    );
    println!(
        "  Leak Protection: {} (fail closed: {})",
        report.runtime.leak_protection_mode,
        yes_no(report.runtime_status.data_plane.fail_closed_active)
    );
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
    // Keep this command lossless as the control-plane schema evolves.  The
    // summary structs used by `status` intentionally cover only fields needed
    // for human-readable output; deserializing those here would silently drop
    // schema-4 policy fields from the JSON shown to operators.
    let config: Value = client.get("/config")?;
    print_json(&config)
}

fn handle_runtime(client: &ApiClient, command: RuntimeCommand, json_output: bool) -> Result<()> {
    match command {
        RuntimeCommand::Status => {
            let config: AppConfig = client.get("/config")?;
            let status: RuntimeStatus = client.get("/runtime/status")?;
            if json_output {
                return print_json(&json!({ "settings": config.runtime, "status": status }));
            }

            println!("Runtime");
            println!("  Enabled: {}", yes_no(config.runtime.enabled));
            println!("  DNS Enforced: {}", yes_no(config.runtime.dns_enforced));
            println!("  IPv6 Blocked: {}", yes_no(config.runtime.ipv6_blocked));
            println!("  DoH Blocked: {}", yes_no(config.runtime.doh_blocked));
            println!("  Log Level: {}", config.runtime.log_level);
            println!("  Leak Protection: {}", config.runtime.leak_protection_mode);
            println!("  Data Plane: {}", status.data_plane.phase);
            println!("  Backend: {}", status.data_plane.backend_name);
            println!("  Active Rules: {}", status.data_plane.active_rules);
            println!("  Firewall Rules: {}", status.data_plane.firewall_rules);
            println!(
                "  Fail Closed: {}",
                yes_no(status.data_plane.fail_closed_active)
            );
            if let Some(reachable) = status.data_plane.proxy_endpoint_reachable {
                println!("  Proxy Reachable: {}", yes_no(reachable));
            }
            if let Some(message) = status.data_plane.message.as_deref() {
                println!("  Message: {message}");
            }
            if let Some(fingerprint) = status.active_plan_fingerprint.as_deref() {
                println!("  Plan Fingerprint: {fingerprint}");
            }
            if !status.required_proxy_ids.is_empty() {
                println!(
                    "  Required Proxies: {}",
                    status.required_proxy_ids.join(", ")
                );
            }
            for reason in &status.degraded_reasons {
                println!("  Degraded Reason: {reason}");
            }
            for diagnostic in &status.compile_diagnostics {
                let code = diagnostic
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("diagnostic");
                let severity = diagnostic
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let message = diagnostic
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("compiler diagnostic");
                println!("  Compile Diagnostic [{severity}] {code}: {message}");
            }
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
                "{:<36}  {:<24}  {:<10}  {:<22}  ENABLED",
                "ID", "NAME", "KIND", "ENDPOINT"
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
                "clearPassword": args.clear_password,
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
        ProxyCommand::Import { file, apply } => {
            let raw = fs::read_to_string(&file)
                .with_context(|| format!("failed to read proxy import file: {}", file.display()))?;
            let source: Value = serde_json::from_str(&raw).with_context(|| {
                format!("failed to parse proxy import file: {}", file.display())
            })?;
            let preview: Value = client.post("/proxies/import/preview", source.clone())?;
            let valid = preview
                .get("valid")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !apply {
                if json_output {
                    return print_json(&preview);
                }
                print_proxy_import_preview(&preview);
                println!("Preview only. Re-run with --apply to commit this merge.");
                return Ok(());
            }
            if !valid {
                let message = preview
                    .get("validationError")
                    .and_then(Value::as_str)
                    .unwrap_or("proxy import preview is not valid");
                bail!("{message}");
            }
            let applied: Value = client.post("/proxies/import", source)?;
            if json_output {
                return print_json(&json!({ "preview": preview, "applied": applied }));
            }
            println!(
                "Imported {}: added {}, updated {}, skipped {}.",
                applied
                    .get("format")
                    .and_then(Value::as_str)
                    .unwrap_or("proxy file"),
                applied.get("added").and_then(Value::as_u64).unwrap_or(0),
                applied.get("updated").and_then(Value::as_u64).unwrap_or(0),
                applied.get("skipped").and_then(Value::as_u64).unwrap_or(0),
            );
            Ok(())
        }
        ProxyCommand::Discover { own_port, auto_add } => {
            let body = json!({ "ownPort": own_port });
            let discovered: Vec<Value> = client.post("/endpoints/discover", body)?;
            if json_output {
                return print_json(&discovered);
            }
            if discovered.is_empty() {
                println!("No local proxy endpoints discovered.");
                return Ok(());
            }
            println!(
                "{:<20}  {:<8}  {:<10}  {:<20}  {:<8}  STATUS",
                "ENDPOINT", "KIND", "LATENCY", "PROCESS", "AUTH"
            );
            for ep in &discovered {
                let endpoint = ep["endpoint"].as_str().unwrap_or("-");
                let kind = ep["kind"].as_str().unwrap_or("-");
                let latency = format!("{}ms", ep["latencyMs"].as_u64().unwrap_or(0));
                let proc_name = ep["processName"].as_str().unwrap_or("-");
                let auth = if ep["authRequired"].as_bool().unwrap_or(false) {
                    "Yes"
                } else {
                    "No"
                };
                let status = if ep["alreadyConfigured"].as_bool().unwrap_or(false) {
                    "Configured"
                } else {
                    "New"
                };
                println!(
                    "{:<20}  {:<8}  {:<10}  {:<20}  {:<8}  {}",
                    endpoint,
                    kind,
                    latency,
                    truncate(proc_name, 20),
                    auth,
                    status
                );

                if auto_add && !ep["alreadyConfigured"].as_bool().unwrap_or(false) {
                    let add_body = json!({
                        "endpoint": endpoint,
                        "name": format!("Auto Discovered {}", endpoint),
                        "kind": kind
                    });
                    let res: Result<Value> = client.post("/endpoints/discover/add", add_body);
                    match res {
                        Ok(_) => println!("  -> Added {} to proxy profiles.", endpoint),
                        Err(e) => println!("  -> Failed to add {}: {}", endpoint, e),
                    }
                }
            }
            Ok(())
        }
    }
}

fn handle_connections(
    client: &ApiClient,
    command: Option<ConnectionCommand>,
    json_output: bool,
) -> Result<()> {
    match command.unwrap_or_else(|| ConnectionCommand::List(ConnectionListArgs::default())) {
        ConnectionCommand::List(args) => {
            let mut query_params = Vec::new();
            if let Some(pid) = args.pid {
                query_params.push(format!("pid={pid}"));
            }
            if let Some(ref proc) = args.process {
                query_params.push(format!("processName={proc}"));
            }
            if let Some(ref st) = args.status {
                query_params.push(format!("status={st}"));
            }
            if let Some(ref q) = args.search {
                query_params.push(format!("search={q}"));
            }
            if let Some(lim) = args.limit {
                query_params.push(format!("limit={lim}"));
            }
            let query_str = if query_params.is_empty() {
                String::new()
            } else {
                format!("?{}", query_params.join("&"))
            };
            let connections: Vec<Value> = client.get(&format!("/connections{query_str}"))?;
            if json_output {
                return print_json(&connections);
            }
            if connections.is_empty() {
                println!("No active connections tracked.");
                return Ok(());
            }
            println!(
                "{:<8}  {:<18}  {:<5}  {:<22}  {:<22}  {:<12}  ACTION",
                "PID", "PROCESS", "PROTO", "LOCAL ADDR", "REMOTE ADDR", "STATUS"
            );
            for conn in connections {
                let pid = conn["pid"].as_u64().unwrap_or(0);
                let proc_name = conn["processName"].as_str().unwrap_or("-");
                let proto = conn["protocol"].as_str().unwrap_or("-");
                let local = format!(
                    "{}:{}",
                    conn["localAddr"].as_str().unwrap_or(""),
                    conn["localPort"].as_u64().unwrap_or(0)
                );
                let remote = format!(
                    "{}:{}",
                    conn["remoteAddr"].as_str().unwrap_or(""),
                    conn["remotePort"].as_u64().unwrap_or(0)
                );
                let status = conn["status"].as_str().unwrap_or("-");
                let action = conn["actionTarget"].as_str().unwrap_or("-");
                println!(
                    "{:<8}  {:<18}  {:<5}  {:<22}  {:<22}  {:<12}  {}",
                    pid,
                    truncate(proc_name, 18),
                    proto,
                    truncate(&local, 22),
                    truncate(&remote, 22),
                    status,
                    action
                );
            }
            Ok(())
        }
        ConnectionCommand::Summary => {
            let summary: Value = client.get("/connections/summary")?;
            if json_output {
                return print_json(&summary);
            }
            println!("Traffic & Connection Summary:");
            println!("  Total Connections: {}", summary["totalConnections"]);
            println!("  Established: {}", summary["establishedConnections"]);
            println!("  Listening Ports: {}", summary["listeningPorts"]);
            if let Some(top) = summary["topProcesses"].as_array() {
                println!("\nTop Processes by Traffic:");
                for p in top {
                    println!(
                        "  {:<20} {} active / {} total",
                        p["processName"].as_str().unwrap_or("-"),
                        p["activeConnections"],
                        p["totalConnections"]
                    );
                }
            }
            Ok(())
        }
    }
}

fn handle_timeline(
    client: &ApiClient,
    command: Option<TimelineCommand>,
    json_output: bool,
) -> Result<()> {
    match command.unwrap_or_else(|| TimelineCommand::List(TimelineListArgs::default())) {
        TimelineCommand::List(args) => {
            let mut query_params = Vec::new();
            if let Some(ref cat) = args.category {
                query_params.push(format!("category={cat}"));
            }
            if let Some(ref sev) = args.severity {
                query_params.push(format!("severity={sev}"));
            }
            if let Some(ref src) = args.source {
                query_params.push(format!("source={src}"));
            }
            if let Some(ref q) = args.search {
                query_params.push(format!("search={q}"));
            }
            query_params.push(format!("limit={}", args.limit));
            let query_str = format!("?{}", query_params.join("&"));
            let events: Vec<Value> = client.get(&format!("/timeline{query_str}"))?;
            if json_output {
                return print_json(&events);
            }
            if events.is_empty() {
                println!("No network events in timeline.");
                return Ok(());
            }
            println!(
                "{:<20}  {:<10}  {:<8}  {:<16}  TITLE / DETAILS",
                "TIMESTAMP", "CATEGORY", "SEVERITY", "SOURCE"
            );
            for ev in events {
                let ts = ev["timestamp"].as_str().unwrap_or("-");
                let cat = ev["category"].as_str().unwrap_or("-");
                let sev = ev["severity"].as_str().unwrap_or("-");
                let src = ev["source"].as_str().unwrap_or("-");
                let title = ev["title"].as_str().unwrap_or("-");
                let details = ev["details"].as_str().unwrap_or("");
                println!(
                    "{:<20}  {:<10}  {:<8}  {:<16}  {} ({})",
                    truncate(ts, 20),
                    cat,
                    sev,
                    truncate(src, 16),
                    title,
                    details
                );
            }
            Ok(())
        }
        TimelineCommand::Clear => {
            let _: Value = client.post("/timeline/clear", json!({}))?;
            if json_output {
                return print_json(&json!({ "cleared": true }));
            }
            println!("Timeline events cleared.");
            Ok(())
        }
    }
}

fn print_proxy_import_preview(preview: &Value) {
    println!(
        "Proxy import preview ({}) — added {}, updated {}, skipped {}.",
        preview
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("unknown format"),
        preview.get("added").and_then(Value::as_u64).unwrap_or(0),
        preview.get("updated").and_then(Value::as_u64).unwrap_or(0),
        preview.get("skipped").and_then(Value::as_u64).unwrap_or(0),
    );
    if let Some(items) = preview.get("items").and_then(Value::as_array) {
        for item in items {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unnamed");
            let endpoint = item.get("endpoint").and_then(Value::as_str).unwrap_or("—");
            let enabled = item
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let warnings = item
                .get("warnings")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_default();
            println!(
                "  {} {} {}{}",
                if enabled { "[enabled]" } else { "[disabled]" },
                name,
                endpoint,
                if warnings.is_empty() {
                    String::new()
                } else {
                    format!(" — {warnings}")
                }
            );
        }
    }
    if let Some(items) = preview.get("skippedItems").and_then(Value::as_array) {
        for item in items.iter().filter_map(Value::as_str) {
            println!("  [skipped] {item}");
        }
    }
}

fn handle_rules(client: &ApiClient, command: RuleCommand, json_output: bool) -> Result<()> {
    match command {
        RuleCommand::List => {
            if json_output {
                let rules: Value = client.get("/rules")?;
                return print_json(&rules);
            }
            let rules: Vec<Rule> = client.get("/rules")?;

            if rules.is_empty() {
                println!("No rules.");
                return Ok(());
            }

            println!(
                "{:<36}  {:<24}  {:<10}  {:<10}  {:<16}  MATCHER",
                "ID", "NAME", "SOURCE", "ENABLED", "PROXY"
            );
            for rule in rules {
                println!(
                    "{:<36}  {:<24}  {:<10}  {:<10}  {:<16}  {}",
                    rule.id,
                    truncate(&rule.name, 24),
                    truncate(&rule.source, 10),
                    yes_no(rule.enabled),
                    truncate(&rule_route_target(&rule), 16),
                    truncate(&matcher_summary(&rule.matcher), 64)
                );
            }
            Ok(())
        }
        RuleCommand::Add(args) => {
            let matcher = build_rule_matcher(&args)?;
            let proxy_id = if matches!(args.action, RuleActionArg::Proxy) {
                let target = args
                    .proxy
                    .as_deref()
                    .ok_or_else(|| anyhow!("--proxy is required for --action proxy"))?;
                let proxies: Vec<ProxyProfile> = client.get("/proxies")?;
                Some(resolve_proxy_target(&proxies, target)?.id.clone())
            } else {
                args.proxy.as_deref().map(str::to_string)
            };
            let body = json!({
                "name": trimmed_non_empty(&args.name, "rule name")?,
                "proxyProfile": proxy_id.clone().unwrap_or_default(),
                "action": args.action.api_value(proxy_id.as_deref()),
                "matcher": matcher,
                "protocols": if args.protocols.is_empty() {
                    None::<Vec<String>>
                } else {
                    Some(args.protocols.iter().copied().map(ProtocolArg::api_value).map(str::to_string).collect::<Vec<_>>())
                },
                "priority": args.priority,
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
        RuleCommand::Compile => {
            let plan: Value = client.post("/rules/compile", json!({}))?;
            if json_output {
                return print_json(&plan);
            }

            let fingerprint = plan
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("—");
            let routes = plan
                .get("proxyRoutes")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            let diagnostics = plan
                .get("diagnostics")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            println!("Routing plan compiled");
            println!("  Fingerprint: {fingerprint}");
            println!("  Proxy routes: {routes}");
            println!("  Diagnostics: {diagnostics}");
            Ok(())
        }
        RuleCommand::EffectivePlan { target } => {
            let rules: Vec<Rule> = client.get("/rules")?;
            let rule = resolve_rule_target(&rules, &target)?;
            let plan: Value = client.get(&format!("/rules/{}/effective-plan", rule.id))?;
            if json_output {
                return print_json(&plan);
            }

            println!("Effective plan: {} ({})", rule.name, rule.id);
            println!(
                "  Engine: {}",
                plan.get("engine").and_then(Value::as_str).unwrap_or("—")
            );
            println!(
                "  Route: {}",
                if plan.get("route").is_some_and(|value| !value.is_null()) {
                    "proxy"
                } else if plan.get("blocked").is_some_and(|value| !value.is_null()) {
                    "blocked"
                } else if plan.get("direct").and_then(Value::as_bool).unwrap_or(false) {
                    "direct"
                } else {
                    "not compiled"
                }
            );
            if let Some(diagnostics) = plan.get("diagnostics").and_then(Value::as_array) {
                for diagnostic in diagnostics {
                    if let Some(message) = diagnostic.get("message").and_then(Value::as_str) {
                        let code = diagnostic
                            .get("code")
                            .and_then(Value::as_str)
                            .unwrap_or("diagnostic");
                        println!("  Diagnostic [{code}]: {message}");
                    }
                }
            }
            Ok(())
        }
        RuleCommand::Analyze => {
            let report: Value = client.get("/rules/analyze")?;
            if json_output {
                return print_json(&report);
            }

            let total = report
                .get("totalRules")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let active = report
                .get("activeRules")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let healthy = report
                .get("healthy")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let issues = report.get("issues").and_then(Value::as_array);

            println!("Policy Analysis Report:");
            println!("  Rules: {total} total / {active} active");
            println!(
                "  Status: {}",
                if healthy {
                    "Healthy (规则无冲突/无死规则)"
                } else {
                    "Issues Detected (发现异常或冲突)"
                }
            );

            if let Some(issues) = issues {
                if issues.is_empty() {
                    println!("  No issues detected.");
                } else {
                    println!("  Issues ({}):", issues.len());
                    for issue in issues {
                        let severity = issue
                            .get("severity")
                            .and_then(Value::as_str)
                            .unwrap_or("info");
                        let kind = issue.get("kind").and_then(Value::as_str).unwrap_or("issue");
                        let message = issue.get("message").and_then(Value::as_str).unwrap_or("");
                        let remediation = issue
                            .get("remediation")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        println!("    [{severity}][{kind}] {message}");
                        if !remediation.is_empty() {
                            println!("      -> 解决建议: {remediation}");
                        }
                    }
                }
            }
            Ok(())
        }
        RuleCommand::Simulate(args) => {
            let payload = json!({
                "processName": args.process_name,
                "exePath": args.exe_path,
                "pid": args.pid,
                "parentProcess": args.parent_process,
                "protocol": args.protocol,
                "domain": args.domain,
                "ip": args.ip,
                "port": args.port,
            });

            let res: Value = client.post("/rules/simulate", payload)?;
            if json_output {
                return print_json(&res);
            }

            println!("Policy Simulation Result:");
            if let Some(sim) = res.get("policySimulation") {
                let summary = sim
                    .get("routeTrace")
                    .and_then(|t| t.get("summary"))
                    .and_then(Value::as_str)
                    .unwrap_or("—");
                let effective_target = sim
                    .get("effectiveTarget")
                    .and_then(Value::as_str)
                    .unwrap_or("—");

                println!("  Final Decision: {summary}");
                println!("  Effective Target: {effective_target}");

                if let Some(trace) = sim
                    .get("routeTrace")
                    .and_then(|t| t.get("steps"))
                    .and_then(Value::as_array)
                {
                    println!("\n  Route Trace (决策链追溯):");
                    for (i, step) in trace.iter().enumerate() {
                        let title = step.get("title").and_then(Value::as_str).unwrap_or("");
                        let detail = step.get("detail").and_then(Value::as_str).unwrap_or("");
                        println!("    {}. {title}: {detail}", i + 1);
                    }
                }

                if let Some(evals) = sim.get("evaluations").and_then(Value::as_array) {
                    println!("\n  Rule Evaluations (规则评估详情):");
                    for eval in evals {
                        let name = eval.get("ruleName").and_then(Value::as_str).unwrap_or("—");
                        let priority = eval.get("priority").and_then(Value::as_i64).unwrap_or(0);
                        let status = eval.get("status").and_then(Value::as_str).unwrap_or("—");
                        let selected = eval
                            .get("selected")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let miss = eval.get("missReason").and_then(Value::as_str).unwrap_or("");

                        let mark = if selected { " [SELECTED WINNER]" } else { "" };
                        println!("    - [{status}]{mark} {name} (Priority {priority})");
                        if !miss.is_empty() {
                            println!("      原因: {miss}");
                        }
                    }
                }

                if let Some(explain_miss) = sim.get("explainMiss").and_then(Value::as_str) {
                    println!("\n  Explain Miss (未命中原因诊断):\n    {explain_miss}");
                }
            } else {
                let direct = res.get("direct").and_then(Value::as_bool).unwrap_or(false);
                let matched = res
                    .get("destinationMatched")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                println!("  Destination Matched: {matched}");
                println!("  Direct: {direct}");
            }
            Ok(())
        }
    }
}

fn handle_profiles(client: &ApiClient, command: ProfileCommand, json_output: bool) -> Result<()> {
    match command {
        ProfileCommand::List => {
            let profiles: Vec<Value> = client.get("/profiles")?;
            if json_output {
                return print_json(&profiles);
            }
            if profiles.is_empty() {
                println!("No profiles.");
                return Ok(());
            }
            println!(
                "{:<36}  {:<24}  {:<10}  DESCRIPTION",
                "ID", "NAME", "ACTIVE"
            );
            let config: Value = client.get("/config")?;
            let active = config
                .get("activeProfileId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            for profile in profiles {
                let id = profile.get("id").and_then(Value::as_str).unwrap_or("—");
                let name = profile.get("name").and_then(Value::as_str).unwrap_or("—");
                let description = profile
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                println!(
                    "{:<36}  {:<24}  {:<10}  {}",
                    truncate(id, 36),
                    truncate(name, 24),
                    yes_no(id == active),
                    truncate(description, 60)
                );
            }
            Ok(())
        }
        ProfileCommand::Create(args) => {
            let name = trimmed_non_empty(&args.name, "profile name")?;
            let profile: Value = client.post(
                "/profiles",
                json!({ "name": name, "description": args.description.trim() }),
            )?;
            if json_output {
                return print_json(&profile);
            }
            println!(
                "Profile created: {} ({})",
                profile.get("name").and_then(Value::as_str).unwrap_or("—"),
                profile.get("id").and_then(Value::as_str).unwrap_or("—")
            );
            Ok(())
        }
        ProfileCommand::Clone { target, name } => {
            let profiles: Vec<Value> = client.get("/profiles")?;
            let profile = resolve_profile_value(&profiles, &target)?;
            let id = profile
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("profile has no id"))?;
            let cloned: Value =
                client.post(&format!("/profiles/{id}/clone"), json!({ "name": name }))?;
            if json_output {
                return print_json(&cloned);
            }
            println!(
                "Profile cloned: {} ({})",
                cloned.get("name").and_then(Value::as_str).unwrap_or("—"),
                cloned.get("id").and_then(Value::as_str).unwrap_or("—")
            );
            Ok(())
        }
        ProfileCommand::Activate { target } => {
            let profiles: Vec<Value> = client.get("/profiles")?;
            let profile = resolve_profile_value(&profiles, &target)?;
            let id = profile
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("profile has no id"))?;
            let activated: Value = client.post(&format!("/profiles/{id}/activate"), json!({}))?;
            if json_output {
                return print_json(&activated);
            }
            println!(
                "Profile activated: {}",
                activated.get("name").and_then(Value::as_str).unwrap_or(id)
            );
            Ok(())
        }
        ProfileCommand::Diff { target } => {
            let profiles: Vec<Value> = client.get("/profiles")?;
            let profile = resolve_profile_value(&profiles, &target)?;
            let id = profile
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("profile has no id"))?;
            let diff: Value = client.get(&format!("/profiles/{id}/diff"))?;
            if json_output {
                return print_json(&diff);
            }
            let changed = diff
                .get("changedSections")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            println!(
                "Profile diff: {}",
                diff.get("profileName")
                    .and_then(Value::as_str)
                    .unwrap_or(id)
            );
            println!(
                "  Changed: {}",
                if changed.is_empty() { "none" } else { &changed }
            );
            println!(
                "  Active: {}",
                yes_no(diff.get("active").and_then(Value::as_bool).unwrap_or(false))
            );
            Ok(())
        }
        ProfileCommand::Remove { target } => {
            let profiles: Vec<Value> = client.get("/profiles")?;
            let profile = resolve_profile_value(&profiles, &target)?;
            let id = profile
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("profile has no id"))?;
            let _: String = client.delete(&format!("/profiles/{id}"))?;
            if json_output {
                return print_json(&json!({ "id": id, "status": "deleted" }));
            }
            println!("Profile removed: {id}");
            Ok(())
        }
    }
}

fn resolve_profile_value<'a>(items: &'a [Value], target: &str) -> Result<&'a Value> {
    if let Some(profile) = items
        .iter()
        .find(|profile| profile.get("id").and_then(Value::as_str) == Some(target))
    {
        return Ok(profile);
    }
    let matches = items
        .iter()
        .filter(|profile| {
            profile
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(target))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [profile] => Ok(profile),
        [] => bail!("no profile matched '{target}'"),
        _ => bail!("multiple profiles matched '{target}'; use the profile id"),
    }
}

fn handle_quickbar(client: &ApiClient, command: QuickBarCommand, json_output: bool) -> Result<()> {
    match command {
        QuickBarCommand::List => {
            if json_output {
                let items: Value = client.get("/quickbar")?;
                return print_json(&items);
            }
            let items: Vec<QuickBarItem> = client.get("/quickbar")?;

            if items.is_empty() {
                println!("No quick bar items.");
                return Ok(());
            }

            println!(
                "{:<36}  {:<24}  {:<18}  {:<16}  EXE",
                "ID", "NAME", "MODE", "PROXY"
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

            println!("{:<8}  {:<14}  {:<28}  EXE", "PID", "START", "NAME");
            for proc_info in processes {
                println!(
                    "{:<8}  {:<14}  {:<28}  {}",
                    proc_info.pid,
                    proc_info
                        .creation_time
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
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
    if args.pids.len() > 1 {
        bail!(
            "--pid accepts one PID per rule; create separate rules for separate process instances"
        );
    }
    if !args.pids.is_empty() && args.pid_creation_time.is_none() {
        bail!(
            "--pid requires --pid-creation-time (use `proxyduck processes list --json` to read creationTime)"
        );
    }

    Ok(json!({
        "appNames": app_names,
        "exePaths": exe_paths,
        "pids": args.pids.clone(),
        "pidCreationTime": args.pid_creation_time,
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
        let suffix = matcher
            .pid_creation_time
            .map(|creation_time| format!("@{creation_time}"))
            .unwrap_or_else(|| "@unknown".to_string());
        parts.push(format!("pids={pids}{suffix}"));
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

fn rule_route_target(rule: &Rule) -> String {
    rule.action
        .as_ref()
        .and_then(|action| action.get("type").and_then(Value::as_str))
        .map(|kind| match kind {
            "direct" => "direct".to_string(),
            "block" => "block".to_string(),
            "reject" => "reject".to_string(),
            _ => rule.proxy_profile.clone(),
        })
        .unwrap_or_else(|| rule.proxy_profile.clone())
}

fn default_rule_source() -> String {
    "user".to_string()
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
            pid_creation_time: Some(1234),
            wildcard: Some("node".to_string()),
        };

        assert_eq!(
            matcher_summary(&matcher),
            "apps=node.exe paths=C:\\node.exe pids=42@1234 wildcard=node"
        );
    }

    #[test]
    fn proxy_import_defaults_to_preview_and_requires_apply_flag_to_write() {
        let cli =
            Cli::try_parse_from(["proxyduck-cli", "proxies", "import", "clash.json"]).unwrap();
        let Command::Proxies {
            command: ProxyCommand::Import { file, apply: false },
        } = cli.command
        else {
            panic!("expected proxy import preview command");
        };
        assert_eq!(file, PathBuf::from("clash.json"));
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
            action: RuleActionArg::Proxy,
            proxy: Some("clash-socks".to_string()),
            priority: None,
            app_names: Vec::new(),
            exe_paths: Vec::new(),
            pids: Vec::new(),
            pid_creation_time: None,
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
    fn rule_action_payload_keeps_non_proxy_actions_without_a_profile() {
        assert_eq!(RuleActionArg::Direct.api_value(None)["type"], "direct");
        assert_eq!(RuleActionArg::Block.api_value(None)["type"], "block");
        assert_eq!(
            RuleActionArg::Proxy.api_value(Some("proxy-1"))["proxyId"],
            "proxy-1"
        );
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
                password_ref: None,
                password: None,
                enabled: true,
            },
            ProxyProfile {
                id: "proxy-2".to_string(),
                name: "Office".to_string(),
                kind: "http".to_string(),
                endpoint: "10.0.0.8:8080".to_string(),
                username: None,
                password_ref: None,
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
