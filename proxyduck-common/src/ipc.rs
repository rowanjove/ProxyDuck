//! Versioned control-plane protocol shared by the desktop client and the
//! future Windows Service transport.
//!
//! The transport is intentionally not part of this module.  Both the current
//! loopback HTTP adapter and the Windows Named Pipe adapter use the same
//! request/response contract, which keeps authentication, timeout and error
//! handling from diverging between transports.

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const IPC_PROTOCOL_VERSION: u16 = 1;
pub const IPC_PIPE_NAME: &str = r"\\.\pipe\ProxyDuck";
pub const IPC_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const IPC_DEFAULT_DEADLINE_MS: u32 = 5_000;
pub const IPC_MAX_DEADLINE_MS: u32 = 120_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpcErrorCode {
    Unauthorized,
    Forbidden,
    InvalidRequest,
    UnsupportedVersion,
    DeadlineExceeded,
    PayloadTooLarge,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

impl IpcErrorCode {
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::InvalidRequest | Self::UnsupportedVersion | Self::PayloadTooLarge => 400,
            Self::DeadlineExceeded => 408,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::Unavailable => 503,
            Self::Internal => 500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub code: IpcErrorCode,
    pub message: String,
    #[serde(default)]
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl IpcError {
    pub fn new(code: IpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            retryable: matches!(code, IpcErrorCode::Unavailable | IpcErrorCode::Internal),
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IpcRequest {
    pub version: u16,
    pub request_id: String,
    /// HTTP-compatible method used by both the Named Pipe and developer API.
    pub method: String,
    /// Absolute API path, for example `/runtime/status`.
    pub path: String,
    /// Per-request deadline.  The server must fail closed after this time.
    pub deadline_ms: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl IpcRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            version: IPC_PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            method: method.into(),
            path: path.into(),
            deadline_ms: IPC_DEFAULT_DEADLINE_MS,
            body: None,
        }
    }

    pub fn with_body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    pub fn with_deadline_ms(mut self, deadline_ms: u32) -> Self {
        self.deadline_ms = deadline_ms;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != IPC_PROTOCOL_VERSION {
            bail!("unsupported IPC protocol version {}", self.version);
        }
        validate_request_id(&self.request_id)?;
        validate_method(&self.method)?;
        validate_path(&self.path)?;
        if self.deadline_ms == 0 || self.deadline_ms > IPC_MAX_DEADLINE_MS {
            bail!(
                "IPC deadline must be between 1 and {} ms",
                IPC_MAX_DEADLINE_MS
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IpcResponse {
    pub version: u16,
    pub request_id: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
    /// Base64-encoded binary response for bounded artifacts such as the
    /// diagnostics ZIP. JSON API responses continue to use `body`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_base64: Option<String>,
}

impl IpcResponse {
    pub fn success(request: &IpcRequest, body: Option<Value>) -> Self {
        Self {
            version: IPC_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            status: 200,
            body,
            error: None,
            binary_base64: None,
        }
    }

    pub fn error(request_id: impl Into<String>, error: IpcError) -> Self {
        let status = error.code.http_status();
        Self::error_with_status(request_id, status, error)
    }

    pub fn error_with_status(request_id: impl Into<String>, status: u16, error: IpcError) -> Self {
        Self {
            version: IPC_PROTOCOL_VERSION,
            request_id: request_id.into(),
            status,
            body: None,
            error: Some(error),
            binary_base64: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != IPC_PROTOCOL_VERSION {
            bail!("unsupported IPC protocol version {}", self.version);
        }
        validate_request_id(&self.request_id)?;
        if !(100..=599).contains(&self.status) {
            bail!("invalid IPC response status {}", self.status);
        }
        if self.status >= 400 && self.error.is_none() {
            bail!("error IPC responses must include a typed error");
        }
        if self.status < 400 && self.error.is_some() {
            bail!("successful IPC responses cannot include an error");
        }
        if self.binary_base64.is_some() && self.body.is_some() {
            bail!("IPC response cannot include both JSON and binary bodies");
        }
        Ok(())
    }
}

/// Encodes one length-delimited JSON message.  The fixed-width prefix makes a
/// stream transport safe: a receiver never has to guess where JSON ends.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(value).context("failed to serialize IPC message")?;
    if payload.len() > IPC_MAX_FRAME_BYTES {
        bail!("IPC payload exceeds {} bytes", IPC_MAX_FRAME_BYTES);
    }
    let length = u32::try_from(payload.len()).context("IPC payload length overflow")?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes exactly one complete frame.  Extra or truncated bytes are rejected
/// so callers cannot accidentally process a second request or a partial one.
pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T> {
    if frame.len() < 4 {
        bail!("IPC frame is truncated");
    }
    let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if declared > IPC_MAX_FRAME_BYTES {
        bail!("IPC payload exceeds {} bytes", IPC_MAX_FRAME_BYTES);
    }
    if frame.len() != declared + 4 {
        bail!(
            "IPC frame length mismatch: declared {}, received {}",
            declared,
            frame.len().saturating_sub(4)
        );
    }
    serde_json::from_slice(&frame[4..]).context("failed to deserialize IPC message")
}

/// Perform one bounded request through the local Windows Named Pipe.  The
/// transport is intentionally kept beside the wire DTO so desktop and CLI
/// clients cannot drift in framing, deadlines, or response validation.
#[cfg(target_os = "windows")]
pub fn request_named_pipe(request: IpcRequest) -> Result<IpcResponse> {
    use std::time::Instant;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::ClientOptions,
        runtime::Builder,
        time::{sleep, timeout},
    };

    request.validate()?;
    let deadline = std::time::Duration::from_millis(u64::from(request.deadline_ms));
    let runtime = Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        let started = Instant::now();
        let mut client = loop {
            match ClientOptions::new().open(IPC_PIPE_NAME) {
                Ok(client) => {
                    verify_service_identity(&client)?;
                    break client;
                }
                Err(error) if started.elapsed() < deadline => {
                    let _ = error;
                    sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let frame = encode_frame(&request)?;
        let remaining = || deadline.saturating_sub(started.elapsed());
        timeout(remaining(), client.write_all(&frame)).await??;
        timeout(remaining(), client.flush()).await??;

        let mut length = [0_u8; 4];
        timeout(remaining(), client.read_exact(&mut length)).await??;
        let declared = u32::from_be_bytes(length) as usize;
        if declared > IPC_MAX_FRAME_BYTES {
            bail!("IPC response exceeds {IPC_MAX_FRAME_BYTES} bytes");
        }
        let mut payload = vec![0_u8; declared];
        timeout(remaining(), client.read_exact(&mut payload)).await??;
        let mut response_frame = Vec::with_capacity(4 + declared);
        response_frame.extend_from_slice(&length);
        response_frame.extend_from_slice(&payload);
        let response: IpcResponse = decode_frame(&response_frame)?;
        response.validate()?;
        Ok(response)
    })
}

#[cfg(target_os = "windows")]
fn verify_service_identity(
    client: &tokio::net::windows::named_pipe::NamedPipeClient,
) -> Result<()> {
    // A developer can explicitly opt into a core-owned pipe for local
    // debugging. Production clients only trust the executable registered in
    // SCM, so a same-user process cannot impersonate a stopped service by
    // racing to create the well-known pipe name.
    if std::env::var("PROXYDUCK_ALLOW_DEV_PIPE")
        .ok()
        .is_some_and(|value| value == "1")
    {
        return Ok(());
    }

    use std::{os::windows::io::AsRawHandle, path::PathBuf};
    use windows::{
        core::PWSTR,
        Win32::{
            Foundation::{CloseHandle, HANDLE},
            System::{
                Pipes::GetNamedPipeServerProcessId,
                Threading::{
                    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                },
            },
        },
    };

    let mut pid = 0_u32;
    unsafe {
        GetNamedPipeServerProcessId(HANDLE(client.as_raw_handle() as _), &mut pid)?;
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? };
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    let image = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )?;
        let value = String::from_utf16_lossy(&buffer[..length as usize]);
        let _ = CloseHandle(process);
        value
    };
    let actual = PathBuf::from(image);
    let actual = canonical_or_normalized(&actual);
    let mut expected = expected_service_executable()?;
    if actual != expected {
        invalidate_expected_service_executable();
        expected = expected_service_executable()?;
        if actual != expected {
            bail!(
                "named pipe server identity mismatch (expected {}, got {})",
                expected.display(),
                actual.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
static EXPECTED_SERVICE_EXE: std::sync::Mutex<Option<std::path::PathBuf>> =
    std::sync::Mutex::new(None);

#[cfg(target_os = "windows")]
fn expected_service_executable() -> Result<std::path::PathBuf> {
    let mut lock = EXPECTED_SERVICE_EXE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = lock.as_ref() {
        return Ok(cached.clone());
    }
    let resolved = canonical_or_normalized(&service_executable_from_scm()?);
    *lock = Some(resolved.clone());
    Ok(resolved)
}

#[cfg(target_os = "windows")]
fn invalidate_expected_service_executable() {
    let mut lock = EXPECTED_SERVICE_EXE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *lock = None;
}

#[cfg(target_os = "windows")]
fn service_executable_from_scm() -> Result<std::path::PathBuf> {
    let sc_path = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("sc.exe");
    let output = std::process::Command::new(sc_path)
        .args(["qc", "ProxyDuckCore"])
        .output()
        .context("querying ProxyDuckCore service configuration")?;
    if !output.status.success() {
        bail!("sc.exe could not query ProxyDuckCore service configuration");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.contains("BINARY_PATH_NAME"))
        })
        .map(|(_, value)| value.trim())
        .ok_or_else(|| anyhow::anyhow!("service configuration did not contain BINARY_PATH_NAME"))?;
    let path = if let Some(value) = value.strip_prefix('"') {
        value.split_once('"').map(|(path, _)| path).unwrap_or(value)
    } else {
        value.split_whitespace().next().unwrap_or(value)
    };
    if path.is_empty() {
        bail!("service executable path is empty");
    }
    Ok(std::path::PathBuf::from(path))
}

#[cfg(target_os = "windows")]
fn canonical_or_normalized(path: &std::path::Path) -> std::path::PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        std::path::Path::new(&path.to_string_lossy().to_ascii_lowercase()).to_path_buf()
    })
}

#[cfg(not(target_os = "windows"))]
pub fn request_named_pipe(_request: IpcRequest) -> Result<IpcResponse> {
    bail!("Named Pipe IPC is only supported on Windows")
}

fn validate_request_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!("IPC request id must be 1-128 printable ASCII characters");
    }
    Ok(())
}

fn validate_method(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("IPC method must be an uppercase token");
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 2048
        || !value.starts_with('/')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("IPC path must be an absolute path without control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_length_delimited_frame() {
        let request = IpcRequest::new("POST", "/runtime")
            .with_deadline_ms(1200)
            .with_body(serde_json::json!({ "enabled": true }));
        request.validate().unwrap();
        let decoded: IpcRequest = decode_frame(&encode_frame(&request).unwrap()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn malformed_and_trailing_frames_are_rejected() {
        assert!(decode_frame::<IpcRequest>(&[0, 0, 0]).is_err());
        let mut frame = encode_frame(&IpcRequest::new("GET", "/health")).unwrap();
        frame[3] = frame[3].saturating_sub(1);
        assert!(decode_frame::<IpcRequest>(&frame).is_err());
        let mut frame = encode_frame(&IpcRequest::new("GET", "/health")).unwrap();
        frame.push(0);
        assert!(decode_frame::<IpcRequest>(&frame).is_err());
    }

    #[test]
    fn request_validation_rejects_unsafe_or_unbounded_values() {
        let mut request = IpcRequest::new("get", "/health");
        assert!(request.validate().is_err());
        request = IpcRequest::new("GET", "http://remote/health");
        assert!(request.validate().is_err());
        request = IpcRequest::new("GET", "/health").with_deadline_ms(0);
        assert!(request.validate().is_err());
    }

    #[test]
    fn typed_errors_map_to_status_and_validate() {
        let request = IpcRequest::new("GET", "/health");
        let response = IpcResponse::error(
            request.request_id.clone(),
            IpcError::new(IpcErrorCode::Forbidden, "not allowed"),
        );
        response.validate().unwrap();
        assert_eq!(response.status, 403);

        let response = IpcResponse::error_with_status(
            request.request_id,
            429,
            IpcError::new(IpcErrorCode::Unavailable, "busy"),
        );
        response.validate().unwrap();
        assert_eq!(response.status, 429);
    }
}
