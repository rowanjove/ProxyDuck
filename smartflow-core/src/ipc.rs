//! Windows Named Pipe adapter for the shared ProxyDuck IPC contract.
//!
//! The adapter deliberately forwards requests through the same authenticated
//! Axum router as localhost HTTP.  This keeps route validation and mutation
//! semantics identical while the service migration is in progress.  Tokio's
//! `reject_remote_clients` gate prevents remote pipe connections; the final
//! LocalSystem service must provide the installer-user SID and still needs VM
//! validation before installer enablement.

use anyhow::Result;
use tokio::sync::oneshot;

use crate::state::CoreState;

#[cfg(target_os = "windows")]
mod windows_transport {
    use super::*;
    use axum::{body::Body, http::Request, response::Response};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use proxyduck_common::{
        ipc::{decode_frame, encode_frame, IpcError, IpcErrorCode, IpcRequest, IpcResponse},
        AUTH_HEADER,
    };
    use serde_json::Value;
    use std::time::Duration;
    use std::{os::windows::io::AsRawHandle, process::Command};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::{PipeMode, ServerOptions},
    };
    use tower::ServiceExt;
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{LocalFree, BOOL, HLOCAL},
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                },
                PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
            },
        },
    };

    const MAX_BODY_BYTES: usize = proxyduck_common::ipc::IPC_MAX_FRAME_BYTES;

    pub fn start(state: CoreState, ready_tx: Option<oneshot::Sender<Result<(), String>>>) {
        tokio::spawn(async move {
            if let Err(error) = serve(state, ready_tx).await {
                tracing::error!(%error, "named pipe IPC stopped");
            }
        });
    }

    async fn serve(
        state: CoreState,
        mut ready_tx: Option<oneshot::Sender<Result<(), String>>>,
    ) -> Result<()> {
        let allowed_user_sid = match configured_user_sid() {
            Ok(sid) => sid,
            Err(error) => {
                tracing::error!(%error, "named pipe user SID is not configured");
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(Err(error.to_string()));
                }
                return Err(error);
            }
        };
        loop {
            let mut options = ServerOptions::new();
            options
                .pipe_mode(PipeMode::Byte)
                .reject_remote_clients(true)
                .max_instances(16);
            let mut pipe = match create_pipe(&options, &allowed_user_sid) {
                Ok(pipe) => pipe,
                Err(error) => {
                    tracing::error!(%error, "failed to create named pipe; retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Ok(()));
            }
            if let Err(error) = pipe.connect().await {
                tracing::debug!(%error, "named pipe connection attempt failed; retrying");
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }

            let request_state = state.clone();
            let user_sid = allowed_user_sid.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_client(&mut pipe, request_state, &user_sid).await {
                    tracing::debug!(%error, "named pipe client disconnected");
                }
            });
        }
    }

    fn create_pipe(
        options: &ServerOptions,
        allowed_user_sid: &str,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        // SYSTEM and local administrators are needed by the service manager;
        // the installing user's SID is the only non-elevated interactive
        // principal granted access.  The DACL is protected against inherited
        // broad grants (`P`).
        let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{allowed_user_sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: BOOL(0),
        };
        let result = unsafe {
            options.create_with_security_attributes_raw(
                proxyduck_common::ipc::IPC_PIPE_NAME,
                &mut attributes as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void,
            )
        };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        Ok(result?)
    }

    fn configured_user_sid() -> Result<String> {
        let explicit = std::env::var(proxyduck_common::INSTALLER_USER_SID_ENV).ok();
        let candidate = explicit
            .clone()
            .or_else(|| {
                Command::new(windows_system32_tool("whoami.exe"))
                    .args(["/user", "/fo", "csv", "/nh"])
                    .output()
                    .ok()
                    .filter(|output| output.status.success())
                    .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            })
            .unwrap_or_default();
        let sid = candidate
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
            .find(|value| value.starts_with("S-1-") && value.len() <= 184)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no installer user SID is available; set {} before running the service",
                    proxyduck_common::INSTALLER_USER_SID_ENV
                )
            })?;
        if explicit.is_none() && sid.eq_ignore_ascii_case("S-1-5-18") {
            anyhow::bail!(
                "LocalSystem cannot infer the interactive user SID; set {}",
                proxyduck_common::INSTALLER_USER_SID_ENV
            );
        }
        Ok(sid.to_string())
    }

    fn windows_system32_tool(name: &str) -> std::path::PathBuf {
        std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join(name)
    }

    async fn handle_client(
        pipe: &mut tokio::net::windows::named_pipe::NamedPipeServer,
        state: CoreState,
        allowed_user_sid: &str,
    ) -> Result<()> {
        let (client_sid, is_admin) = client_sid(pipe)?;
        if client_sid != allowed_user_sid && client_sid != "S-1-5-18" && !is_admin {
            let response = IpcResponse::error(
                "unknown",
                IpcError::new(
                    IpcErrorCode::Forbidden,
                    "named pipe client is not authorized",
                ),
            );
            write_response(pipe, response).await?;
            return Ok(());
        }
        let mut length = [0_u8; 4];
        if tokio::time::timeout(
            Duration::from_millis(u64::from(proxyduck_common::ipc::IPC_DEFAULT_DEADLINE_MS)),
            pipe.read_exact(&mut length),
        )
        .await
        .is_err()
        {
            return Ok(());
        }
        let declared = u32::from_be_bytes(length) as usize;
        if declared > MAX_BODY_BYTES {
            let response = IpcResponse::error(
                "unknown",
                IpcError::new(
                    IpcErrorCode::PayloadTooLarge,
                    format!("IPC payload exceeds {MAX_BODY_BYTES} bytes"),
                ),
            );
            write_response(pipe, response).await?;
            return Ok(());
        }
        let mut payload = vec![0_u8; declared];
        if tokio::time::timeout(
            Duration::from_millis(u64::from(proxyduck_common::ipc::IPC_DEFAULT_DEADLINE_MS)),
            pipe.read_exact(&mut payload),
        )
        .await
        .is_err()
        {
            return Ok(());
        }
        let mut frame = Vec::with_capacity(4 + declared);
        frame.extend_from_slice(&length);
        frame.extend_from_slice(&payload);

        let request_id = serde_json::from_slice::<Value>(&payload)
            .ok()
            .and_then(|value| {
                value
                    .get("requestId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unknown".to_string());
        let request = match decode_frame::<IpcRequest>(&frame) {
            Ok(request) => request,
            Err(error) => {
                let response = IpcResponse::error(
                    request_id,
                    IpcError::new(IpcErrorCode::InvalidRequest, error.to_string()),
                );
                write_response(pipe, response).await?;
                return Ok(());
            }
        };
        let response = dispatch(request, state, &client_sid, is_admin).await;
        write_response(pipe, response).await?;
        Ok(())
    }

    async fn write_response(
        pipe: &mut tokio::net::windows::named_pipe::NamedPipeServer,
        response: IpcResponse,
    ) -> Result<()> {
        let frame = match encode_frame(&response) {
            Ok(frame) => frame,
            Err(error) => encode_frame(&IpcResponse::error(
                response.request_id.clone(),
                IpcError::new(
                    IpcErrorCode::PayloadTooLarge,
                    format!("IPC response exceeds frame limit: {error}"),
                ),
            ))?,
        };
        let deadline =
            Duration::from_millis(u64::from(proxyduck_common::ipc::IPC_DEFAULT_DEADLINE_MS));
        tokio::time::timeout(deadline, pipe.write_all(&frame)).await??;
        tokio::time::timeout(deadline, pipe.flush()).await??;
        Ok(())
    }

    fn client_sid(
        pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> Result<(String, bool)> {
        use windows::Win32::{
            Foundation::{CloseHandle, HANDLE},
            Security::{GetTokenInformation, RevertToSelf, TokenUser, TOKEN_QUERY, TOKEN_USER},
            System::{
                Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient},
                Threading::{
                    GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                },
            },
        };
        let mut token = HANDLE::default();
        let pipe_handle = HANDLE(pipe.as_raw_handle() as _);
        let impersonate_result = unsafe { ImpersonateNamedPipeClient(pipe_handle) };
        let token_result = if impersonate_result.is_ok() {
            let res = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) };
            let _ = unsafe { RevertToSelf() };
            res
        } else {
            let mut pid = 0_u32;
            unsafe {
                GetNamedPipeClientProcessId(pipe_handle, &mut pid)?;
            }
            let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? };
            let res = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
            unsafe {
                let _ = CloseHandle(process);
            }
            res
        };
        token_result?;

        let mut required = 0_u32;
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut required);
        }
        if required == 0 {
            unsafe {
                let _ = CloseHandle(token);
            }
            anyhow::bail!("failed to size the client token SID");
        }
        let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
                required,
                &mut required,
            )
        };
        result?;
        let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        if token_user.User.Sid.0.is_null() {
            unsafe {
                let _ = CloseHandle(token);
            }
            anyhow::bail!("client token did not contain a user SID");
        }
        let value = sid_to_string(token_user.User.Sid);
        let is_admin = token_contains_group(token, "S-1-5-32-544");
        unsafe {
            let _ = CloseHandle(token);
        }
        Ok((value?, is_admin?))
    }

    fn sid_to_string(sid: windows::Win32::Security::PSID) -> Result<String> {
        use windows::Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::Authorization::ConvertSidToStringSidW,
        };
        let mut string_sid = windows::core::PWSTR::null();
        unsafe {
            ConvertSidToStringSidW(sid, &mut string_sid)?;
        }
        let value = unsafe {
            let mut len = 0;
            while *string_sid.0.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(string_sid.0, len))
        };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(string_sid.0 as _)));
        }
        Ok(value)
    }

    fn token_contains_group(
        token: windows::Win32::Foundation::HANDLE,
        target: &str,
    ) -> Result<bool> {
        use windows::Win32::Security::{GetTokenInformation, TokenGroups, TOKEN_GROUPS};
        // A filtered UAC token can still contain the Administrators SID with
        // `SE_GROUP_USE_FOR_DENY_ONLY`. Presence of the SID alone must not
        // grant privileged IPC operations; only an enabled group is an
        // elevated administrator token.
        const SE_GROUP_ENABLED: u32 = 0x0000_0004;
        let mut required = 0_u32;
        unsafe {
            let _ = GetTokenInformation(token, TokenGroups, None, 0, &mut required);
        }
        if required == 0 {
            anyhow::bail!("failed to size the client token groups");
        }
        let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        unsafe {
            GetTokenInformation(
                token,
                TokenGroups,
                Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
                required,
                &mut required,
            )?;
        }
        let groups = unsafe { &*(buffer.as_ptr() as *const TOKEN_GROUPS) };
        for index in 0..groups.GroupCount as usize {
            let group = unsafe { *groups.Groups.as_ptr().add(index) };
            if !group.Sid.0.is_null()
                && group.Attributes & SE_GROUP_ENABLED != 0
                && sid_to_string(group.Sid)? == target
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn dispatch(
        request: IpcRequest,
        state: CoreState,
        client_sid: &str,
        is_admin: bool,
    ) -> IpcResponse {
        let request_id = request.request_id.clone();
        if request.version != proxyduck_common::ipc::IPC_PROTOCOL_VERSION {
            return IpcResponse::error(
                request_id,
                IpcError::new(
                    IpcErrorCode::UnsupportedVersion,
                    "unsupported IPC protocol version",
                ),
            );
        }
        if let Err(error) = request.validate() {
            return IpcResponse::error(
                request_id,
                IpcError::new(IpcErrorCode::InvalidRequest, error.to_string()),
            );
        }

        if !is_known_api_path(&request.path) {
            return IpcResponse::error(
                request_id,
                IpcError::new(IpcErrorCode::NotFound, "IPC operation is not exposed"),
            );
        }
        // Materialize the body before the privilege gate.  A full config PUT
        // can carry `engineMode`, so treating only POST /engine/mode as
        // privileged would let a standard user switch the data-plane engine
        // through the otherwise ordinary config endpoint.
        let request_body = request.body.clone().unwrap_or(Value::Null);
        let changes_engine_mode = request.method == "PUT"
            && request.path.split('?').next().unwrap_or(&request.path) == "/config"
            && config_changes_engine_mode(&request_body, &state);
        if (requires_elevation(&request.method, &request.path) || changes_engine_mode)
            && !is_admin
            && client_sid != "S-1-5-18"
        {
            return IpcResponse::error(
                request_id,
                IpcError::new(IpcErrorCode::Forbidden, "IPC operation requires elevation"),
            );
        }

        let body = request
            .body
            .map(|value| serde_json::to_vec(&value).unwrap_or_default())
            .unwrap_or_default();
        let mut request_builder = Request::builder()
            .method(request.method.as_str())
            .uri(request.path)
            // The pipe's local-only gate is not a substitute for the service
            // SID ACL.  Until the service host owns this adapter, retaining
            // the existing token middleware avoids an unauthenticated path.
            .header(AUTH_HEADER, state.auth_token.as_str());
        if !body.is_empty() {
            request_builder = request_builder.header("content-type", "application/json");
        }
        let http_request = request_builder.body(Body::from(body));
        let Ok(http_request) = http_request else {
            return IpcResponse::error(
                request_id,
                IpcError::new(IpcErrorCode::InvalidRequest, "invalid IPC HTTP request"),
            );
        };

        let deadline = Duration::from_millis(u64::from(request.deadline_ms));
        let response: Response =
            match tokio::time::timeout(deadline, crate::api::router(state).oneshot(http_request))
                .await
            {
                Err(_) => {
                    return IpcResponse::error(
                        request_id,
                        IpcError::new(
                            IpcErrorCode::DeadlineExceeded,
                            "IPC request deadline exceeded",
                        ),
                    )
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "IPC request dispatch failed");
                    return IpcResponse::error(
                        request_id,
                        IpcError::new(IpcErrorCode::Internal, "IPC request dispatch failed"),
                    );
                }
                Ok(Ok(response)) => response,
            };
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = match tokio::time::timeout(
            deadline,
            axum::body::to_bytes(response.into_body(), MAX_BODY_BYTES),
        )
        .await
        {
            Err(_) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::DeadlineExceeded,
                        "IPC response deadline exceeded",
                    ),
                )
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, "IPC response exceeds the frame limit");
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::PayloadTooLarge,
                        "IPC response exceeds frame limit",
                    ),
                );
            }
            Ok(Ok(bytes)) => bytes,
        };
        let value = serde_json::from_slice::<Value>(&bytes).ok();
        if status >= 400 {
            let error = IpcError::new(
                status_to_error(status),
                format!("HTTP API returned {status}"),
            )
            .with_details(value.unwrap_or(Value::Null));
            IpcResponse::error_with_status(request_id, status, error)
        } else {
            let is_json = content_type
                .as_deref()
                .is_some_and(|value| value.to_ascii_lowercase().starts_with("application/json"));
            let (body, binary_base64) = if status == 204 || is_json {
                (value, None)
            } else {
                (None, Some(STANDARD.encode(&bytes)))
            };
            IpcResponse {
                version: proxyduck_common::ipc::IPC_PROTOCOL_VERSION,
                request_id,
                status,
                body,
                error: None,
                binary_base64,
            }
        }
    }

    fn is_known_api_path(path: &str) -> bool {
        let path = path.split('?').next().unwrap_or(path);
        [
            "/health",
            "/capabilities",
            "/snapshot",
            "/diagnostics",
            "/diagnostics/bundle",
            "/config",
            "/configs",
            "/network",
            "/connections",
            "/endpoints",
            "/timeline",
            "/stats",
            "/stats/rules",
            "/stats/proxies",
            "/stats/hits",
            "/logs",
            "/icon/exe",
            "/processes",
            "/rules",
            "/profiles",
            "/quickbar",
            "/proxies",
            "/engine/mode",
            "/runtime",
            "/runtime/status",
            "/health/proxies",
            "/templates",
            "/lifecycle/shutdown",
        ]
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
    }

    fn requires_elevation(method: &str, path: &str) -> bool {
        let path = path.split('?').next().unwrap_or(path);
        method == "POST"
            && (path == "/engine/mode"
                || path == "/lifecycle/shutdown"
                || path.ends_with("/launch")
                || path.ends_with("/activate")
                || path == "/diagnostics/bundle"
                || path == "/network/repair/run"
                || path == "/network/restore"
                || path == "/network/snapshot"
                || path == "/configs/save"
                || path == "/timeline/clear")
    }

    fn config_changes_engine_mode(body: &Value, state: &CoreState) -> bool {
        let Some(value) = body.get("engineMode").or_else(|| body.get("engine_mode")) else {
            return false;
        };
        match serde_json::from_value::<crate::model::EngineMode>(value.clone()) {
            Ok(incoming) => incoming != state.config_snapshot().engine_mode,
            // Let the API return its normal validation error, but keep an
            // invalid mode fail-closed behind the elevated path.
            Err(_) => true,
        }
    }

    fn status_to_error(status: u16) -> IpcErrorCode {
        match status {
            401 => IpcErrorCode::Unauthorized,
            403 => IpcErrorCode::Forbidden,
            404 => IpcErrorCode::NotFound,
            408 => IpcErrorCode::DeadlineExceeded,
            409 => IpcErrorCode::Conflict,
            429 | 500..=599 => IpcErrorCode::Unavailable,
            _ => IpcErrorCode::InvalidRequest,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{is_known_api_path, requires_elevation};

        #[test]
        fn template_collection_and_all_template_ids_are_exposed_over_ipc() {
            for path in [
                "/templates",
                "/templates/ai-dev",
                "/templates/browser",
                "/templates/gaming?locale=zh-CN",
                "/templates/meetings",
            ] {
                assert!(is_known_api_path(path), "{path}");
            }
            assert!(!is_known_api_path("/templates-evil"));
            assert!(!is_known_api_path("/templates-other/browser"));
        }

        #[test]
        fn feature_modules_are_exposed_and_elevated_appropriately() {
            for path in [
                "/network/status",
                "/network/diagnose",
                "/network/history",
                "/network/repair/plan",
                "/network/repair/run",
                "/network/snapshots",
                "/network/snapshot",
                "/network/restore",
                "/configs",
                "/configs/discover",
                "/configs/inspect",
                "/configs/validate",
                "/configs/patch",
                "/configs/save",
                "/connections",
                "/connections/summary",
                "/endpoints/discover",
                "/endpoints/discover/add",
                "/timeline",
                "/timeline/clear",
            ] {
                assert!(is_known_api_path(path), "expected known path: {path}");
            }

            assert!(requires_elevation("POST", "/network/repair/run"));
            assert!(requires_elevation("POST", "/network/restore"));
            assert!(requires_elevation("POST", "/network/snapshot"));
            assert!(requires_elevation("POST", "/configs/save"));
            assert!(requires_elevation("POST", "/timeline/clear"));
            assert!(!requires_elevation("POST", "/network/diagnose"));
            assert!(!requires_elevation("POST", "/configs/inspect"));
            assert!(!requires_elevation("GET", "/network/status"));
        }
    }
}

/// Starts the local IPC listener.  Non-Windows builds intentionally do not
/// expose a fake TCP fallback: localhost HTTP remains the explicit developer
/// transport until a platform-specific service adapter exists.
pub fn start_named_pipe(state: CoreState, ready_tx: Option<oneshot::Sender<Result<(), String>>>) {
    #[cfg(target_os = "windows")]
    windows_transport::start(state, ready_tx);

    #[cfg(not(target_os = "windows"))]
    {
        let _ = state;
        if let Some(tx) = ready_tx {
            let _ = tx.send(Err(
                "named pipe IPC is only available on Windows".to_string()
            ));
        }
    }
}
