use std::env;

const SERVICE_NAME: &str = "ProxyDuckCore";
const SERVICE_DISPLAY_NAME: &str = "ProxyDuck Core";
const SERVICE_DESCRIPTION: &str = "ProxyDuck local policy and data-plane service";

fn should_migrate_user_secrets(user_config_exists: bool, shared_config_exists: bool) -> bool {
    user_config_exists && !shared_config_exists
}

#[cfg(windows)]
mod windows_host {
    use std::{
        ffi::OsString,
        fs,
        path::PathBuf,
        sync::mpsc::{self, Sender},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::{Duration, Instant},
    };

    use anyhow::{Context, Result};
    use proxyduck_core::{run_core_with_readiness, CoreOptions};
    use tokio::{runtime::Builder, sync::oneshot};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
            ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
            ServiceStartType, ServiceState, ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    use super::{
        should_migrate_user_secrets, SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME,
    };

    const SERVICE_ARGUMENT: &str = "--service";

    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("starting ProxyDuck Core service dispatcher")?;
        Ok(())
    }

    pub fn install() -> Result<()> {
        let _install_guard = acquire_install_mutex()?;
        migrate_user_secrets()?;
        // Any existing shared config is now normalized under the same
        // machine-scope DPAPI context the LocalSystem service will use.
        std::env::set_var(proxyduck_common::SERVICE_SECRET_SCOPE_ENV, "machine");
        let _ = prepare_shared_config()?;
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
                .context("opening Windows Service Manager")?;
        let executable = std::env::current_exe().context("locating proxyduck-service.exe")?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable,
            launch_arguments: vec![
                OsString::from(SERVICE_ARGUMENT),
                OsString::from("--user-sid"),
                OsString::from(current_user_sid()?),
            ],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let service = match manager.create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        ) {
            Ok(service) => service,
            Err(create_error) => {
                let existing = manager
                    .open_service(
                        SERVICE_NAME,
                        ServiceAccess::CHANGE_CONFIG
                            | ServiceAccess::START
                            | ServiceAccess::STOP
                            | ServiceAccess::QUERY_STATUS,
                    )
                    .with_context(|| {
                        format!(
                            "creating ProxyDuck Core service (existing service lookup failed after: {create_error})"
                        )
                    })?;
                stop_and_wait(&existing)?;
                existing
                    .change_config(&info)
                    .context("updating ProxyDuck Core service configuration")?;
                existing
            }
        };
        service
            .set_description(SERVICE_DESCRIPTION)
            .context("setting ProxyDuck Core service description")?;
        service
            .set_failure_actions_on_non_crash_failures(true)
            .context("enabling ProxyDuck Core service failure recovery")?;
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(5),
                    },
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(30),
                    },
                    ServiceAction {
                        action_type: ServiceActionType::None,
                        delay: Duration::default(),
                    },
                ]),
            })
            .context("configuring ProxyDuck Core service recovery actions")?;
        println!("Installed {SERVICE_NAME}");
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("opening Windows Service Manager")?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .context("opening ProxyDuck Core service")?;
        stop_and_wait(&service)?;
        service
            .delete()
            .context("deleting ProxyDuck Core service")?;
        println!("Uninstalled {SERVICE_NAME}");
        Ok(())
    }

    pub fn start() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("opening Windows Service Manager")?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .context("opening ProxyDuck Core service")?;
        match service.query_status()?.current_state {
            ServiceState::Running => {
                println!("{SERVICE_NAME} is already running");
                return Ok(());
            }
            ServiceState::StartPending => {
                wait_for_running(&service)?;
                println!("{SERVICE_NAME} is now running");
                return Ok(());
            }
            ServiceState::StopPending => {
                anyhow::bail!("{SERVICE_NAME} is stopping; retry start after it reaches Stopped")
            }
            _ => {}
        }
        service
            .start::<&str>(&[])
            .context("starting ProxyDuck Core service")?;
        wait_for_running(&service)?;
        println!("Started {SERVICE_NAME}");
        Ok(())
    }

    fn wait_for_running(service: &windows_service::service::Service) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let status = service
                .query_status()
                .context("waiting for ProxyDuck Core service start")?;
            match status.current_state {
                ServiceState::Running => return Ok(()),
                ServiceState::Stopped => {
                    anyhow::bail!(
                        "{SERVICE_NAME} stopped before reaching Running (exit code {:?})",
                        status.exit_code
                    )
                }
                ServiceState::StartPending
                | ServiceState::ContinuePending
                | ServiceState::PausePending
                | ServiceState::StopPending => {}
                ServiceState::Paused => {
                    anyhow::bail!("{SERVICE_NAME} reached Paused instead of Running")
                }
            }
            if Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for {SERVICE_NAME} to reach Running")
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop_and_wait(service: &windows_service::service::Service) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut stop_requested = false;
        loop {
            match service
                .query_status()
                .context("waiting for ProxyDuck Core service stop")?
                .current_state
            {
                ServiceState::Stopped => return Ok(()),
                ServiceState::Running | ServiceState::Paused => {
                    if !stop_requested {
                        service
                            .stop()
                            .context("requesting ProxyDuck Core service stop")?;
                        stop_requested = true;
                    }
                }
                // Do not issue STOP while SCM still reports START_PENDING;
                // wait for a stable state so upgrades do not race service
                // initialization and fail with an invalid control request.
                ServiceState::StartPending
                | ServiceState::ContinuePending
                | ServiceState::PausePending
                | ServiceState::StopPending => {}
            }
            if Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for {SERVICE_NAME} to stop");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn service_main(arguments: Vec<OsString>) {
        std::env::set_var(proxyduck_common::SERVICE_SECRET_SCOPE_ENV, "machine");
        if let Some(sid) = user_sid_argument(&arguments) {
            std::env::set_var(proxyduck_common::INSTALLER_USER_SID_ENV, sid);
        }
        if let Err(error) = run_service() {
            eprintln!("ProxyDuck Core service failed: {error:#}");
            // Return a non-zero process exit code so SCM failure actions are
            // eligible after an abnormal Core/readiness failure. A normal
            // Stop/Shutdown path returns from run_service successfully.
            std::process::exit(1);
        }
    }

    fn run_service() -> Result<()> {
        let config_path = prepare_shared_config()?;
        let (stop_tx, stop_rx) = mpsc::channel();
        let timeout_stop_tx = stop_tx.clone();
        let normal_stop = Arc::new(AtomicBool::new(false));
        let status_slot = Arc::new(Mutex::new(None));
        let status_handle =
            register_handler(stop_tx, Arc::clone(&status_slot), Arc::clone(&normal_stop))?;
        *status_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("service status mutex poisoned"))? = Some(status_handle);
        let status_handle = status_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("service status mutex poisoned"))?
            .as_ref()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("service status handle was not initialized"))?;
        status_handle
            .set_service_status(start_pending_status())
            .context("reporting ProxyDuck Core service as starting")?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let watcher_finished = Arc::clone(&finished);
        let stop_thread = std::thread::spawn(move || {
            while !watcher_finished.load(Ordering::Acquire) {
                match stop_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) => {
                        let _ = shutdown_tx.send(());
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        let runtime = match Builder::new_multi_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                finished.store(true, Ordering::Release);
                let _ = stop_thread.join();
                let _ = status_handle.set_service_status(stopped_status(false));
                return Err(error).context("creating service Tokio runtime");
            }
        };
        let result = runtime.block_on(async {
            let (ready_tx, ready_rx) = oneshot::channel();
            let core_task = tokio::spawn(run_core_with_readiness(
                CoreOptions {
                    bind: "127.0.0.1:46666".parse().expect("static loopback bind"),
                    config_path: Some(config_path),
                    log_level: "info".to_string(),
                    ipc_pipe: true,
                    no_http: true,
                    allow_recovery: true,
                },
                Some(shutdown_rx),
                Some(ready_tx),
            ));

            let readiness_error =
                match tokio::time::timeout(Duration::from_secs(30), ready_rx).await {
                    Ok(Ok(Ok(()))) => match status_handle.set_service_status(running_status()) {
                        Ok(()) => None,
                        Err(error) => Some(anyhow::anyhow!(
                            "reporting ProxyDuck Core service as running: {error}"
                        )),
                    },
                    Ok(Ok(Err(message))) => Some(anyhow::anyhow!(
                        "ProxyDuck Core IPC readiness failed: {message}"
                    )),
                    Ok(Err(_)) => Some(anyhow::anyhow!(
                        "ProxyDuck Core exited before IPC readiness"
                    )),
                    Err(_) => Some(anyhow::anyhow!(
                        "timed out waiting for ProxyDuck Core IPC readiness"
                    )),
                };

            if let Some(error) = readiness_error {
                // Wake the existing stop watcher so the core future can run
                // its normal engine cleanup path before the service exits.
                let _ = timeout_stop_tx.send(());
                let _ = core_task.await;
                return Err(error);
            }

            core_task
                .await
                .context("joining ProxyDuck Core service task")?
        });
        finished.store(true, Ordering::Release);
        let _ = stop_thread.join();
        status_handle
            .set_service_status(stopped_status(
                normal_stop.load(Ordering::Acquire) && result.is_ok(),
            ))
            .context("reporting ProxyDuck Core service as stopped")?;
        result
    }

    fn shared_config_path() -> Result<PathBuf> {
        let program_data = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("PROGRAMDATA is not available"))?;
        Ok(program_data.join("ProxyDuck").join("config.json5"))
    }

    fn prepare_shared_config() -> Result<PathBuf> {
        let shared = shared_config_path()?;
        let directory = shared
            .parent()
            .ok_or_else(|| anyhow::anyhow!("shared config path has no parent"))?;
        fs::create_dir_all(directory).with_context(|| {
            format!("creating service config directory {}", directory.display())
        })?;
        if !shared.exists() {
            if let Ok(user_config) = proxyduck_common::resolve_app_file("config.json5") {
                if user_config.exists() {
                    // Never raw-copy a user file into the LocalSystem-owned
                    // path: a malformed legacy file could carry plaintext
                    // credentials that the normal migration cannot scrub.
                    match proxyduck_core::config::load_or_init(&user_config) {
                        Ok(config) => {
                            proxyduck_core::config::save(&shared, &config).with_context(|| {
                                format!(
                                    "migrating sanitized user config {} to {}",
                                    user_config.display(),
                                    shared.display()
                                )
                            })?
                        }
                        Err(error) => {
                            eprintln!(
                                "refusing malformed user config migration ({}): {error:#}",
                                user_config.display()
                            );
                            proxyduck_core::config::save(
                                &shared,
                                &proxyduck_core::model::AppConfig::default(),
                            )
                            .context("writing safe default service configuration")?;
                        }
                    }
                }
            }
        }
        if shared.exists() {
            let raw = fs::read_to_string(&shared)
                .with_context(|| format!("reading shared config {}", shared.display()))?;
            if raw.to_ascii_lowercase().contains("password") {
                // A parseable config is rewritten by load_or_init with the
                // password field omitted.  If parsing fails, stop before the
                // service can boot against a raw credential-bearing file.
                proxyduck_core::config::load_or_init(&shared).with_context(|| {
                    format!(
                        "refusing shared config with unparseable credential fields: {}",
                        shared.display()
                    )
                })?;
            }
        }
        proxyduck_common::harden_service_path(directory)?;
        if shared.exists() {
            proxyduck_common::harden_service_path(&shared)?;
        }
        Ok(shared)
    }

    /// Runs in the installing user's elevated session before the service is
    /// registered.  The old config and DPAPI secrets are readable here, so we
    /// can re-encrypt each credential with the machine DPAPI scope that the
    /// LocalSystem service will use after the upgrade.
    fn migrate_user_secrets() -> Result<()> {
        let shared = shared_config_path()?;
        let user_config = proxyduck_common::resolve_app_file("config.json5")?;
        // Once a machine-scope config exists it is authoritative.  Never let
        // a stale interactive-user file replace service rules or runtime
        // settings during repair/upgrade; credentials are migrated only on
        // the first creation path below.
        if !should_migrate_user_secrets(user_config.exists(), shared.exists()) {
            return Ok(());
        }
        let mut config = match proxyduck_core::config::load_or_init(&user_config) {
            Ok(config) => config,
            Err(error) => {
                // A corrupt primary and backup must not prevent installing
                // the recovery-capable service. `run_core` will expose a
                // default control plane over the pipe so the UI can replace
                // the file with a validated config.
                eprintln!("skipping secret migration until config recovery: {error:#}");
                return Ok(());
            }
        };
        let machine_store = proxyduck_common::SecretStore::for_service()?;
        let user_store = proxyduck_common::SecretStore::new()?;
        for proxy in &mut config.proxies {
            let password = match proxy.password.as_deref() {
                Some(pass) => Some(pass.to_string()),
                None => {
                    if let Some(ref secret_ref) = proxy.password_ref {
                        user_store.get(secret_ref)?
                    } else {
                        None
                    }
                }
            };
            let Some(password) = password.as_deref() else {
                if proxy.password_ref.is_some() {
                    anyhow::bail!(
                        "cannot migrate proxy credential {}; the interactive user's secret is unavailable",
                        proxy.id
                    );
                }
                continue;
            };
            let secret_ref = proxy
                .password_ref
                .clone()
                .unwrap_or_else(|| proxyduck_common::SecretStore::proxy_password_ref(&proxy.id));
            machine_store.put(&secret_ref, password)?;
            proxy.password_ref = Some(secret_ref);
            // The shared config is readable by the LocalSystem service and
            // administrators.  Keep only the machine-scope DPAPI reference;
            // never persist the interactive user's plaintext credential.
            proxy.password = None;
        }

        // Re-check immediately before the first shared write as a defensive
        // guard against an upgrade/repair race creating the authoritative
        // machine config while this migration was reading the user file.
        if shared.exists() {
            return Ok(());
        }
        proxyduck_core::config::save(&shared, &config)
            .context("writing the service shared config after secret migration")?;
        Ok(())
    }

    struct InstallMutex(windows::Win32::Foundation::HANDLE);

    impl Drop for InstallMutex {
        fn drop(&mut self) {
            unsafe {
                let _ = windows::Win32::System::Threading::ReleaseMutex(self.0);
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    fn acquire_install_mutex() -> Result<InstallMutex> {
        use windows::{
            core::PCWSTR,
            Win32::{
                Foundation::{GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HLOCAL},
                Security::{
                    Authorization::{
                        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                    },
                    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
                },
                System::Threading::CreateMutexW,
            },
        };

        // Protect the cross-process gate from low-integrity named-object
        // squatting. Only SYSTEM and local Administrators can open it.
        // Leave owner/group at the creating elevated administrator token; an
        // interactive admin cannot reliably assign SYSTEM as kernel-object
        // owner without SeRestorePrivilege. The protected DACL is the
        // authorization boundary, and ERROR_ALREADY_EXISTS rejects any
        // pre-created object before it can be used.
        let sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let name: Vec<u16> = "Global\\ProxyDuckInstallMutex"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle_result = unsafe {
            CreateMutexW(
                Some(&mut attributes as *mut SECURITY_ATTRIBUTES as *const SECURITY_ATTRIBUTES),
                true,
                PCWSTR(name.as_ptr()),
            )
        };
        let already_exists = unsafe { GetLastError() == ERROR_ALREADY_EXISTS };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        let handle = handle_result.context("creating the ProxyDuck install mutex")?;
        // An existing object is not trusted: CreateMutexW ignores the new
        // security descriptor in that case, so accepting it would permit a
        // low-integrity process to squat the predictable name. Legitimate
        // concurrent installers fail fast and can retry after the owner exits.
        if already_exists {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
            anyhow::bail!("ProxyDuck install is already in progress; retry after it exits");
        }

        // The creating process owns the mutex immediately (bInitialOwner=true),
        // so no unbounded wait is needed.
        Ok(InstallMutex(handle))
    }

    fn start_pending_status() -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: windows_service::service::ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        }
    }

    fn current_user_sid() -> Result<String> {
        let output = std::process::Command::new(windows_system32_tool("whoami.exe"))
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .context("resolving the installing user's SID")?;
        if !output.status.success() {
            anyhow::bail!("whoami failed while resolving the installing user's SID");
        }
        let output_text = String::from_utf8_lossy(&output.stdout);
        let sid = output_text
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
            .find(|value| value.starts_with("S-1-") && value.len() <= 184)
            .ok_or_else(|| anyhow::anyhow!("whoami did not return a Windows user SID"))?;
        Ok(sid.to_string())
    }

    fn windows_system32_tool(name: &str) -> PathBuf {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join(name)
    }

    fn user_sid_argument(arguments: &[OsString]) -> Option<String> {
        arguments
            .windows(2)
            .find(|pair| pair[0].as_os_str() == "--user-sid")
            .map(|pair| pair[1].to_string_lossy().into_owned())
            .filter(|sid| sid.starts_with("S-1-") && sid.len() <= 184)
    }

    fn register_handler(
        stop_tx: Sender<()>,
        status_slot: Arc<Mutex<Option<ServiceStatusHandle>>>,
        normal_stop: Arc<AtomicBool>,
    ) -> Result<ServiceStatusHandle> {
        let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                normal_stop.store(true, Ordering::Release);
                if let Ok(slot) = status_slot.lock() {
                    if let Some(handle) = slot.as_ref() {
                        let _ = handle.set_service_status(stopping_status());
                    }
                }
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .context("registering ProxyDuck Core service control handler")?;
        Ok(handle)
    }

    fn running_status() -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: windows_service::service::ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        }
    }

    fn stopping_status() -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: windows_service::service::ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(15),
            process_id: None,
        }
    }

    fn stopped_status(graceful: bool) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: windows_service::service::ServiceExitCode::Win32(u32::from(!graceful)),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }
}

#[cfg(not(windows))]
mod windows_host {
    use anyhow::{bail, Result};

    pub fn dispatch() -> Result<()> {
        bail!("ProxyDuck Core Windows Service is only supported on Windows")
    }

    pub fn install() -> Result<()> {
        dispatch()
    }

    pub fn start() -> Result<()> {
        dispatch()
    }

    pub fn uninstall() -> Result<()> {
        dispatch()
    }
}

fn main() -> anyhow::Result<()> {
    let command = env::args().nth(1).unwrap_or_default();
    match command.as_str() {
        "--install" => windows_host::install(),
        "--start" => windows_host::start(),
        "--uninstall" => windows_host::uninstall(),
        "--service" | "" => windows_host::dispatch(),
        "--help" | "-h" => {
            println!("ProxyDuck Core service host\n\nUsage: proxyduck-service [--install|--start|--uninstall|--service]");
            Ok(())
        }
        _ => anyhow::bail!("usage: proxyduck-service [--install|--start|--uninstall|--service]"),
    }
}

#[cfg(test)]
mod migration_tests {
    use super::should_migrate_user_secrets;

    #[test]
    fn stale_user_config_never_overwrites_existing_shared_config() {
        assert!(!should_migrate_user_secrets(true, true));
        assert!(should_migrate_user_secrets(true, false));
        assert!(!should_migrate_user_secrets(false, false));
    }
}
