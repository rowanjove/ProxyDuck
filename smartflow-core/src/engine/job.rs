use anyhow::{Context, Result};
use std::process::Child;

#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    },
};

#[derive(Debug)]
pub struct ProcessJobGuard {
    #[cfg(target_os = "windows")]
    job_handle: HANDLE,
}

#[cfg(target_os = "windows")]
unsafe impl Send for ProcessJobGuard {}
#[cfg(target_os = "windows")]
unsafe impl Sync for ProcessJobGuard {}

impl ProcessJobGuard {
    #[cfg(target_os = "windows")]
    pub fn assign(child: &Child) -> Result<Self> {
        unsafe {
            let job = CreateJobObjectW(None, windows::core::PCWSTR::null())
                .context("failed to create JobObject for child process")?;

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            if let Err(err) = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) {
                let _ = CloseHandle(job);
                return Err(err)
                    .context("failed to set JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE on JobObject");
            }

            let child_handle = HANDLE(child.as_raw_handle() as _);
            if let Err(err) = AssignProcessToJobObject(job, child_handle) {
                let _ = CloseHandle(job);
                return Err(err).context("failed to assign child process to JobObject");
            }

            tracing::debug!("assigned child process to Windows JobObject with KILL_ON_JOB_CLOSE");
            Ok(Self { job_handle: job })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn assign(_child: &Child) -> Result<Self> {
        Ok(Self {})
    }
}

impl Drop for ProcessJobGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        if !self.job_handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.job_handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_job_object_kills_child_on_drop() {
        let mut child = Command::new("cmd.exe")
            // Use a time-bounded, non-interactive command. `pause` exits
            // immediately when CI stdin is closed and made this release gate
            // fail before the Job Object behavior was exercised.
            .args(["/c", "ping -n 30 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn cmd.exe");

        {
            let guard = ProcessJobGuard::assign(&child);
            // In case running inside another JobObject without breakaways (e.g. CI runner),
            // assign might fail, but in local Windows dev it succeeds.
            if let Ok(_guard) = guard {
                std::thread::sleep(Duration::from_millis(50));
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "process should still be running"
                );
                // _guard drops here
            } else {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }

        let mut terminated = false;
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(100));
            if child.try_wait().unwrap().is_some() {
                terminated = true;
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            terminated,
            "child process should be killed when JobObject is dropped"
        );
    }
}
