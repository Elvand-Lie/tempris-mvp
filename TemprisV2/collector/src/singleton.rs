use std::fmt;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum LockResult {
    Acquired(SingleInstanceGuard),
    AlreadyRunning,
    Error(String),
}

#[derive(PartialEq, Eq)]
pub struct SingleInstanceGuard {
    #[cfg(windows)]
    handle: isize,
    name: String,
}

impl fmt::Debug for SingleInstanceGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleInstanceGuard")
            .field("name", &self.name)
            .finish()
    }
}

unsafe impl Send for SingleInstanceGuard {}
unsafe impl Sync for SingleInstanceGuard {}

impl SingleInstanceGuard {
    pub const DEFAULT_MUTEX_NAME: &'static str = "TemprisCollectorCoreSingleton";
    pub const MUTEX_SDDL: &'static str = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00100000;;;BU)";

    /// Returns the SDDL descriptor for the single-instance mutex
    pub fn get_mutex_sddl() -> &'static str {
        Self::MUTEX_SDDL
    }

    /// Returns the name of the acquired mutex.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Attempts to acquire a single-instance lock using a Windows named mutex in the Global namespace.
    /// Fails closed on any permission or OS error.
    pub fn acquire(name_suffix: Option<&str>) -> LockResult {
        #[cfg(windows)]
        {
            Self::acquire_windows(name_suffix)
        }
        #[cfg(not(windows))]
        {
            Self::acquire_non_windows(name_suffix)
        }
    }

    /// Checks if another instance is currently holding the lock without claiming it.
    pub fn is_another_instance_running(name_suffix: Option<&str>) -> bool {
        #[cfg(windows)]
        {
            Self::is_running_windows(name_suffix)
        }
        #[cfg(not(windows))]
        {
            Self::is_running_non_windows(name_suffix)
        }
    }

    #[cfg(windows)]
    fn acquire_windows(name_suffix: Option<&str>) -> LockResult {
        use std::ptr::null_mut;
        use winapi::shared::sddl::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use winapi::shared::winerror::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};
        use winapi::um::errhandlingapi::{GetLastError, SetLastError};
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
        use winapi::um::synchapi::CreateMutexW;
        use winapi::um::winbase::LocalFree;

        let base_name = match name_suffix {
            Some(s) => format!("{}{}", Self::DEFAULT_MUTEX_NAME, s),
            None => Self::DEFAULT_MUTEX_NAME.to_string(),
        };

        let global_name = format!("Global\\{}", base_name);
        let global_wide: Vec<u16> = global_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let sddl_wide: Vec<u16> = Self::MUTEX_SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            SetLastError(0);
            let mut p_sd: *mut std::ffi::c_void = null_mut();
            let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
            sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
            sa.bInheritHandle = 0;

            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1 as u32,
                &mut p_sd as *mut _ as *mut _,
                null_mut(),
            ) != 0
            {
                sa.lpSecurityDescriptor = p_sd as *mut _;
            }

            let handle = CreateMutexW(&mut sa, 1, global_wide.as_ptr());
            let err = GetLastError();

            if !p_sd.is_null() {
                LocalFree(p_sd as *mut _);
            }

            if !handle.is_null() {
                if err == ERROR_ALREADY_EXISTS {
                    CloseHandle(handle);
                    return LockResult::AlreadyRunning;
                }
                return LockResult::Acquired(SingleInstanceGuard {
                    handle: handle as isize,
                    name: global_name,
                });
            }

            if err == ERROR_ACCESS_DENIED || err == ERROR_ALREADY_EXISTS {
                return LockResult::AlreadyRunning;
            }

            LockResult::Error(format!(
                "CreateMutexW failed for Global namespace (last error: {})",
                err
            ))
        }
    }

    #[cfg(windows)]
    fn is_running_windows(name_suffix: Option<&str>) -> bool {
        use winapi::shared::winerror::ERROR_ACCESS_DENIED;
        use winapi::um::errhandlingapi::{GetLastError, SetLastError};
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::synchapi::OpenMutexW;
        use winapi::um::winnt::SYNCHRONIZE;

        let base_name = match name_suffix {
            Some(s) => format!("{}{}", Self::DEFAULT_MUTEX_NAME, s),
            None => Self::DEFAULT_MUTEX_NAME.to_string(),
        };

        let global_name = format!("Global\\{}", base_name);
        let global_wide: Vec<u16> = global_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            SetLastError(0);
            let handle = OpenMutexW(SYNCHRONIZE, 0, global_wide.as_ptr());
            let err = GetLastError();

            if !handle.is_null() {
                CloseHandle(handle);
                return true;
            }

            if err == ERROR_ACCESS_DENIED {
                return true;
            }

            false
        }
    }

    #[cfg(not(windows))]
    fn acquire_non_windows(name_suffix: Option<&str>) -> LockResult {
        use std::collections::HashSet;
        use std::sync::Mutex;

        static ACTIVE_LOCKS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

        let name = match name_suffix {
            Some(s) => format!("Global\\{}{}", Self::DEFAULT_MUTEX_NAME, s),
            None => format!("Global\\{}", Self::DEFAULT_MUTEX_NAME),
        };

        let mut lock = ACTIVE_LOCKS.lock().unwrap();
        let set = lock.get_or_insert_with(HashSet::new);

        if set.contains(&name) {
            LockResult::AlreadyRunning
        } else {
            set.insert(name.clone());
            LockResult::Acquired(SingleInstanceGuard { name })
        }
    }

    #[cfg(not(windows))]
    fn is_running_non_windows(name_suffix: Option<&str>) -> bool {
        use std::collections::HashSet;
        use std::sync::Mutex;

        static ACTIVE_LOCKS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

        let name = match name_suffix {
            Some(s) => format!("Global\\{}{}", Self::DEFAULT_MUTEX_NAME, s),
            None => format!("Global\\{}", Self::DEFAULT_MUTEX_NAME),
        };

        let lock = ACTIVE_LOCKS.lock().unwrap();
        if let Some(set) = lock.as_ref() {
            set.contains(&name)
        } else {
            false
        }
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.handle != 0 {
                unsafe {
                    winapi::um::handleapi::CloseHandle(self.handle as *mut _);
                }
            }
        }
        #[cfg(not(windows))]
        {
            use std::collections::HashSet;
            use std::sync::Mutex;

            static ACTIVE_LOCKS: Mutex<Option<HashSet<String>>> = Mutex::new(None);
            let mut lock = ACTIVE_LOCKS.lock().unwrap();
            if let Some(set) = lock.as_mut() {
                set.remove(&self.name);
            }
        }
    }
}

/// Helper to launch the detached background `--core` daemon process
pub fn spawn_detached_core(
    exe_path: Option<&Path>,
    storage_dir: Option<&Path>,
    server_url: Option<&str>,
) -> std::io::Result<std::process::Child> {
    let exe = match exe_path {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe()?,
    };

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--core");
    if let Some(dir) = storage_dir {
        cmd.arg("--storage-dir").arg(dir);
    }
    if let Some(url) = server_url {
        cmd.arg("--server-url").arg(url);
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }

    cmd.spawn()
}

/// Cross-process shutdown signaling
pub struct ShutdownSignalListener {
    #[cfg(windows)]
    event_handle: isize,
    #[allow(dead_code)]
    name: String,
}

impl ShutdownSignalListener {
    pub const EVENT_SDDL: &'static str = "D:(A;;FA;;;SY)(A;;FA;;;BA)";

    pub fn get_event_sddl() -> &'static str {
        Self::EVENT_SDDL
    }

    pub fn new(name_suffix: Option<&str>) -> Self {
        #[cfg(windows)]
        {
            use std::ptr::null_mut;
            use winapi::shared::sddl::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            };
            use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
            use winapi::um::synchapi::CreateEventW;
            use winapi::um::winbase::LocalFree;

            let event_name = format!(
                "Global\\TemprisCollectorShutdownEvent{}",
                name_suffix.unwrap_or("")
            );
            let event_wide: Vec<u16> = event_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let sddl_wide: Vec<u16> = Self::EVENT_SDDL
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let mut p_sd: *mut std::ffi::c_void = null_mut();
                let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
                sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
                sa.bInheritHandle = 0;

                if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_wide.as_ptr(),
                    SDDL_REVISION_1 as u32,
                    &mut p_sd as *mut _ as *mut _,
                    null_mut(),
                ) != 0
                {
                    sa.lpSecurityDescriptor = p_sd as *mut _;
                }

                let handle = CreateEventW(&mut sa, 1, 0, event_wide.as_ptr());
                if !p_sd.is_null() {
                    LocalFree(p_sd as *mut _);
                }

                Self {
                    event_handle: handle as isize,
                    name: event_name,
                }
            }
        }
        #[cfg(not(windows))]
        {
            Self {
                name: format!(
                    "Global\\TemprisCollectorShutdownEvent{}",
                    name_suffix.unwrap_or("")
                ),
            }
        }
    }

    pub fn is_signaled(&self) -> bool {
        #[cfg(windows)]
        {
            if self.event_handle == 0 {
                return false;
            }
            unsafe {
                winapi::um::synchapi::WaitForSingleObject(self.event_handle as *mut _, 0) == 0
            }
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

impl Drop for ShutdownSignalListener {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.event_handle != 0 {
                unsafe {
                    winapi::um::handleapi::CloseHandle(self.event_handle as *mut _);
                }
            }
        }
    }
}

/// Signals any running background `--core` process to gracefully shut down.
pub fn signal_core_shutdown(name_suffix: Option<&str>) -> bool {
    #[cfg(windows)]
    {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::synchapi::{OpenEventW, SetEvent};
        use winapi::um::winnt::EVENT_MODIFY_STATE;

        let event_name = format!(
            "Global\\TemprisCollectorShutdownEvent{}",
            name_suffix.unwrap_or("")
        );
        let event_wide: Vec<u16> = event_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let handle = OpenEventW(EVENT_MODIFY_STATE, 0, event_wide.as_ptr());
            if !handle.is_null() {
                let res = SetEvent(handle);
                CloseHandle(handle);
                return res != 0;
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        let _ = name_suffix;
        true
    }
}

/// Waits for the background `--core` process to release its single-instance mutex.
pub fn wait_for_core_exit(name_suffix: Option<&str>, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if !SingleInstanceGuard::is_another_instance_running(name_suffix) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    !SingleInstanceGuard::is_another_instance_running(name_suffix)
}
