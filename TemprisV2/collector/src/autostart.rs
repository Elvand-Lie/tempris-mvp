use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::info;

use crate::singleton::{signal_core_shutdown, wait_for_core_exit, SingleInstanceGuard};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    /// Task exists, is enabled, and strictly satisfies all boot contract invariants
    Valid,
    /// Task is authoritatively absent from Task Scheduler (HRESULT 0x80070002 or 0x80041303)
    Missing,
    /// Task exists but trigger is not BootTrigger (e.g. legacy LogonTrigger)
    DriftTriggerMismatch,
    /// Task exists but principal is not SID S-1-5-18
    DriftAccountMismatch,
    /// Task exists but action executable path is not canonical or missing --core argument
    DriftActionMismatch,
    /// Task exists but execution limit is not PT0S or power/restart policies are drifted
    DriftSettingsMismatch,
    /// Task exists but is disabled in Task Scheduler
    Disabled,
    /// Query execution failed (e.g. ACCESS_DENIED, RPC/service outage, or COM failure)
    QueryError(String),
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperExitCode {
    Success = 0,
    InvalidArguments = 1,
    BinaryLockOrCopyFailed = 2,
    TaskCreateFailed = 3,
    TaskRemoveFailed = 4,
    ShutdownTimeout = 5,
    SecurityHardeningFailed = 6,
    TaskChangeFailed = 7,
    UnexpectedError = 10,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperResult {
    Success,
    Cancelled,
}

#[derive(Debug, Error)]
pub enum AutoStartError {
    #[error("UAC elevation cancelled by user")]
    Cancelled,
    #[error("Task scheduler execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Failed to determine current executable path: {0}")]
    ExePathError(String),
    #[error("Installation to stable location failed: {0}")]
    InstallError(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl PartialEq for AutoStartError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AutoStartError::Cancelled, AutoStartError::Cancelled) => true,
            (AutoStartError::ExecutionFailed(a), AutoStartError::ExecutionFailed(b)) => a == b,
            (AutoStartError::ExePathError(a), AutoStartError::ExePathError(b)) => a == b,
            (AutoStartError::InstallError(a), AutoStartError::InstallError(b)) => a == b,
            (AutoStartError::Io(a), AutoStartError::Io(b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}

/// Returns the stable protected installation path for the collector binary.
/// Defaults to `%PROGRAMDATA%\Tempris\Collector\bin\tempris-collector.exe`.
pub fn get_stable_install_path() -> PathBuf {
    if let Ok(progdata) = std::env::var("PROGRAMDATA") {
        PathBuf::from(progdata)
            .join("Tempris")
            .join("Collector")
            .join("bin")
            .join("tempris-collector.exe")
    } else if let Some(data_dir) = dirs::data_dir() {
        data_dir
            .join("Tempris")
            .join("Collector")
            .join("bin")
            .join("tempris-collector.exe")
    } else {
        PathBuf::from("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe")
    }
}

/// Ensures the collector executable is installed at the fixed protected installation path
/// with Observer Tier DACL before registering Task Scheduler auto-start.
pub fn ensure_installed_at_stable_path(
    source_exe: Option<&Path>,
) -> Result<PathBuf, AutoStartError> {
    let source = match source_exe {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe().map_err(|e| AutoStartError::ExePathError(e.to_string()))?,
    };

    let target = get_stable_install_path();

    // Canonicalize paths if possible for accurate comparison
    let source_canon = source.canonicalize().unwrap_or_else(|_| source.clone());
    let target_canon = target.canonicalize().unwrap_or_else(|_| target.clone());

    if source_canon != target_canon {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(windows)]
            let _ = crate::storage::win_sec::apply_observer_tier_dacl(parent);
        }

        let random_id = uuid::Uuid::new_v4().to_string();
        let tmp_target = target.with_extension(format!("tmp.{}", &random_id[..8]));

        std::fs::copy(&source, &tmp_target)?;

        #[cfg(windows)]
        let _ = crate::storage::win_sec::apply_observer_tier_dacl(&tmp_target);

        if let Err(e) = crate::storage::win_file::atomic_replace(&target, &tmp_target) {
            let _ = std::fs::remove_file(&tmp_target);
            return Err(AutoStartError::InstallError(format!(
                "Failed to atomically install collector to {:?}: {}",
                target, e
            )));
        }

        #[cfg(windows)]
        let _ = crate::storage::win_sec::apply_observer_tier_dacl(&target);

        info!(
            "Installed collector binary to stable location: {:?}",
            target
        );
    }

    Ok(target)
}

pub type HelperRunner = fn(&str, &str) -> Result<HelperResult, AutoStartError>;

/// Canonical SDDL defining the Scheduled Task Security Descriptor.
/// Grants Full Control to SYSTEM (SY) and Builtin Administrators (BA),
/// and Read-Only access (TASK_READ / FR) to Builtin Users (BU) for unelevated status queries.
/// Explicitly denies Builtin Users any write, delete, execute/run, stop, or modify permissions.
pub const TASK_SECURITY_DESCRIPTOR_SDDL: &'static str = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";

#[derive(Clone)]
pub struct AutoStartManager {
    task_name: String,
    helper_runner: Option<HelperRunner>,
}

impl std::fmt::Debug for AutoStartManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoStartManager")
            .field("task_name", &self.task_name)
            .field("has_custom_helper", &self.helper_runner.is_some())
            .finish()
    }
}

impl Default for AutoStartManager {
    fn default() -> Self {
        Self::new(None)
    }
}

impl AutoStartManager {
    pub const DEFAULT_TASK_NAME: &'static str = "TemprisCollectorCore";

    /// Creates a new AutoStartManager with the specified task name, or default if None.
    pub fn new(task_name: Option<&str>) -> Self {
        Self {
            task_name: task_name.unwrap_or(Self::DEFAULT_TASK_NAME).to_string(),
            helper_runner: None,
        }
    }

    /// Creates a new AutoStartManager with custom helper runner for testing / dependency injection.
    pub fn with_helper_runner(task_name: Option<&str>, runner: HelperRunner) -> Self {
        Self {
            task_name: task_name.unwrap_or(Self::DEFAULT_TASK_NAME).to_string(),
            helper_runner: Some(runner),
        }
    }

    /// Sets or clears the custom helper runner.
    pub fn set_helper_runner(&mut self, runner: Option<HelperRunner>) {
        self.helper_runner = runner;
    }

    /// Returns the configured task name.
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    /// Generates canonical Task Scheduler XML definition for True Boot Autostart (SYSTEM / ONSTART).
    pub fn generate_task_xml(exe_path: &Path, task_name: &str) -> String {
        let exe_str = exe_path.to_string_lossy();
        let normalized_exe = exe_str.strip_prefix(r"\\?\").unwrap_or(&exe_str);
        let working_dir = exe_path
            .parent()
            .and_then(|p| p.parent())
            .map(|p| {
                let p_str = p.to_string_lossy();
                p_str.strip_prefix(r"\\?\").unwrap_or(&p_str).to_string()
            })
            .unwrap_or_else(|| "C:\\ProgramData\\Tempris\\Collector".to_string());

        format!(
            r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Tempris V2 Internal Asset Reachability Collector Core Daemon</Description>
    <URI>\{task_name}</URI>
    <SecurityDescriptor>{sddl}</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe_str}</Command>
      <Arguments>--core</Arguments>
      <WorkingDirectory>{working_dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#,
            task_name = task_name,
            sddl = TASK_SECURITY_DESCRIPTOR_SDDL,
            exe_str = normalized_exe,
            working_dir = working_dir
        )
    }

    /// Maps exact Win32 HRESULT status codes to strongly typed `TaskStatus`.
    pub fn map_hresult_to_status(hr: i32) -> TaskStatus {
        const SCHED_E_TASK_NOT_FOUND: i32 = 0x80041303_u32 as i32;
        const SCHED_E_SERVICE_NOT_RUNNING: i32 = 0x80041315_u32 as i32;
        const RPC_S_SERVER_UNAVAILABLE: i32 = 0x800706BA_u32 as i32;
        const E_ACCESSDENIED: i32 = 0x80070005_u32 as i32;
        const ERROR_FILE_NOT_FOUND_HR: i32 = 0x80070002_u32 as i32;

        if hr == ERROR_FILE_NOT_FOUND_HR || hr == SCHED_E_TASK_NOT_FOUND {
            TaskStatus::Missing
        } else if hr == E_ACCESSDENIED {
            TaskStatus::QueryError("Task query access denied (E_ACCESSDENIED)".into())
        } else if hr == RPC_S_SERVER_UNAVAILABLE || hr == SCHED_E_SERVICE_NOT_RUNNING {
            TaskStatus::QueryError(
                "Task Scheduler service unavailable (RPC_S_SERVER_UNAVAILABLE)".into(),
            )
        } else if hr == 0 {
            TaskStatus::Valid
        } else {
            TaskStatus::QueryError(format!("Task query failed with HRESULT: 0x{:08X}", hr))
        }
    }

    /// Parses Task Scheduler XML definition to verify contract invariants.
    pub fn parse_query_xml(xml: &str, expected_bin: &Path) -> TaskStatus {
        #[cfg(windows)]
        {
            use quick_xml::events::Event;
            use quick_xml::reader::Reader;

            let mut reader = Reader::from_str(xml);
            reader.config_mut().trim_text(true);

            let mut has_boot_trigger = false;
            let mut has_logon_trigger = false;
            let mut user_id: Option<String> = None;
            let mut logon_type: Option<String> = None;
            let mut run_level: Option<String> = None;
            let mut command: Option<String> = None;
            let mut arguments: Option<String> = None;
            let mut execution_time_limit: Option<String> = None;
            let mut disallow_batteries: Option<String> = None;
            let mut stop_batteries: Option<String> = None;
            let mut multiple_instances: Option<String> = None;
            let mut task_enabled: Option<String> = None;

            let mut current_tag = Vec::new();
            let mut buf = Vec::new();

            loop {
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Start(e)) => {
                        let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                        if name == "BootTrigger" {
                            has_boot_trigger = true;
                        } else if name == "LogonTrigger" {
                            has_logon_trigger = true;
                        }
                        current_tag.push(name);
                    }
                    Ok(Event::End(_)) => {
                        current_tag.pop();
                    }
                    Ok(Event::Empty(e)) => {
                        let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                        if name == "BootTrigger" {
                            has_boot_trigger = true;
                        } else if name == "LogonTrigger" {
                            has_logon_trigger = true;
                        }
                    }
                    Ok(Event::Text(e)) => {
                        let text = match e.unescape() {
                            Ok(t) => t.into_owned(),
                            Err(_) => String::from_utf8_lossy(e.as_ref()).to_string(),
                        };
                        let tag = current_tag.last().map(|s| s.as_str()).unwrap_or("");
                        match tag {
                            "UserId" => user_id = Some(text),
                            "LogonType" => logon_type = Some(text),
                            "RunLevel" => run_level = Some(text),
                            "Command" => command = Some(text),
                            "Arguments" => arguments = Some(text),
                            "ExecutionTimeLimit" => execution_time_limit = Some(text),
                            "DisallowStartIfOnBatteries" => disallow_batteries = Some(text),
                            "StopIfGoingOnBatteries" => stop_batteries = Some(text),
                            "MultipleInstancesPolicy" => multiple_instances = Some(text),
                            "Enabled" => {
                                task_enabled = Some(text);
                            }
                            _ => {}
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(e) => return TaskStatus::QueryError(format!("XML parse error: {}", e)),
                    _ => {}
                }
                buf.clear();
            }

            if let Some(en) = task_enabled {
                if en.trim().eq_ignore_ascii_case("false") {
                    return TaskStatus::Disabled;
                }
            }

            if has_logon_trigger || !has_boot_trigger {
                return TaskStatus::DriftTriggerMismatch;
            }

            if let Some(uid) = user_id {
                if uid.trim() != "S-1-5-18" {
                    return TaskStatus::DriftAccountMismatch;
                }
            } else {
                return TaskStatus::DriftAccountMismatch;
            }

            if let Some(rl) = run_level {
                if rl.trim() != "HighestAvailable" {
                    return TaskStatus::DriftAccountMismatch;
                }
            } else {
                return TaskStatus::DriftAccountMismatch;
            }

            if logon_type.is_some() {
                return TaskStatus::DriftAccountMismatch;
            }

            if let Some(cmd) = command {
                let normalized_cmd = cmd.trim().trim_matches('"').replace('/', "\\");
                let expected_cmd = expected_bin
                    .to_string_lossy()
                    .trim()
                    .trim_matches('"')
                    .replace('/', "\\");
                if !normalized_cmd.eq_ignore_ascii_case(&expected_cmd) {
                    return TaskStatus::DriftActionMismatch;
                }
            } else {
                return TaskStatus::DriftActionMismatch;
            }

            if let Some(args) = arguments {
                if !args.contains("--core") {
                    return TaskStatus::DriftActionMismatch;
                }
            } else {
                return TaskStatus::DriftActionMismatch;
            }

            if let Some(etl) = execution_time_limit {
                if etl.trim() != "PT0S" {
                    return TaskStatus::DriftSettingsMismatch;
                }
            }

            if let Some(db) = disallow_batteries {
                if db.trim().eq_ignore_ascii_case("true") {
                    return TaskStatus::DriftSettingsMismatch;
                }
            }

            if let Some(sb) = stop_batteries {
                if sb.trim().eq_ignore_ascii_case("true") {
                    return TaskStatus::DriftSettingsMismatch;
                }
            }

            if let Some(mip) = multiple_instances {
                if mip.trim() != "IgnoreNew" && mip.trim() != "0" {
                    return TaskStatus::DriftSettingsMismatch;
                }
            }

            TaskStatus::Valid
        }
        #[cfg(not(windows))]
        {
            let _ = (xml, expected_bin);
            TaskStatus::Valid
        }
    }

    /// Maps helper process exit code to Result<HelperResult, AutoStartError>.
    pub fn map_exit_code_to_result(exit_code: u32) -> Result<HelperResult, AutoStartError> {
        match exit_code {
            0 => Ok(HelperResult::Success),
            1 => Err(AutoStartError::ExecutionFailed(
                "Invalid helper arguments".into(),
            )),
            2 => Err(AutoStartError::InstallError(
                "Binary copy or file lock acquisition failed".into(),
            )),
            3 => Err(AutoStartError::ExecutionFailed(
                "Task Scheduler XML registration failed".into(),
            )),
            4 => Err(AutoStartError::ExecutionFailed(
                "Task Scheduler task deletion failed".into(),
            )),
            5 => Err(AutoStartError::ExecutionFailed(
                "Core daemon shutdown timed out".into(),
            )),
            6 => Err(AutoStartError::InstallError(
                "Security hardening or ownership transfer failed".into(),
            )),
            7 => Err(AutoStartError::ExecutionFailed(
                "Task Scheduler task state change (enable/disable) failed".into(),
            )),
            code => Err(AutoStartError::ExecutionFailed(format!(
                "Helper failed with exit code {}",
                code
            ))),
        }
    }

    /// Maps ShellExecuteExW GetLastError code to HelperResult.
    pub fn map_win32_error_to_helper_result(err: u32) -> Result<HelperResult, AutoStartError> {
        if err == 1223 {
            Ok(HelperResult::Cancelled)
        } else {
            Err(AutoStartError::ExecutionFailed(format!(
                "ShellExecuteExW failed: error {}",
                err
            )))
        }
    }

    /// Queries authoritative task status via native COM.
    pub fn query_status(&self) -> TaskStatus {
        let stable_bin = get_stable_install_path();
        query_task_status_native(&self.task_name, &stable_bin)
    }

    /// Queries detailed task status.
    pub fn query_detailed_status(&self) -> TaskStatus {
        self.query_status()
    }

    /// Registers the Scheduled Task via the elevated UAC helper.
    pub fn register(&self, _exe_path: Option<&Path>) -> Result<PathBuf, AutoStartError> {
        let stable_bin = get_stable_install_path();
        if let Some(runner) = self.helper_runner {
            let res = runner("install", &self.task_name)?;
            match res {
                HelperResult::Success => Ok(stable_bin),
                HelperResult::Cancelled => Err(AutoStartError::Cancelled),
            }
        } else {
            #[cfg(windows)]
            {
                let res = spawn_uac_helper("install", &self.task_name)?;
                match res {
                    HelperResult::Success => Ok(stable_bin),
                    HelperResult::Cancelled => Err(AutoStartError::Cancelled),
                }
            }
            #[cfg(not(windows))]
            {
                info!(
                    "Non-Windows environment: skipped schtasks registration for '{}'",
                    self.task_name
                );
                Ok(stable_bin)
            }
        }
    }

    /// Unregisters and deletes the Scheduled Task via the elevated UAC helper.
    pub fn unregister(&self) -> Result<(), AutoStartError> {
        if self.query_status() == TaskStatus::Missing {
            return Ok(());
        }
        if let Some(runner) = self.helper_runner {
            let res = runner("remove", &self.task_name)?;
            match res {
                HelperResult::Success => Ok(()),
                HelperResult::Cancelled => Err(AutoStartError::Cancelled),
            }
        } else {
            #[cfg(windows)]
            {
                let res = spawn_uac_helper("remove", &self.task_name)?;
                match res {
                    HelperResult::Success => Ok(()),
                    HelperResult::Cancelled => Err(AutoStartError::Cancelled),
                }
            }
            #[cfg(not(windows))]
            {
                info!(
                    "Non-Windows environment: skipped schtasks unregistration for '{}'",
                    self.task_name
                );
                Ok(())
            }
        }
    }

    /// Enables the Scheduled Task via the elevated UAC helper.
    pub fn enable(&self) -> Result<(), AutoStartError> {
        if let Some(runner) = self.helper_runner {
            let res = runner("enable", &self.task_name)?;
            match res {
                HelperResult::Success => Ok(()),
                HelperResult::Cancelled => Err(AutoStartError::Cancelled),
            }
        } else {
            #[cfg(windows)]
            {
                let res = spawn_uac_helper("enable", &self.task_name)?;
                match res {
                    HelperResult::Success => Ok(()),
                    HelperResult::Cancelled => Err(AutoStartError::Cancelled),
                }
            }
            #[cfg(not(windows))]
            {
                info!(
                    "Non-Windows environment: skipped schtasks enable for '{}'",
                    self.task_name
                );
                Ok(())
            }
        }
    }

    /// Disables the Scheduled Task via the elevated UAC helper.
    /// Disables future boot startup only without stopping core or wiping identity.
    pub fn disable(&self) -> Result<(), AutoStartError> {
        if let Some(runner) = self.helper_runner {
            let res = runner("disable", &self.task_name)?;
            match res {
                HelperResult::Success => Ok(()),
                HelperResult::Cancelled => Err(AutoStartError::Cancelled),
            }
        } else {
            #[cfg(windows)]
            {
                let res = spawn_uac_helper("disable", &self.task_name)?;
                match res {
                    HelperResult::Success => Ok(()),
                    HelperResult::Cancelled => Err(AutoStartError::Cancelled),
                }
            }
            #[cfg(not(windows))]
            {
                info!(
                    "Non-Windows environment: skipped schtasks disable for '{}'",
                    self.task_name
                );
                Ok(())
            }
        }
    }

    /// Checks if the Scheduled Task is registered and valid.
    pub fn is_registered(&self) -> bool {
        self.query_status() == TaskStatus::Valid
    }

    /// Validates Task Scheduler XML in-memory using COM Schedule.Service NewTask(0).
    /// This performs read-only validation in memory without registering or persisting any task.
    #[cfg(windows)]
    pub fn validate_task_xml_in_memory(xml: &str) -> Result<String, i32> {
        use std::ptr::null_mut;
        use winapi::shared::winerror::{S_FALSE, S_OK};
        use winapi::shared::wtypesbase::CLSCTX_INPROC_SERVER;
        use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx, CoUninitialize};
        use winapi::um::oaidl::VARIANT;
        use winapi::um::objbase::COINIT_MULTITHREADED;
        use winapi::um::oleauto::{SysAllocString, SysFreeString, SysStringLen};
        use winapi::um::taskschd::{ITaskDefinition, ITaskService, TaskScheduler};
        use winapi::{Class, Interface};

        unsafe {
            let hr = CoInitializeEx(null_mut(), COINIT_MULTITHREADED);
            let co_initialized = hr == S_OK || hr == S_FALSE;

            let mut service_ptr: *mut ITaskService = null_mut();
            let hr = CoCreateInstance(
                &TaskScheduler::uuidof(),
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &ITaskService::uuidof(),
                &mut service_ptr as *mut _ as *mut _,
            );

            if hr != S_OK || service_ptr.is_null() {
                if co_initialized {
                    CoUninitialize();
                }
                return Err(hr);
            }

            let service = &*service_ptr;
            let empty_var: VARIANT = std::mem::zeroed();
            let hr = service.Connect(empty_var, empty_var, empty_var, empty_var);
            if hr != S_OK {
                service.Release();
                if co_initialized {
                    CoUninitialize();
                }
                return Err(hr);
            }

            let mut task_def_ptr: *mut ITaskDefinition = null_mut();
            let hr = service.NewTask(0, &mut task_def_ptr);
            if hr != S_OK || task_def_ptr.is_null() {
                service.Release();
                if co_initialized {
                    CoUninitialize();
                }
                return Err(hr);
            }

            let task_def = &*task_def_ptr;

            let wide_xml: Vec<u16> = xml
                .trim()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let xml_bstr = SysAllocString(wide_xml.as_ptr());

            let put_hr = task_def.put_XmlText(xml_bstr);
            SysFreeString(xml_bstr);

            let result = if put_hr == S_OK {
                let mut exported_bstr: *mut u16 = null_mut();
                let get_hr = task_def.get_XmlText(&mut exported_bstr);
                if get_hr == S_OK && !exported_bstr.is_null() {
                    let len = SysStringLen(exported_bstr) as usize;
                    let slice = std::slice::from_raw_parts(exported_bstr, len);
                    let exported_str = String::from_utf16_lossy(slice);
                    SysFreeString(exported_bstr);
                    Ok(exported_str)
                } else {
                    Ok(String::new())
                }
            } else {
                Err(put_hr)
            };

            task_def.Release();
            service.Release();
            if co_initialized {
                CoUninitialize();
            }

            result
        }
    }

    #[cfg(not(windows))]
    pub fn validate_task_xml_in_memory(_xml: &str) -> Result<String, i32> {
        Ok(String::new())
    }
}

/// Queries Task Scheduler 2.0 COM interface directly for the specified task name.
#[cfg(windows)]
pub fn query_task_status_native(task_name: &str, expected_bin: &Path) -> TaskStatus {
    use std::ptr::null_mut;
    use winapi::shared::winerror::{
        ERROR_FILE_NOT_FOUND, E_ACCESSDENIED, HRESULT_FROM_WIN32, S_FALSE, S_OK,
    };
    use winapi::shared::wtypesbase::CLSCTX_INPROC_SERVER;
    use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx, CoUninitialize};
    use winapi::um::oaidl::VARIANT;
    use winapi::um::objbase::COINIT_MULTITHREADED;
    use winapi::um::oleauto::{SysAllocString, SysFreeString, SysStringLen};
    use winapi::um::taskschd::{IRegisteredTask, ITaskFolder, ITaskService, TaskScheduler};
    use winapi::{Class, Interface};

    const SCHED_E_TASK_NOT_FOUND: i32 = 0x80041303_u32 as i32;

    unsafe {
        let hr = CoInitializeEx(null_mut(), COINIT_MULTITHREADED);
        let co_initialized = hr == S_OK || hr == S_FALSE;

        let mut service_ptr: *mut ITaskService = null_mut();
        let hr = CoCreateInstance(
            &TaskScheduler::uuidof(),
            null_mut(),
            CLSCTX_INPROC_SERVER,
            &ITaskService::uuidof(),
            &mut service_ptr as *mut _ as *mut _,
        );

        if hr != S_OK || service_ptr.is_null() {
            if co_initialized {
                CoUninitialize();
            }
            return AutoStartManager::map_hresult_to_status(hr);
        }

        let service = &*service_ptr;
        let empty_var: VARIANT = std::mem::zeroed();
        let hr = service.Connect(empty_var, empty_var, empty_var, empty_var);
        if hr != S_OK {
            service.Release();
            if co_initialized {
                CoUninitialize();
            }
            return AutoStartManager::map_hresult_to_status(hr);
        }

        let root_wide: Vec<u16> = "\\\0".encode_utf16().collect();
        let root_bstr = SysAllocString(root_wide.as_ptr());
        let mut folder_ptr: *mut ITaskFolder = null_mut();
        let hr = service.GetFolder(root_bstr, &mut folder_ptr);
        SysFreeString(root_bstr);

        if hr != S_OK || folder_ptr.is_null() {
            service.Release();
            if co_initialized {
                CoUninitialize();
            }
            return AutoStartManager::map_hresult_to_status(hr);
        }

        let folder = &*folder_ptr;
        let task_wide: Vec<u16> = task_name.encode_utf16().chain(std::iter::once(0)).collect();
        let task_bstr = SysAllocString(task_wide.as_ptr());
        let mut reg_task_ptr: *mut IRegisteredTask = null_mut();
        let hr = folder.GetTask(task_bstr, &mut reg_task_ptr);
        SysFreeString(task_bstr);

        let result =
            if hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr == SCHED_E_TASK_NOT_FOUND {
                TaskStatus::Missing
            } else if hr == E_ACCESSDENIED {
                TaskStatus::QueryError("Task query access denied (E_ACCESSDENIED)".into())
            } else if hr == S_OK && !reg_task_ptr.is_null() {
                let reg_task = &*reg_task_ptr;
                let mut xml_bstr: *mut u16 = null_mut();
                let xml_hr = reg_task.get_Xml(&mut xml_bstr);
                if xml_hr == S_OK && !xml_bstr.is_null() {
                    let len = SysStringLen(xml_bstr) as usize;
                    let slice = std::slice::from_raw_parts(xml_bstr, len);
                    let xml_str = String::from_utf16_lossy(slice);
                    SysFreeString(xml_bstr);
                    AutoStartManager::parse_query_xml(&xml_str, expected_bin)
                } else {
                    TaskStatus::QueryError(format!(
                        "Failed to read task XML (HRESULT: 0x{:08X})",
                        xml_hr
                    ))
                }
            } else {
                AutoStartManager::map_hresult_to_status(hr)
            };

        if !reg_task_ptr.is_null() {
            (*reg_task_ptr).Release();
        }
        folder.Release();
        service.Release();
        if co_initialized {
            CoUninitialize();
        }

        result
    }
}

#[cfg(not(windows))]
pub fn query_task_status_native(_task_name: &str, _expected_bin: &Path) -> TaskStatus {
    TaskStatus::Valid
}

/// Spawns elevated `--uac-helper` process via ShellExecuteExW (`runas`).
#[cfg(windows)]
pub fn spawn_uac_helper(action: &str, task_name: &str) -> Result<HelperResult, AutoStartError> {
    let stable_bin = get_stable_install_path();
    let exe_to_elevate = if stable_bin.exists() && action != "install" {
        stable_bin
    } else {
        std::env::current_exe().map_err(|e| AutoStartError::ExePathError(e.to_string()))?
    };

    let exe_str = exe_to_elevate.to_string_lossy();
    let normalized_exe = exe_str.strip_prefix(r"\\?\").unwrap_or(&exe_str);

    let parameters = format!("--uac-helper {} --task-name \"{}\"", action, task_name);

    let wide_exe: Vec<u16> = normalized_exe
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let wide_params: Vec<u16> = parameters
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let wide_verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();

    let mut sei = winapi::um::shellapi::SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<winapi::um::shellapi::SHELLEXECUTEINFOW>() as u32,
        fMask: winapi::um::shellapi::SEE_MASK_NOCLOSEPROCESS,
        hwnd: std::ptr::null_mut(),
        lpVerb: wide_verb.as_ptr(),
        lpFile: wide_exe.as_ptr(),
        lpParameters: wide_params.as_ptr(),
        lpDirectory: std::ptr::null(),
        nShow: winapi::um::winuser::SW_HIDE,
        hInstApp: std::ptr::null_mut(),
        ..unsafe { std::mem::zeroed() }
    };

    let ok = unsafe { winapi::um::shellapi::ShellExecuteExW(&mut sei) };
    if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        return AutoStartManager::map_win32_error_to_helper_result(err);
    }

    if sei.hProcess.is_null() {
        return Err(AutoStartError::ExecutionFailed(
            "ShellExecuteExW did not return a valid process handle".into(),
        ));
    }

    let wait_res = unsafe { winapi::um::synchapi::WaitForSingleObject(sei.hProcess, 30000) };
    if wait_res != 0 {
        unsafe {
            winapi::um::handleapi::CloseHandle(sei.hProcess);
        }
        return Err(AutoStartError::ExecutionFailed(
            "UAC helper process timed out".into(),
        ));
    }

    let mut exit_code: u32 = 0;
    unsafe {
        winapi::um::processthreadsapi::GetExitCodeProcess(sei.hProcess, &mut exit_code);
        winapi::um::handleapi::CloseHandle(sei.hProcess);
    }

    AutoStartManager::map_exit_code_to_result(exit_code)
}

#[cfg(not(windows))]
pub fn spawn_uac_helper(_action: &str, _task_name: &str) -> Result<HelperResult, AutoStartError> {
    Ok(HelperResult::Success)
}

/// Executes internal elevated UAC helper commands. Returns process exit code.
pub fn handle_uac_helper_cli(action: &str, task_name_override: Option<&str>) -> i32 {
    let task_name = task_name_override.unwrap_or(AutoStartManager::DEFAULT_TASK_NAME);
    match action {
        "install" => {
            // 1. Install binary to stable location if needed
            let target_bin = get_stable_install_path();
            let current_exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return HelperExitCode::UnexpectedError as i32,
            };

            let target_existed_before = target_bin.exists();

            let needs_copy = match (std::fs::read(&current_exe), std::fs::read(&target_bin)) {
                (Ok(cur_bytes), Ok(target_bytes)) => cur_bytes != target_bytes,
                _ => true,
            };

            if needs_copy {
                // If core daemon is running, signal shutdown and wait
                if SingleInstanceGuard::is_another_instance_running(None) {
                    let _ = signal_core_shutdown(None);
                    if !wait_for_core_exit(None, std::time::Duration::from_millis(5000)) {
                        let _ = Command::new("schtasks")
                            .args(&["/End", "/TN", task_name])
                            .output();
                        if !wait_for_core_exit(None, std::time::Duration::from_millis(3000)) {
                            return HelperExitCode::ShutdownTimeout as i32;
                        }
                    }
                }

                if let Some(parent) = target_bin.parent() {
                    let _ = std::fs::create_dir_all(parent);
                    #[cfg(windows)]
                    let _ = crate::storage::win_sec::apply_observer_tier_dacl(parent);
                }

                let tmp_target = target_bin.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
                if std::fs::copy(&current_exe, &tmp_target).is_err() {
                    return HelperExitCode::BinaryLockOrCopyFailed as i32;
                }

                #[cfg(windows)]
                let _ = crate::storage::win_sec::apply_observer_tier_dacl(&tmp_target);

                if crate::storage::win_file::atomic_replace(&target_bin, &tmp_target).is_err() {
                    let _ = std::fs::remove_file(&tmp_target);
                    return HelperExitCode::BinaryLockOrCopyFailed as i32;
                }

                #[cfg(windows)]
                let _ = crate::storage::win_sec::apply_observer_tier_dacl(&target_bin);
            }

            // 2. Harden Secret Tier ownership & DACL
            let storage = crate::storage::StorageManager::default_machine_storage();
            let secret_path = storage.protected_identity_path();
            #[cfg(windows)]
            {
                if secret_path.exists() {
                    if crate::storage::win_sec::transfer_ownership_to_administrators(&secret_path)
                        .is_err()
                    {
                        return HelperExitCode::SecurityHardeningFailed as i32;
                    }
                    if crate::storage::win_sec::apply_secret_tier_dacl(&secret_path).is_err() {
                        return HelperExitCode::SecurityHardeningFailed as i32;
                    }
                }
            }

            let staging_dir = storage.staging_dir();
            let _ = std::fs::create_dir_all(&staging_dir);
            #[cfg(windows)]
            {
                if crate::storage::win_sec::transfer_ownership_to_administrators(&staging_dir)
                    .is_err()
                {
                    return HelperExitCode::SecurityHardeningFailed as i32;
                }
                if crate::storage::win_sec::apply_secret_tier_dacl(&staging_dir).is_err() {
                    return HelperExitCode::SecurityHardeningFailed as i32;
                }
            }

            // Helper closure to perform rollback on task creation failure
            let rollback_on_failure = |xml_path: Option<&Path>| {
                if let Some(p) = xml_path {
                    let _ = std::fs::remove_file(p);
                }
                // Clean up any temporary xml/tmp files in staging_dir
                if let Ok(entries) = std::fs::read_dir(&staging_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension()
                            .map(|e| e == "xml" || e == "tmp")
                            .unwrap_or(false)
                        {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                }
                // Remove corrupted or incomplete task if created
                let _ = Command::new("schtasks")
                    .args(&["/Delete", "/TN", task_name, "/F"])
                    .output();
                // If binary didn't exist before this failed install, roll back binary
                if !target_existed_before && target_bin.exists() {
                    let _ = std::fs::remove_file(&target_bin);
                }
            };

            let logger = crate::logging::BoundedLogger::new(storage.logs_dir());

            // 3. Staging XML generation & task registration
            let xml_content = AutoStartManager::generate_task_xml(&target_bin, task_name);
            let xml_filename = format!("task_def_{}.xml", uuid::Uuid::new_v4());
            let xml_path = staging_dir.join(&xml_filename);

            if std::fs::write(&xml_path, xml_content.as_bytes()).is_err() {
                logger.log(
                    "ERROR",
                    &format!(
                        "Failed to write staging task XML for '{}' to {:?}",
                        task_name, xml_path
                    ),
                );
                tracing::error!(
                    task_name = task_name,
                    xml_path = ?xml_path,
                    "Failed to write staging task XML"
                );
                rollback_on_failure(Some(&xml_path));
                return HelperExitCode::TaskCreateFailed as i32;
            }

            #[cfg(windows)]
            let _ = crate::storage::win_sec::apply_secret_tier_dacl(&xml_path);

            let create_output = Command::new("schtasks")
                .args(&[
                    "/Create",
                    "/TN",
                    task_name,
                    "/XML",
                    &xml_path.to_string_lossy(),
                    "/F",
                ])
                .output();

            let _ = std::fs::remove_file(&xml_path);

            match create_output {
                Ok(out) if out.status.success() => {
                    logger.log(
                        "INFO",
                        &format!(
                            "schtasks /Create successfully registered task '{}'",
                            task_name
                        ),
                    );
                }
                Ok(out) => {
                    let code = out.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    logger.log(
                        "ERROR",
                        &format!(
                            "schtasks /Create failed for '{}' (exit {}): stderr='{}', stdout='{}'",
                            task_name,
                            code,
                            stderr.trim(),
                            stdout.trim()
                        ),
                    );
                    tracing::error!(
                        task_name = task_name,
                        exit_code = code,
                        stderr = %stderr.trim(),
                        stdout = %stdout.trim(),
                        "schtasks /Create failed"
                    );
                    rollback_on_failure(None);
                    return HelperExitCode::TaskCreateFailed as i32;
                }
                Err(e) => {
                    logger.log(
                        "ERROR",
                        &format!(
                            "schtasks /Create failed to execute for '{}': {}",
                            task_name, e
                        ),
                    );
                    tracing::error!(
                        task_name = task_name,
                        error = %e,
                        "schtasks /Create process execution error"
                    );
                    rollback_on_failure(None);
                    return HelperExitCode::TaskCreateFailed as i32;
                }
            }

            // 4. Post-registration query verification
            let status = query_task_status_native(task_name, &target_bin);
            if status != TaskStatus::Valid {
                logger.log(
                    "ERROR",
                    &format!(
                        "Post-registration validation failed for task '{}': status is {:?}",
                        task_name, status
                    ),
                );
                tracing::error!(
                    task_name = task_name,
                    status = ?status,
                    "Post-registration task validation failed"
                );
                rollback_on_failure(None);
                return HelperExitCode::TaskCreateFailed as i32;
            }

            // 5. Trigger daemon execution directly from elevated helper
            let _ = Command::new("schtasks")
                .args(&["/Run", "/TN", task_name])
                .output();

            HelperExitCode::Success as i32
        }
        "remove" => {
            if SingleInstanceGuard::is_another_instance_running(None) {
                let _ = signal_core_shutdown(None);
                let _ = wait_for_core_exit(None, std::time::Duration::from_millis(5000));
            }

            let output = Command::new("schtasks")
                .args(&["/Delete", "/TN", task_name, "/F"])
                .output();

            match output {
                Ok(out) if out.status.success() => HelperExitCode::Success as i32,
                _ => {
                    let target_bin = get_stable_install_path();
                    if query_task_status_native(task_name, &target_bin) == TaskStatus::Missing {
                        HelperExitCode::Success as i32
                    } else {
                        HelperExitCode::TaskRemoveFailed as i32
                    }
                }
            }
        }
        "enable" => {
            let output = Command::new("schtasks")
                .args(&["/Change", "/TN", task_name, "/Enable"])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let target_bin = get_stable_install_path();
                    let status = query_task_status_native(task_name, &target_bin);
                    if status == TaskStatus::Valid {
                        HelperExitCode::Success as i32
                    } else {
                        HelperExitCode::TaskChangeFailed as i32
                    }
                }
                _ => HelperExitCode::TaskChangeFailed as i32,
            }
        }
        "disable" => {
            let output = Command::new("schtasks")
                .args(&["/Change", "/TN", task_name, "/Disable"])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let target_bin = get_stable_install_path();
                    let status = query_task_status_native(task_name, &target_bin);
                    if status == TaskStatus::Disabled {
                        HelperExitCode::Success as i32
                    } else {
                        HelperExitCode::TaskChangeFailed as i32
                    }
                }
                _ => HelperExitCode::TaskChangeFailed as i32,
            }
        }
        "stop" => {
            let _ = signal_core_shutdown(None);
            if wait_for_core_exit(None, std::time::Duration::from_millis(5000)) {
                HelperExitCode::Success as i32
            } else {
                HelperExitCode::ShutdownTimeout as i32
            }
        }
        "query" => {
            let target_bin = get_stable_install_path();
            let status = query_task_status_native(task_name, &target_bin);
            match status {
                TaskStatus::Valid => HelperExitCode::Success as i32,
                TaskStatus::Missing => HelperExitCode::InvalidArguments as i32,
                _ => HelperExitCode::UnexpectedError as i32,
            }
        }
        _ => HelperExitCode::InvalidArguments as i32,
    }
}
