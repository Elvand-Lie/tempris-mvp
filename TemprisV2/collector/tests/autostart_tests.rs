use chrono::{Duration, Utc};
use std::path::Path;
use tempris_collector::autostart::{
    AutoStartError, AutoStartManager, HelperExitCode, HelperResult, TaskStatus,
    TASK_SECURITY_DESCRIPTOR_SDDL,
};
use tempris_collector::client::ConnectionStatus;
use tempris_collector::lifecycle::{RuntimeSnapshot, RuntimeStatus};
use tempris_collector::singleton::{ShutdownSignalListener, SingleInstanceGuard};
use tempris_collector::storage::StorageManager;
use tempris_collector::ui::{derive_connection_status, CollectorApp};
use uuid::Uuid;

#[test]
fn test_generate_task_xml_contains_all_contract_invariants() {
    let exe_path = Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe");
    let xml = AutoStartManager::generate_task_xml(exe_path, "TemprisCollectorCore");

    assert!(xml.starts_with("<Task"));
    assert!(!xml.contains("encoding="));
    assert!(!xml.contains("<?xml"));
    assert!(xml.contains("<BootTrigger>"));
    assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
    assert!(!xml.contains("<LogonType>"));
    assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
    assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
    assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
    assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
    assert!(xml.contains("<StartWhenAvailable>true</StartWhenAvailable>"));
    assert!(xml.contains("<RestartOnFailure>"));
    assert!(xml.contains(
        "<Command>C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe</Command>"
    ));
    assert!(xml.contains("<Arguments>--core</Arguments>"));
    assert!(xml.contains(
        "<SecurityDescriptor>D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)</SecurityDescriptor>"
    ));
}

#[test]
fn test_task_security_descriptor_sddl_permissions_and_invariants() {
    // Exact SDDL check
    assert_eq!(
        TASK_SECURITY_DESCRIPTOR_SDDL,
        "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"
    );

    // 1. Must be a DACL
    assert!(TASK_SECURITY_DESCRIPTOR_SDDL.starts_with("D:"));

    // 2. Full control for SYSTEM (S-1-5-18)
    assert!(TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;FA;;;SY)"));

    // 3. Full control for Builtin Administrators (S-1-5-32-544)
    assert!(TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;FA;;;BA)"));

    // 4. READ-ONLY access (FR / FILE_GENERIC_READ) for Builtin Users (S-1-5-32-545)
    assert!(TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;FR;;;BU)"));

    // 5. Must NOT grant Builtin Users full access, write access, or execution access
    assert!(!TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;FA;;;BU)"));
    assert!(!TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;FW;;;BU)"));
    assert!(!TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;FX;;;BU)"));
    assert!(!TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;GA;;;BU)"));
    assert!(!TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;GW;;;BU)"));
    assert!(!TASK_SECURITY_DESCRIPTOR_SDDL.contains("(A;;GX;;;BU)"));
}

#[test]
fn test_hresult_mapping_for_task_status() {
    #[cfg(windows)]
    {
        use winapi::shared::winerror::{ERROR_FILE_NOT_FOUND, E_ACCESSDENIED, HRESULT_FROM_WIN32};
        const SCHED_E_TASK_NOT_FOUND: i32 = 0x80041303_u32 as i32;
        const SCHED_E_SERVICE_NOT_RUNNING: i32 = 0x80041315_u32 as i32;
        const RPC_S_SERVER_UNAVAILABLE: i32 = 0x800706BA_u32 as i32;

        assert_eq!(
            AutoStartManager::map_hresult_to_status(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)),
            TaskStatus::Missing
        );
        assert_eq!(
            AutoStartManager::map_hresult_to_status(SCHED_E_TASK_NOT_FOUND),
            TaskStatus::Missing
        );
        assert_eq!(
            AutoStartManager::map_hresult_to_status(E_ACCESSDENIED),
            TaskStatus::QueryError("Task query access denied (E_ACCESSDENIED)".into())
        );
        assert_eq!(
            AutoStartManager::map_hresult_to_status(RPC_S_SERVER_UNAVAILABLE),
            TaskStatus::QueryError(
                "Task Scheduler service unavailable (RPC_S_SERVER_UNAVAILABLE)".into()
            )
        );
        assert_eq!(
            AutoStartManager::map_hresult_to_status(SCHED_E_SERVICE_NOT_RUNNING),
            TaskStatus::QueryError(
                "Task Scheduler service unavailable (RPC_S_SERVER_UNAVAILABLE)".into()
            )
        );
    }
}

#[test]
fn test_parse_query_xml_valid_task() {
    let valid_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings>
        <Enabled>true</Enabled>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
      </Settings>
      <Actions Context="Author">
        <Exec>
          <Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command>
          <Arguments>--core</Arguments>
        </Exec>
      </Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        valid_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::Valid);
}

#[test]
fn test_parse_query_xml_detects_logon_type_drift() {
    // ServiceAccount must be rejected
    let service_account_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
      <Actions><Exec><Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command><Arguments>--core</Arguments></Exec></Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        service_account_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::DriftAccountMismatch);

    // InteractiveToken instead of omitted/SYSTEM logon type
    let interactive_logon_type_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
      <Actions><Exec><Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command><Arguments>--core</Arguments></Exec></Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        interactive_logon_type_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::DriftAccountMismatch);

    // S4U instead of omitted/SYSTEM logon type
    let s4u_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
      <Actions><Exec><Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command><Arguments>--core</Arguments></Exec></Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        s4u_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::DriftAccountMismatch);
}

#[test]
fn test_parse_query_xml_detects_run_level_drift() {
    // Missing RunLevel
    let missing_run_level_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals>
      <Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
      <Actions><Exec><Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command><Arguments>--core</Arguments></Exec></Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        missing_run_level_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::DriftAccountMismatch);

    // LeastPrivilege instead of HighestAvailable
    let least_priv_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
      <Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
      <Actions><Exec><Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command><Arguments>--core</Arguments></Exec></Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        least_priv_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::DriftAccountMismatch);
}

#[test]
fn test_parse_query_xml_detects_logon_trigger_drift() {
    let drift_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
      <Actions><Exec><Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command><Arguments>--core</Arguments></Exec></Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        drift_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::DriftTriggerMismatch);
}

#[test]
fn test_parse_query_xml_requires_s_1_5_18_and_rejects_textual_system() {
    let user_sid_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-21-123456789-1001</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
      <Actions><Exec><Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command><Arguments>--core</Arguments></Exec></Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        user_sid_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::DriftAccountMismatch);

    // Textual "SYSTEM" is rejected to prevent localization bugs
    let textual_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>NT AUTHORITY\SYSTEM</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
      <Actions><Exec><Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command><Arguments>--core</Arguments></Exec></Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        textual_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::DriftAccountMismatch);
}

#[test]
#[cfg(windows)]
fn test_task_scheduler_com_validates_generated_xml_in_memory() {
    let exe_path = Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe");
    let xml = AutoStartManager::generate_task_xml(exe_path, "TemprisCollectorCore");

    // Assert generated XML starts directly with <Task and contains no encoding attribute or declaration
    assert!(xml.starts_with("<Task"));
    assert!(!xml.contains("encoding="));
    assert!(!xml.contains("<?xml"));

    // 1. Assign generated XML directly to COM TaskDefinition.XmlText - must succeed in-memory without declaration
    let res = AutoStartManager::validate_task_xml_in_memory(&xml);
    assert!(
        res.is_ok(),
        "Generated task XML must validate successfully in-memory via COM: {:?}",
        res.err()
    );

    let normalized_xml = res.unwrap();
    assert!(normalized_xml.contains("<UserId>S-1-5-18</UserId>"));
    assert!(normalized_xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
    assert!(!normalized_xml.contains("<LogonType>"));

    // 2. Re-introducing ServiceAccount must fail with 0x80041318 (SCHED_E_INVALIDVALUE)
    let invalid_xml = xml.replace(
        "<UserId>S-1-5-18</UserId>",
        "<UserId>S-1-5-18</UserId>\n      <LogonType>ServiceAccount</LogonType>",
    );
    let invalid_res = AutoStartManager::validate_task_xml_in_memory(&invalid_xml);
    assert_eq!(
        invalid_res,
        Err(0x80041318_u32 as i32),
        "ServiceAccount must be rejected by Task Scheduler COM with 0x80041318"
    );

    // 3. Regression: old encoding="UTF-8" declaration must fail when assigned to COM (0xC00CEE03 or 0x8004131A SCHED_E_INVALIDTASK)
    let old_utf8_declared_xml = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml);
    let old_decl_res = AutoStartManager::validate_task_xml_in_memory(&old_utf8_declared_xml);
    assert!(
        old_decl_res.is_err(),
        "XML with contradictory UTF-8 declaration must fail when assigned to COM"
    );
    let err_hr = old_decl_res.unwrap_err();
    assert!(
        err_hr == (0xC00CEE03_u32 as i32) || err_hr == (0x8004131A_u32 as i32),
        "Expected HRESULT 0xC00CEE03 or 0x8004131A for contradictory UTF-8 XML declaration, got: 0x{:08X}",
        err_hr
    );

    // 4. InteractiveToken or S4U must be rejected by drift validator
    let interactive_xml = xml.replace(
        "<UserId>S-1-5-18</UserId>",
        "<UserId>S-1-5-18</UserId>\n      <LogonType>InteractiveToken</LogonType>",
    );
    let drift_res = AutoStartManager::parse_query_xml(&interactive_xml, exe_path);
    assert_eq!(drift_res, TaskStatus::DriftAccountMismatch);
}

#[test]
fn test_sddl_generation_for_kernel_objects_and_storage() {
    let mutex_sddl = SingleInstanceGuard::get_mutex_sddl();
    assert_eq!(mutex_sddl, "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00100000;;;BU)");

    let event_sddl = ShutdownSignalListener::get_event_sddl();
    assert_eq!(event_sddl, "D:(A;;FA;;;SY)(A;;FA;;;BA)");

    let secret_sddl = StorageManager::get_secret_tier_sddl();
    assert_eq!(secret_sddl, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    assert!(!secret_sddl.contains("OW"));

    let observer_sddl = StorageManager::get_observer_tier_sddl();
    assert_eq!(
        observer_sddl,
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;GRGX;;;BU)"
    );
}

#[test]
fn test_uac_helper_exit_code_mapping() {
    assert_eq!(
        AutoStartManager::map_exit_code_to_result(HelperExitCode::Success as u32),
        Ok(HelperResult::Success)
    );
    assert_eq!(
        AutoStartManager::map_win32_error_to_helper_result(1223),
        Ok(HelperResult::Cancelled)
    );
}

#[test]
fn test_reset_fails_closed_if_task_query_reports_error() {
    let mut app = CollectorApp::new_test_instance();
    let res =
        app.execute_advanced_reset_with_unreg(None, std::time::Duration::from_millis(100), || {
            Err(AutoStartError::ExecutionFailed("Access Denied".into()))
        });

    assert!(res.is_err());
    // Identity files must remain preserved
    assert!(app.storage().load().is_ok());
}

#[test]
fn test_ui_autostart_button_click_and_debouncing_with_injected_helper() {
    let mut app = CollectorApp::new_test_instance();

    // 1. Success case with injected helper
    let mgr_success =
        AutoStartManager::with_helper_runner(None, |_action, _task| Ok(HelperResult::Success));
    app.set_autostart_manager(mgr_success);

    assert_eq!(app.autostart_in_progress(), false);
    app.execute_autostart_register();
    assert_eq!(app.autostart_in_progress(), false);

    let (msg, color) = app.autostart_action_message().expect("must set message");
    assert!(msg.contains("installed and verified successfully"));
    assert_eq!(*color, egui::Color32::from_rgb(40, 200, 40));

    // 2. Cancellation case with injected helper
    let mgr_cancelled =
        AutoStartManager::with_helper_runner(None, |_action, _task| Ok(HelperResult::Cancelled));
    app.set_autostart_manager(mgr_cancelled);

    app.execute_autostart_register();
    let (msg, color) = app.autostart_action_message().expect("must set message");
    assert!(msg.contains("cancelled by the user"));
    assert_eq!(*color, egui::Color32::from_rgb(255, 180, 0));

    // 3. Execution failure case with injected helper
    let mgr_failed = AutoStartManager::with_helper_runner(None, |_action, _task| {
        Err(AutoStartError::ExecutionFailed(
            "Task Scheduler XML registration failed".into(),
        ))
    });
    app.set_autostart_manager(mgr_failed);

    app.execute_autostart_register();
    let (msg, color) = app.autostart_action_message().expect("must set message");
    assert!(msg.contains("Autostart configuration failed"));
    assert!(msg.contains("Task Scheduler XML registration failed"));
    assert_eq!(*color, egui::Color32::from_rgb(255, 80, 80));
}

#[test]
fn test_query_error_repair_button_routes_through_execute_autostart_register() {
    let mut app = CollectorApp::new_test_instance();

    // Set status to QueryError (e.g. simulated E_ACCESSDENIED from live system)
    let _q_err = "Task query access denied (E_ACCESSDENIED)".to_string();
    let dummy_task = format!("TemprisTestQueryError_{}", Uuid::new_v4().simple());

    // Inject helper runner that succeeds and fixes access
    let mgr = AutoStartManager::with_helper_runner(Some(&dummy_task), |action, task| {
        assert_eq!(action, "install");
        assert!(task.starts_with("TemprisTestQueryError_"));
        Ok(HelperResult::Success)
    });
    app.set_autostart_manager(mgr);

    // Verify button routing through execute_autostart_register updates state & feedback
    assert_eq!(app.autostart_in_progress(), false);
    app.execute_autostart_register();
    assert_eq!(app.autostart_in_progress(), false);

    let (msg, color) = app
        .autostart_action_message()
        .expect("must set message on repair");
    assert!(msg.contains("installed and verified successfully"));
    assert_eq!(*color, egui::Color32::from_rgb(40, 200, 40));
}

#[test]
fn test_derive_connection_status_stale_runtime_snapshot_never_connected() {
    let now = Utc::now();
    let col_id = Uuid::new_v4();

    // 1. Core NOT running -> Always Disconnected even if snapshot has Connected status
    let mut snap = RuntimeSnapshot::new(
        col_id,
        "Test Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snap.last_heartbeat = Some(now - Duration::seconds(5));
    snap.updated_at = now - Duration::seconds(5);

    let status = derive_connection_status(false, Some(&snap), now);
    assert_eq!(status, ConnectionStatus::Disconnected);

    // 2. Core running, but snapshot is stale (> 30s old) -> Connecting, NOT Connected
    let mut stale_snap = RuntimeSnapshot::new(
        col_id,
        "Test Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    stale_snap.last_heartbeat = Some(now - Duration::seconds(60));
    stale_snap.updated_at = now - Duration::seconds(60);

    let status = derive_connection_status(true, Some(&stale_snap), now);
    assert_eq!(status, ConnectionStatus::Connecting);

    // 3. Core running and snapshot is fresh (< 30s) -> Connected
    let status = derive_connection_status(true, Some(&snap), now);
    assert_eq!(status, ConnectionStatus::Connected);
}

static ENABLE_CALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static DISABLE_CALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[test]
fn test_enable_disable_boot_autostart_routes_to_helper() {
    let dummy_task = format!("TemprisTestToggle_{}", Uuid::new_v4().simple());

    // 1. Enable calls runner with "enable"
    ENABLE_CALLED.store(false, std::sync::atomic::Ordering::SeqCst);
    let mgr_enable = AutoStartManager::with_helper_runner(Some(&dummy_task), |action, task| {
        assert_eq!(action, "enable");
        assert!(task.starts_with("TemprisTestToggle_"));
        ENABLE_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(HelperResult::Success)
    });
    assert!(mgr_enable.enable().is_ok());
    assert!(ENABLE_CALLED.load(std::sync::atomic::Ordering::SeqCst));

    // 2. Disable calls runner with "disable"
    DISABLE_CALLED.store(false, std::sync::atomic::Ordering::SeqCst);
    let mgr_disable = AutoStartManager::with_helper_runner(Some(&dummy_task), |action, task| {
        assert_eq!(action, "disable");
        assert!(task.starts_with("TemprisTestToggle_"));
        DISABLE_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(HelperResult::Success)
    });
    assert!(mgr_disable.disable().is_ok());
    assert!(DISABLE_CALLED.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn test_ui_enable_disable_toggle_actions_and_debouncing() {
    let mut app = CollectorApp::new_test_instance();

    // 1. Enable action success
    let mgr_enable = AutoStartManager::with_helper_runner(None, |action, _task| {
        assert_eq!(action, "enable");
        Ok(HelperResult::Success)
    });
    app.set_autostart_manager(mgr_enable);

    assert_eq!(app.autostart_in_progress(), false);
    app.execute_autostart_enable();
    assert_eq!(app.autostart_in_progress(), false);

    let (msg, color) = app
        .autostart_action_message()
        .expect("must set message on enable");
    assert!(msg.contains("enabled successfully"));
    assert_eq!(*color, egui::Color32::from_rgb(40, 200, 40));

    // 2. Disable action success
    let mgr_disable = AutoStartManager::with_helper_runner(None, |action, _task| {
        assert_eq!(action, "disable");
        Ok(HelperResult::Success)
    });
    app.set_autostart_manager(mgr_disable);

    assert_eq!(app.autostart_in_progress(), false);
    app.execute_autostart_disable();
    assert_eq!(app.autostart_in_progress(), false);

    let (msg, color) = app
        .autostart_action_message()
        .expect("must set message on disable");
    assert!(msg.contains("disabled for future boots"));
    assert!(msg.contains("Background core process remains active"));
    assert_eq!(*color, egui::Color32::from_rgb(255, 180, 0));

    // 3. User cancellation on disable
    let mgr_cancelled =
        AutoStartManager::with_helper_runner(None, |_action, _task| Ok(HelperResult::Cancelled));
    app.set_autostart_manager(mgr_cancelled);

    app.execute_autostart_disable();
    let (msg, color) = app
        .autostart_action_message()
        .expect("must set message on cancel");
    assert!(msg.contains("cancelled by the user"));
    assert_eq!(*color, egui::Color32::from_rgb(255, 180, 0));

    // 4. Execution failure on enable
    let mgr_failed = AutoStartManager::with_helper_runner(None, |_action, _task| {
        Err(AutoStartError::ExecutionFailed(
            "Task Scheduler task state change (enable/disable) failed".into(),
        ))
    });
    app.set_autostart_manager(mgr_failed);

    app.execute_autostart_enable();
    let (msg, color) = app
        .autostart_action_message()
        .expect("must set message on fail");
    assert!(msg.contains("Failed to enable autostart"));
    assert_eq!(*color, egui::Color32::from_rgb(255, 80, 80));
}

#[test]
fn test_parse_query_xml_detects_disabled_task() {
    let disabled_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings>
        <Enabled>false</Enabled>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
      </Settings>
      <Actions Context="Author">
        <Exec>
          <Command>C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe</Command>
          <Arguments>--core</Arguments>
        </Exec>
      </Actions>
    </Task>"#;

    let status = AutoStartManager::parse_query_xml(
        disabled_xml,
        Path::new("C:\\ProgramData\\Tempris\\Collector\\bin\\tempris-collector.exe"),
    );
    assert_eq!(status, TaskStatus::Disabled);
}
