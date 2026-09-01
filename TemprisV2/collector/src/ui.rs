use chrono::Utc;
use eframe::egui::{self, Color32, RichText, ScrollArea};
use uuid::Uuid;

use crate::autostart::{get_stable_install_path, AutoStartError, AutoStartManager, TaskStatus};
use crate::client::ConnectionStatus;
use crate::enrollment::enroll_collector;
use crate::lifecycle::{RuntimeSnapshot, RuntimeStatus};
use crate::logging::BoundedLogger;
use crate::singleton::{signal_core_shutdown, wait_for_core_exit, SingleInstanceGuard};
use crate::storage::{CollectorState, StorageError, StorageManager};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiTab {
    Overview,
    Logs,
    Advanced,
}

/// Derives active GUI connection status from live core mutex ownership and runtime snapshot freshness.
/// Strict invariant: ConnectionStatus::Connected requires both:
/// 1. The Global core instance mutex is actively held (is_core_running == true), and
/// 2. The runtime snapshot is fresh (<30s heartbeat / update timestamp).
/// If core mutex is not held, status is authoritatively Disconnected (Offline).
pub fn derive_connection_status(
    is_core_running: bool,
    snapshot: Option<&RuntimeSnapshot>,
    now: chrono::DateTime<Utc>,
) -> ConnectionStatus {
    if !is_core_running {
        return ConnectionStatus::Disconnected;
    }

    if let Some(snap) = snapshot {
        let age_secs = (now - snap.updated_at).num_seconds();
        let is_fresh = age_secs >= 0 && age_secs < 30;

        if !is_fresh {
            return ConnectionStatus::Connecting;
        }

        match snap.status {
            RuntimeStatus::Connected => {
                if let Some(hb) = snap.last_heartbeat {
                    let hb_age = (now - hb).num_seconds();
                    if hb_age < 0 || hb_age >= 30 {
                        return ConnectionStatus::Connecting;
                    }
                }
                ConnectionStatus::Connected
            }
            RuntimeStatus::Connecting => ConnectionStatus::Connecting,
            RuntimeStatus::Authenticating => ConnectionStatus::Authenticating,
            RuntimeStatus::Reconnecting => ConnectionStatus::Reconnecting,
            RuntimeStatus::Paused => ConnectionStatus::Paused,
            RuntimeStatus::Quarantined => ConnectionStatus::Quarantined,
            RuntimeStatus::Revoked => ConnectionStatus::Revoked,
            RuntimeStatus::Offline => ConnectionStatus::Disconnected,
            RuntimeStatus::Error => {
                ConnectionStatus::Failed(snap.error_message.clone().unwrap_or_default())
            }
        }
    } else {
        ConnectionStatus::Connecting
    }
}

pub struct CollectorApp {
    storage: StorageManager,
    state: Option<CollectorState>,
    recovery_error: Option<String>,
    rt_handle: tokio::runtime::Handle,
    autostart_manager: AutoStartManager,
    autostart_status: TaskStatus,
    autostart_in_progress: bool,
    autostart_action_message: Option<(String, Color32)>,

    // Active UI tab
    active_tab: UiTab,

    // Setup & Enrollment form
    input_server_url: String,
    input_collector_id: String,
    input_enrollment_code: String,
    enrollment_in_progress: bool,
    enrollment_error: Option<String>,

    // Reset confirmation
    show_reset_confirm: bool,
}

impl CollectorApp {
    pub fn new(
        storage: StorageManager,
        state: Option<CollectorState>,
        recovery_error: Option<String>,
        rt_handle: tokio::runtime::Handle,
    ) -> Self {
        let server_url = state
            .as_ref()
            .map(|s| s.server_url.clone())
            .unwrap_or_else(|| "https://sandbox.tempris.tech/v2-assets".to_string());
        let collector_id = state
            .as_ref()
            .map(|s| s.collector_id.to_string())
            .unwrap_or_default();

        let autostart_manager = AutoStartManager::default();
        let autostart_status = autostart_manager.query_detailed_status();

        Self {
            storage,
            state,
            recovery_error,
            rt_handle,
            autostart_manager,
            autostart_status,
            autostart_in_progress: false,
            autostart_action_message: None,
            active_tab: UiTab::Overview,
            input_server_url: server_url,
            input_collector_id: collector_id,
            input_enrollment_code: String::new(),
            enrollment_in_progress: false,
            enrollment_error: None,
            show_reset_confirm: false,
        }
    }

    /// Creates a test instance with valid pre-saved test credentials and dummy runtime.
    pub fn new_test_instance() -> Self {
        let temp_dir = std::env::temp_dir().join(format!("tempris_test_app_{}", Uuid::new_v4()));
        let storage = StorageManager::new(temp_dir);
        let (signing_key, verifying_key) = crate::crypto::generate_keypair();
        let pubkey = crate::crypto::public_key_to_base64url(&verifying_key);
        let state = CollectorState::new(
            Uuid::new_v4(),
            "Test Collector".to_string(),
            "https://sandbox.tempris.tech/v2-assets".to_string(),
            pubkey,
            Utc::now(),
        );
        storage
            .save(&state, &signing_key)
            .expect("test save must succeed");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        Self::new(storage, Some(state), None, rt.handle().clone())
    }

    /// Attempts to reload state from storage on recovery retry
    pub fn retry_load(&mut self) {
        match self.storage.load() {
            Ok((state, _key)) => {
                self.state = Some(state);
                self.recovery_error = None;
                self.autostart_status = self.autostart_manager.query_detailed_status();
            }
            Err(StorageError::NotFound) => {
                self.recovery_error = None;
                self.state = None;
            }
            Err(err) => {
                self.recovery_error = Some(err.to_string());
            }
        }
    }

    /// Returns the currently loaded state, if any.
    pub fn state(&self) -> Option<&CollectorState> {
        self.state.as_ref()
    }

    /// Returns the current recovery diagnostic error, if any.
    pub fn recovery_error(&self) -> Option<&str> {
        self.recovery_error.as_deref()
    }

    /// Returns a reference to the underlying StorageManager.
    pub fn storage(&self) -> &StorageManager {
        &self.storage
    }

    /// Returns the current active UI tab.
    pub fn active_tab(&self) -> UiTab {
        self.active_tab
    }

    /// Returns the current autostart task status.
    pub fn autostart_status(&self) -> &TaskStatus {
        &self.autostart_status
    }

    /// Returns whether an autostart action is currently in progress (debounced).
    pub fn autostart_in_progress(&self) -> bool {
        self.autostart_in_progress
    }

    /// Returns the current autostart feedback message and badge color, if any.
    pub fn autostart_action_message(&self) -> Option<&(String, Color32)> {
        self.autostart_action_message.as_ref()
    }

    /// Sets the autostart manager instance (used for dependency injection in tests).
    pub fn set_autostart_manager(&mut self, manager: AutoStartManager) {
        self.autostart_manager = manager;
        self.autostart_status = self.autostart_manager.query_detailed_status();
    }

    /// Builder method to configure custom autostart manager.
    pub fn with_autostart_manager(mut self, manager: AutoStartManager) -> Self {
        self.autostart_status = manager.query_detailed_status();
        self.autostart_manager = manager;
        self
    }

    /// Returns a mutable reference to the underlying AutoStartManager.
    pub fn autostart_manager_mut(&mut self) -> &mut AutoStartManager {
        &mut self.autostart_manager
    }

    /// Executes autostart registration / repair with debouncing and safe error/cancellation handling.
    pub fn execute_autostart_register(&mut self) {
        if self.autostart_in_progress {
            return;
        }

        self.autostart_in_progress = true;
        self.autostart_action_message = None;

        match self.autostart_manager.register(None) {
            Ok(stable_bin) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    "Boot autostart task installed and verified successfully.".to_string(),
                    Color32::from_rgb(40, 200, 40),
                ));
                tracing::info!(
                    "Boot autostart task registered successfully at {:?}",
                    stable_bin
                );
            }
            Err(AutoStartError::Cancelled) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    "Elevation was cancelled by the user. Autostart configuration not completed."
                        .to_string(),
                    Color32::from_rgb(255, 180, 0),
                ));
                tracing::warn!("UAC elevation cancelled by user during autostart registration.");
            }
            Err(err) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    format!("Autostart configuration failed: {}", err),
                    Color32::from_rgb(255, 80, 80),
                ));
                tracing::error!("Autostart registration failed: {}", err);
            }
        }

        self.autostart_in_progress = false;
    }

    /// Executes autostart task enablement with debouncing and safe error/cancellation handling.
    pub fn execute_autostart_enable(&mut self) {
        if self.autostart_in_progress {
            return;
        }

        self.autostart_in_progress = true;
        self.autostart_action_message = None;

        match self.autostart_manager.enable() {
            Ok(()) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    "Boot autostart task enabled successfully.".to_string(),
                    Color32::from_rgb(40, 200, 40),
                ));
                tracing::info!("Boot autostart task enabled successfully.");
            }
            Err(AutoStartError::Cancelled) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    "Elevation was cancelled by the user. Autostart state not changed.".to_string(),
                    Color32::from_rgb(255, 180, 0),
                ));
                tracing::warn!("UAC elevation cancelled by user during autostart enablement.");
            }
            Err(err) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    format!("Failed to enable autostart: {}", err),
                    Color32::from_rgb(255, 80, 80),
                ));
                tracing::error!("Autostart enablement failed: {}", err);
            }
        }

        self.autostart_in_progress = false;
    }

    /// Executes autostart task disablement with debouncing and safe error/cancellation handling.
    /// Disables future boot startup only without stopping core or wiping identity.
    pub fn execute_autostart_disable(&mut self) {
        if self.autostart_in_progress {
            return;
        }

        self.autostart_in_progress = true;
        self.autostart_action_message = None;

        match self.autostart_manager.disable() {
            Ok(()) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    "Boot autostart task disabled for future boots. Background core process remains active."
                        .to_string(),
                    Color32::from_rgb(255, 180, 0),
                ));
                tracing::info!("Boot autostart task disabled successfully.");
            }
            Err(AutoStartError::Cancelled) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    "Elevation was cancelled by the user. Autostart state not changed.".to_string(),
                    Color32::from_rgb(255, 180, 0),
                ));
                tracing::warn!("UAC elevation cancelled by user during autostart disablement.");
            }
            Err(err) => {
                self.autostart_status = self.autostart_manager.query_detailed_status();
                self.autostart_action_message = Some((
                    format!("Failed to disable autostart: {}", err),
                    Color32::from_rgb(255, 80, 80),
                ));
                tracing::error!("Autostart disablement failed: {}", err);
            }
        }

        self.autostart_in_progress = false;
    }

    /// Executes destructive reset of local state.json, protected_identity.dat, and runtime.json.
    /// Fails closed: will NOT delete credentials or report success unless:
    /// (a) Shutdown signaling has a usable result,
    /// (b) The background core is confirmed stopped within timeout,
    /// (c) The auto-start task is successfully absent or unregistered.
    /// Concrete errors are propagated into Recovery UI; identity is preserved on failure.
    pub fn execute_advanced_reset(&mut self) -> Result<(), String> {
        self.execute_advanced_reset_custom(None, None, std::time::Duration::from_secs(4))
    }

    /// Executes reset with custom mutex suffix, task name, and wait timeout (for testing and advanced configurations).
    pub fn execute_advanced_reset_custom(
        &mut self,
        name_suffix: Option<&str>,
        autostart_task_name: Option<&str>,
        core_wait_timeout: std::time::Duration,
    ) -> Result<(), String> {
        let autostart = AutoStartManager::new(autostart_task_name);
        self.execute_advanced_reset_with_unreg(name_suffix, core_wait_timeout, || {
            autostart.unregister()
        })
    }

    /// Executes reset with custom unregistration callback to allow deterministic failure testing.
    pub fn execute_advanced_reset_with_unreg<F>(
        &mut self,
        name_suffix: Option<&str>,
        core_wait_timeout: std::time::Duration,
        unreg_fn: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Result<(), AutoStartError>,
    {
        // 1. (a) & (b) Check and terminate background core daemon if running
        if SingleInstanceGuard::is_another_instance_running(name_suffix) {
            // (a) Shutdown signaling must have a usable result
            if !signal_core_shutdown(name_suffix) {
                let err = "Failed to signal background core process to shut down (shutdown event could not be set)".to_string();
                tracing::error!("Reset aborted: {}", err);
                self.recovery_error = Some(format!("Reset failed: {}", err));
                self.show_reset_confirm = false;
                return Err(err);
            }

            // (b) The independent core must be confirmed stopped within timeout
            if !wait_for_core_exit(name_suffix, core_wait_timeout) {
                let err = format!(
                    "Background core process failed to stop within {:?} timeout (process is still active)",
                    core_wait_timeout
                );
                tracing::error!("Reset aborted: {}", err);
                self.recovery_error = Some(format!("Reset failed: {}", err));
                self.show_reset_confirm = false;
                return Err(err);
            }
        }

        // Final verification that core is stopped
        if SingleInstanceGuard::is_another_instance_running(name_suffix) {
            let err = "Background core process is still running; refusing to reset credentials"
                .to_string();
            tracing::error!("Reset aborted: {}", err);
            self.recovery_error = Some(format!("Reset failed: {}", err));
            self.show_reset_confirm = false;
            return Err(err);
        }

        // 2. (c) Unregister auto-start scheduled task
        if let Err(e) = unreg_fn() {
            let err = format!("Failed to unregister Task Scheduler auto-start task: {}", e);
            tracing::error!("Reset aborted: {}", err);
            self.recovery_error = Some(format!("Reset failed: {}", err));
            self.show_reset_confirm = false;
            return Err(err);
        }

        // Authoritative absence verification via native COM on Windows
        #[cfg(windows)]
        {
            let status = self.autostart_manager.query_detailed_status();
            if status != TaskStatus::Missing {
                let err = match status {
                    TaskStatus::QueryError(q_err) => format!(
                        "Task absence could not be confirmed due to query error: {}. Reset aborted.",
                        q_err
                    ),
                    _ => "Task Scheduler task is still present after unregistration. Reset aborted.".to_string(),
                };
                tracing::error!("Reset aborted: {}", err);
                self.recovery_error = Some(format!("Reset failed: {}", err));
                self.show_reset_confirm = false;
                return Err(err);
            }
        }

        // 3. Delete credential files and verify absence (fails closed if deletion fails)
        match self.storage.reset() {
            Ok(()) => {
                self.state = None;
                self.recovery_error = None;
                self.show_reset_confirm = false;
                self.input_enrollment_code.clear();
                self.active_tab = UiTab::Overview;
                self.autostart_status = TaskStatus::Missing;
                tracing::info!("Collector credentials and state successfully reset.");
                Ok(())
            }
            Err(e) => {
                let err = format!("Storage reset failed: {}", e);
                tracing::error!("Reset failed: {}", err);
                self.recovery_error = Some(format!("Reset failed: {}", err));
                self.show_reset_confirm = false;
                Err(err)
            }
        }
    }
}

impl eframe::App for CollectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Regular repaint for live badges and telemetry
        ctx.request_repaint_after(std::time::Duration::from_millis(1000));

        // Periodic status refresh
        if self.state.is_some() {
            self.autostart_status = self.autostart_manager.query_detailed_status();
        }

        egui::TopBottomPanel::top("header_panel").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(
                    RichText::new("TEMPRIS")
                        .strong()
                        .color(Color32::from_rgb(0, 210, 255)),
                );
                ui.label(
                    RichText::new("Internal Asset Reachability Collector")
                        .color(Color32::LIGHT_GRAY),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .small()
                            .color(Color32::GRAY),
                    );
                });
            });
            ui.add_space(6.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(ref err) = self.recovery_error.clone() {
                self.render_recovery_view(ui, ctx, err);
            } else if self.state.is_none() {
                self.render_setup_view(ui, ctx);
            } else {
                self.render_status_view(ui, ctx);
            }
        });
    }
}

impl CollectorApp {
    fn render_recovery_view(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context, err: &str) {
        ui.heading(
            RichText::new("Storage Recovery Required")
                .strong()
                .color(Color32::from_rgb(255, 90, 90)),
        );
        ui.add_space(8.0);
        ui.label(
            "The local collector identity or state files are corrupted, missing, or unreadable.",
        );
        ui.label("To maintain security invariants, the collector fails closed and will not silently generate new keys.");
        ui.add_space(12.0);

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Diagnostic Error Details:").strong());
            ui.label(
                RichText::new(err)
                    .monospace()
                    .color(Color32::from_rgb(255, 120, 120)),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("Storage Directory: {:?}", self.storage.base_dir()))
                    .small()
                    .color(Color32::GRAY),
            );
        });

        ui.add_space(16.0);

        ui.horizontal(|ui| {
            if ui.button(RichText::new("Retry Load").strong()).clicked() {
                self.retry_load();
            }

            ui.add_space(12.0);

            if ui
                .button(
                    RichText::new("Reset Registration...").color(Color32::from_rgb(255, 100, 100)),
                )
                .clicked()
            {
                self.show_reset_confirm = true;
            }
        });

        if self.show_reset_confirm {
            self.render_reset_confirm_dialog(ui);
        }
    }

    fn render_setup_view(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ui.heading("Collector Setup & Enrollment");
        ui.label(
            "Enroll this Windows workstation to enable zero-ingress internal asset verification.",
        );
        ui.add_space(12.0);

        egui::Grid::new("enroll_grid")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label("Control Plane URL:");
                ui.text_edit_singleline(&mut self.input_server_url);
                ui.end_row();

                ui.label("Collector Profile ID:");
                ui.text_edit_singleline(&mut self.input_collector_id);
                ui.end_row();

                ui.label("One-Time Enrollment Code:");
                ui.add(egui::TextEdit::singleline(&mut self.input_enrollment_code).password(true));
                ui.end_row();
            });

        ui.add_space(16.0);

        if let Some(ref err) = self.enrollment_error {
            ui.label(
                RichText::new(format!("Error: {}", err)).color(Color32::from_rgb(255, 80, 80)),
            );
            ui.add_space(8.0);
        }

        ui.horizontal(|ui| {
            let can_submit = !self.enrollment_in_progress
                && !self.input_server_url.trim().is_empty()
                && !self.input_collector_id.trim().is_empty()
                && !self.input_enrollment_code.trim().is_empty();

            if ui
                .add_enabled(can_submit, egui::Button::new("Enroll & Connect"))
                .clicked()
            {
                self.perform_enrollment();
            }

            if self.enrollment_in_progress {
                ui.spinner();
                ui.label("Enrolling with server...");
            }
        });
    }

    fn perform_enrollment(&mut self) {
        let server_url = self.input_server_url.trim().to_string();
        let col_id_res = Uuid::parse_str(self.input_collector_id.trim());
        let col_id = match col_id_res {
            Ok(id) => id,
            Err(e) => {
                self.enrollment_error = Some(format!("Invalid Collector UUID: {}", e));
                return;
            }
        };

        let code = self.input_enrollment_code.trim().to_string();
        self.input_enrollment_code.clear();

        let storage = self.storage.clone();
        self.enrollment_in_progress = true;
        self.enrollment_error = None;

        let rt = self.rt_handle.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let storage_dir = storage.base_dir().to_path_buf();
        rt.spawn(async move {
            let res = enroll_collector(&server_url, col_id, &code, Some(&storage_dir)).await;
            let _ = tx.send(res);
        });

        if let Ok(res) = rx.blocking_recv() {
            self.enrollment_in_progress = false;
            match res {
                Ok((_new_cfg, _signing_key)) => {
                    // Load new state
                    if let Ok((state, _)) = self.storage.load() {
                        self.state = Some(state);
                    }

                    // Register boot autostart task via elevated UAC helper
                    self.execute_autostart_register();
                }
                Err(e) => {
                    self.enrollment_error = Some(e.to_string());
                }
            }
        }
    }

    fn render_status_view(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        let state = match self.state {
            Some(ref s) => s.clone(),
            None => return,
        };

        let name = &state.collector_name;
        let id_str = state.collector_id.to_string();

        ui.horizontal(|ui| {
            ui.heading(name);
            ui.label(
                RichText::new(format!("({})", id_str))
                    .monospace()
                    .color(Color32::GRAY),
            );
        });

        ui.label(RichText::new(format!("Server: {}", state.server_url)).color(Color32::LIGHT_GRAY));
        ui.add_space(8.0);

        // Tab Navigation Bar
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.active_tab, UiTab::Overview, "Overview");
            ui.selectable_value(&mut self.active_tab, UiTab::Logs, "Activity Log");
            ui.selectable_value(&mut self.active_tab, UiTab::Advanced, "Advanced");
        });
        ui.separator();
        ui.add_space(6.0);

        let is_core_running = SingleInstanceGuard::is_another_instance_running(None);
        let snapshot_opt = RuntimeSnapshot::load_from(&self.storage.runtime_path()).ok();
        let now = Utc::now();
        let status = derive_connection_status(is_core_running, snapshot_opt.as_ref(), now);

        let logs =
            BoundedLogger::tail_from_disk(&self.storage.logs_dir().join("collector.log"), 500);

        let last_hb = snapshot_opt.as_ref().and_then(|s| s.last_heartbeat);
        let jobs_count = snapshot_opt.as_ref().map(|s| s.jobs_verified).unwrap_or(0);
        let current_activity = snapshot_opt
            .as_ref()
            .map(|s| s.current_activity.clone())
            .unwrap_or_else(|| "Idle".to_string());

        match self.active_tab {
            UiTab::Overview => {
                ui.horizontal(|ui| {
                    ui.label("Status:");
                    let (badge_text, badge_color) = match status {
                        ConnectionStatus::Connected => {
                            ("CONNECTED (WSS)", Color32::from_rgb(40, 200, 40))
                        }
                        ConnectionStatus::Connecting | ConnectionStatus::Authenticating => {
                            ("CONNECTING", Color32::from_rgb(240, 180, 0))
                        }
                        ConnectionStatus::Reconnecting => {
                            ("RECONNECTING", Color32::from_rgb(240, 180, 0))
                        }
                        ConnectionStatus::Paused => ("PAUSED", Color32::from_rgb(255, 140, 0)),
                        ConnectionStatus::Quarantined => {
                            ("QUARANTINED", Color32::from_rgb(220, 40, 40))
                        }
                        ConnectionStatus::Revoked => ("REVOKED", Color32::from_rgb(180, 0, 0)),
                        ConnectionStatus::Disconnected => {
                            ("OFFLINE", Color32::from_rgb(120, 120, 120))
                        }
                        ConnectionStatus::Failed(_) => ("FAILED", Color32::from_rgb(220, 40, 40)),
                    };

                    ui.label(
                        RichText::new(format!(" [{}] ", badge_text))
                            .strong()
                            .color(badge_color),
                    );

                    let (as_badge_text, as_badge_color) = match self.autostart_status {
                        TaskStatus::Valid => (
                            "Boot Autostart: Active (SYSTEM / ONSTART)",
                            Color32::from_rgb(40, 200, 40),
                        ),
                        TaskStatus::Missing => (
                            "Boot Autostart: Inactive (Missing)",
                            Color32::from_rgb(240, 180, 0),
                        ),
                        TaskStatus::DriftTriggerMismatch
                        | TaskStatus::DriftAccountMismatch
                        | TaskStatus::DriftActionMismatch
                        | TaskStatus::DriftSettingsMismatch => (
                            "Boot Autostart: Drift Detected",
                            Color32::from_rgb(240, 180, 0),
                        ),
                        TaskStatus::Disabled => {
                            ("Boot Autostart: Disabled", Color32::from_rgb(220, 40, 40))
                        }
                        TaskStatus::QueryError(_) => (
                            "Boot Autostart: Query Error",
                            Color32::from_rgb(220, 40, 40),
                        ),
                    };

                    ui.label(
                        RichText::new(format!(" [{}] ", as_badge_text))
                            .strong()
                            .color(as_badge_color),
                    );

                    if let Some(hb) = last_hb {
                        let diff = Utc::now() - hb;
                        ui.label(
                            RichText::new(format!("Last heartbeat: {}s ago", diff.num_seconds()))
                                .small()
                                .color(Color32::GRAY),
                        );
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new(format!("Jobs Verified: {}", jobs_count)).strong());
                    });
                });

                // Conditional warning banner for non-valid autostart states
                if self.autostart_status != TaskStatus::Valid {
                    ui.add_space(6.0);
                    egui::Frame::group(ui.style())
                        .fill(Color32::from_rgb(45, 35, 15))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(200, 150, 20)))
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                let (warn_msg, btn_label, is_enable_action) = match &self.autostart_status {
                                    TaskStatus::Missing => (
                                        "Boot Autostart Inactive: Collector requires administrator elevation to install the background service.",
                                        "Configure Boot Autostart",
                                        false,
                                    ),
                                    TaskStatus::QueryError(_msg) => (
                                        "Task Scheduler Query Error: Access is denied or task query failed. Administrator elevation required to repair task access permissions.",
                                        "Repair Task Access (UAC)",
                                        false,
                                    ),
                                    TaskStatus::Disabled => (
                                        "Boot Task Disabled: Windows Task Scheduler will not launch the core daemon on future system boots. The currently running daemon is unaffected.",
                                        "Enable Boot Autostart",
                                        true,
                                    ),
                                    _ => (
                                        "Boot Autostart Upgrade Available: Configure Windows boot startup (SYSTEM / ONSTART) for continuous monitoring.",
                                        "Upgrade Autostart",
                                        false,
                                    ),
                                };

                                ui.label(
                                    RichText::new(warn_msg)
                                        .color(Color32::from_rgb(255, 200, 80)),
                                );

                                ui.add_space(6.0);

                                ui.horizontal(|ui| {
                                    if self.autostart_in_progress {
                                        ui.add_enabled(
                                            false,
                                            egui::Button::new(
                                                RichText::new("Configuring Boot Autostart (UAC)...")
                                                    .strong(),
                                            ),
                                        );
                                        ui.spinner();
                                    } else {
                                        if ui.button(RichText::new(btn_label).strong()).clicked() {
                                            if is_enable_action {
                                                self.execute_autostart_enable();
                                            } else {
                                                self.execute_autostart_register();
                                            }
                                        }

                                        if matches!(self.autostart_status, TaskStatus::QueryError(_)) {
                                            if ui.button("Retry Query").clicked() {
                                                self.autostart_status = self.autostart_manager.query_detailed_status();
                                            }
                                        }
                                    }

                                    if let Some((ref msg, color)) = self.autostart_action_message {
                                        ui.add_space(8.0);
                                        ui.label(RichText::new(msg).color(color));
                                    }
                                });
                            });
                        });
                }

                if !current_activity.is_empty() && current_activity != "Idle" {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("Activity: {}", current_activity))
                            .small()
                            .color(Color32::LIGHT_BLUE),
                    );
                }

                ui.add_space(10.0);
                ui.label(RichText::new("Recent Activity (from disk log):").strong());
                ui.add_space(4.0);

                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(240.0)
                    .show(ui, |ui| {
                        if logs.is_empty() {
                            ui.label(
                                RichText::new("No activity recorded in logs yet.")
                                    .italics()
                                    .color(Color32::GRAY),
                            );
                        } else {
                            for entry in logs.iter().rev().take(50) {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(
                                            entry.timestamp.format("%H:%M:%S").to_string(),
                                        )
                                        .monospace()
                                        .color(Color32::GRAY),
                                    );
                                    let lvl_color = match entry.level.as_str() {
                                        "ERROR" => Color32::from_rgb(255, 80, 80),
                                        "WARN" => Color32::from_rgb(255, 180, 0),
                                        "INFO" => Color32::from_rgb(100, 200, 255),
                                        _ => Color32::GRAY,
                                    };
                                    ui.label(
                                        RichText::new(format!("[{}]", entry.level))
                                            .color(lvl_color),
                                    );
                                    ui.label(&entry.message);
                                });
                            }
                        }
                    });
            }

            UiTab::Logs => {
                ui.horizontal(|ui| {
                    ui.heading("Full Activity Log");
                });
                ui.add_space(6.0);

                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if logs.is_empty() {
                            ui.label(
                                RichText::new("No activity recorded in logs yet.")
                                    .italics()
                                    .color(Color32::GRAY),
                            );
                        } else {
                            for entry in logs.iter().rev() {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(
                                            entry.timestamp.format("%H:%M:%S%.3f").to_string(),
                                        )
                                        .monospace()
                                        .color(Color32::GRAY),
                                    );
                                    let lvl_color = match entry.level.as_str() {
                                        "ERROR" => Color32::from_rgb(255, 80, 80),
                                        "WARN" => Color32::from_rgb(255, 180, 0),
                                        "INFO" => Color32::from_rgb(100, 200, 255),
                                        _ => Color32::GRAY,
                                    };
                                    ui.label(
                                        RichText::new(format!("[{}]", entry.level))
                                            .color(lvl_color),
                                    );
                                    ui.label(&entry.message);
                                });
                            }
                        }
                    });
            }

            UiTab::Advanced => {
                ui.heading("Advanced Settings & Maintenance");
                ui.add_space(8.0);
                ui.label("Storage Path:");
                ui.label(
                    RichText::new(format!("{:?}", self.storage.base_dir()))
                        .monospace()
                        .color(Color32::GRAY),
                );
                ui.add_space(12.0);

                // Task Diagnostics Card
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.label(RichText::new("Task Scheduler Diagnostics").strong());
                    ui.add_space(4.0);

                    egui::Grid::new("task_diag_grid")
                        .num_columns(2)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            ui.label("Task Name:");
                            ui.label(RichText::new(self.autostart_manager.task_name()).monospace());
                            ui.end_row();

                            ui.label("Target Principal:");
                            ui.label(RichText::new("NT AUTHORITY\\SYSTEM (S-1-5-18)").monospace());
                            ui.end_row();

                            ui.label("Trigger:");
                            ui.label("At system startup (BootTrigger)");
                            ui.end_row();

                            ui.label("Binary Target:");
                            ui.label(
                                RichText::new(format!("{:?}", get_stable_install_path()))
                                    .monospace(),
                            );
                            ui.end_row();

                            ui.label("Execution Limit:");
                            ui.label("PT0S (Indefinite)");
                            ui.end_row();

                            ui.label("Current Status:");
                            let status_text = format!("{:?}", self.autostart_status);
                            let status_color = if self.autostart_status == TaskStatus::Valid {
                                Color32::from_rgb(40, 200, 40)
                            } else {
                                Color32::from_rgb(240, 180, 0)
                            };
                            ui.label(RichText::new(status_text).color(status_color).strong());
                            ui.end_row();
                        });

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if self.autostart_in_progress {
                            ui.add_enabled(
                                false,
                                egui::Button::new(
                                    RichText::new("Configuring Boot Task (UAC)...")
                                        .strong(),
                                ),
                            );
                            ui.spinner();
                        } else {
                            match self.autostart_status {
                                TaskStatus::Valid => {
                                    if ui
                                        .button(
                                            RichText::new("Disable Boot Autostart").strong(),
                                        )
                                        .clicked()
                                    {
                                        self.execute_autostart_disable();
                                    }
                                }
                                TaskStatus::Disabled => {
                                    if ui
                                        .button(
                                            RichText::new("Enable Boot Autostart").strong(),
                                        )
                                        .clicked()
                                    {
                                        self.execute_autostart_enable();
                                    }
                                }
                                TaskStatus::QueryError(_) => {
                                    if ui
                                        .button(
                                            RichText::new("Repair Task Access (UAC)").strong(),
                                        )
                                        .clicked()
                                    {
                                        self.execute_autostart_register();
                                    }
                                }
                                _ => {
                                    if ui
                                        .button(
                                            RichText::new("Reinstall / Verify Boot Task").strong(),
                                        )
                                        .clicked()
                                    {
                                        self.execute_autostart_register();
                                    }
                                }
                            }

                            if self.autostart_status != TaskStatus::Valid {
                                if ui.button("Retry Query").clicked() {
                                    self.autostart_status =
                                        self.autostart_manager.query_detailed_status();
                                }
                            }
                        }

                        if let Some((ref msg, color)) = self.autostart_action_message {
                            ui.add_space(8.0);
                            ui.label(RichText::new(msg).color(color));
                        }
                    });

                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "Disabling autostart prevents automatic startup on future system boots; it does not stop the currently running core process, unregister the task, or affect collector identity."
                        )
                        .small()
                        .color(Color32::GRAY),
                    );
                });

                ui.add_space(16.0);

                ui.group(|ui| {
                    ui.heading(
                        RichText::new("Reset Collector Registration")
                            .color(Color32::from_rgb(255, 100, 100)),
                    );
                    ui.add_space(4.0);
                    ui.label("Resetting registration stops the background core service, removes the autostart task, and permanently wipes local credentials.");
                    ui.label("Administrative authorization will be requested to unregister the Windows Boot Task. Fails closed if task removal cannot be confirmed.");
                    ui.add_space(8.0);

                    if ui
                        .button(
                            RichText::new("Reset Collector Registration...")
                                .color(Color32::from_rgb(255, 80, 80)),
                        )
                        .clicked()
                    {
                        self.show_reset_confirm = true;
                    }
                });

                if self.show_reset_confirm {
                    self.render_reset_confirm_dialog(ui);
                }
            }
        }
    }

    fn render_reset_confirm_dialog(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(
                RichText::new("CONFIRM RESET REGISTRATION")
                    .strong()
                    .color(Color32::from_rgb(255, 70, 70)),
            );
            ui.label("Are you sure you want to reset this collector registration? This action is irreversible.");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .button(
                        RichText::new("Yes, Delete Credentials & Reset")
                            .strong()
                            .color(Color32::from_rgb(255, 70, 70)),
                    )
                    .clicked()
                {
                    let _ = self.execute_advanced_reset();
                }
                if ui.button("Cancel").clicked() {
                    self.show_reset_confirm = false;
                }
            });
        });
    }
}
