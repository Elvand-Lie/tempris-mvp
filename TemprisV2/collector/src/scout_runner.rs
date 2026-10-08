use crate::protocol::{EngineCapability, ScoutCapabilities};
use crate::storage::StorageManager;
use crate::toolchain::discovery::{discover_external_nmap, NmapPrerequisiteState};
use crate::toolchain::redaction::{
    redact_paths, KnownPaths, EXTERNAL_NMAP_TOKEN, MANAGED_NUCLEI_TOKEN, MANAGED_TEMPLATES_TOKEN,
};
use crate::toolchain::state::{ComponentStatus, ToolchainState};
use anyhow::{anyhow, Result};
use chrono::Utc;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{error, info, warn};
use uuid::Uuid;

pub const OUTPUT_LIMIT: usize = 4 * 1024 * 1024; // 4 MiB

// Keep the 120s host bound below the backend's 180s Nmap job envelope.
fn nmap_scout_args(pinned_target: &str) -> Vec<String> {
    [
        "-sV",
        "-sT",
        "-T3",
        "--open",
        "-Pn",
        "--max-retries",
        "2",
        "--host-timeout",
        "120s",
        "-p",
        "1-10000",
        "-oX",
        "-",
        pinned_target,
    ]
    .iter()
    .map(|arg| (*arg).to_string())
    .collect()
}

fn nmap_host_timed_out(engine: &str, output: &str) -> bool {
    engine == "nmap" && output.contains("timedout=\"true\"")
}

struct SharedCapture {
    buf: Vec<u8>,
    total: usize,
    truncated: bool,
}

impl SharedCapture {
    fn push(&mut self, chunk: &[u8]) {
        self.total += chunk.len();
        if self.truncated {
            return;
        }
        let room = OUTPUT_LIMIT.saturating_sub(self.buf.len());
        if chunk.len() <= room {
            self.buf.extend_from_slice(chunk);
        } else {
            if room > 0 {
                self.buf.extend_from_slice(&chunk[..room]);
            }
            self.truncated = true;
        }
    }

    fn finish(&self) -> (String, usize) {
        let mut text = String::from_utf8_lossy(&self.buf).into_owned();
        if self.truncated {
            text.push_str("\n[output_limited]");
        }
        (text, self.total)
    }
}

fn lock_capture(cap: &Arc<Mutex<SharedCapture>>) -> std::sync::MutexGuard<'_, SharedCapture> {
    cap.lock().unwrap_or_else(|err| err.into_inner())
}

fn snapshot_capture(cap: &Arc<Mutex<SharedCapture>>) -> (String, usize) {
    lock_capture(cap).finish()
}

/// Collector Nuclei profile. `-sj` emits stats JSON so a deadline kill can
/// show whether requests were still moving. Paths in the recorded profile
/// are redacted separately.
fn nuclei_scout_args(
    pinned_target: &str,
    templates_dir: &str,
    original_target: Option<&str>,
    target_type: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "-target".to_string(),
        pinned_target.to_string(),
        "-severity".to_string(),
        "critical,high,medium,low,info".to_string(),
        "-jsonl".to_string(),
        "-silent".to_string(),
        "-nc".to_string(),
        "-duc".to_string(),
        "-ni".to_string(),
        "-no-stdin".to_string(),
        "-c".to_string(),
        "25".to_string(),
        "-timeout".to_string(),
        "3".to_string(),
        "-retries".to_string(),
        "0".to_string(),
        "-sj".to_string(),
        "-si".to_string(),
        "15".to_string(),
        "-t".to_string(),
        templates_dir.to_string(),
    ];

    if let (Some(orig_target), Some(ttype)) = (original_target, target_type) {
        let ttype_norm = ttype.to_lowercase().trim().to_string();
        if ttype_norm == "hostname" || ttype_norm == "domain" {
            let host_trimmed = orig_target.trim();
            if crate::safety::validate_hostname_syntax(host_trimmed).is_ok() {
                args.push("-H".to_string());
                args.push(format!("Host: {}", host_trimmed));
                args.push("-sni".to_string());
                args.push(host_trimmed.to_string());
            } else {
                warn!(
                    "Original target '{}' failed hostname syntax validation; omitting Host/SNI overrides",
                    host_trimmed
                );
            }
        }
    }
    args
}

fn sanitized_profile(binary: &str, args: &[String], known: &KnownPaths) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(binary.to_string());
    parts.extend(args.iter().cloned());
    redact_paths(&parts.join(" "), Some(known))
}

fn collector_deadline_message(
    elapsed_secs: u64,
    deadline_secs: u64,
    stdout_bytes: usize,
    stderr_bytes: usize,
    profile: &str,
) -> String {
    format!(
        "collector_deadline: termination=collector_deadline elapsed={elapsed_secs}s deadline={deadline_secs}s stdout_bytes={stdout_bytes} stderr_bytes={stderr_bytes} profile={profile}"
    )
}

// Concurrency guard: hard limit of at most 1 active concurrent SCOUT scan job
static SCOUT_JOB_RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct ScoutJobGuard;

impl ScoutJobGuard {
    pub fn is_active() -> bool {
        SCOUT_JOB_RUNNING.load(Ordering::SeqCst)
    }

    pub fn try_acquire() -> Result<Self> {
        if SCOUT_JOB_RUNNING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Ok(ScoutJobGuard)
        } else {
            Err(anyhow!("concurrency_limit_exceeded"))
        }
    }
}

impl Drop for ScoutJobGuard {
    fn drop(&mut self) {
        SCOUT_JOB_RUNNING.store(false, Ordering::SeqCst);
    }
}

/// Probes local engine availability and versions strictly without disclosing
/// filesystem paths, environment variables, or stderr output.
pub async fn probe_scout_capabilities() -> ScoutCapabilities {
    probe_scout_capabilities_with_storage(None).await
}

/// Probes local engine availability with explicit storage context for managed toolchain discovery.
pub async fn probe_scout_capabilities_with_storage(
    storage_opt: Option<&StorageManager>,
) -> ScoutCapabilities {
    let storage = storage_opt
        .cloned()
        .unwrap_or_else(StorageManager::default_machine_storage);
    let state_path = storage.toolchain_state_path();
    let state = ToolchainState::load(&state_path).ok();

    let nmap_state = discover_external_nmap().await;
    let nmap_cap = match nmap_state {
        NmapPrerequisiteState::Ready { version, .. } => EngineCapability {
            available: true,
            version: Some(version),
            templates_version: None,
            managed: Some(false),
            status: Some("ready".to_string()),
            integrity_status: Some("verified".to_string()),
            path: Some(EXTERNAL_NMAP_TOKEN.to_string()),
            last_checked_at: Some(Utc::now().to_rfc3339()),
            prerequisite_health: Some("ready".to_string()),
        },
        NmapPrerequisiteState::Missing => EngineCapability {
            available: false,
            version: None,
            templates_version: None,
            managed: Some(false),
            status: Some("missing".to_string()),
            integrity_status: Some("unknown".to_string()),
            path: None,
            last_checked_at: Some(Utc::now().to_rfc3339()),
            prerequisite_health: Some("missing".to_string()),
        },
        NmapPrerequisiteState::UnsupportedVersion { version, .. } => EngineCapability {
            available: false,
            version: Some(version),
            templates_version: None,
            managed: Some(false),
            status: Some("missing".to_string()),
            integrity_status: Some("unknown".to_string()),
            path: None,
            last_checked_at: Some(Utc::now().to_rfc3339()),
            prerequisite_health: Some("unsupported_version".to_string()),
        },
        NmapPrerequisiteState::NpcapMissing { version, .. } => EngineCapability {
            available: false,
            version: Some(version),
            templates_version: None,
            managed: Some(false),
            status: Some("missing".to_string()),
            integrity_status: Some("unknown".to_string()),
            path: None,
            last_checked_at: Some(Utc::now().to_rfc3339()),
            prerequisite_health: Some("npcap_missing".to_string()),
        },
        NmapPrerequisiteState::IntegrityOrPathError(_) => EngineCapability {
            available: false,
            version: None,
            templates_version: None,
            managed: Some(false),
            status: Some("missing".to_string()),
            integrity_status: Some("failed".to_string()),
            path: None,
            last_checked_at: Some(Utc::now().to_rfc3339()),
            prerequisite_health: Some("integrity_or_path_error".to_string()),
        },
    };

    let (nuclei_cap, templates_cap) = probe_nuclei_and_templates(state.as_ref()).await;

    let manifest_seq = state.as_ref().map(|s| s.last_manifest_sequence);
    let last_check = state
        .as_ref()
        .map(|s| s.updated_at.clone())
        .or_else(|| Some(Utc::now().to_rfc3339()));
    let update_status = if nuclei_cap.available {
        Some("up_to_date".to_string())
    } else {
        Some("idle".to_string())
    };

    ScoutCapabilities {
        nmap: nmap_cap,
        nuclei: nuclei_cap,
        nuclei_templates: templates_cap,
        curl: Some(crate::strike_runner::probe_binary_version("curl", &["--version"]).await),
        ffuf: Some(crate::strike_runner::probe_binary_version("ffuf", &["-V"]).await),
        dig: Some(crate::strike_runner::probe_binary_version("dig", &["-v"]).await),
        collector_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        manifest_sequence: manifest_seq,
        channel: Some("stable".to_string()),
        update_status,
        last_checked_at: last_check,
    }
}

async fn probe_nuclei_and_templates(
    state_opt: Option<&ToolchainState>,
) -> (EngineCapability, Option<EngineCapability>) {
    if let Some(state) = state_opt {
        let tmpl_cap = state.components.get("nuclei_templates").map(|t| {
            let is_ready = matches!(
                t.status,
                ComponentStatus::Installed | ComponentStatus::RolledBack
            );
            EngineCapability {
                available: is_ready,
                version: t.version.clone(),
                templates_version: None,
                managed: Some(true),
                status: Some(match t.status {
                    ComponentStatus::Installed => "ready".to_string(),
                    ComponentStatus::RolledBack => "rolled_back".to_string(),
                    ComponentStatus::Uninstalled => "uninstalled".to_string(),
                }),
                integrity_status: Some(if is_ready {
                    "verified".to_string()
                } else {
                    "unknown".to_string()
                }),
                path: if is_ready {
                    Some(MANAGED_TEMPLATES_TOKEN.to_string())
                } else {
                    None
                },
                last_checked_at: t.last_verified_at.clone(),
                prerequisite_health: None,
            }
        });

        if let Some(nuclei_comp) = state.components.get("nuclei") {
            if matches!(
                nuclei_comp.status,
                ComponentStatus::Installed | ComponentStatus::RolledBack
            ) {
                if let Some(active_dir) = &nuclei_comp.active_dir {
                    let exe_name = if cfg!(windows) { "nuclei.exe" } else { "nuclei" };
                    let exe_path = PathBuf::from(active_dir).join(exe_name);
                    if exe_path.exists() {
                        let tmpl_ver = tmpl_cap.as_ref().and_then(|t| t.version.clone());
                        let nuclei_cap = EngineCapability {
                            available: true,
                            version: nuclei_comp.version.clone(),
                            templates_version: tmpl_ver,
                            managed: Some(true),
                            status: Some(match nuclei_comp.status {
                                ComponentStatus::Installed => "ready".to_string(),
                                ComponentStatus::RolledBack => "rolled_back".to_string(),
                                ComponentStatus::Uninstalled => "uninstalled".to_string(),
                            }),
                            integrity_status: Some("verified".to_string()),
                            path: Some(MANAGED_NUCLEI_TOKEN.to_string()),
                            last_checked_at: nuclei_comp.last_verified_at.clone(),
                            prerequisite_health: None,
                        };
                        return (nuclei_cap, tmpl_cap);
                    }
                }
            }
            // When toolchain state is tracked, do not fall back to ambient host PATH
            let nuclei_cap = EngineCapability {
                available: false,
                version: None,
                templates_version: None,
                managed: Some(true),
                status: Some("not_installed".to_string()),
                integrity_status: Some("unknown".to_string()),
                path: None,
                last_checked_at: nuclei_comp.last_verified_at.clone(),
                prerequisite_health: None,
            };
            return (nuclei_cap, tmpl_cap);
        }
    }

    // Zero ambient host PATH fallback. Unprovisioned state is truthfully uninstalled.
    let uninstalled_nuclei = EngineCapability {
        available: false,
        version: None,
        templates_version: None,
        managed: Some(true),
        status: Some("not_installed".to_string()),
        integrity_status: Some("unknown".to_string()),
        path: None,
        last_checked_at: None,
        prerequisite_health: None,
    };
    (uninstalled_nuclei, None)
}

pub fn extract_nmap_version(output: &str) -> Option<String> {
    crate::toolchain::discovery::extract_version_string(output)
}

pub fn extract_nuclei_version(output: &str) -> Option<String> {
    for line in output.lines() {
        // Strip ANSI escape characters
        let clean_line: String = line.chars().filter(|c| *c != '\x1b' && *c >= ' ').collect();
        for token in clean_line.split_whitespace() {
            let clean = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '.');
            let ver = clean.trim_start_matches('v');
            let parts: Vec<&str> = ver.split('.').collect();
            if parts.len() >= 2
                && parts[0].chars().all(|c| c.is_ascii_digit())
                && parts[1].chars().all(|c| c.is_ascii_digit())
                && !parts[0].is_empty()
            {
                return Some(ver.to_string());
            }
        }
    }
    None
}

pub struct ScoutRunResult {
    pub job_id: Uuid,
    pub engine: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub started_at: String,
    pub completed_at: String,
    pub error_message: Option<String>,
}

/// Bounded non-shell execution of Nmap or Nuclei with strict argv profiles.
pub async fn run_scout_job(
    job_id: Uuid,
    engine: &str,
    pinned_target: &str,
    timeout_seconds: u64,
) -> ScoutRunResult {
    run_scout_job_with_context(
        job_id,
        engine,
        pinned_target,
        None,
        None,
        timeout_seconds,
        None,
    )
    .await
}

/// Bounded non-shell execution with explicit storage context for toolchain discovery and telemetry redaction.
pub async fn run_scout_job_with_storage(
    job_id: Uuid,
    engine: &str,
    pinned_target: &str,
    timeout_seconds: u64,
    storage_opt: Option<&StorageManager>,
) -> ScoutRunResult {
    run_scout_job_with_context(
        job_id,
        engine,
        pinned_target,
        None,
        None,
        timeout_seconds,
        storage_opt,
    )
    .await
}

/// Bounded non-shell execution with full context including original target and target_type for HTTP Host & TLS SNI binding.
pub async fn run_scout_job_with_context(
    job_id: Uuid,
    engine: &str,
    pinned_target: &str,
    original_target: Option<&str>,
    target_type: Option<&str>,
    timeout_seconds: u64,
    storage_opt: Option<&StorageManager>,
) -> ScoutRunResult {
    let started_at = Utc::now().to_rfc3339();
    let _guard = match ScoutJobGuard::try_acquire() {
        Ok(g) => g,
        Err(e) => {
            let completed_at = Utc::now().to_rfc3339();
            return ScoutRunResult {
                job_id,
                engine: engine.to_string(),
                status: "rejected".to_string(),
                exit_code: None,
                stdout: "".to_string(),
                stderr: "".to_string(),
                stdout_bytes: 0,
                stderr_bytes: 0,
                started_at,
                completed_at,
                error_message: Some(e.to_string()),
            };
        }
    };

    let mut managed_nuclei_bin: Option<PathBuf> = None;
    let mut managed_templates_dir: Option<PathBuf> = None;
    let mut nmap_binary_path: Option<PathBuf> = None;

    let (binary, args, default_timeout) = match engine {
        "nmap" => {
            let nmap_state = discover_external_nmap().await;
            match nmap_state {
                NmapPrerequisiteState::Ready { path, .. } => {
                    nmap_binary_path = Some(path.clone());
                    let bin_str = path.to_string_lossy().to_string();
                    let args = nmap_scout_args(pinned_target);
                    (bin_str, args, 180)
                }
                other => {
                    let completed_at = Utc::now().to_rfc3339();
                    return ScoutRunResult {
                        job_id,
                        engine: engine.to_string(),
                        status: "failed".to_string(),
                        exit_code: None,
                        stdout: "".to_string(),
                        stderr: "".to_string(),
                        stdout_bytes: 0,
                        stderr_bytes: 0,
                        started_at,
                        completed_at,
                        error_message: Some(format!(
                            "External Nmap prerequisite check failed: {}",
                            other.code()
                        )),
                    };
                }
            }
        }
        "nuclei" => {
            let storage = storage_opt
                .cloned()
                .unwrap_or_else(StorageManager::default_machine_storage);
            let state_path = storage.toolchain_state_path();

            let (n_bin, t_dir) = match ToolchainState::load(&state_path) {
                Ok(state) => {
                    let n_bin = state.components.get("nuclei").and_then(|c| {
                        if matches!(
                            c.status,
                            ComponentStatus::Installed | ComponentStatus::RolledBack
                        ) {
                            c.active_dir.as_ref().and_then(|dir| {
                                let exe_name = if cfg!(windows) { "nuclei.exe" } else { "nuclei" };
                                let exe = PathBuf::from(dir).join(exe_name);
                                if exe.exists() {
                                    Some(exe)
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    });
                    let t_dir = state.components.get("nuclei_templates").and_then(|t| {
                        if matches!(
                            t.status,
                            ComponentStatus::Installed | ComponentStatus::RolledBack
                        ) {
                            t.active_dir.as_ref().and_then(|dir| {
                                let p = PathBuf::from(dir);
                                if p.exists() && p.is_dir() {
                                    Some(p)
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    });
                    (n_bin, t_dir)
                }
                Err(_) => (None, None),
            };

            managed_nuclei_bin = n_bin;
            managed_templates_dir = t_dir;

            let bin_path = match managed_nuclei_bin.as_ref() {
                Some(p) => p,
                None => {
                    let completed_at = Utc::now().to_rfc3339();
                    return ScoutRunResult {
                        job_id,
                        engine: engine.to_string(),
                        status: "failed".to_string(),
                        exit_code: None,
                        stdout: "".to_string(),
                        stderr: "".to_string(),
                        stdout_bytes: 0,
                        stderr_bytes: 0,
                        started_at,
                        completed_at,
                        error_message: Some(
                            "Managed Nuclei binary is not installed or activated".to_string(),
                        ),
                    };
                }
            };

            let tmpl_path = match managed_templates_dir.as_ref() {
                Some(p) => p,
                None => {
                    let completed_at = Utc::now().to_rfc3339();
                    return ScoutRunResult {
                        job_id,
                        engine: engine.to_string(),
                        status: "failed".to_string(),
                        exit_code: None,
                        stdout: "".to_string(),
                        stderr: "".to_string(),
                        stdout_bytes: 0,
                        stderr_bytes: 0,
                        started_at,
                        completed_at,
                        error_message: Some(
                            "Managed Nuclei templates are not installed or activated".to_string(),
                        ),
                    };
                }
            };

            let bin_str = bin_path.to_string_lossy().to_string();
            let args = nuclei_scout_args(
                pinned_target,
                &tmpl_path.to_string_lossy(),
                original_target,
                target_type,
            );

            (bin_str, args, 1200)
        }
        _ => {
            let completed_at = Utc::now().to_rfc3339();
            return ScoutRunResult {
                job_id,
                engine: engine.to_string(),
                status: "rejected".to_string(),
                exit_code: None,
                stdout: "".to_string(),
                stderr: "".to_string(),
                stdout_bytes: 0,
                stderr_bytes: 0,
                started_at,
                completed_at,
                error_message: Some(format!("Unsupported engine '{}'", engine)),
            };
        }
    };

    let effective_timeout = if timeout_seconds > 0 {
        timeout_seconds
    } else {
        default_timeout
    };

    info!(
        "Executing bounded SCOUT job {} with engine '{}' on target '{}' (timeout: {}s)",
        job_id, engine, pinned_target, effective_timeout
    );

    let known_paths = KnownPaths {
        nuclei_path: managed_nuclei_bin.map(|p| p.to_string_lossy().to_string()),
        templates_path: managed_templates_dir.map(|p| p.to_string_lossy().to_string()),
        nmap_path: nmap_binary_path.map(|p| p.to_string_lossy().to_string()),
    };

    let mut cmd = Command::new(&binary);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let completed_at = Utc::now().to_rfc3339();
            error!("Failed to spawn engine '{}': {}", engine, e);
            let raw_msg = format!("Failed to spawn binary '{}'", binary);
            return ScoutRunResult {
                job_id,
                engine: engine.to_string(),
                status: "failed".to_string(),
                exit_code: None,
                stdout: "".to_string(),
                stderr: "".to_string(),
                stdout_bytes: 0,
                stderr_bytes: 0,
                started_at,
                completed_at,
                error_message: Some(redact_paths(&raw_msg, Some(&known_paths))),
            };
        }
    };

    let started_instant = Instant::now();
    let stdout_cap = Arc::new(Mutex::new(SharedCapture {
        buf: Vec::new(),
        total: 0,
        truncated: false,
    }));
    let stderr_cap = Arc::new(Mutex::new(SharedCapture {
        buf: Vec::new(),
        total: 0,
        truncated: false,
    }));
    let mut stdout_handle = child.stdout.take().expect("child stdout piped");
    let mut stderr_handle = child.stderr.take().expect("child stderr piped");
    let stdout_cap_task = Arc::clone(&stdout_cap);
    let stderr_cap_task = Arc::clone(&stderr_cap);

    let read_stdout_task = tokio::spawn(async move {
        let mut chunk = [0u8; 8192];
        loop {
            match stdout_handle.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => lock_capture(&stdout_cap_task).push(&chunk[..n]),
                Err(_) => break,
            }
        }
    });

    let read_stderr_task = tokio::spawn(async move {
        let mut chunk = [0u8; 8192];
        loop {
            match stderr_handle.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => lock_capture(&stderr_cap_task).push(&chunk[..n]),
                Err(_) => break,
            }
        }
    });

    let result = tokio::time::timeout(Duration::from_secs(effective_timeout), child.wait()).await;
    let completed_at = Utc::now().to_rfc3339();

    match result {
        Ok(status_res) => {
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                let _ = read_stdout_task.await;
                let _ = read_stderr_task.await;
            })
            .await;
            let (raw_stdout, stdout_bytes) = snapshot_capture(&stdout_cap);
            let (raw_stderr, stderr_bytes) = snapshot_capture(&stderr_cap);
            // Nmap can exit 0 after --host-timeout and mark the host as timed out
            // in XML. That is an incomplete scan, not an empty successful scan.
            let nmap_timed_out = nmap_host_timed_out(engine, &raw_stdout);
            let stdout = redact_paths(&raw_stdout, Some(&known_paths));
            let stderr = redact_paths(&raw_stderr, Some(&known_paths));

            match status_res {
                Ok(exit_status) => {
                    let code = exit_status.code().unwrap_or(-1);
                    let (status, err_msg) = if nmap_timed_out {
                        ("failed".to_string(), Some("timeout".to_string()))
                    } else if exit_status.success() {
                        ("completed".to_string(), None)
                    } else {
                        (
                            "failed".to_string(),
                            Some(redact_paths(
                                &format!("Engine exited with status {}", code),
                                Some(&known_paths),
                            )),
                        )
                    };
                    ScoutRunResult {
                        job_id,
                        engine: engine.to_string(),
                        status,
                        exit_code: Some(code),
                        stdout,
                        stderr,
                        stdout_bytes,
                        stderr_bytes,
                        started_at,
                        completed_at,
                        error_message: err_msg,
                    }
                }
                Err(e) => ScoutRunResult {
                    job_id,
                    engine: engine.to_string(),
                    status: "failed".to_string(),
                    exit_code: None,
                    stdout,
                    stderr,
                    stdout_bytes,
                    stderr_bytes,
                    started_at,
                    completed_at,
                    error_message: Some(redact_paths(
                        &format!("Error waiting for process: {}", e),
                        Some(&known_paths),
                    )),
                },
            }
        }
        Err(_) => {
            let elapsed = started_instant.elapsed().as_secs();
            warn!(
                "SCOUT job {} still running after {}s; killing and keeping partial output",
                job_id, effective_timeout
            );
            // The child has not exited. Kill it, keep bytes already captured,
            // and reap in the background so a stuck wait cannot eat the server margin.
            let _ = child.start_kill();
            tokio::time::sleep(Duration::from_millis(250)).await;
            let (raw_stdout, stdout_bytes) = snapshot_capture(&stdout_cap);
            let (raw_stderr, stderr_bytes) = snapshot_capture(&stderr_cap);
            let stdout = redact_paths(&raw_stdout, Some(&known_paths));
            let stderr = redact_paths(&raw_stderr, Some(&known_paths));
            let profile = sanitized_profile(&binary, &args, &known_paths);
            tokio::spawn(async move {
                let _guard = _guard;
                let _ = child.wait().await;
                read_stdout_task.abort();
                read_stderr_task.abort();
            });
            ScoutRunResult {
                job_id,
                engine: engine.to_string(),
                status: "timed_out".to_string(),
                exit_code: None,
                stdout,
                stderr,
                stdout_bytes,
                stderr_bytes,
                started_at,
                completed_at,
                error_message: Some(collector_deadline_message(
                    elapsed,
                    effective_timeout,
                    stdout_bytes,
                    stderr_bytes,
                    &profile,
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_self_timeout_precedes_collector_envelope() {
        let args = nmap_scout_args("192.0.2.1");
        assert!(args.windows(2).any(|w| w == ["--host-timeout", "120s"]));
        assert!(args.windows(2).any(|w| w == ["--max-retries", "2"]));
        assert_eq!(args.last().unwrap(), "192.0.2.1");
        assert!(120 < 180);
        assert!(nmap_host_timed_out(
            "nmap",
            "<host starttime=\"1\" timedout=\"true\"><status state=\"up\"/></host>"
        ));
        assert!(!nmap_host_timed_out("nmap", "<host timedout=\"false\"/>"));
    }

    #[tokio::test]
    async fn test_concurrency_guard() {
        let g1 = ScoutJobGuard::try_acquire();
        assert!(g1.is_ok());
        let g2 = ScoutJobGuard::try_acquire();
        assert!(g2.is_err());
        assert_eq!(g2.unwrap_err().to_string(), "concurrency_limit_exceeded");
        drop(g1);
        let g3 = ScoutJobGuard::try_acquire();
        assert!(g3.is_ok());
    }

    #[tokio::test]
    async fn test_unsupported_engine_rejection() {
        let res = run_scout_job(Uuid::new_v4(), "unknown_scanner", "10.0.0.1", 10).await;
        assert_eq!(res.status, "rejected");
        assert!(res.error_message.unwrap().contains("Unsupported engine"));
    }

    #[tokio::test]
    async fn test_capabilities_probing() {
        let caps = probe_scout_capabilities().await;
        assert_eq!(
            caps.collector_version,
            Some(env!("CARGO_PKG_VERSION").to_string())
        );
        // On dev host, either available or not, but never crashes or discloses paths
        if caps.nmap.available {
            assert!(caps.nmap.version.is_some());
        }
        if caps.nuclei.available {
            assert!(caps.nuclei.version.is_some());
        }
    }

    #[test]
    fn nuclei_deadline_profile_redacts_paths_and_names_its_limits() {
        let templates = r"C:\ProgramData\Tempris\Collector\tools\nuclei_templates\10.4.4";
        let binary = r"C:\ProgramData\Tempris\Collector\tools\nuclei\3.8.0\nuclei.exe";
        let args = nuclei_scout_args("192.0.2.10", templates, None, None);
        assert!(args.windows(2).any(|w| w == ["-timeout", "3"]));
        assert!(args.windows(2).any(|w| w == ["-retries", "0"]));
        assert!(args.windows(2).any(|w| w == ["-si", "15"]));
        assert!(args.iter().any(|arg| arg == "-sj"));
        assert!(args.iter().any(|arg| arg == "-ni"));
        assert!(args.iter().any(|arg| arg == "-duc"));
        let known = KnownPaths {
            nuclei_path: Some(binary.to_string()),
            templates_path: Some(templates.to_string()),
            nmap_path: None,
        };
        let profile = sanitized_profile(binary, &args, &known);
        assert!(profile.contains("[MANAGED_NUCLEI]"));
        assert!(profile.contains("[MANAGED_TEMPLATES]"));
        assert!(!profile.to_lowercase().contains("programdata"));
        let message = collector_deadline_message(300, 300, 12, 340, &profile);
        assert!(message.starts_with("collector_deadline:"));
        assert!(message.contains("termination=collector_deadline"));
        assert!(message.contains("elapsed=300s"));
        assert!(message.contains("deadline=300s"));
        assert!(message.contains("stdout_bytes=12"));
        assert!(message.contains("stderr_bytes=340"));
    }

    #[test]
    fn test_version_extractors() {
        assert_eq!(
            extract_nmap_version("Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64"),
            Some("7.94".to_string())
        );
        assert_eq!(
            extract_nuclei_version("[INF] Current Version: v3.3.0\n[INF] Templates: v10.0.0"),
            Some("3.3.0".to_string())
        );
    }
}
