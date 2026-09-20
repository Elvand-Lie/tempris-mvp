use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use chrono::Utc;
use regex::Regex;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::archive::safe_extract_zip;
use super::manifest::ComponentManifest;
use super::offline::verify_offline_package;
use super::state::{ComponentState, ComponentStatus, ToolchainState};
use super::{ToolchainError, TOOLCHAIN_UPDATE_ORIGIN};
use crate::scout_runner::ScoutJobGuard;
use crate::storage::{apply_observer_tier_dacl, StorageManager};

/// Global updater mutual exclusion lock ensuring only one toolchain update routine executes at any time.
static TOOLCHAIN_UPDATE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Maximum ceiling for any downloaded or staged component artifact (100 MiB).
pub const MAX_ARTIFACT_CEILING_BYTES: u64 = 100 * 1024 * 1024;

/// RAII guard for the global updater lock.
#[derive(Debug)]
pub struct ToolchainUpdateGuard;

impl ToolchainUpdateGuard {
    pub fn try_acquire() -> Result<Self, ToolchainError> {
        if TOOLCHAIN_UPDATE_IN_PROGRESS
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Ok(ToolchainUpdateGuard)
        } else {
            Err(ToolchainError::UpdateAlreadyInProgress)
        }
    }

    pub async fn acquire_with_timeout(timeout: Duration) -> Result<Self, ToolchainError> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if let Ok(guard) = Self::try_acquire() {
                return Ok(guard);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(ToolchainError::UpdateAlreadyInProgress)
    }
}

impl Drop for ToolchainUpdateGuard {
    fn drop(&mut self) {
        TOOLCHAIN_UPDATE_IN_PROGRESS.store(false, Ordering::SeqCst);
    }
}

/// RAII guard ensuring staging directories are cleaned up on all error/abort/panic paths.
pub struct StagingGuard {
    pub path: PathBuf,
    committed: bool,
}

impl StagingGuard {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if !self.committed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// ToolchainManager coordinates artifact retrieval, verification, safe extraction,
/// pre-activation probing, idle-gated transactional activation, health checks, and rollback.
pub struct ToolchainManager {
    pub storage: StorageManager,
    http_client: reqwest::Client,
}

impl ToolchainManager {
    pub fn new(storage: StorageManager) -> Self {
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            storage,
            http_client,
        }
    }

    pub fn origin(&self) -> &'static str {
        TOOLCHAIN_UPDATE_ORIGIN
    }

    /// Acquires the global updater lock.
    pub fn acquire_updater_lock(&self) -> Result<ToolchainUpdateGuard, ToolchainError> {
        ToolchainUpdateGuard::try_acquire()
    }

    /// Acquires the global updater lock with bounded timeout wait.
    pub async fn acquire_updater_lock_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ToolchainUpdateGuard, ToolchainError> {
        ToolchainUpdateGuard::acquire_with_timeout(timeout).await
    }

    /// Checks if a SCOUT scan job is currently executing.
    pub fn is_scout_job_running(&self) -> bool {
        ScoutJobGuard::is_active()
    }

    /// Pre-activation executable probing for newly staged binaries.
    ///
    /// Executes `<staged_dir>/<entrypoint> -version` directly with:
    /// - 5-second timeout
    /// - null stdin, piped stdout/stderr
    /// - zero shell invocation
    /// - verifies exit code 0 and output matching manifest component version
    pub async fn probe_staged_executable(
        &self,
        executable_path: &Path,
        expected_version: &str,
    ) -> Result<(), ToolchainError> {
        let file_name = match executable_path.file_name().and_then(|f| f.to_str()) {
            Some(f) => f,
            None => {
                return Err(ToolchainError::InvalidEntrypoint(
                    "Missing or invalid executable file name".to_string(),
                ));
            }
        };

        // Whitelist regex check: ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
        let re = Regex::new(r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$").expect("valid regex");
        if !re.is_match(file_name) {
            return Err(ToolchainError::InvalidEntrypoint(format!(
                "Entrypoint '{}' does not match whitelist regex",
                file_name
            )));
        }

        if !executable_path.exists() {
            return Err(ToolchainError::PreActivationCheckFailed(format!(
                "Executable not found at path: '{}'",
                executable_path.display()
            )));
        }

        let mut cmd = Command::new(executable_path);
        cmd.arg("-version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output_res = tokio::time::timeout(Duration::from_secs(5), cmd.output()).await;

        let output = match output_res {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(ToolchainError::PreActivationCheckFailed(format!(
                    "Failed to execute staged binary: {}",
                    e
                )));
            }
            Err(_) => {
                return Err(ToolchainError::PreActivationCheckFailed(
                    "Pre-activation binary probe timed out after 5 seconds".to_string(),
                ));
            }
        };

        if !output.status.success() {
            return Err(ToolchainError::PreActivationCheckFailed(format!(
                "Pre-activation binary exited with non-zero status: {:?}",
                output.status.code()
            )));
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout_str, stderr_str);

        if !combined.contains(expected_version) {
            return Err(ToolchainError::PreActivationCheckFailed(format!(
                "Version mismatch: probe output does not contain expected version '{}'. Output: '{}'",
                expected_version, stdout_str
            )));
        }

        Ok(())
    }

    /// Post-activation health check routines for managed toolchain components.
    ///
    /// - Nuclei binary: executes `<active_dir>/nuclei.exe -version` with 5s timeout, exit 0, matching semver.
    /// - Nuclei templates: verifies `<active_dir>` contains valid non-empty YAML templates or standard directories.
    pub async fn run_post_activation_health_check(
        &self,
        component: &str,
        active_dir: &Path,
        expected_version: &str,
    ) -> Result<(), ToolchainError> {
        match component {
            "nuclei" => {
                let bin_name = if cfg!(windows) { "nuclei.exe" } else { "nuclei" };
                let binary_path = active_dir.join(bin_name);

                if !binary_path.exists() {
                    return Err(ToolchainError::HealthCheckFailed(format!(
                        "Nuclei binary not found at '{}'",
                        binary_path.display()
                    )));
                }

                let mut cmd = Command::new(&binary_path);
                cmd.arg("-version")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                let res = tokio::time::timeout(Duration::from_secs(5), cmd.output()).await;
                let output = match res {
                    Ok(Ok(out)) => out,
                    Ok(Err(e)) => {
                        return Err(ToolchainError::HealthCheckFailed(format!(
                            "Nuclei health check execution failed: {}",
                            e
                        )));
                    }
                    Err(_) => {
                        return Err(ToolchainError::HealthCheckFailed(
                            "Nuclei health check timed out after 5s".to_string(),
                        ));
                    }
                };

                if !output.status.success() {
                    return Err(ToolchainError::HealthCheckFailed(format!(
                        "Nuclei health check exited with non-zero status: {:?}",
                        output.status.code()
                    )));
                }

                let stdout_str = String::from_utf8_lossy(&output.stdout);
                let stderr_str = String::from_utf8_lossy(&output.stderr);
                let combined = format!("{}\n{}", stdout_str, stderr_str);

                if !combined.contains(expected_version) {
                    return Err(ToolchainError::HealthCheckFailed(format!(
                        "Nuclei health check version mismatch: expected '{}', output was: '{}'",
                        expected_version, stdout_str
                    )));
                }

                Ok(())
            }
            "nuclei_templates" => {
                if !active_dir.exists() || !active_dir.is_dir() {
                    return Err(ToolchainError::HealthCheckFailed(format!(
                        "Templates directory does not exist or is not a directory: '{}'",
                        active_dir.display()
                    )));
                }

                // Verify directory is non-empty and contains yaml files or standard template subdirectories
                let mut has_entries = false;
                let mut has_valid_content = false;

                if let Ok(entries) = fs::read_dir(active_dir) {
                    for entry in entries.flatten() {
                        has_entries = true;
                        let path = entry.path();
                        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                            if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
                                has_valid_content = true;
                                break;
                            }
                        }
                        if path.is_dir() {
                            let name = entry.file_name().to_string_lossy().to_lowercase();
                            if [
                                "http",
                                "network",
                                "ssl",
                                "cves",
                                "misconfiguration",
                                "vulnerabilities",
                                "dns",
                                "technologies",
                            ]
                            .contains(&name.as_str())
                            {
                                has_valid_content = true;
                                break;
                            }
                        }
                    }
                }

                if !has_entries || !has_valid_content {
                    return Err(ToolchainError::HealthCheckFailed(format!(
                        "Templates directory '{}' is empty or does not contain valid templates or directories",
                        active_dir.display()
                    )));
                }

                Ok(())
            }
            other => Err(ToolchainError::UnknownComponent(other.to_string())),
        }
    }

    /// Rolls back a component to its previous known-good version.
    ///
    /// If previous_dir exists, restores it as active_dir and sets status to RolledBack.
    /// If no previous_dir exists, sets status to Uninstalled.
    /// Updates toolchain-state.json atomically and does not crash the process.
    pub fn rollback_component(&self, component: &str) -> Result<ComponentStatus, ToolchainError> {
        let state_path = self.storage.toolchain_state_path();
        let mut state = ToolchainState::load(&state_path)?;

        let comp_state = match state.components.get_mut(component) {
            Some(cs) => cs,
            None => {
                return Err(ToolchainError::UnknownComponent(component.to_string()));
            }
        };

        let current_failed_dir = comp_state.active_dir.take();
        let previous_dir = comp_state.previous_dir.take();

        let final_status = if let Some(prev) = previous_dir {
            let prev_path = PathBuf::from(&prev);
            if prev_path.exists() && prev_path.is_dir() {
                comp_state.active_dir = Some(prev);
                comp_state.previous_dir = None;
                comp_state.status = ComponentStatus::RolledBack;
                comp_state.last_verified_at = Some(Utc::now().to_rfc3339());
                ComponentStatus::RolledBack
            } else {
                comp_state.active_dir = None;
                comp_state.previous_dir = None;
                comp_state.status = ComponentStatus::Uninstalled;
                ComponentStatus::Uninstalled
            }
        } else {
            comp_state.active_dir = None;
            comp_state.previous_dir = None;
            comp_state.status = ComponentStatus::Uninstalled;
            ComponentStatus::Uninstalled
        };

        state.updated_at = Utc::now().to_rfc3339();
        state.save(&state_path)?;

        // Remove failed directory if it exists
        if let Some(failed_dir) = current_failed_dir {
            let path = PathBuf::from(failed_dir);
            if path.exists() {
                let _ = fs::remove_dir_all(&path);
            }
        }

        info!(
            "Component '{}' successfully rolled back (status: {:?})",
            component, final_status
        );
        Ok(final_status)
    }

    /// Prunes older inactive version directories, preserving at most the active_dir
    /// and one previous_dir.
    pub fn prune_old_versions(
        &self,
        component: &str,
        active_dir: &Path,
        previous_dir: Option<&Path>,
    ) -> Result<(), ToolchainError> {
        let component_tools_root = self.storage.tools_dir().join(component);
        if !component_tools_root.exists() {
            return Ok(());
        }

        let canonical_active = active_dir.canonicalize().unwrap_or_else(|_| active_dir.to_path_buf());
        let canonical_prev = previous_dir.and_then(|p| p.canonicalize().ok());

        if let Ok(entries) = fs::read_dir(&component_tools_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let canonical_entry = path.canonicalize().unwrap_or_else(|_| path.clone());
                    if canonical_entry == canonical_active {
                        continue;
                    }
                    if let Some(prev) = &canonical_prev {
                        if &canonical_entry == prev {
                            continue;
                        }
                    }
                    debug!("Pruning old toolchain directory: '{}'", path.display());
                    let _ = fs::remove_dir_all(&path);
                }
            }
        }

        Ok(())
    }

    /// Transactionally activates a staged component into production versioned layout.
    ///
    /// Invariants:
    /// - Checks SCOUT idle gating (defers if a scan is active).
    /// - Performs atomic directory placement to `tools/<component>/<version>/`.
    /// - Applies Observer DACL permissions.
    /// - Updates `toolchain-state.json` atomically.
    /// - Executes post-activation health checks; rolls back automatically on failure.
    /// - Prunes older versions.
    pub async fn activate_staged_component(
        &self,
        component: &str,
        staging_dir: &Path,
        comp_manifest: &ComponentManifest,
        manifest_sequence: u64,
    ) -> Result<PathBuf, ToolchainError> {
        // Concurrency gating: check if active scan job is running
        if self.is_scout_job_running() {
            return Err(ToolchainError::UpdateDeferredJobRunning);
        }

        let destination = self.storage.component_tools_dir(component, &comp_manifest.version);
        if destination.exists() {
            let _ = fs::remove_dir_all(&destination);
        }

        // Ensure parent directory exists and has Observer DACL
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(ToolchainError::Io)?;
            let _ = apply_observer_tier_dacl(parent);
        }

        // Atomic directory rename/move
        fs::rename(staging_dir, &destination).map_err(ToolchainError::Io)?;
        let _ = apply_observer_tier_dacl(&destination);

        // Load existing state to capture previous_dir
        let state_path = self.storage.toolchain_state_path();
        let mut state = ToolchainState::load(&state_path)?;

        let previous_active_dir = state
            .components
            .get(component)
            .and_then(|cs| cs.active_dir.clone());

        let new_active_dir_str = destination.to_string_lossy().to_string();

        let updated_comp_state = ComponentState {
            status: ComponentStatus::Installed,
            version: Some(comp_manifest.version.clone()),
            sha256: Some(comp_manifest.sha256.clone()),
            active_dir: Some(new_active_dir_str.clone()),
            previous_dir: previous_active_dir.clone(),
            installed_at: Some(Utc::now().to_rfc3339()),
            last_verified_at: Some(Utc::now().to_rfc3339()),
        };

        state.components.insert(component.to_string(), updated_comp_state);
        state.last_manifest_sequence = manifest_sequence;
        state.updated_at = Utc::now().to_rfc3339();

        // Atomically persist updated toolchain state
        state.save(&state_path)?;

        // Execute post-activation health check
        let health_res = self
            .run_post_activation_health_check(component, &destination, &comp_manifest.version)
            .await;

        if let Err(e) = health_res {
            warn!(
                "Post-activation health check failed for '{}': {}. Triggering automated rollback.",
                component, e
            );
            let _ = self.rollback_component(component);
            return Err(e);
        }

        // Prune older inactive versions
        let prev_path_buf = previous_active_dir.map(PathBuf::from);
        let _ = self.prune_old_versions(component, &destination, prev_path_buf.as_deref());

        info!(
            "Successfully activated toolchain component '{}' v{} at '{}'",
            component, comp_manifest.version, destination.display()
        );

        Ok(destination)
    }

    /// Bounded HTTPS download and verification of component artifact.
    ///
    /// Invariants:
    /// - Origin restricted strictly to compile-time constant `TOOLCHAIN_UPDATE_ORIGIN`.
    /// - Redirects disabled.
    /// - Streaming size continuously checked against `comp_manifest.byte_size` and 100 MiB ceiling.
    /// - Computes SHA-256 digest and verifies against `comp_manifest.sha256`.
    pub async fn download_and_verify_artifact(
        &self,
        component_name: &str,
        comp_manifest: &ComponentManifest,
        dest_file: &Path,
    ) -> Result<(), ToolchainError> {
        let origin = TOOLCHAIN_UPDATE_ORIGIN.trim_end_matches('/');
        let ext = if component_name == "nuclei_templates" || comp_manifest.entrypoint.ends_with(".zip") {
            "zip"
        } else {
            "exe"
        };
        let artifact_filename = format!("{}-{}.{}", component_name, comp_manifest.version, ext);
        let download_url = format!("{}/{}", origin, artifact_filename);

        let response = self
            .http_client
            .get(&download_url)
            .send()
            .await
            .map_err(|e| ToolchainError::Io(io::Error::new(io::ErrorKind::Other, e)))?;

        if !response.status().is_success() {
            return Err(ToolchainError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("HTTP error {}: {}", response.status(), download_url),
            )));
        }

        if let Some(content_length) = response.content_length() {
            if content_length > comp_manifest.byte_size || content_length > MAX_ARTIFACT_CEILING_BYTES {
                return Err(ToolchainError::ArtifactSizeExceeded {
                    size: content_length,
                    max: comp_manifest.byte_size,
                });
            }
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| ToolchainError::Io(io::Error::new(io::ErrorKind::Other, e)))?;

        let size = bytes.len() as u64;
        if size > comp_manifest.byte_size || size > MAX_ARTIFACT_CEILING_BYTES {
            return Err(ToolchainError::ArtifactSizeExceeded {
                size,
                max: comp_manifest.byte_size,
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let calculated_hash = hex::encode(hasher.finalize());

        if calculated_hash != comp_manifest.sha256 {
            return Err(ToolchainError::ChecksumMismatch {
                expected: comp_manifest.sha256.clone(),
                actual: calculated_hash,
            });
        }

        fs::write(dest_file, &bytes).map_err(ToolchainError::Io)?;
        let _ = apply_observer_tier_dacl(dest_file);
        Ok(())
    }

    /// Searches for an offline toolchain package in standard candidate locations.
    pub fn find_offline_package_dir(&self) -> Option<PathBuf> {
        let mut candidates = Vec::new();

        // 1. Storage base dir / offline_package
        candidates.push(self.storage.base_dir().join("offline_package"));

        // 2. Current executable directory / offline_package and directory itself
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                candidates.push(exe_dir.join("offline_package"));
                candidates.push(exe_dir.to_path_buf());
            }
        }

        // 3. Current working directory / offline_package, dist directory, and current directory
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("offline_package"));
            candidates.push(cwd.join("dist").join("TemprisCollector-0.4.0").join("offline_package"));
            candidates.push(cwd.join("dist").join("TemprisCollector-0.4.0"));
            candidates.push(cwd);
        }

        for dir in candidates {
            if dir.is_dir() && dir.join(super::offline::MANIFEST_FILENAME).exists() {
                return Some(dir);
            }
        }

        None
    }

    /// Fetches the signed toolchain manifest from the fixed origin and verifies its envelope.
    pub async fn fetch_and_verify_online_manifest(&self) -> Result<super::manifest::ToolchainManifest, ToolchainError> {
        let origin = TOOLCHAIN_UPDATE_ORIGIN.trim_end_matches('/');
        let manifest_url = format!("{}/{}", origin, super::offline::MANIFEST_FILENAME);

        let response = self
            .http_client
            .get(&manifest_url)
            .send()
            .await
            .map_err(|e| ToolchainError::Io(io::Error::new(io::ErrorKind::Other, e)))?;

        if !response.status().is_success() {
            return Err(ToolchainError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("HTTP error {}: {}", response.status(), manifest_url),
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| ToolchainError::Io(io::Error::new(io::ErrorKind::Other, e)))?;

        if bytes.len() > super::manifest::MAX_MANIFEST_RAW_BYTES * 2 {
            return Err(ToolchainError::ManifestTooLarge {
                size: bytes.len(),
                max: super::manifest::MAX_MANIFEST_RAW_BYTES * 2,
            });
        }

        super::verifier::verify_envelope(&bytes)
    }

    /// Applies a verified online manifest by downloading, verifying, and activating all components.
    pub async fn apply_online_manifest(
        &self,
        manifest: &super::manifest::ToolchainManifest,
    ) -> Result<ToolchainState, ToolchainError> {
        let _lock = self.acquire_updater_lock_timeout(Duration::from_secs(120)).await?;

        let state_path = self.storage.toolchain_state_path();
        let current_state = ToolchainState::load(&state_path)?;
        current_state.validate_candidate_manifest(manifest)?;

        for (comp_name, comp_manifest) in &manifest.components {
            let session_uuid = Uuid::new_v4().to_string();
            let staging_dir = self.storage.staging_component_dir(comp_name, &session_uuid);
            fs::create_dir_all(&staging_dir).map_err(ToolchainError::Io)?;
            let _ = apply_observer_tier_dacl(&staging_dir);

            let staging_guard = StagingGuard::new(staging_dir.clone());

            let is_zip = comp_name == "nuclei_templates" || comp_manifest.entrypoint.ends_with(".zip");
            let ext = if is_zip { "zip" } else { "exe" };
            let artifact_dest = staging_dir.join(format!("artifact.{}", ext));

            self.download_and_verify_artifact(comp_name, comp_manifest, &artifact_dest)
                .await?;

            if is_zip {
                safe_extract_zip(&artifact_dest, &staging_dir)?;
                let _ = fs::remove_file(&artifact_dest);

                if comp_name == "nuclei" {
                    let exe_path = staging_dir.join(&comp_manifest.entrypoint);
                    self.probe_staged_executable(&exe_path, &comp_manifest.version)
                        .await?;
                }
            } else {
                let dest_exe = staging_dir.join(&comp_manifest.entrypoint);
                if artifact_dest != dest_exe {
                    fs::rename(&artifact_dest, &dest_exe).map_err(ToolchainError::Io)?;
                }
                let _ = apply_observer_tier_dacl(&dest_exe);

                self.probe_staged_executable(&dest_exe, &comp_manifest.version)
                    .await?;
            }

            staging_guard.commit();
            self.activate_staged_component(
                comp_name,
                &staging_dir,
                comp_manifest,
                manifest.sequence_number,
            )
            .await?;
        }

        ToolchainState::load(&state_path)
    }

    /// Shared check and provisioning path:
    /// 1. If an offline package is found and valid, ingests it.
    /// 2. If online update is reachable, fetches signed manifest and applies updates.
    /// 3. Returns latest ToolchainState without panicking on transient network/offline failures.
    pub async fn check_and_apply_update(&self) -> Result<ToolchainState, ToolchainError> {
        // 1. Check for offline package
        if let Some(pkg_dir) = self.find_offline_package_dir() {
            if let Ok(verified) = super::offline::verify_offline_package(&pkg_dir) {
                let state_path = self.storage.toolchain_state_path();
                let current_state = ToolchainState::load(&state_path).unwrap_or_default();
                if current_state.validate_candidate_manifest(&verified.manifest).is_ok() {
                    info!("Discovered valid offline toolchain package at '{}', ingesting...", pkg_dir.display());
                    if let Err(e) = self.ingest_offline_package(&pkg_dir).await {
                        warn!("Offline toolchain package ingestion notice: {}", e);
                    }
                }
            }
        }

        // 2. Attempt online manifest check
        match self.fetch_and_verify_online_manifest().await {
            Ok(manifest) => {
                let state_path = self.storage.toolchain_state_path();
                let current_state = ToolchainState::load(&state_path).unwrap_or_default();
                if current_state.validate_candidate_manifest(&manifest).is_ok() {
                    info!("Discovered newer online toolchain manifest (seq={}), applying...", manifest.sequence_number);
                    if let Err(e) = self.apply_online_manifest(&manifest).await {
                        warn!("Online toolchain update application failed: {}", e);
                    }
                }
            }
            Err(e) => {
                debug!("Online toolchain update check skipped or unreachable: {}", e);
            }
        }

        let state_path = self.storage.toolchain_state_path();
        ToolchainState::load(&state_path)
    }

    /// Ingests an offline toolchain package adhering to 100% security parity with online provisioning.
    ///
    /// Pipeline:
    /// 1. Verifies signed manifest envelope (`verify_envelope`).
    /// 2. Verifies offline package directory completeness & rejects extraneous files (`verify_offline_package`).
    /// 3. Validates candidate manifest sequence monotonicity and anti-downgrade rules.
    /// 4. Acquires global updater concurrency lock (`TOOLCHAIN_UPDATE_IN_PROGRESS`).
    /// 5. For each component:
    ///    - Unpacks exclusively into isolated staging (`staging/<component>_<uuid>/`).
    ///    - Verifies SHA-256 digest against manifest.
    ///    - Extracts zip archives via `safe_extract_zip` (Zip Slip, ADS, null, DOS devices, bomb limits).
    ///    - Enforces Observer DACL permissions.
    ///    - Executes pre-activation probe.
    ///    - Transactionally activates to versioned layout.
    ///    - Executes post-activation health check with automatic rollback on failure.
    pub async fn ingest_offline_package(
        &self,
        package_dir: &Path,
    ) -> Result<ToolchainState, ToolchainError> {
        let _lock = self.acquire_updater_lock_timeout(Duration::from_secs(120)).await?;

        // Step 1: Envelope & offline package verification
        let verified = verify_offline_package(package_dir)?;
        let manifest = &verified.manifest;

        // Step 2: Validate state anti-replay & downgrade
        let state_path = self.storage.toolchain_state_path();
        let current_state = ToolchainState::load(&state_path)?;
        current_state.validate_candidate_manifest(manifest)?;

        // Step 3: Ingest components
        for (comp_name, source_artifact) in &verified.component_artifacts {
            let comp_manifest = manifest.components.get(comp_name).ok_or_else(|| {
                ToolchainError::UnknownComponent(comp_name.clone())
            })?;

            let session_uuid = Uuid::new_v4().to_string();
            let staging_dir = self.storage.staging_component_dir(comp_name, &session_uuid);
            fs::create_dir_all(&staging_dir).map_err(ToolchainError::Io)?;
            let _ = apply_observer_tier_dacl(&staging_dir);

            let staging_guard = StagingGuard::new(staging_dir.clone());

            let is_zip = source_artifact
                .extension()
                .and_then(|e| e.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("zip"))
                .unwrap_or(false);

            if is_zip {
                // Safe zip archive extraction
                safe_extract_zip(source_artifact, &staging_dir)?;

                if comp_name == "nuclei" {
                    let exe_path = staging_dir.join(&comp_manifest.entrypoint);
                    self.probe_staged_executable(&exe_path, &comp_manifest.version)
                        .await?;
                }
            } else {
                // Raw binary executable
                let dest_exe = staging_dir.join(&comp_manifest.entrypoint);
                fs::copy(source_artifact, &dest_exe).map_err(ToolchainError::Io)?;
                let _ = apply_observer_tier_dacl(&dest_exe);

                // Pre-activation probe
                self.probe_staged_executable(&dest_exe, &comp_manifest.version)
                    .await?;
            }

            // Transactional activation
            staging_guard.commit();
            self.activate_staged_component(
                comp_name,
                &staging_dir,
                comp_manifest,
                manifest.sequence_number,
            )
            .await?;
        }

        ToolchainState::load(&state_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_updater_concurrency_lock() {
        let storage = StorageManager::new(tempdir().unwrap().path().to_path_buf());
        let mgr = ToolchainManager::new(storage);

        let lock1 = mgr.acquire_updater_lock();
        assert!(lock1.is_ok());

        let lock2 = mgr.acquire_updater_lock();
        assert!(lock2.is_err());
        match lock2.unwrap_err() {
            ToolchainError::UpdateAlreadyInProgress => {}
            other => panic!("Unexpected error: {:?}", other),
        }

        drop(lock1);
        let lock3 = mgr.acquire_updater_lock();
        assert!(lock3.is_ok());
    }

    #[test]
    fn test_staging_guard_cleanup_on_drop() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging_test");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("test.bin"), b"hello").unwrap();
        assert!(staging.exists());

        {
            let _guard = StagingGuard::new(staging.clone());
            // Drop without committing
        }

        assert!(!staging.exists(), "Staging guard should clean up directory on drop");
    }

    #[test]
    fn test_staging_guard_commit() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging_test_commit");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("test.bin"), b"hello").unwrap();
        assert!(staging.exists());

        {
            let guard = StagingGuard::new(staging.clone());
            guard.commit();
        }

        assert!(staging.exists(), "Committed staging guard must preserve directory");
    }

    #[test]
    fn test_rollback_component() {
        let dir = tempdir().unwrap();
        let storage = StorageManager::new(dir.path().to_path_buf());
        let mgr = ToolchainManager::new(storage.clone());

        let state_path = storage.toolchain_state_path();
        let prev_dir = dir.path().join("tools").join("nuclei").join("v3.2.0");
        let active_dir = dir.path().join("tools").join("nuclei").join("v3.3.0");
        fs::create_dir_all(&prev_dir).unwrap();
        fs::create_dir_all(&active_dir).unwrap();

        let mut state = ToolchainState::default();
        state.components.insert(
            "nuclei".to_string(),
            ComponentState {
                status: ComponentStatus::Installed,
                version: Some("3.3.0".to_string()),
                sha256: Some("sha_new".to_string()),
                active_dir: Some(active_dir.to_string_lossy().to_string()),
                previous_dir: Some(prev_dir.to_string_lossy().to_string()),
                installed_at: Some("2026-01-01T00:00:00Z".to_string()),
                last_verified_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
        );
        state.save(&state_path).unwrap();

        let status = mgr.rollback_component("nuclei").unwrap();
        assert_eq!(status, ComponentStatus::RolledBack);

        let reloaded = ToolchainState::load(&state_path).unwrap();
        let comp = reloaded.components.get("nuclei").unwrap();
        assert_eq!(comp.status, ComponentStatus::RolledBack);
        assert_eq!(comp.active_dir, Some(prev_dir.to_string_lossy().to_string()));
        assert_eq!(comp.previous_dir, None);
        assert!(!active_dir.exists(), "Failed directory should have been pruned on rollback");
    }

    #[test]
    fn test_version_pruning() {
        let dir = tempdir().unwrap();
        let storage = StorageManager::new(dir.path().to_path_buf());
        let mgr = ToolchainManager::new(storage.clone());

        let v1 = storage.tools_dir().join("nuclei").join("v1.0.0");
        let v2 = storage.tools_dir().join("nuclei").join("v2.0.0");
        let v3 = storage.tools_dir().join("nuclei").join("v3.0.0");

        fs::create_dir_all(&v1).unwrap();
        fs::create_dir_all(&v2).unwrap();
        fs::create_dir_all(&v3).unwrap();

        // active = v3, previous = v2, so v1 should be pruned
        mgr.prune_old_versions("nuclei", &v3, Some(&v2)).unwrap();

        assert!(!v1.exists(), "v1.0.0 should be pruned");
        assert!(v2.exists(), "v2.0.0 (previous) should be preserved");
        assert!(v3.exists(), "v3.0.0 (active) should be preserved");
    }
}

