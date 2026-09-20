use std::collections::BTreeMap;
use std::path::Path;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::manifest::ToolchainManifest;
use super::ToolchainError;
use crate::storage::atomic_write_file_with_tier;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Uninstalled,
    Installed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComponentState {
    pub status: ComponentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<String>,
}

impl Default for ComponentState {
    fn default() -> Self {
        Self {
            status: ComponentStatus::Uninstalled,
            version: None,
            sha256: None,
            active_dir: None,
            previous_dir: None,
            installed_at: None,
            last_verified_at: None,
        }
    }
}

/// Durable toolchain state tracked in `%PROGRAMDATA%\Tempris\Collector\toolchain-state.json`.
/// Sealed with `deny_unknown_fields`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolchainState {
    pub schema_version: u32,
    pub last_manifest_sequence: u64,
    pub updated_at: String,
    pub components: BTreeMap<String, ComponentState>,
}

impl Default for ToolchainState {
    fn default() -> Self {
        let mut components = BTreeMap::new();
        components.insert("nuclei".to_string(), ComponentState::default());
        components.insert("nuclei_templates".to_string(), ComponentState::default());

        Self {
            schema_version: 1,
            last_manifest_sequence: 0,
            updated_at: Utc::now().to_rfc3339(),
            components,
        }
    }
}

impl ToolchainState {
    /// Loads toolchain state from the specified path.
    /// If the file does not exist, returns initialized default state with sequence = 0.
    /// If the file exists but contains corrupt or unmodeled JSON, fails closed with CorruptToolchainState.
    pub fn load(path: &Path) -> Result<Self, ToolchainError> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let bytes = std::fs::read(path)
            .map_err(|e| ToolchainError::Io(e))?;

        let state_str = std::str::from_utf8(&bytes)
            .map_err(|e| ToolchainError::CorruptToolchainState(format!("Invalid UTF-8: {}", e)))?;

        let state: ToolchainState = serde_json::from_str(state_str)
            .map_err(|e| ToolchainError::CorruptToolchainState(format!("Invalid JSON schema: {}", e)))?;

        if state.schema_version != 1 {
            return Err(ToolchainError::UnsupportedSchemaVersion(state.schema_version));
        }

        Ok(state)
    }

    /// Atomically persists toolchain state using the Observer DACL tier.
    pub fn save(&self, path: &Path) -> Result<(), ToolchainError> {
        let json_data = serde_json::to_vec_pretty(self)
            .map_err(|e| ToolchainError::CorruptToolchainState(e.to_string()))?;

        atomic_write_file_with_tier(path, &json_data, false)
            .map_err(|e| ToolchainError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Evaluates anti-replay and downgrade constraints against a candidate manifest.
    ///
    /// Strict Invariants:
    /// 1. Sequence number MUST be strictly greater than last_manifest_sequence (Anti-Replay).
    ///    Even for emergency rollbacks, sequence monotonicity is strictly required.
    /// 2. Component version must be >= installed version, unless is_emergency_rollback == true.
    pub fn validate_candidate_manifest(&self, manifest: &ToolchainManifest) -> Result<(), ToolchainError> {
        // Monotonic sequence enforcement: unconditionally required for both normal updates and emergency rollbacks
        if manifest.sequence_number <= self.last_manifest_sequence {
            return Err(ToolchainError::ReplayDetected {
                manifest_sequence: manifest.sequence_number,
                last_sequence: self.last_manifest_sequence,
            });
        }

        // Downgrade protection per component
        for (comp_name, comp_manifest) in &manifest.components {
            if let Some(current_state) = self.components.get(comp_name) {
                if current_state.status == ComponentStatus::Installed {
                    if let Some(current_ver_str) = &current_state.version {
                        let current_semver = semver::Version::parse(current_ver_str)
                            .map_err(|e| ToolchainError::InvalidSemver(format!("Current version '{}': {}", current_ver_str, e)))?;

                        let candidate_semver = semver::Version::parse(&comp_manifest.version)
                            .map_err(|e| ToolchainError::InvalidSemver(format!("Candidate version '{}': {}", comp_manifest.version, e)))?;

                        if candidate_semver < current_semver {
                            if !comp_manifest.is_emergency_rollback {
                                return Err(ToolchainError::UnauthorizedDowngrade {
                                    component: comp_name.clone(),
                                    current_version: current_ver_str.clone(),
                                    candidate_version: comp_manifest.version.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
