use std::collections::BTreeMap;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::ToolchainError;

pub const MAX_MANIFEST_RAW_BYTES: usize = 65_536; // 64 KiB
pub const MAX_COMPONENT_ARTIFACT_BYTES: u64 = 104_857_600; // 100 MiB

pub const ALLOWED_MANAGED_COMPONENTS: &[&str] = &["nuclei", "nuclei_templates"];

const RESERVED_DOS_DEVICES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Canonical envelope wrapping a signed manifest.
/// Strictly enforces schema sealing with `deny_unknown_fields`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolchainEnvelope {
    pub format_version: u32,
    pub key_id: String,
    pub signature: String,
    pub manifest_raw: String,
}

/// Target platform specification for a component artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlatformSpec {
    pub os: String,
    pub arch: String,
}

/// Manifest specification for an individual component artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComponentManifest {
    pub version: String,
    pub platform: PlatformSpec,
    pub sha256: String,
    pub byte_size: u64,
    pub entrypoint: String,
    #[serde(default)]
    pub is_emergency_rollback: bool,
}

/// Core signed toolchain manifest payload.
/// Strictly enforces schema sealing with `deny_unknown_fields`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolchainManifest {
    pub schema_version: u32,
    pub channel: String,
    pub sequence_number: u64,
    pub generated_at: String,
    pub min_collector_version: String,
    pub components: BTreeMap<String, ComponentManifest>,
}

impl ToolchainManifest {
    /// Deserializes a manifest from raw JSON bytes, enforcing:
    /// 1. Maximum size limit of 64 KiB before parsing.
    /// 2. Schema sealing with `deny_unknown_fields`.
    /// 3. Validation of schema version, channel, platform, semver, hash, entrypoint, and component allowlist.
    pub fn parse_and_validate(raw_bytes: &[u8]) -> Result<Self, ToolchainError> {
        if raw_bytes.len() > MAX_MANIFEST_RAW_BYTES {
            return Err(ToolchainError::ManifestTooLarge {
                size: raw_bytes.len(),
                max: MAX_MANIFEST_RAW_BYTES,
            });
        }

        let raw_str = std::str::from_utf8(raw_bytes)
            .map_err(|e| ToolchainError::DeserializationError(format!("Invalid UTF-8: {}", e)))?;

        let manifest: ToolchainManifest = serde_json::from_str(raw_str)
            .map_err(|e| ToolchainError::DeserializationError(e.to_string()))?;

        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates all fields against the strict security contract.
    pub fn validate(&self) -> Result<(), ToolchainError> {
        if self.schema_version != 1 {
            return Err(ToolchainError::UnsupportedSchemaVersion(self.schema_version));
        }

        if self.channel != "production" && self.channel != "poc" {
            return Err(ToolchainError::InvalidChannel(self.channel.clone()));
        }

        // Validate min_collector_version format
        semver::Version::parse(&self.min_collector_version)
            .map_err(|e| ToolchainError::InvalidSemver(format!("min_collector_version '{}': {}", self.min_collector_version, e)))?;

        // Validate generated_at RFC3339 timestamp
        chrono::DateTime::parse_from_rfc3339(&self.generated_at)
            .map_err(|e| ToolchainError::InvalidTimestamp(format!("generated_at '{}': {}", self.generated_at, e)))?;

        if self.components.is_empty() {
            return Err(ToolchainError::EmptyComponents);
        }

        for (comp_name, comp) in &self.components {
            // Strict component allowlist check
            if !ALLOWED_MANAGED_COMPONENTS.contains(&comp_name.as_str()) {
                return Err(ToolchainError::UnknownComponent(comp_name.clone()));
            }

            comp.validate(comp_name)?;
        }

        Ok(())
    }
}

impl ComponentManifest {
    pub fn validate(&self, component_name: &str) -> Result<(), ToolchainError> {
        // 1. Semver validation
        semver::Version::parse(&self.version)
            .map_err(|e| ToolchainError::InvalidSemver(format!("component '{}' version '{}': {}", component_name, self.version, e)))?;

        // 2. Platform validation (Windows x86_64 only)
        if self.platform.os != "windows" || self.platform.arch != "x86_64" {
            return Err(ToolchainError::UnsupportedPlatform {
                os: self.platform.os.clone(),
                arch: self.platform.arch.clone(),
            });
        }

        // 3. SHA-256 validation (exact 64 lowercase hex characters)
        if self.sha256.len() != 64 || !self.sha256.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            return Err(ToolchainError::InvalidDigest(format!(
                "component '{}' has invalid sha256 '{}'",
                component_name, self.sha256
            )));
        }

        // 4. Byte size bounds
        if self.byte_size == 0 || self.byte_size > MAX_COMPONENT_ARTIFACT_BYTES {
            return Err(ToolchainError::InvalidByteSize {
                component: component_name.to_string(),
                size: self.byte_size,
                max: MAX_COMPONENT_ARTIFACT_BYTES,
            });
        }

        // 5. Strict entrypoint sanitization
        validate_entrypoint(&self.entrypoint, component_name)?;

        Ok(())
    }
}

/// Validates entrypoint according to strict security rules:
/// - Rejects path traversal (`..`, `.`)
/// - Rejects path separators (`/`, `\`)
/// - Rejects Alternate Data Streams (`:`)
/// - Rejects null bytes (`\0`)
/// - Rejects reserved DOS device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
/// - Must match whitelist regex: `^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$`
pub fn validate_entrypoint(entrypoint: &str, component_name: &str) -> Result<(), ToolchainError> {
    if entrypoint.contains('\0')
        || entrypoint.contains('/')
        || entrypoint.contains('\\')
        || entrypoint.contains(':')
        || entrypoint.contains("..")
    {
        return Err(ToolchainError::InvalidEntrypoint(format!(
            "component '{}' entrypoint '{}' contains forbidden characters",
            component_name, entrypoint
        )));
    }

    let regex = Regex::new(r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$")
        .expect("Valid static entrypoint regex");

    if !regex.is_match(entrypoint) {
        return Err(ToolchainError::InvalidEntrypoint(format!(
            "component '{}' entrypoint '{}' fails character whitelist",
            component_name, entrypoint
        )));
    }

    // Check stem against reserved DOS device names
    let stem = entrypoint.split('.').next().unwrap_or("");
    let stem_upper = stem.to_ascii_uppercase();
    if RESERVED_DOS_DEVICES.contains(&stem_upper.as_str()) {
        return Err(ToolchainError::InvalidEntrypoint(format!(
            "component '{}' entrypoint '{}' uses reserved DOS device name",
            component_name, entrypoint
        )));
    }

    Ok(())
}
