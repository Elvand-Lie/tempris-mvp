use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::manifest::ToolchainManifest;
use super::verifier::{verify_artifact_bytes, verify_envelope};
use super::ToolchainError;

pub const MANIFEST_FILENAME: &str = "toolchain-manifest.json";

/// Verified offline package representation containing validated manifest and artifact paths.
#[derive(Debug, Clone)]
pub struct VerifiedOfflinePackage {
    pub manifest: ToolchainManifest,
    pub component_artifacts: Vec<(String, PathBuf)>,
}

/// Inspects and verifies an offline package directory against the signed manifest.
///
/// Strict Invariants:
/// 1. `toolchain-manifest.json` must exist and pass cryptographic envelope verification.
/// 2. All declared manifest components must have corresponding artifact files with exact SHA-256 and byte size matches.
/// 3. Extraneous file rejection: Any unmanifested file, script, executable, or archive in the package
///    directory triggers immediate rejection.
/// 4. Forbidden prerequisite rejection: Any file named `nmap*` or `npcap*` triggers immediate rejection.
/// 5. Zero binary execution occurs during verification.
pub fn verify_offline_package(package_dir: &Path) -> Result<VerifiedOfflinePackage, ToolchainError> {
    if !package_dir.is_dir() {
        return Err(ToolchainError::PackageNotFound(package_dir.to_string_lossy().to_string()));
    }

    let manifest_path = package_dir.join(MANIFEST_FILENAME);
    if !manifest_path.exists() {
        return Err(ToolchainError::MissingManifestFile(manifest_path.to_string_lossy().to_string()));
    }

    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|e| ToolchainError::Io(e))?;

    // 1. Verify signed envelope and parse manifest
    let manifest = verify_envelope(&manifest_bytes)?;

    // 2. Track expected files
    let mut expected_filenames = HashSet::new();
    expected_filenames.insert(MANIFEST_FILENAME.to_string());

    let mut component_artifacts = Vec::new();

    // 3. For each declared component, locate its artifact file
    for (comp_name, comp) in &manifest.components {
        let possible_names = [
            format!("{}-{}.zip", comp_name, comp.version),
            format!("{}.zip", comp_name),
            format!("{}-{}.tar.gz", comp_name, comp.version),
        ];

        let mut found_path: Option<PathBuf> = None;
        let mut found_filename: Option<String> = None;

        for name in &possible_names {
            let p = package_dir.join(name);
            if p.exists() {
                found_path = Some(p);
                found_filename = Some(name.clone());
                break;
            }
        }

        let (artifact_path, artifact_filename) = match (found_path, found_filename) {
            (Some(p), Some(n)) => (p, n),
            _ => {
                return Err(ToolchainError::MissingComponentArtifact(format!(
                    "Component '{}' artifact not found in package directory (checked: {:?})",
                    comp_name, possible_names
                )));
            }
        };

        // Verify artifact content
        let artifact_bytes = std::fs::read(&artifact_path)
            .map_err(|e| ToolchainError::Io(e))?;

        verify_artifact_bytes(&artifact_bytes, &comp.sha256, comp.byte_size)?;

        expected_filenames.insert(artifact_filename);
        component_artifacts.push((comp_name.clone(), artifact_path));
    }

    // 4. Extraneous file and forbidden component detection
    let dir_entries = std::fs::read_dir(package_dir)
        .map_err(|e| ToolchainError::Io(e))?;

    for entry in dir_entries {
        let entry = entry.map_err(|e| ToolchainError::Io(e))?;
        let filename = entry.file_name().to_string_lossy().to_string();

        let filename_lower = filename.to_ascii_lowercase();

        // Check for forbidden external prerequisites (Nmap / Npcap)
        if filename_lower.contains("nmap") || filename_lower.contains("npcap") {
            return Err(ToolchainError::ForbiddenComponent(format!(
                "Offline package contains prohibited external prerequisite '{}'. Nmap/Npcap must not be distributed via Tempris packages.",
                filename
            )));
        }

        // Check against expected manifest files
        if !expected_filenames.contains(&filename) {
            return Err(ToolchainError::ExtraneousFileDetected(format!(
                "Unmanifested extraneous file '{}' detected in offline package",
                filename
            )));
        }
    }

    Ok(VerifiedOfflinePackage {
        manifest,
        component_artifacts,
    })
}
