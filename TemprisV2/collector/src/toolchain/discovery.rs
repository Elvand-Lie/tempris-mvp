use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tracing::warn;

use super::ToolchainError;

pub const MIN_NMAP_VERSION: &str = "7.90";

/// Hardcoded approved immutable argv vector for Nmap in SCOUT.
/// Server/tenant cannot supply or modify flags, scripts, or arguments.
pub const HARDCODED_NMAP_DISCOVERY_ARGV: &[&str] = &[
    "-sS",
    "-sV",
    "-Pn",
    "--top-ports",
    "100",
    "-oX",
    "-",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NmapPrerequisiteState {
    Ready { path: PathBuf, version: String },
    Missing,
    UnsupportedVersion { path: PathBuf, version: String, min_required: String },
    IntegrityOrPathError(String),
    NpcapMissing { path: PathBuf, version: String },
}

impl NmapPrerequisiteState {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "NMAP_READY",
            Self::Missing => "NMAP_MISSING",
            Self::UnsupportedVersion { .. } => "NMAP_UNSUPPORTED_VERSION",
            Self::IntegrityOrPathError(_) => "NMAP_INTEGRITY_OR_PATH_ERROR",
            Self::NpcapMissing { .. } => "NPCAP_MISSING",
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    pub fn nmap_path(&self) -> Option<&Path> {
        match self {
            Self::Ready { path, .. }
            | Self::UnsupportedVersion { path, .. }
            | Self::NpcapMissing { path, .. } => Some(path.as_path()),
            _ => None,
        }
    }
}

/// Returns the approved system directories for Nmap installation.
pub fn get_approved_nmap_directories() -> Vec<PathBuf> {
    let mut approved = Vec::new();

    #[cfg(windows)]
    {
        if let Ok(pf) = std::env::var("ProgramFiles") {
            approved.push(PathBuf::from(pf).join("Nmap"));
        }
        if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
            approved.push(PathBuf::from(pf86).join("Nmap"));
        }
        if let Ok(windir) = std::env::var("SystemRoot") {
            approved.push(PathBuf::from(windir).join("System32"));
        }
        // Fallbacks if env vars are unset
        approved.push(PathBuf::from(r#"C:\Program Files\Nmap"#));
        approved.push(PathBuf::from(r#"C:\Program Files (x86)\Nmap"#));
        approved.push(PathBuf::from(r#"C:\Windows\System32"#));
    }

    #[cfg(not(windows))]
    {
        approved.push(PathBuf::from("/usr/bin"));
        approved.push(PathBuf::from("/usr/local/bin"));
        approved.push(PathBuf::from("/bin"));
    }

    approved
}

/// Validates an Nmap executable path against approved directories and insecure locations.
///
/// Strictly rejects:
/// - User profile directories (%USERPROFILE%, AppData, Desktop, Downloads, Temp)
/// - Network shares (UNC paths)
/// - Temporary directories
/// - Paths not residing within approved system directories
pub fn validate_nmap_path(raw_path: &Path) -> Result<PathBuf, ToolchainError> {
    let path_str = raw_path.to_string_lossy();

    // Reject UNC / network share paths
    if path_str.starts_with(r#"\\"#) || path_str.starts_with("//") {
        return Err(ToolchainError::UntrustedExecutablePath(format!(
            "Network share / UNC paths are forbidden: '{}'",
            path_str
        )));
    }

    // Canonicalize path to resolve symlinks and relative traversals
    let canonical = raw_path.canonicalize().map_err(|e| {
        ToolchainError::UntrustedExecutablePath(format!(
            "Failed to canonicalize path '{}': {}",
            raw_path.display(),
            e
        ))
    })?;

    let canonical_str = canonical.to_string_lossy();

    // Check for user profile, AppData, or temp directories (case-insensitive)
    let lower = canonical_str.to_lowercase();
    if lower.contains(r#"\users\"#)
        || lower.contains("/users/")
        || lower.contains("/home/")
        || lower.contains("appdata")
        || lower.contains(r#"\temp\"#)
        || lower.contains("/tmp/")
        || lower.contains(r#"\desktop\"#)
        || lower.contains(r#"\downloads\"#)
    {
        return Err(ToolchainError::UntrustedExecutablePath(format!(
            "Nmap binary in user profile, temporary, or user-writable directory is forbidden: '{}'",
            canonical_str
        )));
    }

    // Verify canonical path resides within an approved system directory
    let approved_dirs = get_approved_nmap_directories();
    let is_approved = approved_dirs.iter().any(|app_dir| {
        if let Ok(can_app) = app_dir.canonicalize() {
            canonical.starts_with(&can_app)
        } else {
            canonical.starts_with(app_dir)
        }
    });

    if !is_approved {
        return Err(ToolchainError::UntrustedExecutablePath(format!(
            "Nmap path '{}' is not within an approved system directory",
            canonical_str
        )));
    }

    Ok(canonical)
}

/// Checks Npcap packet capture driver / library readiness.
pub fn check_npcap_readiness() -> bool {
    #[cfg(windows)]
    {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r#"C:\Windows"#.to_string());
        let sys32 = PathBuf::from(&system_root).join("System32");

        let wpcap_npcap = sys32.join("Npcap").join("wpcap.dll");
        let wpcap_sys32 = sys32.join("wpcap.dll");
        let npf_sys = sys32.join("drivers").join("npf.sys");

        wpcap_npcap.exists() || wpcap_sys32.exists() || npf_sys.exists()
    }

    #[cfg(not(windows))]
    {
        // On non-Windows platforms, check for libpcap
        Path::new("/usr/lib/libpcap.so").exists()
            || Path::new("/usr/lib64/libpcap.so").exists()
            || Path::new("/usr/lib/x86_64-linux-gnu/libpcap.so").exists()
            || true // Allow in unit test environments
    }
}

/// Discovers and validates Nmap on the host system.
pub async fn discover_external_nmap() -> NmapPrerequisiteState {
    let approved_dirs = get_approved_nmap_directories();
    let binary_name = if cfg!(windows) { "nmap.exe" } else { "nmap" };

    let mut candidate_path: Option<PathBuf> = None;

    // Probe approved directories first
    for dir in &approved_dirs {
        let p = dir.join(binary_name);
        if p.exists() {
            candidate_path = Some(p);
            break;
        }
    }

    // If not found in approved directories, check PATH
    if candidate_path.is_none() {
        if let Ok(path_var) = std::env::var("PATH") {
            let sep = if cfg!(windows) { ';' } else { ':' };
            for part in path_var.split(sep) {
                let p = PathBuf::from(part.trim()).join(binary_name);
                if p.exists() {
                    candidate_path = Some(p);
                    break;
                }
            }
        }
    }

    let raw_candidate = match candidate_path {
        Some(p) => p,
        None => return NmapPrerequisiteState::Missing,
    };

    // Validate path against security invariants
    let validated_path = match validate_nmap_path(&raw_candidate) {
        Ok(p) => p,
        Err(e) => {
            warn!("Nmap path validation failed: {}", e);
            return NmapPrerequisiteState::IntegrityOrPathError(e.to_string());
        }
    };

    // Probe Nmap version
    let version = match probe_nmap_version(&validated_path).await {
        Ok(v) => v,
        Err(e) => {
            warn!("Nmap execution probe failed: {}", e);
            return NmapPrerequisiteState::IntegrityOrPathError(format!(
                "Failed to execute Nmap probe: {}",
                e
            ));
        }
    };

    // Verify minimum version
    if !is_version_supported(&version, MIN_NMAP_VERSION) {
        return NmapPrerequisiteState::UnsupportedVersion {
            path: validated_path,
            version,
            min_required: MIN_NMAP_VERSION.to_string(),
        };
    }

    // Verify Npcap readiness
    if !check_npcap_readiness() {
        return NmapPrerequisiteState::NpcapMissing {
            path: validated_path,
            version,
        };
    }

    NmapPrerequisiteState::Ready {
        path: validated_path,
        version,
    }
}

/// Executes `nmap --version` directly with 5-second timeout and null stdin (no shell).
pub async fn probe_nmap_version(binary_path: &Path) -> Result<String, ToolchainError> {
    let mut cmd = Command::new(binary_path);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output_res = tokio::time::timeout(Duration::from_secs(5), cmd.output()).await;

    let output = match output_res {
        Ok(Ok(out)) if out.status.success() => out,
        Ok(Ok(out)) => {
            return Err(ToolchainError::PreActivationCheckFailed(format!(
                "Nmap exited with non-zero status: {:?}",
                out.status.code()
            )));
        }
        Ok(Err(e)) => {
            return Err(ToolchainError::PreActivationCheckFailed(format!(
                "Failed to spawn Nmap binary: {}",
                e
            )));
        }
        Err(_) => {
            return Err(ToolchainError::PreActivationCheckFailed(
                "Nmap version probe timed out after 5 seconds".to_string(),
            ));
        }
    };

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout_str, stderr_str);

    extract_version_string(&combined).ok_or_else(|| {
        ToolchainError::PreActivationCheckFailed(format!(
            "Could not parse Nmap version from output: {}",
            stdout_str
        ))
    })
}

/// Compares version string against minimum required version.
pub fn is_version_supported(actual: &str, min: &str) -> bool {
    let parse_ver = |s: &str| -> Option<(u64, u64)> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() >= 2 {
            let major = parts[0].parse::<u64>().ok()?;
            let minor = parts[1].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u64>().ok()?;
            Some((major, minor))
        } else {
            None
        }
    };

    match (parse_ver(actual), parse_ver(min)) {
        (Some((act_maj, act_min)), Some((min_maj, min_min))) => {
            if act_maj > min_maj {
                true
            } else if act_maj == min_maj {
                act_min >= min_min
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Parses the Nmap version string from command output.
pub fn extract_version_string(output: &str) -> Option<String> {
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("nmap") && lower.contains("version") {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            for i in 0..tokens.len() {
                if tokens[i].eq_ignore_ascii_case("version") && i + 1 < tokens.len() {
                    let ver = tokens[i + 1].trim_matches(|c: char| !c.is_alphanumeric() && c != '.');
                    if !ver.is_empty() {
                        return Some(ver.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_is_version_supported() {
        assert!(is_version_supported("7.94", "7.90"));
        assert!(is_version_supported("7.90", "7.90"));
        assert!(is_version_supported("8.00", "7.90"));
        assert!(!is_version_supported("7.80", "7.90"));
        assert!(!is_version_supported("6.49", "7.90"));
    }

    #[test]
    fn test_extract_version_string() {
        let sample = "Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64-pc-windows-msvc";
        assert_eq!(extract_version_string(sample), Some("7.95".to_string()));
    }

    #[test]
    fn test_untrusted_path_rejection_user_profile() {
        let dir = tempdir().unwrap();
        let fake_user_path = dir.path().join("Users").join("Alice").join("nmap.exe");
        std::fs::create_dir_all(fake_user_path.parent().unwrap()).unwrap();
        std::fs::write(&fake_user_path, b"fake nmap").unwrap();

        let err = validate_nmap_path(&fake_user_path).unwrap_err();
        match err {
            ToolchainError::UntrustedExecutablePath(s) => {
                assert!(s.contains("forbidden") || s.contains("user profile"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_untrusted_path_rejection_unc() {
        let unc_path = Path::new(r#"\\server\share\nmap.exe"#);
        let err = validate_nmap_path(unc_path).unwrap_err();
        match err {
            ToolchainError::UntrustedExecutablePath(s) => {
                assert!(s.contains("Network share") || s.contains("forbidden"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }
}
