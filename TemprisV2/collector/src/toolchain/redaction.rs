use regex::{Regex, RegexBuilder};
use std::sync::OnceLock;

pub const MANAGED_NUCLEI_TOKEN: &str = "[MANAGED_NUCLEI]";
pub const MANAGED_TEMPLATES_TOKEN: &str = "[MANAGED_TEMPLATES]";
pub const EXTERNAL_NMAP_TOKEN: &str = "[EXTERNAL_NMAP]";
pub const REDACTED_LOCAL_PATH_TOKEN: &str = "[REDACTED_LOCAL_PATH]";

#[derive(Debug, Clone, Default)]
pub struct KnownPaths {
    pub nuclei_path: Option<String>,
    pub templates_path: Option<String>,
    pub nmap_path: Option<String>,
}

static WINDOWS_DRIVE_REGEX: OnceLock<Regex> = OnceLock::new();
static UNC_PATH_REGEX: OnceLock<Regex> = OnceLock::new();
static UNIX_PATH_REGEX: OnceLock<Regex> = OnceLock::new();
static USER_PROFILE_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_windows_drive_regex() -> &'static Regex {
    WINDOWS_DRIVE_REGEX.get_or_init(|| {
        // Matches drive letter followed by :\ or :/ and path characters
        RegexBuilder::new(r#"[a-zA-Z]:[\\/][a-zA-Z0-9_\.\-\\/\s]+"#)
            .case_insensitive(true)
            .build()
            .expect("valid regex")
    })
}

fn get_unc_path_regex() -> &'static Regex {
    UNC_PATH_REGEX.get_or_init(|| {
        // Matches UNC paths like \\server\share\path
        RegexBuilder::new(r#"\\\\[a-zA-Z0-9_\.\-]+\\[a-zA-Z0-9_\.\-\\/\s]+"#)
            .case_insensitive(true)
            .build()
            .expect("valid regex")
    })
}

fn get_unix_path_regex() -> &'static Regex {
    UNIX_PATH_REGEX.get_or_init(|| {
        // Matches unix absolute paths with at least 2 segments e.g. /home/user or /tmp/dir
        Regex::new(r#"/(?:home|tmp|var|usr|etc|opt|Users)/[a-zA-Z0-9_\.\-/]+"#)
            .expect("valid regex")
    })
}

fn get_user_profile_regex() -> &'static Regex {
    USER_PROFILE_REGEX.get_or_init(|| {
        // Matches user directory references e.g. \Users\username or /Users/username
        RegexBuilder::new(r#"[\\/]Users[\\/][a-zA-Z0-9_\.\-]+"#)
            .case_insensitive(true)
            .build()
            .expect("valid regex")
    })
}

/// Redacts local filesystem paths, user accounts, and toolchain paths from telemetry,
/// execution logs, and stdout/stderr output.
///
/// Replaces:
/// - Known Nuclei binary path with `[MANAGED_NUCLEI]`
/// - Known Templates directory path with `[MANAGED_TEMPLATES]`
/// - Known Nmap binary path with `[EXTERNAL_NMAP]`
/// - Any other Windows/Unix local path or user profile path with `[REDACTED_LOCAL_PATH]`
pub fn redact_paths(text: &str, known: Option<&KnownPaths>) -> String {
    if text.is_empty() {
        return String::new();
    }

    let mut result = text.to_string();

    // Step 1: Replace known toolchain paths with specific tokens
    if let Some(k) = known {
        if let Some(t_path) = &k.templates_path {
            if !t_path.is_empty() {
                result = replace_path_variants(&result, t_path, MANAGED_TEMPLATES_TOKEN);
            }
        }
        if let Some(n_path) = &k.nuclei_path {
            if !n_path.is_empty() {
                result = replace_path_variants(&result, n_path, MANAGED_NUCLEI_TOKEN);
            }
        }
        if let Some(m_path) = &k.nmap_path {
            if !m_path.is_empty() {
                result = replace_path_variants(&result, m_path, EXTERNAL_NMAP_TOKEN);
            }
        }
    }

    // Step 2: Redact UNC paths
    result = get_unc_path_regex().replace_all(&result, REDACTED_LOCAL_PATH_TOKEN).to_string();

    // Step 3: Redact Windows drive paths
    result = get_windows_drive_regex().replace_all(&result, REDACTED_LOCAL_PATH_TOKEN).to_string();

    // Step 4: Redact Unix system paths
    result = get_unix_path_regex().replace_all(&result, REDACTED_LOCAL_PATH_TOKEN).to_string();

    // Step 5: Redact any remaining user profile paths
    result = get_user_profile_regex().replace_all(&result, REDACTED_LOCAL_PATH_TOKEN).to_string();

    result
}

/// Replaces a target path considering forward-slash, backslash, and canonical variations.
fn replace_path_variants(text: &str, target_path: &str, token: &str) -> String {
    let mut out = text.to_string();

    // Direct match
    out = out.replace(target_path, token);

    // Backslash variant
    let backslash_variant = target_path.replace('/', "\\");
    if backslash_variant != target_path {
        out = out.replace(&backslash_variant, token);
    }

    // Forward-slash variant
    let forward_variant = target_path.replace('\\', "/");
    if forward_variant != target_path {
        out = out.replace(&forward_variant, token);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_known_paths() {
        let known = KnownPaths {
            nuclei_path: Some(r#"C:\ProgramData\Tempris\Collector\tools\nuclei\3.8.0\nuclei.exe"#.to_string()),
            templates_path: Some(r#"C:\ProgramData\Tempris\Collector\tools\nuclei_templates\10.4.4"#.to_string()),
            nmap_path: Some(r#"C:\Program Files\Nmap\nmap.exe"#.to_string()),
        };

        let raw = "Executing C:\\ProgramData\\Tempris\\Collector\\tools\\nuclei\\3.8.0\\nuclei.exe with -t C:\\ProgramData\\Tempris\\Collector\\tools\\nuclei_templates\\10.4.4 and nmap at C:\\Program Files\\Nmap\\nmap.exe";
        let redacted = redact_paths(raw, Some(&known));

        assert!(redacted.contains(MANAGED_NUCLEI_TOKEN));
        assert!(redacted.contains(MANAGED_TEMPLATES_TOKEN));
        assert!(redacted.contains(EXTERNAL_NMAP_TOKEN));
        assert!(!redacted.contains("ProgramData"));
        assert!(!redacted.contains("Program Files"));
    }

    #[test]
    fn test_redact_generic_windows_paths_and_user_profiles() {
        let raw = "Error reading config from C:\\Users\\Administrator\\AppData\\Local\\Temp\\test.json";
        let redacted = redact_paths(raw, None);

        assert!(!redacted.contains("Administrator"));
        assert!(!redacted.contains("AppData"));
        assert!(redacted.contains(REDACTED_LOCAL_PATH_TOKEN));
    }

    #[test]
    fn test_redact_unc_paths() {
        let raw = r#"Failed to load \\fileserver\tools\scanner.exe"#;
        let redacted = redact_paths(raw, None);

        assert!(!redacted.contains("fileserver"));
        assert!(redacted.contains(REDACTED_LOCAL_PATH_TOKEN));
    }

    #[test]
    fn test_redact_unix_paths() {
        let raw = "Logs at /var/log/tempris/collector.log and /home/alice/scanner";
        let redacted = redact_paths(raw, None);

        assert!(!redacted.contains("alice"));
        assert!(!redacted.contains("/var/log"));
        assert!(redacted.contains(REDACTED_LOCAL_PATH_TOKEN));
    }
}
