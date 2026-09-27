//! STRIKE toolbox execution at the collector (Phase 1: fixed curl GET/HEAD).
//!
//! The server owns authorization (tenant, scope pinning); this module owns
//! the honest local half: a FIXED argv (no shell, no redirects, no request
//! body, no credentials), the server-pinned destinations enforced via
//! curl `--resolve` entries (no second DNS resolution path), a hard
//! timeout, and a bounded capture. Spawn failures are reported truthfully
//! — a missing binary is a failed result, never a fabricated success.
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;

/// Bound on captured stdout/stderr per stream; the server applies its own
/// 64 KiB inline bound on top.
pub const STRIKE_OUTPUT_LIMIT: usize = 1024 * 1024;

/// Pinned reviewed Phase 1 wordlist.
pub const STRIKE_WORDLIST: &str = include_str!("strike_wordlist.txt");

/// Per-tool execution envelopes — must mirror the backend's
/// app/strike/runs.py TOOL_ENVELOPE_SECONDS.
pub fn strike_envelope(capability: &str) -> Option<u64> {
    match capability {
        "curl" => Some(60),
        "nmap" => Some(180),
        "nuclei" => Some(1200),
        "ffuf" => Some(300),
        "dig" => Some(30),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrikeRunResult {
    pub status: String, // "completed" | "failed" | "rejected"
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub started_at: String,
    pub completed_at: String,
    pub error_message: Option<String>,
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn truncated_note() -> String {
    format!(
        "\n[tempris: output truncated at {} bytes]\n",
        STRIKE_OUTPUT_LIMIT
    )
}

fn cap_to_limit(bytes: Vec<u8>) -> (String, usize, bool) {
    let total = bytes.len();
    let clipped: Vec<u8> = bytes.into_iter().take(STRIKE_OUTPUT_LIMIT).collect();
    let was_truncated = total > STRIKE_OUTPUT_LIMIT;
    let mut text = String::from_utf8_lossy(&clipped).to_string();
    if was_truncated {
        text.push_str(&truncated_note());
    }
    (text, total.min(usize::MAX), was_truncated)
}

/// Extract (host, port) from an http/https URL the server already validated.
pub fn split_url(url: &str) -> Result<(String, u16), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "URL has no scheme".to_string())?;
    let default_port = match scheme {
        "http" => 80u16,
        "https" => 443u16,
        _ => return Err(format!("unsupported scheme '{}'", scheme)),
    };
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') {
        return Err("credentials in URL are refused".to_string());
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal
        let close = stripped
            .find(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let host = &stripped[..close];
        let after = &stripped[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| "invalid port".to_string())?,
            None => default_port,
        };
        (host.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (
            h.to_string(),
            p.parse::<u16>().map_err(|_| "invalid port".to_string())?,
        )
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() {
        return Err("URL has no host".to_string());
    }
    Ok((host, port))
}

/// The FIXED argv. The server sends capability/method/url/pins; the collector
/// builds every flag itself — nothing from the wire is ever interpolated into
/// a shell, and redirects are structurally impossible (no -L; --max-redirs 0).
pub fn build_strike_argv(
    method: &str,
    url: &str,
    pinned_ips: &[String],
    timeout_seconds: u64,
) -> Result<Vec<String>, String> {
    let method = method.to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "HEAD") {
        return Err(format!("unsupported method '{}'", method));
    }
    if timeout_seconds == 0 || timeout_seconds > 600 {
        return Err(format!("timeout '{}' outside the allowed envelope", timeout_seconds));
    }
    if pinned_ips.is_empty() {
        return Err("no server-pinned destinations — refusing an unpinned run".to_string());
    }
    let (host, port) = split_url(url)?;

    let mut argv: Vec<String> = vec![
        "-sS".to_string(),
        "-i".to_string(),
        "--max-redirs".to_string(),
        "0".to_string(),
        "--max-time".to_string(),
        timeout_seconds.to_string(),
    ];
    for ip in pinned_ips {
        // fail the transfer rather than ever consulting DNS outside the pin
        argv.push("--resolve".to_string());
        argv.push(format!("{}:{}:{}", host, port, ip));
        argv.push("--connect-timeout".to_string());
        argv.push(timeout_seconds.to_string());
    }
    if method == "HEAD" {
        argv.push("-I".to_string());
    }
    argv.push("--".to_string());
    argv.push(url.to_string());
    Ok(argv)
}

// ---------------------------------------------------------------------------
// Phase 1 toolbox: fixed argv per tool (nmap / nuclei / ffuf / dig).
// Every builder is total over ONLY its reviewed inputs; nothing from the
// wire is interpolated anywhere but a single argument position, and no
// shell is ever involved.
// ---------------------------------------------------------------------------

fn parse_pinned_target(target: &str) -> Result<(), String> {
    if let Some((base, prefix)) = target.split_once('/') {
        let addr: std::net::IpAddr = base
            .parse()
            .map_err(|_| format!("pinned CIDR base '{}' is not an IP", base))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("pinned CIDR prefix '{}' is not numeric", prefix))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("pinned CIDR prefix /{} out of bounds", prefix));
        }
    } else {
        target
            .parse::<std::net::IpAddr>()
            .map_err(|_| format!("pinned target '{}' is not an IP or CIDR", target))?;
    }
    Ok(())
}

/// Unprivileged TCP connect scan only. No -sS, no -O, no -A, no --script —
/// ever. One invocation carries every pinned target.
pub fn build_nmap_argv(pinned_targets: &[String]) -> Result<Vec<String>, String> {
    if pinned_targets.is_empty() {
        return Err("no server-pinned targets — refusing an unpinned run".to_string());
    }
    for t in pinned_targets {
        parse_pinned_target(t)?;
    }
    let mut argv: Vec<String> = [
        "-sT",
        "-Pn",
        "--open",
        "-T3",
        "--max-retries",
        "2",
        "--host-timeout",
        "120s",
        "--max-rate",
        "100",
        "-p",
        "1-10000",
        "-oX",
        "-",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    argv.extend(pinned_targets.iter().cloned());
    Ok(argv)
}

/// The SCOUT-shaped nuclei run against the collector's MANAGED templates
/// directory: -ni (no interactsh) and -duc (don't update templates) are
/// mandatory, and there is no redirect option to follow.
pub fn build_nuclei_argv(
    pinned_target: &str,
    templates_dir: &str,
    timeout_seconds: u64,
) -> Result<Vec<String>, String> {
    if pinned_target.is_empty() {
        return Err("no pinned target — refusing an unpinned run".to_string());
    }
    if templates_dir.is_empty() {
        return Err("no managed templates directory — refusing".to_string());
    }
    if timeout_seconds == 0 || timeout_seconds > 1200 {
        return Err(format!(
            "timeout '{}' outside the allowed envelope",
            timeout_seconds
        ));
    }
    Ok([
        "-target",
        pinned_target,
        "-severity",
        "critical,high,medium,low,info",
        "-jsonl",
        "-silent",
        "-nc",
        "-ni",
        "-duc",
        "-timeout",
        &timeout_seconds.to_string(),
        "-t",
        templates_dir,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect())
}

/// Path fuzzing against the embedded reviewed wordlist only: FUZZ appears
/// exactly once and only in the path; no recursion, no request tampering,
/// no custom headers — those flags simply do not exist in this argv.
pub fn build_ffuf_argv(url_with_fuzz: &str, wordlist_path: &str) -> Result<Vec<String>, String> {
    let rest = url_with_fuzz
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url_with_fuzz);
    let authority_end = rest.find(['/','?','#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains("FUZZ") {
        return Err("FUZZ is only allowed in the URL path, never in the host".to_string());
    }
    if authority.contains('@') {
        return Err("credentials in URL are refused".to_string());
    }
    // FUZZ counts only inside the PATH — a query/fragment FUZZ never counts
    let after_authority = &rest[authority_end..];
    let path = after_authority.split(['?', '#']).next().unwrap_or("");
    if path.matches("FUZZ").count() != 1 {
        return Err("the URL path must contain exactly one FUZZ token".to_string());
    }
    if wordlist_path.is_empty() {
        return Err("no wordlist — refusing".to_string());
    }
    Ok([
        "-u",
        url_with_fuzz,
        "-w",
        wordlist_path,
        "-t",
        "10",
        "-rate",
        "100",
        "-timeout",
        "10",
        "-ac",
        "-mc",
        "200-299,301,302,401,403,405",
        "-o",
        "-",
        "-of",
        "json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect())
}

/// dig +short with an allow-listed qtype — ANY/AXFR are structurally
/// impossible here (the API refuses them; so does this builder).
pub fn build_dig_argv(record_type: &str, hostname: &str) -> Result<Vec<String>, String> {
    const ALLOWED: &[&str] = &["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "PTR"];
    let qtype = record_type.trim().to_ascii_uppercase();
    if !ALLOWED.contains(&qtype.as_str()) {
        return Err(format!("record type '{}' is not allow-listed", record_type));
    }
    if hostname.is_empty()
        || hostname.contains('/')
        || hostname.contains('@')
        || hostname.contains('%')
        || hostname.contains(char::is_whitespace)
    {
        return Err(format!("invalid lookup name '{}'", hostname));
    }
    Ok(vec!["+short".to_string(), qtype, hostname.to_string()])
}

/// Resolve the collector's managed nuclei binary + templates directory from
/// the tracked toolchain state (same source of truth as SCOUT — there is no
/// ambient-PATH fallback).
pub fn resolve_managed_nuclei() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    use crate::storage::StorageManager;
    use crate::toolchain::state::{ComponentStatus, ToolchainState};

    let storage = StorageManager::default_machine_storage();
    let state = ToolchainState::load(&storage.toolchain_state_path()).ok()?;
    let ready = |status: &ComponentStatus| {
        matches!(status, ComponentStatus::Installed | ComponentStatus::RolledBack)
    };
    let nuclei = state.components.get("nuclei")?;
    if !ready(&nuclei.status) {
        return None;
    }
    let exe = nuclei.active_dir.as_ref()?;
    let exe_name = if cfg!(windows) { "nuclei.exe" } else { "nuclei" };
    let exe = std::path::PathBuf::from(exe).join(exe_name);
    if !exe.exists() {
        return None;
    }
    let templates = state.components.get("nuclei_templates")?;
    if !ready(&templates.status) {
        return None;
    }
    let dir = std::path::PathBuf::from(templates.active_dir.as_ref()?);
    if dir.exists() && dir.is_dir() {
        Some((exe, dir))
    } else {
        None
    }
}

/// Execute the fixed curl invocation. No shell anywhere: the argv is passed
/// directly to the OS process.
pub async fn run_strike_job(
    _job_id: uuid::Uuid,
    method: &str,
    url: &str,
    pinned_ips: &[String],
    timeout_seconds: u64,
) -> StrikeRunResult {
    let started_at = now_rfc3339();
    match build_strike_argv(method, url, pinned_ips, timeout_seconds) {
        Ok(argv) => execute_fixed("curl", argv, timeout_seconds, "curl", started_at).await,
        Err(e) => StrikeRunResult {
            status: "rejected".to_string(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            stdout_bytes: 0,
            stderr_bytes: 0,
            started_at,
            completed_at: now_rfc3339(),
            error_message: Some(e),
        },
    }
}

/// Dispatch a STRIKE toolbox run by capability. Every tool gets its FIXED
/// argv; the only wire-controlled values are the server-validated pins.
pub async fn run_strike_tool(
    capability: &str,
    method: &str,
    url: &str,
    pinned_ips: &[String],
    pinned_targets: &[String],
    record_type: Option<&str>,
    timeout_seconds: u64,
) -> StrikeRunResult {
    let started_at = now_rfc3339();
    let envelope = match strike_envelope(capability) {
        Some(e) => e,
        None => {
            return StrikeRunResult {
                status: "rejected".to_string(),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                stdout_bytes: 0,
                stderr_bytes: 0,
                started_at,
                completed_at: now_rfc3339(),
                error_message: Some(format!("unknown capability '{}'", capability)),
            }
        }
    };
    let timeout_seconds = timeout_seconds.min(envelope).max(1);

    match capability {
        "curl" => run_strike_job(uuid::Uuid::nil(), method, url, pinned_ips, timeout_seconds).await,
        "nmap" => match build_nmap_argv(pinned_targets) {
            Ok(argv) => execute_fixed("nmap", argv, timeout_seconds, "nmap", started_at).await,
            Err(e) => rejected(e, started_at),
        },
        "nuclei" => match resolve_managed_nuclei() {
            Some((bin, templates_dir)) => {
                let target = if !url.is_empty() {
                    url.to_string()
                } else {
                    pinned_targets.join(",")
                };
                match build_nuclei_argv(&target, &templates_dir.to_string_lossy(), timeout_seconds) {
                    Ok(argv) => {
                        execute_fixed(&bin.to_string_lossy(), argv, timeout_seconds, "nuclei", started_at).await
                    }
                    Err(e) => rejected(e, started_at),
                }
            }
            None => rejected(
                "Managed Nuclei binary/templates are not installed or activated".to_string(),
                started_at,
            ),
        },
        "ffuf" => {
            // the embedded wordlist travels through a temp file whose path is
            // never user-controlled
            let wordlist_path = std::env::temp_dir().join(format!(
                "tempris-strike-wordlist-{}.txt",
                uuid::Uuid::new_v4()
            ));
            let result = match std::fs::write(&wordlist_path, STRIKE_WORDLIST) {
                Ok(()) => match build_ffuf_argv(url, &wordlist_path.to_string_lossy()) {
                    Ok(argv) => {
                        execute_fixed("ffuf", argv, timeout_seconds, "ffuf", started_at).await
                    }
                    Err(e) => rejected(e, started_at),
                },
                Err(e) => rejected(format!("could not materialize wordlist: {}", e), started_at),
            };
            let _ = std::fs::remove_file(&wordlist_path);
            result
        }
        "dig" => match record_type {
            Some(qtype) => match build_dig_argv(qtype, url) {
                Ok(argv) => execute_fixed("dig", argv, timeout_seconds, "dig", started_at).await,
                Err(e) => rejected(e, started_at),
            },
            None => rejected("a dig run requires a record type".to_string(), started_at),
        },
        _ => rejected(format!("unknown capability '{}'", capability), started_at),
    }
}

fn rejected(error_message: String, started_at: String) -> StrikeRunResult {
    StrikeRunResult {
        status: "rejected".to_string(),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        stdout_bytes: 0,
        stderr_bytes: 0,
        started_at,
        completed_at: now_rfc3339(),
        error_message: Some(error_message),
    }
}

/// The shared bounded execution core: spawn the fixed argv (no shell),
/// drain both pipes under a capture bound, kill on the envelope, report
/// truthfully.
async fn execute_fixed(
    program: &str,
    argv: Vec<String>,
    timeout_seconds: u64,
    tool_label: &str,
    started_at: String,
) -> StrikeRunResult {
    let mut child = match Command::new(program).args(&argv).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            return StrikeRunResult {
                status: "failed".to_string(),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                stdout_bytes: 0,
                stderr_bytes: 0,
                started_at,
                completed_at: now_rfc3339(),
                error_message: Some(format!("{} could not be started: {}", tool_label, e)),
            }
        }
    };

    // Take the pipes BEFORE waiting so a large output cannot deadlock the kill path.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    async fn read_bounded(pipe: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf.len() < STRIKE_OUTPUT_LIMIT + 1 {
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    // keep draining so curl never blocks on a full pipe
                }
            }
        }
        buf
    }

    let wait = async {
        let (out_bytes, err_bytes) = tokio::join!(
            read_bounded(stdout_pipe.as_mut().expect("stdout piped")),
            read_bounded(stderr_pipe.as_mut().expect("stderr piped")),
        );
        (out_bytes, err_bytes)
    };

    let timeout = Duration::from_secs(timeout_seconds.saturating_add(10));
    let (out_bytes, err_bytes, exit_code, timed_out) =
        match tokio::time::timeout(timeout, async { (wait.await, child.wait().await) }).await {
            Ok(((out_bytes, err_bytes), status)) => {
                let code = status.ok().and_then(|s| s.code());
                (out_bytes, err_bytes, code, false)
            }
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                (Vec::new(), Vec::new(), None, true)
            }
        };

    let (stdout, _out_total, _out_trunc) = cap_to_limit(out_bytes);
    let (stderr, _err_total, _err_trunc) = cap_to_limit(err_bytes);

    let (status, error_message) = if timed_out {
        (
            "failed".to_string(),
            Some(format!(
                "{} was killed after the {}s envelope",
                tool_label, timeout_seconds
            )),
        )
    } else {
        match exit_code {
            Some(0) => ("completed".to_string(), None),
            Some(code) => (
                "completed".to_string(),
                Some(format!("{} exited with code {}", tool_label, code)),
            ),
            None => (
                "failed".to_string(),
                Some(format!("{} terminated without an exit code", tool_label)),
            ),
        }
    };

    StrikeRunResult {
        status,
        exit_code,
        stdout_bytes: stdout.len(),
        stderr_bytes: stderr.len(),
        stdout,
        stderr,
        started_at,
        completed_at: now_rfc3339(),
        error_message,
    }
}

/// Probe a simple version-printing binary (curl/ffuf/dig readiness).
pub async fn probe_binary_version(program: &str, version_args: &[&str]) -> crate::protocol::EngineCapability {
    let last_checked_at = Some(now_rfc3339());
    let output = Command::new(program)
        .args(version_args)
        .output()
        .await;
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let version = text
                .split_whitespace()
                .find(|t| t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
                .map(|s| s.to_string());
            crate::protocol::EngineCapability {
                available: true,
                version,
                templates_version: None,
                managed: Some(false),
                status: Some("ready".to_string()),
                integrity_status: Some("verified".to_string()),
                path: None,
                last_checked_at,
                prerequisite_health: Some("ready".to_string()),
            }
        }
        _ => crate::protocol::EngineCapability {
            available: false,
            version: None,
            templates_version: None,
            managed: Some(false),
            status: Some("missing".to_string()),
            integrity_status: Some("unknown".to_string()),
            path: None,
            last_checked_at,
            prerequisite_health: Some("missing".to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_get_with_pins() {
        let argv = build_strike_argv(
            "GET",
            "http://192.168.1.1/",
            &["192.168.1.1".to_string()],
            60,
        )
        .unwrap();
        assert_eq!(argv.first().unwrap(), "-sS");
        assert!(!argv.iter().any(|a| a == "-L"));
        assert!(argv.iter().any(|a| a == "--max-redirs"));
        assert!(argv.contains(&"192.168.1.1:80:192.168.1.1".to_string()));
        assert_eq!(argv.last().unwrap(), "http://192.168.1.1/");
    }

    #[test]
    fn argv_head_uses_uppercase_i() {
        let argv = build_strike_argv("HEAD", "https://router.local:8443/x", &["10.0.0.9".to_string()], 30).unwrap();
        assert!(argv.contains(&"-I".to_string()));
        assert!(argv.contains(&"router.local:8443:10.0.0.9".to_string()));
    }

    #[test]
    fn argv_refuses_bad_method_and_empty_pins() {
        assert!(build_strike_argv("POST", "http://h/", &["1.2.3.4".to_string()], 60).is_err());
        assert!(build_strike_argv("GET", "http://h/", &[], 60).is_err());
        assert!(build_strike_argv("GET", "http://h/", &["1.2.3.4".to_string()], 0).is_err());
    }

    #[test]
    fn split_url_handles_ipv6_and_creds() {
        assert_eq!(
            split_url("http://[::1]:8080/x").unwrap(),
            ("::1".to_string(), 8080)
        );
        assert!(split_url("http://user:pw@host/").is_err());
        assert_eq!(split_url("https://host").unwrap(), ("host".to_string(), 443));
    }

    // -- nmap -------------------------------------------------------------

    #[test]
    fn nmap_argv_is_unprivileged_connect_scan_only() {
        let argv = build_nmap_argv(&["203.0.113.10".to_string()]).unwrap();
        let expected_head = [
            "-sT", "-Pn", "--open", "-T3", "--max-retries", "2",
            "--host-timeout", "120s", "--max-rate", "100", "-p", "1-10000",
            "-oX", "-",
        ];
        assert_eq!(&argv[..expected_head.len()], &expected_head);
        assert_eq!(argv.last().unwrap(), "203.0.113.10");
        for dangerous in ["-sS", "-O", "-A", "--script", "--osscan"] {
            assert!(!argv.iter().any(|a| a == dangerous), "{} present", dangerous);
        }
    }

    #[test]
    fn nmap_argv_carries_every_pinned_target_and_refuses_junk() {
        let argv = build_nmap_argv(&[
            "203.0.113.10".to_string(),
            "203.0.113.0/24".to_string(),
        ])
        .unwrap();
        assert_eq!(&argv[argv.len() - 2..], &["203.0.113.10", "203.0.113.0/24"]);
        assert!(build_nmap_argv(&[]).is_err());
        assert!(build_nmap_argv(&["not-an-ip".to_string()]).is_err());
        assert!(build_nmap_argv(&["203.0.113.0/99".to_string()]).is_err());
        assert!(build_nmap_argv(&["example.com".to_string()]).is_err());
    }

    // -- nuclei -----------------------------------------------------------

    #[test]
    fn nuclei_argv_has_ni_duc_and_managed_templates() {
        let argv =
            build_nuclei_argv("https://203.0.113.10/", "/managed/templates", 1200).unwrap();
        let pos = |needle: &str| argv.iter().position(|a| a == needle).unwrap();
        assert_eq!(argv[pos("-ni") + 1], "-duc"); // adjacent flags both present
        assert!(argv.contains(&"-ni".to_string()));
        assert!(argv.contains(&"-duc".to_string()));
        assert_eq!(argv[pos("-t") + 1], "/managed/templates");
        assert_eq!(argv[pos("-target") + 1], "https://203.0.113.10/");
        // no redirect option exists anywhere in the argv
        assert!(!argv.iter().any(|a| a.contains("redirect")));
        assert!(build_nuclei_argv("", "/t", 60).is_err());
        assert!(build_nuclei_argv("https://h/", "", 60).is_err());
        assert!(build_nuclei_argv("https://h/", "/t", 0).is_err());
        assert!(build_nuclei_argv("https://h/", "/t", 1201).is_err());
    }

    // -- ffuf -------------------------------------------------------------

    #[test]
    fn ffuf_argv_has_no_dangerous_flags() {
        let argv = build_ffuf_argv("http://203.0.113.10/FUZZ", "/tmp/wl.txt").unwrap();
        assert_eq!(argv[argv.iter().position(|a| a == "-u").unwrap() + 1], "http://203.0.113.10/FUZZ");
        assert_eq!(argv[argv.iter().position(|a| a == "-w").unwrap() + 1], "/tmp/wl.txt");
        assert!(argv.contains(&"-ac".to_string()));
        assert!(argv.contains(&"-mc".to_string()));
        for dangerous in [
            "-r", "-recursion", "-input-cmd", "-input-shell", "-preflight",
            "-postflight", "-request", "-x", "-H",
        ] {
            assert!(!argv.iter().any(|a| a == dangerous), "{} present", dangerous);
        }
    }

    #[test]
    fn ffuf_fuzz_position_rules() {
        // missing FUZZ
        assert!(build_ffuf_argv("http://h/admin", "/tmp/wl").is_err());
        // FUZZ in the authority/host
        assert!(build_ffuf_argv("http://FUZZ.example.com/", "/tmp/wl").is_err());
        // two FUZZ tokens in the path
        assert!(build_ffuf_argv("http://h/FUZZ/FUZZ", "/tmp/wl").is_err());
        // FUZZ in the query string
        assert!(build_ffuf_argv("http://h/admin?q=FUZZ", "/tmp/wl").is_err());
        // credentials refused
        assert!(build_ffuf_argv("http://user:pw@h/FUZZ", "/tmp/wl").is_err());
        // the one good shape
        assert!(build_ffuf_argv("https://h:8443/api/FUZZ/", "/tmp/wl").is_ok());
    }

    // -- dig --------------------------------------------------------------

    #[test]
    fn dig_argv_is_short_type_name() {
        let argv = build_dig_argv("txt", "scoped.example.com").unwrap();
        assert_eq!(argv, vec!["+short", "TXT", "scoped.example.com"]);
    }

    #[test]
    fn dig_refuses_any_axfr_and_everything_unlisted() {
        for qtype in ["ANY", "AXFR", "IXFR", "HINFO", "*", "all", ""] {
            assert!(
                build_dig_argv(qtype, "scoped.example.com").is_err(),
                "{} must be refused",
                qtype
            );
        }
        assert!(build_dig_argv("A", "bad name").is_err());
        assert!(build_dig_argv("A", "name@example").is_err());
        assert!(build_dig_argv("A", "").is_err());
    }

    // -- wordlist embed ----------------------------------------------------

    #[test]
    fn wordlist_is_embedded_relative_paths_only() {
        assert!(STRIKE_WORDLIST.len() > 100);
        let entries: Vec<&str> = STRIKE_WORDLIST.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(entries.len(), 33);
        for e in &entries {
            assert!(!e.starts_with('/'), "absolute path in wordlist: {}", e);
            assert!(!e.contains(".."), "traversal in wordlist: {}", e);
        }
        assert!(STRIKE_WORDLIST.ends_with('\n'));
    }

    // -- envelopes / gating -----------------------------------------------

    #[test]
    fn envelopes_mirror_the_backend() {
        assert_eq!(strike_envelope("curl"), Some(60));
        assert_eq!(strike_envelope("nmap"), Some(180));
        assert_eq!(strike_envelope("nuclei"), Some(1200));
        assert_eq!(strike_envelope("ffuf"), Some(300));
        assert_eq!(strike_envelope("dig"), Some(30));
        assert_eq!(strike_envelope("nc"), None);
    }
}
