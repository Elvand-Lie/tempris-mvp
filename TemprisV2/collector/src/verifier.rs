use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::safety::{resolve_and_pin_safe_target, TargetType};

pub const MAX_PORT_PROBE_TIMEOUT_MS: u64 = 2000;

#[derive(Debug, Clone, PartialEq)]
pub struct VerificationOutcome {
    pub reachability_status: String, // "verified" | "unreachable"
    pub port_reached: Option<u16>,   // 443 | 80 | None
    pub latency_ms: Option<f64>,
    pub error_message: Option<String>,
}

/// Executes internal target verification for a single target.
/// 1. Runs safety validation and single-resolution DNS pinning (rejection with 0 socket connects if forbidden).
/// 2. Executes sequential zero-byte TCP probe to port 443 (timeout <= 2.0s).
/// 3. If port 443 fails/times out, executes sequential zero-byte TCP probe to port 80 (timeout <= 2.0s).
/// 4. Returns typed VerificationOutcome.
pub async fn verify_internal_target(
    target_value: &str,
    target_type_hint: Option<&TargetType>,
) -> VerificationOutcome {
    let clean = target_value.trim();

    // 1. Safety validation and DNS resolution pinning
    let pinned_ip = match resolve_and_pin_safe_target(clean, target_type_hint).await {
        Ok(ip) => ip,
        Err(e) => {
            warn!("Target safety check rejected '{}': {}", clean, e);
            return VerificationOutcome {
                reachability_status: "unreachable".to_string(),
                port_reached: None,
                latency_ms: None,
                error_message: Some(format!("Target safety check failed: {}", e)),
            };
        }
    };

    let probe_timeout = Duration::from_millis(MAX_PORT_PROBE_TIMEOUT_MS);

    // 2. Sequential zero-byte TCP probe to port 443
    let addr_443 = SocketAddr::new(pinned_ip, 443);
    debug!(
        "Probing pinned target {} on port 443 (timeout: {:?})...",
        addr_443, probe_timeout
    );
    let start_443 = Instant::now();

    match timeout(probe_timeout, TcpStream::connect(addr_443)).await {
        Ok(Ok(stream)) => {
            let elapsed_ms = start_443.elapsed().as_secs_f64() * 1000.0;
            // Explicitly drop/close the socket immediately
            drop(stream);
            info!(
                "Successfully verified target {} on port 443 in {:.2}ms",
                clean, elapsed_ms
            );
            return VerificationOutcome {
                reachability_status: "verified".to_string(),
                port_reached: Some(443),
                latency_ms: Some((elapsed_ms * 100.0).round() / 100.0),
                error_message: None,
            };
        }
        Ok(Err(e)) => {
            debug!("Port 443 connect failed for {}: {}", addr_443, e);
        }
        Err(_) => {
            debug!(
                "Port 443 connect timed out for {} after {:?}",
                addr_443, probe_timeout
            );
        }
    }

    // 3. Fallback sequential zero-byte TCP probe to port 80
    let addr_80 = SocketAddr::new(pinned_ip, 80);
    debug!(
        "Probing pinned target {} on port 80 (timeout: {:?})...",
        addr_80, probe_timeout
    );
    let start_80 = Instant::now();

    match timeout(probe_timeout, TcpStream::connect(addr_80)).await {
        Ok(Ok(stream)) => {
            let elapsed_ms = start_80.elapsed().as_secs_f64() * 1000.0;
            drop(stream);
            info!(
                "Successfully verified target {} on port 80 in {:.2}ms",
                clean, elapsed_ms
            );
            return VerificationOutcome {
                reachability_status: "verified".to_string(),
                port_reached: Some(80),
                latency_ms: Some((elapsed_ms * 100.0).round() / 100.0),
                error_message: None,
            };
        }
        Ok(Err(e)) => {
            debug!("Port 80 connect failed for {}: {}", addr_80, e);
        }
        Err(_) => {
            debug!(
                "Port 80 connect timed out for {} after {:?}",
                addr_80, probe_timeout
            );
        }
    }

    // Both ports failed
    info!(
        "Target {} ({}) unreachable on both port 443 and port 80",
        clean, pinned_ip
    );
    VerificationOutcome {
        reachability_status: "unreachable".to_string(),
        port_reached: None,
        latency_ms: None,
        error_message: Some(
            "Connection failed or timed out on both port 443 and port 80.".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_forbidden_target_fails_closed() {
        let outcome = verify_internal_target("127.0.0.1", None).await;
        assert_eq!(outcome.reachability_status, "unreachable");
        assert_eq!(outcome.port_reached, None);
        assert!(outcome
            .error_message
            .unwrap()
            .contains("forbidden address class"));
    }

    #[tokio::test]
    async fn test_verify_unreachable_target() {
        let outcome = verify_internal_target("192.168.1.253", None).await;
        assert_eq!(outcome.reachability_status, "unreachable");
        assert_eq!(outcome.port_reached, None);
    }
}
