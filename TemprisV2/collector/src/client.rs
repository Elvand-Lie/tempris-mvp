use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, watch, RwLock};
use tokio::time::{interval, sleep};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

use crate::config::{validate_transport_url, CollectorConfig};
use crate::crypto::sign_canonical_challenge;
use crate::lifecycle::{BackoffLadder, RuntimeSnapshot, RuntimeStatus};
use crate::logging::{BoundedLogger, LogEntry};
use crate::protocol::{ClientFrame, ServerFrame};
use crate::safety::{NetworkScope, TargetType};
use crate::storage::{CollectorState, StorageManager};
use crate::verifier::verify_internal_target;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Reconnecting,
    Paused,
    Quarantined,
    Revoked,
    Failed(String),
}

impl ConnectionStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ConnectionStatus::Disconnected => "Disconnected",
            ConnectionStatus::Connecting => "Connecting",
            ConnectionStatus::Authenticating => "Authenticating",
            ConnectionStatus::Connected => "Connected",
            ConnectionStatus::Reconnecting => "Reconnecting",
            ConnectionStatus::Paused => "Paused",
            ConnectionStatus::Quarantined => "Quarantined",
            ConnectionStatus::Revoked => "Revoked",
            ConnectionStatus::Failed(_) => "Failed",
        }
    }

    pub fn to_runtime_status(&self) -> RuntimeStatus {
        match self {
            ConnectionStatus::Disconnected => RuntimeStatus::Offline,
            ConnectionStatus::Connecting => RuntimeStatus::Connecting,
            ConnectionStatus::Authenticating => RuntimeStatus::Authenticating,
            ConnectionStatus::Connected => RuntimeStatus::Connected,
            ConnectionStatus::Reconnecting => RuntimeStatus::Reconnecting,
            ConnectionStatus::Paused => RuntimeStatus::Paused,
            ConnectionStatus::Quarantined => RuntimeStatus::Quarantined,
            ConnectionStatus::Revoked => RuntimeStatus::Revoked,
            ConnectionStatus::Failed(_) => RuntimeStatus::Error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CollectorClientState {
    pub status: ConnectionStatus,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub last_verified_target: Option<String>,
    pub jobs_completed: u64,
    pub activity_log: Vec<LogEntry>,
}

impl Default for CollectorClientState {
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            last_heartbeat: None,
            last_verified_target: None,
            jobs_completed: 0,
            activity_log: Vec::new(),
        }
    }
}

pub struct CollectorClient {
    pub config: CollectorConfig,
    signing_key: SigningKey,
    pub storage: Option<StorageManager>,
    pub logger: BoundedLogger,
    pub state: Arc<RwLock<CollectorClientState>>,
    pub log_sender: broadcast::Sender<LogEntry>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl CollectorClient {
    pub fn new(config: CollectorConfig, signing_key: SigningKey) -> Self {
        Self::with_storage(config, signing_key, None)
    }

    pub fn with_storage(
        config: CollectorConfig,
        signing_key: SigningKey,
        storage: Option<StorageManager>,
    ) -> Self {
        let logs_dir = storage
            .as_ref()
            .map(|s| s.logs_dir())
            .unwrap_or_else(|| std::env::temp_dir().join("tempris_collector_logs"));
        let logger = BoundedLogger::new(logs_dir);
        let (log_sender, _) = broadcast::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            signing_key,
            storage,
            logger,
            state: Arc::new(RwLock::new(CollectorClientState::default())),
            log_sender,
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub fn from_storage_state(
        state: &CollectorState,
        signing_key: SigningKey,
        storage: StorageManager,
    ) -> Self {
        let mut config = CollectorConfig::default();
        config.server_url = state.server_url.clone();
        config.collector_id = Some(state.collector_id);
        config.collector_name = Some(state.collector_name.clone());
        config.enrolled = true;
        config.public_key = Some(state.public_key.clone());
        config.created_at = Some(state.enrolled_at);
        config.updated_at = Some(state.enrolled_at);

        Self::with_storage(config, signing_key, Some(storage))
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn log(&self, level: &str, msg: &str) {
        tracing::info!("[{}] {}", level, msg);
        self.logger.log(level, msg);

        let entry = LogEntry::new(level, msg);

        {
            let mut state = self.state.write().await;
            if state.activity_log.len() >= 500 {
                state.activity_log.remove(0);
            }
            state.activity_log.push(entry.clone());
        }

        let _ = self.log_sender.send(entry);
    }

    /// Atomically updates `runtime.json` snapshot if storage manager is configured.
    pub async fn sync_runtime_snapshot(&self) {
        if let Some(ref storage) = self.storage {
            let (status, last_hb, last_target, jobs, err_msg) = {
                let state = self.state.read().await;
                let rt_status = state.status.to_runtime_status();
                let err = match &state.status {
                    ConnectionStatus::Failed(msg) => Some(msg.clone()),
                    _ => None,
                };
                (
                    rt_status,
                    state.last_heartbeat,
                    state.last_verified_target.clone(),
                    state.jobs_completed,
                    err,
                )
            };

            let col_id = self.config.collector_id.unwrap_or_default();
            let col_name = self
                .config
                .collector_name
                .clone()
                .unwrap_or_else(|| format!("Collector-{}", &col_id.to_string()[..8]));

            let mut snap =
                RuntimeSnapshot::new(col_id, col_name, self.config.server_url.clone(), status);
            snap.last_heartbeat = last_hb;
            snap.jobs_verified = jobs;
            if let Some(target) = last_target {
                snap.current_activity = target;
            }
            snap.error_message = err_msg;
            snap.updated_at = Utc::now();

            let _ = snap.save_atomic(&storage.runtime_path());
        }
    }

    pub async fn set_status(&self, status: ConnectionStatus) {
        {
            let mut state = self.state.write().await;
            state.status = status;
        }
        self.sync_runtime_snapshot().await;
    }

    pub fn build_ws_url(&self) -> String {
        let base = CollectorConfig::normalize_server_url(&self.config.server_url);
        let ws_base = if base.starts_with("https://") {
            format!("wss://{}", &base[8..])
        } else if base.starts_with("http://") {
            format!("ws://{}", &base[7..])
        } else if base.starts_with("wss://") || base.starts_with("ws://") {
            base.to_string()
        } else {
            format!("wss://{}", base)
        };
        format!("{}/api/collectors/ws", ws_base)
    }

    pub async fn run_loop(self: Arc<Self>) {
        let collector_id = match self.config.collector_id {
            Some(id) => id,
            None => {
                self.log("ERROR", "Cannot start WebSocket client: collector is not enrolled (missing collector_id).").await;
                self.set_status(ConnectionStatus::Failed("Not enrolled".to_string()))
                    .await;
                return;
            }
        };

        // Enforce transport gate before establishing persistent WebSocket connection
        if let Err(e) = validate_transport_url(&self.config.server_url) {
            self.log(
                "ERROR",
                &format!(
                    "Transport security rejection for '{}': {}. Aborting connection loop.",
                    self.config.server_url, e
                ),
            )
            .await;
            self.set_status(ConnectionStatus::Failed(format!(
                "Transport security rejection: {}",
                e
            )))
            .await;
            return;
        }

        let ws_url = self.build_ws_url();
        self.log(
            "INFO",
            &format!("Starting collector loop targeting {}", ws_url),
        )
        .await;

        let mut ladder = BackoffLadder::new();
        let mut shutdown_rx = self.shutdown_rx.clone();

        loop {
            if *shutdown_rx.borrow() {
                self.log("INFO", "Collector loop received shutdown signal. Exiting.")
                    .await;
                self.set_status(ConnectionStatus::Disconnected).await;
                break;
            }

            self.set_status(ConnectionStatus::Connecting).await;
            self.log("INFO", &format!("Connecting to WebSocket at {}", ws_url))
                .await;

            match connect_async(&ws_url).await {
                Ok((ws_stream, response)) => {
                    debug!("WebSocket connected: status {:?}", response.status());
                    self.set_status(ConnectionStatus::Authenticating).await;
                    self.log("INFO", "WebSocket connected. Initiating cryptographic challenge-response handshake...").await;

                    // Invariant: Backoff ladder is NOT reset on raw TCP connect. It resets ONLY upon AUTH_SUCCESS.

                    let (mut write_half, mut read_half) = ws_stream.split();
                    let (tx_outbound, mut rx_outbound) = mpsc::channel::<Message>(32);

                    // Writer task forwarder
                    let writer_task = tokio::spawn(async move {
                        while let Some(msg) = rx_outbound.recv().await {
                            if let Err(e) = write_half.send(msg).await {
                                warn!("Error sending WebSocket message: {}", e);
                                break;
                            }
                        }
                        let _ = write_half.close().await;
                    });

                    let mut authenticated = false;
                    let mut policy_violation = false;
                    let mut policy_reason = String::new();
                    let mut probe_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

                    let mut heartbeat_interval = interval(Duration::from_secs(20));
                    heartbeat_interval.reset();

                    'session: loop {
                        tokio::select! {
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() {
                                    self.log("INFO", "Shutdown received during active session.").await;
                                    break 'session;
                                }
                            }

                            _ = heartbeat_interval.tick(), if authenticated => {
                                let now_rfc3339 = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
                                let hb_frame = ClientFrame::HEARTBEAT { timestamp: now_rfc3339 };
                                if let Ok(json_str) = serde_json::to_string(&hb_frame) {
                                    if tx_outbound.send(Message::Text(json_str.into())).await.is_err() {
                                        break 'session;
                                    }
                                }
                            }

                            msg_opt = read_half.next() => {
                                match msg_opt {
                                    Some(Ok(Message::Text(text))) => {
                                        let text_str = text.as_str();
                                        match serde_json::from_str::<ServerFrame>(text_str) {
                                            Ok(ServerFrame::AUTH_CHALLENGE { nonce, expires_at }) => {
                                                self.log("DEBUG", &format!("Received AUTH_CHALLENGE (nonce={}, expires_at={})", nonce, expires_at)).await;
                                                let signature = sign_canonical_challenge(
                                                    &self.signing_key,
                                                    &collector_id,
                                                    &nonce,
                                                    &expires_at
                                                );
                                                let auth_resp = ClientFrame::AUTH_RESPONSE {
                                                    collector_id,
                                                    nonce,
                                                    expires_at,
                                                    signature,
                                                };
                                                if let Ok(resp_json) = serde_json::to_string(&auth_resp) {
                                                    if tx_outbound.send(Message::Text(resp_json.into())).await.is_err() {
                                                        break 'session;
                                                    }
                                                    self.log("DEBUG", "Transmitted AUTH_RESPONSE frame").await;
                                                }
                                            }
                                            Ok(ServerFrame::AUTH_SUCCESS { collector_id: succ_id, status }) => {
                                                authenticated = true;
                                                // Invariant: Reset backoff ladder ONLY upon AUTH_SUCCESS
                                                ladder.reset();

                                                let status_lower = status.to_lowercase();
                                                if status_lower == "paused" {
                                                    self.set_status(ConnectionStatus::Paused).await;
                                                    self.log("WARN", &format!("Authentication SUCCESS for collector {} (status: PAUSED - 0 verification jobs will be executed)", succ_id)).await;
                                                } else {
                                                    self.set_status(ConnectionStatus::Connected).await;
                                                    self.log("INFO", &format!("Authentication SUCCESS for collector {} (status: {})", succ_id, status)).await;
                                                }
                                            }
                                            Ok(ServerFrame::HEARTBEAT_ACK { timestamp }) => {
                                                {
                                                    let mut state = self.state.write().await;
                                                    state.last_heartbeat = Some(Utc::now());
                                                }
                                                self.sync_runtime_snapshot().await;
                                                debug!("Received HEARTBEAT_ACK at {}", timestamp);
                                            }
                                            Ok(ServerFrame::VERIFY_TARGET {
                                                job_id,
                                                operation,
                                                asset_id: _,
                                                correlation_id: _,
                                                target,
                                                target_value,
                                                target_type,
                                                network_scope,
                                                expires_at,
                                                timeout_seconds: _,
                                            }) => {
                                                // M1: Reject pre-auth frames fail-closed
                                                if !authenticated {
                                                    self.log("WARN", &format!("Ignored pre-auth VERIFY_TARGET job {} before AUTH_SUCCESS", job_id)).await;
                                                    continue 'session;
                                                }

                                                // Check if collector is currently in PAUSED state
                                                let is_paused = {
                                                    let st = self.state.read().await;
                                                    st.status == ConnectionStatus::Paused
                                                };
                                                if is_paused {
                                                    self.log("WARN", &format!("VERIFY_TARGET job {} rejected: collector is currently PAUSED", job_id)).await;
                                                    let now = Utc::now().to_rfc3339();
                                                    let rej_frame = ClientFrame::VERIFY_TARGET_RESULT {
                                                        job_id,
                                                        status: "rejected".to_string(),
                                                        reachable: false,
                                                        method: "tcp_probe".to_string(),
                                                        port: None,
                                                        port_reached: None,
                                                        reachability_status: "unreachable".to_string(),
                                                        latency_ms: None,
                                                        error_message: Some("Collector is currently paused by administrator policy".to_string()),
                                                        started_at: now.clone(),
                                                        completed_at: now,
                                                    };
                                                    if let Ok(json_res) = serde_json::to_string(&rej_frame) {
                                                        let _ = tx_outbound.send(Message::Text(json_res.into())).await;
                                                    }
                                                    continue 'session;
                                                }

                                                // M1: Enforce exact operation == "VERIFY_TARGET"
                                                if operation.as_deref() != Some("VERIFY_TARGET") {
                                                    self.log("WARN", &format!("VERIFY_TARGET job {} rejected: invalid operation '{:?}'", job_id, operation)).await;
                                                    let now = Utc::now().to_rfc3339();
                                                    let rej_frame = ClientFrame::VERIFY_TARGET_RESULT {
                                                        job_id,
                                                        status: "rejected".to_string(),
                                                        reachable: false,
                                                        method: "tcp_probe".to_string(),
                                                        port: None,
                                                        port_reached: None,
                                                        reachability_status: "unreachable".to_string(),
                                                        latency_ms: None,
                                                        error_message: Some(format!("Invalid operation '{:?}' - expected 'VERIFY_TARGET'", operation)),
                                                        started_at: now.clone(),
                                                        completed_at: now,
                                                    };
                                                    if let Ok(json_res) = serde_json::to_string(&rej_frame) {
                                                        let _ = tx_outbound.send(Message::Text(json_res.into())).await;
                                                    }
                                                    continue 'session;
                                                }

                                                // M1: Check required and unexpired expires_at
                                                let is_valid_expiry = match expires_at.as_deref() {
                                                    Some(exp_str) => match DateTime::parse_from_rfc3339(exp_str) {
                                                        Ok(exp_dt) => Utc::now() <= exp_dt.with_timezone(&Utc),
                                                        Err(_) => false,
                                                    },
                                                    None => false,
                                                };
                                                if !is_valid_expiry {
                                                    self.log("WARN", &format!("VERIFY_TARGET job {} rejected: missing, unparseable, or expired expires_at '{:?}'", job_id, expires_at)).await;
                                                    let now = Utc::now().to_rfc3339();
                                                    let rej_frame = ClientFrame::VERIFY_TARGET_RESULT {
                                                        job_id,
                                                        status: "rejected".to_string(),
                                                        reachable: false,
                                                        method: "tcp_probe".to_string(),
                                                        port: None,
                                                        port_reached: None,
                                                        reachability_status: "unreachable".to_string(),
                                                        latency_ms: None,
                                                        error_message: Some(format!("Job rejected: invalid or expired expires_at timestamp '{:?}'", expires_at)),
                                                        started_at: now.clone(),
                                                        completed_at: now,
                                                    };
                                                    if let Ok(json_res) = serde_json::to_string(&rej_frame) {
                                                        let _ = tx_outbound.send(Message::Text(json_res.into())).await;
                                                    }
                                                    continue 'session;
                                                }

                                                let target_raw = target.or(target_value).unwrap_or_default();
                                                let scope_parsed = network_scope.as_deref().and_then(NetworkScope::from_str);
                                                let type_parsed = target_type.as_deref().and_then(TargetType::from_str);

                                                // M1: Validate scope strictly
                                                if scope_parsed != Some(NetworkScope::Internal) {
                                                    self.log("WARN", &format!("VERIFY_TARGET job {} rejected: scope '{:?}' is not internal", job_id, network_scope)).await;
                                                    let now = Utc::now().to_rfc3339();
                                                    let rej_frame = ClientFrame::VERIFY_TARGET_RESULT {
                                                        job_id,
                                                        status: "rejected".to_string(),
                                                        reachable: false,
                                                        method: "tcp_probe".to_string(),
                                                        port: None,
                                                        port_reached: None,
                                                        reachability_status: "unreachable".to_string(),
                                                        latency_ms: None,
                                                        error_message: Some(format!("Invalid network scope '{:?}' - only 'internal' is supported", network_scope)),
                                                        started_at: now.clone(),
                                                        completed_at: now,
                                                    };
                                                    if let Ok(json_res) = serde_json::to_string(&rej_frame) {
                                                        let _ = tx_outbound.send(Message::Text(json_res.into())).await;
                                                    }
                                                    continue 'session;
                                                }

                                                // M1: Validate target_type strictly
                                                let validated_type = match type_parsed {
                                                    Some(t) => t,
                                                    None => {
                                                        self.log("WARN", &format!("VERIFY_TARGET job {} rejected: unknown target_type '{:?}'", job_id, target_type)).await;
                                                        let now = Utc::now().to_rfc3339();
                                                        let rej_frame = ClientFrame::VERIFY_TARGET_RESULT {
                                                            job_id,
                                                            status: "rejected".to_string(),
                                                            reachable: false,
                                                            method: "tcp_probe".to_string(),
                                                            port: None,
                                                            port_reached: None,
                                                            reachability_status: "unreachable".to_string(),
                                                            latency_ms: None,
                                                            error_message: Some(format!("Unsupported target_type '{:?}' - expected 'ip', 'hostname', or 'domain'", target_type)),
                                                            started_at: now.clone(),
                                                            completed_at: now,
                                                        };
                                                        if let Ok(json_res) = serde_json::to_string(&rej_frame) {
                                                            let _ = tx_outbound.send(Message::Text(json_res.into())).await;
                                                        }
                                                        continue 'session;
                                                    }
                                                };

                                                let client_clone = Arc::clone(&self);
                                                let tx_clone = tx_outbound.clone();
                                                let handle = tokio::spawn(async move {
                                                    let started_at = Utc::now().to_rfc3339();
                                                    client_clone.log("INFO", &format!("Executing VERIFY_TARGET job {} for target '{}' ({:?})", job_id, target_raw, validated_type)).await;
                                                    let outcome = verify_internal_target(&target_raw, Some(&validated_type)).await;
                                                    let completed_at = Utc::now().to_rfc3339();

                                                    client_clone.log("INFO", &format!("VERIFY_TARGET job {} finished: status='{}', port={:?}, latency={:?}ms", job_id, outcome.reachability_status, outcome.port_reached, outcome.latency_ms)).await;

                                                    {
                                                        let mut state = client_clone.state.write().await;
                                                        state.jobs_completed += 1;
                                                        state.last_verified_target = Some(format!("{} -> {}", target_raw, outcome.reachability_status));
                                                    }
                                                    client_clone.sync_runtime_snapshot().await;

                                                    let reachable = outcome.reachability_status == "verified";
                                                    let res_frame = ClientFrame::VERIFY_TARGET_RESULT {
                                                        job_id,
                                                        status: if outcome.error_message.is_some() && !reachable { "failed".to_string() } else { "completed".to_string() },
                                                        reachable,
                                                        method: "tcp_probe".to_string(),
                                                        port: outcome.port_reached,
                                                        port_reached: outcome.port_reached,
                                                        reachability_status: outcome.reachability_status,
                                                        latency_ms: outcome.latency_ms,
                                                        error_message: outcome.error_message,
                                                        started_at,
                                                        completed_at,
                                                    };

                                                    if let Ok(json_res) = serde_json::to_string(&res_frame) {
                                                        let _ = tx_clone.send(Message::Text(json_res.into())).await;
                                                    }
                                                });
                                                probe_tasks.retain(|t| !t.is_finished());
                                                probe_tasks.push(handle);
                                            }
                                            Err(e) => {
                                                warn!("Failed to deserialize server frame (len: {} bytes): {}", text_str.len(), e);
                                            }
                                        }
                                    }
                                    Some(Ok(Message::Close(Some(close_frame)))) => {
                                        let code = close_frame.code;
                                        let reason = close_frame.reason.to_string();
                                        self.log("WARN", &format!("WebSocket closed by server with code {:?}: {}", code, reason)).await;

                                        if code == CloseCode::from(1008u16) || code == CloseCode::Policy {
                                            policy_violation = true;
                                            policy_reason = reason;
                                        }
                                        break 'session;
                                    }
                                    Some(Ok(Message::Close(None))) => {
                                        self.log("WARN", "WebSocket closed cleanly by server.").await;
                                        break 'session;
                                    }
                                    Some(Ok(Message::Ping(p))) => {
                                        let _ = tx_outbound.send(Message::Pong(p)).await;
                                    }
                                    Some(Err(e)) => {
                                        self.log("WARN", &format!("WebSocket read error: {}", e)).await;
                                        break 'session;
                                    }
                                    None => {
                                        self.log("INFO", "WebSocket stream terminated.").await;
                                        break 'session;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    // Abort and join all active in-flight probe tasks
                    for task in &probe_tasks {
                        task.abort();
                    }
                    for task in probe_tasks {
                        let _ = task.await;
                    }

                    // Abort writer task so it never hangs on session close
                    writer_task.abort();
                    let _ = writer_task.await;

                    if policy_violation {
                        let reason_lower = policy_reason.to_lowercase();
                        let final_status = if reason_lower.contains("quarantin") {
                            ConnectionStatus::Quarantined
                        } else if reason_lower.contains("revoke") {
                            ConnectionStatus::Revoked
                        } else {
                            ConnectionStatus::Failed(format!(
                                "Policy Violation (1008): {}",
                                policy_reason
                            ))
                        };

                        self.log("ERROR", &format!("Terminating connection loop due to Policy Violation (1008): {}. Reconnection halted.", policy_reason)).await;
                        self.set_status(final_status).await;
                        return; // Fail-closed: do not reconnect automatically on 1008 policy violation
                    }
                }
                Err(e) => {
                    self.log(
                        "WARN",
                        &format!(
                            "Connection to {} failed: {}. Retrying in {:?}...",
                            ws_url,
                            e,
                            ladder.current()
                        ),
                    )
                    .await;
                }
            }

            // Invariant: Bounded discrete backoff ladder
            let delay = ladder.next();
            self.set_status(ConnectionStatus::Reconnecting).await;

            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        self.log("INFO", "Collector loop received shutdown signal during backoff. Exiting.").await;
                        self.set_status(ConnectionStatus::Disconnected).await;
                        break;
                    }
                }
                _ = sleep(delay) => {}
            }
        }
    }
}
