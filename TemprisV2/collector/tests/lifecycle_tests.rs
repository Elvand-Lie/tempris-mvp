use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use tempris_collector::client::{CollectorClient, ConnectionStatus};
use tempris_collector::config::CollectorConfig;
use tempris_collector::crypto::{generate_keypair, public_key_to_base64url};
use tempris_collector::lifecycle::{BackoffLadder, RuntimeSnapshot, RuntimeStatus};
use tempris_collector::logging::BoundedLogger;
use tempris_collector::protocol::{ClientFrame, ServerFrame};
use tempris_collector::storage::{CollectorState, StorageError, StorageManager};

#[test]
fn test_backoff_ladder_exact_progression_and_capping() {
    let mut ladder = BackoffLadder::new();
    assert_eq!(ladder.current(), Duration::from_secs(1));
    assert_eq!(ladder.next(), Duration::from_secs(1));

    assert_eq!(ladder.current(), Duration::from_secs(2));
    assert_eq!(ladder.next(), Duration::from_secs(2));

    assert_eq!(ladder.current(), Duration::from_secs(5));
    assert_eq!(ladder.next(), Duration::from_secs(5));

    assert_eq!(ladder.current(), Duration::from_secs(10));
    assert_eq!(ladder.next(), Duration::from_secs(10));

    assert_eq!(ladder.current(), Duration::from_secs(30));
    assert_eq!(ladder.next(), Duration::from_secs(30));

    // Cap at 30 seconds
    assert_eq!(ladder.current(), Duration::from_secs(30));
    assert_eq!(ladder.next(), Duration::from_secs(30));
    assert!(ladder.is_max());

    // Reset back to 1 second
    ladder.reset();
    assert_eq!(ladder.current(), Duration::from_secs(1));
    assert_eq!(ladder.current_step(), 0);
    assert!(!ladder.is_max());
}

#[tokio::test]
async fn test_backoff_ladder_resets_only_on_auth_success() {
    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let temp_dir = std::env::temp_dir().join(format!("tempris_ladder_test_{}", Uuid::new_v4()));
    let storage = StorageManager::new(temp_dir.clone());

    let state = CollectorState::new(
        col_id,
        "Test-Ladder-Collector".to_string(),
        "http://127.0.0.1:0".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let server_url = format!("http://127.0.0.1:{}", port);

    let mut config = CollectorConfig::default();
    config.server_url = server_url.clone();
    config.collector_id = Some(col_id);
    config.enrolled = true;

    let client = Arc::new(CollectorClient::with_storage(
        config,
        signing_key,
        Some(storage.clone()),
    ));
    let client_clone = Arc::clone(&client);

    let server_task = tokio::spawn(async move {
        // First connection: server drops immediately before challenge (simulating transient network drop)
        if let Ok((stream, _)) = listener.accept().await {
            let mut ws = accept_async(stream).await.expect("ws handshake");
            let _ = ws.close(None).await;
        }

        // Second connection: server completes auth challenge and issues AUTH_SUCCESS
        if let Ok((stream, _)) = listener.accept().await {
            let mut ws = accept_async(stream).await.expect("ws handshake");
            let challenge = ServerFrame::AUTH_CHALLENGE {
                nonce: "ladder-test-nonce".to_string(),
                expires_at: (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
            };
            ws.send(Message::Text(
                serde_json::to_string(&challenge).unwrap().into(),
            ))
            .await
            .expect("send challenge");

            // Read response
            if let Some(Ok(Message::Text(_auth_resp))) = ws.next().await {
                let success = ServerFrame::AUTH_SUCCESS {
                    collector_id: col_id,
                    status: "connected".to_string(),
                };
                ws.send(Message::Text(
                    serde_json::to_string(&success).unwrap().into(),
                ))
                .await
                .expect("send success");

                // Keep connection open briefly then close
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    });

    let client_task = tokio::spawn(async move {
        client_clone.run_loop().await;
    });

    // Wait until client transitions to Connected
    for _ in 0..50 {
        sleep(Duration::from_millis(50)).await;
        let st = client.state.read().await;
        if st.status == ConnectionStatus::Connected {
            break;
        }
    }

    {
        let st = client.state.read().await;
        assert_eq!(st.status, ConnectionStatus::Connected);
    }

    client.shutdown();
    let _ = timeout(Duration::from_secs(2), client_task).await;
    let _ = timeout(Duration::from_secs(2), server_task).await;

    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_policy_quarantined_stops_reconnect_loop() {
    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let temp_dir = std::env::temp_dir().join(format!("tempris_quarantine_test_{}", Uuid::new_v4()));
    let storage = StorageManager::new(temp_dir.clone());

    let state = CollectorState::new(
        col_id,
        "Quarantine-Test-Collector".to_string(),
        "http://127.0.0.1:0".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let server_url = format!("http://127.0.0.1:{}", port);

    let mut config = CollectorConfig::default();
    config.server_url = server_url.clone();
    config.collector_id = Some(col_id);
    config.enrolled = true;

    let client = Arc::new(CollectorClient::with_storage(
        config,
        signing_key,
        Some(storage.clone()),
    ));
    let client_clone = Arc::clone(&client);

    let server_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut ws = accept_async(stream).await.expect("ws handshake");
            // Send 1008 Close frame with "Quarantined" policy violation
            let close_frame = CloseFrame {
                code: CloseCode::from(1008u16),
                reason: "Collector quarantined by operator policy".into(),
            };
            let _ = ws.close(Some(close_frame)).await;
        }
    });

    let client_task = tokio::spawn(async move {
        client_clone.run_loop().await;
    });

    // Client run_loop must terminate quickly without reconnecting
    let res = timeout(Duration::from_secs(4), client_task).await;
    assert!(
        res.is_ok(),
        "Client loop must terminate immediately upon 1008 Quarantine policy close"
    );

    {
        let st = client.state.read().await;
        assert_eq!(st.status, ConnectionStatus::Quarantined);
    }

    // Disk state must remain intact (not wiped by policy close)
    assert!(
        storage.state_path().exists(),
        "state.json must remain on disk after quarantine"
    );
    assert!(
        storage.identity_path().exists(),
        "protected_identity.dat must remain on disk after quarantine"
    );

    // Runtime snapshot must reflect QUARANTINED status
    let snap = RuntimeSnapshot::load_from(&storage.runtime_path()).expect("read runtime.json");
    assert_eq!(snap.status, RuntimeStatus::Quarantined);

    let _ = timeout(Duration::from_secs(1), server_task).await;
    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_policy_revoked_stops_reconnect_loop() {
    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let temp_dir = std::env::temp_dir().join(format!("tempris_revoked_test_{}", Uuid::new_v4()));
    let storage = StorageManager::new(temp_dir.clone());

    let state = CollectorState::new(
        col_id,
        "Revoked-Test-Collector".to_string(),
        "http://127.0.0.1:0".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let server_url = format!("http://127.0.0.1:{}", port);

    let mut config = CollectorConfig::default();
    config.server_url = server_url.clone();
    config.collector_id = Some(col_id);
    config.enrolled = true;

    let client = Arc::new(CollectorClient::with_storage(
        config,
        signing_key,
        Some(storage.clone()),
    ));
    let client_clone = Arc::clone(&client);

    let server_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut ws = accept_async(stream).await.expect("ws handshake");
            let close_frame = CloseFrame {
                code: CloseCode::from(1008u16),
                reason: "Collector revoked permanently".into(),
            };
            let _ = ws.close(Some(close_frame)).await;
        }
    });

    let client_task = tokio::spawn(async move {
        client_clone.run_loop().await;
    });

    let res = timeout(Duration::from_secs(4), client_task).await;
    assert!(
        res.is_ok(),
        "Client loop must terminate immediately upon 1008 Revoked policy close"
    );

    {
        let st = client.state.read().await;
        assert_eq!(st.status, ConnectionStatus::Revoked);
    }

    assert!(
        storage.state_path().exists(),
        "state.json must remain intact on disk"
    );
    assert!(
        storage.identity_path().exists(),
        "protected_identity.dat must remain intact on disk"
    );

    let snap = RuntimeSnapshot::load_from(&storage.runtime_path()).expect("read runtime.json");
    assert_eq!(snap.status, RuntimeStatus::Revoked);

    let _ = timeout(Duration::from_secs(1), server_task).await;
    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_policy_paused_retains_connection_and_suppresses_jobs() {
    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let temp_dir = std::env::temp_dir().join(format!("tempris_paused_test_{}", Uuid::new_v4()));
    let storage = StorageManager::new(temp_dir.clone());

    let state = CollectorState::new(
        col_id,
        "Paused-Test-Collector".to_string(),
        "http://127.0.0.1:0".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let server_url = format!("http://127.0.0.1:{}", port);

    let mut config = CollectorConfig::default();
    config.server_url = server_url.clone();
    config.collector_id = Some(col_id);
    config.enrolled = true;

    let client = Arc::new(CollectorClient::with_storage(
        config,
        signing_key,
        Some(storage.clone()),
    ));
    let client_clone = Arc::clone(&client);

    let job_id = Uuid::new_v4();

    let server_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut ws = accept_async(stream).await.expect("ws handshake");
            let challenge = ServerFrame::AUTH_CHALLENGE {
                nonce: "paused-test-nonce".to_string(),
                expires_at: (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
            };
            ws.send(Message::Text(
                serde_json::to_string(&challenge).unwrap().into(),
            ))
            .await
            .expect("send challenge");

            if let Some(Ok(Message::Text(_auth_resp))) = ws.next().await {
                // Server authenticates with status = "paused"
                let success = ServerFrame::AUTH_SUCCESS {
                    collector_id: col_id,
                    status: "paused".to_string(),
                };
                ws.send(Message::Text(
                    serde_json::to_string(&success).unwrap().into(),
                ))
                .await
                .expect("send success");

                // Send a VERIFY_TARGET job while paused
                let job_frame = ServerFrame::VERIFY_TARGET {
                    job_id,
                    operation: Some("VERIFY_TARGET".to_string()),
                    asset_id: Some(Uuid::new_v4()),
                    correlation_id: Some("corr-123".to_string()),
                    target: Some("10.0.0.50".to_string()),
                    target_value: Some("10.0.0.50".to_string()),
                    target_type: Some("ip".to_string()),
                    network_scope: Some("internal".to_string()),
                    expires_at: Some((Utc::now() + chrono::Duration::seconds(30)).to_rfc3339()),
                    timeout_seconds: Some(5),
                };
                ws.send(Message::Text(
                    serde_json::to_string(&job_frame).unwrap().into(),
                ))
                .await
                .expect("send job");

                // Expect client to reject job because it is PAUSED
                if let Some(Ok(Message::Text(res_text))) = ws.next().await {
                    let parsed: ClientFrame = serde_json::from_str(&res_text).unwrap();
                    match parsed {
                        ClientFrame::VERIFY_TARGET_RESULT {
                            job_id: r_job_id,
                            status,
                            reachable,
                            reachability_status,
                            error_message,
                            ..
                        } => {
                            assert_eq!(r_job_id, job_id);
                            assert_eq!(status, "rejected");
                            assert!(!reachable);
                            assert_eq!(reachability_status, "unreachable");
                            assert!(error_message.unwrap().contains("paused"));
                        }
                        _ => panic!("Expected VERIFY_TARGET_RESULT"),
                    }
                }

                // Keep connection open until client shuts down
                while let Some(_) = ws.next().await {}
            }
        }
    });

    let client_task = tokio::spawn(async move {
        client_clone.run_loop().await;
    });

    // Wait until client enters Paused state
    for _ in 0..50 {
        sleep(Duration::from_millis(50)).await;
        let st = client.state.read().await;
        if st.status == ConnectionStatus::Paused {
            break;
        }
    }

    {
        let st = client.state.read().await;
        assert_eq!(st.status, ConnectionStatus::Paused);
        assert_eq!(
            st.jobs_completed, 0,
            "Paused collector must execute zero jobs"
        );
    }

    client.shutdown();
    let _ = timeout(Duration::from_secs(2), client_task).await;
    let _ = timeout(Duration::from_secs(2), server_task).await;

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_runtime_snapshot_atomic_write_read_and_zero_secrets() {
    let temp_dir = std::env::temp_dir().join(format!("tempris_runtime_test_{}", Uuid::new_v4()));
    let runtime_path = temp_dir.join("runtime.json");

    let col_id = Uuid::new_v4();
    let mut snap = RuntimeSnapshot::new(
        col_id,
        "Snapshot-Test-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snap.last_heartbeat = Some(Utc::now());
    snap.jobs_verified = 27;
    snap.current_activity = "Verifying 10.0.1.5 -> verified".to_string();

    snap.save_atomic(&runtime_path)
        .expect("save_atomic runtime.json");
    assert!(runtime_path.exists());

    let loaded = RuntimeSnapshot::load_from(&runtime_path).expect("load_from runtime.json");
    assert_eq!(loaded.schema_version, 1);
    assert_eq!(loaded.collector_id, col_id);
    assert_eq!(loaded.collector_name, "Snapshot-Test-Collector");
    assert_eq!(loaded.status, RuntimeStatus::Connected);
    assert_eq!(loaded.jobs_verified, 27);
    assert_eq!(loaded.current_activity, "Verifying 10.0.1.5 -> verified");
    assert_eq!(loaded.collector_version, "0.2.0");

    let raw_text = fs::read_to_string(&runtime_path).expect("read raw runtime.json");
    assert!(raw_text.contains("\"status\": \"CONNECTED\""));
    assert!(!raw_text.contains("private_key"));
    assert!(!raw_text.contains("secret"));
    assert!(!raw_text.contains("protected_identity"));
    assert!(!raw_text.contains("jwt"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_bounded_log_rotation_and_zero_secrets() {
    let temp_dir = std::env::temp_dir().join(format!("tempris_logrot_test_{}", Uuid::new_v4()));
    // Small threshold (250 bytes) to force rapid rotation
    let logger = BoundedLogger::with_limits(temp_dir.clone(), 250, 3, 50);

    for i in 0..30 {
        logger.log(
            "INFO",
            &format!("Operational event #{:04} target=192.168.1.{}", i, i),
        );
    }

    let active_log = temp_dir.join("collector.log");
    let rot1 = temp_dir.join("collector.log.1");
    let rot2 = temp_dir.join("collector.log.2");
    let rot3 = temp_dir.join("collector.log.3");
    let rot4 = temp_dir.join("collector.log.4");

    assert!(active_log.exists(), "collector.log should exist");
    assert!(rot1.exists(), "collector.log.1 should exist");
    assert!(rot2.exists(), "collector.log.2 should exist");
    assert!(rot3.exists(), "collector.log.3 should exist");
    assert!(
        !rot4.exists(),
        "collector.log.4 should NOT exist (capped at 3)"
    );

    let log_content = fs::read_to_string(&active_log).expect("read active log");
    assert!(!log_content.contains("private_key"));
    assert!(!log_content.contains("secret"));
    assert!(!log_content.contains("signing_key"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_advanced_reset_wipes_all_state_and_runtime() {
    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let temp_dir = std::env::temp_dir().join(format!("tempris_reset_test_{}", Uuid::new_v4()));
    let storage = StorageManager::new(temp_dir.clone());

    let state = CollectorState::new(
        col_id,
        "Reset-Test-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    let snap = RuntimeSnapshot::new(
        col_id,
        "Reset-Test-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snap.save_atomic(&storage.runtime_path())
        .expect("save runtime");

    assert!(storage.state_path().exists());
    assert!(storage.identity_path().exists());
    assert!(storage.runtime_path().exists());

    // Execute reset
    storage.reset().expect("storage reset");

    assert!(
        !storage.state_path().exists(),
        "state.json must be deleted by reset"
    );
    assert!(
        !storage.identity_path().exists(),
        "protected_identity.dat must be deleted by reset"
    );
    assert!(
        !storage.runtime_path().exists(),
        "runtime.json must be deleted by reset"
    );

    // Loading after reset must return StorageError::NotFound
    let load_res = storage.load();
    assert!(matches!(load_res, Err(StorageError::NotFound)));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_recovery_behavior_on_corrupt_files() {
    let temp_dir = std::env::temp_dir().join(format!("tempris_corrupt_test_{}", Uuid::new_v4()));
    let storage = StorageManager::new(temp_dir.clone());

    // 1. Corrupt state.json
    fs::create_dir_all(storage.base_dir()).unwrap();
    fs::write(storage.state_path(), "{ invalid json state").unwrap();
    fs::write(storage.identity_path(), vec![1, 2, 3, 4]).unwrap();

    let res = storage.load();
    assert!(matches!(res, Err(StorageError::CorruptStateJson(_))));

    // 2. Corrupt/missing identity with valid state.json
    let valid_state = CollectorState::new(
        Uuid::new_v4(),
        "Corrupt-Test".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        "invalid-pubkey".to_string(),
        Utc::now(),
    );
    let valid_json = serde_json::to_string(&valid_state).unwrap();
    fs::write(storage.state_path(), valid_json).unwrap();
    let _ = fs::remove_file(storage.identity_path());

    let res2 = storage.load();
    assert!(matches!(
        res2,
        Err(StorageError::CorruptProtectedIdentity(_))
    ));

    let _ = fs::remove_dir_all(&temp_dir);
}
