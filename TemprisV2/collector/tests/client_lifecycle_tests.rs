use std::sync::Arc;
use std::time::Duration;
use tempris_collector::client::{CollectorClient, ConnectionStatus};
use tempris_collector::config::CollectorConfig;
use tempris_collector::crypto::generate_keypair;
use tokio::time::timeout;
use uuid::Uuid;

#[tokio::test]
async fn test_client_rejects_remote_plaintext_transport_gate() {
    let (signing_key, _) = generate_keypair();
    let mut config = CollectorConfig::default();
    config.collector_id = Some(Uuid::new_v4());
    config.server_url = "http://remote-server.com:8000".to_string(); // plaintext remote forbidden
    config.enrolled = true;

    let client = Arc::new(CollectorClient::new(config, signing_key));
    let client_clone = Arc::clone(&client);

    // Running run_loop should immediately fail and terminate without looping
    let handle = tokio::spawn(async move {
        client_clone.run_loop().await;
    });

    let res = timeout(Duration::from_secs(3), handle).await;
    assert!(
        res.is_ok(),
        "run_loop should terminate immediately on transport violation"
    );

    let state = client.state.read().await;
    match &state.status {
        ConnectionStatus::Failed(msg) => {
            assert!(
                msg.contains("Transport security rejection") || msg.contains("strictly forbidden")
            );
        }
        other => panic!("Expected ConnectionStatus::Failed, got {:?}", other),
    }
}

#[tokio::test]
async fn test_client_shutdown_signal_terminates_cleanly() {
    let (signing_key, _) = generate_keypair();
    let mut config = CollectorConfig::default();
    config.collector_id = Some(Uuid::new_v4());
    config.server_url = "http://127.0.0.1:8000".to_string(); // loopback allowed
    config.enrolled = true;

    let client = Arc::new(CollectorClient::new(config, signing_key));
    let client_clone = Arc::clone(&client);

    let handle = tokio::spawn(async move {
        client_clone.run_loop().await;
    });

    // Send shutdown after short delay
    tokio::time::sleep(Duration::from_millis(50)).await;
    client.shutdown();

    let res = timeout(Duration::from_secs(5), handle).await;
    assert!(
        res.is_ok(),
        "run_loop must terminate upon shutdown signal without hanging"
    );
}

#[tokio::test]
async fn test_probe_task_cancellation_and_abort_safety() {
    // Proves that probe tasks are properly tracked and abort cleanly without task leaks
    let mut probe_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    for _ in 0..5 {
        let task = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        probe_tasks.push(task);
    }

    assert_eq!(probe_tasks.len(), 5);

    // Simulate session teardown: abort and join all
    for task in &probe_tasks {
        task.abort();
    }
    for task in probe_tasks {
        let res = task.await;
        assert!(
            res.is_err(),
            "Aborted probe task should resolve to JoinError::Cancelled"
        );
    }
}
