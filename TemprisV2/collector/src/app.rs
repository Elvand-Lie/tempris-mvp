use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::autostart::{handle_uac_helper_cli, AutoStartManager};
use crate::client::CollectorClient;
use crate::enrollment::enroll_collector;
use crate::singleton::{LockResult, ShutdownSignalListener, SingleInstanceGuard};
use crate::storage::{StorageError, StorageManager};
use crate::ui::CollectorApp;

#[derive(Parser, Debug)]
#[command(name = "tempris-collector")]
#[command(author = "Tempris Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Tempris V2 Internal Asset Reachability Collector for Windows", long_about = None)]
pub struct Cli {
    /// Run in headless / daemon mode without opening the GUI window
    #[arg(long, alias = "daemon", alias = "headless")]
    pub core: bool,

    /// Custom storage directory path (defaults to %PROGRAMDATA%\Tempris\Collector)
    #[arg(long, alias = "data-dir")]
    pub storage_dir: Option<PathBuf>,

    /// Legacy configuration file path or directory for V0.1 migration
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Override control plane base URL
    #[arg(long)]
    pub server_url: Option<String>,

    /// One-time enrollment code to enroll from CLI
    #[arg(long)]
    pub enroll: Option<String>,

    /// Collector Profile UUID for CLI enrollment
    #[arg(long)]
    pub collector_id: Option<Uuid>,

    /// Run internal UAC elevation helper
    #[arg(long, value_name = "ACTION")]
    pub uac_helper: Option<String>,

    /// Task name override for UAC helper operations
    #[arg(long, value_name = "TASK_NAME")]
    pub task_name: Option<String>,
}

pub fn run_app() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Fast-path: Handle UAC elevation helper immediately before initializing GUI or full logger
    if let Some(ref action) = cli.uac_helper {
        let code = handle_uac_helper_cli(action, cli.task_name.as_deref());
        std::process::exit(code);
    }

    // Initialize structured tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("Starting Tempris Collector v{}", env!("CARGO_PKG_VERSION"));

    // 1. Initialize StorageManager
    let storage = if let Some(dir) = cli.storage_dir {
        StorageManager::new(dir)
    } else if let Some(ref cfg_path) = cli.config {
        if cfg_path.is_dir() {
            StorageManager::new(cfg_path.clone())
        } else if let Some(parent) = cfg_path.parent() {
            StorageManager::new(parent.to_path_buf())
        } else {
            StorageManager::default_machine_storage()
        }
    } else {
        StorageManager::default_machine_storage()
    };

    info!("Using storage directory: {:?}", storage.base_dir());

    // 2. Automatically perform lossless V0.1 migration if legacy config is present
    let mut migration_error: Option<String> = None;
    match storage.migrate_v01_if_needed(cli.config.as_deref()) {
        Ok(Some((migrated_state, _))) => {
            info!(
                "Successfully migrated legacy V0.1 config to V0.2 storage layout for collector '{}' ({})",
                migrated_state.collector_name, migrated_state.collector_id
            );
        }
        Ok(None) => {}
        Err(e) => {
            error!("V0.1 migration failed: {}", e);
            migration_error = Some(format!("Migration failed: {}", e));
        }
    }

    // Set up tokio multithreaded runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // 3. Handle CLI enrollment if specified
    if let (Some(code), Some(col_id)) = (cli.enroll, cli.collector_id) {
        let server_url = cli
            .server_url
            .clone()
            .unwrap_or_else(|| "https://sandbox.tempris.tech/v2-assets".to_string());
        info!("Executing CLI enrollment for collector ID {}...", col_id);
        rt.block_on(async {
            enroll_collector(&server_url, col_id, &code, Some(storage.base_dir())).await
        })?;
        info!("CLI enrollment completed successfully.");

        let autostart = AutoStartManager::new(None);
        if let Err(e) = autostart.register(None) {
            warn!("Task Scheduler boot autostart registration notice: {}", e);
        } else {
            info!(
                "Registered Task Scheduler boot autostart task '{}' (SYSTEM / ONSTART).",
                autostart.task_name()
            );
        }
    }

    // 4. Headless Daemon / Core mode
    if cli.core {
        info!("Running in headless core daemon mode (--core). Press Ctrl+C to exit.");

        // If migration failed in core mode, fail closed immediately
        if let Some(ref m_err) = migration_error {
            error!(
                "Core daemon startup aborted due to migration error: {}",
                m_err
            );
            return Err(anyhow::anyhow!("Migration failure: {}", m_err));
        }

        // Acquire singleton mutex lock across processes in Global namespace (fail closed on any error)
        let _singleton_guard = match SingleInstanceGuard::acquire(None) {
            LockResult::Acquired(guard) => {
                info!("Acquired singleton mutex guard '{}'", guard.name());
                guard
            }
            LockResult::AlreadyRunning => {
                info!(
                    "Another Tempris Collector core instance is already running. Exiting cleanly."
                );
                return Ok(());
            }
            LockResult::Error(e) => {
                error!("Could not acquire singleton mutex (failing closed): {}", e);
                return Err(anyhow::anyhow!("Singleton acquisition failed: {}", e));
            }
        };

        // Load persisted state from StorageManager
        let (state, key) = match storage.load() {
            Ok((mut s, k)) => {
                if let Some(url) = cli.server_url {
                    s.server_url = url;
                }
                (s, k)
            }
            Err(StorageError::NotFound) => {
                warn!("Collector is not enrolled. Run with --enroll <CODE> --collector-id <UUID> or start GUI to enroll.");
                return Ok(());
            }
            Err(err) => {
                error!(
                    "Core mode cannot start due to storage corruption: {}. Failing closed.",
                    err
                );
                return Err(anyhow::anyhow!("Storage corruption: {}", err));
            }
        };

        let client = Arc::new(CollectorClient::from_storage_state(
            &state,
            key,
            storage.clone(),
        ));
        info!(
            "Loaded enrolled identity for collector '{}' ({}). Initiating core daemon connection.",
            state.collector_name, state.collector_id
        );

        let shutdown_listener = ShutdownSignalListener::new(None);
        rt.block_on(async move {
            let c_loop = client.clone();
            let c_shutdown = client.clone();
            let loop_handle = tokio::spawn(async move {
                c_loop.run_loop().await;
            });

            let mut check_interval = tokio::time::interval(std::time::Duration::from_millis(200));
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received SIGINT/Ctrl+C termination signal. Shutting down.");
                        c_shutdown.shutdown();
                        break;
                    }
                    _ = check_interval.tick() => {
                        if shutdown_listener.is_signaled() {
                            info!("Received cross-process shutdown signal. Shutting down.");
                            c_shutdown.shutdown();
                            break;
                        }
                    }
                }
            }
            let _ = loop_handle.await;
        });

        return Ok(());
    }

    // 5. GUI Observer Mode: Read persisted storage without launching unprivileged local daemons
    let (persisted_state, recovery_error) = if let Some(m_err) = migration_error {
        (None, Some(m_err))
    } else {
        match storage.load() {
            Ok((mut state, _key)) => {
                if let Some(url) = cli.server_url.clone() {
                    state.server_url = url;
                }

                // Check if background core daemon is running in Session 0
                let is_core_running = SingleInstanceGuard::is_another_instance_running(None);
                if is_core_running {
                    info!("Detected active background core daemon. GUI running in decoupled observer mode.");
                } else {
                    info!("Background core daemon not active. GUI running in decoupled observer mode.");
                }

                (Some(state), None)
            }
            Err(StorageError::NotFound) => {
                info!("No persisted collector identity found (unenrolled setup view).");
                (None, None)
            }
            Err(err) => {
                error!(
                    "Failed to load collector storage state: {}. Entering recovery view.",
                    err
                );
                (None, Some(err.to_string()))
            }
        }
    };

    // 6. Launch Native Windows Desktop GUI (eframe)
    info!("Launching Windows desktop GUI window...");
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([740.0, 540.0])
            .with_min_inner_size([580.0, 420.0])
            .with_title("Tempris Collector"),
        ..Default::default()
    };

    let rt_handle = rt.handle().clone();
    eframe::run_native(
        "Tempris Collector",
        native_options,
        Box::new(move |_cc| {
            Ok(Box::new(CollectorApp::new(
                storage,
                persisted_state,
                recovery_error,
                rt_handle,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("GUI runtime error: {}", e))?;

    Ok(())
}
