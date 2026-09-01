pub mod app;
pub mod autostart;
pub mod client;
pub mod config;
pub mod crypto;
pub mod enrollment;
pub mod lifecycle;
pub mod logging;
pub mod protocol;
pub mod safety;
pub mod singleton;
pub mod storage;
pub mod ui;
pub mod verifier;

pub use app::run_app;
