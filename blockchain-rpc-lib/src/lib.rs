pub mod config;
pub mod context;
pub mod error;
pub mod firewall;
pub mod jobs;
pub mod rpc;

pub use context::SecureRpcContext;
pub use error::Error;

use std::path::PathBuf;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Default data directory for the blueprint if not specified.
pub fn default_data_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Home directory should exist")
        .join(".secure-rpc-gateway")
}
