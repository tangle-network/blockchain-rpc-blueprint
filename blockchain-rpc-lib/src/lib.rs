pub mod config;
pub mod context;
pub mod error;
pub mod firewall;
pub mod jobs;
pub mod rpc;

pub use context::SecureRpcContext;
pub use error::Error;

// Re-export core SDK items for convenience
pub use blueprint_sdk::{
    self, TangleClient, TangleClientContext, TangleLayer, TangleResult, common::*, consumer::*,
    core::*, keystore::*, logger::*, producer::*, signer::*,
};

use sp_core::sr25519::Pair as Sr25519Pair;
use sp_runtime::AccountId32;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Default data directory for the blueprint if not specified.
pub fn default_data_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Home directory should exist")
        .join(".secure-rpc-gateway")
}
