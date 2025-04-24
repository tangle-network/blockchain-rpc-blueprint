use crate::Result;
use crate::config::ServiceConfig;
use crate::default_data_dir;
use crate::error::Error;
use crate::firewall::Firewall;
use blueprint_sdk::common::{BlueprintEnvironment, KeystoreContext, TangleClientContext};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sp_core::sr25519::Pair as Sr25519Pair;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::interval;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporaryAccessRecord {
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, TangleClientContext, KeystoreContext)]
pub struct SecureRpcContext {
    #[config]
    pub env: BlueprintEnvironment,
    pub service_config: Arc<ServiceConfig>,
    pub data_dir: PathBuf,
    pub firewall: Arc<Firewall>,
    // We keep the signer pair accessible for potential admin checks if needed
    pub admin_pair: Option<Arc<Sr25519Pair>>,
}

impl SecureRpcContext {
    pub async fn new(env: BlueprintEnvironment, service_config: ServiceConfig) -> Result<Self> {
        let data_dir = env.data_dir().clone().unwrap_or_else(default_data_dir);
        if !data_dir.exists() {
            std::fs::create_dir_all(&data_dir)?;
        }

        let service_config = Arc::new(service_config);
        let firewall = Arc::new(Firewall::new(
            &service_config.firewall,
            &service_config.webhooks.event_urls,
        ));

        // Start the cleanup task for expired temporary access
        let firewall_clone = firewall.clone();
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::seconds(60).to_std().unwrap());
            loop {
                cleanup_interval.tick().await;
                firewall_clone.cleanup_expired_access();
            }
        });

        // Optionally load an admin key if configured/needed for certain jobs
        let admin_pair = env
            .keystore()
            .get_secret::<Sr25519Pair>("admin") // Assumes an alias 'admin'
            .ok()
            .map(|p| Arc::new(p.0));

        Ok(Self {
            env,
            service_config,
            data_dir,
            firewall,
            admin_pair,
        })
    }

    pub fn config(&self) -> &ServiceConfig {
        &self.service_config
    }
}
