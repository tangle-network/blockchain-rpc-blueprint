use crate::Result;
use crate::error::Error;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sp_runtime::AccountId32;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub rpc: RpcConfig,
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub webhooks: WebhookConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub listen_addr: SocketAddr,
    pub proxy_to_url: Url,
    #[serde(default = "default_max_body_size_bytes")]
    pub max_body_size_bytes: usize,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default, deserialize_with = "deserialize_ip_networks")]
    pub allow_ips: HashSet<IpNetwork>,
    #[serde(default, deserialize_with = "deserialize_accounts")]
    pub allow_accounts: HashSet<AccountId32>,
    #[serde(default)]
    pub allow_unrestricted_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebhookConfig {
    #[serde(default)]
    pub event_urls: Vec<Url>,
}

fn default_max_body_size_bytes() -> usize {
    1024 * 1024 * 10 // 10 MB
}

fn default_request_timeout_secs() -> u64 {
    30
}

impl ServiceConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = ::config::Config::builder()
            .add_source(::config::File::from(path.as_ref()))
            .add_source(::config::Environment::with_prefix("SECURE_RPC").separator("__"))
            .build()
            .map_err(Error::ConfigError)?;
        let service_config: ServiceConfig = config.try_deserialize().map_err(Error::ConfigError)?;
        Ok(service_config)
    }
}

// Custom deserializer for HashSet<IpNetwork>
fn deserialize_ip_networks<'de, D>(deserializer: D) -> Result<HashSet<IpNetwork>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ips_str = Vec::<String>::deserialize(deserializer)?;
    ips_str
        .into_iter()
        .map(|s| {
            IpNetwork::from_str(&s)
                .map_err(|e| serde::de::Error::custom(format!("Invalid IP/CIDR '{}': {}", s, e)))
        })
        .collect()
}

// Custom deserializer for HashSet<AccountId32>
fn deserialize_accounts<'de, D>(deserializer: D) -> Result<HashSet<AccountId32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let accounts_str = Vec::<String>::deserialize(deserializer)?;
    accounts_str
        .into_iter()
        .map(|s| {
            AccountId32::from_str(&s)
                .map_err(|_| serde::de::Error::custom(format!("Invalid AccountId32: {}", s)))
        })
        .collect()
}
