use crate::Result;
use crate::config::FirewallConfig;
use crate::context::TemporaryAccessRecord;
use crate::error::Error;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;
use url::Url;

#[derive(Debug, Clone)]
pub struct Firewall {
    // Permanent allow lists from config
    allow_ips_config: HashSet<IpNetwork>,
    allow_accounts_config: HashSet<AccountId32>,
    allow_unrestricted_access: bool,

    // Dynamic allow lists managed by jobs
    allow_ips_dynamic: Arc<RwLock<HashSet<IpNetwork>>>,
    allow_accounts_dynamic: Arc<RwLock<HashSet<AccountId32>>>,
    temporary_access: Arc<RwLock<HashMap<AccountId32, TemporaryAccessRecord>>>,

    // Webhooks for notifications
    webhooks: Arc<RwLock<Vec<Url>>>,
    http_client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WebhookEvent {
    AccessGranted {
        source: String,      // IP or AccountId
        access_type: String, // "Permanent", "Temporary", "Unrestricted"
    },
    AccessDenied {
        source: String, // IP
    },
    TemporaryAccessExpired {
        account: AccountId32,
    },
    RuleAdded {
        rule_type: String, // "IP", "Account"
        value: String,
    },
    WebhookRegistered {
        url: Url,
    },
}

impl Firewall {
    pub fn new(config: &FirewallConfig, webhook_config: &[Url]) -> Self {
        Firewall {
            allow_ips_config: config.allow_ips.clone(),
            allow_accounts_config: config.allow_accounts.clone(),
            allow_unrestricted_access: config.allow_unrestricted_access,
            allow_ips_dynamic: Arc::new(RwLock::new(HashSet::new())),
            allow_accounts_dynamic: Arc::new(RwLock::new(HashSet::new())),
            temporary_access: Arc::new(RwLock::new(HashMap::new())),
            webhooks: Arc::new(RwLock::new(webhook_config.to_vec())),
            http_client: reqwest::Client::new(),
        }
    }

    /// Checks if an IP address is allowed access.
    /// Order of checks: Unrestricted -> Config IPs -> Dynamic IPs -> Temporary (via lookup)
    pub async fn is_allowed(&self, ip: &IpAddr) -> bool {
        if self.allow_unrestricted_access {
            debug!(%ip, "Access granted: Unrestricted access enabled");
            self.notify_webhook(WebhookEvent::AccessGranted {
                source: ip.to_string(),
                access_type: "Unrestricted".to_string(),
            })
            .await;
            return true;
        }

        if self.allow_ips_config.iter().any(|net| net.contains(*ip)) {
            debug!(%ip, "Access granted: IP found in static config allowlist");
            self.notify_webhook(WebhookEvent::AccessGranted {
                source: ip.to_string(),
                access_type: "Permanent (Config)".to_string(),
            })
            .await;
            return true;
        }

        if self
            .allow_ips_dynamic
            .read()
            .iter()
            .any(|net| net.contains(*ip))
        {
            debug!(%ip, "Access granted: IP found in dynamic allowlist");
            self.notify_webhook(WebhookEvent::AccessGranted {
                source: ip.to_string(),
                access_type: "Permanent (Dynamic)".to_string(),
            })
            .await;
            return true;
        }

        // Note: Temporary access check is usually tied to an account derived from auth token
        // in a real scenario. Here we only check permanent lists based on IP.
        debug!(%ip, "Access denied: IP not found in any allowlist");
        self.notify_webhook(WebhookEvent::AccessDenied {
            source: ip.to_string(),
        })
        .await;
        false
    }

    /// Checks if an account is allowed (config, dynamic, or temporary).
    pub async fn is_account_allowed(&self, account: &AccountId32) -> bool {
        if self.allow_unrestricted_access {
            debug!(%account, "Account access granted: Unrestricted access enabled");
            self.notify_webhook(WebhookEvent::AccessGranted {
                source: account.to_string(),
                access_type: "Unrestricted".to_string(),
            })
            .await;
            return true;
        }

        if self.allow_accounts_config.contains(account) {
            debug!(%account, "Account access granted: Found in static config allowlist");
            self.notify_webhook(WebhookEvent::AccessGranted {
                source: account.to_string(),
                access_type: "Permanent (Config)".to_string(),
            })
            .await;
            return true;
        }

        if self.allow_accounts_dynamic.read().contains(account) {
            debug!(%account, "Account access granted: Found in dynamic allowlist");
            self.notify_webhook(WebhookEvent::AccessGranted {
                source: account.to_string(),
                access_type: "Permanent (Dynamic)".to_string(),
            })
            .await;
            return true;
        }

        if self.check_temporary_access(account).await {
            debug!(%account, "Account access granted: Found in temporary access list");
            self.notify_webhook(WebhookEvent::AccessGranted {
                source: account.to_string(),
                access_type: "Temporary".to_string(),
            })
            .await;
            return true;
        }

        debug!(%account, "Account access denied: Not found in any allowlist");
        // No separate webhook for account denial unless specifically requested
        false
    }

    /// Adds a dynamic IP rule (can be single IP or CIDR).
    pub async fn add_ip_rule(&self, ip_network: IpNetwork) -> Result<()> {
        let inserted = self.allow_ips_dynamic.write().insert(ip_network);
        if inserted {
            debug!(rule = %ip_network, "Added dynamic IP rule");
            self.notify_webhook(WebhookEvent::RuleAdded {
                rule_type: "IP".to_string(),
                value: ip_network.to_string(),
            })
            .await;
        }
        Ok(())
    }

    /// Adds a dynamic account rule.
    pub async fn add_account_rule(&self, account: AccountId32) -> Result<()> {
        let inserted = self.allow_accounts_dynamic.write().insert(account.clone());
        if inserted {
            debug!(%account, "Added dynamic account rule");
            self.notify_webhook(WebhookEvent::RuleAdded {
                rule_type: "Account".to_string(),
                value: account.to_string(),
            })
            .await;
        }
        Ok(())
    }

    /// Grants temporary access to an account.
    pub async fn grant_temporary_access(
        &self,
        account: AccountId32,
        record: TemporaryAccessRecord,
    ) -> Result<()> {
        debug!(%account, expires_at = %record.expires_at, "Granting temporary access");
        self.temporary_access.write().insert(account, record);
        // Notification happens during check usually, or could add one here
        Ok(())
    }

    /// Checks if temporary access for an account is still valid.
    async fn check_temporary_access(&self, account: &AccountId32) -> bool {
        let now = Utc::now();
        let mut access_map = self.temporary_access.write();

        if let Some(record) = access_map.get(account) {
            if record.expires_at > now {
                return true; // Access valid
            }
            // Access expired
            debug!(%account, "Temporary access expired");
            access_map.remove(account);
            self.notify_webhook(WebhookEvent::TemporaryAccessExpired {
                account: account.clone(),
            })
            .await;
        }
        false
    }

    /// Cleans up expired temporary access records.
    pub fn cleanup_expired_access(&self) {
        let now = Utc::now();
        let mut access_map = self.temporary_access.write();
        let expired_accounts: Vec<AccountId32> = access_map
            .iter()
            .filter(|(_, record)| record.expires_at <= now)
            .map(|(account, _)| account.clone())
            .collect();

        for account in expired_accounts {
            debug!(%account, "Cleaning up expired temporary access");
            access_map.remove(&account);
            // Consider if notification is needed here too, though check_temporary_access handles it
            // self.notify_webhook(WebhookEvent::TemporaryAccessExpired { account }).await;
        }
    }

    /// Registers a new webhook URL.
    pub async fn add_webhook(&self, url: Url) -> Result<()> {
        debug!(%url, "Registering new webhook");
        self.webhooks.write().push(url.clone());
        self.notify_webhook(WebhookEvent::WebhookRegistered { url })
            .await;
        Ok(())
    }

    /// Sends an event notification to all registered webhooks.
    async fn notify_webhook(&self, event: WebhookEvent) {
        let urls = self.webhooks.read().clone();
        if urls.is_empty() {
            return;
        }

        let client = self.http_client.clone();
        let event_json = match serde_json::to_value(&event) {
            Ok(json) => json,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize webhook event");
                return;
            }
        };

        for url in urls {
            let client = client.clone();
            let event_json = event_json.clone();
            tokio::spawn(async move {
                match client.post(url.clone()).json(&event_json).send().await {
                    Ok(response) => {
                        if !response.status().is_success() {
                            tracing::warn!(%url, status = %response.status(), "Webhook notification failed");
                        } else {
                            tracing::debug!(%url, status = %response.status(), "Webhook notification sent successfully");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%url, error = %e, "Webhook notification failed");
                    }
                }
            });
        }
    }
}
