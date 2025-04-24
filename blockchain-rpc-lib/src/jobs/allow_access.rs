use crate::Result;
use crate::context::SecureRpcContext;
use crate::error::Error;
use blueprint_sdk::{
    extract::Context,
    macros::debug_job,
    tangle::extract::{TangleArg, TangleResult},
};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AccessTarget {
    Ip(String),      // Can be single IP or CIDR
    Account(String), // AccountId32 as string
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllowAccessInput {
    pub target: AccessTarget,
}

/// Job handler to add a permanent access rule (IP or Account).
/// Should ideally check if the caller is an authorized admin.
#[debug_job]
pub async fn handler(
    Context(ctx): Context<SecureRpcContext>,
    TangleArg(input): TangleArg<AllowAccessInput>,
) -> Result<TangleResult<()>> {
    // Optional: Add admin check here using ctx.admin_pair and job metadata (caller)
    // if !is_admin(&ctx, &job_metadata.caller) {
    //     return Err(Error::AccessDeniedAdmin("Only admin can call allow_access"));
    // }

    match input.target {
        AccessTarget::Ip(ip_str) => {
            let ip_network = IpNetwork::from_str(&ip_str)
                .map_err(|e| Error::InvalidJobInput(format!("Invalid IP/CIDR: {}", e)))?;
            ctx.firewall.add_ip_rule(ip_network).await?;
            Ok(TangleResult(()))
        }
        AccessTarget::Account(account_str) => {
            let account_id = AccountId32::from_str(&account_str)
                .map_err(|_| Error::InvalidJobInput("Invalid AccountId32 format".to_string()))?;
            ctx.firewall.add_account_rule(account_id).await?;
            Ok(TangleResult(()))
        }
    }
}
