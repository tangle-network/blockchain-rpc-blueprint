use crate::Result;
use crate::context::{SecureRpcContext, TemporaryAccessRecord};
use crate::error::Error;
use blueprint_sdk::macros::debug_job;
use blueprint_sdk::tangle::extract::{Context, DecodedArgs, JobMetadata, TangleResult};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PayForAccessInput {
    /// Duration in seconds for which access should be granted.
    pub duration_secs: u64,
}

/// Job handler for users to pay for temporary access.
/// Assumes payment verification happens off-chain or via another mechanism.
/// The caller's AccountId gets temporary access.
#[debug_job]
pub async fn handler(
    Context(ctx): Context<SecureRpcContext>,
    JobMetadata(meta): JobMetadata,
    DecodedArgs(input): DecodedArgs<PayForAccessInput>,
) -> Result<TangleResult<()>> {
    let caller_account = meta
        .caller
        .ok_or_else(|| Error::InvalidJobInput("Job caller information missing".to_string()))?;

    if input.duration_secs == 0 {
        return Err(Error::InvalidJobInput(
            "Duration must be positive".to_string(),
        ));
    }

    // TODO: Implement actual payment verification here.
    // This could involve:
    // 1. Checking an EVM contract event via an EVMConsumer if this blueprint has one.
    // 2. Querying the Tangle chain state via ctx.tangle_client().
    // 3. Receiving proof-of-payment within the job inputs.
    // For this example, we assume payment is implicitly verified.

    let now = Utc::now();
    let expires_at = now + Duration::seconds(input.duration_secs as i64);
    let record = TemporaryAccessRecord {
        granted_at: now,
        expires_at,
    };

    ctx.firewall
        .grant_temporary_access(caller_account.clone(), record)
        .await?;

    tracing::info!(account = %caller_account, duration_secs = input.duration_secs, expires_at = %expires_at, "Granted temporary access");

    // Return empty result on success
    Ok(TangleResult(()))
}
