use crate::Result;
use crate::context::{SecureRpcContext, TemporaryAccessRecord};
use crate::error::Error;
use blueprint_sdk::macros::debug_job;
use blueprint_sdk::tangle::extract::{Context, DecodedArgs, TangleResult};
use chrono::{Duration, Utc};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sp_runtime::AccountId32;

/// Input arguments for the pay_for_access job, encoded using SCALE codec.
#[derive(Encode, Decode, Debug, Clone, Serialize, Deserialize)]
pub struct PayForAccessInput {
    /// The account that paid and should receive temporary access.
    pub beneficiary: AccountId32,
    /// Duration in seconds for which access should be granted.
    pub duration_secs: u64,
}

/// Job handler for users to pay for temporary access.
/// The beneficiary is passed explicitly in the arguments, as the contract proxies the call.
#[debug_job]
pub async fn handler(
    Context(ctx): Context<SecureRpcContext>,
    TangleArgs2(input): TangleArgs2<PayForAccessInput>,
) -> Result<TangleResult<()>> {
    if input.duration_secs == 0 {
        return Err(Error::InvalidJobInput(
            "Duration must be positive".to_string(),
        ));
    }

    // Payment verification is assumed to have happened in the calling contract.
    // The contract took the ERC20 payment before calling `SERVICES_CONTRACT.callJob`.

    let now = Utc::now();
    let expires_at = now + Duration::seconds(input.duration_secs as i64);
    let record = TemporaryAccessRecord {
        granted_at: now,
        expires_at,
    };

    // Grant access to the beneficiary specified in the input args
    ctx.firewall
        .grant_temporary_access(input.beneficiary.clone(), record)
        .await?;

    tracing::info!(account = %input.beneficiary, duration_secs = input.duration_secs, expires_at = %expires_at, "Granted temporary access via paid job");

    // Return empty result on success
    Ok(TangleResult(()))
}
