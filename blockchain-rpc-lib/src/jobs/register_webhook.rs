use crate::Result;
use crate::context::SecureRpcContext;
use crate::error::Error;
use blueprint_sdk::extract::Context;
use blueprint_sdk::macros::debug_job;
use blueprint_sdk::tangle::extract::{TangleArg, TangleResult};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterWebhookInput {
    pub url: String,
}

/// Job handler to register a new webhook URL for firewall event notifications.
#[debug_job]
pub async fn handler(
    Context(ctx): Context<SecureRpcContext>,
    TangleArg(input): TangleArg<RegisterWebhookInput>,
) -> Result<TangleResult<()>> {
    let url = Url::parse(&input.url)
        .map_err(|e| Error::InvalidJobInput(format!("Invalid URL: {}", e)))?;

    // Basic validation: Ensure it's HTTP/HTTPS
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(Error::InvalidJobInput(
            "Webhook URL must use http or https scheme".to_string(),
        ));
    }

    ctx.firewall.add_webhook(url).await?;

    tracing::info!(url = %input.url, "Registered new webhook");

    // Return empty result on success
    Ok(TangleResult(()))
}
