use blockchain_rpc_blueprint_lib::{MyContext, SAY_HELLO_JOB_ID, say_hello};
use blockchain_rpc_lib::config::ServiceConfig;
use blockchain_rpc_lib::context::SecureRpcContext;
use blockchain_rpc_lib::jobs;
use blockchain_rpc_lib::rpc::start_rpc_gateway;
use blueprint_sdk::Job;
use blueprint_sdk::Router;
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::crypto::sp_core::SpSr25519;
use blueprint_sdk::crypto::tangle_pair_signer::TanglePairSigner;
use blueprint_sdk::keystore::backends::Backend;
use blueprint_sdk::runner::BlueprintRunner;
use blueprint_sdk::runner::config::BlueprintEnvironment;
use blueprint_sdk::runner::tangle::config::TangleConfig;
use blueprint_sdk::tangle::consumer::TangleConsumer;
use blueprint_sdk::tangle::filters::MatchesServiceId;
use blueprint_sdk::tangle::layers::TangleLayer;
use blueprint_sdk::tangle::producer::TangleProducer;
use sp_core::sr25519::Pair as Sr25519Pair;
use std::sync::Arc;
use tower::filter::FilterLayer;
use tracing::error;
use tracing::info;
use tracing::level_filters::LevelFilter;

#[tokio::main]
async fn main() -> Result<(), Error> {
    color_eyre::install().expect("Failed to install color_eyre");
    configure_tracing("secure_rpc_gateway=debug,blueprint_sdk=info")?;

    info!("Loading Blueprint environment...");
    let env = BlueprintEnvironment::load()?;

    info!("Loading service configuration...");
    let service_config = ServiceConfig::load(env.config_dir().join("config.toml"))?;
    info!(?service_config, "Service configuration loaded");

    info!("Setting up Tangle signer...");
    let signer_key = env
        .keystore()
        .first_local::<Sr25519Pair>()
        .map_err(Into::<KeystoreError>::into)?;
    let pair = env
        .keystore()
        .get_secret::<Sr25519Pair>(&signer_key)
        .map_err(Into::<KeystoreError>::into)?;
    let signer = TanglePairSigner::new(pair.0);
    info!(signer_address = %signer.account_id(), "Tangle signer configured");

    info!("Connecting to Tangle client...");
    let client = env.tangle_client().await?;

    info!("Setting up Tangle producer...");
    let producer = TangleProducer::finalized_blocks(client.rpc_client.clone()).await?;

    info!("Setting up Tangle consumer...");
    let consumer = TangleConsumer::new(client.rpc_client.clone(), signer.clone());

    info!("Creating service context...");
    let context = Arc::new(SecureRpcContext::new(env.clone(), service_config).await?);

    info!("Starting RPC gateway in background...");
    let gateway_handle = tokio::spawn(start_rpc_gateway(context.clone()));

    info!("Building job router...");
    let router = Router::new()
        .route(
            jobs::ALLOW_ACCESS_JOB_ID,
            jobs::allow_access::handler.layer(TangleLayer),
        )
        .route(
            jobs::PAY_FOR_ACCESS_JOB_ID,
            jobs::pay_for_access::handler.layer(TangleLayer),
        )
        .route(
            jobs::REGISTER_WEBHOOK_JOB_ID,
            jobs::register_webhook::handler.layer(TangleLayer),
        )
        .with_context(context.clone());

    info!("Starting Blueprint runner...");
    BlueprintRunner::builder(TangleConfig::default(), env)
        .router(router)
        .producer(producer)
        .consumer(consumer)
        .run()
        .await?;

    info!("Blueprint runner finished. Waiting for gateway to shutdown...");
    // If the runner exits (e.g., due to error or signal), wait for the gateway to finish.
    let _ = gateway_handle.await;

    info!("Secure RPC Gateway finished.");
    Ok(())
}

pub fn setup_log() {
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::fmt::SubscriberBuilder::default()
        .without_time()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .finish()
        .try_init();
}
