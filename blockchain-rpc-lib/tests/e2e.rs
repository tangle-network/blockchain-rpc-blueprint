use blueprint_sdk::Job;
use blueprint_sdk::tangle::layers::TangleLayer;
use blueprint_sdk::testing::tempfile;
use blueprint_sdk::testing::utils::setup_log;
use blueprint_sdk::testing::utils::tangle::TangleTestHarness;
use blueprint_sdk::tangle::serde::to_field;
use blockchain_rpc_blueprint_lib::{MyContext, say_hello};

// The number of nodes to spawn in the test
const N: usize = 1;

#[tokio::test]
async fn test_blueprint() -> color_eyre::Result<()> {
    setup_log();

    // Initialize test harness (node, keys, deployment)
    let temp_dir = tempfile::TempDir::new()?;
    let context = MyContext::new();
    let harness = TangleTestHarness::setup(temp_dir).await?;

    // Setup service with `N` nodes
    let (mut test_env, service_id, _) = harness.setup_services::<N>(false).await?;

    // Setup the node(s)
    test_env.initialize().await?;
    test_env.add_job(say_hello.layer(TangleLayer)).await;

    // Start the test environment. It is now ready to receive job calls.
    test_env.start(context).await?;

    // Submit the job call
    let job_inputs = vec![to_field(Some("Alice")).unwrap()];
    let job = harness.submit_job(service_id, 0, job_inputs).await?;

    let results = harness.wait_for_job_execution(service_id, job).await?;

    // Verify results match expected output
    let expected_outputs = vec![to_field("Hello, Alice!").unwrap()];
    harness.verify_job(&results, expected_outputs);

    assert_eq!(results.service_id, service_id);
    Ok(())
}
