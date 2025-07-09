use frost_demo::{generate_keys, keys::load_key_data, signer::run_signing_ceremony};
use tempfile::NamedTempFile;

mod utils;
use crate::utils::test::TestHarness;

#[tokio::test]
async fn test_generate_keys_success() {
    let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
    let path = temp_file.path();

    generate_keys(2, 3, path, None).await.expect("Failed to generate keys");
    let keys = load_key_data(path).await.expect("Failed to load generated keys");
    assert_eq!(keys.key_packages.len(), 3);
    assert_eq!(keys.threshold, 2);
}

#[tokio::test]
async fn test_full_signing_ceremony() {
    let harness = TestHarness::new(2, 3, None).await;
    let key_data = harness.key_data.clone();
    let (tx, prevouts) = harness.create_dummy_transaction(1);

    let res = run_signing_ceremony(key_data, tx, &prevouts).await;

    assert!(res.is_ok(), "signing failed: {:?}", res.err());
}
