use bitcoin::{Address, Network, OutPoint};
use frost_demo::{
    bitcoin::{create_spend_transaction, KeyData},
    generate_keys,
    signer::run_signing_ceremony,
};
use std::str::FromStr;
use tempfile::NamedTempFile;
use tokio::fs;

#[tokio::test]
async fn test_generate_keys_success() {
    let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
    let path = temp_file.path();

    generate_keys(2, 3, path).await.expect("Failed to generate keys");

    let file_content = fs::read_to_string(path).await.expect("Failed to read generated keys file");

    assert!(!file_content.is_empty(), "Generated keys file should not be empty");

    let data: KeyData = serde_json::from_str(&file_content).expect("JSON should deserialize");
    assert_eq!(data.key_packages.len(), 3);
    assert_eq!(data.threshold, 2);
}

#[tokio::test]
async fn test_full_signing_ceremony() {
    let threshold = 2;
    let parties = 3;
    let temp_file = NamedTempFile::new().unwrap();
    let keys_path = temp_file.path();

    generate_keys(threshold, parties, keys_path).await.unwrap();

    let keys_json = fs::read_to_string(keys_path).await.unwrap();
    let key_data: KeyData = serde_json::from_str(&keys_json).unwrap();

    // Dummy transaction data
    let outpoint = OutPoint::from_str("f2ba6014dd5598a2333b7d1553c932f7a9d7a22b704481da4a10fb0032e35f4b:0")
        .expect("Failed to parse outpoint");

    // Signet address ???
    let to_address = Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        .expect("Failed to parse address");

    let amount = 10000;

    // Signet address ???
    let transaction = create_spend_transaction(
        outpoint,
        to_address.require_network(Network::Signet).expect("Address network mismatch"),
        amount,
    )
    .expect("Failed to create transaction");

    let result = run_signing_ceremony(key_data, transaction).await;
    assert!(result.is_ok(), "Signing ceremony failed: {:?}", result.err());
    println!("Signed transaction: {}", result.unwrap());
}
