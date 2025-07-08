use bitcoin::{Address, Amount, Network, OutPoint,  TapTweakHash, TxOut};
use bitcoin::{secp256k1::{self, Secp256k1, PublicKey as SecpPub}};
use frost_demo::{
    bitcoin::{create_spend_transaction, KeyData},
    generate_keys,
    signer::run_signing_ceremony,
};
use std::str::FromStr;
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use tempfile::NamedTempFile;
use tokio::fs;
use frost_demo::bitcoin::compute_sighash;

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

/// check that a 2 of 3 FROST signature verifies against the tweaked Taproot output key Q = P + H(P)*G
#[tokio::test]
async fn taproot_signature_roundtrip() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    generate_keys(2, 3, tmp.path()).await.unwrap();
    let kd: KeyData =
        serde_json::from_slice(&fs::read(tmp.path()).await.unwrap()).unwrap();
    
    // dummy 1-sat self-transfer (never broadcast)
    let outpoint = OutPoint::from_str(
        "0000000000000000000000000000000000000000000000000000000000000000:0"
    ).unwrap();
    let dest  = kd.address(Network::Signet).unwrap();
    let mut tx = create_spend_transaction(outpoint, dest, 1).unwrap();

    // prevout used for the sighash
    let prevouts = &[TxOut {
        value: Amount::from_sat(1),
        script_pubkey: kd.address(Network::Signet).unwrap().script_pubkey(),
    }];
    
    // run the signing ceremony
    let signed = run_signing_ceremony(kd.clone(), tx.clone(), prevouts).await.unwrap();
    let sig = secp256k1::schnorr::Signature::from_slice(&signed.input[0].witness[0])
        .expect("64-byte Schnorr signature");
    
    // rebuild Q with the same tap-tweak routine
    let secp = Secp256k1::verification_only();

    // internal key P (even-Y)
    let mut p_affine = kd.public.verifying_key().to_element().to_affine();
    if p_affine.y_is_odd().into() { p_affine = -p_affine; }
    let p_bytes = p_affine.to_encoded_point(true);
    let p_secp  = secp256k1::PublicKey::from_slice(p_bytes.as_bytes()).unwrap();
    let (p_xonly, _) = p_secp.x_only_public_key();

    // untweaked to tweaked
    let untweaked  = UntweakedPublicKey::from(p_xonly);
    let (tweaked, _) = untweaked.tap_tweak(&secp, None);
    let q_xonly = tweaked.to_x_only_public_key();
    
    // verify the aggregated signature
    let msg = compute_sighash(&mut tx, prevouts).expect("sighash Message");
    secp.verify_schnorr(&sig, &msg, &q_xonly)
        .expect("threshold signature must verify");
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

    // transaction data
    let outpoint = OutPoint::from_str("f2ba6014dd5598a2333b7d1553c932f7a9d7a22b704481da4a10fb0032e35f4b:0")
        .expect("Failed to parse outpoint");
    let to_address = Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        .expect("Failed to parse address");
    let amount = 10000;

    let transaction = create_spend_transaction(
        outpoint,
        to_address.require_network(Network::Signet).expect("Address network mismatch"),
        amount,
    )
    .expect("Failed to create transaction");

    // previous output for a valid sighash
    let prevout_amount = 50000;
    let group_address = key_data.address(Network::Signet).expect("Failed to get group address");
    let prevout_txout = TxOut { value: Amount::from_sat(prevout_amount), script_pubkey: group_address.script_pubkey() };
    let prevouts = &[prevout_txout];

    let result = run_signing_ceremony(key_data, transaction, prevouts).await;
    assert!(result.is_ok(), "Signing ceremony failed: {:?}", result.err());
    println!("Signed transaction: {:?}", result.unwrap());
}
