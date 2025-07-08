use bitcoin::{
    key::{TapTweak, UntweakedPublicKey},
    secp256k1::{self, Secp256k1},
    Address, Amount, Network, OutPoint, TxOut,
};
use frost_demo::{
    bitcoin::{compute_sighash, create_unsiged_transaction},
    generate_keys,
    keys::KeyData,
    signer::run_signing_ceremony,
};
use k256::elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint};
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

/// check that a 2 of 3 FROST signature verifies against the tweaked Taproot output key Q = P + H(P)*G
#[tokio::test]
async fn taproot_signature_roundtrip() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    generate_keys(2, 3, tmp.path()).await.unwrap();
    let kd: KeyData = serde_json::from_slice(&fs::read(tmp.path()).await.unwrap()).unwrap();

    let change_addr = kd.address(Network::Signet).unwrap();

    // dummy 1-sat self-transfer (never broadcast)
    let outpoint = OutPoint::from_str("0000000000000000000000000000000000000000000000000000000000000000:0").unwrap();
    let utxo_value_sat = 50_000;
    let pay_amount_sat = 10_000;
    let txout = TxOut {
        value: Amount::from_sat(utxo_value_sat),
        script_pubkey: kd.address(Network::Signet).unwrap().script_pubkey(),
    };
    let prevouts = &[txout.clone()];
    let dest = kd.address(Network::Signet).unwrap();
    let mut tx =
        create_unsiged_transaction(outpoint, &txout, dest, Amount::from_sat(pay_amount_sat), change_addr).unwrap();

    // prevout used for the sighash

    // run the signing ceremony
    let signed = run_signing_ceremony(kd.clone(), tx.clone(), prevouts).await.unwrap();
    let sig =
        secp256k1::schnorr::Signature::from_slice(&signed.input[0].witness[0]).expect("64-byte Schnorr signature");

    // rebuild Q with the same tap-tweak routine
    let secp = Secp256k1::verification_only();

    // internal key P (even-Y)
    let mut p_affine = kd.public.verifying_key().to_element().to_affine();
    if p_affine.y_is_odd().into() {
        p_affine = -p_affine;
    }
    let p_bytes = p_affine.to_encoded_point(true);
    let p_secp = secp256k1::PublicKey::from_slice(p_bytes.as_bytes()).unwrap();
    let (p_xonly, _) = p_secp.x_only_public_key();

    // untweaked to tweaked
    let untweaked = UntweakedPublicKey::from(p_xonly);
    let (tweaked, _) = untweaked.tap_tweak(&secp, None);
    let q_xonly = tweaked.to_x_only_public_key();

    // verify the aggregated signature
    let msg = compute_sighash(&mut tx, prevouts).expect("sighash Message");
    secp.verify_schnorr(&sig, &msg, &q_xonly).expect("threshold signature must verify");
}

#[tokio::test]
async fn test_full_signing_ceremony() {
    let threshold = 2;
    let parties = 3;
    let tmp_keys = tempfile::NamedTempFile::new().unwrap();
    generate_keys(threshold, parties, tmp_keys.path()).await.unwrap();

    let keys_json = tokio::fs::read_to_string(tmp_keys.path()).await.unwrap();
    let key_data: KeyData = serde_json::from_str(&keys_json).unwrap();

    // fixed outpoint we pretend to spend
    let utxo = OutPoint::from_str("f2ba6014dd5598a2333b7d1553c932f7a9d7a22b704481da4a10fb0032e35f4b:0")
        .expect("parse outpoint");
    let utxo_value_sat = 50_000;
    let pay_amount_sat = 10_000;
    let txout = TxOut {
        value: Amount::from_sat(utxo_value_sat),
        script_pubkey: key_data.address(Network::Signet).unwrap().script_pubkey(),
    };

    // destination (any testnet P2TR will do)
    let to_addr = Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        .unwrap()
        .require_network(Network::Signet)
        .unwrap();

    // change goes back to the group address derived from the threshold key
    let change_addr = key_data.address(Network::Signet).unwrap();

    // build tx with change sent back
    let tx = create_unsiged_transaction(utxo, &txout, to_addr, Amount::from_sat(pay_amount_sat), change_addr.clone())
        .expect("create spend tx");

    // prevout slice needed for sighash calculation
    let prev_txout = TxOut {
        value: Amount::from_sat(utxo_value_sat),
        // that’s what the UTXO pays to
        script_pubkey: change_addr.script_pubkey(),
    };
    let prevouts = &[prev_txout];

    let res = run_signing_ceremony(key_data, tx, prevouts).await;
    assert!(res.is_ok(), "signing failed: {:?}", res.err());
    println!("signed tx = {:?}", res.unwrap());
}
