use bitcoin::{
    key::{TapTweak, UntweakedPublicKey},
    secp256k1::{self, Secp256k1},
};
use frost_demo::{bitcoin::compute_sighash, signer::run_signing_ceremony};
use k256::elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint};

mod utils;
use crate::utils::test::TestHarness;

/// Test FROST with BTC Schnorr compatibility: check that a 2 of 3 FROST signature verifies against the tweaked Taproot output key Q = P + H(P)*G
#[tokio::test]
async fn taproot_signature_roundtrip() {
    let harness = TestHarness::new(2, 3, None).await;
    let key_data = harness.key_data.clone();
    let (mut tx, prevouts) = harness.create_dummy_transaction(1);

    // Run the signing ceremony to get the aggregated Schnorr signature.
    let signed_tx = run_signing_ceremony(key_data.clone(), tx.clone(), &prevouts).await.unwrap();
    let signature = secp256k1::schnorr::Signature::from_slice(&signed_tx.input[0].witness[0])
        .expect("Witness should contain a 64-byte Schnorr signature");

    // Manually rebuild the tweaked public key (Q) and verify the signature against it.
    // This confirms the FROST output is compatible with Bitcoin's Taproot sighash scheme.
    let secp = Secp256k1::verification_only();

    // Get the internal public key (P) with an even Y coordinate.
    let mut p_affine = key_data.public.verifying_key().to_element().to_affine();
    if p_affine.y_is_odd().into() {
        p_affine = -p_affine;
    }
    let p_bytes = p_affine.to_encoded_point(true);
    let p_secp = secp256k1::PublicKey::from_slice(p_bytes.as_bytes()).unwrap();
    let (p_xonly, _) = p_secp.x_only_public_key();

    // Tweak P to get the output key Q, as per Taproot rules.
    let untweaked = UntweakedPublicKey::from(p_xonly);
    let (tweaked, _) = untweaked.tap_tweak(&secp, None);
    let q_xonly = tweaked.to_x_only_public_key();

    // Compute the sighash message that was actually signed.
    let msg = compute_sighash(&mut tx, &prevouts).expect("Sighash message should be computable");

    // Verify the signature against the correct message and tweaked key.
    secp.verify_schnorr(&signature, &msg, &q_xonly)
        .expect("Aggregated FROST signature must be valid for the tweaked Taproot key");
}
