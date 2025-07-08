use crate::{bitcoin::{aggregate_and_finalize_tx, compute_sighash, KeyData}, errors::SigningError, transport::{InMemoryTransport, Transport}, ParticipantId};
use bitcoin::{secp256k1, secp256k1::Secp256k1, Network, PublicKey as BtcPk, TapTweakHash, Transaction, TxOut};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::{round1::{SigningCommitments, SigningNonces}, round2::SignatureShare, Ciphersuite, Identifier, SigningPackage};
use k256::{
    Scalar,
    elliptic_curve::{bigint::U256, ops::Reduce},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use k256::elliptic_curve::bigint::Encoding;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use frost_secp256k1_tr::keys::Tweak;

pub type SessionId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    NonceCommitment(SessionId, Identifier, Box<SigningCommitments>),
    SignatureShare(SessionId, Identifier, SignatureShare),
}

#[derive(Debug)]
pub enum SigningState {
    Idle,
    CollectingCommitments {
        session_id: SessionId,
        transaction: Transaction,
        commitments: BTreeMap<Identifier, SigningCommitments>,
        deadline: Instant,
    },
    CollectingShares {
        session_id: SessionId,
        transaction: Transaction,
        signing_package: SigningPackage,
        shares: BTreeMap<Identifier, SignatureShare>,
        deadline: Instant,
    },
    Complete {
        signed_transaction: Transaction,
    },
    Failed {
        error: SigningError,
    },
}

pub struct FrostSigner {
    pub participant_id: Identifier,
    pub key_package: frost::keys::KeyPackage,
    state: SigningState,
    transport: Arc<dyn Transport<Msg = SigningMessage>>,
}

impl FrostSigner {
    pub fn new(
        participant_id: Identifier,
        key_package: frost::keys::KeyPackage,
        transport: Arc<dyn Transport<Msg = SigningMessage>>,
    ) -> Self {
        Self { participant_id, key_package, state: SigningState::Idle, transport }
    }

    /// Initiates round 1 of the signing ceremony:
    /// - coordinator should provide a unique session ID for the ceremony.
    /// - this function returns the secret nonces which must be stored by the coordinator and used in round 2.
    pub async fn initiate_signing(
        &mut self,
        session_id: SessionId,
        transaction: Transaction,
    ) -> Result<SigningNonces, SigningError> {
        if !matches!(self.state, SigningState::Idle) {
            return Err(SigningError::InvalidState("Not in Idle state to initiate signing".to_string()));
        }

        let deadline = Instant::now() + Duration::from_secs(60);

        self.state =
            SigningState::CollectingCommitments { session_id, transaction, commitments: BTreeMap::new(), deadline };

        let (nonces, commitments) = frost::round1::commit(self.key_package.signing_share(), &mut OsRng);

        let msg = SigningMessage::NonceCommitment(session_id, self.participant_id, Box::new(commitments));
        self.transport.broadcast(msg).await?;

        Ok(nonces)
    }

    pub async fn process_message(&mut self, msg: SigningMessage) -> Result<(), SigningError> {
        match &mut self.state {
            SigningState::CollectingCommitments { session_id, commitments, .. } => {
                if let SigningMessage::NonceCommitment(msg_session_id, sender, new_commitments) = msg {
                    if msg_session_id == *session_id {
                        commitments.insert(sender, *new_commitments);
                    }
                }
            }
            SigningState::CollectingShares { session_id, shares, .. } => {
                if let SigningMessage::SignatureShare(msg_session_id, sender, share) = msg {
                    if msg_session_id == *session_id {
                        // TODO: verify shares as they arrive.
                        shares.insert(sender, share);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// TODO: introduce logging and metrics!
fn dbg_hex(tag: &str, bytes: &[u8]) { println!("{tag}: {}", hex::encode(bytes)); }

/// Run a verbose FROST Taproot signing ceremony with diagnostics...
pub async fn run_signing_ceremony(
    key_data: KeyData,
    mut tx: Transaction,
    prev_tx_outs: &[TxOut],
) -> Result<Transaction, SigningError> {
    // map <ParticipantId to KeyPackage> transport
    let key_pkgs: BTreeMap<Identifier, _> = key_data.clone()
        .key_packages
        .into_iter()
        .map(|(pid, kp)| Identifier::try_from(&pid)
            .map(|id| (id, kp))
            .map_err(|e| SigningError::InternalError(e.to_string())))
        .collect::<Result<_, _>>()?;

    let transport = Arc::new(InMemoryTransport::new(key_pkgs.keys().copied().collect()));
    let mut signers: HashMap<_, _> = key_pkgs
        .into_iter()
        .map(|(id, kp)| (id, FrostSigner::new(id, kp, transport.clone())))
        .collect();

    // TapTweak diagnostics (raw hash fed to FROST)
    let secp   = Secp256k1::verification_only();
    let p_bytes = key_data.public.verifying_key().to_element().to_affine()
        .to_encoded_point(true);
    dbg_hex("P(compressed)", p_bytes.as_bytes());

    let (px, _) = bitcoin::PublicKey::from_slice(p_bytes.as_bytes())
        .unwrap()
        .inner
        .x_only_public_key();
    dbg_hex("Px", &px.serialize());

    let h = TapTweakHash::from_key_and_tweak(px, None);
    dbg_hex("h = H_TapTweak(Px)", h.as_ref());

    // purely diagnostic:
    let t_be: [u8; 32] =
        <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(h.as_ref()))
            .to_bytes()
            .into();
    dbg_hex("t (big-endian, diagnostic only)", &t_be);

    let q_xonly = UntweakedPublicKey::from(px).tap_tweak(&secp, None).0.to_inner();
    dbg_hex("Q (library)", &q_xonly.serialize());

    let script_pk = key_data.address(Network::Signet)?.script_pubkey();
    let q_addr = match script_pk.as_bytes() {
        [0x51, 32, rest @ ..] => rest,
        _ => return Err(SigningError::InternalError("unexpected script".into())),
    };
    dbg_hex("Q (address)", q_addr);
    if q_addr != q_xonly.serialize() {
        return Err(SigningError::InternalError("Tweaked key mismatch!".into()));
    }

    // round-1 commitments
    let session_id = rand::random::<SessionId>();
    let mut nonces = BTreeMap::new();
    for (id, s) in signers.iter_mut() {
        nonces.insert(*id, s.initiate_signing(session_id, tx.clone()).await?);
    }
    while let Ok(Some((_to, m))) = transport.receive().await {
        for s in signers.values_mut() { s.process_message(m.clone()).await?; }
    }
    let commitments = signers.values().find_map(|s| {
        if let SigningState::CollectingCommitments { commitments, .. } = &s.state {
            Some(commitments.clone())
        } else { None }
    }).unwrap();
    if commitments.len() < key_data.threshold as usize {
        return Err(SigningError::NotEnoughSigners);
    }

    // signing package (BIP-341 msg)
    let sighash = compute_sighash(&mut tx, prev_tx_outs)?;
    dbg_hex("BIP-341 Msg", sighash.as_ref());
    let pkg = SigningPackage::new(commitments, sighash.as_ref());

    // ── 4. round-2 shares (crate computes tweak internally) ────────
    let mut shares = BTreeMap::new();
    for s in signers.values() {
        let n = &nonces[&s.participant_id];
        let sh = frost::round2::sign_with_tweak(&pkg, n, &s.key_package, None)?;
        dbg_hex(&format!("share({:?})", s.participant_id), &sh.serialize());
        shares.insert(s.participant_id, sh);
    }

    // aggregate + verify
    let grp_sig = frost::aggregate_with_tweak(&pkg, &shares,
                                              &key_data.public, None)?;
    let mut sig_bytes = frost::Secp256K1Sha256TR::serialize_signature(&grp_sig)?;
    dbg_hex("Aggregated Sig (raw)", &sig_bytes);

    // verify each share against its own crate-tweaked key
    for (id, sh) in &shares {
        let pid = ParticipantId::from(*id);
        let tweaked_kp =
            key_data.key_packages[&pid].clone().tweak::<&[u8]>(None);   // ← type annotated
        let elem = tweaked_kp.verifying_share().to_element();
        let (px_s, _) =
            bitcoin::PublicKey::from_slice(elem.to_encoded_point(true).as_bytes())
                .unwrap()
                .inner
                .x_only_public_key();
        let q_i = UntweakedPublicKey::from(px_s).tap_tweak(&secp, None).0.to_inner();

        let mut sig64 = [0u8; 64];
        sig64[..32].copy_from_slice(&sig_bytes[..32]);
        sig64[32..].copy_from_slice(&sh.serialize());
        let ok = secp.verify_schnorr(
            &secp256k1::schnorr::Signature::from_slice(&sig64).unwrap(),
            &secp256k1::Message::from_slice(sighash.as_ref()).unwrap(),
            &q_i,
        ).is_ok();
        println!("### share verify {id:?} ok={ok}");
    }

    // verify aggregate
    let msg = secp256k1::Message::from_slice(sighash.as_ref()).unwrap();
    let mut sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
    let mut ok = secp.verify_schnorr(&sig, &msg, &q_xonly).is_ok();
    println!("verify attempt 1 ok={ok}");
    if !ok {
        let n = U256::from_be_hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        let (_, s_part) = sig_bytes.split_at_mut(32);
        let s_fix = n.wrapping_sub(&U256::from_be_slice(s_part)).to_be_bytes();
        s_part.copy_from_slice(&s_fix);
        sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
        ok = secp.verify_schnorr(&sig, &msg, &q_xonly).is_ok();
        println!("verify attempt 2 (n-s) ok={ok}");
    }
    if !ok {
        return Err(SigningError::InternalError("libsecp verify failed".into()));
    }
    dbg_hex("Aggregated Sig (final)", &sig_bytes);
    println!("libsecp verification succeeded");

    // final witness
    tx.input[0].witness.push(sig_bytes.to_vec());
    Ok(tx)
}
