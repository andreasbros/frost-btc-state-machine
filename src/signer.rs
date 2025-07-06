use crate::{
    bitcoin::{aggregate_and_finalize_tx, compute_sighash, KeyData},
    errors::SigningError,
    transport::{InMemoryTransport, Transport},
};
use bitcoin::{Transaction, TxOut};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::{
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, SigningPackage,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

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

/// coordinator for the FROST signing ceremony.
pub async fn run_signing_ceremony(
    key_data: KeyData,
    mut tx: Transaction,
    prev_tx_outs: &[TxOut],
) -> Result<String, SigningError> {
    let key_packages_by_identifier: BTreeMap<Identifier, _> = key_data
        .key_packages
        .into_iter()
        .map(|(p_id, key_pkg)| Identifier::try_from(&p_id).map(|id| (id, key_pkg)))
        .collect::<Result<_, _>>()
        .map_err(|e| SigningError::InternalError(e.to_string()))?;

    let participants: Vec<_> = key_packages_by_identifier.keys().cloned().collect();
    let transport = Arc::new(InMemoryTransport::new(participants));

    let mut signers = HashMap::new();
    for (id, key_pkg) in key_packages_by_identifier {
        signers.insert(id, FrostSigner::new(id, key_pkg, transport.clone()));
    }

    let session_id = rand::random::<SessionId>();
    let mut nonces: HashMap<Identifier, SigningNonces> = HashMap::new();

    // Round 1: All participants generate nonces and broadcast commitments.
    for (id, signer) in signers.iter_mut() {
        let signer_nonces = signer.initiate_signing(session_id, tx.clone()).await?;
        nonces.insert(*id, signer_nonces);
    }

    // Simulate message passing for commitments.
    while let Ok(Some((_recipient, msg))) = transport.receive().await {
        for signer in signers.values_mut() {
            signer.process_message(msg.clone()).await?;
        }
    }

    // The coordinator gathers all commitments to create the signing package.
    let mut all_commitments = BTreeMap::new();
    if let Some(first_signer) = signers.values().next() {
        if let SigningState::CollectingCommitments { commitments, .. } = &first_signer.state {
            all_commitments = commitments.clone();
        }
    }

    if all_commitments.len() < key_data.threshold as usize {
        return Err(SigningError::NotEnoughSigners);
    }

    let sighash_message = compute_sighash(&mut tx, prev_tx_outs)?;
    let signing_package = frost::SigningPackage::new(all_commitments, sighash_message.as_ref());

    // Round 2: Each participant creates and broadcasts their signature share.
    let mut all_shares = BTreeMap::new();
    for signer in signers.values() {
        let nonce = nonces
            .get(&signer.participant_id)
            .ok_or_else(|| SigningError::InternalError("Nonce not found for participant".to_string()))?;

        let share = frost::round2::sign(&signing_package, nonce, &signer.key_package)?;
        all_shares.insert(signer.participant_id, share);
        let msg = SigningMessage::SignatureShare(session_id, signer.participant_id, share);
        transport.broadcast(msg).await?;
    }

    // Aggregate signatures.
    let group_signature = frost::aggregate(&signing_package, &all_shares, &key_data.public)?;

    // Finalize transaction.
    let final_tx_hex = aggregate_and_finalize_tx(&mut tx, &group_signature)?;

    Ok(final_tx_hex)
}
