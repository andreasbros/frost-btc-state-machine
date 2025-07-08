use crate::{
    bitcoin::compute_sighash,
    errors::SigningError,
    keys::KeyData,
    transport::{InMemoryTransport, Transport},
};
use bitcoin::{Transaction, TxOut};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::{
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Ciphersuite, Identifier, SigningPackage,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::timeout;
use tracing::{debug, info, instrument, warn};

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

    #[instrument(skip(self, transaction), fields(participant_id = ?self.participant_id))]
    pub async fn initiate_signing_round(
        &mut self,
        session_id: SessionId,
        transaction: Transaction,
    ) -> Result<SigningNonces, SigningError> {
        if !matches!(self.state, SigningState::Idle) {
            return Err(SigningError::InvalidState("Signer is not in Idle state.".to_string()));
        }

        let deadline = Instant::now() + Duration::from_secs(60);
        self.state =
            SigningState::CollectingCommitments { session_id, transaction, commitments: BTreeMap::new(), deadline };

        let (nonces, commitments) = frost::round1::commit(self.key_package.signing_share(), &mut OsRng);

        debug!("Broadcasting nonce commitment.");
        let msg = SigningMessage::NonceCommitment(session_id, self.participant_id, Box::new(commitments));
        self.transport.broadcast(msg).await?;

        Ok(nonces)
    }

    #[instrument(skip(self, msg), fields(participant_id = ?self.participant_id))]
    pub async fn process_message(&mut self, msg: SigningMessage) -> Result<(), SigningError> {
        match &mut self.state {
            SigningState::CollectingCommitments { session_id, commitments, .. } => {
                if let SigningMessage::NonceCommitment(msg_session_id, sender, new_commitments) = msg {
                    if msg_session_id == *session_id {
                        debug!(from = ?sender, "Received nonce commitment.");
                        commitments.insert(sender, *new_commitments);

                        metrics::counter!("frost_messages_processed_total", "type" => "nonce_commitment").increment(1);
                    }
                }
            }
            SigningState::CollectingShares { session_id, shares, .. } => {
                if let SigningMessage::SignatureShare(msg_session_id, sender, share) = msg {
                    if msg_session_id == *session_id {
                        // TODO: need to verify received signature shares are valid to fail early and prevent certain attacks.
                        debug!(from = ?sender, "Received signature share.");
                        shares.insert(sender, share);

                        metrics::counter!("frost_messages_processed_total", "type" => "signature_share").increment(1);
                    }
                }
            }
            _ => {
                warn!("Received message in unexpected state.");
            }
        }
        Ok(())
    }
}

/// A coordinator function to perform a FROST signing ceremony for a Taproot input.
#[instrument(skip_all, fields(session_id))]
pub async fn run_signing_ceremony(
    key_data: KeyData,
    mut transaction: Transaction,
    prev_tx_outs: &[TxOut],
) -> Result<Transaction, SigningError> {
    let session_id = rand::random::<SessionId>();
    tracing::Span::current().record("session_id", session_id);

    info!("Starting signing ceremony.");

    let (mut signers, transport) = setup_signers(&key_data)?;

    // Round 1: All participants generate and broadcast commitments.
    let nonces = perform_round_one(&mut signers, session_id, transaction.clone()).await?;

    // Collect all broadcasted commitments.
    let commitments = collect_commitments(&transport, &mut signers).await?;
    if commitments.len() < key_data.threshold as usize {
        return Err(SigningError::NotEnoughSigners);
    }

    // Create the signing package containing the message to be signed.
    let signing_package = create_signing_package(&mut transaction, prev_tx_outs, commitments)?;

    // Round 2: Participants generate and broadcast signature shares.
    let shares = perform_round_two(&signers, &nonces, &signing_package)?;

    // Aggregate the shares into a final signature.
    let group_signature = frost::aggregate_with_tweak(&signing_package, &shares, &key_data.public, None)?;
    let signature_bytes = frost::Secp256K1Sha256TR::serialize_signature(&group_signature)?;
    debug!(aggregated_signature = %hex::encode(&signature_bytes), "Signature aggregation successful.");

    // Finalize the transaction by adding the witness.
    transaction.input[0].witness.push(signature_bytes);
    info!("Signing ceremony complete, transaction is finalized.");

    Ok(transaction)
}

/// Initializes the signers and the transport layer for communication.
fn setup_signers(
    key_data: &KeyData,
) -> Result<(HashMap<Identifier, FrostSigner>, Arc<InMemoryTransport>), SigningError> {
    let identifiers = key_data.key_packages.keys().cloned().collect();

    let transport = Arc::new(InMemoryTransport::new(identifiers));

    let signers: HashMap<_, _> = key_data
        .key_packages
        .iter()
        .map(|(identifier, key_package)| {
            let signer = FrostSigner::new(*identifier, key_package.clone(), transport.clone());
            (*identifier, signer)
        })
        .collect();

    Ok((signers, transport))
}

/// Executes Round 1 of the signing protocol for all participants.
async fn perform_round_one(
    signers: &mut HashMap<Identifier, FrostSigner>,
    session_id: SessionId,
    transaction: Transaction,
) -> Result<BTreeMap<Identifier, SigningNonces>, SigningError> {
    info!("Initiating Round 1: Generating and broadcasting commitments.");
    let mut nonces = BTreeMap::new();
    for (id, signer) in signers.iter_mut() {
        let signer_nonces = signer.initiate_signing_round(session_id, transaction.clone()).await?;
        nonces.insert(*id, signer_nonces);
    }
    Ok(nonces)
}

/// Waits for and processes messages to collect commitments.
async fn collect_commitments(
    transport: &Arc<InMemoryTransport>,
    signers: &mut HashMap<Identifier, FrostSigner>,
) -> Result<BTreeMap<Identifier, SigningCommitments>, SigningError> {
    info!("Collecting nonce commitments from all participants.");

    // Get the deadline that was set during round one.
    let deadline = signers
        .values()
        .find_map(|s| match &s.state {
            SigningState::CollectingCommitments { deadline, .. } => Some(*deadline),
            _ => None,
        })
        .ok_or_else(|| {
            SigningError::InvalidState("Cannot collect commitments: signers are not in the correct state.".to_string())
        })?;

    // Loop until the messages are empty or the deadline is reached.
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(SigningError::Timeout("Timed out while waiting for nonce commitments.".to_string()));
        }
        let remaining_time = deadline - now;

        match timeout(remaining_time, transport.receive()).await {
            Err(_) => {
                warn!("Timed out waiting for a commitment from a participant.");
                return Err(SigningError::Timeout("Timed out while waiting for nonce commitments.".to_string()));
            }
            Ok(receive_result) => match receive_result {
                Ok(Some((_recipient, message))) => {
                    for signer in signers.values_mut() {
                        signer.process_message(message.clone()).await?;
                    }
                }
                // The transport channel was closed gracefully, meaning no more messages.
                Ok(None) => {
                    info!("Transport channel closed. Proceeding with collected commitments.");
                    break;
                }
                // The transport returned an error.
                Err(e) => {
                    warn!(error = ?e, "Error receiving from transport. Breaking collection loop.");
                    break;
                }
            },
        }
    }

    // Extract and return the collected commitments from any signer's state.
    signers
        .values()
        .find_map(|s| match &s.state {
            SigningState::CollectingCommitments { commitments, .. } => Some(commitments.clone()),
            _ => None,
        })
        .ok_or_else(|| SigningError::InternalError("Could not retrieve commitments.".to_string()))
}

/// Creates the signing package, which includes the message to be signed (sighash).
fn create_signing_package(
    transaction: &mut Transaction,
    prev_tx_outs: &[TxOut],
    commitments: BTreeMap<Identifier, SigningCommitments>,
) -> Result<SigningPackage, SigningError> {
    let sighash = compute_sighash(transaction, prev_tx_outs)?;
    debug!(
        sighash = %hex::encode(sighash.as_ref()),
        "Computed BIP-341 message digest for signing package."
    );
    Ok(SigningPackage::new(commitments, sighash.as_ref()))
}

/// Executes Round 2 of the signing protocol for all participants.
fn perform_round_two(
    signers: &HashMap<Identifier, FrostSigner>,
    nonces: &BTreeMap<Identifier, SigningNonces>,
    signing_package: &SigningPackage,
) -> Result<BTreeMap<Identifier, SignatureShare>, SigningError> {
    info!("Initiating Round 2: Generating signature shares.");
    let mut shares = BTreeMap::new();
    for signer in signers.values() {
        let nonce = &nonces[&signer.participant_id];
        let share = frost::round2::sign_with_tweak(signing_package, nonce, &signer.key_package, None)?;
        shares.insert(signer.participant_id, share);
    }
    Ok(shares)
}
