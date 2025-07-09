use crate::{
    bitcoin::compute_sighash,
    errors::SigningError,
    keys::KeyData,
    transport::{InMemoryTransport, Transport},
};
use bitcoin::{Transaction, TxOut};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::{Ciphersuite, Identifier, SigningPackage};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::time::timeout;
use tracing::{debug, info, instrument, warn};

pub type SessionId = u64;

/// Message transmitted between participants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    NonceCommitment(SessionId, Identifier, Box<frost::round1::SigningCommitments>),
    SignatureShare(SessionId, Identifier, frost::round2::SignatureShare),
}

/// FROST state machine states
#[derive(Debug, Clone)]
pub enum SigningState {
    /// Idle state
    Idle,

    /// Round 1: All participants generate and broadcast commitments.
    CollectingCommitments {
        session_id: SessionId,
        transaction: Transaction,
        commitments: BTreeMap<Identifier, frost::round1::SigningCommitments>,
        deadline: Instant,
    },

    /// Round 2: Participants generate and broadcast signature shares.
    CollectingShares {
        session_id: SessionId,
        signing_package: SigningPackage,
        shares: BTreeMap<Identifier, frost::round2::SignatureShare>,
        deadline: Instant,
    },

    /// Finalize the transaction
    Complete { signed_transaction: Transaction },

    /// Failed state
    Failed { error: SigningError },
}

/// FROST Signer
#[derive(Clone)]
pub struct FrostSigner {
    pub participant_id: Identifier,
    pub key_package: frost::keys::KeyPackage,
    state: Arc<Mutex<SigningState>>,
    transport: Arc<dyn Transport<Msg = SigningMessage>>,
}

impl FrostSigner {
    pub fn new(
        participant_id: Identifier,
        key_package: frost::keys::KeyPackage,
        transport: Arc<dyn Transport<Msg = SigningMessage>>,
    ) -> Self {
        Self { participant_id, key_package, state: Arc::new(Mutex::new(SigningState::Idle)), transport }
    }

    pub fn get_state(&self) -> Result<SigningState, SigningError> {
        self.state
            .lock()
            .map_err(|e| SigningError::InternalError(format!("Failed to lock state mutex: {e}")))
            .map(|s| s.clone())
    }

    /// Start round 1
    #[instrument(skip(self, transaction), fields(participant_id = ?self.participant_id))]
    pub async fn initiate_signing_round(
        &self,
        session_id: SessionId,
        transaction: Transaction,
    ) -> Result<frost::round1::SigningNonces, SigningError> {
        let (nonces, commitments) = {
            let mut state = self
                .state
                .lock()
                .map_err(|e| SigningError::InternalError(format!("Failed to lock state mutex: {e}")))?;

            if !matches!(*state, SigningState::Idle) {
                return Err(SigningError::InvalidState("Signer is not in Idle state.".to_string()));
            }

            let deadline = Instant::now() + Duration::from_secs(60);
            *state =
                SigningState::CollectingCommitments { session_id, transaction, commitments: BTreeMap::new(), deadline };

            frost::round1::commit(self.key_package.signing_share(), &mut OsRng)
        };

        debug!("Broadcasting nonce commitment.");
        let msg = SigningMessage::NonceCommitment(session_id, self.participant_id, Box::new(commitments));
        self.transport.broadcast(msg).await?;

        Ok(nonces)
    }

    /// Start round 2
    #[instrument(skip(self, signing_package), fields(participant_id = ?self.participant_id))]
    pub fn advance_to_sharing_round(&self, signing_package: SigningPackage) -> Result<(), SigningError> {
        let mut state = self.state.lock().map_err(|e| SigningError::InternalError(e.to_string()))?;

        match state.deref_mut() {
            SigningState::CollectingCommitments { session_id, .. } => {
                debug!("Transitioning to CollectingShares state.");
                *state = SigningState::CollectingShares {
                    session_id: *session_id,
                    signing_package,
                    shares: BTreeMap::new(),
                    deadline: Instant::now() + Duration::from_secs(60),
                };
                Ok(())
            }
            s => Err(SigningError::InvalidState(format!("Cannot advance to sharing round from state {s:?}"))),
        }
    }

    /// Broadcast signature shares.
    #[instrument(skip(self, nonces), fields(participant_id = ?self.participant_id))]
    pub async fn sign_and_broadcast_share(&self, nonces: &frost::round1::SigningNonces) -> Result<(), SigningError> {
        let (share, session_id) = {
            let state = self.state.lock().map_err(|e| SigningError::InternalError(e.to_string()))?;
            match &*state {
                SigningState::CollectingShares { signing_package, session_id, .. } => {
                    let share = frost::round2::sign_with_tweak(signing_package, nonces, &self.key_package, None)?;
                    (share, *session_id)
                }
                s => return Err(SigningError::InvalidState(format!("Cannot sign share in state {s:?}"))),
            }
        };

        let msg = SigningMessage::SignatureShare(session_id, self.participant_id, share);
        self.transport.broadcast(msg).await?;
        Ok(())
    }

    /// Finalize the transaction
    #[instrument(skip(self, signed_transaction), fields(participant_id = ?self.participant_id))]
    pub fn complete_signing(&self, signed_transaction: Transaction) {
        let mut state = self.state.lock().unwrap();
        if !matches!(*state, SigningState::CollectingShares { .. }) {
            warn!("Completing signature from unexpected state.");
        }
        *state = SigningState::Complete { signed_transaction };
    }

    /// Process messages from other participants.
    #[instrument(skip(self, msg), fields(participant_id = ?self.participant_id))]
    pub async fn process_message(&self, msg: SigningMessage) -> Result<(), SigningError> {
        let mut state =
            self.state.lock().map_err(|e| SigningError::InternalError(format!("Failed to lock state mutex: {e}")))?;

        match state.deref_mut() {
            SigningState::CollectingCommitments { session_id, commitments, .. } => {
                if let SigningMessage::NonceCommitment(msg_session_id, sender, new_commitments) = msg {
                    if msg_session_id == *session_id {
                        debug!(from = ?sender, "Received nonce commitment.");
                        commitments.insert(sender, *new_commitments);
                    }
                }
            }
            SigningState::CollectingShares { session_id, shares, .. } => {
                if let SigningMessage::SignatureShare(msg_session_id, sender, share) = msg {
                    if msg_session_id == *session_id {
                        // TODO: need to verify received signature shares are valid to fail early and prevent certain attacks.
                        debug!(from = ?sender, "Received signature share.");
                        shares.insert(sender, share);
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

    let (signers, transport) = setup_signers(&key_data)?;

    // Round 1: All participants generate and broadcast commitments.
    let nonces = perform_round_one(&signers, session_id, transaction.clone()).await?;
    let commitments = collect_commitments(transport.clone(), &signers).await?;
    if commitments.len() < key_data.threshold as usize {
        return Err(SigningError::NotEnoughSigners);
    }
    let signing_package = create_signing_package(&mut transaction, prev_tx_outs, commitments)?;

    // Transition signers to Round 2
    for signer in signers.values() {
        signer.advance_to_sharing_round(signing_package.clone())?;
    }

    // Round 2: Participants generate and broadcast signature shares.
    perform_round_two(&signers, &nonces).await?;
    let shares = collect_shares(transport, &signers).await?;
    if shares.len() < key_data.threshold as usize {
        return Err(SigningError::NotEnoughSigners);
    }

    // Aggregate the shares into a final signature.
    let group_signature = frost::aggregate_with_tweak(&signing_package, &shares, &key_data.public, None)?;
    let signature_bytes = frost::Secp256K1Sha256TR::serialize_signature(&group_signature)?;
    debug!(aggregated_signature = %hex::encode(&signature_bytes), "Signature aggregation successful.");

    // Finalize the transaction
    transaction.input[0].witness.push(signature_bytes);

    // Transition signers to complete state
    for signer in signers.values() {
        signer.complete_signing(transaction.clone());
    }

    info!("Signing ceremony complete, transaction is finalized.");
    Ok(transaction)
}

/// Initializes the signers and the transport layer for communication.
pub fn setup_signers(
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
    signers: &HashMap<Identifier, FrostSigner>,
    session_id: SessionId,
    transaction: Transaction,
) -> Result<BTreeMap<Identifier, frost::round1::SigningNonces>, SigningError> {
    info!("Initiating Round 1: Generating and broadcasting commitments.");
    let mut nonces = BTreeMap::new();
    for (id, signer) in signers.iter() {
        let signer_nonces = signer.initiate_signing_round(session_id, transaction.clone()).await?;
        nonces.insert(*id, signer_nonces);
    }
    Ok(nonces)
}

/// Waits for and processes messages to collect commitments.
async fn collect_commitments(
    transport: Arc<InMemoryTransport>,
    signers: &HashMap<Identifier, FrostSigner>,
) -> Result<BTreeMap<Identifier, frost::round1::SigningCommitments>, SigningError> {
    info!("Collecting nonce commitments from all participants.");

    let deadline = signers
        .values()
        .find_map(|s| match s.get_state().ok()? {
            SigningState::CollectingCommitments { deadline, .. } => Some(deadline),
            _ => None,
        })
        .ok_or_else(|| SigningError::InvalidState("Signers not in commitment collection state.".to_string()))?;

    // Drain the message queue until the deadline is hit or the queue is empty
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break; // Timeout is handled by extracting whatever we have below
        }
        let remaining_time = deadline - now;

        match timeout(remaining_time, transport.receive()).await {
            Ok(Ok(Some((_, message)))) => {
                for signer in signers.values() {
                    signer.process_message(message.clone()).await?;
                }
            }
            Ok(Ok(None)) | Err(_) => {
                // Channel closed or timeout, break and process what was received
                break;
            }
            Ok(Err(e)) => return Err(e.into()), // Transport error
        }
    }

    // Extract the collected commitments from any signer (they should all be in sync)
    signers
        .values()
        .find_map(|s| {
            if let Ok(SigningState::CollectingCommitments { commitments, .. }) = s.get_state() {
                Some(commitments)
            } else {
                None
            }
        })
        .ok_or_else(|| SigningError::InternalError("Could not retrieve commitments.".to_string()))
}

/// Creates the signing package, which includes the message to be signed (sighash).
fn create_signing_package(
    transaction: &mut Transaction,
    prev_tx_outs: &[TxOut],
    commitments: BTreeMap<Identifier, frost::round1::SigningCommitments>,
) -> Result<SigningPackage, SigningError> {
    let sighash = compute_sighash(transaction, prev_tx_outs)?;
    debug!(
        sighash = %hex::encode(sighash.as_ref()),
        "Computed BIP-341 message digest for signing package."
    );
    Ok(SigningPackage::new(commitments, sighash.as_ref()))
}

/// Executes Round 2 of the signing protocol for all participants.
async fn perform_round_two(
    signers: &HashMap<Identifier, FrostSigner>,
    nonces: &BTreeMap<Identifier, frost::round1::SigningNonces>,
) -> Result<(), SigningError> {
    info!("Initiating Round 2: Generating and broadcasting signature shares.");
    for signer in signers.values() {
        let nonce = &nonces[&signer.participant_id];
        signer.sign_and_broadcast_share(nonce).await?;
    }
    Ok(())
}

/// Waits for and processes signature shares.
async fn collect_shares(
    transport: Arc<InMemoryTransport>,
    signers: &HashMap<Identifier, FrostSigner>,
) -> Result<BTreeMap<Identifier, frost::round2::SignatureShare>, SigningError> {
    info!("Collecting signature shares from all participants.");

    let deadline = signers
        .values()
        .find_map(|s| match s.get_state().ok()? {
            SigningState::CollectingShares { deadline, .. } => Some(deadline),
            _ => None,
        })
        .ok_or_else(|| SigningError::InvalidState("Signers not in share collection state.".to_string()))?;

    // Drain the message queue until the deadline is hit or the queue is empty
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining_time = deadline - now;

        match timeout(remaining_time, transport.receive()).await {
            Ok(Ok(Some((_, message)))) => {
                for signer in signers.values() {
                    signer.process_message(message.clone()).await?;
                }
            }
            // Channel closed or timeout, break and process what was received
            Ok(Ok(None)) | Err(_) => {
                break;
            }
            // Transport error
            Ok(Err(e)) => return Err(e.into()),
        }
    }

    // Extract the collected shares from any signer
    signers
        .values()
        .find_map(|s| {
            if let Ok(SigningState::CollectingShares { shares, .. }) = s.get_state() {
                Some(shares)
            } else {
                None
            }
        })
        .ok_or_else(|| SigningError::InternalError("Could not retrieve shares.".to_string()))
}
