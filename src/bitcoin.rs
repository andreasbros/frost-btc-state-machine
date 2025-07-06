use crate::{errors::BitcoinError, ParticipantId};
use bitcoin::{
    absolute::LockTime,
    address::Address,
    secp256k1::{Message, Secp256k1},
    sighash::{self, Prevouts, SighashCache},
    transaction::Transaction,
    Amount, Network, OutPoint, PublicKey, ScriptBuf, TxIn, TxOut, Witness,
};
use frost_secp256k1_tr::{
    self as frost,
    keys::{KeyPackage, PublicKeyPackage},
    Ciphersuite, Signature,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Key generation data
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyData {
    pub threshold: u16,
    pub total: u16,
    pub public: PublicKeyPackage,
    pub key_packages: BTreeMap<ParticipantId, KeyPackage>,
}

impl KeyData {
    /// Bitcoin address for a given network: Bitcoin, Testnet, Testnet4, Signet, Regtest
    pub fn address(&self, network: Network) -> Result<Address, BitcoinError> {
        let secp_engine = Secp256k1::new();
        let verifying_key_bytes =
            self.public.verifying_key().serialize().map_err(|e| BitcoinError::Address(e.to_string()))?;

        let bitcoin_public_key =
            PublicKey::from_slice(&verifying_key_bytes).map_err(|e| BitcoinError::Address(e.to_string()))?;

        let (internal_key, _parity) = bitcoin_public_key.inner.x_only_public_key();
        let address = Address::p2tr(&secp_engine, internal_key, None, network);
        Ok(address)
    }
}

/// Create spend transaction
pub fn create_spend_transaction(
    utxo: OutPoint,
    to_address: Address,
    amount_sats: u64,
) -> Result<Transaction, BitcoinError> {
    let tx_in = TxIn {
        previous_output: utxo,
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: Witness::new(),
    };

    let tx_out = TxOut { value: Amount::from_sat(amount_sats), script_pubkey: to_address.script_pubkey() };

    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    Ok(transaction)
}

/// Compute signature hash for segwit / taproot inputs.
pub fn compute_sighash(
    transaction: &mut Transaction,
    verifying_key: &frost::VerifyingKey,
) -> Result<Message, BitcoinError> {
    let secp = Secp256k1::new();

    let verifying_key_bytes = verifying_key.serialize().map_err(|e| BitcoinError::Sighash(e.to_string()))?;
    let bitcoin_public_key =
        PublicKey::from_slice(&verifying_key_bytes).map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    let (internal_key, _parity) = bitcoin_public_key.inner.x_only_public_key();

    // TODO: We need the full previous transaction output. Replace with actual UTXO details for a real transaction.
    let prevouts = vec![TxOut {
        value: Amount::from_sat(0), // dummy value
        script_pubkey: Address::p2tr(&secp, internal_key, None, Network::Signet).script_pubkey(),
    }];

    let mut sighasher = SighashCache::new(transaction);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), sighash::TapSighashType::Default)
        .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    Ok(Message::from(sighash))
}

/// Finalise transaction
pub fn aggregate_and_finalize_tx(
    transaction: &mut Transaction,
    aggregated_signature: &Signature,
) -> Result<String, BitcoinError> {
    // Serialise the signature into the correct 64B format for a Taproot keypath spend.
    let sig_bytes = frost::Secp256K1Sha256TR::serialize_signature(aggregated_signature)
        .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    let mut witness = Witness::new();
    witness.push(sig_bytes);
    transaction.input[0].witness = witness;

    Ok(bitcoin::consensus::encode::serialize_hex(transaction))
}
