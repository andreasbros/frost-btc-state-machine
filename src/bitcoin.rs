use crate::{errors::BitcoinError, ParticipantId};
use bitcoin::{absolute::LockTime, address::Address, secp256k1::{Message, Secp256k1}, sighash::{self, Prevouts, SighashCache}, transaction::Transaction, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, TxIn, TxOut, Witness};
use frost_secp256k1_tr::{
    self as frost,
    keys::{KeyPackage, PublicKeyPackage},
    Ciphersuite, Signature,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;

const DEFAULT_FEE: u64 = 500;
const DUST_P2TR: u64 = 330;

/// Key generation data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyData {
    pub threshold: u16,
    pub total: u16,
    pub public: PublicKeyPackage,
    pub key_packages: BTreeMap<ParticipantId, KeyPackage>,
}

impl KeyData {
    /// Derive bitcoin group address for a given network: Bitcoin, Testnet, Testnet4, Signet, Regtest
    pub fn address(&self, network: Network) -> Result<Address, BitcoinError> {
        let secp_engine = Secp256k1::new();

        // g the FROST group verifying key.
        let group_verifying_key = self.public.verifying_key();
        let mut affine_point = group_verifying_key.to_element().to_affine();

        // for a taproo keypath spend, the internal public key must have an even
        // y coordinate. If it's odd, we must use its negation?
        if affine_point.y_is_odd().into() {
            affine_point = -affine_point;
        }

        // serialize the potential internal key to a compressed public key format
        let pk_bytes = affine_point.to_encoded_point(true);
        let bitcoin_public_key = PublicKey::from_slice(pk_bytes.as_bytes())
            .map_err(|e| BitcoinError::Address(e.to_string()))?;

        // get the x only public key from the inner secp256k1 key
        let (x_only_pk, _parity) = bitcoin_public_key.inner.x_only_public_key();
        let untweaked_pk = UntweakedPublicKey::from(x_only_pk);

        // tweak the key for a key-path-only spend as per BIP-341.
        // the output key Q = P + H(P)G. The bitcoin library handles this.
        // We pass None for the merkle root.
        let (tweaked_pk, _tweak_parity) = untweaked_pk.tap_tweak(&secp_engine, None);
        
        // create the P2TR address from the final, tweaked internal key.
        let address = Address::p2tr(&secp_engine, untweaked_pk, None, network);
        Ok(address)
    }
}

/// Create spend transaction
pub fn create_spend_transaction(
    utxo: OutPoint,
    utxo_value_sat: u64,
    to_addr: Address,
    pay_amount_sat: u64,
    change_addr: Address,
) -> Result<Transaction, BitcoinError> {
    
    if pay_amount_sat + DEFAULT_FEE > utxo_value_sat {
        return Err(BitcoinError::Spend(format!(
            "amount ({pay_amount_sat}) + fee ({DEFAULT_FEE}) exceeds utxo value ({utxo_value_sat})"
        )));
    }

    let tx_in = TxIn {
        previous_output: utxo,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };

    // first output - real payment
    let pay_out = TxOut {
        value: Amount::from_sat(pay_amount_sat),
        script_pubkey: to_addr.script_pubkey(),
    };

    // change (if any)
    let change_value = utxo_value_sat - pay_amount_sat - DEFAULT_FEE;
    let mut outputs = vec![pay_out];

    if change_value >= DUST_P2TR {
        outputs.push(TxOut {
            value: Amount::from_sat(change_value),
            script_pubkey: change_addr.script_pubkey(),
        });
    } else {
        // otherwise we deliberately leave the remainder as an extra fee
        println!(
            "change ({change_value} sat) below dust – adding it to the fee instead"
        );
    }
    
    Ok(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: outputs,
    })
}

/// Compute signature hash for segwit / taproot inputs.
pub fn compute_sighash(tx: &mut Transaction, prev_tx_outs: &[TxOut]) -> Result<Message, BitcoinError> {
    let mut sighasher = SighashCache::new(tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &Prevouts::All(prev_tx_outs), sighash::TapSighashType::Default)
        .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    Ok(Message::from(sighash))
}

/// Finalise transaction
pub fn aggregate_and_finalize_tx(
    tx: &mut Transaction,
    aggregated_signature: &Signature,
) -> Result<Transaction, BitcoinError> {
    // Serialise the signature into the correct 64B format for a Taproot keypath spend.
    let sig_bytes = frost::Secp256K1Sha256TR::serialize_signature(aggregated_signature)
        .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    let mut witness = Witness::new();
    witness.push(sig_bytes);
    tx.input[0].witness = witness;

    Ok(tx.clone())
}
