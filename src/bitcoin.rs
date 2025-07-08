use crate::errors::BitcoinError;
use bitcoin::{
    absolute::LockTime,
    address::Address,
    secp256k1::Message,
    sighash::{self, Prevouts, SighashCache},
    transaction::Transaction,
    Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use frost_secp256k1_tr::{self as frost, Ciphersuite, Signature};
use std::str::FromStr;
use tracing::{debug, warn};

const DEFAULT_FEE: u64 = 500;
const DUST_P2TR: u64 = 330;

/// Create spend transaction
pub fn create_unsiged_transaction(
    utxo: OutPoint,
    utxo_to_spend: &TxOut,
    to_addr: Address,
    pay_amount_sat: Amount,
    change_addr: Address,
) -> Result<Transaction, BitcoinError> {
    let fee = Amount::from_sat(DEFAULT_FEE);
    let dust = Amount::from_sat(DUST_P2TR);
    let total_value = utxo_to_spend.value;
    if pay_amount_sat + fee > total_value {
        return Err(BitcoinError::Spend(format!(
            "amount ({pay_amount_sat}) + fee ({DEFAULT_FEE}) exceeds utxo value ({total_value})"
        )));
    }

    let tx_in =
        TxIn { previous_output: utxo, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() };

    let pay_out = TxOut { value: pay_amount_sat, script_pubkey: to_addr.script_pubkey() };

    let change_value = total_value - pay_amount_sat - fee;
    let mut outputs = vec![pay_out];

    if change_value >= dust {
        outputs.push(TxOut { value: change_value, script_pubkey: change_addr.script_pubkey() });
    } else {
        // deliberately leave the remainder as an extra fee
        warn!("change ({change_value} sat) below dust – adding it to the fee instead");
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

/// Creates a new RPC client for communicating with the Bitcoin node.
pub fn create_rpc_client(url: &str, user: Option<&str>, pass: Option<&str>) -> Result<Client, BitcoinError> {
    debug!("Creating Bitcoin client...");
    let auth = match (user, pass) {
        (Some(user), Some(pass)) => Auth::UserPass(user.to_string(), pass.to_string()),
        _ => Auth::None,
    };
    Client::new(url, auth).map_err(|e| BitcoinError::Utxo(e.to_string()))
}

/// Parses a UTXO string of the format "txid:vout" into an OutPoint.
pub fn parse_utxo(utxo_str: &str) -> Result<OutPoint, BitcoinError> {
    let (txid_str, vout_str) = utxo_str
        .split_once(':')
        .ok_or_else(|| BitcoinError::Utxo("Invalid UTXO format. Expected txid:vout".to_string()))?;
    let txid = Txid::from_str(txid_str).map_err(|_| BitcoinError::Utxo("Invalid txid".to_string()))?;
    let vout = vout_str.parse::<u32>().map_err(|_| BitcoinError::Utxo("Invalid vout".to_string()))?;
    Ok(OutPoint { txid, vout })
}

/// Fetches the specific transaction output (TxOut) we intend to spend.
pub fn fetch_utxo_to_spend(rpc_client: &Client, outpoint: &OutPoint) -> Result<TxOut, BitcoinError> {
    let prev_tx =
        rpc_client.get_raw_transaction(&outpoint.txid, None).map_err(|e| BitcoinError::Client(e.to_string()))?;

    prev_tx
        .output
        .get(outpoint.vout as usize)
        .cloned()
        .ok_or_else(|| BitcoinError::Utxo("Vout index out of bounds for the previous transaction".to_string()))
}

/// Broadcasts the signed transaction to the Bitcoin network.
pub fn broadcast_transaction(rpc_client: &Client, signed_tx: &bitcoin::Transaction) -> Result<Txid, BitcoinError> {
    rpc_client.send_raw_transaction(signed_tx).map_err(|e| BitcoinError::Client(e.to_string()))
}
