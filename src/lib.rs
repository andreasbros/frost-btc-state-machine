pub mod bitcoin;
pub mod errors;
pub mod signer;
mod transport;

use crate::{
    bitcoin::{create_spend_transaction, KeyData},
    signer::run_signing_ceremony,
};
use ::bitcoin::{Address, Network, OutPoint, Txid};
use anyhow::{Context, Error};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use frost::keys::{generate_with_dealer, IdentifierList, KeyPackage};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use std::{collections::BTreeMap, path::Path, str::FromStr};
use thiserror::Error;
use tokio::{fs::File, io::AsyncWriteExt};

/// An error related to ParticipantId.
#[derive(Debug, Error)]
pub enum ParticipantIdError {
    #[error("Invalid identifier: must be u16 non-zero")]
    InvalidIdentifier,
}

/// Identifier of participant in the network.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ParticipantId(#[serde_as(as = "Hex")] Vec<u8>);

impl From<Identifier> for ParticipantId {
    fn from(identifier: Identifier) -> Self {
        ParticipantId(identifier.serialize())
    }
}

impl TryFrom<u16> for ParticipantId {
    type Error = ParticipantIdError;

    fn try_from(id: u16) -> Result<Self, Self::Error> {
        let identifier = frost::Identifier::try_from(id).map_err(|_| ParticipantIdError::InvalidIdentifier)?;
        Ok(ParticipantId::from(identifier))
    }
}

impl<'a> TryFrom<&'a ParticipantId> for Identifier {
    type Error = ParticipantIdError;

    fn try_from(id: &'a ParticipantId) -> Result<Self, Self::Error> {
        Identifier::deserialize(&id.0).map_err(|_| ParticipantIdError::InvalidIdentifier)
    }
}

pub async fn generate_keys(threshold: u16, total: u16, output: &Path) -> Result<(), Error> {
    let rng = OsRng;
    let (shares, pubkey_package) = generate_with_dealer(total, threshold, IdentifierList::Default, rng)?;

    let key_packages = shares
        .into_iter()
        .map(|(identifier, secret_share)| {
            KeyPackage::try_from(secret_share).map(|key_package| (identifier.into(), key_package))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let data = KeyData { threshold, total, public: pubkey_package, key_packages };

    let json_bytes = serde_json::to_vec_pretty(&data).context("Failed to serialize data to JSON")?;

    let mut file = File::create(output).await.context("Failed to create output file")?;
    file.write_all(&json_bytes).await?;
    file.flush().await.context("Failed to flush data to file")?;

    Ok(())
}

/// Spend arguments.
pub struct SpendArgs<'a> {
    /// JSON file containing threshold key shares.
    pub keys_path: &'a Path,

    /// UTXO to spend from (txid:vout).
    pub utxo: &'a str,

    /// Destination address to send funds to.
    pub to: &'a str,

    /// Amount in satoshis to send.
    pub amount: u64,

    /// Bitcoin network to use.
    pub network: Network,

    /// URL of the Bitcoin Core RPC server.
    pub rpc_url: &'a str,

    /// RPC username for authentication (optional).
    pub rpc_user: Option<&'a str>,

    /// RPC password for authentication (optional).
    pub rpc_pass: Option<&'a str>,
}

/// Connects to a node, constructs, signs, and broadcasts a transaction.
pub async fn spend(args: SpendArgs<'_>) -> Result<Txid, Error> {
    let keys_json = tokio::fs::read_to_string(args.keys_path).await.context("Failed to read keys file")?;
    let key_data: KeyData = serde_json::from_str(&keys_json).context("Failed to parse keys JSON")?;

    let (txid_str, vout_str) = args.utxo.split_once(':').context("Invalid UTXO format. Expected txid:vout")?;
    let txid = Txid::from_str(txid_str).context("Invalid txid")?;
    let vout = vout_str.parse::<u32>().context("Invalid vout")?;
    let outpoint = OutPoint { txid, vout };

    let destination_address = Address::from_str(args.to)?.require_network(args.network)?;

    let auth = match (args.rpc_user, args.rpc_pass) {
        (Some(user), Some(pass)) => Auth::UserPass(user.to_string(), pass.to_string()),
        _ => Auth::None,
    };
    let rpc = Client::new(args.rpc_url, auth).context("Failed to create RPC client")?;

    println!("Fetching previous transaction details from the node...");
    let prev_tx =
        rpc.get_raw_transaction(&outpoint.txid, None).context("Failed to fetch previous transaction from node")?;
    let prevout_txout = prev_tx
        .output
        .get(outpoint.vout as usize)
        .cloned()
        .context("Vout index out of bounds for the previous transaction")?;
    let prevouts = &[prevout_txout];

    let transaction = create_spend_transaction(outpoint, destination_address, args.amount)?;

    println!("Starting FROST signing ceremony...");
    let signed_tx_hex = run_signing_ceremony(key_data, transaction, prevouts).await?;

    println!("Broadcasting signed transaction to the network...");
    let final_txid =
        rpc.send_raw_transaction(signed_tx_hex.as_str()).context("Failed to broadcast the final transaction")?;

    Ok(final_txid)
}
