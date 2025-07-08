pub mod bitcoin;
pub mod errors;
pub mod keys;
pub mod signer;
mod transport;

use crate::{
    bitcoin::{broadcast_transaction, create_rpc_client, create_unsiged_transaction, fetch_utxo_to_spend, parse_utxo},
    keys::load_key_data,
    signer::run_signing_ceremony,
};
use ::bitcoin::{Address, Amount, Network, Txid};
use anyhow::{Context, Error};
use frost::keys::{generate_with_dealer, IdentifierList, KeyPackage};
use frost_secp256k1_tr as frost;
use keys::KeyData;
use rand::rngs::OsRng;
use std::{collections::BTreeMap, path::Path, str::FromStr};
use tokio::{fs::File, io::AsyncWriteExt};
use tracing::info;

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

/// Constructs a spend transaction, signs it in MPC, and broadcasts it to the network.
pub async fn spend(args: SpendArgs<'_>) -> Result<Txid, Error> {
    let rpc_client = create_rpc_client(args.rpc_url, args.rpc_user, args.rpc_pass)?;
    let utxo = parse_utxo(args.utxo)?;
    let key_data = load_key_data(args.keys_path).await?;
    let destination_address = Address::from_str(args.to)?.require_network(args.network)?;
    let change_address = key_data.address(args.network).context("Failed to derive change address")?;

    let utxo_to_spend = fetch_utxo_to_spend(&rpc_client, &utxo)?;
    let unsigned_transaction = create_unsiged_transaction(
        utxo,
        &utxo_to_spend,
        destination_address,
        Amount::from_sat(args.amount),
        change_address,
    )?;

    info!("Starting FROST signing ceremony...");
    let signed_tx = run_signing_ceremony(key_data, unsigned_transaction, &[utxo_to_spend]).await?;

    info!("Broadcasting signed transaction to the network...");
    let final_txid = broadcast_transaction(&rpc_client, &signed_tx)?;

    Ok(final_txid)
}

/// Generate threshold key shares (trusted dealer) and writes to the output file.
pub async fn generate_keys(threshold: u16, total: u16, output: &Path) -> Result<(), Error> {
    let rng = OsRng;
    let (shares, pubkey_package) = generate_with_dealer(total, threshold, IdentifierList::Default, rng)?;

    let key_packages = shares
        .into_iter()
        .map(|(identifier, secret_share)| {
            KeyPackage::try_from(secret_share).map(|key_package| (identifier, key_package))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let data = KeyData { threshold, total, public: pubkey_package, key_packages };
    let json_bytes = serde_json::to_vec_pretty(&data).context("Failed to serialize data to JSON")?;

    let mut file = File::create(output).await.context("Failed to create output file")?;
    file.write_all(&json_bytes).await?;
    file.flush().await.context("Failed to flush data to file")?;

    Ok(())
}
