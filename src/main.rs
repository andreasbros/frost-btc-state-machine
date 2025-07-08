use anyhow::{Context, Error};
use bitcoin::Network;
use clap::{Parser, Subcommand, ValueEnum};
use frost_demo::{generate_keys, keys::KeyData, spend, SpendArgs};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

/// The default public RPC endpoint for the Bitcoin (https://signet-rpc.publicnode.com, https://bitcoin-testnet-rpc.publicnode.com)
const DEFAULT_BITCOIN_CORE_RPC_URL: &str = "https://bitcoin-testnet-rpc.publicnode.com";

#[derive(Parser)]
#[command(name = "frost-demo", about = "FROST BTC Taproot threshold signing demo")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate threshold key shares.
    Keygen {
        /// Threshold number of signers.
        #[arg(long)]
        threshold: u16,

        /// Total number of parties.
        #[arg(long)]
        parties: u16,

        /// Output file for key shares (JSON).
        #[arg(long)]
        output: PathBuf,
    },

    /// Derives and prints the group address for a given network to be funded.
    GroupAddress {
        /// JSON file containing threshold key shares.
        #[arg(long)]
        keys: PathBuf,

        /// Bitcoin network to derive the address for.
        #[arg(long, value_enum, default_value_t = CliNetwork::Signet)]
        network: CliNetwork,
    },

    /// Spend from a threshold address
    Spend {
        /// JSON file containing threshold key shares.
        #[arg(long)]
        keys: PathBuf,

        /// UTXO to spend from (txid:vout).
        #[arg(long)]
        utxo: String,

        /// Destination address to send funds to.
        #[arg(long)]
        to: String,

        /// Amount in satoshis to send.
        #[arg(long)]
        amount: u64,

        /// Bitcoin network to use.
        #[arg(long, value_enum, default_value_t = CliNetwork::Signet)]
        network: CliNetwork,

        /// URL of the Bitcoin Core RPC server.
        #[arg(long, default_value = DEFAULT_BITCOIN_CORE_RPC_URL)]
        rpc_url: String,

        /// RPC username for authentication (optional).
        #[arg(long)]
        rpc_user: Option<String>,

        /// RPC password for authentication (optional).
        #[arg(long)]
        rpc_pass: Option<String>,
    },
}

/// Bitcoin network to use.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliNetwork {
    /// Bitcoin mainnet.
    Bitcoin,

    /// Bitcoin testnet.
    Testnet,

    /// Bitcoin testnet4.
    Testnet4,

    /// Bitcoin signet.
    Signet,

    /// Bitcoin regtest.
    Regtest,
}

impl From<CliNetwork> for Network {
    fn from(network: CliNetwork) -> Self {
        match network {
            CliNetwork::Bitcoin => Network::Bitcoin,
            CliNetwork::Testnet => Network::Testnet,
            CliNetwork::Testnet4 => Network::Testnet4,
            CliNetwork::Signet => Network::Signet,
            CliNetwork::Regtest => Network::Regtest,
        }
    }
}

// Setup metrics recorder to export metrics to Prometheus
fn setup_metrics_recorder() {
    let _ =
        metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder().context("failed to install recorder");
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let filter = EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).without_time().init();

    setup_metrics_recorder();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen { threshold, parties, output } => {
            info!("Generating {threshold} of {parties} threshold keys...");
            generate_keys(*threshold, *parties, output.as_path()).await?;
            info!("Keys saved to {output:?}");
        }

        Commands::GroupAddress { keys, network } => {
            let btc_network: Network = (*network).into();

            let keys_json = std::fs::read_to_string(keys).context("Failed to read keys file")?;
            let key_data: KeyData = serde_json::from_str(&keys_json).context("Failed to parse keys JSON")?;

            let address = key_data.address(btc_network).context("Failed to derive address from key data")?;

            info!("Group address for '{btc_network}': {address}");
        }

        Commands::Spend { keys, utxo, to, amount, network, rpc_url, rpc_user, rpc_pass } => {
            info!("Spending {amount} sats to {to} on the {network:?} network...");

            let args = SpendArgs {
                keys_path: keys,
                utxo,
                to,
                amount: *amount,
                network: (*network).into(),
                rpc_url,
                rpc_user: rpc_user.as_deref(),
                rpc_pass: rpc_pass.as_deref(),
            };
            let tx_id = spend(args).await?;

            info!("Transaction signed and broadcasted!");
            info!("TxID: {tx_id}");
        }
    }

    Ok(())
}
