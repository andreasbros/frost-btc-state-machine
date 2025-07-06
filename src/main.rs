use anyhow::Error;
use clap::{Parser, Subcommand};
use frost_demo::{generate_keys, spend};
use std::path::PathBuf;

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
    },
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen { threshold, parties, output } => {
            println!("Generating {threshold} of {parties} threshold keys...");
            generate_keys(*threshold, *parties, output.as_path()).await?;
            println!("Keys saved to {output:?}");
        }

        Commands::Spend { keys, utxo, to, amount } => {
            println!("Spending {amount} sats to {to}...");
            spend(keys, utxo, to, *amount).await?;
            println!("Signed transaction (hex): ...");
        }
    }

    Ok(())
}
