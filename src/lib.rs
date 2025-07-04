use anyhow::Error;
use frost::keys::{generate_with_dealer, IdentifierList, KeyPackage};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

/// Key generation data
#[derive(Serialize, Deserialize)]
pub struct KeyGenerationData {
    /// Threshold number of signers needed.
    pub threshold: u16,

    /// Total number of parties.
    pub total: u16,

    /// Public key package: contains all the signers' public keys as well as the group public key.
    pub public: frost::keys::PublicKeyPackage,

    /// Each party,s key package: identifier, signing share and verifying share.
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
}

pub async fn generate_keys(threshold: u16, total: u16, output: &Path) -> Result<(), Error> {
    let rng = OsRng;
    let (shares, pubkey_package) = generate_with_dealer(total, threshold, IdentifierList::Default, rng)?;

    let key_packages = shares
        .into_iter()
        .map(|(identifier, secret_share)| {
            KeyPackage::try_from(secret_share).map(|key_package| (identifier, key_package))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let data = KeyGenerationData { threshold, total, public: pubkey_package, key_packages };

    let json_bytes = serde_json::to_vec_pretty(&data)?;

    let mut file = File::create(output).await?;
    file.write_all(&json_bytes).await?;

    Ok(())
}

pub async fn spend(_keys_path: &Path, _to: &str, _amount: u64) -> Result<String, Error> {
    Ok("hex".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_keys_success() {
        let result = generate_keys(2, 3, Path::new("keys.json")).await;
        assert!(result.is_ok(), "should return Ok on success");
        let _ = tokio::fs::remove_file("keys.json").await;
    }

    #[tokio::test]
    async fn test_spend_success() {
        let to_address = "bc1q...";
        let amount_satoshi = 1000;
        let result = spend(Path::new("keys.json"), to_address, amount_satoshi).await;
        assert!(result.is_ok(), "should return Ok on success");
    }
}
