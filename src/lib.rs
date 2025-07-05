mod guardian;
mod transport;

use anyhow::{Context, Error};
use frost::keys::{generate_with_dealer, IdentifierList, KeyPackage};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use std::{collections::BTreeMap, path::Path};
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

/// Key generation data
#[derive(Serialize, Deserialize)]
pub struct KeyGenerationData {
    pub threshold: u16,
    pub total: u16,
    pub public: frost::keys::PublicKeyPackage,
    pub key_packages: BTreeMap<ParticipantId, KeyPackage>,
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

    let data = KeyGenerationData { threshold, total, public: pubkey_package, key_packages };

    let json_bytes = serde_json::to_vec_pretty(&data).context("Failed to serialize data to JSON")?;

    let mut file = File::create(output).await.context("Failed to create output file")?;
    file.write_all(&json_bytes).await?;

    Ok(())
}

pub async fn spend(_keys_path: &Path, _to: &str, _amount: u64) -> Result<String, Error> {
    Ok("hex".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::fs;

    #[tokio::test]
    async fn test_generate_keys_success() {
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let path = temp_file.path();

        generate_keys(2, 3, path).await.expect("Failed to generate keys");

        let file_content = fs::read_to_string(path).await.expect("Failed to read generated keys file");

        assert!(!file_content.is_empty(), "Generated keys file should not be empty");

        let data: KeyGenerationData = serde_json::from_str(&file_content).expect("JSON should deserialize");
        assert_eq!(data.key_packages.len(), 3);
    }

    #[tokio::test]
    async fn test_spend_success() {
        let to_address = "bc1q...";
        let amount_satoshi = 1000;
        let result = spend(Path::new("keys.json"), to_address, amount_satoshi).await;
        assert!(result.is_ok(), "should return Ok on success");
    }
}
