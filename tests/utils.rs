#![allow(dead_code)]

#[cfg(test)]
pub mod test {
    use bitcoin::{
        secp256k1::{Secp256k1, SecretKey},
        Address, Amount, Network, OutPoint, Transaction, TxOut,
    };
    use frost_demo::{
        bitcoin::create_unsigned_transaction,
        generate_keys,
        keys::KeyData,
        signer::{setup_signers, FrostSigner},
        transport::InMemoryTransport,
    };
    use frost_secp256k1_tr::Identifier;
    use std::{collections::HashMap, str::FromStr, sync::Arc};
    use tempfile::NamedTempFile;

    /// A test harness to simplify setup for state machine tests.
    pub struct TestHarness {
        pub key_data: KeyData,
        _temp_file: NamedTempFile, // Keep the file alive for the duration of the test
    }

    impl TestHarness {
        /// Creates a new TestHarness, generating keys for the given threshold and total participants.
        pub async fn new(threshold: u16, total: u16, seed: Option<[u8; 32]>) -> Self {
            let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
            generate_keys(threshold, total, temp_file.path(), seed).await.expect("Failed to generate keys");
            let keys_json = tokio::fs::read_to_string(temp_file.path()).await.expect("Failed to read key data file");
            let key_data: KeyData = serde_json::from_str(&keys_json).expect("Failed to deserialize key data");
            Self { key_data, _temp_file: temp_file }
        }

        /// Creates a set of signers and an in-memory transport layer based on the generated key data.
        pub fn create_signers(&self) -> (HashMap<Identifier, FrostSigner>, Arc<InMemoryTransport>) {
            setup_signers(&self.key_data).expect("Failed to set up signers")
        }

        /// Creates a simple, unsigned dummy transaction and its corresponding prevouts for use in tests.
        pub fn create_dummy_transaction(&self, seed: u64) -> (Transaction, Vec<TxOut>) {
            let utxo =
                OutPoint::from_str("f2ba6014dd5598a2333b7d1553c932f7a9d7a22b704481da4a10fb0032e35f4b:0").unwrap();
            let utxo_value_sat = 50_000;
            let change_addr = self.key_data.address(Network::Signet).unwrap();

            let utxo_to_spend =
                TxOut { value: Amount::from_sat(utxo_value_sat), script_pubkey: change_addr.script_pubkey() };

            // Create a unique destination address from the seed.
            let secp = Secp256k1::new();
            let mut seed_bytes = [0u8; 32];
            seed_bytes[..8].copy_from_slice(&seed.to_le_bytes()); // for simplicity and test purposes we only take first 8 bytes
            let secret_key = SecretKey::from_slice(&seed_bytes).expect("Seed must be 32 bytes");
            let public_key = secret_key.public_key(&secp);
            let (x_only_pk, _) = public_key.x_only_public_key();
            let to_addr = Address::p2tr(&secp, x_only_pk, None, Network::Signet);

            let transaction =
                create_unsigned_transaction(utxo, &utxo_to_spend, to_addr, Amount::from_sat(10_000), change_addr)
                    .unwrap();

            let prevouts = vec![utxo_to_spend];

            (transaction, prevouts)
        }
    }
}
