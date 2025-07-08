use crate::errors::KeyDataError;
use bitcoin::{
    key::{Secp256k1, UntweakedPublicKey},
    Address, Network, PublicKey,
};
use frost_secp256k1_tr::{
    keys::{KeyPackage, PublicKeyPackage},
    Identifier,
};
use k256::elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

/// Key generation data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyData {
    pub threshold: u16,
    pub total: u16,
    pub public: PublicKeyPackage,
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
}

impl KeyData {
    /// Derives group address
    pub fn address(&self, network: Network) -> Result<Address, KeyDataError> {
        let secp_engine = Secp256k1::new();

        // g the FROST group verifying key
        let group_verifying_key = self.public.verifying_key();
        let mut affine_point = group_verifying_key.to_element().to_affine();

        // for a taproot keypath spend, the internal public key must have an even
        // y coordinate. If it's odd, we must use its negation.
        if affine_point.y_is_odd().into() {
            affine_point = -affine_point;
        }

        // serialize the potential internal key to a compressed public key format
        let pk_bytes = affine_point.to_encoded_point(true);
        let bitcoin_public_key =
            PublicKey::from_slice(pk_bytes.as_bytes()).map_err(|e| KeyDataError::PublicKey(e.to_string()))?;

        // get the x only public key from the inner secp256k1 key
        let (x_only_pk, _parity) = bitcoin_public_key.inner.x_only_public_key();
        let untweaked_pk = UntweakedPublicKey::from(x_only_pk);

        // create the P2TR address from the final, tweaked internal key.
        let address = Address::p2tr(&secp_engine, untweaked_pk, None, network);
        Ok(address)
    }
}

/// Loads and parses the FROST key data from a JSON file.
pub async fn load_key_data(path: &Path) -> Result<KeyData, KeyDataError> {
    let keys_json = tokio::fs::read_to_string(path).await.map_err(|e| KeyDataError::File(e.to_string()))?;
    serde_json::from_str(&keys_json).map_err(|e| KeyDataError::JsonParse(e.to_string()))
}
