use frost_secp256k1_tr as frost;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyDataError {
    #[error("Public key error: {0}")]
    PublicKey(String),
    #[error("File error: {0}")]
    File(String),
    #[error("JSON parse error: {0}")]
    JsonParse(String),
}

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Signing ceremony timed out: {0}")]
    Timeout(String),

    #[error("Not enough signers")]
    NotEnoughSigners,

    #[error("Received an invalid signature share from participant {0:?}")]
    InvalidSignatureShare(frost::Identifier),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("FROST error: {0}")]
    Frost(#[from] frost::Error),

    #[error("Bitcoin error: {0}")]
    Bitcoin(#[from] BitcoinError),
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Transport send error: {0}")]
    Send(String),

    #[error("Transport broadcast error: {0}")]
    Broadcast(String),

    #[error("Transport receive error: {0}")]
    Receive(String),
}

#[derive(Error, Debug)]
pub enum BitcoinError {
    #[error("Sighash computation failed: {0}")]
    Sighash(String),

    #[error("Bitcoin address error: {0}")]
    Address(String),

    #[error("Bitcoin spend error: {0}")]
    Spend(String),

    #[error("Bitcoin UTXO error: {0}")]
    Utxo(String),

    #[error("Bitcoin client error: {0}")]
    Client(String),
}
