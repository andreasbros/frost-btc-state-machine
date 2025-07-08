use frost_secp256k1_tr as frost;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Not enough signers")]
    NotEnoughSigners,
    #[error("Internal error: {0}")]
    InternalError(String),
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
}
