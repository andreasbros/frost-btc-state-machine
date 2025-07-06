#![allow(dead_code)]

use crate::{errors::TransportError, signer::SigningMessage};
use async_trait::async_trait;
use frost_secp256k1_tr::Identifier;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// Transport trait for sending and receiving messages.
#[async_trait]
pub trait Transport: Send + Sync {
    type Msg: Send + Sync + Clone;

    /// Send a message to a participant.
    async fn send(&self, receiver: Identifier, msg: Self::Msg) -> Result<(), TransportError>;

    /// Broadcast a message to all participants.
    async fn broadcast(&self, msg: Self::Msg) -> Result<(), TransportError>;

    /// Receive a message if any.
    async fn receive(&self) -> Result<Option<(Identifier, Self::Msg)>, TransportError>;
}

/// Transport message shared queue.
pub type TransportMsgQueue = VecDeque<(Identifier, SigningMessage)>;

/// In memory transport implementation
#[derive(Clone)]
pub struct InMemoryTransport {
    /// Queue of messages
    queue: Arc<Mutex<TransportMsgQueue>>,

    /// List of participant IDs.
    participants: Vec<Identifier>,
}

impl InMemoryTransport {
    pub fn new(participants: Vec<Identifier>) -> Self {
        InMemoryTransport { queue: Arc::new(Mutex::new(VecDeque::new())), participants }
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    type Msg = SigningMessage;

    async fn send(&self, receiver: Identifier, msg: Self::Msg) -> Result<(), TransportError> {
        let mut q = self.queue.lock().map_err(|e| TransportError::Send(e.to_string()))?;
        q.push_back((receiver, msg));
        Ok(())
    }

    async fn broadcast(&self, msg: Self::Msg) -> Result<(), TransportError> {
        let mut q = self.queue.lock().map_err(|e| TransportError::Broadcast(e.to_string()))?;
        for id in &self.participants {
            q.push_back((*id, msg.clone()));
        }
        Ok(())
    }

    async fn receive(&self) -> Result<Option<(Identifier, Self::Msg)>, TransportError> {
        let mut q = self.queue.lock().map_err(|e| TransportError::Receive(e.to_string()))?;
        Ok(q.pop_front())
    }
}
