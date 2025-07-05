#![allow(dead_code)]

use crate::ParticipantId;
use async_trait::async_trait;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Transport send error: {0}")]
    Send(String),

    #[error("Transport broadcast error: {0}")]
    Broadcast(String),

    #[error("Transport broadcast error: {0}")]
    Receive(String),
}

/// Transport trait for sending and receiving messages.
#[async_trait]
pub trait Transport: Send + Sync {
    type Msg: Send + Sync;

    /// Send a message to a participant.
    async fn send(&self, receiver: ParticipantId, msg: Self::Msg) -> Result<(), TransportError>;

    /// Broadcast a message to all participants.
    async fn broadcast(&self, msg: Self::Msg) -> Result<(), TransportError>;

    /// Receive a message if any.
    async fn receive(&self) -> Result<Option<(ParticipantId, Self::Msg)>, TransportError>;
}

/// Transport message shared queue.
pub type TransportMsgQueue = VecDeque<(ParticipantId, Vec<u8>)>;

/// In memory transport implementation
#[derive(Clone)]
pub struct InMemoryTransport {
    /// Queue of messages
    queue: Arc<Mutex<TransportMsgQueue>>,

    /// List of participant IDs.
    participants: Vec<ParticipantId>,
}

impl InMemoryTransport {
    pub fn new(participants: Vec<ParticipantId>) -> Self {
        InMemoryTransport { queue: Arc::new(Mutex::new(VecDeque::new())), participants }
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    type Msg = Vec<u8>;

    async fn send(&self, receiver: ParticipantId, msg: Self::Msg) -> Result<(), TransportError> {
        let mut q = self.queue.lock().map_err(|e| TransportError::Send(e.to_string()))?;
        q.push_back((receiver, msg));
        Ok(())
    }

    async fn broadcast(&self, msg: Self::Msg) -> Result<(), TransportError> {
        let mut q = self.queue.lock().map_err(|e| TransportError::Broadcast(e.to_string()))?;
        for id in &self.participants {
            q.push_back((id.clone(), msg.clone()));
        }
        Ok(())
    }

    async fn receive(&self) -> Result<Option<(ParticipantId, Self::Msg)>, TransportError> {
        let mut q = self.queue.lock().map_err(|e| TransportError::Receive(e.to_string()))?;
        Ok(q.pop_front())
    }
}
