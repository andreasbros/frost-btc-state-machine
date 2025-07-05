#![allow(dead_code)]

use crate::{
    transport::{Transport, TransportError},
    ParticipantId,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GuardianError {
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("Failed to serialize message: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Mutex lock poisoned: {0}")]
    Lock(String),

    #[error("Invalid state for operation: found {found:?}")]
    InvalidState { found: State },
}

/// Toy message payload for the state machine.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    Ping,
    Pong,
}

/// message sent over the transport layer
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WireMessage {
    pub sender: ParticipantId,
    pub payload: Message,
}

/// Toy state machine.
#[derive(Debug, PartialEq, Clone)]
pub enum State {
    Idle,
    AwaitingPong(ParticipantId),
    Done,
}

/// Represents a node in the guardian network.
pub struct GuardianNode {
    id: ParticipantId,
    transport: Arc<dyn Transport<Msg = Vec<u8>>>,
    state: Arc<Mutex<State>>,
}

impl GuardianNode {
    /// Creates a new GuardianNode.
    pub fn new(id: ParticipantId, transport: Arc<dyn Transport<Msg = Vec<u8>>>) -> Self {
        Self { id, transport, state: Arc::new(Mutex::new(State::Idle)) }
    }

    /// Returns the current state of the node.
    pub fn state(&self) -> Result<State, GuardianError> {
        self.state.lock().map(|s| s.clone()).map_err(|e| GuardianError::Lock(e.to_string()))
    }

    /// Starts the node's message processing loop.
    pub async fn run(&self) {
        if let Ok(Some((receiver_id, msg_bytes))) = self.transport.receive().await {
            if receiver_id == self.id {
                if let Ok(wire_message) = serde_json::from_slice::<WireMessage>(&msg_bytes) {
                    if let Err(_e) = self.handle_message(wire_message).await {
                        // TODO: handle errors
                    }
                }
            }
        }
        // TODO: handle errors
    }

    /// Sends a Ping to another participant to initiate the state machine.
    pub async fn ping(&self, receiver_id: ParticipantId) -> Result<(), GuardianError> {
        // scope the lock to ensure it is dropped before async calls
        {
            let mut state = self.state.lock().map_err(|e| GuardianError::Lock(e.to_string()))?;
            if *state != State::Idle {
                return Err(GuardianError::InvalidState { found: state.clone() });
            }
            // optimistically update state.
            *state = State::AwaitingPong(receiver_id.clone());
        }

        let message = WireMessage { sender: self.id.clone(), payload: Message::Ping };
        let msg_bytes = serde_json::to_vec(&message)?;

        if let Err(e) = self.transport.send(receiver_id.clone(), msg_bytes).await {
            // revert state on error
            let mut state = self.state.lock().map_err(|e| GuardianError::Lock(e.to_string()))?;
            if *state == State::AwaitingPong(receiver_id) {
                *state = State::Idle;
            }
            return Err(e.into());
        }

        Ok(())
    }

    /// Handles an incoming message and updates the state machine.
    async fn handle_message(&self, msg: WireMessage) -> Result<(), GuardianError> {
        let recipient_for_pong = {
            let mut state = self.state.lock().map_err(|e| GuardianError::Lock(e.to_string()))?;
            match (&*state, msg.payload) {
                (State::Idle, Message::Ping) => Some(msg.sender),
                (State::AwaitingPong(p_id), Message::Pong) if *p_id == msg.sender => {
                    *state = State::Done;
                    None
                }
                _ => None,
            }
        };

        if let Some(recipient) = recipient_for_pong {
            let response = WireMessage { sender: self.id.clone(), payload: Message::Pong };
            let response_bytes = serde_json::to_vec(&response)?;
            self.transport.send(recipient, response_bytes).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::InMemoryTransport;

    fn create_participants(n: u16) -> Vec<ParticipantId> {
        (1..=n).map(|i| ParticipantId::try_from(i).unwrap()).collect()
    }

    #[tokio::test]
    async fn test_ping_pong_communication() {
        let participants = create_participants(2);
        let node_a_id = participants[0].clone();
        let node_b_id = participants[1].clone();

        let transport = Arc::new(InMemoryTransport::new(participants));

        let node_a = GuardianNode::new(node_a_id.clone(), transport.clone());
        let node_b = GuardianNode::new(node_b_id.clone(), transport.clone());

        // 1 - Node A pings Node B
        assert_eq!(node_a.state().unwrap(), State::Idle);
        node_a.ping(node_b_id.clone()).await.unwrap();
        assert_eq!(node_a.state().unwrap(), State::AwaitingPong(node_b_id.clone()));

        // 2 - Node B runs, receives Ping, and sends Pong
        assert_eq!(node_b.state().unwrap(), State::Idle);
        node_b.run().await;
        assert_eq!(node_b.state().unwrap(), State::Idle);

        // 3 - Node A runs, receives Pong
        node_a.run().await;
        assert_eq!(node_a.state().unwrap(), State::Done);
    }
}
