use frost_demo::{
    errors::SigningError,
    signer::{run_signing_ceremony, SessionId, SigningMessage, SigningState},
    transport::Transport,
};

mod utils;
use crate::utils::test::TestHarness;

#[tokio::test]
async fn test_state_transition_idle_to_collecting_commitments() {
    // --- Setup
    let harness = TestHarness::new(2, 3, None).await;
    let (signers, transport) = harness.create_signers();
    let signer = signers.values().next().unwrap();
    let session_id: SessionId = 123;
    let (transaction, _) = harness.create_dummy_transaction(1);

    let initial_state = signer.get_state().unwrap();
    assert!(matches!(initial_state, SigningState::Idle));

    let result = signer.initiate_signing_round(session_id, transaction).await;

    assert!(result.is_ok());

    // Check state transition
    let new_state = signer.get_state().unwrap();
    match new_state {
        SigningState::CollectingCommitments { session_id: state_session_id, .. } => {
            assert_eq!(state_session_id, session_id);
        }
        _ => panic!("Expected CollectingCommitments state"),
    }

    // Check that a message was broadcast
    let sent_message = transport.receive().await.unwrap();
    assert!(sent_message.is_some());
    if let Some((_, msg)) = sent_message {
        match msg {
            SigningMessage::NonceCommitment(msg_session_id, sender_id, _) => {
                assert_eq!(msg_session_id, session_id);
                assert_eq!(sender_id, signer.participant_id);
            }
            _ => panic!("Expected a NonceCommitment message"),
        }
    }
}

#[tokio::test]
async fn test_initiate_signing_in_invalid_state() {
    // --- Setup
    let harness = TestHarness::new(2, 3, None).await;
    let (signers, _) = harness.create_signers();
    let signer = signers.values().next().unwrap();
    let session_id: SessionId = 123;
    let (transaction, _) = harness.create_dummy_transaction(1);

    // Initiate first round to move state away from Idle
    signer.initiate_signing_round(session_id, transaction.clone()).await.unwrap();
    let state_after_first_call = signer.get_state().unwrap();
    assert!(matches!(state_after_first_call, SigningState::CollectingCommitments { .. }));

    // Try to initiate again
    let result = signer.initiate_signing_round(session_id + 1, transaction).await;

    // --- Assertions
    assert!(result.is_err());
    match result.err().unwrap() {
        SigningError::InvalidState(msg) => {
            assert_eq!(msg, "Signer is not in Idle state.");
        }
        e => panic!("Expected InvalidState error, but got {:?}", e),
    }
}

#[tokio::test]
async fn test_process_message_in_collecting_commitments() {
    let harness = TestHarness::new(2, 3, None).await;
    let (signers, _) = harness.create_signers();
    let signer = signers.values().next().unwrap();
    let session_id: SessionId = 123;
    let (transaction, _) = harness.create_dummy_transaction(1);

    // Move to CollectingCommitments state
    signer.initiate_signing_round(session_id, transaction).await.unwrap();

    // Create a dummy commitment message from another participant
    let (other_signer, _) = harness.create_signers();
    let other_participant_id = other_signer.keys().find(|&&id| id != signer.participant_id).unwrap();
    let (_, commitments) = frost_secp256k1_tr::round1::commit(
        &harness.key_data.key_packages[other_participant_id].signing_share(),
        &mut rand::rngs::OsRng,
    );
    let message = SigningMessage::NonceCommitment(session_id, *other_participant_id, Box::new(commitments.clone()));

    let result = signer.process_message(message).await;

    assert!(result.is_ok());

    // Check that the commitment was added to the state
    let state = signer.get_state().unwrap();
    match state {
        SigningState::CollectingCommitments { commitments: state_commitments, .. } => {
            assert_eq!(state_commitments.len(), 1);
            assert!(state_commitments.contains_key(other_participant_id));
        }
        _ => panic!("Expected CollectingCommitments state"),
    }
}

#[tokio::test]
async fn test_process_message_with_wrong_session_id() {
    let harness = TestHarness::new(2, 3, None).await;
    let (signers, _) = harness.create_signers();
    let signer = signers.values().next().unwrap();
    let correct_session_id: SessionId = 123;
    let wrong_session_id: SessionId = 456;
    let (transaction, _) = harness.create_dummy_transaction(1);

    signer.initiate_signing_round(correct_session_id, transaction).await.unwrap();

    // Create a message with the wrong session ID
    let (other_signer, _) = harness.create_signers();
    let other_participant_id = other_signer.keys().find(|&&id| id != signer.participant_id).unwrap();
    let (_, commitments) = frost_secp256k1_tr::round1::commit(
        &harness.key_data.key_packages[other_participant_id].signing_share(),
        &mut rand::rngs::OsRng,
    );
    let message = SigningMessage::NonceCommitment(wrong_session_id, *other_participant_id, Box::new(commitments));

    signer.process_message(message).await.unwrap();

    // The message should be ignored, so the commitments list should be empty
    let state = signer.get_state().unwrap();
    match state {
        SigningState::CollectingCommitments { commitments, .. } => {
            assert!(commitments.is_empty());
        }
        _ => panic!("Expected CollectingCommitments state"),
    }
}

#[tokio::test]
async fn test_parallel_initiation_is_safe() {
    let harness = TestHarness::new(2, 3, None).await;
    let (signers, _) = harness.create_signers();
    // Clone  signer to simulate concurrent access
    let signer = signers.values().next().unwrap().clone();
    let signer_clone = signer.clone();
    let (transaction, _) = harness.create_dummy_transaction(1);
    let transaction_clone = transaction.clone();

    // Spawn two tasks trying to initiate a round concurrently
    let task1 = tokio::spawn(async move { signer.initiate_signing_round(1, transaction).await });
    // Add a small delay to increase the chance of collision
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    let task2 = tokio::spawn(async move { signer_clone.initiate_signing_round(2, transaction_clone).await });

    let results = vec![task1.await.unwrap(), task2.await.unwrap()];

    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.iter().filter(|r| r.is_err()).count();

    // Exactly one must succeed, and one must fail due to the state mutex
    assert_eq!(successes, 1, "Exactly one initiation should succeed");
    assert_eq!(failures, 1, "Exactly one initiation should fail");

    // Verify the failure is the expected InvalidState error
    let failure = results.iter().find(|r| r.is_err()).unwrap().as_ref().err().unwrap();
    assert!(matches!(failure, SigningError::InvalidState(_)));
}

#[tokio::test]
async fn test_parallel_signing_ceremonies_are_isolated() {
    let seed1 = [1; 32];
    let harness1 = TestHarness::new(2, 3, Some(seed1)).await;
    let key_data1 = harness1.key_data.clone();
    let (tx1, prevouts1) = harness1.create_dummy_transaction(1);

    let seed2 = [1; 32];
    let harness2 = TestHarness::new(2, 3, Some(seed2)).await;
    let key_data2 = harness2.key_data.clone();
    let (tx2, prevouts2) = harness2.create_dummy_transaction(2);

    // Spawn both signing ceremonies to run concurrently.
    let ceremony1_task = tokio::spawn(async move { run_signing_ceremony(key_data1, tx1, &prevouts1).await });
    let ceremony2_task = tokio::spawn(async move { run_signing_ceremony(key_data2, tx2, &prevouts2).await });

    // Wait for both ceremonies to complete.
    let (result1, result2) = tokio::join!(ceremony1_task, ceremony2_task);

    // Check that both tasks completed without panicking.
    let ceremony1_tx = result1.expect("Ceremony 1 task panicked").expect("Ceremony 1 failed");
    let ceremony2_tx = result2.expect("Ceremony 2 task panicked").expect("Ceremony 2 failed");

    println!("{ceremony1_tx:?}");
    println!("{ceremony2_tx:?}");

    // Check tx1 hash is matching because we used deterministic key generation using seed
    let tx1_output = ceremony1_tx.output.get(0).expect("Transaction should have at least one output");
    let script_pubkey1 = hex::encode(&tx1_output.script_pubkey.as_bytes());
    let expected_script_pubkey1 = "5120351c5cdc8c95b944abaf3054caf98d75e88cba356958c46afb571f93ab873192";
    assert_eq!(script_pubkey1, expected_script_pubkey1, "The tx1 script_pubkey did not match the expected value");

    // Check tx2 hash is matching because we used deterministic key generation using seed
    let tx2_output = ceremony2_tx.output.get(0).expect("Transaction should have at least one output");
    let script_pubkey2 = hex::encode(&tx2_output.script_pubkey.as_bytes());
    let expected_script_pubkey2 = "5120eaeab93eab93d0066df96fbe1553f9dcbe4a84ee63ccc33ed10201e3244de1f8";
    assert_eq!(script_pubkey2, expected_script_pubkey2, "The tx2 script_pubkey did not match the expected value");
}
