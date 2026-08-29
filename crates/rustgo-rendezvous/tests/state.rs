use rustgo_rendezvous::{CandidateGeneration, RendezvousState, SessionId, StateError};

fn session_id() -> SessionId {
    SessionId::from([7; 32])
}

#[test]
fn state_rejects_replayed_step() {
    let state = RendezvousState::requested(session_id(), 7);
    assert_eq!(state.accept_step(7), Err(StateError::ReplayedStep));
}

#[test]
fn state_accepts_only_strictly_increasing_steps() {
    let mut state = RendezvousState::requested(session_id(), 7);
    assert_eq!(state.advance_step(8), Ok(()));
    assert_eq!(state.last_step(), 8);
    assert_eq!(state.advance_step(8), Err(StateError::ReplayedStep));
    assert_eq!(state.advance_step(6), Err(StateError::ReplayedStep));
}

#[test]
fn state_rejects_a_candidate_generation_mismatch() {
    let state = RendezvousState::requested(session_id(), 1);
    assert_eq!(
        state.accept_generation(CandidateGeneration::new(2).unwrap()),
        Err(StateError::GenerationMismatch {
            expected: CandidateGeneration::new(1).unwrap(),
            actual: CandidateGeneration::new(2).unwrap(),
        })
    );
}

#[test]
fn generation_advance_accepts_only_exactly_one_and_rejects_replay_and_skip() {
    let id = SessionId::from([0x71; 32]);
    let mut state = RendezvousState::new(id);
    state.request(1, CandidateGeneration::INITIAL).unwrap();
    assert!(
        state
            .advance_generation(CandidateGeneration::new(3).unwrap())
            .is_err()
    );
    state
        .advance_generation(CandidateGeneration::new(2).unwrap())
        .unwrap();
    assert!(
        state
            .advance_generation(CandidateGeneration::new(2).unwrap())
            .is_err()
    );
    assert!(
        state
            .advance_generation(CandidateGeneration::new(4).unwrap())
            .is_err()
    );
}

#[test]
fn state_rejects_provider_accept_before_request() {
    let mut state = RendezvousState::new(session_id());
    assert_eq!(
        state.provider_decision(1, CandidateGeneration::new(1).unwrap(), true),
        Err(StateError::IllegalTransition)
    );
}

#[test]
fn state_rejects_expired_messages_without_advancing_step() {
    let mut state = RendezvousState::requested(session_id(), 1);
    assert_eq!(
        state.accept_metadata(
            &session_id(),
            2,
            CandidateGeneration::new(1).unwrap(),
            99,
            100,
        ),
        Err(StateError::Expired)
    );
    assert_eq!(state.last_step(), 1);
}
