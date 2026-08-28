use std::sync::Arc;

use rustgo_path::{PathError, PathKind, PathState, PathStateMachine, SelectedPath};

#[test]
fn selected_path_preserves_an_opaque_adapter_owned_handle() {
    let handle = Arc::new(42_u64);

    let selected = SelectedPath::authenticated_with(PathKind::QuicV6, handle.clone());

    assert_eq!(selected.kind(), PathKind::QuicV6);
    assert!(Arc::ptr_eq(&selected.handle::<u64>().unwrap(), &handle));
    assert!(selected.handle::<String>().is_none());
}

#[test]
fn state_machine_accepts_exactly_the_documented_transitions() {
    let mut state = PathStateMachine::new();

    state.transition(PathState::Checking).unwrap();
    state.transition(PathState::Direct).unwrap();
    state.transition(PathState::Rechecking).unwrap();
    state.transition(PathState::Relay).unwrap();
    state.transition(PathState::Rechecking).unwrap();
    state.transition(PathState::Direct).unwrap();
    state.transition(PathState::Closed).unwrap();

    assert_eq!(state.current(), PathState::Closed);
}

#[test]
fn illegal_transition_is_rejected_without_mutating_state() {
    let mut state = PathStateMachine::new();

    let error = state.transition(PathState::Direct).unwrap_err();

    assert_eq!(
        error,
        PathError::IllegalTransition {
            from: PathState::Discovering,
            to: PathState::Direct,
        }
    );
    assert_eq!(state.current(), PathState::Discovering);
}

#[test]
fn every_undocumented_transition_is_illegal() {
    let states = [
        PathState::Discovering,
        PathState::Checking,
        PathState::Direct,
        PathState::Relay,
        PathState::Rechecking,
        PathState::Closed,
    ];
    let legal = [
        (PathState::Discovering, PathState::Checking),
        (PathState::Checking, PathState::Direct),
        (PathState::Checking, PathState::Relay),
        (PathState::Direct, PathState::Rechecking),
        (PathState::Relay, PathState::Rechecking),
        (PathState::Rechecking, PathState::Direct),
        (PathState::Rechecking, PathState::Relay),
        (PathState::Direct, PathState::Closed),
        (PathState::Relay, PathState::Closed),
        (PathState::Rechecking, PathState::Closed),
    ];

    for from in states {
        for to in states {
            let mut state = PathStateMachine::at(from);
            let result = state.transition(to);
            if legal.contains(&(from, to)) {
                assert_eq!(result, Ok(()), "{from:?} -> {to:?}");
                assert_eq!(state.current(), to);
            } else {
                assert_eq!(
                    result,
                    Err(PathError::IllegalTransition { from, to }),
                    "{from:?} -> {to:?}"
                );
                assert_eq!(state.current(), from);
            }
        }
    }
}
