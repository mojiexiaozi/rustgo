use crate::PathError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Discovering,
    Checking,
    Direct,
    Relay,
    Rechecking,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStateMachine {
    current: PathState,
}

impl Default for PathStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl PathStateMachine {
    pub const fn new() -> Self {
        Self::at(PathState::Discovering)
    }

    pub const fn at(state: PathState) -> Self {
        Self { current: state }
    }

    pub const fn current(&self) -> PathState {
        self.current
    }

    pub fn transition(&mut self, next: PathState) -> Result<(), PathError> {
        let legal = matches!(
            (self.current, next),
            (PathState::Discovering, PathState::Checking)
                | (PathState::Checking, PathState::Direct | PathState::Relay)
                | (
                    PathState::Direct | PathState::Relay,
                    PathState::Rechecking | PathState::Closed
                )
                | (
                    PathState::Rechecking,
                    PathState::Direct | PathState::Relay | PathState::Closed
                )
        );
        if !legal {
            return Err(PathError::IllegalTransition {
                from: self.current,
                to: next,
            });
        }
        self.current = next;
        Ok(())
    }
}
