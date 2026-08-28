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
        // Discovering -> Closed and Checking -> Closed are terminal abort edges:
        // they are used only when startup is cancelled or exhausts every viable
        // authenticated path before one can be published.
        let legal = matches!(
            (self.current, next),
            (
                PathState::Discovering,
                PathState::Checking | PathState::Closed
            ) | (
                PathState::Checking,
                PathState::Direct | PathState::Relay | PathState::Closed
            ) | (
                PathState::Direct | PathState::Relay,
                PathState::Rechecking | PathState::Closed
            ) | (
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
