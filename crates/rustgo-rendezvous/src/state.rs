use thiserror::Error;

use crate::{CandidateGeneration, SessionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousPhase {
    New,
    Requested,
    Accepted,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousState {
    session_id: SessionId,
    phase: RendezvousPhase,
    last_step: u64,
    generation: CandidateGeneration,
}

impl RendezvousState {
    pub const fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            phase: RendezvousPhase::New,
            last_step: 0,
            generation: CandidateGeneration::INITIAL,
        }
    }

    pub const fn requested(session_id: SessionId, step: u64) -> Self {
        Self {
            session_id,
            phase: RendezvousPhase::Requested,
            last_step: step,
            generation: CandidateGeneration::INITIAL,
        }
    }

    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub const fn phase(&self) -> RendezvousPhase {
        self.phase
    }

    pub const fn last_step(&self) -> u64 {
        self.last_step
    }

    pub const fn generation(&self) -> CandidateGeneration {
        self.generation
    }

    pub fn request(
        &mut self,
        step: u64,
        generation: CandidateGeneration,
    ) -> Result<(), StateError> {
        if self.phase != RendezvousPhase::New {
            return Err(StateError::IllegalTransition);
        }
        self.accept_step(step)?;
        self.phase = RendezvousPhase::Requested;
        self.last_step = step;
        self.generation = generation;
        Ok(())
    }

    pub fn provider_decision(
        &mut self,
        step: u64,
        generation: CandidateGeneration,
        accepted: bool,
    ) -> Result<(), StateError> {
        if self.phase != RendezvousPhase::Requested {
            return Err(StateError::IllegalTransition);
        }
        self.accept_step(step)?;
        self.accept_generation(generation)?;
        self.last_step = step;
        self.phase = if accepted {
            RendezvousPhase::Accepted
        } else {
            RendezvousPhase::Closed
        };
        Ok(())
    }

    pub const fn accept_step(&self, step: u64) -> Result<(), StateError> {
        if step <= self.last_step {
            Err(StateError::ReplayedStep)
        } else {
            Ok(())
        }
    }

    pub fn advance_step(&mut self, step: u64) -> Result<(), StateError> {
        self.accept_step(step)?;
        self.last_step = step;
        Ok(())
    }

    pub const fn accept_generation(
        &self,
        generation: CandidateGeneration,
    ) -> Result<(), StateError> {
        if generation.get() != self.generation.get() {
            Err(StateError::GenerationMismatch {
                expected: self.generation,
                actual: generation,
            })
        } else {
            Ok(())
        }
    }

    pub fn accept_metadata(
        &mut self,
        session_id: &SessionId,
        step: u64,
        generation: CandidateGeneration,
        expires_unix_secs: u64,
        now_unix_secs: u64,
    ) -> Result<(), StateError> {
        if session_id != &self.session_id {
            return Err(StateError::SessionMismatch);
        }
        if expires_unix_secs <= now_unix_secs {
            return Err(StateError::Expired);
        }
        self.accept_generation(generation)?;
        self.advance_step(step)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StateError {
    #[error("rendezvous message step is not strictly increasing")]
    ReplayedStep,
    #[error("candidate generation mismatch: expected {expected:?}, got {actual:?}")]
    GenerationMismatch {
        expected: CandidateGeneration,
        actual: CandidateGeneration,
    },
    #[error("rendezvous message session does not match state")]
    SessionMismatch,
    #[error("rendezvous message has expired")]
    Expired,
    #[error("illegal rendezvous state transition")]
    IllegalTransition,
}
