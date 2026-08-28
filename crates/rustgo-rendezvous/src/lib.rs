#![forbid(unsafe_code)]

//! Bounded, socket-free rendezvous wire types and session state.

mod message;
mod state;

pub use message::*;
pub use state::{RendezvousPhase, RendezvousState, StateError};
