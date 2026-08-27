#![forbid(unsafe_code)]

//! Wire protocol types and rules for Rustgo.

mod frame;
mod message;
mod state;
mod version;

pub use frame::{Frame, FrameCodec, FrameError, HEADER_LEN, MAGIC, SUPPORTED_FLAGS};
pub use message::*;
pub use state::{ClientHandshakeState, StateError};
pub use version::ProtocolVersion;
