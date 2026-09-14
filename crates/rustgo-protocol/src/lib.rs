#![forbid(unsafe_code)]

//! Wire protocol types and rules for Rustgo.

mod enrollment;
mod frame;
mod message;
mod state;
mod version;

pub use enrollment::{
    EnrollmentKeyError, EnrollmentKeyMaterial, EnrollmentPurpose, RegistrationIntent,
    canonical_enrollment_server_addr,
};
pub use frame::{Frame, FrameCodec, FrameError, HEADER_LEN, MAGIC, SUPPORTED_FLAGS};
pub use message::*;
pub use state::{ClientHandshakeState, ControlMessageDirection, StateError};
pub use version::ProtocolVersion;
