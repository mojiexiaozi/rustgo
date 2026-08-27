#![forbid(unsafe_code)]

//! Shared cryptographic support for Rustgo.

mod identity;
mod keyfile;
mod transcript;

pub use identity::{
    CryptoError, DeviceKeypair, DevicePublicKey, Fingerprint, sign_auth, verify_auth,
};
pub use keyfile::generate_key_file;
pub use transcript::AuthTranscript;
