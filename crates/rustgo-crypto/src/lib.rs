#![forbid(unsafe_code)]

//! Shared cryptographic support for Rustgo.

mod identity;
mod keyfile;
mod peer;
mod transcript;

pub use identity::{
    CryptoError, DeviceKeypair, DevicePublicKey, Fingerprint, sign_auth, verify_auth,
};
pub use keyfile::generate_key_file;
pub use peer::{
    EphemeralPeerKey, PEER_HANDSHAKE_TAG_BYTES, PEER_TRANSPORT_BINDING_BYTES, PeerCryptoError,
    PeerFrameOpener, PeerFrameSealer, PeerRole, PeerSessionKeys, PeerTranscript,
    sign_peer_envelope, verify_peer_envelope,
};
pub use transcript::AuthTranscript;
