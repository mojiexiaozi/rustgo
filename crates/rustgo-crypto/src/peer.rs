use std::{collections::HashSet, fmt};

use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use rand::{TryRngCore as _, rngs::OsRng};
use rustgo_protocol::{BoundedBytes, BoundedString, ProtocolVersion, SocketAddress};
use rustgo_rendezvous::{
    Candidate, CandidateGeneration, CandidateTransport, ConnectivityResult, MAX_EXPORT_NAME_BYTES,
    MAX_PEER_RELAY_CIPHERTEXT_BYTES, MAX_SIGNATURE_BYTES, PeerRelayFlags, PeerRelayFrame,
    RendezvousEnvelope, RendezvousPayload, SessionId,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{DeviceKeypair, DevicePublicKey};

const ENVELOPE_DOMAIN: &[u8] = b"rustgo-peer-envelope-v1";
const SESSION_DOMAIN: &[u8] = b"rustgo-peer-session-v1";
const FRAME_DOMAIN: &[u8] = b"rustgo-peer-frame-v1";
const FRAME_KEY_DOMAIN: &[u8] = b"rustgo-peer-frame-key-v1";
const HANDSHAKE_DOMAIN: &[u8] = b"rustgo-peer-handshake-confirmation-v1";
const AEAD_TAG_BYTES: usize = 16;
const REPLAY_WINDOW_BITS: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Initiator,
    Responder,
}

impl PeerRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 2,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PeerCryptoError {
    #[error("peer envelope signature verification failed")]
    SignatureVerificationFailed,
    #[error("local ephemeral key does not match the claimed peer role")]
    LocalEphemeralKeyMismatch,
    #[error("peer ephemeral key is not contributory")]
    InvalidPeerEphemeralKey,
    #[error("peer key derivation failed")]
    KeyDerivationFailed,
    #[error("peer handshake confirmation failed")]
    HandshakeAuthenticationFailed,
    #[error("peer frame authentication failed")]
    FrameAuthenticationFailed,
    #[error("peer frame belongs to a different session or channel")]
    FrameContextMismatch,
    #[error("peer frame channel or flags are invalid for this cipher")]
    InvalidFrameContext,
    #[error("peer frame cryptographic domain was already issued")]
    DomainAlreadyIssued,
    #[error("peer frame flags violate the ordered channel lifecycle")]
    InvalidFlagTransition,
    #[error("peer frame sequence was already used or is outside the replay window")]
    Replay,
    #[error("ordered peer frame sequence is not the exact next value")]
    UnexpectedSequence,
    #[error("peer frame sequence space is exhausted")]
    SequenceExhausted,
    #[error("peer frame plaintext exceeds the ciphertext bound")]
    FrameTooLarge,
}

/// A process-local, single-owner ephemeral X25519 key.
///
/// Raw secret reconstruction is intentionally not part of the public API:
///
/// ```compile_fail
/// use rustgo_crypto::EphemeralPeerKey;
///
/// let _key = EphemeralPeerKey::from_secret_bytes([0x42; 32]);
/// ```
///
/// Ephemeral keys cannot be cloned into a second key schedule:
///
/// ```compile_fail
/// use rustgo_crypto::EphemeralPeerKey;
///
/// let key = EphemeralPeerKey::generate();
/// let _duplicate = key.clone();
/// ```
pub struct EphemeralPeerKey {
    secret: StaticSecret,
}

impl EphemeralPeerKey {
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(secret.as_mut())
            .expect("operating-system randomness unavailable for ephemeral peer key");
        Self {
            secret: StaticSecret::from(*secret),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.secret).to_bytes()
    }
}

impl fmt::Debug for EphemeralPeerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralPeerKey([REDACTED])")
    }
}

pub struct PeerTranscript {
    encoded: Vec<u8>,
    session_id: SessionId,
    initiator_ephemeral: [u8; 32],
    responder_ephemeral: [u8; 32],
}

impl PeerTranscript {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        session_id: SessionId,
        generation: CandidateGeneration,
        initiator_identity: DevicePublicKey,
        responder_identity: DevicePublicKey,
        initiator_ephemeral: [u8; 32],
        responder_ephemeral: [u8; 32],
        export: BoundedString<MAX_EXPORT_NAME_BYTES>,
        version: ProtocolVersion,
        rendezvous_transcript_hash: [u8; 32],
    ) -> Self {
        let mut encoded = Vec::with_capacity(256 + export.as_str().len());
        encoded.extend_from_slice(SESSION_DOMAIN);
        append_bytes(&mut encoded, session_id.as_bytes());
        append_u64(&mut encoded, generation.get());
        append_role(
            &mut encoded,
            PeerRole::Initiator,
            &initiator_identity,
            &initiator_ephemeral,
        );
        append_role(
            &mut encoded,
            PeerRole::Responder,
            &responder_identity,
            &responder_ephemeral,
        );
        append_bytes(&mut encoded, export.as_str().as_bytes());
        append_u16(&mut encoded, version.major);
        append_u16(&mut encoded, version.minor);
        append_bytes(&mut encoded, &rendezvous_transcript_hash);
        Self {
            encoded,
            session_id,
            initiator_ephemeral,
            responder_ephemeral,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    fn local_ephemeral(&self, role: PeerRole) -> &[u8; 32] {
        match role {
            PeerRole::Initiator => &self.initiator_ephemeral,
            PeerRole::Responder => &self.responder_ephemeral,
        }
    }

    fn peer_ephemeral(&self, role: PeerRole) -> &[u8; 32] {
        match role {
            PeerRole::Initiator => &self.responder_ephemeral,
            PeerRole::Responder => &self.initiator_ephemeral,
        }
    }
}

impl fmt::Debug for PeerTranscript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerTranscript")
            .field("session_id", &self.session_id)
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(self.0.as_ref()))
    }
}

struct HandshakeKey(SecretKey);
struct StreamKey(SecretKey);
struct DatagramKey(SecretKey);

pub struct PeerSessionKeys {
    role: PeerRole,
    session_id: SessionId,
    context_hash: [u8; 32],
    handshake_initiator_to_responder: HandshakeKey,
    handshake_responder_to_initiator: HandshakeKey,
    stream_initiator_to_responder: StreamKey,
    stream_responder_to_initiator: StreamKey,
    datagram_initiator_to_responder: DatagramKey,
    datagram_responder_to_initiator: DatagramKey,
    issued_sealers: HashSet<FrameDomain>,
    issued_openers: HashSet<FrameDomain>,
}

impl PeerSessionKeys {
    pub fn derive(
        role: PeerRole,
        local_ephemeral: EphemeralPeerKey,
        transcript: &PeerTranscript,
    ) -> Result<Self, PeerCryptoError> {
        if local_ephemeral.public_key() != *transcript.local_ephemeral(role) {
            return Err(PeerCryptoError::LocalEphemeralKeyMismatch);
        }
        let peer_public = X25519PublicKey::from(*transcript.peer_ephemeral(role));
        let shared = local_ephemeral.secret.diffie_hellman(&peer_public);
        if !shared.was_contributory() {
            return Err(PeerCryptoError::InvalidPeerEphemeralKey);
        }

        let context_hash: [u8; 32] = Sha256::digest(transcript.as_bytes()).into();
        let shared_bytes = Zeroizing::new(*shared.as_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(&context_hash), shared_bytes.as_ref());
        Ok(Self {
            role,
            session_id: transcript.session_id,
            context_hash,
            handshake_initiator_to_responder: HandshakeKey(expand_key(
                &hkdf,
                b"rustgo-peer-handshake-initiator-to-responder-v1",
            )?),
            handshake_responder_to_initiator: HandshakeKey(expand_key(
                &hkdf,
                b"rustgo-peer-handshake-responder-to-initiator-v1",
            )?),
            stream_initiator_to_responder: StreamKey(expand_key(
                &hkdf,
                b"rustgo-peer-stream-initiator-to-responder-v1",
            )?),
            stream_responder_to_initiator: StreamKey(expand_key(
                &hkdf,
                b"rustgo-peer-stream-responder-to-initiator-v1",
            )?),
            datagram_initiator_to_responder: DatagramKey(expand_key(
                &hkdf,
                b"rustgo-peer-datagram-initiator-to-responder-v1",
            )?),
            datagram_responder_to_initiator: DatagramKey(expand_key(
                &hkdf,
                b"rustgo-peer-datagram-responder-to-initiator-v1",
            )?),
            issued_sealers: HashSet::new(),
            issued_openers: HashSet::new(),
        })
    }

    #[must_use]
    pub fn handshake_tag(&self) -> [u8; AEAD_TAG_BYTES] {
        let cipher = self.outgoing_handshake_key().0.cipher();
        let mut empty = [];
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&[0_u8; 12]),
                &handshake_aad(&self.context_hash),
                &mut empty,
            )
            .expect("empty ChaCha20-Poly1305 handshake tag cannot fail");
        tag.into()
    }

    pub fn verify_handshake_tag(&self, tag: &[u8; AEAD_TAG_BYTES]) -> Result<(), PeerCryptoError> {
        let cipher = self.incoming_handshake_key().0.cipher();
        let mut empty = [];
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&[0_u8; 12]),
                &handshake_aad(&self.context_hash),
                &mut empty,
                Tag::from_slice(tag),
            )
            .map_err(|_| PeerCryptoError::HandshakeAuthenticationFailed)
    }

    pub fn stream_sealer(&mut self, channel_id: u64) -> Result<PeerFrameSealer, PeerCryptoError> {
        let domain = self.issue_sealer(FrameMode::Ordered, channel_id)?;
        PeerFrameSealer::new(
            self.session_id,
            domain.channel_id,
            self.context_hash,
            derive_frame_key(
                &self.outgoing_stream_key().0,
                &self.context_hash,
                &self.session_id,
                domain.mode,
                domain.channel_id,
            )?,
            domain.mode,
            nonce_prefix(FrameMode::Ordered, self.outgoing_direction()),
        )
    }

    pub fn stream_opener(&mut self, channel_id: u64) -> Result<PeerFrameOpener, PeerCryptoError> {
        let domain = self.issue_opener(FrameMode::Ordered, channel_id)?;
        PeerFrameOpener::new(
            self.session_id,
            domain.channel_id,
            self.context_hash,
            derive_frame_key(
                &self.incoming_stream_key().0,
                &self.context_hash,
                &self.session_id,
                domain.mode,
                domain.channel_id,
            )?,
            domain.mode,
            nonce_prefix(FrameMode::Ordered, self.incoming_direction()),
        )
    }

    pub fn datagram_sealer(&mut self, channel_id: u64) -> Result<PeerFrameSealer, PeerCryptoError> {
        let domain = self.issue_sealer(FrameMode::Datagram, channel_id)?;
        PeerFrameSealer::new(
            self.session_id,
            domain.channel_id,
            self.context_hash,
            derive_frame_key(
                &self.outgoing_datagram_key().0,
                &self.context_hash,
                &self.session_id,
                domain.mode,
                domain.channel_id,
            )?,
            domain.mode,
            nonce_prefix(FrameMode::Datagram, self.outgoing_direction()),
        )
    }

    pub fn datagram_opener(&mut self, channel_id: u64) -> Result<PeerFrameOpener, PeerCryptoError> {
        let domain = self.issue_opener(FrameMode::Datagram, channel_id)?;
        PeerFrameOpener::new(
            self.session_id,
            domain.channel_id,
            self.context_hash,
            derive_frame_key(
                &self.incoming_datagram_key().0,
                &self.context_hash,
                &self.session_id,
                domain.mode,
                domain.channel_id,
            )?,
            domain.mode,
            nonce_prefix(FrameMode::Datagram, self.incoming_direction()),
        )
    }

    fn issue_sealer(
        &mut self,
        mode: FrameMode,
        channel_id: u64,
    ) -> Result<FrameDomain, PeerCryptoError> {
        issue_domain(&mut self.issued_sealers, mode, channel_id)
    }

    fn issue_opener(
        &mut self,
        mode: FrameMode,
        channel_id: u64,
    ) -> Result<FrameDomain, PeerCryptoError> {
        issue_domain(&mut self.issued_openers, mode, channel_id)
    }

    fn outgoing_direction(&self) -> PeerRole {
        self.role
    }

    fn incoming_direction(&self) -> PeerRole {
        match self.role {
            PeerRole::Initiator => PeerRole::Responder,
            PeerRole::Responder => PeerRole::Initiator,
        }
    }

    fn outgoing_handshake_key(&self) -> &HandshakeKey {
        match self.role {
            PeerRole::Initiator => &self.handshake_initiator_to_responder,
            PeerRole::Responder => &self.handshake_responder_to_initiator,
        }
    }

    fn incoming_handshake_key(&self) -> &HandshakeKey {
        match self.role {
            PeerRole::Initiator => &self.handshake_responder_to_initiator,
            PeerRole::Responder => &self.handshake_initiator_to_responder,
        }
    }

    fn outgoing_stream_key(&self) -> &StreamKey {
        match self.role {
            PeerRole::Initiator => &self.stream_initiator_to_responder,
            PeerRole::Responder => &self.stream_responder_to_initiator,
        }
    }

    fn incoming_stream_key(&self) -> &StreamKey {
        match self.role {
            PeerRole::Initiator => &self.stream_responder_to_initiator,
            PeerRole::Responder => &self.stream_initiator_to_responder,
        }
    }

    fn outgoing_datagram_key(&self) -> &DatagramKey {
        match self.role {
            PeerRole::Initiator => &self.datagram_initiator_to_responder,
            PeerRole::Responder => &self.datagram_responder_to_initiator,
        }
    }

    fn incoming_datagram_key(&self) -> &DatagramKey {
        match self.role {
            PeerRole::Initiator => &self.datagram_responder_to_initiator,
            PeerRole::Responder => &self.datagram_initiator_to_responder,
        }
    }
}

impl fmt::Debug for PeerSessionKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerSessionKeys([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum FrameMode {
    Ordered,
    Datagram,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FrameDomain {
    mode: FrameMode,
    channel_id: u64,
}

pub struct PeerFrameSealer {
    session_id: SessionId,
    channel_id: u64,
    context_hash: [u8; 32],
    key: SecretKey,
    mode: FrameMode,
    nonce_prefix: [u8; 4],
    next_sequence: u64,
    exhausted: bool,
    finished: bool,
}

impl PeerFrameSealer {
    fn new(
        session_id: SessionId,
        channel_id: u64,
        context_hash: [u8; 32],
        key: SecretKey,
        mode: FrameMode,
        nonce_prefix: [u8; 4],
    ) -> Result<Self, PeerCryptoError> {
        validate_channel_id(channel_id)?;
        Ok(Self {
            session_id,
            channel_id,
            context_hash,
            key,
            mode,
            nonce_prefix,
            next_sequence: 0,
            exhausted: false,
            finished: false,
        })
    }

    pub fn seal(
        &mut self,
        plaintext: &[u8],
        flags: PeerRelayFlags,
    ) -> Result<PeerRelayFrame, PeerCryptoError> {
        if plaintext.len() > MAX_PEER_RELAY_CIPHERTEXT_BYTES.saturating_sub(AEAD_TAG_BYTES) {
            return Err(PeerCryptoError::FrameTooLarge);
        }
        validate_frame_flags(self.mode, flags)?;
        validate_flag_transition(self.mode, self.finished)?;
        if self.exhausted {
            return Err(PeerCryptoError::SequenceExhausted);
        }
        let sequence = self.next_sequence;
        let nonce = frame_nonce(self.nonce_prefix, sequence);
        let aad = frame_aad(
            &self.context_hash,
            &self.session_id,
            self.channel_id,
            flags,
            sequence,
        );
        let ciphertext = self
            .key
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| PeerCryptoError::FrameTooLarge)?;
        let frame = PeerRelayFrame::new(
            self.session_id,
            self.channel_id,
            sequence,
            flags,
            ciphertext,
        )
        .map_err(|_| PeerCryptoError::FrameTooLarge)?;
        match sequence.checked_add(1) {
            Some(next) => self.next_sequence = next,
            None => self.exhausted = true,
        }
        self.finished = self.finished || has_fin(flags);
        Ok(frame)
    }
}

impl fmt::Debug for PeerFrameSealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerFrameSealer([REDACTED])")
    }
}

#[derive(Clone, Copy)]
enum ReceiveState {
    Ordered { expected: u64, exhausted: bool },
    Datagram(ReplayWindow),
}

#[derive(Clone, Copy)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

pub struct PeerFrameOpener {
    session_id: SessionId,
    channel_id: u64,
    context_hash: [u8; 32],
    key: SecretKey,
    mode: FrameMode,
    nonce_prefix: [u8; 4],
    state: ReceiveState,
    finished: bool,
}

impl PeerFrameOpener {
    fn new(
        session_id: SessionId,
        channel_id: u64,
        context_hash: [u8; 32],
        key: SecretKey,
        mode: FrameMode,
        nonce_prefix: [u8; 4],
    ) -> Result<Self, PeerCryptoError> {
        validate_channel_id(channel_id)?;
        let state = match mode {
            FrameMode::Ordered => ReceiveState::Ordered {
                expected: 0,
                exhausted: false,
            },
            FrameMode::Datagram => ReceiveState::Datagram(ReplayWindow {
                highest: None,
                bitmap: 0,
            }),
        };
        Ok(Self {
            session_id,
            channel_id,
            context_hash,
            key,
            mode,
            nonce_prefix,
            state,
            finished: false,
        })
    }

    pub fn open(&mut self, frame: &PeerRelayFrame) -> Result<Vec<u8>, PeerCryptoError> {
        if frame.session_id != self.session_id || frame.channel_id != self.channel_id {
            return Err(PeerCryptoError::FrameContextMismatch);
        }
        validate_frame_flags(self.mode, frame.flags)?;
        let next_state = receive_sequence(self.state, frame.sequence)?;
        validate_flag_transition(self.mode, self.finished)?;
        let nonce = frame_nonce(self.nonce_prefix, frame.sequence);
        let aad = frame_aad(
            &self.context_hash,
            &frame.session_id,
            frame.channel_id,
            frame.flags,
            frame.sequence,
        );
        let plaintext = self
            .key
            .cipher()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: frame.ciphertext(),
                    aad: &aad,
                },
            )
            .map_err(|_| PeerCryptoError::FrameAuthenticationFailed)?;
        self.state = next_state;
        self.finished = self.finished || has_fin(frame.flags);
        Ok(plaintext)
    }
}

impl fmt::Debug for PeerFrameOpener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerFrameOpener([REDACTED])")
    }
}

pub fn sign_peer_envelope(
    keypair: &DeviceKeypair,
    envelope: &RendezvousEnvelope,
) -> Result<BoundedBytes<MAX_SIGNATURE_BYTES>, PeerCryptoError> {
    let transcript = encode_envelope(envelope);
    BoundedBytes::try_from(keypair.sign_bytes(&transcript).to_vec())
        .map_err(|_| PeerCryptoError::SignatureVerificationFailed)
}

pub fn verify_peer_envelope(
    expected_public_key: &DevicePublicKey,
    envelope: &RendezvousEnvelope,
) -> Result<(), PeerCryptoError> {
    let transcript = encode_envelope(envelope);
    expected_public_key
        .verify_bytes(&transcript, envelope.signature.as_slice())
        .map_err(|_| PeerCryptoError::SignatureVerificationFailed)
}

fn append_role(
    encoded: &mut Vec<u8>,
    role: PeerRole,
    identity: &DevicePublicKey,
    ephemeral: &[u8; 32],
) {
    encoded.push(role.tag());
    append_bytes(encoded, identity.as_bytes());
    append_bytes(encoded, ephemeral);
}

fn expand_key(hkdf: &Hkdf<Sha256>, label: &[u8]) -> Result<SecretKey, PeerCryptoError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    hkdf.expand(label, bytes.as_mut())
        .map_err(|_| PeerCryptoError::KeyDerivationFailed)?;
    Ok(SecretKey(bytes))
}

fn derive_frame_key(
    base_key: &SecretKey,
    context_hash: &[u8; 32],
    session_id: &SessionId,
    mode: FrameMode,
    channel_id: u64,
) -> Result<SecretKey, PeerCryptoError> {
    let hkdf = Hkdf::<Sha256>::from_prk(base_key.0.as_ref())
        .map_err(|_| PeerCryptoError::KeyDerivationFailed)?;
    let mut info = Vec::with_capacity(FRAME_KEY_DOMAIN.len() + 80);
    info.extend_from_slice(FRAME_KEY_DOMAIN);
    append_bytes(&mut info, context_hash);
    append_bytes(&mut info, session_id.as_bytes());
    info.push(frame_mode_tag(mode));
    append_u64(&mut info, channel_id);
    expand_key(&hkdf, &info)
}

fn handshake_aad(context_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + context_hash.len() + 4);
    aad.extend_from_slice(HANDSHAKE_DOMAIN);
    append_bytes(&mut aad, context_hash);
    aad
}

fn issue_domain(
    issued: &mut HashSet<FrameDomain>,
    mode: FrameMode,
    channel_id: u64,
) -> Result<FrameDomain, PeerCryptoError> {
    validate_channel_id(channel_id)?;
    let domain = FrameDomain { mode, channel_id };
    if issued.insert(domain) {
        Ok(domain)
    } else {
        Err(PeerCryptoError::DomainAlreadyIssued)
    }
}

fn validate_channel_id(channel_id: u64) -> Result<(), PeerCryptoError> {
    if channel_id == 0 {
        return Err(PeerCryptoError::InvalidFrameContext);
    }
    Ok(())
}

fn validate_frame_flags(mode: FrameMode, flags: PeerRelayFlags) -> Result<(), PeerCryptoError> {
    let valid = match mode {
        FrameMode::Ordered => {
            flags == PeerRelayFlags::RELIABLE
                || flags == (PeerRelayFlags::RELIABLE | PeerRelayFlags::FIN)
        }
        FrameMode::Datagram => flags == PeerRelayFlags::DATAGRAM,
    };
    if valid {
        Ok(())
    } else {
        Err(PeerCryptoError::InvalidFrameContext)
    }
}

fn validate_flag_transition(mode: FrameMode, finished: bool) -> Result<(), PeerCryptoError> {
    if matches!(mode, FrameMode::Ordered) && finished {
        Err(PeerCryptoError::InvalidFlagTransition)
    } else {
        Ok(())
    }
}

fn receive_sequence(state: ReceiveState, sequence: u64) -> Result<ReceiveState, PeerCryptoError> {
    match state {
        ReceiveState::Ordered {
            expected: _,
            exhausted: true,
        } => {
            if sequence == u64::MAX {
                Err(PeerCryptoError::Replay)
            } else {
                Err(PeerCryptoError::SequenceExhausted)
            }
        }
        ReceiveState::Ordered {
            expected,
            exhausted: false,
        } if sequence < expected => Err(PeerCryptoError::Replay),
        ReceiveState::Ordered {
            expected,
            exhausted: false,
        } if sequence > expected => Err(PeerCryptoError::UnexpectedSequence),
        ReceiveState::Ordered {
            expected,
            exhausted: false,
        } => {
            let (expected, exhausted) = match expected.checked_add(1) {
                Some(next) => (next, false),
                None => (expected, true),
            };
            Ok(ReceiveState::Ordered {
                expected,
                exhausted,
            })
        }
        ReceiveState::Datagram(window) => {
            replay_window_accept(window, sequence).map(ReceiveState::Datagram)
        }
    }
}

fn replay_window_accept(
    window: ReplayWindow,
    sequence: u64,
) -> Result<ReplayWindow, PeerCryptoError> {
    let Some(highest) = window.highest else {
        return Ok(ReplayWindow {
            highest: Some(sequence),
            bitmap: 1,
        });
    };
    if sequence > highest {
        let distance = sequence - highest;
        let bitmap = if distance >= REPLAY_WINDOW_BITS {
            1
        } else {
            (window.bitmap << distance) | 1
        };
        return Ok(ReplayWindow {
            highest: Some(sequence),
            bitmap,
        });
    }

    let distance = highest - sequence;
    if distance >= REPLAY_WINDOW_BITS || window.bitmap & (1_u64 << distance) != 0 {
        return Err(PeerCryptoError::Replay);
    }
    Ok(ReplayWindow {
        highest: window.highest,
        bitmap: window.bitmap | (1_u64 << distance),
    })
}

fn nonce_prefix(mode: FrameMode, direction: PeerRole) -> [u8; 4] {
    let purpose = frame_mode_tag(mode);
    [purpose, direction.tag(), 0, 0]
}

fn frame_mode_tag(mode: FrameMode) -> u8 {
    match mode {
        FrameMode::Ordered => 1,
        FrameMode::Datagram => 2,
    }
}

fn has_fin(flags: PeerRelayFlags) -> bool {
    flags.bits() & PeerRelayFlags::FIN.bits() != 0
}

fn frame_nonce(prefix: [u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn frame_aad(
    context_hash: &[u8; 32],
    session_id: &SessionId,
    channel_id: u64,
    flags: PeerRelayFlags,
    sequence: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FRAME_DOMAIN.len() + 32 + 32 + 24);
    aad.extend_from_slice(FRAME_DOMAIN);
    append_bytes(&mut aad, context_hash);
    append_bytes(&mut aad, session_id.as_bytes());
    append_u64(&mut aad, channel_id);
    aad.push(flags.bits());
    append_u64(&mut aad, sequence);
    aad
}

fn encode_envelope(envelope: &RendezvousEnvelope) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(ENVELOPE_DOMAIN);
    append_u16(&mut encoded, envelope.version.major);
    append_u16(&mut encoded, envelope.version.minor);
    append_bytes(&mut encoded, envelope.session_id.as_bytes());
    append_bytes(&mut encoded, envelope.sender.as_str().as_bytes());
    append_bytes(&mut encoded, envelope.target.as_str().as_bytes());
    append_u64(&mut encoded, envelope.step);
    append_u64(&mut encoded, envelope.generation.get());
    append_u64(&mut encoded, envelope.expires_unix_secs);
    append_payload(&mut encoded, &envelope.payload);
    encoded
}

fn append_payload(encoded: &mut Vec<u8>, payload: &RendezvousPayload) {
    match payload {
        RendezvousPayload::Request(request) => {
            encoded.push(1);
            append_bytes(encoded, request.export.as_str().as_bytes());
        }
        RendezvousPayload::ProviderDecision(decision) => {
            encoded.push(2);
            encoded.push(u8::from(decision.is_accepted()));
            append_optional_protocol(encoded, decision.protocol());
            append_optional_string(encoded, decision.detail().map(BoundedString::as_str));
        }
        RendezvousPayload::CandidateSet(set) => {
            encoded.push(3);
            append_bytes(encoded, set.ephemeral_public_key.as_slice());
            append_u32(
                encoded,
                u32::try_from(set.candidates.as_slice().len())
                    .expect("bounded candidate collection exceeds u32"),
            );
            for candidate in set.candidates.as_slice() {
                append_candidate(encoded, candidate);
            }
        }
        RendezvousPayload::ConnectivityResult(result) => {
            encoded.push(4);
            append_connectivity_result(encoded, result);
        }
        RendezvousPayload::RelayRequest(request) => {
            encoded.push(5);
            encoded.push(u8::from(request.datagram));
        }
        RendezvousPayload::Close(close) => {
            encoded.push(6);
            append_optional_string(encoded, close.detail.as_ref().map(BoundedString::as_str));
        }
        RendezvousPayload::Error(error) => {
            encoded.push(7);
            append_u16(encoded, error.code);
            append_bytes(encoded, error.detail.as_str().as_bytes());
        }
    }
}

fn append_candidate(encoded: &mut Vec<u8>, candidate: &Candidate) {
    encoded.push(match candidate.transport {
        CandidateTransport::QuicUdp => 1,
        CandidateTransport::NativeTcp => 2,
        CandidateTransport::Relay => 3,
    });
    match &candidate.address {
        SocketAddress::V4 { octets, port } => {
            encoded.push(1);
            append_bytes(encoded, octets);
            append_u16(encoded, *port);
        }
        SocketAddress::V6 { octets, port } => {
            encoded.push(2);
            append_bytes(encoded, octets);
            append_u16(encoded, *port);
        }
    }
    append_u32(encoded, candidate.priority);
    append_bytes(encoded, candidate.foundation.as_str().as_bytes());
    append_u64(encoded, candidate.generation.get());
    append_u64(encoded, candidate.expires_unix_secs);
    append_bytes(encoded, candidate.observation_source.as_str().as_bytes());
}

fn append_connectivity_result(encoded: &mut Vec<u8>, result: &ConnectivityResult) {
    encoded.push(u8::from(result.connected));
    match result.transport {
        None => encoded.push(0),
        Some(CandidateTransport::QuicUdp) => encoded.extend_from_slice(&[1, 1]),
        Some(CandidateTransport::NativeTcp) => encoded.extend_from_slice(&[1, 2]),
        Some(CandidateTransport::Relay) => encoded.extend_from_slice(&[1, 3]),
    }
    append_optional_string(encoded, result.detail.as_ref().map(BoundedString::as_str));
}

fn append_optional_protocol(
    encoded: &mut Vec<u8>,
    protocol: Option<rustgo_protocol::TunnelProtocol>,
) {
    match protocol {
        None => encoded.push(0),
        Some(protocol) => encoded.extend_from_slice(&[1, protocol.as_u8()]),
    }
}

fn append_optional_string(encoded: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => encoded.push(0),
        Some(value) => {
            encoded.push(1);
            append_bytes(encoded, value.as_bytes());
        }
    }
}

fn append_bytes(encoded: &mut Vec<u8>, value: &[u8]) {
    append_u32(
        encoded,
        u32::try_from(value.len()).expect("bounded peer transcript field exceeds u32"),
    );
    encoded.extend_from_slice(value);
}

fn append_u16(encoded: &mut Vec<u8>, value: u16) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn append_u32(encoded: &mut Vec<u8>, value: u32) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(encoded: &mut Vec<u8>, value: u64) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealer_reports_exhaustion_after_allocating_the_last_internal_sequence() {
        let mut sealer = PeerFrameSealer {
            session_id: SessionId::from([0x42; 32]),
            channel_id: 9,
            context_hash: [0x66; 32],
            key: SecretKey(Zeroizing::new([0x77; 32])),
            mode: FrameMode::Datagram,
            nonce_prefix: [2, 1, 0, 0],
            next_sequence: u64::MAX,
            exhausted: false,
            finished: false,
        };

        let final_frame = sealer.seal(b"last", PeerRelayFlags::DATAGRAM).unwrap();
        assert_eq!(final_frame.sequence, u64::MAX);
        assert_eq!(
            sealer.seal(b"wrapped", PeerRelayFlags::DATAGRAM),
            Err(PeerCryptoError::SequenceExhausted)
        );
    }
}
