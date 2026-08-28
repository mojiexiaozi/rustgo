use std::ops::BitOr;

use rustgo_protocol::{
    BoundExceeded, BoundedBytes, BoundedString, BoundedVec, Message, MessageId,
    OpaquePeerRelayFrame, OpaqueRendezvousMessage, ProtocolVersion, SocketAddress, TunnelProtocol,
};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub const MAX_CANDIDATES: usize = 32;
pub const MAX_DEVICE_NAME_BYTES: usize = 128;
pub const MAX_EXPORT_NAME_BYTES: usize = 128;
pub const MAX_FOUNDATION_BYTES: usize = 64;
pub const MAX_OBSERVATION_SOURCE_BYTES: usize = 128;
pub const MAX_EPHEMERAL_PUBLIC_KEY_BYTES: usize = 64;
pub const MAX_SIGNATURE_BYTES: usize = 128;
pub const MAX_ERROR_DETAIL_BYTES: usize = 512;
pub const MAX_PEER_RELAY_CIPHERTEXT_BYTES: usize = 65_536;
pub const OBSERVATION_TOKEN_BYTES: usize = 32;
pub const OBSERVATION_NONCE_BYTES: usize = 16;
const MAX_POSTCARD_U16_BYTES: usize = 3;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObservationToken([u8; OBSERVATION_TOKEN_BYTES]);

impl ObservationToken {
    pub const fn as_bytes(&self) -> &[u8; OBSERVATION_TOKEN_BYTES] {
        &self.0
    }
}

impl From<[u8; OBSERVATION_TOKEN_BYTES]> for ObservationToken {
    fn from(value: [u8; OBSERVATION_TOKEN_BYTES]) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for ObservationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ObservationToken([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObservationNonce([u8; OBSERVATION_NONCE_BYTES]);

impl From<[u8; OBSERVATION_NONCE_BYTES]> for ObservationNonce {
    fn from(value: [u8; OBSERVATION_NONCE_BYTES]) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObservationEndpoint {
    Primary,
    Alternate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationGrant {
    primary_token: ObservationToken,
    alternate_token: ObservationToken,
    expires_unix_secs: u64,
}

impl ObservationGrant {
    pub const fn new(
        primary_token: ObservationToken,
        alternate_token: ObservationToken,
        expires_unix_secs: u64,
    ) -> Self {
        Self {
            primary_token,
            alternate_token,
            expires_unix_secs,
        }
    }

    pub const fn primary_token(&self) -> &ObservationToken {
        &self.primary_token
    }

    pub const fn alternate_token(&self) -> &ObservationToken {
        &self.alternate_token
    }

    pub const fn expires_unix_secs(&self) -> u64 {
        self.expires_unix_secs
    }

    pub fn to_protocol_message(&self) -> Result<Message, ObservationWireError> {
        let encoded = encode_bounded(self, rustgo_protocol::MAX_OBSERVATION_GRANT_BYTES)?;
        let opaque = rustgo_protocol::OpaqueObservationGrant::try_from(encoded)
            .map_err(|_| ObservationWireError::TooLarge)?;
        Ok(Message::ObservationGrant(opaque))
    }

    pub fn from_protocol_message(message: Message) -> Result<Self, ObservationWireError> {
        let Message::ObservationGrant(opaque) = message else {
            return Err(ObservationWireError::WrongControlMessage);
        };
        decode_bounded(
            opaque.as_slice(),
            rustgo_protocol::MAX_OBSERVATION_GRANT_BYTES,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationProbe {
    token: ObservationToken,
    nonce: ObservationNonce,
}

impl ObservationProbe {
    pub const MAX_WIRE_BYTES: usize = OBSERVATION_TOKEN_BYTES + OBSERVATION_NONCE_BYTES;

    pub const fn new(token: ObservationToken, nonce: ObservationNonce) -> Self {
        Self { token, nonce }
    }

    pub const fn token(&self) -> &ObservationToken {
        &self.token
    }

    pub const fn nonce(&self) -> ObservationNonce {
        self.nonce
    }

    pub fn encode(&self) -> Result<Vec<u8>, ObservationWireError> {
        encode_bounded(self, Self::MAX_WIRE_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ObservationWireError> {
        decode_bounded(bytes, Self::MAX_WIRE_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationReply {
    nonce: ObservationNonce,
    observed_source: SocketAddress,
    endpoint: ObservationEndpoint,
}

impl ObservationReply {
    pub const MAX_WIRE_BYTES: usize = OBSERVATION_NONCE_BYTES + 1 + 16 + MAX_POSTCARD_U16_BYTES + 1;

    pub const fn new(
        nonce: ObservationNonce,
        observed_source: SocketAddress,
        endpoint: ObservationEndpoint,
    ) -> Self {
        Self {
            nonce,
            observed_source,
            endpoint,
        }
    }

    pub const fn nonce(&self) -> ObservationNonce {
        self.nonce
    }

    pub const fn observed_source(&self) -> &SocketAddress {
        &self.observed_source
    }

    pub const fn endpoint(&self) -> ObservationEndpoint {
        self.endpoint
    }

    pub fn encode(&self) -> Result<Vec<u8>, ObservationWireError> {
        encode_bounded(self, Self::MAX_WIRE_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ObservationWireError> {
        decode_bounded(bytes, Self::MAX_WIRE_BYTES)
    }
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ObservationWireError> {
    let encoded = postcard::to_allocvec(value).map_err(ObservationWireError::Codec)?;
    if encoded.len() > maximum {
        return Err(ObservationWireError::TooLarge);
    }
    Ok(encoded)
}

fn decode_bounded<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    maximum: usize,
) -> Result<T, ObservationWireError> {
    if bytes.len() > maximum {
        return Err(ObservationWireError::TooLarge);
    }
    postcard::from_bytes(bytes).map_err(ObservationWireError::Codec)
}

#[derive(Debug, Error)]
pub enum ObservationWireError {
    #[error("observation packet exceeds its fixed wire bound")]
    TooLarge,
    #[error("invalid observation packet: {0}")]
    Codec(postcard::Error),
    #[error("control message does not contain an observation grant")]
    WrongControlMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

impl SessionId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SessionId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct CandidateGeneration(u64);

impl CandidateGeneration {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for CandidateGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).ok_or_else(|| de::Error::custom("candidate generation must be nonzero"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CandidateTransport {
    QuicUdp,
    NativeTcp,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub transport: CandidateTransport,
    pub address: SocketAddress,
    pub priority: u32,
    pub foundation: BoundedString<MAX_FOUNDATION_BYTES>,
    pub generation: CandidateGeneration,
    pub expires_unix_secs: u64,
    pub observation_source: BoundedString<MAX_OBSERVATION_SOURCE_BYTES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousRequest {
    pub export: BoundedString<MAX_EXPORT_NAME_BYTES>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDecision {
    accepted: bool,
    protocol: Option<TunnelProtocol>,
    detail: Option<BoundedString<MAX_ERROR_DETAIL_BYTES>>,
}

impl ProviderDecision {
    pub const fn accepted(protocol: TunnelProtocol) -> Self {
        Self {
            accepted: true,
            protocol: Some(protocol),
            detail: None,
        }
    }

    pub const fn rejected(detail: Option<BoundedString<MAX_ERROR_DETAIL_BYTES>>) -> Self {
        Self {
            accepted: false,
            protocol: None,
            detail,
        }
    }

    pub const fn is_accepted(&self) -> bool {
        self.accepted
    }

    pub const fn protocol(&self) -> Option<TunnelProtocol> {
        self.protocol
    }

    pub const fn detail(&self) -> Option<&BoundedString<MAX_ERROR_DETAIL_BYTES>> {
        self.detail.as_ref()
    }
}

impl Serialize for ProviderDecision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            accepted: bool,
            protocol: Option<TunnelProtocol>,
            detail: Option<&'a BoundedString<MAX_ERROR_DETAIL_BYTES>>,
        }

        Wire {
            accepted: self.accepted,
            protocol: self.protocol,
            detail: self.detail.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProviderDecision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            accepted: bool,
            protocol: Option<TunnelProtocol>,
            detail: Option<BoundedString<MAX_ERROR_DETAIL_BYTES>>,
        }

        let wire = Wire::deserialize(deserializer)?;
        match (wire.accepted, wire.protocol, wire.detail) {
            (true, Some(protocol), None) => Ok(Self::accepted(protocol)),
            (false, None, detail) => Ok(Self::rejected(detail)),
            _ => Err(de::Error::custom(
                "invalid provider decision protocol fields",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateSet {
    pub ephemeral_public_key: BoundedBytes<MAX_EPHEMERAL_PUBLIC_KEY_BYTES>,
    pub candidates: BoundedVec<Candidate, MAX_CANDIDATES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectivityResult {
    pub connected: bool,
    pub transport: Option<CandidateTransport>,
    pub detail: Option<BoundedString<MAX_ERROR_DETAIL_BYTES>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRequest {
    pub datagram: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousClose {
    pub detail: Option<BoundedString<MAX_ERROR_DETAIL_BYTES>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousError {
    pub code: u16,
    pub detail: BoundedString<MAX_ERROR_DETAIL_BYTES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RendezvousPayload {
    Request(RendezvousRequest),
    ProviderDecision(ProviderDecision),
    CandidateSet(CandidateSet),
    ConnectivityResult(ConnectivityResult),
    RelayRequest(RelayRequest),
    Close(RendezvousClose),
    Error(RendezvousError),
}

impl RendezvousPayload {
    pub const fn message_id(&self) -> MessageId {
        match self {
            Self::Request(_) => MessageId::RENDEZVOUS_REQUEST,
            Self::ProviderDecision(_) => MessageId::RENDEZVOUS_PROVIDER_DECISION,
            Self::CandidateSet(_) => MessageId::RENDEZVOUS_CANDIDATE_SET,
            Self::ConnectivityResult(_) => MessageId::RENDEZVOUS_CONNECTIVITY_RESULT,
            Self::RelayRequest(_) => MessageId::RENDEZVOUS_RELAY_REQUEST,
            Self::Close(_) => MessageId::RENDEZVOUS_CLOSE,
            Self::Error(_) => MessageId::RENDEZVOUS_ERROR,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousEnvelope {
    pub version: ProtocolVersion,
    pub session_id: SessionId,
    pub sender: BoundedString<MAX_DEVICE_NAME_BYTES>,
    pub target: BoundedString<MAX_DEVICE_NAME_BYTES>,
    pub step: u64,
    pub generation: CandidateGeneration,
    pub expires_unix_secs: u64,
    pub payload: RendezvousPayload,
    pub signature: BoundedBytes<MAX_SIGNATURE_BYTES>,
}

impl RendezvousEnvelope {
    pub const fn message_id(&self) -> MessageId {
        self.payload.message_id()
    }

    pub const fn is_expired_at(&self, now_unix_secs: u64) -> bool {
        self.expires_unix_secs <= now_unix_secs
    }

    pub fn to_protocol_message(&self) -> Result<Message, WireError> {
        let encoded = postcard::to_allocvec(self).map_err(|_| WireError::Encode)?;
        let opaque =
            OpaqueRendezvousMessage::try_from(encoded).map_err(WireError::EnvelopeTooLarge)?;
        Ok(match self.message_id() {
            MessageId::RENDEZVOUS_REQUEST => Message::RendezvousRequest(opaque),
            MessageId::RENDEZVOUS_PROVIDER_DECISION => Message::RendezvousProviderDecision(opaque),
            MessageId::RENDEZVOUS_CANDIDATE_SET => Message::RendezvousCandidateSet(opaque),
            MessageId::RENDEZVOUS_CONNECTIVITY_RESULT => {
                Message::RendezvousConnectivityResult(opaque)
            }
            MessageId::RENDEZVOUS_RELAY_REQUEST => Message::RendezvousRelayRequest(opaque),
            MessageId::RENDEZVOUS_CLOSE => Message::RendezvousClose(opaque),
            MessageId::RENDEZVOUS_ERROR => Message::RendezvousError(opaque),
            _ => unreachable!("rendezvous payloads map only to rendezvous message IDs"),
        })
    }

    pub fn from_protocol_message(message: Message) -> Result<Self, WireError> {
        let actual = message.id();
        let opaque = match message {
            Message::RendezvousRequest(value)
            | Message::RendezvousProviderDecision(value)
            | Message::RendezvousCandidateSet(value)
            | Message::RendezvousConnectivityResult(value)
            | Message::RendezvousRelayRequest(value)
            | Message::RendezvousClose(value)
            | Message::RendezvousError(value) => value,
            _ => return Err(WireError::NotRendezvousMessage(actual)),
        };
        let envelope: Self =
            postcard::from_bytes(opaque.as_slice()).map_err(|_| WireError::Decode)?;
        let expected = envelope.message_id();
        if expected != actual {
            return Err(WireError::MessageIdMismatch { expected, actual });
        }
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerRelayFlags(u8);

impl PeerRelayFlags {
    pub const RELIABLE: Self = Self(0x01);
    pub const DATAGRAM: Self = Self(0x02);
    pub const FIN: Self = Self(0x04);
    const SUPPORTED: u8 = Self::RELIABLE.0 | Self::DATAGRAM.0 | Self::FIN.0;

    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for PeerRelayFlags {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value & !Self::SUPPORTED == 0 {
            Ok(Self(value))
        } else {
            Err(WireError::UnsupportedRelayFlags(value))
        }
    }
}

impl BitOr for PeerRelayFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl Serialize for PeerRelayFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for PeerRelayFlags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(u8::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRelayFrame {
    pub session_id: SessionId,
    pub channel_id: u64,
    pub sequence: u64,
    pub flags: PeerRelayFlags,
    ciphertext_len: u32,
    ciphertext: BoundedBytes<MAX_PEER_RELAY_CIPHERTEXT_BYTES>,
}

impl PeerRelayFrame {
    pub fn new(
        session_id: SessionId,
        channel_id: u64,
        sequence: u64,
        flags: PeerRelayFlags,
        ciphertext: Vec<u8>,
    ) -> Result<Self, WireError> {
        if channel_id == 0 {
            return Err(WireError::ZeroRelayChannel);
        }
        let ciphertext_len =
            u32::try_from(ciphertext.len()).map_err(|_| WireError::CiphertextTooLarge)?;
        let ciphertext =
            BoundedBytes::try_from(ciphertext).map_err(|_| WireError::CiphertextTooLarge)?;
        Ok(Self {
            session_id,
            channel_id,
            sequence,
            flags,
            ciphertext_len,
            ciphertext,
        })
    }

    pub const fn ciphertext_len(&self) -> u32 {
        self.ciphertext_len
    }

    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }

    pub fn to_protocol_message(&self) -> Result<Message, WireError> {
        let encoded = postcard::to_allocvec(self).map_err(|_| WireError::Encode)?;
        let opaque =
            OpaquePeerRelayFrame::try_from(encoded).map_err(WireError::RelayFrameTooLarge)?;
        Ok(Message::PeerRelayFrame(opaque))
    }

    pub fn from_protocol_message(message: Message) -> Result<Self, WireError> {
        let id = message.id();
        let Message::PeerRelayFrame(opaque) = message else {
            return Err(WireError::NotPeerRelayFrame(id));
        };
        postcard::from_bytes(opaque.as_slice()).map_err(|_| WireError::Decode)
    }
}

impl Serialize for PeerRelayFrame {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            session_id: SessionId,
            channel_id: u64,
            sequence: u64,
            flags: PeerRelayFlags,
            ciphertext_len: u32,
            ciphertext: &'a BoundedBytes<MAX_PEER_RELAY_CIPHERTEXT_BYTES>,
        }

        Wire {
            session_id: self.session_id,
            channel_id: self.channel_id,
            sequence: self.sequence,
            flags: self.flags,
            ciphertext_len: self.ciphertext_len,
            ciphertext: &self.ciphertext,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PeerRelayFrame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            session_id: SessionId,
            channel_id: u64,
            sequence: u64,
            flags: PeerRelayFlags,
            ciphertext_len: u32,
            ciphertext: BoundedBytes<MAX_PEER_RELAY_CIPHERTEXT_BYTES>,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.channel_id == 0 {
            return Err(de::Error::custom("relay channel ID must be nonzero"));
        }
        if usize::try_from(wire.ciphertext_len).ok() != Some(wire.ciphertext.as_slice().len()) {
            return Err(de::Error::custom("relay ciphertext length mismatch"));
        }
        Ok(Self {
            session_id: wire.session_id,
            channel_id: wire.channel_id,
            sequence: wire.sequence,
            flags: wire.flags,
            ciphertext_len: wire.ciphertext_len,
            ciphertext: wire.ciphertext,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WireError {
    #[error("rendezvous wire encoding failed")]
    Encode,
    #[error("rendezvous wire decoding failed")]
    Decode,
    #[error("rendezvous envelope exceeds its wire bound: {0}")]
    EnvelopeTooLarge(BoundExceeded),
    #[error("peer relay frame exceeds its wire bound: {0}")]
    RelayFrameTooLarge(BoundExceeded),
    #[error("peer relay ciphertext exceeds its bound")]
    CiphertextTooLarge,
    #[error("peer relay channel ID must be nonzero")]
    ZeroRelayChannel,
    #[error("unsupported peer relay flags {0:#04x}")]
    UnsupportedRelayFlags(u8),
    #[error("rendezvous inner message ID {expected:?} does not match outer ID {actual:?}")]
    MessageIdMismatch {
        expected: MessageId,
        actual: MessageId,
    },
    #[error("message {0:?} is not a rendezvous message")]
    NotRendezvousMessage(MessageId),
    #[error("message {0:?} is not a peer relay frame")]
    NotPeerRelayFrame(MessageId),
}
