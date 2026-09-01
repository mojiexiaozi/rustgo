use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::ProtocolVersion;
use crate::message::{
    AuthResult, BoundedBytes, ClientAuthenticate, ClientHello, DataChannelBind, ErrorMessage,
    Heartbeat, MAX_UDP_PAYLOAD_BYTES, Message, MessageId, ObservationGrantRequest, OpenTcpStream,
    OpenUdpChannel, RegisterTunnels, ServerChallenge, ServerNotice, SocketAddress, TcpStreamReady,
    TelemetryReport, TunnelResults, UDP_METADATA_LEN, UdpDatagram, UdpSessionRetired,
};

pub const MAGIC: [u8; 4] = *b"RSGO";
pub const HEADER_LEN: usize = 16;
pub const SUPPORTED_FLAGS: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: ProtocolVersion,
    pub flags: u16,
    pub message: Message,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameError {
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("unknown message ID {0}")]
    UnknownMessage(u16),
    #[error("unsupported frame flags {0:#06x}")]
    UnsupportedFlags(u16),
    #[error("payload length {declared} exceeds frame maximum {max}")]
    PayloadTooLarge { declared: usize, max: usize },
    #[error("payload length {declared} exceeds {message:?} maximum {max}")]
    MessagePayloadTooLarge {
        message: MessageId,
        declared: usize,
        max: usize,
    },
    #[error("truncated frame: need {needed} bytes, have {available}")]
    Truncated { needed: usize, available: usize },
    #[error("malformed payload for {message:?}")]
    MalformedPayload { message: MessageId },
    #[error("frame has {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("encoded payload cannot be represented by the wire length field")]
    LengthOverflow,
}

#[derive(Debug, Clone, Copy)]
pub struct FrameCodec {
    pub max_payload: usize,
}

impl FrameCodec {
    pub const fn new(max_payload: usize) -> Self {
        Self { max_payload }
    }

    pub fn encode(
        &self,
        version: ProtocolVersion,
        flags: u16,
        message: &Message,
    ) -> Result<Bytes, FrameError> {
        validate_flags(flags)?;
        let message_id = message.id();
        let payload = encode_payload(message)?;
        self.validate_payload_length(message_id, payload.len())?;
        let payload_len = u32::try_from(payload.len()).map_err(|_| FrameError::LengthOverflow)?;
        let mut output = BytesMut::with_capacity(HEADER_LEN + payload.len());
        output.extend_from_slice(&MAGIC);
        output.put_u16(version.major);
        output.put_u16(version.minor);
        output.put_u16(message_id.as_u16());
        output.put_u16(flags);
        output.put_u32(payload_len);
        output.extend_from_slice(&payload);
        Ok(output.freeze())
    }

    /// Decodes one complete frame from an incremental input buffer.
    ///
    /// An incomplete frame returns `Ok(None)` without consuming input. A
    /// complete valid frame is consumed. Any validation or payload error also
    /// leaves the offending frame untouched so the caller can capture
    /// diagnostic context before closing the owning connection.
    pub fn decode(&self, input: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        let header = match self.inspect_header(input)? {
            Some(header) => header,
            None => return Ok(None),
        };
        let frame_len = HEADER_LEN + header.payload_len;
        if input.len() < frame_len {
            return Ok(None);
        }
        let message = decode_payload(header.message_id, &input[HEADER_LEN..frame_len])?;
        input.advance(frame_len);
        Ok(Some(Frame {
            version: header.version,
            flags: header.flags,
            message,
        }))
    }

    pub fn decode_exact(&self, input: &[u8]) -> Result<Frame, FrameError> {
        if input.len() < HEADER_LEN {
            return Err(FrameError::Truncated {
                needed: HEADER_LEN,
                available: input.len(),
            });
        }
        let header = self
            .inspect_header(input)?
            .expect("header length was checked above");
        let frame_len = HEADER_LEN + header.payload_len;
        if input.len() < frame_len {
            return Err(FrameError::Truncated {
                needed: frame_len,
                available: input.len(),
            });
        }
        if input.len() > frame_len {
            return Err(FrameError::TrailingBytes(input.len() - frame_len));
        }
        let message = decode_payload(header.message_id, &input[HEADER_LEN..])?;
        Ok(Frame {
            version: header.version,
            flags: header.flags,
            message,
        })
    }

    fn inspect_header(&self, input: &[u8]) -> Result<Option<Header>, FrameError> {
        if input.len() < HEADER_LEN {
            return Ok(None);
        }
        if input[0..4] != MAGIC {
            return Err(FrameError::InvalidMagic);
        }
        let major = u16::from_be_bytes([input[4], input[5]]);
        let minor = u16::from_be_bytes([input[6], input[7]]);
        let raw_message_id = u16::from_be_bytes([input[8], input[9]]);
        let message_id = MessageId::try_from(raw_message_id).map_err(FrameError::UnknownMessage)?;
        let flags = u16::from_be_bytes([input[10], input[11]]);
        validate_flags(flags)?;
        let declared = u32::from_be_bytes([input[12], input[13], input[14], input[15]]);
        let payload_len = usize::try_from(declared).map_err(|_| FrameError::LengthOverflow)?;
        self.validate_payload_length(message_id, payload_len)?;
        Ok(Some(Header {
            version: ProtocolVersion::new(major, minor),
            message_id,
            flags,
            payload_len,
        }))
    }

    fn validate_payload_length(
        &self,
        message: MessageId,
        declared: usize,
    ) -> Result<(), FrameError> {
        if declared > self.max_payload {
            return Err(FrameError::PayloadTooLarge {
                declared,
                max: self.max_payload,
            });
        }
        let message_max = message.max_payload();
        if declared > message_max {
            return Err(FrameError::MessagePayloadTooLarge {
                message,
                declared,
                max: message_max,
            });
        }
        Ok(())
    }
}

fn validate_flags(flags: u16) -> Result<(), FrameError> {
    let unsupported = flags & !SUPPORTED_FLAGS;
    if unsupported != 0 {
        return Err(FrameError::UnsupportedFlags(unsupported));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Header {
    version: ProtocolVersion,
    message_id: MessageId,
    flags: u16,
    payload_len: usize,
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    postcard::to_allocvec(value).map_err(|_| FrameError::LengthOverflow)
}

fn encode_payload(message: &Message) -> Result<Vec<u8>, FrameError> {
    match message {
        Message::ClientHello(value) => serialize(value),
        Message::ServerChallenge(value) => serialize(value),
        Message::ClientAuthenticate(value) => serialize(value),
        Message::AuthResult(value) => serialize(value),
        Message::RegisterTunnels(value) => serialize(value),
        Message::TunnelResults(value) => serialize(value),
        Message::OpenTcpStream(value) => serialize(value),
        Message::TcpStreamReady(value) => serialize(value),
        Message::UdpDatagram(value) => encode_udp(value),
        Message::Heartbeat(value) => serialize(value),
        Message::Error(value) => serialize(value),
        Message::OpenUdpChannel(value) => serialize(value),
        Message::DataChannelBind(value) => serialize(value),
        Message::UdpSessionRetired(value) => serialize(value),
        Message::RendezvousRequest(value)
        | Message::RendezvousProviderDecision(value)
        | Message::RendezvousCandidateSet(value)
        | Message::RendezvousCandidateSetV2(value)
        | Message::RendezvousConnectivityResult(value)
        | Message::RendezvousRelayRequest(value)
        | Message::RendezvousClose(value)
        | Message::RendezvousError(value) => Ok(value.as_slice().to_vec()),
        Message::PeerRelayFrame(value) => Ok(value.as_slice().to_vec()),
        Message::ObservationGrantRequest(value) => serialize(value),
        Message::ObservationGrant(value) => Ok(value.as_slice().to_vec()),
        Message::ServerNotice(value) => serialize(value),
        Message::PeerIdentityBinding(value) => serialize(value),
        Message::PeerIdentityLookup(value) => serialize(value),
        Message::PunchGrant(value) => serialize(value),
        Message::TelemetryReport(value) => serialize(value),
    }
}

fn deserialize<T: DeserializeOwned>(message: MessageId, payload: &[u8]) -> Result<T, FrameError> {
    let (value, remainder) =
        postcard::take_from_bytes(payload).map_err(|_| FrameError::MalformedPayload { message })?;
    if !remainder.is_empty() {
        return Err(FrameError::MalformedPayload { message });
    }
    Ok(value)
}

fn decode_payload(message: MessageId, payload: &[u8]) -> Result<Message, FrameError> {
    match message {
        MessageId::CLIENT_HELLO => {
            deserialize::<ClientHello>(message, payload).map(Message::ClientHello)
        }
        MessageId::SERVER_CHALLENGE => {
            deserialize::<ServerChallenge>(message, payload).map(Message::ServerChallenge)
        }
        MessageId::CLIENT_AUTHENTICATE => {
            deserialize::<ClientAuthenticate>(message, payload).map(Message::ClientAuthenticate)
        }
        MessageId::AUTH_RESULT => {
            deserialize::<AuthResult>(message, payload).map(Message::AuthResult)
        }
        MessageId::REGISTER_TUNNELS => {
            deserialize::<RegisterTunnels>(message, payload).map(Message::RegisterTunnels)
        }
        MessageId::TUNNEL_RESULTS => {
            deserialize::<TunnelResults>(message, payload).map(Message::TunnelResults)
        }
        MessageId::OPEN_TCP_STREAM => {
            deserialize::<OpenTcpStream>(message, payload).map(Message::OpenTcpStream)
        }
        MessageId::TCP_STREAM_READY => {
            deserialize::<TcpStreamReady>(message, payload).map(Message::TcpStreamReady)
        }
        MessageId::UDP_DATAGRAM => decode_udp(message, payload).map(Message::UdpDatagram),
        MessageId::HEARTBEAT => deserialize::<Heartbeat>(message, payload).map(Message::Heartbeat),
        MessageId::ERROR => deserialize::<ErrorMessage>(message, payload).map(Message::Error),
        MessageId::OPEN_UDP_CHANNEL => {
            deserialize::<OpenUdpChannel>(message, payload).map(Message::OpenUdpChannel)
        }
        MessageId::DATA_CHANNEL_BIND => {
            deserialize::<DataChannelBind>(message, payload).map(Message::DataChannelBind)
        }
        MessageId::UDP_SESSION_RETIRED => {
            deserialize::<UdpSessionRetired>(message, payload).map(Message::UdpSessionRetired)
        }
        MessageId::RENDEZVOUS_REQUEST => decode_opaque(payload).map(Message::RendezvousRequest),
        MessageId::RENDEZVOUS_PROVIDER_DECISION => {
            decode_opaque(payload).map(Message::RendezvousProviderDecision)
        }
        MessageId::RENDEZVOUS_CANDIDATE_SET => {
            decode_opaque(payload).map(Message::RendezvousCandidateSet)
        }
        MessageId::RENDEZVOUS_CANDIDATE_SET_V2 => {
            decode_opaque(payload).map(Message::RendezvousCandidateSetV2)
        }
        MessageId::RENDEZVOUS_CONNECTIVITY_RESULT => {
            decode_opaque(payload).map(Message::RendezvousConnectivityResult)
        }
        MessageId::RENDEZVOUS_RELAY_REQUEST => {
            decode_opaque(payload).map(Message::RendezvousRelayRequest)
        }
        MessageId::RENDEZVOUS_CLOSE => decode_opaque(payload).map(Message::RendezvousClose),
        MessageId::RENDEZVOUS_ERROR => decode_opaque(payload).map(Message::RendezvousError),
        MessageId::PEER_RELAY_FRAME => decode_opaque(payload).map(Message::PeerRelayFrame),
        MessageId::OBSERVATION_GRANT_REQUEST => {
            deserialize::<ObservationGrantRequest>(message, payload)
                .map(Message::ObservationGrantRequest)
        }
        MessageId::OBSERVATION_GRANT => decode_opaque(payload).map(Message::ObservationGrant),
        MessageId::SERVER_NOTICE => {
            deserialize::<ServerNotice>(message, payload).map(Message::ServerNotice)
        }
        MessageId::PEER_IDENTITY_BINDING => {
            deserialize::<crate::PeerIdentityBinding>(message, payload)
                .map(Message::PeerIdentityBinding)
        }
        MessageId::PEER_IDENTITY_LOOKUP => {
            deserialize::<crate::PeerIdentityLookup>(message, payload)
                .map(Message::PeerIdentityLookup)
        }
        MessageId::PUNCH_GRANT => {
            deserialize::<crate::PunchGrant>(message, payload).map(Message::PunchGrant)
        }
        MessageId::TELEMETRY_REPORT => {
            deserialize::<TelemetryReport>(message, payload).map(Message::TelemetryReport)
        }
        _ => unreachable!("MessageId values are validated before payload dispatch"),
    }
}

fn decode_opaque<const MAX: usize>(payload: &[u8]) -> Result<BoundedBytes<MAX>, FrameError> {
    BoundedBytes::try_from(payload).map_err(|_| FrameError::LengthOverflow)
}

fn encode_udp(datagram: &UdpDatagram) -> Result<Vec<u8>, FrameError> {
    if datagram.tunnel_id == 0 || datagram.session_id == 0 {
        return Err(FrameError::MalformedPayload {
            message: MessageId::UDP_DATAGRAM,
        });
    }
    let mut payload = Vec::with_capacity(UDP_METADATA_LEN + datagram.payload.as_slice().len());
    payload.put_u32(datagram.tunnel_id);
    payload.put_u64(datagram.session_id);
    match datagram.source {
        SocketAddress::V4 { octets, port } => {
            payload.put_u8(4);
            payload.extend_from_slice(&octets);
            payload.extend_from_slice(&[0; 12]);
            payload.put_u16(port);
        }
        SocketAddress::V6 { octets, port } => {
            payload.put_u8(6);
            payload.extend_from_slice(&octets);
            payload.put_u16(port);
        }
    }
    payload.extend_from_slice(datagram.payload.as_slice());
    Ok(payload)
}

fn decode_udp(message: MessageId, payload: &[u8]) -> Result<UdpDatagram, FrameError> {
    if payload.len() < UDP_METADATA_LEN {
        return Err(FrameError::MalformedPayload { message });
    }
    let raw = &payload[UDP_METADATA_LEN..];
    if raw.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(FrameError::MessagePayloadTooLarge {
            message,
            declared: payload.len(),
            max: UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES,
        });
    }

    let tunnel_id = u32::from_be_bytes(payload[0..4].try_into().expect("fixed metadata width"));
    let session_id = u64::from_be_bytes(payload[4..12].try_into().expect("fixed metadata width"));
    if tunnel_id == 0 || session_id == 0 {
        return Err(FrameError::MalformedPayload { message });
    }
    let address: [u8; 16] = payload[13..29].try_into().expect("fixed metadata width");
    let port = u16::from_be_bytes(payload[29..31].try_into().expect("fixed metadata width"));
    let source = match payload[12] {
        4 if address[4..] == [0; 12] => SocketAddress::V4 {
            octets: address[0..4].try_into().expect("IPv4 width"),
            port,
        },
        6 => SocketAddress::V6 {
            octets: address,
            port,
        },
        _ => return Err(FrameError::MalformedPayload { message }),
    };
    let payload = BoundedBytes::try_from(raw).map_err(|_| FrameError::MessagePayloadTooLarge {
        message,
        declared: payload.len(),
        max: UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES,
    })?;
    Ok(UdpDatagram {
        tunnel_id,
        session_id,
        source,
        payload,
    })
}
