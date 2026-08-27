use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::ProtocolVersion;
use crate::message::{
    AuthResult, ClientAuthenticate, ClientHello, ErrorMessage, Heartbeat, Message, MessageId,
    OpenTcpStream, RegisterTunnels, ServerChallenge, TcpStreamReady, TunnelResults, UdpDatagram,
};

pub const MAGIC: [u8; 4] = *b"RSGO";
pub const HEADER_LEN: usize = 16;

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

    pub fn decode(&self, input: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        let header = match self.inspect_header(input)? {
            Some(header) => header,
            None => return Ok(None),
        };
        let frame_len = HEADER_LEN + header.payload_len;
        if input.len() < frame_len {
            return Ok(None);
        }
        let mut frame_bytes = input.split_to(frame_len);
        frame_bytes.advance(HEADER_LEN);
        let message = decode_payload(header.message_id, &frame_bytes)?;
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
        Message::UdpDatagram(value) => serialize(value),
        Message::Heartbeat(value) => serialize(value),
        Message::Error(value) => serialize(value),
    }
}

fn deserialize<T: DeserializeOwned>(message: MessageId, payload: &[u8]) -> Result<T, FrameError> {
    postcard::from_bytes(payload).map_err(|_| FrameError::MalformedPayload { message })
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
        MessageId::UDP_DATAGRAM => {
            deserialize::<UdpDatagram>(message, payload).map(Message::UdpDatagram)
        }
        MessageId::HEARTBEAT => deserialize::<Heartbeat>(message, payload).map(Message::Heartbeat),
        MessageId::ERROR => deserialize::<ErrorMessage>(message, payload).map(Message::Error),
        _ => unreachable!("all valid message IDs are handled"),
    }
}
