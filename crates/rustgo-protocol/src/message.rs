use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub const MAX_CLIENT_NAME_BYTES: usize = 128;
pub const MAX_FINGERPRINT_BYTES: usize = 64;
pub const MAX_CHALLENGE_BYTES: usize = 64;
pub const MAX_SESSION_ID_BYTES: usize = 32;
pub const MAX_PUBLIC_KEY_BYTES: usize = 64;
pub const MAX_SIGNATURE_BYTES: usize = 128;
pub const MAX_TUNNELS: usize = 64;
pub const MAX_TUNNEL_NAME_BYTES: usize = 128;
pub const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;
pub const MAX_ERROR_DETAIL_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("value length {actual} exceeds bound {max}")]
pub struct BoundExceeded {
    pub actual: usize,
    pub max: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl<const MAX: usize> TryFrom<&[u8]> for BoundedBytes<MAX> {
    type Error = BoundExceeded;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() > MAX {
            return Err(BoundExceeded {
                actual: value.len(),
                max: MAX,
            });
        }
        Ok(Self(value.to_vec()))
    }
}

impl<const MAX: usize> TryFrom<Vec<u8>> for BoundedBytes<MAX> {
    type Error = BoundExceeded;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > MAX {
            return Err(BoundExceeded {
                actual: value.len(),
                max: MAX,
            });
        }
        Ok(Self(value))
    }
}

impl<const MAX: usize> Serialize for BoundedBytes<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedBytes<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<const MAX: usize>;

        impl<'de, const MAX: usize> Visitor<'de> for BytesVisitor<MAX> {
            type Value = BoundedBytes<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "at most {MAX} bytes")
            }

            fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                BoundedBytes::try_from(value).map_err(E::custom)
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                BoundedBytes::try_from(value).map_err(E::custom)
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                BoundedBytes::try_from(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor::<MAX>)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedString<const MAX: usize>(String);

impl<const MAX: usize> BoundedString<MAX> {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> TryFrom<&str> for BoundedString<MAX> {
    type Error = BoundExceeded;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > MAX {
            return Err(BoundExceeded {
                actual: value.len(),
                max: MAX,
            });
        }
        Ok(Self(value.to_owned()))
    }
}

impl<const MAX: usize> Serialize for BoundedString<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor<const MAX: usize>;

        impl<'de, const MAX: usize> Visitor<'de> for StringVisitor<MAX> {
            type Value = BoundedString<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a UTF-8 string of at most {MAX} bytes")
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                BoundedString::try_from(value).map_err(E::custom)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                BoundedString::try_from(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(StringVisitor::<MAX>)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MAX: usize> TryFrom<Vec<T>> for BoundedVec<T, MAX> {
    type Error = BoundExceeded;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() > MAX {
            return Err(BoundExceeded {
                actual: value.len(),
                max: MAX,
            });
        }
        Ok(Self(value))
    }
}

impl<T: Serialize, const MAX: usize> Serialize for BoundedVec<T, MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecVisitor<T, const MAX: usize>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for VecVisitor<T, MAX> {
            type Value = BoundedVec<T, MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a sequence with at most {MAX} elements")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let hint = sequence.size_hint().unwrap_or(0);
                if hint > MAX {
                    return Err(de::Error::custom(BoundExceeded {
                        actual: hint,
                        max: MAX,
                    }));
                }
                let mut values = Vec::with_capacity(hint);
                while let Some(value) = sequence.next_element()? {
                    if values.len() == MAX {
                        return Err(de::Error::custom(BoundExceeded {
                            actual: MAX.saturating_add(1),
                            max: MAX,
                        }));
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(VecVisitor::<T, MAX>(std::marker::PhantomData))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(u16);

impl MessageId {
    pub const CLIENT_HELLO: Self = Self(1);
    pub const SERVER_CHALLENGE: Self = Self(2);
    pub const CLIENT_AUTHENTICATE: Self = Self(3);
    pub const AUTH_RESULT: Self = Self(4);
    pub const REGISTER_TUNNELS: Self = Self(5);
    pub const TUNNEL_RESULTS: Self = Self(6);
    pub const OPEN_TCP_STREAM: Self = Self(7);
    pub const TCP_STREAM_READY: Self = Self(8);
    pub const UDP_DATAGRAM: Self = Self(9);
    pub const HEARTBEAT: Self = Self(10);
    pub const ERROR: Self = Self(11);

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub const fn max_payload(self) -> usize {
        match self.0 {
            1 => 256,
            2 => 128,
            3 => 256,
            4 => 16,
            5 => 32 * 1024,
            6 => 8 * 1024,
            7 => 64,
            8 => 32,
            9 => 65_600,
            10 => 16,
            11 => 1024,
            _ => 0,
        }
    }
}

impl TryFrom<u16> for MessageId {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1..=11 => Ok(Self(value)),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolErrorCode(u16);

impl ProtocolErrorCode {
    pub const UNSUPPORTED_VERSION: Self = Self(1);
    pub const UNKNOWN_MESSAGE: Self = Self(2);
    pub const INVALID_FRAME: Self = Self(3);
    pub const PAYLOAD_TOO_LARGE: Self = Self(4);
    pub const INVALID_STATE: Self = Self(5);
    pub const AUTHENTICATION_FAILED: Self = Self(6);
    pub const UNKNOWN_SESSION: Self = Self(7);
    pub const TUNNEL_REJECTED: Self = Self(8);
    pub const INTERNAL: Self = Self(255);

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl Serialize for ProtocolErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for ProtocolErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        match value {
            1..=8 | 255 => Ok(Self(value)),
            _ => Err(de::Error::custom("unknown protocol error code")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelProtocol(u8);

impl TunnelProtocol {
    pub const TCP: Self = Self(1);
    pub const UDP: Self = Self(2);

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl Serialize for TunnelProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for TunnelProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            1 => Ok(Self::TCP),
            2 => Ok(Self::UDP),
            _ => Err(de::Error::custom("unknown tunnel protocol")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketAddress {
    V4 { octets: [u8; 4], port: u16 },
    V6 { octets: [u8; 16], port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    pub client_name: BoundedString<MAX_CLIENT_NAME_BYTES>,
    pub fingerprint: BoundedBytes<MAX_FINGERPRINT_BYTES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerChallenge {
    pub challenge: BoundedBytes<MAX_CHALLENGE_BYTES>,
    pub session_id: BoundedBytes<MAX_SESSION_ID_BYTES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAuthenticate {
    pub public_key: BoundedBytes<MAX_PUBLIC_KEY_BYTES>,
    pub signature: BoundedBytes<MAX_SIGNATURE_BYTES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResult {
    pub accepted: bool,
    pub error: Option<ProtocolErrorCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelRegistration {
    pub tunnel_id: u32,
    pub name: BoundedString<MAX_TUNNEL_NAME_BYTES>,
    pub protocol: TunnelProtocol,
    pub remote_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterTunnels {
    pub tunnels: BoundedVec<TunnelRegistration, MAX_TUNNELS>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelResult {
    pub tunnel_id: u32,
    pub accepted: bool,
    pub error: Option<ProtocolErrorCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelResults {
    pub results: BoundedVec<TunnelResult, MAX_TUNNELS>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenTcpStream {
    pub tunnel_id: u32,
    pub connection_id: u64,
    pub peer: SocketAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpStreamReady {
    pub connection_id: u64,
    pub accepted: bool,
    pub error: Option<ProtocolErrorCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpDatagram {
    pub tunnel_id: u32,
    pub session_id: u64,
    pub source: SocketAddress,
    pub payload: BoundedBytes<MAX_UDP_PAYLOAD_BYTES>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: ProtocolErrorCode,
    pub detail: BoundedString<MAX_ERROR_DETAIL_BYTES>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    ClientHello(ClientHello),
    ServerChallenge(ServerChallenge),
    ClientAuthenticate(ClientAuthenticate),
    AuthResult(AuthResult),
    RegisterTunnels(RegisterTunnels),
    TunnelResults(TunnelResults),
    OpenTcpStream(OpenTcpStream),
    TcpStreamReady(TcpStreamReady),
    UdpDatagram(UdpDatagram),
    Heartbeat(Heartbeat),
    Error(ErrorMessage),
}

impl Message {
    pub const fn id(&self) -> MessageId {
        match self {
            Self::ClientHello(_) => MessageId::CLIENT_HELLO,
            Self::ServerChallenge(_) => MessageId::SERVER_CHALLENGE,
            Self::ClientAuthenticate(_) => MessageId::CLIENT_AUTHENTICATE,
            Self::AuthResult(_) => MessageId::AUTH_RESULT,
            Self::RegisterTunnels(_) => MessageId::REGISTER_TUNNELS,
            Self::TunnelResults(_) => MessageId::TUNNEL_RESULTS,
            Self::OpenTcpStream(_) => MessageId::OPEN_TCP_STREAM,
            Self::TcpStreamReady(_) => MessageId::TCP_STREAM_READY,
            Self::UdpDatagram(_) => MessageId::UDP_DATAGRAM,
            Self::Heartbeat(_) => MessageId::HEARTBEAT,
            Self::Error(_) => MessageId::ERROR,
        }
    }
}
