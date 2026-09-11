use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PREFIX: &str = "rustgo-enroll-v1.";
const MAX_ENCODED_BYTES: usize = 512;
const SECRET_BYTES: usize = 32;
const CHECKSUM_HEX_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentPurpose {
    Enroll,
    ReEnroll,
}

pub struct EnrollmentKeyMaterial {
    server_addr: String,
    certificate_fingerprint: [u8; SECRET_BYTES],
    purpose: EnrollmentPurpose,
    token: [u8; SECRET_BYTES],
}

impl EnrollmentKeyMaterial {
    pub fn new(
        purpose: EnrollmentPurpose,
        server_addr: &str,
        certificate_fingerprint: [u8; SECRET_BYTES],
        token: [u8; SECRET_BYTES],
    ) -> Result<Self, EnrollmentKeyError> {
        Ok(Self {
            server_addr: canonical_enrollment_server_addr(server_addr)?,
            certificate_fingerprint,
            purpose,
            token,
        })
    }

    pub fn encode(&self) -> String {
        let address = self.server_addr.as_bytes();
        let mut payload = Vec::with_capacity(3 + address.len() + 2 * SECRET_BYTES);
        payload.push(match self.purpose {
            EnrollmentPurpose::Enroll => 1,
            EnrollmentPurpose::ReEnroll => 2,
        });
        payload.extend_from_slice(&(address.len() as u16).to_be_bytes());
        payload.extend_from_slice(address);
        payload.extend_from_slice(&self.certificate_fingerprint);
        payload.extend_from_slice(&self.token);
        let checksum = Sha256::digest(&payload);
        format!(
            "{PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            hex_checksum(&checksum[..4])
        )
    }

    pub fn decode(encoded: &str) -> Result<Self, EnrollmentKeyError> {
        if encoded.is_empty() || encoded.len() > MAX_ENCODED_BYTES {
            return Err(EnrollmentKeyError::InvalidFormat);
        }
        let remainder = encoded
            .strip_prefix(PREFIX)
            .ok_or(EnrollmentKeyError::UnsupportedVersion)?;
        let (payload_encoded, checksum_encoded) = remainder
            .split_once('.')
            .ok_or(EnrollmentKeyError::InvalidFormat)?;
        if checksum_encoded.len() != CHECKSUM_HEX_BYTES || checksum_encoded.contains('.') {
            return Err(EnrollmentKeyError::InvalidChecksum);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload_encoded)
            .map_err(|_| EnrollmentKeyError::InvalidFormat)?;
        let checksum = decode_checksum(checksum_encoded)?;
        let digest = Sha256::digest(&payload);
        if digest[..4] != checksum {
            return Err(EnrollmentKeyError::InvalidChecksum);
        }
        if payload.len() < 3 + 2 * SECRET_BYTES {
            return Err(EnrollmentKeyError::InvalidFormat);
        }
        let purpose = match payload[0] {
            1 => EnrollmentPurpose::Enroll,
            2 => EnrollmentPurpose::ReEnroll,
            _ => return Err(EnrollmentKeyError::InvalidPurpose),
        };
        let address_len = usize::from(u16::from_be_bytes([payload[1], payload[2]]));
        if payload.len() != 3 + address_len + 2 * SECRET_BYTES {
            return Err(EnrollmentKeyError::InvalidFormat);
        }
        let address_end = 3 + address_len;
        let address = std::str::from_utf8(&payload[3..address_end])
            .map_err(|_| EnrollmentKeyError::InvalidAddress)?;
        let fingerprint_end = address_end + SECRET_BYTES;
        Self::new(
            purpose,
            address,
            payload[address_end..fingerprint_end]
                .try_into()
                .map_err(|_| EnrollmentKeyError::InvalidFormat)?,
            payload[fingerprint_end..]
                .try_into()
                .map_err(|_| EnrollmentKeyError::InvalidFormat)?,
        )
    }

    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }
    pub fn certificate_fingerprint(&self) -> &[u8; SECRET_BYTES] {
        &self.certificate_fingerprint
    }
    pub fn purpose(&self) -> EnrollmentPurpose {
        self.purpose
    }
    pub fn token(&self) -> &[u8; SECRET_BYTES] {
        &self.token
    }
}

impl fmt::Debug for EnrollmentKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentKeyMaterial")
            .field("server_addr", &self.server_addr)
            .field("certificate_fingerprint", &"[REDACTED]")
            .field("purpose", &self.purpose)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnrollmentKeyError {
    #[error("invalid enrollment key format")]
    InvalidFormat,
    #[error("unsupported enrollment key version")]
    UnsupportedVersion,
    #[error("invalid enrollment key checksum")]
    InvalidChecksum,
    #[error("invalid enrollment key purpose")]
    InvalidPurpose,
    #[error("invalid enrollment server address")]
    InvalidAddress,
}

fn hex_checksum(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_checksum(encoded: &str) -> Result<[u8; 4], EnrollmentKeyError> {
    let mut checksum = [0; 4];
    let (chunks, remainder) = encoded.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(EnrollmentKeyError::InvalidChecksum);
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| EnrollmentKeyError::InvalidChecksum)?;
        checksum[index] =
            u8::from_str_radix(text, 16).map_err(|_| EnrollmentKeyError::InvalidChecksum)?;
    }
    Ok(checksum)
}

pub fn canonical_enrollment_server_addr(address: &str) -> Result<String, EnrollmentKeyError> {
    if address.starts_with('[') {
        let bracket = address
            .find(']')
            .ok_or(EnrollmentKeyError::InvalidAddress)?;
        let host = &address[1..bracket];
        let port = address
            .get(bracket + 1..)
            .and_then(|suffix| suffix.strip_prefix(':'));
        let port = validate_port(port)?;
        let ip = host
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| EnrollmentKeyError::InvalidAddress)?;
        return Ok(format!("[{ip}]:{port}"));
    }
    let (host, port) = address
        .rsplit_once(':')
        .ok_or(EnrollmentKeyError::InvalidAddress)?;
    if host.is_empty()
        || host.contains(':')
        || !host.is_ascii()
        || host.chars().any(char::is_whitespace)
    {
        return Err(EnrollmentKeyError::InvalidAddress);
    }
    let port = validate_port(Some(port))?;
    Ok(format!("{}:{port}", host.to_ascii_lowercase()))
}

fn validate_port(port: Option<&str>) -> Result<u16, EnrollmentKeyError> {
    let port = port
        .ok_or(EnrollmentKeyError::InvalidAddress)?
        .parse::<u16>()
        .map_err(|_| EnrollmentKeyError::InvalidAddress)?;
    if port == 0 {
        return Err(EnrollmentKeyError::InvalidAddress);
    }
    Ok(port)
}
