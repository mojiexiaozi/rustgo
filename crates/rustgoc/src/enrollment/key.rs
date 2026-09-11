use std::fmt;

pub use rustgo_protocol::EnrollmentPurpose;
use rustgo_protocol::{EnrollmentKeyError, EnrollmentKeyMaterial};
use thiserror::Error;

pub struct EnrollmentKey(EnrollmentKeyMaterial);

impl EnrollmentKey {
    pub fn parse(encoded: &str) -> Result<Self, EnrollmentError> {
        EnrollmentKeyMaterial::decode(encoded)
            .map(Self)
            .map_err(EnrollmentError::from)
    }

    pub fn server_addr(&self) -> &str {
        self.0.server_addr()
    }
    pub fn certificate_fingerprint(&self) -> &[u8; 32] {
        self.0.certificate_fingerprint()
    }
    pub fn purpose(&self) -> EnrollmentPurpose {
        self.0.purpose()
    }
    pub fn token(&self) -> &[u8; 32] {
        self.0.token()
    }
    pub(crate) fn encoded(&self) -> String {
        self.0.encode()
    }
}

impl fmt::Debug for EnrollmentKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnrollmentError {
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
    #[error("static identity private key is missing")]
    MissingStaticPrivateKey,
    #[error("static identity private key is invalid")]
    InvalidStaticPrivateKey,
    #[error("enrollment pending state is invalid")]
    InvalidPendingState,
    #[error("cannot {operation} enrollment pending state ({kind:?})")]
    PendingIo {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    #[error("enrollment destination already exists")]
    DestinationExists,
    #[error("enrollment network protocol failed")]
    Network,
    #[error("enrollment was rejected: {0:?}")]
    Rejected(rustgo_protocol::EnrollmentErrorCode),
    #[error("cannot update client configuration ({0:?})")]
    ConfigurationIo(std::io::ErrorKind),
}

impl From<EnrollmentKeyError> for EnrollmentError {
    fn from(error: EnrollmentKeyError) -> Self {
        match error {
            EnrollmentKeyError::InvalidFormat => Self::InvalidFormat,
            EnrollmentKeyError::UnsupportedVersion => Self::UnsupportedVersion,
            EnrollmentKeyError::InvalidChecksum => Self::InvalidChecksum,
            EnrollmentKeyError::InvalidPurpose => Self::InvalidPurpose,
            EnrollmentKeyError::InvalidAddress => Self::InvalidAddress,
        }
    }
}
