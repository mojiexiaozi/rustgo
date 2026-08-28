use std::{fmt, io, path::PathBuf, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::AuthTranscript;

const PUBLIC_KEY_PREFIX: &str = "ed25519:";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("authentication verification failed")]
    AuthenticationFailed,
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid Rustgo private key file")]
    InvalidPrivateKey,
    #[error("refusing to overwrite existing key file: {path}")]
    KeyDestinationExists { path: PathBuf },
    #[error("could not {operation} key file {path}: {kind}")]
    KeyFileIo {
        operation: &'static str,
        path: PathBuf,
        kind: io::ErrorKind,
    },
}

pub struct DeviceKeypair {
    signing_key: SigningKey,
}

impl DeviceKeypair {
    #[must_use]
    pub fn from_secret_bytes(mut secret: [u8; 32]) -> Self {
        let keypair = Self::from_secret_bytes_ref(&secret);
        secret.zeroize();
        keypair
    }

    #[must_use]
    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey(self.signing_key.verifying_key())
    }

    pub(crate) fn from_secret_bytes_ref(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    pub(crate) fn sign_bytes(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

impl fmt::Debug for DeviceKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceKeypair([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DevicePublicKey(VerifyingKey);

impl DevicePublicKey {
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from(self)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub(crate) fn verify_bytes(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let signature =
            Signature::from_slice(signature).map_err(|_| CryptoError::AuthenticationFailed)?;
        self.0
            .verify_strict(message, &signature)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DevicePublicKey")
            .field(&self.fingerprint())
            .finish()
    }
}

impl fmt::Display for DevicePublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{PUBLIC_KEY_PREFIX}{}",
            STANDARD.encode(self.0.as_bytes())
        )
    }
}

impl FromStr for DevicePublicKey {
    type Err = CryptoError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let payload = encoded
            .strip_prefix(PUBLIC_KEY_PREFIX)
            .ok_or(CryptoError::InvalidPublicKey)?;
        let bytes = STANDARD
            .decode(payload)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self(key))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl From<&DevicePublicKey> for Fingerprint {
    fn from(public_key: &DevicePublicKey) -> Self {
        Self(Sha256::digest(public_key.0.as_bytes()).into())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[must_use]
pub fn sign_auth(keypair: &DeviceKeypair, transcript: &AuthTranscript) -> [u8; 64] {
    keypair.signing_key.sign(transcript.as_bytes()).to_bytes()
}

pub fn verify_auth(
    public_key: &DevicePublicKey,
    transcript: &AuthTranscript,
    signature: &[u8],
) -> Result<(), CryptoError> {
    public_key.verify_bytes(transcript.as_bytes(), signature)
}
