use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use rand::{TryRngCore, rngs::OsRng};
use rustgo_crypto::DeviceKeypair;
use serde::{Deserialize, Serialize};

use super::{EnrollmentError, EnrollmentKey, EnrollmentPurpose};

const FORMAT_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingMetadata {
    format_version: u8,
    #[serde(default)]
    approval_intent: Option<String>,
    #[serde(default = "legacy_approval_metadata_version")]
    approval_metadata_version: u8,
    kind: String,
    candidate_private_key: PathBuf,
    final_private_key: PathBuf,
    request_id: String,
    server_addr: String,
    certificate_fingerprint: String,
    trust_mode: String,
    public_key: String,
    #[serde(default)]
    reuse_existing: bool,
    #[serde(default)]
    allow_replace: bool,
}

pub struct PendingEnrollment {
    metadata_path: PathBuf,
    metadata: PendingMetadata,
}

impl PendingEnrollment {
    pub(crate) fn exists(config_path: &Path) -> bool {
        metadata_path(config_path).exists()
    }

    pub fn create(
        config_path: &Path,
        final_private_key: &Path,
        key: &EnrollmentKey,
    ) -> Result<Self, EnrollmentError> {
        Self::create_inner(config_path, final_private_key, key, false)
    }

    /// Approval requests reuse a valid local key; only missing/invalid keys are generated.
    pub fn create_reusing(
        config_path: &Path,
        final_private_key: &Path,
        key: &EnrollmentKey,
    ) -> Result<Self, EnrollmentError> {
        Self::create_inner(config_path, final_private_key, key, true)
    }

    fn create_inner(
        config_path: &Path,
        final_private_key: &Path,
        key: &EnrollmentKey,
        reuse: bool,
    ) -> Result<Self, EnrollmentError> {
        let metadata_path = metadata_path(config_path);
        if metadata_path.exists()
            || (!reuse && key.purpose() == EnrollmentPurpose::Enroll && final_private_key.exists())
        {
            return Err(EnrollmentError::DestinationExists);
        }
        let request_id = random_request_id()?;
        let final_parent = final_private_key
            .parent()
            .ok_or(EnrollmentError::InvalidPendingState)?;
        fs::create_dir_all(final_parent)
            .map_err(|error| pending_io("create key directory", error))?;
        let candidate_directory =
            final_parent.join(format!(".rustgo-enrollment-pending-{request_id}"));
        let existing = if reuse {
            DeviceKeypair::load_private_file(final_private_key).ok()
        } else {
            None
        };
        let reuse_existing = existing.is_some();
        let (public_key, candidate_private_key) = if let Some(existing) = existing {
            (existing.public_key(), final_private_key.to_path_buf())
        } else {
            (
                rustgo_crypto::generate_key_file(&candidate_directory)
                    .map_err(|_| EnrollmentError::InvalidPendingState)?,
                candidate_directory.join("device.key"),
            )
        };
        let metadata = PendingMetadata {
            format_version: FORMAT_VERSION,
            approval_intent: None,
            approval_metadata_version: 2,
            kind: match key.purpose() {
                EnrollmentPurpose::Enroll => "enroll",
                EnrollmentPurpose::ReEnroll => "reenroll",
            }
            .to_owned(),
            candidate_private_key,
            final_private_key: final_private_key.to_path_buf(),
            request_id,
            server_addr: key.server_addr().to_owned(),
            certificate_fingerprint: hex(key.certificate_fingerprint()),
            trust_mode: "pinned".to_owned(),
            public_key: public_key.to_string(),
            reuse_existing,
            allow_replace: reuse || key.purpose() == EnrollmentPurpose::ReEnroll,
        };
        write_metadata(&metadata_path, &metadata)?;
        Ok(Self {
            metadata_path,
            metadata,
        })
    }

    pub fn load(config_path: &Path) -> Result<Self, EnrollmentError> {
        let metadata_path = metadata_path(config_path);
        let contents =
            fs::read_to_string(&metadata_path).map_err(|error| pending_io("read", error))?;
        let mut metadata: PendingMetadata =
            toml::from_str(&contents).map_err(|_| EnrollmentError::InvalidPendingState)?;
        // Recover a crash after the atomic key move but before metadata cleanup.
        if !metadata.candidate_private_key.exists()
            && DeviceKeypair::load_private_file(&metadata.final_private_key)
                .is_ok_and(|key| key.public_key().to_string() == metadata.public_key)
        {
            metadata.candidate_private_key = metadata.final_private_key.clone();
            metadata.reuse_existing = true;
        }
        validate_metadata(&metadata)?;
        Ok(Self {
            metadata_path,
            metadata,
        })
    }

    pub(crate) fn requires_legacy_approval_intent(&self) -> bool {
        self.metadata.approval_metadata_version == 1 && self.metadata.approval_intent.is_none()
    }

    pub(crate) fn bind_approval_intent(&mut self, intent: &str) -> Result<String, EnrollmentError> {
        if let Some(existing) = &self.metadata.approval_intent {
            return Ok(existing.clone());
        }
        self.metadata.approval_intent = Some(intent.to_owned());
        write_metadata(&self.metadata_path, &self.metadata)?;
        Ok(intent.to_owned())
    }

    pub fn public_key(&self) -> &str {
        &self.metadata.public_key
    }

    pub fn request_id(&self) -> &str {
        &self.metadata.request_id
    }

    pub fn purpose(&self) -> EnrollmentPurpose {
        if self.metadata.kind == "reenroll" {
            EnrollmentPurpose::ReEnroll
        } else {
            EnrollmentPurpose::Enroll
        }
    }

    pub fn server_addr(&self) -> &str {
        &self.metadata.server_addr
    }

    pub(crate) fn candidate_private_key(&self) -> &Path {
        &self.metadata.candidate_private_key
    }

    pub fn certificate_fingerprint(&self) -> Result<[u8; 32], EnrollmentError> {
        let decoded = (0..32)
            .map(|index| {
                u8::from_str_radix(
                    &self.metadata.certificate_fingerprint[index * 2..index * 2 + 2],
                    16,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| EnrollmentError::InvalidPendingState)?;
        decoded
            .try_into()
            .map_err(|_| EnrollmentError::InvalidPendingState)
    }

    pub fn promote(self) -> Result<(), EnrollmentError> {
        validate_metadata(&self.metadata)?;
        if self.metadata.reuse_existing {
            return fs::remove_file(&self.metadata_path)
                .map_err(|e| pending_io("remove metadata", e));
        }
        if self.metadata.final_private_key.exists()
            && !self.metadata.allow_replace
            && self.purpose() != EnrollmentPurpose::ReEnroll
        {
            return Err(EnrollmentError::DestinationExists);
        }
        atomicwrites::replace_atomic(
            &self.metadata.candidate_private_key,
            &self.metadata.final_private_key,
        )
        .map_err(|error| pending_io("promote candidate key", error))?;
        let candidate_directory = self
            .metadata
            .candidate_private_key
            .parent()
            .ok_or(EnrollmentError::InvalidPendingState)?;
        let _ = fs::remove_file(candidate_directory.join("device.pub"));
        let _ = fs::remove_dir(candidate_directory);
        fs::remove_file(&self.metadata_path)
            .map_err(|error| pending_io("remove metadata", error))?;
        Ok(())
    }

    pub fn promote_replacing(self) -> Result<(), EnrollmentError> {
        self.promote()
    }
}

fn legacy_approval_metadata_version() -> u8 {
    1
}

fn metadata_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("enrollment-pending.toml")
}

fn validate_metadata(metadata: &PendingMetadata) -> Result<(), EnrollmentError> {
    if metadata.format_version != FORMAT_VERSION
        || !matches!(metadata.approval_metadata_version, 1 | 2)
        || !matches!(metadata.kind.as_str(), "enroll" | "reenroll")
        || metadata.request_id.len() != 32
        || metadata.server_addr.is_empty()
        || metadata.certificate_fingerprint.len() != 64
        || !metadata
            .certificate_fingerprint
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
        || metadata.trust_mode != "pinned"
        || (metadata.kind == "enroll"
            && metadata.final_private_key.exists()
            && !metadata.reuse_existing
            && !metadata.allow_replace)
        || (metadata.reuse_existing && metadata.candidate_private_key != metadata.final_private_key)
    {
        return Err(EnrollmentError::InvalidPendingState);
    }
    let keypair = DeviceKeypair::load_private_file(&metadata.candidate_private_key)
        .map_err(|_| EnrollmentError::InvalidPendingState)?;
    if keypair.public_key().to_string() != metadata.public_key {
        return Err(EnrollmentError::InvalidPendingState);
    }
    Ok(())
}

fn write_metadata(path: &Path, metadata: &PendingMetadata) -> Result<(), EnrollmentError> {
    let parent = path.parent().ok_or(EnrollmentError::InvalidPendingState)?;
    fs::create_dir_all(parent).map_err(|error| pending_io("create metadata directory", error))?;
    let temporary = parent.join(format!(".enrollment-pending-{}.tmp", metadata.request_id));
    let encoded = toml::to_string(metadata).map_err(|_| EnrollmentError::InvalidPendingState)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| pending_io("create metadata", error))?;
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|error| pending_io("write metadata", error))?;
    fs::rename(&temporary, path).map_err(|error| pending_io("install metadata", error))
}

fn random_request_id() -> Result<String, EnrollmentError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| pending_io("obtain randomness for", std::io::Error::other(error)))?;
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn pending_io(operation: &'static str, error: std::io::Error) -> EnrollmentError {
    EnrollmentError::PendingIo {
        operation,
        kind: error.kind(),
    }
}
