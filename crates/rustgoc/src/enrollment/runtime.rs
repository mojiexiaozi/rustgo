use std::{fs, io::Write, path::Path, time::Duration};

use bytes::BytesMut;
use rustgo_config::{ClientConfig, IdentityMode, TrustMode};
use rustgo_protocol::{
    BoundedBytes, BoundedString, ENROLLMENT_PROTOCOL_VERSION, EnrollmentRequest, FrameCodec,
    MAX_ENROLLMENT_KEY_BYTES, MAX_ENROLLMENT_REQUEST_ID_BYTES, MAX_PUBLIC_KEY_BYTES, Message,
    ProtocolVersion,
};
use rustgo_transport::TlsClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{EnrollmentError, EnrollmentKey, EnrollmentPurpose, PendingEnrollment};
use crate::{ClientError, ControlClient};

const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PAYLOAD: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentCompletion {
    pub client_id: String,
    pub revision: u64,
}

pub async fn enroll(
    config: &mut ClientConfig,
    config_path: &Path,
    encoded_key: &str,
) -> Result<EnrollmentCompletion, EnrollmentError> {
    let key = EnrollmentKey::parse(encoded_key)?;
    let pending = if PendingEnrollment::exists(config_path) {
        PendingEnrollment::load(config_path)?
    } else {
        PendingEnrollment::create(config_path, &config.client.private_key_file, &key)?
    };
    if pending.purpose() != key.purpose()
        || pending.server_addr() != key.server_addr()
        || pending.certificate_fingerprint()? != *key.certificate_fingerprint()
    {
        return Err(EnrollmentError::InvalidPendingState);
    }
    let server_name = server_name(key.server_addr())?;
    let tls = TlsClient::from_pinned_fingerprint(&server_name, *key.certificate_fingerprint())
        .map_err(|_| EnrollmentError::Network)?;
    let operation = async {
        let stream = tls
            .connect(key.server_addr())
            .await
            .map_err(|_| EnrollmentError::Network)?;
        let codec = FrameCodec::new(MAX_PAYLOAD);
        let request = Message::EnrollmentRequest(EnrollmentRequest {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            enrollment_key: BoundedString::<MAX_ENROLLMENT_KEY_BYTES>::try_from(
                key.encoded().as_str(),
            )
            .map_err(|_| EnrollmentError::InvalidFormat)?,
            public_key: BoundedBytes::<MAX_PUBLIC_KEY_BYTES>::try_from(
                pending.public_key().as_bytes(),
            )
            .map_err(|_| EnrollmentError::InvalidPendingState)?,
            request_id: BoundedString::<MAX_ENROLLMENT_REQUEST_ID_BYTES>::try_from(
                pending.request_id(),
            )
            .map_err(|_| EnrollmentError::InvalidPendingState)?,
        });
        let frame = codec
            .encode(ProtocolVersion::SUPPORTED, 0, &request)
            .map_err(|_| EnrollmentError::Network)?;
        let (mut reader, mut writer) = tokio::io::split(stream);
        writer
            .write_all(&frame)
            .await
            .map_err(|_| EnrollmentError::Network)?;
        let mut buffer = BytesMut::new();
        let result = loop {
            if let Some(frame) = codec
                .decode(&mut buffer)
                .map_err(|_| EnrollmentError::Network)?
            {
                break frame;
            }
            if buffer.len() >= MAX_PAYLOAD + rustgo_protocol::HEADER_LEN {
                return Err(EnrollmentError::Network);
            }
            if reader
                .read_buf(&mut buffer)
                .await
                .map_err(|_| EnrollmentError::Network)?
                == 0
            {
                return Err(EnrollmentError::Network);
            }
        };
        let Message::EnrollmentResult(result) = result.message else {
            return Err(EnrollmentError::Network);
        };
        if result.protocol_version != ENROLLMENT_PROTOCOL_VERSION || !result.accepted {
            return Err(EnrollmentError::Rejected(
                result
                    .error
                    .unwrap_or(rustgo_protocol::EnrollmentErrorCode::Unavailable),
            ));
        }
        Ok(EnrollmentCompletion {
            client_id: result
                .client_id
                .ok_or(EnrollmentError::Network)?
                .as_str()
                .to_owned(),
            revision: result.revision.ok_or(EnrollmentError::Network)?,
        })
    };
    let completion = tokio::time::timeout(ENROLLMENT_TIMEOUT, operation)
        .await
        .map_err(|_| EnrollmentError::Network)??;
    update_config(config, config_path, &key, &completion.client_id)?;
    match key.purpose() {
        EnrollmentPurpose::Enroll => pending.promote()?,
        EnrollmentPurpose::ReEnroll => pending.promote_replacing()?,
    }
    Ok(completion)
}

pub async fn recover_pending_enrollment(
    config: &mut ClientConfig,
    config_path: &Path,
) -> Result<bool, EnrollmentError> {
    let pending = PendingEnrollment::load(config_path)?;
    let fingerprint = pending.certificate_fingerprint()?;
    let mut candidate = config.clone();
    candidate.client.identity_mode = Some(IdentityMode::Dynamic);
    candidate.client.private_key_file = pending.candidate_private_key().to_owned();
    candidate.client.server_addr = pending.server_addr().to_owned();
    candidate.client.server_name = server_name(pending.server_addr())?;
    candidate.client.trust_mode = Some(TrustMode::Pinned);
    candidate.client.server_certificate_fingerprint = Some(hex(&fingerprint));
    match ControlClient::from_config(candidate)
        .map_err(|_| EnrollmentError::InvalidPendingState)?
        .connect()
        .await
    {
        Ok(session) => drop(session),
        Err(ClientError::AuthenticationRejected) => return Ok(false),
        Err(_) => return Err(EnrollmentError::Network),
    }
    update_config_values(
        config,
        config_path,
        pending.server_addr(),
        fingerprint,
        None,
    )?;
    match pending.purpose() {
        EnrollmentPurpose::Enroll => pending.promote()?,
        EnrollmentPurpose::ReEnroll => pending.promote_replacing()?,
    }
    Ok(true)
}

fn server_name(address: &str) -> Result<String, EnrollmentError> {
    if address.starts_with('[') {
        return address
            .strip_prefix('[')
            .and_then(|value| value.split_once(']'))
            .map(|(host, _)| host.to_owned())
            .ok_or(EnrollmentError::InvalidAddress);
    }
    address
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .ok_or(EnrollmentError::InvalidAddress)
}

fn update_config(
    config: &mut ClientConfig,
    path: &Path,
    key: &EnrollmentKey,
    client_id: &str,
) -> Result<(), EnrollmentError> {
    update_config_values(
        config,
        path,
        key.server_addr(),
        *key.certificate_fingerprint(),
        Some(client_id),
    )
}

fn update_config_values(
    config: &mut ClientConfig,
    path: &Path,
    server_addr: &str,
    fingerprint: [u8; 32],
    client_id: Option<&str>,
) -> Result<(), EnrollmentError> {
    let contents =
        fs::read_to_string(path).map_err(|error| EnrollmentError::ConfigurationIo(error.kind()))?;
    let mut document: toml::Value = toml::from_str(&contents)
        .map_err(|_| EnrollmentError::ConfigurationIo(std::io::ErrorKind::InvalidData))?;
    let client = document
        .get_mut("client")
        .and_then(toml::Value::as_table_mut)
        .ok_or(EnrollmentError::ConfigurationIo(
            std::io::ErrorKind::InvalidData,
        ))?;
    if let Some(client_id) = client_id {
        client.insert("name".to_owned(), toml::Value::String(client_id.to_owned()));
    }
    client.insert(
        "identity_mode".to_owned(),
        toml::Value::String("dynamic".to_owned()),
    );
    client.insert(
        "server_addr".to_owned(),
        toml::Value::String(server_addr.to_owned()),
    );
    client.insert(
        "trust_mode".to_owned(),
        toml::Value::String("pinned".to_owned()),
    );
    client.insert(
        "server_certificate_fingerprint".to_owned(),
        toml::Value::String(hex(&fingerprint)),
    );
    let encoded = toml::to_string_pretty(&document)
        .map_err(|_| EnrollmentError::ConfigurationIo(std::io::ErrorKind::InvalidData))?;
    let temporary = path.with_extension("enrollment-update.tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| EnrollmentError::ConfigurationIo(error.kind()))?;
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| EnrollmentError::ConfigurationIo(error.kind()))?;
    fs::rename(&temporary, path).map_err(|error| EnrollmentError::ConfigurationIo(error.kind()))?;
    if let Some(client_id) = client_id {
        config.client.name = client_id.to_owned();
    }
    config.client.identity_mode = Some(IdentityMode::Dynamic);
    config.client.server_addr = server_addr.to_owned();
    config.client.trust_mode = Some(TrustMode::Pinned);
    config.client.server_certificate_fingerprint = Some(hex(&fingerprint));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
