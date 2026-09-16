use std::{fs, io::Write, path::Path, time::Duration};

use bytes::BytesMut;
use rustgo_config::{ClientConfig, IdentityMode, TrustMode};
use rustgo_protocol::{
    BoundedBytes, BoundedString, ENROLLMENT_PROTOCOL_VERSION, EnrollmentRequest, FrameCodec,
    MAX_ENROLLMENT_KEY_BYTES, MAX_ENROLLMENT_REQUEST_ID_BYTES, MAX_PUBLIC_KEY_BYTES, Message,
    ProtocolVersion,
};
use rustgo_transport::TlsClient;
use sha2::{Digest, Sha256};
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

pub async fn request_registration(
    config: &mut ClientConfig,
    config_path: &Path,
    purpose: EnrollmentPurpose,
) -> Result<EnrollmentCompletion, EnrollmentError> {
    let intent = rustgo_protocol::RegistrationIntent::for_profile(
        config.client.display_name(),
        config
            .client
            .profile
            .as_ref()
            .and_then(|p| p.uid.as_deref()),
        purpose,
    )?;
    enroll(config, config_path, &intent.encode()).await
}

/// Explicit rotation still uses a candidate key and never overwrites the active key before approval.
pub async fn request_key_rotation(
    config: &mut ClientConfig,
    config_path: &Path,
) -> Result<EnrollmentCompletion, EnrollmentError> {
    if config
        .client
        .profile
        .as_ref()
        .and_then(|p| p.uid.as_ref())
        .is_none()
        && !PendingEnrollment::exists(config_path)
    {
        let session = ControlClient::from_config(config.clone())
            .map_err(|_| EnrollmentError::InvalidPendingState)?
            .connect()
            .await
            .map_err(|_| EnrollmentError::Network)?;
        if let Some(profile) = session
            .effective_config()
            .and_then(|c| c.client.profile.clone())
        {
            config.client.profile = Some(profile);
        }
    }
    let intent = rustgo_protocol::RegistrationIntent::for_profile(
        config.client.display_name(),
        config
            .client
            .profile
            .as_ref()
            .and_then(|p| p.uid.as_deref()),
        EnrollmentPurpose::ReEnroll,
    )?;
    enroll_inner(config, config_path, &intent.encode(), false).await
}

pub async fn enroll(
    config: &mut ClientConfig,
    config_path: &Path,
    encoded_key: &str,
) -> Result<EnrollmentCompletion, EnrollmentError> {
    enroll_inner(config, config_path, encoded_key, true).await
}

async fn enroll_inner(
    config: &mut ClientConfig,
    config_path: &Path,
    encoded_key: &str,
    reuse: bool,
) -> Result<EnrollmentCompletion, EnrollmentError> {
    let approval = rustgo_protocol::RegistrationIntent::decode(encoded_key).ok();
    let legacy = if approval.is_none() {
        Some(EnrollmentKey::parse(encoded_key)?)
    } else {
        None
    };
    let (tls, address) = if let Some(key) = &legacy {
        (
            TlsClient::from_pinned_fingerprint(
                &server_name(key.server_addr())?,
                *key.certificate_fingerprint(),
            )
            .map_err(|_| EnrollmentError::Network)?,
            key.server_addr().to_owned(),
        )
    } else if PendingEnrollment::exists(config_path) {
        let pending = PendingEnrollment::load(config_path)?;
        if pending.server_addr() != config.client.server_addr {
            return Err(EnrollmentError::InvalidPendingState);
        }
        (
            TlsClient::from_pinned_fingerprint(
                &config.client.server_name,
                pending.certificate_fingerprint()?,
            )
            .map_err(|error| EnrollmentError::LocalCertificate(error.to_string()))?,
            config.client.server_addr.clone(),
        )
    } else {
        let tls = match config.client.trust_mode {
            Some(TrustMode::Pinned) => {
                let encoded = config
                    .client
                    .server_certificate_fingerprint
                    .as_deref()
                    .ok_or(EnrollmentError::InvalidPendingState)?;
                if encoded.len() != 64 || !encoded.is_ascii() {
                    return Err(EnrollmentError::InvalidPendingState);
                }
                let mut fingerprint = [0u8; 32];
                for (index, byte) in fingerprint.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                        .map_err(|_| EnrollmentError::InvalidPendingState)?;
                }
                TlsClient::from_pinned_fingerprint(&config.client.server_name, fingerprint)
            }
            None if !config
                .client
                .certificate_authority_file
                .try_exists()
                .map_err(|error| EnrollmentError::LocalCertificate(error.to_string()))? =>
            {
                TlsClient::for_initial_enrollment(&config.client.server_name)
            }
            None => TlsClient::from_ca_file(
                &config.client.certificate_authority_file,
                &config.client.server_name,
            ),
        }
        .map_err(|error| EnrollmentError::LocalCertificate(error.to_string()))?;
        (tls, config.client.server_addr.clone())
    };
    let stream = tokio::time::timeout(ENROLLMENT_TIMEOUT, tls.connect(&address))
        .await
        .map_err(|_| EnrollmentError::NetworkDetail("连接服务器超时，申请尚未提交".into()))?
        .map_err(|error| {
            EnrollmentError::NetworkDetail(format!("连接服务器失败，申请尚未提交：{error}"))
        })?;
    let key = if let Some(key) = legacy {
        key
    } else {
        let cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or(EnrollmentError::Network)?;
        EnrollmentKey::for_verified_server(
            approval
                .as_ref()
                .ok_or(EnrollmentError::InvalidFormat)?
                .purpose,
            &address,
            Sha256::digest(cert.as_ref()).into(),
        )?
    };
    let pending_existed = PendingEnrollment::exists(config_path);
    let mut pending = if pending_existed {
        PendingEnrollment::load(config_path)?
    } else if approval.is_some() && reuse {
        PendingEnrollment::create_reusing(config_path, &config.client.private_key_file, &key)?
    } else {
        PendingEnrollment::create(config_path, &config.client.private_key_file, &key)?
    };
    if pending.purpose() != key.purpose()
        || pending.server_addr() != key.server_addr()
        || pending.certificate_fingerprint()? != *key.certificate_fingerprint()
    {
        return Err(EnrollmentError::InvalidPendingState);
    }
    let approval = if let Some(intent) = approval {
        // Metadata written before profile support belongs to a v1 request. Its
        // signed bytes must remain identical when the same request ID is retried.
        let intent = if pending_existed && pending.requires_legacy_approval_intent() {
            rustgo_protocol::RegistrationIntent::new(&config.client.name, intent.purpose)?
        } else {
            intent
        };
        let encoded = pending.bind_approval_intent(&intent.encode())?;
        Some(rustgo_protocol::RegistrationIntent::decode(&encoded)?)
    } else {
        None
    };
    let wire_credential = if let Some(intent) = &approval {
        let keypair =
            rustgo_crypto::DeviceKeypair::load_private_file(pending.candidate_private_key())
                .map_err(|_| EnrollmentError::InvalidPendingState)?;
        let transcript = rustgo_crypto::AuthTranscript::new(
            b"rustgo-approval-v1".to_vec(),
            pending.request_id().as_bytes().to_vec(),
            1,
            intent.encode(),
        );
        let signature = rustgo_crypto::sign_auth(&keypair, &transcript);
        format!("{}:{}", intent.encode(), hex(&signature))
    } else {
        encoded_key.to_owned()
    };
    let operation = async {
        let codec = FrameCodec::new(MAX_PAYLOAD);
        let request = Message::EnrollmentRequest(EnrollmentRequest {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            enrollment_key: BoundedString::<MAX_ENROLLMENT_KEY_BYTES>::try_from(
                wire_credential.as_str(),
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
    let profile = config
        .client
        .profile
        .clone()
        .unwrap_or_else(|| rustgo_config::ClientProfile {
            display_name: config.client.name.clone(),
            uid: None,
            local_ip: None,
        });
    client.insert(
        "profile".to_owned(),
        toml::Value::try_from(&profile)
            .map_err(|_| EnrollmentError::ConfigurationIo(std::io::ErrorKind::InvalidData))?,
    );
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
    config.client.profile = Some(profile);
    config.client.identity_mode = Some(IdentityMode::Dynamic);
    config.client.server_addr = server_addr.to_owned();
    config.client.trust_mode = Some(TrustMode::Pinned);
    config.client.server_certificate_fingerprint = Some(hex(&fingerprint));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
