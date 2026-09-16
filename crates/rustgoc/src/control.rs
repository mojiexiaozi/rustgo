use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use rustgo_config::{ClientConfig, TrustMode, TunnelProtocol as ConfigTunnelProtocol};
use rustgo_crypto::{AuthTranscript, CryptoError, DeviceKeypair, sign_auth};
use rustgo_protocol::{
    BoundedBytes, BoundedString, BoundedVec, ClientAuthenticate, ClientHandshakeState, ClientHello,
    Frame, FrameCodec, FrameError, MAX_CLIENT_NAME_BYTES, MAX_FINGERPRINT_BYTES,
    MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES, MAX_TUNNEL_NAME_BYTES, Message, ProtocolErrorCode,
    ProtocolVersion, RegisterTunnels, TunnelProtocol, TunnelRegistration,
};
use rustgo_rendezvous::{ObservationGrant, PeerRelayFrame, RendezvousEnvelope};
use rustgo_transport::{TlsClient, TlsError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::telemetry::TelemetryControlWriteGate;

pub const CLIENT_VERSION: ProtocolVersion = ProtocolVersion::SUPPORTED;
const MAX_CONTROL_PAYLOAD: usize = 70 * 1024;
const CONTROL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct ControlClient {
    config: Arc<ClientConfig>,
    keypair: Arc<DeviceKeypair>,
    tls_client: TlsClient,
    heartbeat_interval: Duration,
    version: ProtocolVersion,
}

impl ControlClient {
    /// Loads every local credential used by the production client without
    /// creating or connecting a network socket.
    pub fn validate_credentials(config: &ClientConfig) -> Result<(), ClientError> {
        load_credentials(config).map(drop)
    }

    /// Builds every local security dependency before any network socket is opened.
    pub fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
        let (keypair, tls_client, heartbeat_interval) = load_credentials(&config)?;
        let version = internal_test_protocol_version()?;
        Ok(Self {
            config: Arc::new(config),
            keypair: Arc::new(keypair),
            tls_client,
            heartbeat_interval,
            version,
        })
    }

    pub(crate) fn with_effective_config(&self, config: ClientConfig) -> Self {
        let mut client = self.clone();
        client.config = Arc::new(config);
        client
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub(crate) fn tls_client(&self) -> TlsClient {
        self.tls_client.clone()
    }

    pub(crate) fn keypair(&self) -> Arc<DeviceKeypair> {
        self.keypair.clone()
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    pub async fn connect(&self) -> Result<ControlSession, ClientError> {
        tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, self.connect_inner(None))
            .await
            .map_err(|_| ClientError::HandshakeTimeout)?
    }

    async fn connect_inner(
        &self,
        update: Option<(u64, &rustgo_config::ManagedConfiguration)>,
    ) -> Result<ControlSession, ClientError> {
        let stream = self
            .tls_client
            .connect(&self.config.client.server_addr)
            .await?;
        let local_ip = stream.get_ref().0.local_addr()?.ip().to_string();
        let mut framed = FramedControl::new(stream);
        let mut state = ClientHandshakeState::new();

        let public_key = self.keypair.public_key();
        let fingerprint = public_key.fingerprint().to_string();
        let fingerprint = fingerprint
            .strip_prefix("sha256:")
            .ok_or(ClientError::InvalidIdentity)?;
        let hello = Message::ClientHello(ClientHello {
            client_name: BoundedString::<MAX_CLIENT_NAME_BYTES>::try_from(
                self.config.client.name.as_str(),
            )
            .map_err(|_| ClientError::InvalidConfiguration)?,
            fingerprint: BoundedBytes::<MAX_FINGERPRINT_BYTES>::try_from(fingerprint.as_bytes())
                .map_err(|_| ClientError::InvalidIdentity)?,
            heartbeat_interval_secs: u32::try_from(self.config.client.heartbeat_interval_secs)
                .map_err(|_| ClientError::InvalidConfiguration)?,
        });
        state = state.transition(&hello)?;
        framed.send(self.version, hello).await?;

        let challenge_frame = framed.receive().await?;
        let negotiated = negotiated_version(self.version, challenge_frame.version)?;
        let challenge = match challenge_frame.message {
            Message::ServerChallenge(challenge) => challenge,
            Message::Error(error) => return Err(ClientError::Protocol(error.code)),
            _ => return Err(ClientError::InvalidState),
        };
        state = state.transition(&Message::ServerChallenge(challenge.clone()))?;

        let transcript = AuthTranscript::new(
            challenge.challenge.as_slice().to_vec(),
            challenge.session_id.as_slice().to_vec(),
            transcript_version(negotiated)?,
            self.config.client.name.clone(),
        );
        let authentication = Message::ClientAuthenticate(ClientAuthenticate {
            public_key: BoundedBytes::<MAX_PUBLIC_KEY_BYTES>::try_from(
                public_key.to_string().as_bytes(),
            )
            .map_err(|_| ClientError::InvalidIdentity)?,
            signature: BoundedBytes::<MAX_SIGNATURE_BYTES>::try_from(
                sign_auth(&self.keypair, &transcript).as_slice(),
            )
            .map_err(|_| ClientError::InvalidIdentity)?,
        });
        state = state.transition(&authentication)?;
        framed.send(negotiated, authentication).await?;

        let auth_frame = framed.receive().await?;
        require_version(auth_frame.version, negotiated)?;
        let result = match auth_frame.message {
            Message::AuthResult(result) => result,
            Message::Error(error) => return Err(ClientError::Protocol(error.code)),
            _ => return Err(ClientError::InvalidState),
        };
        state = state.transition(&Message::AuthResult(result.clone()))?;
        if !result.accepted {
            return Err(ClientError::AuthenticationRejected);
        }

        if let Some((expected_revision, desired)) = update {
            if !negotiated.supports_managed_editing() {
                return Err(ClientError::ManagedUpdate(
                    "服务器版本不支持客户端修改，请先升级服务器".into(),
                ));
            }
            let configuration =
                serde_json::to_vec(desired).map_err(|_| ClientError::InvalidConfiguration)?;
            framed
                .send(
                    negotiated,
                    Message::ManagedConfigUpdate(rustgo_protocol::ManagedConfigUpdate {
                        expected_revision,
                        configuration: configuration
                            .try_into()
                            .map_err(|_| ClientError::InvalidConfiguration)?,
                    }),
                )
                .await?;
            let response = framed.receive().await?;
            require_version(response.version, negotiated)?;
            let Message::ManagedConfigUpdateResult(result) = response.message else {
                return Err(ClientError::InvalidState);
            };
            if let Some(error) = result.error {
                return Err(ClientError::ManagedUpdate(error.as_str().to_owned()));
            }
            if expected_revision.checked_add(1) != Some(result.revision) {
                return Err(ClientError::ManagedUpdate(
                    "服务器确认的配置版本不一致，请重新载入后核对".into(),
                ));
            }
            let mut session = ControlSession::new(
                framed,
                negotiated,
                challenge.session_id.into_vec(),
                self.heartbeat_interval,
                Vec::new().into(),
            );
            session.managed_revision = Some(result.revision);
            return Ok(session);
        }

        let mut effective = self.config.as_ref().clone();
        let mut managed_revision = None;
        if negotiated.supports_managed_configuration() {
            let mut value =
                serde_json::to_value(rustgo_config::ManagedConfiguration::from_client(&effective))
                    .map_err(|_| ClientError::InvalidConfiguration)?;
            if negotiated.supports_client_profile() {
                let profile = rustgo_config::ClientProfile {
                    display_name: effective.client.display_name().to_owned(),
                    uid: effective
                        .client
                        .profile
                        .as_ref()
                        .and_then(|p| p.uid.clone()),
                    local_ip: Some(local_ip.clone()),
                };
                value["client_profile"] =
                    serde_json::to_value(profile).map_err(|_| ClientError::InvalidConfiguration)?;
            }
            let configuration =
                serde_json::to_vec(&value).map_err(|_| ClientError::InvalidConfiguration)?;
            framed
                .send(
                    negotiated,
                    Message::ManagedConfigRequest(rustgo_protocol::ManagedConfigRequest {
                        configuration: BoundedBytes::try_from(configuration)
                            .map_err(|_| ClientError::InvalidConfiguration)?,
                    }),
                )
                .await?;
            let snapshot = framed.receive().await?;
            require_version(snapshot.version, negotiated)?;
            match snapshot.message {
                Message::ManagedConfigSnapshot(rustgo_protocol::ManagedConfigSnapshot {
                    revision,
                    configuration: Some(configuration),
                }) => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(configuration.as_slice())
                            .map_err(|_| ClientError::InvalidConfiguration)?;
                    if negotiated.supports_client_profile() {
                        if let Some(profile) = value
                            .as_object_mut()
                            .and_then(|v| v.remove("client_profile"))
                        {
                            let mut profile: rustgo_config::ClientProfile =
                                serde_json::from_value(profile)
                                    .map_err(|_| ClientError::InvalidConfiguration)?;
                            profile.local_ip = Some(local_ip.clone());
                            effective.client.profile = Some(profile);
                        }
                    }
                    if !value.as_object().is_some_and(|object| object.is_empty()) {
                        let desired: rustgo_config::ManagedConfiguration =
                            serde_json::from_value(value)
                                .map_err(|_| ClientError::InvalidConfiguration)?;
                        if let Err(error) = desired.apply_to(&mut effective) {
                            framed
                                .send(
                                    negotiated,
                                    rejected_configuration_report(
                                        revision,
                                        &desired,
                                        &error.to_string(),
                                    )?,
                                )
                                .await?;
                            return Err(ClientError::InvalidConfiguration);
                        }
                        managed_revision = Some(revision);
                    }
                }
                Message::ManagedConfigSnapshot(rustgo_protocol::ManagedConfigSnapshot {
                    configuration: None,
                    ..
                }) => {}
                Message::Error(error) => return Err(ClientError::Protocol(error.code)),
                _ => return Err(ClientError::InvalidState),
            }
        }
        let registration = registration_message(&effective)?;
        state = state.transition(&registration)?;
        if !state.is_active() {
            return Err(ClientError::InvalidState);
        }
        framed.send(negotiated, registration).await?;

        let results_frame = framed.receive().await?;
        require_version(results_frame.version, negotiated)?;
        let results = match results_frame.message {
            Message::TunnelResults(results) => results,
            Message::Error(error) => return Err(ClientError::Protocol(error.code)),
            _ => return Err(ClientError::InvalidState),
        };
        let registered_tunnels = correlate_results(&effective, results.results.into_vec())?;

        let mut session = ControlSession::new(
            framed,
            negotiated,
            challenge.session_id.into_vec(),
            self.heartbeat_interval,
            registered_tunnels,
        );
        session.effective_config = Some(Arc::new(effective));
        session.managed_revision = managed_revision;
        Ok(session)
    }
}

/// Save this device's server configuration using its existing TLS/device credentials.
/// The caller must stop its active client first; no automatic overwrite or retry occurs.
pub async fn update_managed_configuration(
    config: ClientConfig,
    expected_revision: u64,
    desired: rustgo_config::ManagedConfiguration,
) -> Result<u64, ClientError> {
    update_managed_inner(config, expected_revision, desired)
        .await
        .map_err(|error| {
            let reason = match &error {
                ClientError::ManagedUpdate(_) => return error,
                ClientError::AuthenticationRejected => {
                    "服务器拒绝设备认证，请检查授权或等待旧连接退出"
                }
                ClientError::Crypto(_) | ClientError::InvalidIdentity => {
                    "设备凭据不可用，请检查本地密钥文件"
                }
                ClientError::Tls(_) => "无法建立安全连接，请检查服务器地址、证书和网络",
                ClientError::Io(_) | ClientError::Closed => {
                    "与服务器的连接中断，保存结果未确认，请重新载入配置核对"
                }
                ClientError::InvalidConfiguration => "客户端配置无效，请检查本地设置",
                _ => "保存未获有效确认，请检查程序版本并重新载入服务器配置核对",
            };
            ClientError::ManagedUpdate(format!("{reason}（详情：{error}）"))
        })
}

async fn update_managed_inner(
    config: ClientConfig,
    expected_revision: u64,
    mut desired: rustgo_config::ManagedConfiguration,
) -> Result<u64, ClientError> {
    desired.p2p_enabled = config.p2p.as_ref().is_some_and(|p| p.enabled);
    desired
        .apply_to(&mut config.clone())
        .map_err(|error| ClientError::ManagedUpdate(format!("配置无效：{error}")))?;
    let client = ControlClient::from_config(config)?;
    let session = tokio::time::timeout(
        CONTROL_HANDSHAKE_TIMEOUT,
        client.connect_inner(Some((expected_revision, &desired))),
    )
    .await
    .map_err(|_| {
        ClientError::ManagedUpdate("保存超时，结果尚未确认，请重新载入服务器配置核对".into())
    })??;
    session.managed_revision.ok_or(ClientError::InvalidState)
}

fn rejected_configuration_report(
    revision: u64,
    desired: &rustgo_config::ManagedConfiguration,
    error: &str,
) -> Result<Message, ClientError> {
    let mut results = desired
        .tunnels
        .iter()
        .map(|item| ("tunnel", &item.name))
        .chain(desired.exports.iter().map(|item| ("export", &item.name)))
        .chain(desired.forwards.iter().map(|item| ("forward", &item.name)))
        .map(
            |(kind, name)| serde_json::json!({"kind":kind,"name":name,"state":"failed","error":""}),
        )
        .collect::<Vec<_>>();
    let baseline = serde_json::to_vec(&results)
        .map_err(|_| ClientError::InvalidConfiguration)?
        .len();
    let error_budget = 65536usize.saturating_sub(baseline) / results.len().max(1);
    let mut detail = error.to_owned();
    while detail.len() > 2048
        || serde_json::to_string(&detail)
            .map_err(|_| ClientError::InvalidConfiguration)?
            .len()
            .saturating_sub(2)
            > error_budget
    {
        detail.pop();
    }
    for result in &mut results {
        result["error"] = serde_json::Value::String(detail.clone());
    }
    let results = serde_json::to_vec(&results).map_err(|_| ClientError::InvalidConfiguration)?;
    Ok(Message::ManagedConfigReport(
        rustgo_protocol::ManagedConfigReport {
            revision,
            results: BoundedBytes::try_from(results)
                .map_err(|_| ClientError::InvalidConfiguration)?,
        },
    ))
}

fn load_credentials(
    config: &ClientConfig,
) -> Result<(DeviceKeypair, TlsClient, Duration), ClientError> {
    config
        .validate()
        .map_err(|_| ClientError::InvalidConfiguration)?;
    let heartbeat_interval_secs = u32::try_from(config.client.heartbeat_interval_secs)
        .map_err(|_| ClientError::InvalidConfiguration)?;
    if heartbeat_interval_secs == 0 {
        return Err(ClientError::InvalidConfiguration);
    }
    let keypair = DeviceKeypair::load_private_file(&config.client.private_key_file)?;
    let tls_client = match config.client.trust_mode {
        Some(TrustMode::Pinned) => TlsClient::from_pinned_fingerprint(
            &config.client.server_name,
            decode_fingerprint(
                config
                    .client
                    .server_certificate_fingerprint
                    .as_deref()
                    .ok_or(ClientError::InvalidConfiguration)?,
            )?,
        )?,
        None => TlsClient::from_ca_file(
            &config.client.certificate_authority_file,
            &config.client.server_name,
        )?,
    };
    Ok((
        keypair,
        tls_client,
        Duration::from_secs(u64::from(heartbeat_interval_secs)),
    ))
}

fn decode_fingerprint(encoded: &str) -> Result<[u8; 32], ClientError> {
    if encoded.len() != 64 {
        return Err(ClientError::InvalidConfiguration);
    }
    let mut fingerprint = [0_u8; 32];
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| ClientError::InvalidConfiguration)?;
    }
    Ok(fingerprint)
}

fn negotiated_version(
    local_version: ProtocolVersion,
    server_version: ProtocolVersion,
) -> Result<ProtocolVersion, ClientError> {
    let negotiated = local_version
        .negotiate(server_version)
        .map_err(ClientError::Protocol)?;
    if negotiated != server_version {
        return Err(ClientError::InvalidState);
    }
    Ok(negotiated)
}

fn internal_test_protocol_version() -> Result<ProtocolVersion, ClientError> {
    if std::env::var("RUSTGO_INTERNAL_TESTING").as_deref() != Ok("1") {
        return Ok(CLIENT_VERSION);
    }
    let minor = std::env::var("RUSTGO_TEST_PROTOCOL_MINOR")
        .ok()
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| ClientError::InvalidConfiguration)
        })
        .transpose()?
        .unwrap_or(CLIENT_VERSION.minor);
    Ok(ProtocolVersion::new(CLIENT_VERSION.major, minor))
}

fn require_version(
    actual: ProtocolVersion,
    negotiated: ProtocolVersion,
) -> Result<(), ClientError> {
    if actual == negotiated {
        Ok(())
    } else {
        Err(ClientError::InvalidState)
    }
}

fn transcript_version(version: ProtocolVersion) -> Result<u16, ClientError> {
    if version.major > u16::from(u8::MAX) || version.minor > u16::from(u8::MAX) {
        return Err(ClientError::InvalidState);
    }
    Ok((version.major << 8) | version.minor)
}

fn registration_message(config: &ClientConfig) -> Result<Message, ClientError> {
    let mut tunnels = Vec::with_capacity(config.tunnels.len());
    for (index, tunnel) in config.tunnels.iter().enumerate() {
        let tunnel_id = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ClientError::InvalidConfiguration)?;
        tunnels.push(TunnelRegistration {
            tunnel_id,
            name: BoundedString::<MAX_TUNNEL_NAME_BYTES>::try_from(tunnel.name.as_str())
                .map_err(|_| ClientError::InvalidConfiguration)?,
            protocol: match tunnel.protocol {
                ConfigTunnelProtocol::Tcp => TunnelProtocol::TCP,
                ConfigTunnelProtocol::Udp => TunnelProtocol::UDP,
            },
            remote_port: u16::try_from(tunnel.remote_port)
                .map_err(|_| ClientError::InvalidConfiguration)?,
        });
    }
    Ok(Message::RegisterTunnels(RegisterTunnels {
        tunnels: BoundedVec::try_from(tunnels).map_err(|_| ClientError::InvalidConfiguration)?,
    }))
}

fn correlate_results(
    config: &ClientConfig,
    results: Vec<rustgo_protocol::TunnelResult>,
) -> Result<Arc<[RegisteredTunnel]>, ClientError> {
    if results.len() != config.tunnels.len() {
        return Err(ClientError::InvalidTunnelResults);
    }
    let mut by_id = HashMap::with_capacity(results.len());
    for result in results {
        if result.tunnel_id == 0 || by_id.insert(result.tunnel_id, result).is_some() {
            return Err(ClientError::InvalidTunnelResults);
        }
    }
    let mut registered = Vec::with_capacity(config.tunnels.len());
    for (index, tunnel) in config.tunnels.iter().enumerate() {
        let tunnel_id = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ClientError::InvalidTunnelResults)?;
        let result = by_id
            .remove(&tunnel_id)
            .ok_or(ClientError::InvalidTunnelResults)?;
        registered.push(RegisteredTunnel {
            tunnel_id,
            name: tunnel.name.clone(),
            protocol: tunnel.protocol,
            local_addr: tunnel.local_addr.clone(),
            remote_port: u16::try_from(tunnel.remote_port)
                .map_err(|_| ClientError::InvalidTunnelResults)?,
            accepted: result.accepted,
            error: result.error,
        });
    }
    if !by_id.is_empty() {
        return Err(ClientError::InvalidTunnelResults);
    }
    Ok(registered.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredTunnel {
    tunnel_id: u32,
    name: String,
    protocol: ConfigTunnelProtocol,
    local_addr: String,
    remote_port: u16,
    accepted: bool,
    error: Option<ProtocolErrorCode>,
}

impl RegisteredTunnel {
    #[cfg(test)]
    pub(crate) fn accepted_for_test(tunnel_id: u32, protocol: ConfigTunnelProtocol) -> Self {
        Self {
            tunnel_id,
            name: format!("test-{tunnel_id}"),
            protocol,
            local_addr: "127.0.0.1:1".to_owned(),
            remote_port: 1,
            accepted: true,
            error: None,
        }
    }

    pub const fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn protocol(&self) -> ConfigTunnelProtocol {
        self.protocol
    }

    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }

    pub const fn remote_port(&self) -> u16 {
        self.remote_port
    }

    pub const fn accepted(&self) -> bool {
        self.accepted
    }

    pub const fn error(&self) -> Option<ProtocolErrorCode> {
        self.error
    }

    /// Human-readable registration failure, shared by the GUI and managed reports.
    pub fn error_message(&self) -> Option<String> {
        let code = self.error?;
        let reason = match code {
            ProtocolErrorCode::TUNNEL_PORT_IN_USE => {
                format!("服务器端口 {} 已被占用，请更换远程端口", self.remote_port)
            }
            ProtocolErrorCode::TUNNEL_PERMISSION_DENIED => format!(
                "服务器无权监听端口 {}，请更换端口或检查服务权限",
                self.remote_port
            ),
            ProtocolErrorCode::TUNNEL_REJECTED => {
                "服务端拒绝注册隧道，请检查隧道配置、数量限制及服务端日志".to_owned()
            }
            ProtocolErrorCode::UDP_BIND_ADDRESS_REQUIRED => {
                "服务器未配置 UDP 监听地址，请设置 server.udp_bind_ip".to_owned()
            }
            ProtocolErrorCode::AUTHENTICATION_FAILED => {
                "客户端身份验证失败，请检查设备授权".to_owned()
            }
            ProtocolErrorCode::UNSUPPORTED_VERSION => {
                "客户端与服务器协议版本不兼容，请升级程序".to_owned()
            }
            ProtocolErrorCode::UNKNOWN_MESSAGE => {
                "收到无法识别的协议消息，请检查程序版本".to_owned()
            }
            ProtocolErrorCode::INVALID_FRAME => {
                "通信数据格式错误，请检查程序版本及服务端日志".to_owned()
            }
            ProtocolErrorCode::PAYLOAD_TOO_LARGE => {
                "通信数据超过大小限制，请减少配置内容".to_owned()
            }
            ProtocolErrorCode::INVALID_STATE => "连接状态异常，请重新连接".to_owned(),
            ProtocolErrorCode::UNKNOWN_SESSION => "连接会话已失效，请重新连接".to_owned(),
            ProtocolErrorCode::INCOMPATIBLE_HEARTBEAT => {
                "心跳配置不兼容，请检查客户端与服务器心跳设置".to_owned()
            }
            ProtocolErrorCode::INTERNAL => "服务器内部错误，请查看服务端日志".to_owned(),
            _ => "服务端返回未知错误，请查看服务端日志".to_owned(),
        };
        Some(format!("{reason}（错误码 {}）", code.as_u16()))
    }
}

pub struct ControlSession {
    pub(crate) framed: FramedControl,
    pub(crate) version: ProtocolVersion,
    pub(crate) session_id: Vec<u8>,
    pub(crate) heartbeat_interval: Duration,
    registered_tunnels: Arc<[RegisteredTunnel]>,
    effective_config: Option<Arc<ClientConfig>>,
    managed_revision: Option<u64>,
}

#[cfg(test)]
mod registration_error_tests {
    use super::*;

    #[test]
    fn occupied_port_has_chinese_reason_and_action() {
        let mut tunnel = RegisteredTunnel::accepted_for_test(1, ConfigTunnelProtocol::Tcp);
        tunnel.remote_port = 10022;
        tunnel.error = Some(ProtocolErrorCode::TUNNEL_PORT_IN_USE);
        assert_eq!(
            tunnel.error_message().unwrap(),
            "服务器端口 10022 已被占用，请更换远程端口（错误码 11）"
        );
        tunnel.error = Some(ProtocolErrorCode::TUNNEL_REJECTED);
        let reason = tunnel.error_message().unwrap();
        assert!(reason.contains("服务端拒绝注册隧道"));
        assert!(!reason.contains("已被占用"));
        assert!(!reason.contains("ProtocolErrorCode"));
        tunnel.error = None;
        assert_eq!(tunnel.error_message(), None);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    ObservationGrant(ObservationGrant),
    Rendezvous(RendezvousEnvelope),
    ServerNotice(rustgo_protocol::ServerNotice),
    PeerRelayFrame(PeerRelayFrame),
    PeerIdentityBinding(rustgo_protocol::PeerIdentityBinding),
    PunchGrant(rustgo_protocol::PunchGrant),
}

impl ControlSession {
    pub(crate) fn new(
        framed: FramedControl,
        version: ProtocolVersion,
        session_id: Vec<u8>,
        heartbeat_interval: Duration,
        registered_tunnels: Arc<[RegisteredTunnel]>,
    ) -> Self {
        Self {
            framed,
            version,
            session_id,
            heartbeat_interval,
            registered_tunnels,
            effective_config: None,
            managed_revision: None,
        }
    }

    pub(crate) fn managed_report(&self) -> Option<(u64, Vec<serde_json::Value>)> {
        let revision = self.managed_revision?;
        let mut results = self.registered_tunnels.iter().map(|tunnel| serde_json::json!({"kind":"tunnel","name":tunnel.name(),"state":if tunnel.accepted() {"ready"} else {"failed"},"error":tunnel.error_message()})).collect::<Vec<_>>();
        if let Some(config) = self.effective_config() {
            results.extend(config.exports.iter().map(|export| serde_json::json!({"kind":"export","name":export.name,"state":"ready","error":null})));
        }
        Some((revision, results))
    }

    pub fn effective_config(&self) -> Option<&ClientConfig> {
        self.effective_config.as_deref()
    }

    pub fn managed_revision(&self) -> Option<u64> {
        self.managed_revision
    }

    pub fn registered_tunnels(&self) -> &[RegisteredTunnel] {
        &self.registered_tunnels
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    pub(crate) const fn supports_telemetry(&self) -> bool {
        self.version.supports_telemetry()
    }

    pub async fn request_observation_grant(&mut self) -> Result<(), ClientError> {
        self.require_v02()?;
        self.framed
            .send(
                self.version,
                Message::ObservationGrantRequest(rustgo_protocol::ObservationGrantRequest {}),
            )
            .await
    }

    pub async fn request_peer_identity(
        &mut self,
        session_id: rustgo_rendezvous::SessionId,
        peer: &str,
    ) -> Result<(), ClientError> {
        self.require_v02()?;
        self.framed
            .send(
                self.version,
                Message::PeerIdentityLookup(rustgo_protocol::PeerIdentityLookup {
                    session_id: *session_id.as_bytes(),
                    peer: BoundedString::try_from(peer).map_err(|_| ClientError::InvalidState)?,
                }),
            )
            .await
    }

    pub async fn send_rendezvous_envelope(
        &mut self,
        envelope: &RendezvousEnvelope,
    ) -> Result<(), ClientError> {
        self.require_v02()?;
        if envelope.version != self.version {
            return Err(ClientError::InvalidState);
        }
        let message = envelope
            .to_protocol_message()
            .map_err(|_| ClientError::InvalidState)?;
        self.framed.send(self.version, message).await
    }

    pub async fn send_peer_relay_frame(
        &mut self,
        frame: &PeerRelayFrame,
    ) -> Result<(), ClientError> {
        self.require_v02()?;
        let message = frame
            .to_protocol_message()
            .map_err(|_| ClientError::InvalidState)?;
        self.framed.send(self.version, message).await
    }

    pub async fn next_control_event(&mut self) -> Result<ControlEvent, ClientError> {
        self.require_v02()?;
        let frame = self.framed.receive().await?;
        require_version(frame.version, self.version)?;
        match frame.message {
            message @ Message::ObservationGrant(_) => {
                ObservationGrant::from_protocol_message(message)
                    .map(ControlEvent::ObservationGrant)
                    .map_err(|_| ClientError::InvalidState)
            }
            message if is_rendezvous_message(&message) => {
                RendezvousEnvelope::from_protocol_message(message)
                    .map(ControlEvent::Rendezvous)
                    .map_err(|_| ClientError::InvalidState)
            }
            Message::ServerNotice(notice) => Ok(ControlEvent::ServerNotice(notice)),
            message @ Message::PeerRelayFrame(_) => PeerRelayFrame::from_protocol_message(message)
                .map(ControlEvent::PeerRelayFrame)
                .map_err(|_| ClientError::InvalidState),
            Message::PeerIdentityBinding(binding) => Ok(ControlEvent::PeerIdentityBinding(binding)),
            Message::PunchGrant(grant) => Ok(ControlEvent::PunchGrant(grant)),
            Message::Error(error) => Err(ClientError::Protocol(error.code)),
            _ => Err(ClientError::InvalidState),
        }
    }

    fn require_v02(&self) -> Result<(), ClientError> {
        if self.version.major == ProtocolVersion::V0_2.major
            && self.version.minor >= ProtocolVersion::V0_2.minor
        {
            Ok(())
        } else {
            Err(ClientError::Protocol(
                ProtocolErrorCode::UNSUPPORTED_VERSION,
            ))
        }
    }

    pub(crate) fn registered_tunnels_shared(&self) -> Arc<[RegisteredTunnel]> {
        self.registered_tunnels.clone()
    }
}

fn is_rendezvous_message(message: &Message) -> bool {
    matches!(
        message,
        Message::RendezvousRequest(_)
            | Message::RendezvousProviderDecision(_)
            | Message::RendezvousCandidateSet(_)
            | Message::RendezvousCandidateSetV2(_)
            | Message::RendezvousConnectivityResult(_)
            | Message::RendezvousRelayRequest(_)
            | Message::RendezvousClose(_)
            | Message::RendezvousError(_)
    )
}

impl std::fmt::Debug for ControlSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlSession")
            .field("version", &self.version)
            .field("session_id", &"[REDACTED]")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("registered_tunnels", &self.registered_tunnels)
            .finish_non_exhaustive()
    }
}

trait ControlIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ControlIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct GatedControlIo {
    inner: Box<dyn ControlIo>,
    gate: Arc<dyn TelemetryControlWriteGate>,
}

impl AsyncRead for GatedControlIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for GatedControlIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.gate.poll_write(context).is_pending() {
            Poll::Pending
        } else {
            Pin::new(&mut *self.inner).poll_write(context, buffer)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(context)
    }
}

pub(crate) struct FramedControl {
    stream: Box<dyn ControlIo>,
    read_buffer: BytesMut,
    codec: FrameCodec,
}

impl FramedControl {
    pub(crate) fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            stream: Box::new(stream),
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(MAX_CONTROL_PAYLOAD),
        }
    }

    pub(crate) fn install_telemetry_write_gate(
        &mut self,
        gate: Arc<dyn TelemetryControlWriteGate>,
    ) {
        let (placeholder, _) = tokio::io::duplex(1);
        let inner = std::mem::replace(&mut self.stream, Box::new(placeholder));
        self.stream = Box::new(GatedControlIo { inner, gate });
    }

    pub(crate) async fn receive(&mut self) -> Result<Frame, ClientError> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.read_buffer)? {
                return Ok(frame);
            }
            if self.read_buffer.len() >= MAX_CONTROL_PAYLOAD + rustgo_protocol::HEADER_LEN {
                return Err(ClientError::FrameTooLarge);
            }
            if self.stream.read_buf(&mut self.read_buffer).await? == 0 {
                return Err(ClientError::Closed);
            }
        }
    }

    pub(crate) async fn send(
        &mut self,
        version: ProtocolVersion,
        message: Message,
    ) -> Result<(), ClientError> {
        let encoded = self.codec.encode(version, 0, &message)?;
        self.stream.write_all(&encoded).await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("{0}")]
    ManagedUpdate(String),
    #[error("invalid client configuration")]
    InvalidConfiguration,
    #[error("invalid client identity")]
    InvalidIdentity,
    #[error("TLS transport failed: {0}")]
    Tls(#[from] TlsError),
    #[error("device identity failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("control frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("control protocol state failed: {0}")]
    State(#[from] rustgo_protocol::StateError),
    #[error("control I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("server rejected authentication")]
    AuthenticationRejected,
    #[error("server rejected control protocol operation with code {0:?}")]
    Protocol(ProtocolErrorCode),
    #[error("server returned an invalid control protocol state")]
    InvalidState,
    #[error("server returned invalid tunnel registration results")]
    InvalidTunnelResults,
    #[error("control connection closed")]
    Closed,
    #[error("control frame exceeded the configured maximum")]
    FrameTooLarge,
    #[error("client task failed to join")]
    TaskJoin,
    #[error("peer generation owner failed during teardown")]
    PeerGenerationFailed,
    #[error("a persistent data session terminated while its control generation was active")]
    DataSessionTerminated,
    #[error("client session generation exhausted")]
    GenerationExhausted,
    #[error("client heartbeat sequence exhausted")]
    SequenceExhausted,
    #[error("server heartbeat response timed out")]
    HeartbeatTimeout,
    #[error("control connection handshake timed out")]
    HandshakeTimeout,
    #[error("active control write timed out")]
    ControlWriteTimeout,
    #[error("low-priority telemetry write timed out; control generation must reconnect")]
    TelemetryWriteTimeout,
}
