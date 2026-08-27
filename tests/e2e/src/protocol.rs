use std::{io, net::Ipv4Addr, path::Path};

use bytes::BytesMut;
use rustgo_crypto::{AuthTranscript, DeviceKeypair, sign_auth};
use rustgo_protocol::{
    AuthResult, BoundExceeded, BoundedBytes, BoundedString, ClientAuthenticate, ClientHello, Frame,
    FrameCodec, FrameError, Message, ProtocolErrorCode, ProtocolVersion, ServerChallenge,
};
use rustgo_transport::{TlsClient, TlsError};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::client::TlsStream;

const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const FRAME_MAX: usize = 70 * 1024;

#[derive(Debug, Error)]
pub enum ScriptedProtocolError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Bound(#[from] BoundExceeded),
    #[error("the peer closed the scripted protocol connection")]
    ConnectionClosed,
    #[error("the peer returned an unexpected scripted protocol message")]
    UnexpectedMessage,
}

pub struct ScriptedProtocolClient {
    stream: TlsStream<TcpStream>,
    read_buffer: BytesMut,
    codec: FrameCodec,
}

impl ScriptedProtocolClient {
    pub async fn connect(
        certificate_authority_file: impl AsRef<Path>,
        server_name: &str,
        address: std::net::SocketAddr,
    ) -> Result<Self, ScriptedProtocolError> {
        let tls = TlsClient::from_ca_file(certificate_authority_file, server_name)?;
        let stream = tls.connect(address).await?;
        Ok(Self {
            stream,
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(FRAME_MAX),
        })
    }

    pub async fn connect_from(
        certificate_authority_file: impl AsRef<Path>,
        server_name: &str,
        address: std::net::SocketAddr,
        source: Ipv4Addr,
    ) -> Result<Self, ScriptedProtocolError> {
        let socket = TcpSocket::new_v4()?;
        socket.bind((source, 0).into())?;
        let socket = socket.connect(address).await?;
        let tls = TlsClient::from_ca_file(certificate_authority_file, server_name)?;
        let stream = tls.handshake(socket).await?;
        Ok(Self {
            stream,
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(FRAME_MAX),
        })
    }

    pub async fn send(
        &mut self,
        version: ProtocolVersion,
        message: Message,
    ) -> Result<(), ScriptedProtocolError> {
        let encoded = self.codec.encode(version, 0, &message)?;
        self.stream.write_all(&encoded).await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Frame, ScriptedProtocolError> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.read_buffer)? {
                return Ok(frame);
            }
            if self.stream.read_buf(&mut self.read_buffer).await? == 0 {
                return Err(ScriptedProtocolError::ConnectionClosed);
            }
        }
    }

    pub async fn abort_after_response(
        mut self,
        version: ProtocolVersion,
        message: Message,
    ) -> Result<(), ScriptedProtocolError> {
        self.send(version, message).await?;
        let response = self.receive().await?;
        if response.message
            != Message::AuthResult(AuthResult {
                accepted: false,
                error: Some(ProtocolErrorCode::AUTHENTICATION_FAILED),
            })
        {
            return Err(ScriptedProtocolError::UnexpectedMessage);
        }
        self.set_zero_linger()?;
        Ok(())
    }

    pub fn set_zero_linger(&self) -> io::Result<()> {
        self.stream.get_ref().0.set_zero_linger()
    }
}

#[derive(Clone)]
pub struct AuthenticationChallenge {
    pub challenge: Vec<u8>,
    pub session_id: Vec<u8>,
}

pub async fn begin_authentication(
    client: &mut ScriptedProtocolClient,
    version: ProtocolVersion,
    name: &str,
    fingerprint_key: &DeviceKeypair,
) -> Result<AuthenticationChallenge, ScriptedProtocolError> {
    begin_authentication_with_fingerprint(
        client,
        version,
        name,
        wire_fingerprint(fingerprint_key).as_slice(),
    )
    .await
}

pub async fn begin_authentication_with_fingerprint(
    client: &mut ScriptedProtocolClient,
    version: ProtocolVersion,
    name: &str,
    fingerprint: &[u8],
) -> Result<AuthenticationChallenge, ScriptedProtocolError> {
    client
        .send(
            version,
            Message::ClientHello(ClientHello {
                client_name: BoundedString::try_from(name)?,
                fingerprint: BoundedBytes::try_from(fingerprint)?,
                heartbeat_interval_secs: 1,
            }),
        )
        .await?;
    let Frame {
        message:
            Message::ServerChallenge(ServerChallenge {
                challenge,
                session_id,
            }),
        ..
    } = client.receive().await?
    else {
        return Err(ScriptedProtocolError::UnexpectedMessage);
    };
    Ok(AuthenticationChallenge {
        challenge: challenge.into_vec(),
        session_id: session_id.into_vec(),
    })
}

pub fn authentication_message(
    challenge: &AuthenticationChallenge,
    public_key: &DeviceKeypair,
    signing_key: &DeviceKeypair,
    transcript_version_value: ProtocolVersion,
    transcript_name: &str,
) -> Message {
    let transcript = AuthTranscript::new(
        challenge.challenge.clone(),
        challenge.session_id.clone(),
        transcript_version(transcript_version_value),
        transcript_name.to_owned(),
    );
    Message::ClientAuthenticate(ClientAuthenticate {
        public_key: BoundedBytes::try_from(public_key.public_key().to_string().as_bytes())
            .expect("an Ed25519 public key fits the protocol bound"),
        signature: BoundedBytes::try_from(sign_auth(signing_key, &transcript).as_slice())
            .expect("an Ed25519 signature fits the protocol bound"),
    })
}

pub async fn finish_authentication(
    client: &mut ScriptedProtocolClient,
    version: ProtocolVersion,
    authentication: Message,
) -> Result<AuthResult, ScriptedProtocolError> {
    client.send(version, authentication).await?;
    let Frame {
        message: Message::AuthResult(result),
        ..
    } = client.receive().await?
    else {
        return Err(ScriptedProtocolError::UnexpectedMessage);
    };
    Ok(result)
}

pub async fn authenticate(
    client: &mut ScriptedProtocolClient,
    name: &str,
    key: &DeviceKeypair,
) -> Result<AuthResult, ScriptedProtocolError> {
    let challenge = begin_authentication(client, VERSION, name, key).await?;
    finish_authentication(
        client,
        VERSION,
        authentication_message(&challenge, key, key, VERSION, name),
    )
    .await
}

pub fn wire_fingerprint(key: &DeviceKeypair) -> Vec<u8> {
    key.public_key()
        .fingerprint()
        .to_string()
        .strip_prefix("sha256:")
        .expect("fingerprints use the sha256 prefix")
        .as_bytes()
        .to_vec()
}

fn transcript_version(version: ProtocolVersion) -> u16 {
    assert!(version.major <= u8::MAX.into() && version.minor <= u8::MAX.into());
    (version.major << 8) | version.minor
}
