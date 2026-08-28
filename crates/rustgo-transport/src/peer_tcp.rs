use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use rustgo_crypto::{
    EphemeralPeerKey, PEER_HANDSHAKE_TAG_BYTES, PEER_TRANSPORT_BINDING_BYTES, PeerCryptoError,
    PeerFrameOpener, PeerFrameSealer, PeerRole, PeerSessionKeys, PeerTranscript,
};
use rustgo_nat::TcpPuncher;
use rustgo_path::{PathAttempt, PathError, PathKind, SelectedPath};
use rustgo_rendezvous::{PeerRelayFlags, PeerRelayFrame};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

const AUTH_MAGIC: &[u8; 8] = b"RGOTCP01";
const AUTH_RECORD_BYTES: usize = 8 + 1 + PEER_HANDSHAKE_TAG_BYTES;
const AUTH_INITIATOR: u8 = 1;
const AUTH_RESPONDER: u8 = 2;
const MAX_WIRE_FRAME_BYTES: usize = 70 * 1024;
const TCP_TRANSPORT_BINDING: [u8; PEER_TRANSPORT_BINDING_BYTES] = [0x54; 32];
pub const MAX_PEER_TCP_PLAINTEXT_BYTES: usize = 60 * 1024;

#[derive(Debug, Error)]
pub enum PeerTcpError {
    #[error("native TCP I/O failed")]
    Io(#[from] std::io::Error),
    #[error("native TCP peer authentication failed")]
    AuthenticationFailed,
    #[error("native TCP peer authentication timed out")]
    AuthenticationTimedOut,
    #[error("native TCP operation was cancelled")]
    Cancelled,
    #[error("native TCP peer frame exceeds its hard bound")]
    FrameTooLarge,
    #[error("native TCP peer frame is malformed")]
    MalformedFrame,
    #[error("native TCP peer cryptography failed")]
    Crypto(#[from] PeerCryptoError),
}

pub struct PeerTcpAuthentication {
    role: PeerRole,
    keys: PeerSessionKeys,
}

impl PeerTcpAuthentication {
    pub fn new(
        role: PeerRole,
        local_ephemeral: EphemeralPeerKey,
        transcript: PeerTranscript,
    ) -> Result<Self, PeerTcpError> {
        Ok(Self {
            role,
            keys: PeerSessionKeys::derive(role, local_ephemeral, &transcript)?,
        })
    }
}

impl fmt::Debug for PeerTcpAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerTcpAuthentication([REDACTED])")
    }
}

pub trait PeerTcpAuthenticationFactory: Send + Sync {
    fn create(&self) -> Result<PeerTcpAuthentication, PeerTcpError>;
}

pub struct EncryptedPeerTcp {
    reader: Mutex<ReadHalf<TcpStream>>,
    writer: Mutex<WriteHalf<TcpStream>>,
    opener: Mutex<PeerFrameOpener>,
    sealer: Mutex<PeerFrameSealer>,
}

impl EncryptedPeerTcp {
    pub async fn authenticate(
        mut stream: TcpStream,
        authentication: PeerTcpAuthentication,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<Self, PeerTcpError> {
        let exchange = async {
            let local = auth_record(
                authentication.role,
                authentication.keys.handshake_tag(&TCP_TRANSPORT_BINDING),
            );
            let peer = match authentication.role {
                PeerRole::Initiator => {
                    stream.write_all(&local).await?;
                    read_auth_record(&mut stream).await?
                }
                PeerRole::Responder => {
                    let peer = read_auth_record(&mut stream).await?;
                    stream.write_all(&local).await?;
                    peer
                }
            };
            let expected_role = match authentication.role {
                PeerRole::Initiator => AUTH_RESPONDER,
                PeerRole::Responder => AUTH_INITIATOR,
            };
            if peer[8] != expected_role || &peer[..8] != AUTH_MAGIC {
                return Err(PeerTcpError::AuthenticationFailed);
            }
            let tag: [u8; PEER_HANDSHAKE_TAG_BYTES] = peer[9..]
                .try_into()
                .map_err(|_| PeerTcpError::AuthenticationFailed)?;
            authentication
                .keys
                .verify_handshake_tag(&TCP_TRANSPORT_BINDING, &tag)?;
            Ok::<_, PeerTcpError>((stream, authentication.keys))
        };
        let (stream, mut keys) = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(PeerTcpError::Cancelled),
            result = tokio::time::timeout(timeout, exchange) => result.map_err(|_| PeerTcpError::AuthenticationTimedOut)??,
        };
        let sealer = keys.stream_sealer(1)?;
        let opener = keys.stream_opener(1)?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            opener: Mutex::new(opener),
            sealer: Mutex::new(sealer),
        })
    }

    pub async fn send(&self, plaintext: &[u8]) -> Result<(), PeerTcpError> {
        if plaintext.len() > MAX_PEER_TCP_PLAINTEXT_BYTES {
            return Err(PeerTcpError::FrameTooLarge);
        }
        let frame = self
            .sealer
            .lock()
            .await
            .seal(plaintext, PeerRelayFlags::RELIABLE)?;
        write_frame(&mut *self.writer.lock().await, &frame).await
    }

    pub async fn receive(&self) -> Result<Option<Vec<u8>>, PeerTcpError> {
        let frame = read_frame(&mut *self.reader.lock().await).await?;
        let is_fin = frame.flags.bits() & PeerRelayFlags::FIN.bits() != 0;
        let plaintext = self.opener.lock().await.open(&frame)?;
        if is_fin {
            Ok(None)
        } else {
            Ok(Some(plaintext))
        }
    }

    pub async fn shutdown(&self) -> Result<(), PeerTcpError> {
        let frame = self
            .sealer
            .lock()
            .await
            .seal(&[], PeerRelayFlags::RELIABLE | PeerRelayFlags::FIN)?;
        let mut writer = self.writer.lock().await;
        write_frame(&mut writer, &frame).await?;
        writer.shutdown().await?;
        Ok(())
    }
}

pub struct TcpPathAttempt {
    local: SocketAddr,
    candidates: Vec<SocketAddr>,
    connect_timeout: Duration,
    authentication_timeout: Duration,
    authentication_factory: Arc<dyn PeerTcpAuthenticationFactory>,
}

impl TcpPathAttempt {
    pub fn new(
        local: SocketAddr,
        candidates: Vec<SocketAddr>,
        connect_timeout: Duration,
        authentication_timeout: Duration,
        authentication_factory: Arc<dyn PeerTcpAuthenticationFactory>,
    ) -> Self {
        Self {
            local,
            candidates,
            connect_timeout,
            authentication_timeout,
            authentication_factory,
        }
    }
}

#[async_trait]
impl PathAttempt for TcpPathAttempt {
    fn kind(&self) -> PathKind {
        PathKind::NativeTcp
    }

    async fn connect(&self, cancellation: CancellationToken) -> Result<SelectedPath, PathError> {
        let authentication = self
            .authentication_factory
            .create()
            .map_err(|_| PathError::AttemptFailed(PathKind::NativeTcp))?;
        let stream = TcpPuncher::connect(
            self.local,
            self.candidates.clone(),
            tokio::time::Instant::now() + self.connect_timeout,
            cancellation.clone(),
        )
        .await
        .map_err(|error| {
            if matches!(error, rustgo_nat::TcpPunchError::Cancelled) {
                PathError::Cancelled
            } else {
                PathError::AttemptFailed(PathKind::NativeTcp)
            }
        })?;
        let session = EncryptedPeerTcp::authenticate(
            stream,
            authentication,
            self.authentication_timeout,
            cancellation,
        )
        .await
        .map_err(|error| {
            if matches!(error, PeerTcpError::Cancelled) {
                PathError::Cancelled
            } else {
                PathError::AttemptFailed(PathKind::NativeTcp)
            }
        })?;
        Ok(SelectedPath::authenticated_with(
            PathKind::NativeTcp,
            Arc::new(session),
        ))
    }
}

fn auth_record(role: PeerRole, tag: [u8; PEER_HANDSHAKE_TAG_BYTES]) -> [u8; AUTH_RECORD_BYTES] {
    let mut record = [0_u8; AUTH_RECORD_BYTES];
    record[..8].copy_from_slice(AUTH_MAGIC);
    record[8] = match role {
        PeerRole::Initiator => AUTH_INITIATOR,
        PeerRole::Responder => AUTH_RESPONDER,
    };
    record[9..].copy_from_slice(&tag);
    record
}

async fn read_auth_record(stream: &mut TcpStream) -> Result<[u8; AUTH_RECORD_BYTES], PeerTcpError> {
    let mut record = [0_u8; AUTH_RECORD_BYTES];
    stream.read_exact(&mut record).await?;
    Ok(record)
}

async fn write_frame(
    writer: &mut WriteHalf<TcpStream>,
    frame: &PeerRelayFrame,
) -> Result<(), PeerTcpError> {
    let encoded = postcard::to_allocvec(frame).map_err(|_| PeerTcpError::MalformedFrame)?;
    if encoded.len() > MAX_WIRE_FRAME_BYTES {
        return Err(PeerTcpError::FrameTooLarge);
    }
    writer
        .write_u32(u32::try_from(encoded.len()).map_err(|_| PeerTcpError::FrameTooLarge)?)
        .await?;
    writer.write_all(&encoded).await?;
    Ok(())
}

async fn read_frame(reader: &mut ReadHalf<TcpStream>) -> Result<PeerRelayFrame, PeerTcpError> {
    let size = reader.read_u32().await? as usize;
    if size > MAX_WIRE_FRAME_BYTES {
        return Err(PeerTcpError::FrameTooLarge);
    }
    let mut encoded = vec![0_u8; size];
    reader.read_exact(&mut encoded).await?;
    postcard::from_bytes(&encoded).map_err(|_| PeerTcpError::MalformedFrame)
}
