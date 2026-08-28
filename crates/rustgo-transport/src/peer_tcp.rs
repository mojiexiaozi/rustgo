use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use rand::{TryRngCore as _, rngs::OsRng};
use rustgo_crypto::{
    EphemeralPeerKey, PEER_HANDSHAKE_TAG_BYTES, PEER_TRANSPORT_BINDING_BYTES, PeerCryptoError,
    PeerFrameOpener, PeerFrameSealer, PeerRole, PeerSessionKeys, PeerTranscript,
};
use rustgo_nat::TcpPuncher;
use rustgo_path::{PathAttempt, PathError, PathKind, SelectedPath};
use rustgo_rendezvous::{PeerRelayFlags, PeerRelayFrame};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::Mutex,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

const AUTH_MAGIC: &[u8; 8] = b"RGOTCP01";
const CHALLENGE_BYTES: usize = 32;
const HELLO_RECORD_BYTES: usize = 8 + 1 + CHALLENGE_BYTES;
const PROOF_RECORD_BYTES: usize = 8 + 1 + PEER_HANDSHAKE_TAG_BYTES;
const AUTH_INITIATOR: u8 = 1;
const AUTH_RESPONDER: u8 = 2;
const MAX_WIRE_FRAME_BYTES: usize = 70 * 1024;
const TCP_BINDING_DOMAIN: &[u8] = b"rustgo-peer-tcp-live-binding-v1";
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
            let mut local_challenge = [0_u8; CHALLENGE_BYTES];
            OsRng
                .try_fill_bytes(&mut local_challenge)
                .map_err(|_| PeerTcpError::AuthenticationFailed)?;
            let local_hello = hello_record(authentication.role, local_challenge);
            let peer_hello = match authentication.role {
                PeerRole::Initiator => {
                    stream.write_all(&local_hello).await?;
                    read_hello_record(&mut stream).await?
                }
                PeerRole::Responder => {
                    let peer = read_hello_record(&mut stream).await?;
                    stream.write_all(&local_hello).await?;
                    peer
                }
            };
            let expected_role = match authentication.role {
                PeerRole::Initiator => AUTH_RESPONDER,
                PeerRole::Responder => AUTH_INITIATOR,
            };
            if peer_hello[8] != expected_role || &peer_hello[..8] != AUTH_MAGIC {
                return Err(PeerTcpError::AuthenticationFailed);
            }
            let peer_challenge: [u8; CHALLENGE_BYTES] = peer_hello[9..]
                .try_into()
                .map_err(|_| PeerTcpError::AuthenticationFailed)?;
            let binding = live_binding(authentication.role, &local_challenge, &peer_challenge);
            let local_proof = proof_record(
                authentication.role,
                authentication.keys.handshake_tag(&binding),
            );
            let peer_proof = match authentication.role {
                PeerRole::Initiator => {
                    stream.write_all(&local_proof).await?;
                    read_proof_record(&mut stream).await?
                }
                PeerRole::Responder => {
                    let peer = read_proof_record(&mut stream).await?;
                    verify_proof(&authentication.keys, expected_role, &binding, &peer)?;
                    stream.write_all(&local_proof).await?;
                    peer
                }
            };
            verify_proof(&authentication.keys, expected_role, &binding, &peer_proof)?;
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
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        let mut candidates = TcpPuncher::candidates(
            self.local,
            self.candidates.clone(),
            deadline,
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
        let mut authentication_tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    candidates.cancel();
                    authentication_tasks.abort_all();
                    return Err(PathError::Cancelled);
                }
                () = tokio::time::sleep_until(deadline) => {
                    candidates.cancel();
                    authentication_tasks.abort_all();
                    return Err(PathError::AttemptTimedOut(PathKind::NativeTcp));
                }
                result = authentication_tasks.join_next(), if !authentication_tasks.is_empty() => {
                    if let Some(Ok(Ok(session))) = result {
                        candidates.cancel();
                        authentication_tasks.abort_all();
                        return Ok(SelectedPath::authenticated_with(PathKind::NativeTcp, Arc::new(session)));
                    }
                }
                stream = candidates.next() => match stream {
                    Ok(Some(stream)) => {
                        let authentication = match self.authentication_factory.create() {
                            Ok(authentication) => authentication,
                            Err(_) => continue,
                        };
                        let timeout = self.authentication_timeout;
                        let child = cancellation.child_token();
                        authentication_tasks.spawn(async move {
                            EncryptedPeerTcp::authenticate(stream, authentication, timeout, child).await
                        });
                    }
                    Ok(None) | Err(rustgo_nat::TcpPunchError::ConnectFailed) => {
                        if authentication_tasks.is_empty() {
                            return Err(PathError::AttemptFailed(PathKind::NativeTcp));
                        }
                    }
                    Err(rustgo_nat::TcpPunchError::Cancelled) => return Err(PathError::Cancelled),
                    Err(rustgo_nat::TcpPunchError::Deadline) => {
                        authentication_tasks.abort_all();
                        return Err(PathError::AttemptTimedOut(PathKind::NativeTcp));
                    }
                    Err(_) => return Err(PathError::AttemptFailed(PathKind::NativeTcp)),
                }
            }
        }
    }
}

fn hello_record(role: PeerRole, challenge: [u8; CHALLENGE_BYTES]) -> [u8; HELLO_RECORD_BYTES] {
    let mut record = [0_u8; HELLO_RECORD_BYTES];
    record[..8].copy_from_slice(AUTH_MAGIC);
    record[8] = match role {
        PeerRole::Initiator => AUTH_INITIATOR,
        PeerRole::Responder => AUTH_RESPONDER,
    };
    record[9..].copy_from_slice(&challenge);
    record
}

fn proof_record(role: PeerRole, tag: [u8; PEER_HANDSHAKE_TAG_BYTES]) -> [u8; PROOF_RECORD_BYTES] {
    let mut record = [0_u8; PROOF_RECORD_BYTES];
    record[..8].copy_from_slice(AUTH_MAGIC);
    record[8] = match role {
        PeerRole::Initiator => AUTH_INITIATOR,
        PeerRole::Responder => AUTH_RESPONDER,
    };
    record[9..].copy_from_slice(&tag);
    record
}

async fn read_hello_record(
    stream: &mut TcpStream,
) -> Result<[u8; HELLO_RECORD_BYTES], PeerTcpError> {
    let mut record = [0_u8; HELLO_RECORD_BYTES];
    stream.read_exact(&mut record).await?;
    Ok(record)
}

async fn read_proof_record(
    stream: &mut TcpStream,
) -> Result<[u8; PROOF_RECORD_BYTES], PeerTcpError> {
    let mut record = [0_u8; PROOF_RECORD_BYTES];
    stream.read_exact(&mut record).await?;
    Ok(record)
}

fn live_binding(
    role: PeerRole,
    local: &[u8; CHALLENGE_BYTES],
    peer: &[u8; CHALLENGE_BYTES],
) -> [u8; PEER_TRANSPORT_BINDING_BYTES] {
    let (initiator, responder) = match role {
        PeerRole::Initiator => (local, peer),
        PeerRole::Responder => (peer, local),
    };
    let mut hash = Sha256::new();
    hash.update(TCP_BINDING_DOMAIN);
    hash.update([AUTH_INITIATOR]);
    hash.update(initiator);
    hash.update([AUTH_RESPONDER]);
    hash.update(responder);
    hash.finalize().into()
}

fn verify_proof(
    keys: &PeerSessionKeys,
    expected_role: u8,
    binding: &[u8; PEER_TRANSPORT_BINDING_BYTES],
    proof: &[u8; PROOF_RECORD_BYTES],
) -> Result<(), PeerTcpError> {
    if &proof[..8] != AUTH_MAGIC || proof[8] != expected_role {
        return Err(PeerTcpError::AuthenticationFailed);
    }
    let tag: [u8; PEER_HANDSHAKE_TAG_BYTES] = proof[9..]
        .try_into()
        .map_err(|_| PeerTcpError::AuthenticationFailed)?;
    keys.verify_handshake_tag(binding, &tag)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustgo_crypto::DeviceKeypair;
    use rustgo_protocol::{BoundedString, ProtocolVersion};
    use rustgo_rendezvous::{CandidateGeneration, SessionId};

    fn key_pair() -> (PeerSessionKeys, PeerSessionKeys) {
        let initiator_identity = DeviceKeypair::from_secret_bytes([0x81; 32]);
        let responder_identity = DeviceKeypair::from_secret_bytes([0x82; 32]);
        let initiator_ephemeral = EphemeralPeerKey::generate();
        let responder_ephemeral = EphemeralPeerKey::generate();
        let initiator_public = initiator_ephemeral.public_key();
        let responder_public = responder_ephemeral.public_key();
        let transcript = || {
            PeerTranscript::new(
                SessionId::from([0x83; 32]),
                CandidateGeneration::new(1).unwrap(),
                initiator_identity.public_key(),
                responder_identity.public_key(),
                initiator_public,
                responder_public,
                BoundedString::try_from("ssh").unwrap(),
                ProtocolVersion::V0_2,
                [0x84; 32],
            )
        };
        (
            PeerSessionKeys::derive(PeerRole::Initiator, initiator_ephemeral, &transcript())
                .unwrap(),
            PeerSessionKeys::derive(PeerRole::Responder, responder_ephemeral, &transcript())
                .unwrap(),
        )
    }

    #[test]
    fn captured_proof_is_rejected_on_a_fresh_connection_challenge() {
        let (initiator, responder) = key_pair();
        let old_binding = live_binding(PeerRole::Initiator, &[1; 32], &[2; 32]);
        let new_binding = live_binding(PeerRole::Initiator, &[3; 32], &[4; 32]);
        let captured = responder.handshake_tag(&old_binding);
        assert!(
            initiator
                .verify_handshake_tag(&old_binding, &captured)
                .is_ok()
        );
        assert!(
            initiator
                .verify_handshake_tag(&new_binding, &captured)
                .is_err()
        );
    }

    #[test]
    fn tampered_live_proof_is_rejected() {
        let (initiator, responder) = key_pair();
        let binding = live_binding(PeerRole::Initiator, &[5; 32], &[6; 32]);
        let mut proof = responder.handshake_tag(&binding);
        proof[0] ^= 0x80;
        assert!(initiator.verify_handshake_tag(&binding, &proof).is_err());
    }

    #[test]
    fn replayed_and_corrupted_native_tcp_frames_are_rejected() {
        let (mut initiator, mut responder) = key_pair();
        let mut opener = initiator.stream_opener(1).unwrap();
        let mut sealer = responder.stream_sealer(1).unwrap();
        let frame = sealer.seal(b"payload", PeerRelayFlags::RELIABLE).unwrap();
        assert_eq!(opener.open(&frame).unwrap(), b"payload");
        assert!(opener.open(&frame).is_err());

        let mut fresh_opener = initiator.stream_opener(2).unwrap();
        let mut fresh_sealer = responder.stream_sealer(2).unwrap();
        let fresh = fresh_sealer
            .seal(b"payload", PeerRelayFlags::RELIABLE)
            .unwrap();
        let mut wire = postcard::to_allocvec(&fresh).unwrap();
        *wire.last_mut().unwrap() ^= 0x40;
        let corrupted: PeerRelayFrame = postcard::from_bytes(&wire).unwrap();
        assert!(fresh_opener.open(&corrupted).is_err());
    }
}
