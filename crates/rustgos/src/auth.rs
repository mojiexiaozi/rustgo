use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rand::{TryRngCore, rngs::OsRng};
use rustgo_config::AuthorizedClient;
use rustgo_crypto::{AuthTranscript, DevicePublicKey, verify_auth};
use rustgo_protocol::{
    BoundedBytes, ClientAuthenticate, ClientHello, MAX_CHALLENGE_BYTES, MAX_SESSION_ID_BYTES,
    ProtocolVersion, ServerChallenge,
};
use thiserror::Error;

const CHALLENGE_BYTES: usize = 32;
const SESSION_ID_BYTES: usize = 32;
const SESSION_RANDOM_BYTES: usize = SESSION_ID_BYTES - size_of::<u64>();

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedClient {
    name: String,
    fingerprint: String,
    session_id: Vec<u8>,
}

impl std::fmt::Debug for AuthenticatedClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedClient")
            .field("name", &self.name)
            .field("fingerprint", &self.fingerprint)
            .field("session_id", &"[REDACTED]")
            .finish()
    }
}

impl AuthenticatedClient {
    pub(crate) fn verified(name: String, fingerprint: String, session_id: Vec<u8>) -> Self {
        Self {
            name,
            fingerprint,
            session_id,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
}

#[derive(Clone)]
pub(crate) struct Authenticator {
    entries_by_name: Arc<HashMap<String, AuthorizationEntry>>,
    names_by_fingerprint: Arc<HashMap<String, String>>,
    next_session_sequence: Arc<AtomicU64>,
}

#[derive(Clone)]
struct AuthorizationEntry {
    public_key: DevicePublicKey,
    fingerprint: String,
    enabled: bool,
}

pub(crate) struct PendingAuthentication {
    client_name: String,
    claimed_fingerprint: Vec<u8>,
    challenge: Vec<u8>,
    session_id: Vec<u8>,
    version: ProtocolVersion,
}

impl PendingAuthentication {
    pub(crate) fn challenge(&self) -> Result<ServerChallenge, AuthError> {
        Ok(ServerChallenge {
            challenge: BoundedBytes::<MAX_CHALLENGE_BYTES>::try_from(self.challenge.clone())
                .map_err(|_| AuthError::Internal)?,
            session_id: BoundedBytes::<MAX_SESSION_ID_BYTES>::try_from(self.session_id.clone())
                .map_err(|_| AuthError::Internal)?,
        })
    }
}

impl Authenticator {
    pub(crate) fn new(clients: &[AuthorizedClient]) -> Result<Self, AuthError> {
        let mut entries_by_name = HashMap::with_capacity(clients.len());
        let mut names_by_fingerprint = HashMap::with_capacity(clients.len());
        for client in clients {
            let public_key = DevicePublicKey::from_str(&client.public_key)
                .map_err(|_| AuthError::InvalidConfiguration)?;
            let fingerprint = public_key.fingerprint().to_string();
            if entries_by_name
                .insert(
                    client.name.clone(),
                    AuthorizationEntry {
                        public_key,
                        fingerprint: fingerprint.clone(),
                        enabled: client.enabled,
                    },
                )
                .is_some()
                || names_by_fingerprint
                    .insert(fingerprint, client.name.clone())
                    .is_some()
            {
                return Err(AuthError::InvalidConfiguration);
            }
        }
        Ok(Self {
            entries_by_name: Arc::new(entries_by_name),
            names_by_fingerprint: Arc::new(names_by_fingerprint),
            next_session_sequence: Arc::new(AtomicU64::new(0)),
        })
    }

    pub(crate) fn begin(
        &self,
        hello: ClientHello,
        version: ProtocolVersion,
    ) -> Result<PendingAuthentication, AuthError> {
        let mut challenge = [0_u8; CHALLENGE_BYTES];
        OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|_| AuthError::EntropyUnavailable)?;
        let session_id = self.issue_session_id()?;
        Ok(PendingAuthentication {
            client_name: hello.client_name.as_str().to_owned(),
            claimed_fingerprint: hello.fingerprint.into_vec(),
            challenge: challenge.to_vec(),
            session_id: session_id.to_vec(),
            version,
        })
    }

    pub(crate) fn finish(
        &self,
        pending: PendingAuthentication,
        authentication: ClientAuthenticate,
    ) -> Result<AuthenticatedClient, AuthError> {
        let encoded_public_key = std::str::from_utf8(authentication.public_key.as_slice())
            .map_err(|_| AuthError::Rejected)?;
        let public_key =
            DevicePublicKey::from_str(encoded_public_key).map_err(|_| AuthError::Rejected)?;
        let fingerprint = public_key.fingerprint().to_string();
        let wire_fingerprint = fingerprint
            .strip_prefix("sha256:")
            .ok_or(AuthError::Internal)?;

        let entry = self
            .entries_by_name
            .get(&pending.client_name)
            .ok_or(AuthError::Rejected)?;
        if !entry.enabled
            || entry.public_key != public_key
            || entry.fingerprint != fingerprint
            || pending.claimed_fingerprint != wire_fingerprint.as_bytes()
            || self.names_by_fingerprint.get(&fingerprint) != Some(&pending.client_name)
        {
            return Err(AuthError::Rejected);
        }

        let transcript = AuthTranscript::new(
            pending.challenge,
            pending.session_id.clone(),
            transcript_version(pending.version)?,
            pending.client_name.clone(),
        );
        verify_auth(
            &public_key,
            &transcript,
            authentication.signature.as_slice(),
        )
        .map_err(|_| AuthError::Rejected)?;
        Ok(AuthenticatedClient::verified(
            pending.client_name,
            fingerprint,
            pending.session_id,
        ))
    }

    fn issue_session_id(&self) -> Result<[u8; SESSION_ID_BYTES], AuthError> {
        let sequence = self
            .next_session_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| AuthError::Internal)?;
        let mut session_id = [0_u8; SESSION_ID_BYTES];
        OsRng
            .try_fill_bytes(&mut session_id[..SESSION_RANDOM_BYTES])
            .map_err(|_| AuthError::EntropyUnavailable)?;
        session_id[SESSION_RANDOM_BYTES..].copy_from_slice(&sequence.to_be_bytes());
        Ok(session_id)
    }
}

fn transcript_version(version: ProtocolVersion) -> Result<u16, AuthError> {
    if version.major > u16::from(u8::MAX) || version.minor > u16::from(u8::MAX) {
        return Err(AuthError::Rejected);
    }
    Ok((version.major << 8) | version.minor)
}

#[derive(Clone)]
pub(crate) struct FailedAuthLimiter {
    state: Arc<Mutex<FailedAuthState>>,
    max_attempts: usize,
    window: Duration,
    max_tracked_peers: usize,
}

#[derive(Default)]
struct FailedAuthState {
    attempts: HashMap<IpAddr, VecDeque<tokio::time::Instant>>,
}

impl FailedAuthLimiter {
    pub(crate) fn new(max_attempts: usize, window: Duration, max_tracked_peers: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(FailedAuthState::default())),
            max_attempts,
            window,
            max_tracked_peers,
        }
    }

    pub(crate) fn allows(&self, peer: IpAddr) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let now = tokio::time::Instant::now();
        state.attempts.retain(|_, attempts| {
            trim_expired(attempts, now, self.window);
            !attempts.is_empty()
        });
        match state.attempts.get(&peer) {
            Some(attempts) => attempts.len() < self.max_attempts,
            None => state.attempts.len() < self.max_tracked_peers,
        }
    }

    pub(crate) fn record_failure(&self, peer: IpAddr) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let now = tokio::time::Instant::now();
        if !state.attempts.contains_key(&peer) && state.attempts.len() >= self.max_tracked_peers {
            state.attempts.retain(|_, attempts| {
                trim_expired(attempts, now, self.window);
                !attempts.is_empty()
            });
            if state.attempts.len() >= self.max_tracked_peers {
                return;
            }
        }
        let attempts = state.attempts.entry(peer).or_default();
        trim_expired(attempts, now, self.window);
        if attempts.len() < self.max_attempts {
            attempts.push_back(now);
        }
    }

    pub(crate) fn record_success(&self, peer: IpAddr) {
        if let Ok(mut state) = self.state.lock() {
            state.attempts.remove(&peer);
        }
    }
}

fn trim_expired(
    attempts: &mut VecDeque<tokio::time::Instant>,
    now: tokio::time::Instant,
    window: Duration,
) {
    while attempts
        .front()
        .is_some_and(|attempt| now.duration_since(*attempt) >= window)
    {
        attempts.pop_front();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum AuthError {
    #[error("invalid authentication configuration")]
    InvalidConfiguration,
    #[error("authentication rejected")]
    Rejected,
    #[error("secure authentication entropy is unavailable")]
    EntropyUnavailable,
    #[error("internal authentication failure")]
    Internal,
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use super::{AuthenticatedClient, FailedAuthLimiter};

    #[test]
    fn full_peer_table_fails_closed_for_an_untracked_peer() {
        let limiter = FailedAuthLimiter::new(2, Duration::from_secs(60), 1);
        let tracked = IpAddr::from([192, 0, 2, 1]);
        let untracked = IpAddr::from([192, 0, 2, 2]);
        limiter.record_failure(tracked);

        assert!(limiter.allows(tracked));
        assert!(!limiter.allows(untracked));
    }

    #[test]
    fn authenticated_client_debug_redacts_the_session_id() {
        let client = AuthenticatedClient {
            name: "home-pc".to_owned(),
            fingerprint: "sha256:test".to_owned(),
            session_id: vec![7; 32],
        };

        let debug = format!("{client:?}");
        assert!(debug.contains("home-pc"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("7, 7"));
    }
}
