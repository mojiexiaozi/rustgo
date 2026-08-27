use std::{
    collections::{BTreeSet, HashMap, VecDeque},
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
    max_attempt_records: usize,
}

#[derive(Default)]
struct FailedAuthState {
    buckets: HashMap<PeerBucket, PeerAttempts>,
    idle_lru: BTreeSet<(u64, PeerBucket)>,
    total_failure_records: usize,
    total_pending: usize,
    next_touch: u64,
    #[cfg(test)]
    last_admission_bucket_visits: usize,
}

struct PeerAttempts {
    failures: VecDeque<tokio::time::Instant>,
    pending: usize,
    last_touch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PeerBucket {
    V4([u8; 4]),
    V6Prefix64([u8; 8]),
}

impl From<IpAddr> for PeerBucket {
    fn from(peer: IpAddr) -> Self {
        match peer {
            IpAddr::V4(address) => Self::V4(address.octets()),
            IpAddr::V6(address) => {
                let octets = address.octets();
                Self::V6Prefix64(octets[..8].try_into().expect("IPv6 /64 width"))
            }
        }
    }
}

pub(crate) struct AuthAttemptReservation {
    limiter: FailedAuthLimiter,
    peer: PeerBucket,
    resolved: bool,
}

impl FailedAuthLimiter {
    pub(crate) fn new(
        max_attempts: usize,
        window: Duration,
        max_tracked_peers: usize,
        max_attempt_records: usize,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(FailedAuthState::default())),
            max_attempts,
            window,
            max_tracked_peers,
            max_attempt_records,
        }
    }

    pub(crate) fn reserve(&self, peer: IpAddr) -> Option<AuthAttemptReservation> {
        // IPv4 identities are exact addresses; IPv6 identities are /64 prefixes so
        // rotating interface identifiers cannot grow the table or bypass the limit.
        let peer = PeerBucket::from(peer);
        let mut state = self.state.lock().ok()?;
        #[cfg(test)]
        {
            state.last_admission_bucket_visits = 0;
        }
        let now = tokio::time::Instant::now();
        let mut bucket = state.buckets.remove(&peer);
        let denied_by_peer_limit = if let Some(existing) = bucket.as_mut() {
            state.visit_bucket();
            if existing.pending == 0 {
                state.idle_lru.remove(&(existing.last_touch, peer));
            }
            let removed = trim_expired(&mut existing.failures, now, self.window);
            state.total_failure_records -= removed;
            existing.failures.len().saturating_add(existing.pending) >= self.max_attempts
        } else {
            false
        };
        if denied_by_peer_limit {
            state.insert_bucket(peer, bucket.expect("existing peer bucket"));
            return None;
        }

        let is_new_peer = bucket.is_none();
        // Only idle history is evictable. In-flight verification reservations are
        // never displaced; if they exhaust either bound, admission fails closed.
        while (is_new_peer && state.buckets.len() >= self.max_tracked_peers)
            || state
                .total_failure_records
                .saturating_add(state.total_pending)
                >= self.max_attempt_records
        {
            if !state.evict_oldest_idle() {
                if let Some(bucket) = bucket {
                    state.insert_bucket(peer, bucket);
                }
                return None;
            }
        }

        let Some(touch) = state.next_touch() else {
            if let Some(bucket) = bucket {
                state.insert_bucket(peer, bucket);
            }
            return None;
        };
        let mut bucket = bucket.unwrap_or_else(|| PeerAttempts {
            failures: VecDeque::new(),
            pending: 0,
            last_touch: touch,
        });
        bucket.pending += 1;
        bucket.last_touch = touch;
        state.total_pending += 1;
        state.buckets.insert(peer, bucket);
        Some(AuthAttemptReservation {
            limiter: self.clone(),
            peer,
            resolved: false,
        })
    }

    fn resolve(&self, peer: PeerBucket, succeeded: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(mut bucket) = state.buckets.remove(&peer) else {
            return;
        };
        if bucket.pending == 0 {
            state.insert_bucket(peer, bucket);
            return;
        }
        bucket.pending -= 1;
        state.total_pending -= 1;
        let removed = trim_expired(
            &mut bucket.failures,
            tokio::time::Instant::now(),
            self.window,
        );
        state.total_failure_records -= removed;
        if succeeded {
            state.total_failure_records -= bucket.failures.len();
            bucket.failures.clear();
        } else {
            bucket.failures.push_back(tokio::time::Instant::now());
            state.total_failure_records += 1;
        }
        bucket.last_touch = state.next_touch_for_resolution();
        if bucket.pending != 0 || !bucket.failures.is_empty() {
            state.insert_bucket(peer, bucket);
        }
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.state.lock().unwrap().total_pending
    }

    #[cfg(test)]
    fn failure_record_count(&self) -> usize {
        self.state.lock().unwrap().total_failure_records
    }

    #[cfg(test)]
    fn last_admission_bucket_visits(&self) -> usize {
        self.state.lock().unwrap().last_admission_bucket_visits
    }
}

impl AuthAttemptReservation {
    pub(crate) fn succeed(&mut self) {
        self.finish(true);
    }

    pub(crate) fn fail(&mut self) {
        self.finish(false);
    }

    fn finish(&mut self, succeeded: bool) {
        if !self.resolved {
            self.limiter.resolve(self.peer, succeeded);
            self.resolved = true;
        }
    }
}

impl Drop for AuthAttemptReservation {
    fn drop(&mut self) {
        // Cancellation and early-return paths consume the reserved attempt instead
        // of leaking a pending slot or silently escaping failure accounting.
        self.finish(false);
    }
}

impl FailedAuthState {
    fn insert_bucket(&mut self, peer: PeerBucket, bucket: PeerAttempts) {
        if bucket.pending == 0 {
            self.idle_lru.insert((bucket.last_touch, peer));
        }
        self.buckets.insert(peer, bucket);
    }

    fn evict_oldest_idle(&mut self) -> bool {
        while let Some((_, peer)) = self.idle_lru.pop_first() {
            self.visit_bucket();
            if let Some(bucket) = self.buckets.remove(&peer) {
                self.total_failure_records -= bucket.failures.len();
                return true;
            }
        }
        false
    }

    fn next_touch(&mut self) -> Option<u64> {
        let touch = self.next_touch;
        self.next_touch = self.next_touch.checked_add(1)?;
        Some(touch)
    }

    fn next_touch_for_resolution(&mut self) -> u64 {
        let touch = self.next_touch;
        self.next_touch = self.next_touch.saturating_add(1);
        touch
    }

    fn visit_bucket(&mut self) {
        #[cfg(test)]
        {
            self.last_admission_bucket_visits += 1;
        }
    }
}

fn trim_expired(
    attempts: &mut VecDeque<tokio::time::Instant>,
    now: tokio::time::Instant,
    window: Duration,
) -> usize {
    let before = attempts.len();
    while attempts
        .front()
        .is_some_and(|attempt| now.duration_since(*attempt) >= window)
    {
        attempts.pop_front();
    }
    before - attempts.len()
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
    use std::{
        net::IpAddr,
        sync::{Arc, Barrier, mpsc},
        thread,
        time::Duration,
    };

    use super::{AuthenticatedClient, FailedAuthLimiter};

    #[test]
    fn all_pending_table_fails_closed_for_an_untracked_peer() {
        let limiter = FailedAuthLimiter::new(2, Duration::from_secs(60), 1, 2);
        let mut tracked = limiter.reserve(IpAddr::from([192, 0, 2, 1])).unwrap();

        assert!(limiter.reserve(IpAddr::from([192, 0, 2, 2])).is_none());
        tracked.succeed();
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

    #[test]
    fn sixty_four_concurrent_attempts_reserve_at_most_the_peer_limit() {
        const ATTEMPTS: usize = 64;
        const PEER_LIMIT: usize = 8;
        let limiter = FailedAuthLimiter::new(PEER_LIMIT, Duration::from_secs(60), 64, 512);
        let start = Arc::new(Barrier::new(ATTEMPTS + 1));
        let release = Arc::new(Barrier::new(ATTEMPTS + 1));
        let (sender, receiver) = mpsc::channel();
        let peer = IpAddr::from([192, 0, 2, 10]);
        let mut threads = Vec::new();

        for _ in 0..ATTEMPTS {
            let limiter = limiter.clone();
            let start = start.clone();
            let release = release.clone();
            let sender = sender.clone();
            threads.push(thread::spawn(move || {
                start.wait();
                let reservation = limiter.reserve(peer);
                sender.send(reservation.is_some()).unwrap();
                release.wait();
                drop(reservation);
            }));
        }
        drop(sender);
        start.wait();
        let admitted = receiver
            .iter()
            .take(ATTEMPTS)
            .filter(|value| *value)
            .count();
        assert_eq!(admitted, PEER_LIMIT);
        release.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn dropped_reservation_becomes_a_failure_without_leaving_pending_state() {
        let limiter = FailedAuthLimiter::new(1, Duration::from_secs(60), 4, 4);
        let peer = IpAddr::from([192, 0, 2, 20]);

        drop(limiter.reserve(peer).unwrap());

        assert!(limiter.reserve(peer).is_none());
        assert_eq!(limiter.pending_count(), 0);
        assert_eq!(limiter.failure_record_count(), 1);
    }

    #[tokio::test]
    async fn cancelling_a_task_converts_its_reservation_to_a_failure() {
        let limiter = FailedAuthLimiter::new(1, Duration::from_secs(60), 4, 4);
        let task_limiter = limiter.clone();
        let peer = IpAddr::from([192, 0, 2, 22]);
        let (reserved, wait_until_cancelled) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _reservation = task_limiter.reserve(peer).unwrap();
            reserved.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        wait_until_cancelled.await.unwrap();

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        assert_eq!(limiter.pending_count(), 0);
        assert_eq!(limiter.failure_record_count(), 1);
        assert!(limiter.reserve(peer).is_none());
    }

    #[test]
    fn successful_reservation_releases_pending_and_clears_prior_failures() {
        let limiter = FailedAuthLimiter::new(2, Duration::from_secs(60), 4, 8);
        let peer = IpAddr::from([192, 0, 2, 21]);
        limiter.reserve(peer).unwrap().fail();
        limiter.reserve(peer).unwrap().succeed();

        let mut next = limiter.reserve(peer).unwrap();
        assert_eq!(limiter.failure_record_count(), 0);
        next.succeed();
    }

    #[test]
    fn ipv6_addresses_share_one_rate_bucket_per_64_prefix() {
        let limiter = FailedAuthLimiter::new(1, Duration::from_secs(60), 4, 4);
        let first = "2001:db8:10:20::1".parse().unwrap();
        let same_prefix = "2001:db8:10:20:ffff::2".parse().unwrap();
        let other_prefix = "2001:db8:10:21::1".parse().unwrap();

        limiter.reserve(first).unwrap().fail();

        assert!(limiter.reserve(same_prefix).is_none());
        assert!(limiter.reserve(other_prefix).is_some());
    }

    #[test]
    fn ipv4_addresses_keep_exact_rate_buckets() {
        let limiter = FailedAuthLimiter::new(1, Duration::from_secs(60), 4, 4);
        let first = IpAddr::from([192, 0, 2, 50]);
        let other = IpAddr::from([192, 0, 2, 51]);

        limiter.reserve(first).unwrap().fail();

        assert!(limiter.reserve(first).is_none());
        assert!(limiter.reserve(other).is_some());
    }

    #[test]
    fn capacity_pressure_evicts_only_idle_lru_and_does_not_globally_lock_new_peers() {
        let limiter = FailedAuthLimiter::new(1, Duration::from_secs(60), 2, 2);
        let active_peer = IpAddr::from([192, 0, 2, 30]);
        let idle_peer = IpAddr::from([192, 0, 2, 31]);
        let new_peer = IpAddr::from([192, 0, 2, 32]);
        let mut active = limiter.reserve(active_peer).unwrap();
        limiter.reserve(idle_peer).unwrap().fail();

        let replacement = limiter.reserve(new_peer);

        assert!(replacement.is_some());
        assert!(limiter.reserve(active_peer).is_none());
        active.succeed();
        assert!(limiter.reserve(active_peer).is_some());
    }

    #[test]
    fn global_record_budget_denies_when_every_record_is_pending_and_recovers_on_release() {
        let limiter = FailedAuthLimiter::new(4, Duration::from_secs(60), 4, 2);
        let mut first = limiter.reserve(IpAddr::from([192, 0, 2, 40])).unwrap();
        let _second = limiter.reserve(IpAddr::from([192, 0, 2, 41])).unwrap();

        assert!(limiter.reserve(IpAddr::from([192, 0, 2, 42])).is_none());
        first.succeed();
        assert!(limiter.reserve(IpAddr::from([192, 0, 2, 42])).is_some());
    }

    #[test]
    fn admission_prunes_only_the_target_bucket_when_the_table_is_large() {
        const PEERS: usize = 1024;
        let limiter = FailedAuthLimiter::new(2, Duration::from_secs(60), PEERS, PEERS * 2);
        for index in 0..PEERS {
            let peer = IpAddr::from([10, (index >> 8) as u8, index as u8, 1]);
            limiter.reserve(peer).unwrap().fail();
        }

        let target = IpAddr::from([10, 2, 0, 1]);
        assert!(limiter.reserve(target).is_some());
        assert_eq!(limiter.last_admission_bucket_visits(), 1);
    }
}
