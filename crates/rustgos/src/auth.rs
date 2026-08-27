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
const AUTH_ATTEMPT_SHARDS_PER_FAMILY: usize = 8;
const AUTH_ATTEMPT_SHARDS: usize = AUTH_ATTEMPT_SHARDS_PER_FAMILY * 2;

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

struct FailedAuthState {
    buckets: HashMap<PeerBucket, PeerAttempts>,
    evictable_idle_failures: BTreeSet<(tokio::time::Instant, PeerBucket)>,
    protected_idle_failures: BTreeSet<(tokio::time::Instant, PeerBucket)>,
    attempt_budget: Vec<AttemptBudgetShard>,
    overflow_pending_by_peer: HashMap<PeerBucket, usize>,
    total_failure_records: usize,
    total_pending: usize,
    total_overflow_pending: usize,
    #[cfg(test)]
    last_admission_bucket_visits: usize,
}

struct PeerAttempts {
    failures: VecDeque<tokio::time::Instant>,
    pending: usize,
}

struct AttemptBudgetShard {
    window_started: Option<tokio::time::Instant>,
    used: usize,
    capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PeerBucket {
    V4([u8; 4]),
    V6Prefix64([u8; 8]),
}

#[derive(Clone)]
pub(crate) struct TlsHandshakeLimiter {
    state: Arc<Mutex<HashMap<PeerBucket, usize>>>,
    max_in_flight_per_peer: usize,
}

pub(crate) struct TlsHandshakePermit {
    limiter: TlsHandshakeLimiter,
    peer: PeerBucket,
}

impl TlsHandshakeLimiter {
    pub(crate) fn new(max_in_flight_per_peer: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_in_flight_per_peer,
        }
    }

    pub(crate) fn try_acquire(&self, peer: IpAddr) -> Option<TlsHandshakePermit> {
        let peer = PeerBucket::from(peer);
        let mut state = self.state.lock().ok()?;
        let in_flight = state.entry(peer).or_default();
        if *in_flight >= self.max_in_flight_per_peer {
            return None;
        }
        *in_flight += 1;
        Some(TlsHandshakePermit {
            limiter: self.clone(),
            peer,
        })
    }
}

impl Drop for TlsHandshakePermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.limiter.state.lock() else {
            return;
        };
        let Some(in_flight) = state.get_mut(&self.peer) else {
            return;
        };
        *in_flight -= 1;
        if *in_flight == 0 {
            state.remove(&self.peer);
        }
    }
}

impl From<IpAddr> for PeerBucket {
    fn from(peer: IpAddr) -> Self {
        match peer {
            IpAddr::V4(address) => Self::V4(address.octets()),
            IpAddr::V6(address) => {
                if let Some(mapped) = address.to_ipv4_mapped() {
                    return Self::V4(mapped.octets());
                }
                let octets = address.octets();
                Self::V6Prefix64(octets[..8].try_into().expect("IPv6 /64 width"))
            }
        }
    }
}

impl PeerBucket {
    fn attempt_shard(self) -> usize {
        let (family_offset, bytes): (usize, &[u8]) = match &self {
            Self::V4(bytes) => (0, bytes),
            Self::V6Prefix64(bytes) => (AUTH_ATTEMPT_SHARDS_PER_FAMILY, bytes),
        };
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        family_offset + (hash % AUTH_ATTEMPT_SHARDS_PER_FAMILY as u64) as usize
    }
}

pub(crate) struct AuthAttemptReservation {
    limiter: FailedAuthLimiter,
    peer: PeerBucket,
    tracked: bool,
    resolved: bool,
}

#[derive(Clone, Copy)]
enum ReservationOutcome {
    Succeeded,
    Failed,
    Neutral,
}

impl FailedAuthLimiter {
    #[cfg(test)]
    pub(crate) fn new(
        max_attempts: usize,
        window: Duration,
        max_tracked_peers: usize,
        max_attempt_records: usize,
    ) -> Self {
        Self::new_with_attempt_budget(
            max_attempts,
            window,
            max_tracked_peers,
            max_attempt_records,
            usize::MAX,
        )
    }

    pub(crate) fn new_with_attempt_budget(
        max_attempts: usize,
        window: Duration,
        max_tracked_peers: usize,
        max_attempt_records: usize,
        max_attempts_per_window: usize,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(FailedAuthState::new(max_attempts_per_window))),
            max_attempts,
            window,
            max_tracked_peers,
            max_attempt_records,
        }
    }

    #[cfg(test)]
    fn attempt_shard_for_test(&self, peer: IpAddr) -> usize {
        PeerBucket::from(peer).attempt_shard()
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
        if let Some(existing) = bucket.as_mut() {
            state.visit_bucket();
            if existing.pending == 0
                && let Some(last_failure) = existing.failures.back()
            {
                let key = (*last_failure, peer);
                state.evictable_idle_failures.remove(&key);
                state.protected_idle_failures.remove(&key);
            }
            let removed = trim_expired(&mut existing.failures, now, self.window);
            state.total_failure_records -= removed;
        }
        let tracked_peer_records = bucket.as_ref().map_or(0, |existing| {
            existing.failures.len().saturating_add(existing.pending)
        });
        if tracked_peer_records.saturating_add(state.overflow_pending_for(peer))
            >= self.max_attempts
        {
            if let Some(bucket) = bucket {
                state.insert_bucket(peer, bucket, self.max_attempts);
            }
            return None;
        }
        if state
            .total_pending
            .saturating_add(state.total_overflow_pending)
            >= self.max_attempt_records
        {
            if let Some(bucket) = bucket {
                state.insert_bucket(peer, bucket, self.max_attempts);
            }
            return None;
        }
        if !state.consume_attempt_budget(peer, now, self.window) {
            if let Some(bucket) = bucket {
                state.insert_bucket(peer, bucket, self.max_attempts);
            }
            return None;
        }

        let is_new_peer = bucket.is_none();
        // Below-threshold idle history is replaceable because the sharded global
        // budget still bounds churn. Threshold history and pending work are not.
        while (is_new_peer && state.buckets.len() >= self.max_tracked_peers)
            || state
                .total_failure_records
                .saturating_add(state.total_pending)
                >= self.max_attempt_records
        {
            if state.evict_one_low_value_idle()
                || state.reclaim_one_expired_protected(now, self.window)
            {
                continue;
            }
            let overflow_headroom = self.max_attempts.saturating_sub(tracked_peer_records);
            if state.total_failure_records == 0
                || state
                    .total_pending
                    .saturating_add(state.total_overflow_pending)
                    >= self.max_attempt_records
                || !state.try_reserve_overflow(peer, overflow_headroom)
            {
                if let Some(bucket) = bucket {
                    state.insert_bucket(peer, bucket, self.max_attempts);
                }
                state.refund_attempt_budget(peer);
                return None;
            }
            if let Some(bucket) = bucket {
                state.insert_bucket(peer, bucket, self.max_attempts);
            }
            return Some(AuthAttemptReservation {
                limiter: self.clone(),
                peer,
                tracked: false,
                resolved: false,
            });
        }

        let mut bucket = bucket.unwrap_or_else(|| PeerAttempts {
            failures: VecDeque::new(),
            pending: 0,
        });
        bucket.pending += 1;
        state.total_pending += 1;
        state.buckets.insert(peer, bucket);
        Some(AuthAttemptReservation {
            limiter: self.clone(),
            peer,
            tracked: true,
            resolved: false,
        })
    }

    fn resolve(&self, peer: PeerBucket, tracked: bool, outcome: ReservationOutcome) {
        if !tracked {
            if let Ok(mut state) = self.state.lock() {
                let released = state.release_overflow(peer);
                if released && matches!(outcome, ReservationOutcome::Succeeded) {
                    state.clear_peer_failures(peer);
                }
            }
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(mut bucket) = state.buckets.remove(&peer) else {
            return;
        };
        if bucket.pending == 0 {
            state.insert_bucket(peer, bucket, self.max_attempts);
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
        match outcome {
            ReservationOutcome::Succeeded => {
                state.total_failure_records -= bucket.failures.len();
                bucket.failures.clear();
            }
            ReservationOutcome::Failed => {
                bucket.failures.push_back(tokio::time::Instant::now());
                state.total_failure_records += 1;
            }
            ReservationOutcome::Neutral => {}
        }
        if bucket.pending != 0 || !bucket.failures.is_empty() {
            state.insert_bucket(peer, bucket, self.max_attempts);
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
        self.finish(ReservationOutcome::Succeeded);
    }

    pub(crate) fn fail(&mut self) {
        self.finish(ReservationOutcome::Failed);
    }

    fn finish(&mut self, outcome: ReservationOutcome) {
        if !self.resolved {
            self.limiter.resolve(self.peer, self.tracked, outcome);
            self.resolved = true;
        }
    }
}

impl Drop for AuthAttemptReservation {
    fn drop(&mut self) {
        // Cancellation and early-return paths release capacity without charging an
        // authentication failure; explicit protocol/auth failures call `fail`.
        self.finish(ReservationOutcome::Neutral);
    }
}

impl FailedAuthState {
    fn new(max_attempts_per_window: usize) -> Self {
        let base_capacity = max_attempts_per_window / AUTH_ATTEMPT_SHARDS;
        let extra_capacity = max_attempts_per_window % AUTH_ATTEMPT_SHARDS;
        let attempt_budget = (0..AUTH_ATTEMPT_SHARDS)
            .map(|shard| AttemptBudgetShard {
                window_started: None,
                used: 0,
                capacity: base_capacity + usize::from(shard < extra_capacity),
            })
            .collect();
        Self {
            buckets: HashMap::new(),
            evictable_idle_failures: BTreeSet::new(),
            protected_idle_failures: BTreeSet::new(),
            attempt_budget,
            overflow_pending_by_peer: HashMap::new(),
            total_failure_records: 0,
            total_pending: 0,
            total_overflow_pending: 0,
            #[cfg(test)]
            last_admission_bucket_visits: 0,
        }
    }

    fn consume_attempt_budget(
        &mut self,
        peer: PeerBucket,
        now: tokio::time::Instant,
        window: Duration,
    ) -> bool {
        let shard = &mut self.attempt_budget[peer.attempt_shard()];
        if shard
            .window_started
            .is_none_or(|started| now.duration_since(started) >= window)
        {
            shard.window_started = Some(now);
            shard.used = 0;
        }
        if shard.used >= shard.capacity {
            return false;
        }
        shard.used += 1;
        true
    }

    fn refund_attempt_budget(&mut self, peer: PeerBucket) {
        let shard = &mut self.attempt_budget[peer.attempt_shard()];
        shard.used = shard.used.saturating_sub(1);
    }

    fn try_reserve_overflow(&mut self, peer: PeerBucket, peer_headroom: usize) -> bool {
        let pending = self.overflow_pending_by_peer.entry(peer).or_default();
        if *pending >= peer_headroom {
            return false;
        }
        *pending += 1;
        self.total_overflow_pending += 1;
        true
    }

    fn overflow_pending_for(&self, peer: PeerBucket) -> usize {
        self.overflow_pending_by_peer
            .get(&peer)
            .copied()
            .unwrap_or(0)
    }

    fn release_overflow(&mut self, peer: PeerBucket) -> bool {
        let Some(pending) = self.overflow_pending_by_peer.get_mut(&peer) else {
            return false;
        };
        if *pending == 0 {
            return false;
        }
        *pending -= 1;
        self.total_overflow_pending -= 1;
        if *pending == 0 {
            self.overflow_pending_by_peer.remove(&peer);
        }
        true
    }

    fn clear_peer_failures(&mut self, peer: PeerBucket) {
        let Some(mut bucket) = self.buckets.remove(&peer) else {
            return;
        };
        if bucket.pending == 0
            && let Some(last_failure) = bucket.failures.back()
        {
            let key = (*last_failure, peer);
            self.evictable_idle_failures.remove(&key);
            self.protected_idle_failures.remove(&key);
        }
        self.total_failure_records -= bucket.failures.len();
        bucket.failures.clear();
        if bucket.pending != 0 {
            self.buckets.insert(peer, bucket);
        }
    }

    fn insert_bucket(&mut self, peer: PeerBucket, bucket: PeerAttempts, max_attempts: usize) {
        if bucket.pending == 0 && bucket.failures.is_empty() {
            return;
        }
        if bucket.pending == 0
            && let Some(last_failure) = bucket.failures.back()
        {
            let index = if bucket.failures.len() >= max_attempts {
                &mut self.protected_idle_failures
            } else {
                &mut self.evictable_idle_failures
            };
            index.insert((*last_failure, peer));
        }
        self.buckets.insert(peer, bucket);
    }

    fn evict_one_low_value_idle(&mut self) -> bool {
        let Some((_, peer)) = self.evictable_idle_failures.pop_first() else {
            return false;
        };
        self.visit_bucket();
        let Some(bucket) = self.buckets.remove(&peer) else {
            return false;
        };
        self.total_failure_records -= bucket.failures.len();
        true
    }

    fn reclaim_one_expired_protected(
        &mut self,
        now: tokio::time::Instant,
        window: Duration,
    ) -> bool {
        let Some((last_failure, peer)) = self.protected_idle_failures.first().copied() else {
            return false;
        };
        if now.duration_since(last_failure) < window {
            return false;
        }
        self.protected_idle_failures.pop_first();
        self.visit_bucket();
        let Some(bucket) = self.buckets.remove(&peer) else {
            return false;
        };
        self.total_failure_records -= bucket.failures.len();
        true
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

    use super::{
        AUTH_ATTEMPT_SHARDS_PER_FAMILY, AuthenticatedClient, FailedAuthLimiter, TlsHandshakeLimiter,
    };

    #[test]
    fn tls_handshake_admission_is_per_canonical_peer_and_releases_neutrally() {
        let limiter = TlsHandshakeLimiter::new(2);
        let native = IpAddr::from([192, 0, 2, 90]);
        let mapped_same = "::ffff:192.0.2.90".parse().unwrap();
        let other = IpAddr::from([192, 0, 2, 91]);
        let first = limiter.try_acquire(native).unwrap();
        let _second = limiter.try_acquire(mapped_same).unwrap();

        assert!(limiter.try_acquire(native).is_none());
        assert!(limiter.try_acquire(other).is_some());

        drop(first);
        assert!(limiter.try_acquire(mapped_same).is_some());
    }

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
    fn sixty_four_concurrent_overflow_attempts_still_respect_the_peer_limit() {
        const ATTEMPTS: usize = 64;
        const PEER_LIMIT: usize = 8;
        let limiter = FailedAuthLimiter::new_with_attempt_budget(
            PEER_LIMIT,
            Duration::from_secs(60),
            1,
            ATTEMPTS,
            256,
        );
        let protected_peer = IpAddr::from([192, 0, 2, 11]);
        for _ in 0..PEER_LIMIT {
            limiter.reserve(protected_peer).unwrap().fail();
        }
        let overflow_peer = IpAddr::from([192, 0, 2, 12]);
        let start = Arc::new(Barrier::new(ATTEMPTS + 1));
        let release = Arc::new(Barrier::new(ATTEMPTS + 1));
        let (sender, receiver) = mpsc::channel();
        let mut threads = Vec::new();

        for _ in 0..ATTEMPTS {
            let limiter = limiter.clone();
            let start = start.clone();
            let release = release.clone();
            let sender = sender.clone();
            threads.push(thread::spawn(move || {
                start.wait();
                let reservation = limiter.reserve(overflow_peer);
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

        let released: Vec<_> = (0..PEER_LIMIT)
            .map(|_| {
                limiter
                    .reserve(overflow_peer)
                    .expect("dropped overflow reservation releases its pending slot")
            })
            .collect();
        assert!(limiter.reserve(overflow_peer).is_none());
        drop(released);
    }

    #[test]
    fn overflow_admission_counts_existing_failures_toward_the_peer_limit() {
        const PEER_LIMIT: usize = 8;
        let limiter = FailedAuthLimiter::new_with_attempt_budget(
            PEER_LIMIT,
            Duration::from_secs(60),
            3,
            16,
            1024,
        );
        let protected_peer = IpAddr::from([192, 0, 2, 13]);
        let nearly_limited_peer = IpAddr::from([192, 0, 2, 14]);
        let pending_peer = IpAddr::from([192, 0, 2, 15]);
        for _ in 0..PEER_LIMIT {
            limiter.reserve(protected_peer).unwrap().fail();
        }
        for _ in 0..(PEER_LIMIT - 1) {
            limiter.reserve(nearly_limited_peer).unwrap().fail();
        }
        let _pending = limiter.reserve(pending_peer).unwrap();

        let mut last_peer_slot = limiter.reserve(nearly_limited_peer).unwrap();
        assert!(limiter.reserve(nearly_limited_peer).is_none());
        last_peer_slot.succeed();
        assert_eq!(limiter.failure_record_count(), PEER_LIMIT);
    }

    #[test]
    fn overflow_and_tracked_reservations_share_the_global_pending_cap() {
        let window = Duration::from_millis(40);
        let limiter = FailedAuthLimiter::new_with_attempt_budget(2, window, 1, 2, 1024);
        let protected_peer = IpAddr::from([192, 0, 2, 16]);
        limiter.reserve(protected_peer).unwrap().fail();
        limiter.reserve(protected_peer).unwrap().fail();
        let first_overflow = limiter.reserve(IpAddr::from([192, 0, 2, 17])).unwrap();
        let _second_overflow = limiter.reserve(IpAddr::from([192, 0, 2, 18])).unwrap();
        thread::sleep(window + Duration::from_millis(20));
        let recovering_peer = IpAddr::from([192, 0, 2, 19]);

        assert!(limiter.reserve(recovering_peer).is_none());
        drop(first_overflow);
        assert!(limiter.reserve(recovering_peer).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn pending_cap_rejection_does_not_reinsert_an_expired_empty_bucket() {
        let window = Duration::from_secs(60);
        let limiter = FailedAuthLimiter::new(1, window, 1, 1);
        let protected_peer = IpAddr::from([192, 0, 2, 100]);
        let overflow_peer = IpAddr::from([192, 0, 2, 101]);
        let unseen_peer = IpAddr::from([192, 0, 2, 102]);
        limiter.reserve(protected_peer).unwrap().fail();
        let overflow = limiter.reserve(overflow_peer).unwrap();

        tokio::time::advance(window).await;
        assert!(limiter.reserve(protected_peer).is_none());
        drop(overflow);

        assert!(
            limiter.reserve(unseen_peer).is_some(),
            "an expired empty target must not occupy the only tracked-peer slot"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shard_budget_rejection_does_not_reinsert_an_expired_empty_bucket() {
        let window = Duration::from_secs(60);
        let limiter = FailedAuthLimiter::new_with_attempt_budget(1, window, 1, 2, 32);
        let protected_peer = IpAddr::from([198, 51, 100, 1]);
        let protected_shard = limiter.attempt_shard_for_test(protected_peer);
        let mut same_shard = Vec::new();
        let mut other_shard = None;
        for suffix in 2..=254 {
            let candidate = IpAddr::from([198, 51, 100, suffix]);
            if limiter.attempt_shard_for_test(candidate) == protected_shard {
                same_shard.push(candidate);
            } else {
                other_shard.get_or_insert(candidate);
            }
            if same_shard.len() == 3 && other_shard.is_some() {
                break;
            }
        }
        let [bootstrap, first_burn, second_burn]: [IpAddr; 3] = same_shard
            .try_into()
            .expect("three IPv4 peers colliding with the protected shard");
        let unseen_peer = other_shard.expect("an IPv4 peer in another shard");

        drop(limiter.reserve(bootstrap).unwrap());
        tokio::time::advance(Duration::from_secs(10)).await;
        limiter.reserve(protected_peer).unwrap().fail();
        tokio::time::advance(Duration::from_secs(50)).await;
        drop(limiter.reserve(first_burn).unwrap());
        drop(limiter.reserve(second_burn).unwrap());
        tokio::time::advance(Duration::from_secs(10)).await;

        assert!(limiter.reserve(protected_peer).is_none());
        assert!(
            limiter.reserve(unseen_peer).is_some(),
            "a shard-budget denial must delete its expired empty target bucket"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn overflow_and_tracked_reservations_share_the_per_peer_limit() {
        let window = Duration::from_secs(60);
        let limiter = FailedAuthLimiter::new_with_attempt_budget(2, window, 1, 4, 1024);
        let protected_peer = IpAddr::from([192, 0, 2, 103]);
        let converting_peer = IpAddr::from([192, 0, 2, 104]);
        limiter.reserve(protected_peer).unwrap().fail();
        limiter.reserve(protected_peer).unwrap().fail();
        let first_overflow = limiter.reserve(converting_peer).unwrap();
        let second_overflow = limiter.reserve(converting_peer).unwrap();

        tokio::time::advance(window).await;
        assert!(
            limiter.reserve(converting_peer).is_none(),
            "two held overflow reservations must exhaust the peer limit after capacity recovery"
        );

        drop(first_overflow);
        let tracked = limiter
            .reserve(converting_peer)
            .expect("releasing one overflow reservation restores exactly one peer slot");
        assert!(limiter.reserve(converting_peer).is_none());

        drop(tracked);
        drop(second_overflow);
        assert!(limiter.reserve(converting_peer).is_some());
    }

    #[test]
    fn dropped_reservation_releases_neutrally_without_leaving_pending_state() {
        let limiter = FailedAuthLimiter::new(2, Duration::from_secs(60), 4, 4);
        let peer = IpAddr::from([192, 0, 2, 20]);

        drop(limiter.reserve(peer).unwrap());

        assert_eq!(limiter.pending_count(), 0);
        assert_eq!(limiter.failure_record_count(), 0);
        assert!(limiter.reserve(peer).is_some());
    }

    #[tokio::test]
    async fn cancelling_a_task_releases_its_reservation_neutrally() {
        let limiter = FailedAuthLimiter::new(2, Duration::from_secs(60), 4, 4);
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
        assert_eq!(limiter.failure_record_count(), 0);
        assert!(limiter.reserve(peer).is_some());
    }

    #[test]
    fn neutral_release_preserves_prior_failures_without_adding_one() {
        let limiter = FailedAuthLimiter::new(2, Duration::from_secs(60), 4, 4);
        let peer = IpAddr::from([192, 0, 2, 23]);
        limiter.reserve(peer).unwrap().fail();

        drop(limiter.reserve(peer).unwrap());

        assert_eq!(limiter.failure_record_count(), 1);
        limiter.reserve(peer).unwrap().fail();
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
    fn ipv4_mapped_addresses_are_exact_and_share_the_native_ipv4_bucket() {
        let limiter = FailedAuthLimiter::new(1, Duration::from_secs(60), 4, 4);
        let mapped = "::ffff:192.0.2.60".parse().unwrap();
        let other_mapped = "::ffff:192.0.2.61".parse().unwrap();
        let native_same = IpAddr::from([192, 0, 2, 60]);
        limiter.reserve(mapped).unwrap().fail();

        let mut other = limiter
            .reserve(other_mapped)
            .expect("different IPv4 address");
        assert!(limiter.reserve(native_same).is_none());
        other.succeed();
    }

    #[test]
    fn protected_penalty_survives_churn_while_new_peer_remains_admissible_and_window_recovers() {
        let window = Duration::from_millis(40);
        let limiter = FailedAuthLimiter::new_with_attempt_budget(1, window, 2, 2, 128);
        let first = IpAddr::from([192, 0, 2, 30]);
        limiter.reserve(first).unwrap().fail();

        for suffix in 31..=94 {
            if let Some(mut attempt) = limiter.reserve(IpAddr::from([192, 0, 2, suffix])) {
                attempt.fail();
            }
        }

        assert!(limiter.reserve(first).is_none());
        assert!(
            limiter
                .reserve("2001:db8:ffff::1".parse().unwrap())
                .is_some()
        );

        thread::sleep(window + Duration::from_millis(20));
        assert!(limiter.reserve(first).is_some());
    }

    #[test]
    fn sharded_attempt_budget_limits_collisions_without_blocking_other_shards_or_families() {
        let window = Duration::from_millis(40);
        let limiter = FailedAuthLimiter::new_with_attempt_budget(8, window, 32, 128, 16);
        let first = IpAddr::from([198, 51, 100, 1]);
        let first_shard = limiter.attempt_shard_for_test(first);
        let mut collision = None;
        let mut other_shard = None;
        for suffix in 2..=254 {
            let candidate = IpAddr::from([198, 51, 100, suffix]);
            if limiter.attempt_shard_for_test(candidate) == first_shard {
                collision.get_or_insert(candidate);
            } else {
                other_shard.get_or_insert(candidate);
            }
            if collision.is_some() && other_shard.is_some() {
                break;
            }
        }
        let collision = collision.expect("IPv4 shard collision");
        let other_shard = other_shard.expect("different IPv4 shard");

        drop(limiter.reserve(first).unwrap());

        assert!(limiter.reserve(collision).is_none());
        assert!(limiter.reserve(other_shard).is_some());
        let mut used_ipv4_shards = [false; AUTH_ATTEMPT_SHARDS_PER_FAMILY];
        used_ipv4_shards[first_shard] = true;
        used_ipv4_shards[limiter.attempt_shard_for_test(other_shard)] = true;
        for suffix in 2..=254 {
            let candidate = IpAddr::from([203, 0, 113, suffix]);
            let shard = limiter.attempt_shard_for_test(candidate);
            if !used_ipv4_shards[shard] {
                drop(limiter.reserve(candidate).unwrap());
                used_ipv4_shards[shard] = true;
            }
            if used_ipv4_shards.into_iter().all(|used| used) {
                break;
            }
        }
        assert!(used_ipv4_shards.into_iter().all(|used| used));
        assert!(
            limiter
                .reserve("2001:db8:abcd::1".parse().unwrap())
                .is_some()
        );

        thread::sleep(window + Duration::from_millis(20));
        assert!(limiter.reserve(collision).is_some());
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

    #[test]
    fn one_admission_reclaims_only_one_expired_bucket_under_capacity_pressure() {
        const PEERS: usize = 1024;
        let window = Duration::from_millis(200);
        let limiter = FailedAuthLimiter::new(1, window, PEERS, PEERS);
        for index in 0..PEERS {
            let peer = IpAddr::from([10, (index >> 8) as u8, index as u8, 2]);
            limiter.reserve(peer).unwrap().fail();
        }
        thread::sleep(window + Duration::from_millis(20));

        assert!(limiter.reserve(IpAddr::from([192, 0, 2, 80])).is_some());
        assert_eq!(limiter.last_admission_bucket_visits(), 1);
        assert_eq!(limiter.failure_record_count(), PEERS - 1);
    }
}
