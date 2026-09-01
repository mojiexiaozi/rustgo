use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::time::Instant;

use super::WebRuntimeLimits;

pub(super) const SESSION_COOKIE_NAME: &str = "rustgo_session";
const SESSION_TOKEN_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const MAX_COOKIE_HEADER_BYTES: usize = 1_024;

type HmacSha256 = Hmac<Sha256>;

pub(super) struct AuthenticationState {
    credentials: CredentialDigests,
    sessions: SessionStore,
    login_limiter: Mutex<LoginRateLimiter>,
}

impl AuthenticationState {
    pub(super) fn new(
        username: &str,
        password: &str,
        limits: &WebRuntimeLimits,
    ) -> Result<Self, AuthenticationError> {
        Ok(Self {
            credentials: CredentialDigests::new(username, password),
            sessions: SessionStore::new(limits)?,
            login_limiter: Mutex::new(LoginRateLimiter::new(limits)),
        })
    }

    pub(super) fn admit_login(&self, peer: IpAddr) -> bool {
        self.login_limiter
            .lock()
            .map(|mut limiter| limiter.admit(canonical_ip(peer), Instant::now()))
            .unwrap_or(false)
    }

    pub(super) fn credentials_match(&self, username: &str, password: &str) -> bool {
        self.credentials.matches(username, password)
    }

    pub(super) fn issue_session(&self) -> Result<String, AuthenticationError> {
        self.sessions.issue(Instant::now())
    }

    pub(super) fn authenticate_cookie(&self, cookie_header: Option<&str>) -> bool {
        let Some(mut token) = cookie_header.and_then(parse_session_cookie) else {
            return false;
        };
        let authenticated = self.sessions.authenticate(&token, Instant::now());
        token.fill(0);
        authenticated
    }

    pub(super) fn revoke_cookie(&self, cookie_header: Option<&str>) -> bool {
        let Some(mut token) = cookie_header.and_then(parse_session_cookie) else {
            return false;
        };
        let revoked = self.sessions.revoke(&token, Instant::now());
        token.fill(0);
        revoked
    }
}

struct CredentialDigests {
    username: [u8; DIGEST_BYTES],
    password: [u8; DIGEST_BYTES],
}

impl CredentialDigests {
    fn new(username: &str, password: &str) -> Self {
        Self {
            username: digest(username.as_bytes()),
            password: digest(password.as_bytes()),
        }
    }

    fn matches(&self, username: &str, password: &str) -> bool {
        let supplied_username = digest(username.as_bytes());
        let supplied_password = digest(password.as_bytes());
        let username_matches = self.username.ct_eq(&supplied_username);
        let password_matches = self.password.ct_eq(&supplied_password);
        bool::from(username_matches & password_matches)
    }
}

fn digest(value: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(value).into()
}

struct SessionStore {
    hmac_key: [u8; DIGEST_BYTES],
    table: Mutex<SessionTable>,
    idle_timeout: Duration,
    absolute_timeout: Duration,
    capacity: usize,
}

impl SessionStore {
    fn new(limits: &WebRuntimeLimits) -> Result<Self, AuthenticationError> {
        let mut hmac_key = [0_u8; DIGEST_BYTES];
        OsRng
            .try_fill_bytes(&mut hmac_key)
            .map_err(|_| AuthenticationError::Randomness)?;
        Ok(Self {
            hmac_key,
            table: Mutex::new(SessionTable::default()),
            idle_timeout: limits.session_idle_timeout,
            absolute_timeout: limits.session_absolute_timeout,
            capacity: limits.max_sessions,
        })
    }

    fn issue(&self, now: Instant) -> Result<String, AuthenticationError> {
        for _ in 0..4 {
            let mut token = [0_u8; SESSION_TOKEN_BYTES];
            OsRng
                .try_fill_bytes(&mut token)
                .map_err(|_| AuthenticationError::Randomness)?;
            let key = self.derive_key(&token);
            let encoded = URL_SAFE_NO_PAD.encode(token);
            token.fill(0);

            let mut table = self
                .table
                .lock()
                .map_err(|_| AuthenticationError::Unavailable)?;
            table.remove_expired(now, self.idle_timeout, self.absolute_timeout);
            if table.sessions.contains_key(&key) {
                continue;
            }
            if table.sessions.len() == self.capacity {
                table.evict_oldest();
            }
            let sequence = table.next_sequence;
            table.next_sequence = table.next_sequence.saturating_add(1);
            table.sessions.insert(
                key,
                SessionRecord {
                    created: now,
                    last_activity: now,
                    sequence,
                },
            );
            return Ok(encoded);
        }
        Err(AuthenticationError::Unavailable)
    }

    fn authenticate(&self, token: &[u8; SESSION_TOKEN_BYTES], now: Instant) -> bool {
        let key = self.derive_key(token);
        let Ok(mut table) = self.table.lock() else {
            return false;
        };
        table.remove_expired(now, self.idle_timeout, self.absolute_timeout);
        let Some(record) = table.sessions.get_mut(&key) else {
            return false;
        };
        record.last_activity = now;
        true
    }

    fn revoke(&self, token: &[u8; SESSION_TOKEN_BYTES], now: Instant) -> bool {
        let key = self.derive_key(token);
        let Ok(mut table) = self.table.lock() else {
            return false;
        };
        table.remove_expired(now, self.idle_timeout, self.absolute_timeout);
        table.sessions.remove(&key).is_some()
    }

    fn derive_key(&self, token: &[u8; SESSION_TOKEN_BYTES]) -> SessionKey {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key)
            .expect("HMAC-SHA256 accepts keys of every size");
        mac.update(token);
        SessionKey(mac.finalize().into_bytes().into())
    }
}

impl Drop for SessionStore {
    fn drop(&mut self) {
        self.hmac_key.fill(0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey([u8; DIGEST_BYTES]);

struct SessionRecord {
    created: Instant,
    last_activity: Instant,
    sequence: u64,
}

#[derive(Default)]
struct SessionTable {
    sessions: HashMap<SessionKey, SessionRecord>,
    next_sequence: u64,
}

impl SessionTable {
    fn remove_expired(&mut self, now: Instant, idle: Duration, absolute: Duration) {
        self.sessions.retain(|_, record| {
            now.duration_since(record.last_activity) < idle
                && now.duration_since(record.created) < absolute
        });
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .sessions
            .iter()
            .min_by_key(|(_, record)| (record.last_activity, record.created, record.sequence))
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.sessions.remove(&key);
        }
    }
}

struct LoginRateLimiter {
    global: VecDeque<Instant>,
    peers: HashMap<IpAddr, PeerAttempts>,
    next_sequence: u64,
    window: Duration,
    per_peer_limit: usize,
    global_limit: usize,
    max_peers: usize,
}

impl LoginRateLimiter {
    fn new(limits: &WebRuntimeLimits) -> Self {
        Self {
            global: VecDeque::with_capacity(limits.max_global_login_attempts),
            peers: HashMap::with_capacity(limits.max_tracked_login_peers),
            next_sequence: 0,
            window: limits.login_window,
            per_peer_limit: limits.max_login_attempts_per_peer,
            global_limit: limits.max_global_login_attempts,
            max_peers: limits.max_tracked_login_peers,
        }
    }

    fn admit(&mut self, peer: IpAddr, now: Instant) -> bool {
        prune_attempts(&mut self.global, now, self.window);
        self.peers.retain(|_, attempts| {
            prune_attempts(&mut attempts.attempts, now, self.window);
            !attempts.attempts.is_empty()
        });

        if self.global.len() >= self.global_limit {
            return false;
        }
        if self
            .peers
            .get(&peer)
            .is_some_and(|attempts| attempts.attempts.len() >= self.per_peer_limit)
        {
            return false;
        }

        if !self.peers.contains_key(&peer) && self.peers.len() == self.max_peers {
            let oldest = self
                .peers
                .iter()
                .min_by_key(|(address, attempts)| {
                    (attempts.last_seen, attempts.sequence, **address)
                })
                .map(|(address, _)| *address);
            if let Some(oldest) = oldest {
                self.peers.remove(&oldest);
            }
        }

        self.global.push_back(now);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let attempts = self.peers.entry(peer).or_insert_with(|| PeerAttempts {
            attempts: VecDeque::with_capacity(self.per_peer_limit),
            last_seen: now,
            sequence,
        });
        attempts.attempts.push_back(now);
        attempts.last_seen = now;
        true
    }
}

struct PeerAttempts {
    attempts: VecDeque<Instant>,
    last_seen: Instant,
    sequence: u64,
}

fn prune_attempts(attempts: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while attempts
        .front()
        .is_some_and(|attempt| now.duration_since(*attempt) >= window)
    {
        attempts.pop_front();
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(Ipv6Addr::from(ipv6.octets()))),
        IpAddr::V4(_) => ip,
    }
}

fn parse_session_cookie(header: &str) -> Option<[u8; SESSION_TOKEN_BYTES]> {
    if header.len() > MAX_COOKIE_HEADER_BYTES {
        return None;
    }
    let mut value = None;
    for pair in header.split(';') {
        let (name, candidate) = pair.trim().split_once('=')?;
        if name == SESSION_COOKIE_NAME && value.replace(candidate).is_some() {
            return None;
        }
    }
    let value = value?;
    if value.len() != 43 {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(value.as_bytes()).ok()?;
    decoded.try_into().ok()
}

#[derive(Debug, thiserror::Error)]
pub(super) enum AuthenticationError {
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("authentication state is unavailable")]
    Unavailable,
}
