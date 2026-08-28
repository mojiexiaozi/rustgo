use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::{TryRngCore, rngs::OsRng};
use rustgo_protocol::SocketAddress;
use rustgo_rendezvous::{
    OBSERVATION_TOKEN_BYTES, ObservationEndpoint, ObservationGrant, ObservationProbe,
    ObservationReply, ObservationToken,
};
use thiserror::Error;
use tokio::{net::UdpSocket, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::{AuthenticatedClient, ClientRegistry};

const MAX_PENDING_OBSERVATION_TOKENS: usize = 65_536;
const MAX_TRACKED_OBSERVATION_SUBJECTS: usize = 65_536;
const MAX_OBSERVATION_BURST: u32 = 65_536;
const TOKEN_GENERATION_ATTEMPTS: usize = 16;
const MAX_BUCKET_MAINTENANCE_STEPS_PER_PACKET: usize = 4;

#[derive(Debug, Clone)]
pub struct ObservationRuntimeLimits {
    pub token_ttl: Duration,
    pub max_pending_tokens: usize,
    pub max_tracked_ips: usize,
    pub max_tracked_devices: usize,
    pub per_ip_burst: u32,
    pub per_device_burst: u32,
    pub refill_interval: Duration,
    #[doc(hidden)]
    pub test_send_delay: Duration,
}

impl Default for ObservationRuntimeLimits {
    fn default() -> Self {
        Self {
            token_ttl: Duration::from_secs(30),
            max_pending_tokens: 4096,
            max_tracked_ips: 16_384,
            max_tracked_devices: 4096,
            per_ip_burst: 32,
            per_device_burst: 8,
            refill_interval: Duration::from_secs(1),
            test_send_delay: Duration::ZERO,
        }
    }
}

impl ObservationRuntimeLimits {
    fn is_valid(&self) -> bool {
        !self.token_ttl.is_zero()
            && self.max_pending_tokens >= 2
            && self.max_pending_tokens <= MAX_PENDING_OBSERVATION_TOKENS
            && self.max_tracked_ips > 0
            && self.max_tracked_ips <= MAX_TRACKED_OBSERVATION_SUBJECTS
            && self.max_tracked_devices > 0
            && self.max_tracked_devices <= MAX_TRACKED_OBSERVATION_SUBJECTS
            && (1..=MAX_OBSERVATION_BURST).contains(&self.per_ip_burst)
            && (1..=MAX_OBSERVATION_BURST).contains(&self.per_device_burst)
            && !self.refill_interval.is_zero()
            && self.test_send_delay <= Duration::from_secs(60)
            && Instant::now().checked_add(self.token_ttl).is_some()
            && Instant::now().checked_add(self.refill_interval).is_some()
            && Instant::now().checked_add(self.test_send_delay).is_some()
            && SystemTime::now().checked_add(self.token_ttl).is_some()
    }
}

pub struct ObservationService {
    primary: UdpSocket,
    alternate: UdpSocket,
    state: Arc<Mutex<ObservationState>>,
    limits: ObservationRuntimeLimits,
}

impl std::fmt::Debug for ObservationService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObservationService")
            .field("local_addrs", &self.local_addrs().ok())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl ObservationService {
    pub async fn bind(
        primary: SocketAddr,
        alternate: SocketAddr,
        limits: ObservationRuntimeLimits,
    ) -> io::Result<Self> {
        if !limits.is_valid()
            || (primary.port() != 0 && alternate.port() != 0 && primary.port() == alternate.port())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid observation service configuration",
            ));
        }
        let primary = UdpSocket::bind(primary).await?;
        let alternate = UdpSocket::bind(alternate).await?;
        Ok(Self {
            primary,
            alternate,
            state: Arc::new(Mutex::new(ObservationState::default())),
            limits,
        })
    }

    pub fn local_addrs(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        Ok((self.primary.local_addr()?, self.alternate.local_addr()?))
    }

    pub fn token_issuer(&self, registry: ClientRegistry) -> ObservationTokenIssuer {
        ObservationTokenIssuer {
            state: self.state.clone(),
            registry,
            limits: self.limits.clone(),
        }
    }

    pub async fn run(self, shutdown: CancellationToken) -> io::Result<()> {
        let primary = serve_socket(
            &self.primary,
            ObservationEndpoint::Primary,
            self.state.clone(),
            self.limits.clone(),
            shutdown.clone(),
        );
        let alternate = serve_socket(
            &self.alternate,
            ObservationEndpoint::Alternate,
            self.state.clone(),
            self.limits.clone(),
            shutdown,
        );
        tokio::try_join!(primary, alternate)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ObservationTokenIssuer {
    state: Arc<Mutex<ObservationState>>,
    registry: ClientRegistry,
    limits: ObservationRuntimeLimits,
}

impl std::fmt::Debug for ObservationTokenIssuer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObservationTokenIssuer")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl ObservationTokenIssuer {
    pub fn issue(
        &self,
        identity: &AuthenticatedClient,
    ) -> Result<ObservationGrant, ObservationIssueError> {
        if !self.registry.is_active_session(identity) {
            return Err(ObservationIssueError::InactiveSession);
        }
        let now = Instant::now();
        let expires_at = now
            .checked_add(self.limits.token_ttl)
            .ok_or(ObservationIssueError::InvalidLifetime)?;
        let expires_unix_secs = SystemTime::now()
            .checked_add(self.limits.token_ttl)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .ok_or(ObservationIssueError::InvalidLifetime)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ObservationIssueError::Internal)?;
        state.pending.retain(|_, entry| entry.expires_at > now);
        if state.pending.len() > self.limits.max_pending_tokens.saturating_sub(2) {
            return Err(ObservationIssueError::CapacityReached);
        }
        let primary = issue_unique_token(&state.pending, None)?;
        let alternate = issue_unique_token(&state.pending, Some(primary.as_bytes()))?;
        let entry = |endpoint| PendingToken {
            identity: identity.clone(),
            registry: self.registry.clone(),
            endpoint,
            expires_at,
        };
        state
            .pending
            .insert(*primary.as_bytes(), entry(ObservationEndpoint::Primary));
        state
            .pending
            .insert(*alternate.as_bytes(), entry(ObservationEndpoint::Alternate));
        Ok(ObservationGrant::new(primary, alternate, expires_unix_secs))
    }
}

#[derive(Debug, Error)]
pub enum ObservationIssueError {
    #[error("observation tokens require an active authenticated control session")]
    InactiveSession,
    #[error("observation token capacity reached")]
    CapacityReached,
    #[error("could not generate an observation token")]
    Entropy,
    #[error("invalid observation token lifetime")]
    InvalidLifetime,
    #[error("observation token state is unavailable")]
    Internal,
}

struct ObservationState {
    pending: HashMap<[u8; OBSERVATION_TOKEN_BYTES], PendingToken>,
    global_ip_admission: TokenBucket,
    ip_buckets: BucketTable<IpAddr>,
    device_buckets: BucketTable<String>,
}

impl Default for ObservationState {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            global_ip_admission: TokenBucket::new(0, Instant::now()),
            ip_buckets: BucketTable::default(),
            device_buckets: BucketTable::default(),
        }
    }
}

struct PendingToken {
    identity: AuthenticatedClient,
    registry: ClientRegistry,
    endpoint: ObservationEndpoint,
    expires_at: Instant,
}

struct TokenBucket {
    capacity: u32,
    tokens: u32,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, now: Instant) -> Self {
        Self {
            capacity,
            tokens: capacity,
            last_refill: now,
        }
    }

    fn take(&mut self, capacity: u32, refill_interval: Duration, now: Instant) -> bool {
        if self.capacity != capacity {
            *self = Self::new(capacity, now);
        }
        let elapsed = now.duration_since(self.last_refill);
        let refill = elapsed.as_nanos() / refill_interval.as_nanos();
        if refill > 0 {
            self.tokens = self
                .tokens
                .saturating_add(u32::try_from(refill).unwrap_or(u32::MAX))
                .min(capacity);
            self.last_refill = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    #[cfg(test)]
    const fn remaining(&self) -> u32 {
        self.tokens
    }
}

struct BucketEntry {
    bucket: TokenBucket,
    generation: u64,
}

struct BucketExpiry<K> {
    key: K,
    generation: u64,
    expires_at: Instant,
}

struct BucketTable<K> {
    entries: HashMap<K, BucketEntry>,
    expirations: VecDeque<BucketExpiry<K>>,
    next_generation: u64,
}

impl<K> Default for BucketTable<K> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            expirations: VecDeque::new(),
            next_generation: 1,
        }
    }
}

struct BucketAdmission {
    allowed: bool,
    maintenance_steps: usize,
}

impl<K: Eq + Hash + Clone> BucketTable<K> {
    fn allow(
        &mut self,
        key: K,
        maximum_entries: usize,
        capacity: u32,
        refill_interval: Duration,
        now: Instant,
    ) -> BucketAdmission {
        if let Some(entry) = self.entries.get_mut(&key) {
            return BucketAdmission {
                allowed: entry.bucket.take(capacity, refill_interval, now),
                maintenance_steps: 0,
            };
        }

        let stale_after = refill_interval
            .checked_mul(capacity)
            .unwrap_or(Duration::MAX);
        let mut maintenance_steps = self.sweep_expired(now, stale_after);
        if self.entries.len() >= maximum_entries {
            while maintenance_steps < MAX_BUCKET_MAINTENANCE_STEPS_PER_PACKET {
                let Some(expiry) = self.expirations.pop_front() else {
                    break;
                };
                maintenance_steps += 1;
                if self
                    .entries
                    .get(&expiry.key)
                    .is_some_and(|entry| entry.generation == expiry.generation)
                {
                    self.entries.remove(&expiry.key);
                    break;
                }
            }
        }
        if self.entries.len() >= maximum_entries {
            return BucketAdmission {
                allowed: false,
                maintenance_steps,
            };
        }

        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let mut bucket = TokenBucket::new(capacity, now);
        let allowed = bucket.take(capacity, refill_interval, now);
        self.entries
            .insert(key.clone(), BucketEntry { bucket, generation });
        self.expirations.push_back(BucketExpiry {
            key,
            generation,
            expires_at: expiration_from(now, stale_after, refill_interval),
        });
        BucketAdmission {
            allowed,
            maintenance_steps,
        }
    }

    fn sweep_expired(&mut self, now: Instant, stale_after: Duration) -> usize {
        let mut steps = 0;
        while steps < MAX_BUCKET_MAINTENANCE_STEPS_PER_PACKET {
            let Some(expiry) = self.expirations.front() else {
                break;
            };
            if expiry.expires_at > now {
                break;
            }
            let expiry = self
                .expirations
                .pop_front()
                .expect("the expiry queue front exists");
            steps += 1;
            let Some(entry) = self.entries.get(&expiry.key) else {
                continue;
            };
            if entry.generation != expiry.generation {
                continue;
            }
            let expires_at = expiration_from(entry.bucket.last_refill, stale_after, Duration::ZERO);
            if expires_at <= now {
                self.entries.remove(&expiry.key);
            } else {
                self.expirations.push_back(BucketExpiry {
                    expires_at,
                    ..expiry
                });
            }
        }
        steps
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn queue_len(&self) -> usize {
        self.expirations.len()
    }
}

fn expiration_from(now: Instant, stale_after: Duration, fallback: Duration) -> Instant {
    now.checked_add(stale_after)
        .or_else(|| now.checked_add(fallback))
        .unwrap_or(now)
}

async fn serve_socket(
    socket: &UdpSocket,
    endpoint: ObservationEndpoint,
    state: Arc<Mutex<ObservationState>>,
    limits: ObservationRuntimeLimits,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let mut buffer = [0_u8; ObservationProbe::MAX_WIRE_BYTES + 1];
    loop {
        let received = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            received = socket.recv_from(&mut buffer) => received,
        };
        let received = match received {
            Ok(received) => received,
            Err(error) if is_oversized_datagram(&error) => continue,
            Err(error) => return Err(error),
        };
        let (length, source) = received;
        let Ok(probe) = ObservationProbe::decode(&buffer[..length]) else {
            continue;
        };
        let Some(nonce) = authorize_probe(&state, &limits, &probe, endpoint, source.ip()) else {
            continue;
        };
        if !limits.test_send_delay.is_zero() {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                () = tokio::time::sleep(limits.test_send_delay) => {}
            }
        }
        let reply = ObservationReply::new(nonce, wire_address(source), endpoint);
        let Ok(encoded) = reply.encode() else {
            continue;
        };
        if encoded.len() > length {
            continue;
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            sent = socket.send_to(&encoded, source) => {
                sent?;
            }
        }
    }
}

fn authorize_probe(
    state: &Mutex<ObservationState>,
    limits: &ObservationRuntimeLimits,
    probe: &ObservationProbe,
    endpoint: ObservationEndpoint,
    source_ip: IpAddr,
) -> Option<rustgo_rendezvous::ObservationNonce> {
    let now = Instant::now();
    let pending = {
        let mut state = state.lock().ok()?;
        if !state.global_ip_admission.take(
            u32::try_from(limits.max_tracked_ips).ok()?,
            limits.refill_interval,
            now,
        ) {
            return None;
        }
        let admission = state.ip_buckets.allow(
            canonical_ip(source_ip),
            limits.max_tracked_ips,
            limits.per_ip_burst,
            limits.refill_interval,
            now,
        );
        debug_assert!(admission.maintenance_steps <= MAX_BUCKET_MAINTENANCE_STEPS_PER_PACKET);
        if !admission.allowed {
            return None;
        }
        let key = *probe.token().as_bytes();
        let entry = state.pending.get(&key)?;
        if entry.endpoint != endpoint {
            return None;
        }
        let entry = state.pending.remove(&key)?;
        if entry.expires_at <= now {
            return None;
        }
        entry
    };

    let device_key = pending.identity.fingerprint().to_owned();
    // The identity object can only be created by successful control authentication.
    // Every UDP redemption still rechecks the exact live registry session.
    if !pending.registry.is_active_session(&pending.identity) {
        return None;
    }
    let mut state = state.lock().ok()?;
    let admission = state.device_buckets.allow(
        device_key,
        limits.max_tracked_devices,
        limits.per_device_burst,
        limits.refill_interval,
        now,
    );
    debug_assert!(admission.maintenance_steps <= MAX_BUCKET_MAINTENANCE_STEPS_PER_PACKET);
    admission.allowed.then_some(probe.nonce())
}

fn issue_unique_token(
    pending: &HashMap<[u8; OBSERVATION_TOKEN_BYTES], PendingToken>,
    excluded: Option<&[u8; OBSERVATION_TOKEN_BYTES]>,
) -> Result<ObservationToken, ObservationIssueError> {
    for _ in 0..TOKEN_GENERATION_ATTEMPTS {
        let mut bytes = [0_u8; OBSERVATION_TOKEN_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| ObservationIssueError::Entropy)?;
        if !pending.contains_key(&bytes) && excluded != Some(&bytes) {
            return Ok(ObservationToken::from(bytes));
        }
    }
    Err(ObservationIssueError::Entropy)
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ipv6)),
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
    }
}

fn wire_address(address: SocketAddr) -> SocketAddress {
    match address {
        SocketAddr::V4(address) => SocketAddress::V4 {
            octets: address.ip().octets(),
            port: address.port(),
        },
        SocketAddr::V6(address) => SocketAddress::V6 {
            octets: address.ip().octets(),
            port: address.port(),
        },
    }
}

fn is_oversized_datagram(error: &io::Error) -> bool {
    // Windows reports WSAEMSGSIZE when a datagram does not fit the fixed
    // receive buffer. Unix UDP commonly reports a truncated length instead.
    error.raw_os_error() == Some(10_040)
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        net::{Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use rustgo_rendezvous::{
        ObservationEndpoint, ObservationNonce, ObservationProbe, ObservationReply,
    };
    use tokio::{net::UdpSocket, time::timeout};
    use tokio_util::sync::CancellationToken;

    use super::{
        BucketTable, MAX_BUCKET_MAINTENANCE_STEPS_PER_PACKET, ObservationRuntimeLimits,
        ObservationService,
    };
    use crate::{AuthenticatedClient, ClientRegistry};

    fn loopback(host: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, host], 0))
    }

    fn limits() -> ObservationRuntimeLimits {
        ObservationRuntimeLimits {
            token_ttl: Duration::from_secs(1),
            max_pending_tokens: 16,
            max_tracked_ips: 16,
            max_tracked_devices: 16,
            per_ip_burst: 8,
            per_device_burst: 8,
            refill_interval: Duration::from_secs(1),
            test_send_delay: Duration::ZERO,
        }
    }

    fn active_client() -> Result<(ClientRegistry, crate::ControlSessionGuard), Box<dyn Error>> {
        let registry = ClientRegistry::new(2, 1, "127.0.0.1".parse()?, 4, Duration::from_secs(30))?;
        let identity = AuthenticatedClient::verified(
            "home-pc".to_owned(),
            "sha256:unit-test".to_owned(),
            vec![7; 32],
        );
        let guard = registry.claim(identity)?;
        Ok((registry, guard))
    }

    async fn receive_reply(
        socket: &UdpSocket,
    ) -> Result<(ObservationReply, SocketAddr), Box<dyn Error>> {
        let mut bytes = [0_u8; ObservationReply::MAX_WIRE_BYTES];
        let (length, source) =
            timeout(Duration::from_secs(1), socket.recv_from(&mut bytes)).await??;
        Ok((ObservationReply::decode(&bytes[..length])?, source))
    }

    async fn expect_no_reply(socket: &UdpSocket) {
        let mut bytes = [0_u8; ObservationReply::MAX_WIRE_BYTES];
        assert!(
            timeout(Duration::from_millis(100), socket.recv_from(&mut bytes))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn one_use_role_bound_tokens_reply_from_both_ports_with_the_observed_source()
    -> Result<(), Box<dyn Error>> {
        let service = ObservationService::bind(loopback(1), loopback(1), limits()).await?;
        let addresses = service.local_addrs()?;
        let (registry, guard) = active_client()?;
        let issuer = service.token_issuer(registry);
        let grant = issuer.issue(guard.identity())?;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(service.run(shutdown.clone()));
        let client = UdpSocket::bind(loopback(1)).await?;

        let primary_nonce = ObservationNonce::from([1; 16]);
        let primary_probe =
            ObservationProbe::new(grant.primary_token().clone(), primary_nonce).encode()?;
        client.send_to(&primary_probe, addresses.0).await?;
        let (reply, source) = receive_reply(&client).await?;
        assert_eq!(source, addresses.0);
        assert_eq!(reply.nonce(), primary_nonce);
        assert_eq!(reply.endpoint(), ObservationEndpoint::Primary);
        assert_eq!(
            reply.observed_source(),
            &super::wire_address(client.local_addr()?)
        );

        client.send_to(&primary_probe, addresses.0).await?;
        expect_no_reply(&client).await;

        let alternate_nonce = ObservationNonce::from([2; 16]);
        let alternate_probe =
            ObservationProbe::new(grant.alternate_token().clone(), alternate_nonce).encode()?;
        client.send_to(&alternate_probe, addresses.0).await?;
        expect_no_reply(&client).await;
        client.send_to(&alternate_probe, addresses.1).await?;
        let (reply, source) = receive_reply(&client).await?;
        assert_eq!(source, addresses.1);
        assert_eq!(reply.nonce(), alternate_nonce);
        assert_eq!(reply.endpoint(), ObservationEndpoint::Alternate);
        assert_eq!(
            reply.observed_source(),
            &super::wire_address(client.local_addr()?)
        );

        shutdown.cancel();
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn expired_or_disconnected_session_tokens_are_dropped() -> Result<(), Box<dyn Error>> {
        let short = ObservationRuntimeLimits {
            token_ttl: Duration::from_millis(20),
            ..limits()
        };
        let service = ObservationService::bind(loopback(1), loopback(1), short).await?;
        let primary = service.local_addrs()?.0;
        let (registry, guard) = active_client()?;
        let issuer = service.token_issuer(registry);
        let expired = issuer.issue(guard.identity())?;
        tokio::time::sleep(Duration::from_millis(40)).await;
        let disconnected = issuer.issue(guard.identity())?;
        drop(guard);
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(service.run(shutdown.clone()));
        let client = UdpSocket::bind(loopback(1)).await?;

        for (token, nonce) in [
            (
                expired.primary_token().clone(),
                ObservationNonce::from([3; 16]),
            ),
            (
                disconnected.primary_token().clone(),
                ObservationNonce::from([4; 16]),
            ),
        ] {
            client
                .send_to(&ObservationProbe::new(token, nonce).encode()?, primary)
                .await?;
            expect_no_reply(&client).await;
        }

        shutdown.cancel();
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn per_ip_and_per_device_limits_apply_before_reply() -> Result<(), Box<dyn Error>> {
        let constrained = ObservationRuntimeLimits {
            per_ip_burst: 1,
            per_device_burst: 1,
            ..limits()
        };
        let service = ObservationService::bind(loopback(1), loopback(1), constrained).await?;
        let addresses = service.local_addrs()?;
        let (registry, guard) = active_client()?;
        let issuer = service.token_issuer(registry);
        let first = issuer.issue(guard.identity())?;
        let second = issuer.issue(guard.identity())?;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(service.run(shutdown.clone()));
        let first_ip = UdpSocket::bind(loopback(1)).await?;
        let second_ip = UdpSocket::bind(loopback(2)).await?;

        first_ip
            .send_to(
                &ObservationProbe::new(
                    first.primary_token().clone(),
                    ObservationNonce::from([5; 16]),
                )
                .encode()?,
                addresses.0,
            )
            .await?;
        receive_reply(&first_ip).await?;

        first_ip
            .send_to(
                &ObservationProbe::new(
                    first.alternate_token().clone(),
                    ObservationNonce::from([6; 16]),
                )
                .encode()?,
                addresses.1,
            )
            .await?;
        expect_no_reply(&first_ip).await;

        second_ip
            .send_to(
                &ObservationProbe::new(
                    second.primary_token().clone(),
                    ObservationNonce::from([7; 16]),
                )
                .encode()?,
                addresses.0,
            )
            .await?;
        expect_no_reply(&second_ip).await;

        shutdown.cancel();
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn ipv6_high_port_probe_receives_the_full_observed_source() -> Result<(), Box<dyn Error>>
    {
        let ipv6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        let service = match ObservationService::bind(ipv6, ipv6, limits()).await {
            Ok(service) => service,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let addresses = service.local_addrs()?;
        let (registry, guard) = active_client()?;
        let issuer = service.token_issuer(registry);
        let grant = issuer.issue(guard.identity())?;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(service.run(shutdown.clone()));
        let std_client = (40_000..40_100)
            .find_map(|port| std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).ok())
            .ok_or("no high IPv6 loopback UDP port was available")?;
        std_client.set_nonblocking(true)?;
        let client = UdpSocket::from_std(std_client)?;
        let nonce = ObservationNonce::from([8; 16]);

        client
            .send_to(
                &ObservationProbe::new(grant.primary_token().clone(), nonce).encode()?,
                addresses.0,
            )
            .await?;
        let (reply, source) = receive_reply(&client).await?;
        assert_eq!(source, addresses.0);
        assert_eq!(reply.nonce(), nonce);
        assert_eq!(reply.endpoint(), ObservationEndpoint::Primary);
        assert_eq!(
            reply.observed_source(),
            &super::wire_address(client.local_addr()?)
        );

        shutdown.cancel();
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn pending_token_capacity_is_hard_and_expiry_reclaims_it() -> Result<(), Box<dyn Error>> {
        let constrained = ObservationRuntimeLimits {
            token_ttl: Duration::from_millis(20),
            max_pending_tokens: 2,
            ..limits()
        };
        let service = ObservationService::bind(loopback(1), loopback(1), constrained).await?;
        let (registry, guard) = active_client()?;
        let issuer = service.token_issuer(registry);

        issuer.issue(guard.identity())?;
        assert!(matches!(
            issuer.issue(guard.identity()),
            Err(super::ObservationIssueError::CapacityReached)
        ));
        tokio::time::sleep(Duration::from_millis(40)).await;
        issuer.issue(guard.identity())?;
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_interrupts_the_authenticated_reply_send_boundary()
    -> Result<(), Box<dyn Error>> {
        let constrained = ObservationRuntimeLimits {
            test_send_delay: Duration::from_secs(60),
            ..limits()
        };
        let service = ObservationService::bind(loopback(1), loopback(1), constrained).await?;
        let primary = service.local_addrs()?.0;
        let (registry, guard) = active_client()?;
        let issuer = service.token_issuer(registry);
        let grant = issuer.issue(guard.identity())?;
        let primary_key = *grant.primary_token().as_bytes();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(service.run(shutdown.clone()));
        let client = UdpSocket::bind(loopback(1)).await?;
        client
            .send_to(
                &ObservationProbe::new(
                    grant.primary_token().clone(),
                    ObservationNonce::from([10; 16]),
                )
                .encode()?,
                primary,
            )
            .await?;
        timeout(Duration::from_secs(1), async {
            loop {
                if !issuer
                    .state
                    .lock()
                    .unwrap()
                    .pending
                    .contains_key(&primary_key)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;

        shutdown.cancel();
        timeout(Duration::from_millis(500), task).await???;
        Ok(())
    }

    #[test]
    fn saturated_bucket_table_keeps_fixed_memory_and_maintenance_work() {
        let capacity = 8;
        let interval = Duration::from_secs(1);
        let now = tokio::time::Instant::now();
        let mut table = BucketTable::<u32>::default();

        for key in 0..10_000 {
            let admission = table.allow(key, capacity, 1, interval, now);
            assert!(admission.allowed);
            assert!(
                admission.maintenance_steps <= MAX_BUCKET_MAINTENANCE_STEPS_PER_PACKET,
                "one admission performed {} maintenance steps",
                admission.maintenance_steps
            );
            assert!(table.len() <= capacity);
            assert!(table.queue_len() <= capacity);
        }
    }

    #[test]
    fn expired_bucket_cleanup_is_bounded_per_admission() {
        let capacity = 8;
        let interval = Duration::from_secs(1);
        let now = tokio::time::Instant::now();
        let mut table = BucketTable::<u32>::default();
        for key in 0..capacity as u32 {
            assert!(table.allow(key, capacity, 1, interval, now).allowed);
        }

        let later = now + Duration::from_secs(2);
        let admission = table.allow(99, capacity, 1, interval, later);
        assert!(admission.allowed);
        assert!(admission.maintenance_steps <= MAX_BUCKET_MAINTENANCE_STEPS_PER_PACKET);
        assert!(table.len() <= capacity);
        assert!(table.queue_len() <= capacity);
    }

    #[test]
    fn invalid_token_flood_is_globally_bounded_before_per_source_state() {
        let constrained = ObservationRuntimeLimits {
            max_tracked_ips: 8,
            per_ip_burst: 1,
            ..limits()
        };
        let state = std::sync::Mutex::new(super::ObservationState::default());
        let probe = ObservationProbe::new(
            rustgo_rendezvous::ObservationToken::from([0xEE; 32]),
            ObservationNonce::from([9; 16]),
        );

        for source in 1_u32..=10_000 {
            assert!(
                super::authorize_probe(
                    &state,
                    &constrained,
                    &probe,
                    ObservationEndpoint::Primary,
                    std::net::Ipv4Addr::from(source).into(),
                )
                .is_none()
            );
        }

        let state = state.into_inner().unwrap();
        assert_eq!(state.ip_buckets.len(), constrained.max_tracked_ips);
        assert!(state.ip_buckets.queue_len() <= constrained.max_tracked_ips);
        assert_eq!(state.global_ip_admission.remaining(), 0);
    }
}
