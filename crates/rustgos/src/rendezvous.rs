use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rustgo_config::AuthorizedClient;
use rustgo_protocol::{
    BoundedString, Message, PeerIdentityBinding, PeerIdentityLookup, ProtocolVersion, ServerNotice,
    TunnelProtocol,
};
use rustgo_rendezvous::{
    MAX_ERROR_DETAIL_BYTES, PeerRelayFlags, PeerRelayFrame, RendezvousEnvelope, RendezvousPayload,
    RendezvousPhase, RendezvousState, SessionId,
};
use thiserror::Error;
use tokio::sync::mpsc::error::TrySendError;

use crate::{
    AuthenticatedClient,
    registry::{ClientRegistry, ControlSessionGuard},
};

const EXPIRY_MAINTENANCE_BATCH: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RendezvousErrorCode(u16);

impl RendezvousErrorCode {
    pub const UNKNOWN_PEER: Self = Self(1);
    pub const PEER_DISABLED: Self = Self(2);
    pub const PEER_OFFLINE: Self = Self(3);
    pub const SELF_TARGET: Self = Self(4);
    pub const CAPACITY_REACHED: Self = Self(5);
    pub const DUPLICATE_SESSION: Self = Self(6);
    pub const IDENTITY_MISMATCH: Self = Self(7);
    pub const EXPIRED: Self = Self(8);
    pub const UNKNOWN_SESSION: Self = Self(9);
    pub const NOT_PARTICIPANT: Self = Self(10);
    pub const INVALID_STATE: Self = Self(11);
    pub const DELIVERY_UNAVAILABLE: Self = Self(12);
    pub const PEER_DISCONNECTED: Self = Self(13);
    pub const UNSUPPORTED_PEER_VERSION: Self = Self(14);
    pub const INVALID_EXPIRY: Self = Self(15);

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    const fn detail(self) -> &'static str {
        match self.0 {
            1 => "unknown peer",
            2 => "peer is disabled",
            3 => "peer is offline",
            4 => "cannot rendezvous with self",
            5 => "rendezvous capacity reached",
            6 => "duplicate rendezvous session",
            7 => "authenticated identity mismatch",
            8 => "rendezvous session expired",
            9 => "unknown rendezvous session",
            10 => "authenticated device is not a session participant",
            11 => "invalid rendezvous state",
            12 => "rendezvous delivery unavailable",
            13 => "peer control session disconnected",
            14 => "peer does not support rendezvous",
            15 => "rendezvous expiry is outside the server horizon",
            _ => "rendezvous rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("rendezvous operation rejected with code {code:?}")]
pub struct RendezvousCoordinatorError {
    code: RendezvousErrorCode,
}

impl RendezvousCoordinatorError {
    pub const fn code(self) -> RendezvousErrorCode {
        self.code
    }
}

impl From<RendezvousErrorCode> for RendezvousCoordinatorError {
    fn from(code: RendezvousErrorCode) -> Self {
        Self { code }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousSessionMetadata {
    session_id: SessionId,
    consumer: String,
    provider: String,
    export: String,
    protocol: Option<TunnelProtocol>,
    expires_unix_secs: u64,
}

impl RendezvousSessionMetadata {
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn consumer(&self) -> &str {
        &self.consumer
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn export(&self) -> &str {
        &self.export
    }

    pub const fn protocol(&self) -> Option<TunnelProtocol> {
        self.protocol
    }

    pub const fn expires_unix_secs(&self) -> u64 {
        self.expires_unix_secs
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RendezvousLimits {
    pub(crate) max_sessions: usize,
    pub(crate) max_sessions_per_device: usize,
    pub(crate) session_ttl: Duration,
}

#[derive(Clone)]
pub struct RendezvousCoordinator {
    registry: ClientRegistry,
    directory: Arc<HashMap<String, DirectoryEntry>>,
    limits: RendezvousLimits,
    state: Arc<Mutex<CoordinatorState>>,
}

struct DirectoryEntry {
    public_key: String,
    enabled: bool,
}

#[derive(Default)]
struct CoordinatorState {
    sessions: HashMap<SessionId, SessionRecord>,
    device_counts: HashMap<String, usize>,
    expiry: BinaryHeap<Reverse<ExpiryEntry>>,
}

enum SessionRecord {
    Active(Box<StoredSession>),
    Tombstone(SessionTombstone),
}

struct StoredSession {
    metadata: RendezvousSessionMetadata,
    consumer: SessionOwner,
    provider: SessionOwner,
    state: RendezvousState,
    relay: RelayAdmission,
}

struct RelayAdmission {
    requested_by: u8,
    datagram: Option<bool>,
    window_started: Instant,
    frames_in_window: u32,
    bytes_in_window: usize,
}

impl RelayAdmission {
    fn new() -> Self {
        Self {
            requested_by: 0,
            datagram: None,
            window_started: Instant::now(),
            frames_in_window: 0,
            bytes_in_window: 0,
        }
    }

    fn authorized(&self) -> bool {
        self.requested_by == 0b11
    }

    fn admit(&mut self, bytes: usize) -> bool {
        const MAX_FRAMES_PER_SECOND: u32 = 256;
        const MAX_BYTES_PER_SECOND: usize = 4 * 1024 * 1024;
        if self.window_started.elapsed() >= Duration::from_secs(1) {
            self.window_started = Instant::now();
            self.frames_in_window = 0;
            self.bytes_in_window = 0;
        }
        let Some(next_bytes) = self.bytes_in_window.checked_add(bytes) else {
            return false;
        };
        if self.frames_in_window >= MAX_FRAMES_PER_SECOND || next_bytes > MAX_BYTES_PER_SECOND {
            return false;
        }
        self.frames_in_window += 1;
        self.bytes_in_window = next_bytes;
        true
    }
}

struct SessionTombstone {
    consumer: String,
    provider: String,
    expires_unix_secs: u64,
}

impl SessionTombstone {
    fn from_session(session: &StoredSession) -> Self {
        Self {
            consumer: session.consumer.name.clone(),
            provider: session.provider.name.clone(),
            expires_unix_secs: session.metadata.expires_unix_secs,
        }
    }
}

impl SessionRecord {
    fn active(&self) -> Option<&StoredSession> {
        match self {
            Self::Active(session) => Some(session),
            Self::Tombstone(_) => None,
        }
    }

    fn active_mut(&mut self) -> Option<&mut StoredSession> {
        match self {
            Self::Active(session) => Some(session),
            Self::Tombstone(_) => None,
        }
    }

    fn expires_unix_secs(&self) -> u64 {
        match self {
            Self::Active(session) => session.metadata.expires_unix_secs,
            Self::Tombstone(tombstone) => tombstone.expires_unix_secs,
        }
    }

    fn devices(&self) -> (&str, &str) {
        match self {
            Self::Active(session) => (&session.consumer.name, &session.provider.name),
            Self::Tombstone(tombstone) => (&tombstone.consumer, &tombstone.provider),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ExpiryEntry {
    expires_unix_secs: u64,
    session_id: SessionId,
}

impl Ord for ExpiryEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expires_unix_secs
            .cmp(&other.expires_unix_secs)
            .then_with(|| self.session_id.as_bytes().cmp(other.session_id.as_bytes()))
    }
}

impl PartialOrd for ExpiryEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SessionOwner {
    name: String,
    fingerprint: String,
    control_session_id: Vec<u8>,
}

impl SessionOwner {
    fn from_identity(identity: &AuthenticatedClient) -> Self {
        Self {
            name: identity.name().to_owned(),
            fingerprint: identity.fingerprint().to_owned(),
            control_session_id: identity.session_id().to_vec(),
        }
    }

    fn matches(&self, identity: &AuthenticatedClient) -> bool {
        self.name == identity.name()
            && self.fingerprint == identity.fingerprint()
            && self.control_session_id == identity.session_id()
    }
}

impl std::fmt::Debug for RendezvousCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RendezvousCoordinator")
            .field("registered_devices", &self.directory.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl RendezvousCoordinator {
    pub fn identity_binding(
        &self,
        authenticated: &ControlSessionGuard,
        lookup: PeerIdentityLookup,
    ) -> Result<Message, RendezvousCoordinatorError> {
        if !self.registry.is_active_session(authenticated.identity()) {
            return Err(RendezvousErrorCode::IDENTITY_MISMATCH.into());
        }
        let session_id = SessionId::from(lookup.session_id);
        let state = self
            .state
            .lock()
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        let session = state
            .sessions
            .get(&session_id)
            .and_then(SessionRecord::active)
            .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
        if session.metadata.expires_unix_secs <= now_unix_secs() {
            return Err(RendezvousErrorCode::EXPIRED.into());
        }
        let peer = other_participant(session, authenticated.identity(), lookup.peer.as_str())?;
        let directory = self
            .directory
            .get(&peer.name)
            .filter(|entry| entry.enabled)
            .ok_or(RendezvousErrorCode::UNKNOWN_PEER)?;
        Ok(Message::PeerIdentityBinding(PeerIdentityBinding {
            session_id: lookup.session_id,
            peer: BoundedString::try_from(peer.name.as_str())
                .map_err(|_| RendezvousErrorCode::INVALID_STATE)?,
            public_key: BoundedString::try_from(directory.public_key.as_str())
                .map_err(|_| RendezvousErrorCode::INVALID_STATE)?,
            protocol: session.metadata.protocol,
            peer_is_provider: session.provider == *peer,
            expires_unix_secs: session.metadata.expires_unix_secs,
        }))
    }
    /// Routes an already encrypted peer frame without inspecting its payload.
    /// The authenticated control identity, rather than any client supplied name,
    /// selects the opposite participant of the live rendezvous session.
    pub async fn forward_relay_frame(
        &self,
        authenticated: &ControlSessionGuard,
        frame: PeerRelayFrame,
    ) -> Result<(), RendezvousCoordinatorError> {
        if !self.registry.is_active_session(authenticated.identity()) {
            return Err(RendezvousErrorCode::IDENTITY_MISMATCH.into());
        }
        self.expire_sessions_batch(now_unix_secs());
        let (permit, message) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
            let session = state
                .sessions
                .get_mut(&frame.session_id)
                .and_then(SessionRecord::active_mut)
                .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
            if session.state.phase() != RendezvousPhase::Accepted {
                return Err(RendezvousErrorCode::INVALID_STATE.into());
            }
            let target = if session.consumer.matches(authenticated.identity()) {
                session.provider.clone()
            } else if session.provider.matches(authenticated.identity()) {
                session.consumer.clone()
            } else {
                return Err(RendezvousErrorCode::NOT_PARTICIPANT.into());
            };
            if !session.relay.authorized() {
                return Err(RendezvousErrorCode::INVALID_STATE.into());
            }
            let datagram = session
                .relay
                .datagram
                .ok_or(RendezvousErrorCode::INVALID_STATE)?;
            let flags = frame.flags.bits();
            let flags_match = if datagram {
                flags == PeerRelayFlags::DATAGRAM.bits()
            } else {
                flags == PeerRelayFlags::RELIABLE.bits()
                    || flags == (PeerRelayFlags::RELIABLE | PeerRelayFlags::FIN).bits()
            };
            if !flags_match || !session.relay.admit(frame.ciphertext().len()) {
                return Err(RendezvousErrorCode::CAPACITY_REACHED.into());
            }
            let permit = self.reserve_to(&target)?;
            let message = frame
                .to_protocol_message()
                .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
            (permit, message)
        };
        permit.send(message);
        Ok(())
    }
    pub(crate) fn new(
        registry: ClientRegistry,
        clients: &[AuthorizedClient],
        limits: RendezvousLimits,
    ) -> Self {
        let directory = clients
            .iter()
            .map(|client| {
                (
                    client.name.clone(),
                    DirectoryEntry {
                        public_key: client.public_key.clone(),
                        enabled: client.enabled,
                    },
                )
            })
            .collect();
        Self {
            registry,
            directory: Arc::new(directory),
            limits,
            state: Arc::new(Mutex::new(CoordinatorState::default())),
        }
    }

    pub fn session(&self, session_id: SessionId) -> Option<RendezvousSessionMetadata> {
        self.state
            .lock()
            .ok()?
            .sessions
            .get(&session_id)
            .and_then(SessionRecord::active)
            .filter(|session| session.metadata.expires_unix_secs > now_unix_secs())
            .map(|session| session.metadata.clone())
    }

    pub(crate) fn expire_now(&self) {
        self.expire_sessions_batch(now_unix_secs());
    }

    pub async fn request(
        &self,
        authenticated: &ControlSessionGuard,
        envelope: RendezvousEnvelope,
    ) -> Result<SessionId, RendezvousCoordinatorError> {
        self.validate_origin(authenticated, &envelope)?;
        let RendezvousPayload::Request(request) = &envelope.payload else {
            return Err(RendezvousErrorCode::INVALID_STATE.into());
        };
        if envelope.target.as_str() == authenticated.identity().name() {
            return Err(RendezvousErrorCode::SELF_TARGET.into());
        }
        match self.directory.get(envelope.target.as_str()) {
            None => return Err(RendezvousErrorCode::UNKNOWN_PEER.into()),
            Some(entry) if !entry.enabled => return Err(RendezvousErrorCode::PEER_DISABLED.into()),
            Some(_) => {}
        }
        let provider = self
            .registry
            .active_control_session(envelope.target.as_str())
            .ok_or(RendezvousErrorCode::PEER_OFFLINE)?;
        if !supports_v02(provider.protocol_version()) {
            return Err(RendezvousErrorCode::UNSUPPORTED_PEER_VERSION.into());
        }
        let now = now_unix_secs();
        if envelope.expires_unix_secs <= now {
            return Err(RendezvousErrorCode::EXPIRED.into());
        }
        let max_expiry = now
            .checked_add(self.limits.session_ttl.as_secs())
            .ok_or(RendezvousErrorCode::INVALID_EXPIRY)?;
        if envelope.expires_unix_secs > max_expiry {
            return Err(RendezvousErrorCode::INVALID_EXPIRY.into());
        }
        let authoritative_expiry = envelope.expires_unix_secs;
        let mut rendezvous_state = RendezvousState::new(envelope.session_id);
        rendezvous_state
            .request(envelope.step, envelope.generation)
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        let consumer_owner = SessionOwner::from_identity(authenticated.identity());
        let provider_owner = SessionOwner::from_identity(provider.identity());
        let message = envelope
            .to_protocol_message()
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RendezvousErrorCode::DELIVERY_UNAVAILABLE)?;
        if state.sessions.contains_key(&envelope.session_id) {
            return Err(RendezvousErrorCode::DUPLICATE_SESSION.into());
        }
        if state.sessions.len() >= self.limits.max_sessions
            || state
                .device_counts
                .get(&consumer_owner.name)
                .copied()
                .unwrap_or(0)
                >= self.limits.max_sessions_per_device
            || state
                .device_counts
                .get(&provider_owner.name)
                .copied()
                .unwrap_or(0)
                >= self.limits.max_sessions_per_device
        {
            return Err(RendezvousErrorCode::CAPACITY_REACHED.into());
        }
        let permit = self.reserve_to(&provider_owner)?;
        increment_device_count(&mut state.device_counts, &consumer_owner.name);
        increment_device_count(&mut state.device_counts, &provider_owner.name);
        state.expiry.push(Reverse(ExpiryEntry {
            expires_unix_secs: authoritative_expiry,
            session_id: envelope.session_id,
        }));
        state.sessions.insert(
            envelope.session_id,
            SessionRecord::Active(Box::new(StoredSession {
                metadata: RendezvousSessionMetadata {
                    session_id: envelope.session_id,
                    consumer: consumer_owner.name.clone(),
                    provider: provider_owner.name.clone(),
                    export: request.export.as_str().to_owned(),
                    protocol: None,
                    expires_unix_secs: authoritative_expiry,
                },
                consumer: consumer_owner,
                provider: provider_owner,
                state: rendezvous_state,
                relay: RelayAdmission::new(),
            })),
        );
        drop(state);
        permit.send(message);
        Ok(envelope.session_id)
    }

    pub async fn provider_decision(
        &self,
        authenticated: &ControlSessionGuard,
        envelope: RendezvousEnvelope,
    ) -> Result<(), RendezvousCoordinatorError> {
        self.validate_origin(authenticated, &envelope)?;
        let RendezvousPayload::ProviderDecision(decision) = &envelope.payload else {
            return Err(RendezvousErrorCode::INVALID_STATE.into());
        };
        let message = envelope
            .to_protocol_message()
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RendezvousErrorCode::DELIVERY_UNAVAILABLE)?;
        let (consumer, next_session_state) = {
            let record = state
                .sessions
                .get(&envelope.session_id)
                .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
            let session = record
                .active()
                .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
            if session.metadata.expires_unix_secs <= now_unix_secs() {
                return Err(RendezvousErrorCode::EXPIRED.into());
            }
            if !session.provider.matches(authenticated.identity()) {
                return Err(RendezvousErrorCode::NOT_PARTICIPANT.into());
            }
            if envelope.target.as_str() != session.consumer.name {
                return Err(RendezvousErrorCode::IDENTITY_MISMATCH.into());
            }
            let mut next = session.state.clone();
            next.provider_decision(envelope.step, envelope.generation, decision.is_accepted())
                .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
            (session.consumer.clone(), next)
        };
        let permit = self.reserve_to(&consumer)?;
        let session = state
            .sessions
            .get_mut(&envelope.session_id)
            .and_then(SessionRecord::active_mut)
            .expect("coordinator lock serializes the validated session");
        session.state = next_session_state;
        if decision.is_accepted() {
            session.metadata.protocol = decision.protocol();
        }
        if !decision.is_accepted() {
            tombstone_session(&mut state, envelope.session_id);
        }
        drop(state);
        permit.send(message);
        Ok(())
    }

    pub async fn forward_envelope(
        &self,
        authenticated: &ControlSessionGuard,
        envelope: RendezvousEnvelope,
    ) -> Result<(), RendezvousCoordinatorError> {
        self.validate_origin(authenticated, &envelope)?;
        if matches!(
            envelope.payload,
            RendezvousPayload::Request(_)
                | RendezvousPayload::ProviderDecision(_)
                | RendezvousPayload::Close(_)
                | RendezvousPayload::Error(_)
        ) {
            return Err(RendezvousErrorCode::INVALID_STATE.into());
        }
        let message = envelope
            .to_protocol_message()
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RendezvousErrorCode::DELIVERY_UNAVAILABLE)?;
        let (target, next_session_state, relay_update) = {
            let record = state
                .sessions
                .get(&envelope.session_id)
                .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
            let session = record
                .active()
                .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
            if session.metadata.expires_unix_secs <= now_unix_secs() {
                return Err(RendezvousErrorCode::EXPIRED.into());
            }
            if session.metadata.protocol.is_none() {
                return Err(RendezvousErrorCode::INVALID_STATE.into());
            }
            let target =
                other_participant(session, authenticated.identity(), envelope.target.as_str())?
                    .clone();
            let mut next = session.state.clone();
            next.accept_metadata(
                &envelope.session_id,
                envelope.step,
                envelope.generation,
                envelope.expires_unix_secs,
                now_unix_secs(),
            )
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
            let relay_update = if let RendezvousPayload::RelayRequest(request) = &envelope.payload {
                let expected_datagram = session.metadata.protocol == Some(TunnelProtocol::UDP);
                if request.datagram != expected_datagram {
                    return Err(RendezvousErrorCode::INVALID_STATE.into());
                }
                let participant = if session.consumer.matches(authenticated.identity()) {
                    0b01
                } else {
                    0b10
                };
                if session
                    .relay
                    .datagram
                    .is_some_and(|value| value != request.datagram)
                {
                    return Err(RendezvousErrorCode::INVALID_STATE.into());
                }
                Some((participant, request.datagram))
            } else {
                None
            };
            (target, next, relay_update)
        };
        let permit = self.reserve_to(&target)?;
        let session = state
            .sessions
            .get_mut(&envelope.session_id)
            .and_then(SessionRecord::active_mut)
            .expect("coordinator lock serializes the validated session");
        session.state = next_session_state;
        if let Some((participant, datagram)) = relay_update {
            session.relay.requested_by |= participant;
            session.relay.datagram = Some(datagram);
        }
        drop(state);
        permit.send(message);
        Ok(())
    }

    pub async fn close_session(
        &self,
        authenticated: &ControlSessionGuard,
        envelope: RendezvousEnvelope,
    ) -> Result<(), RendezvousCoordinatorError> {
        self.validate_origin(authenticated, &envelope)?;
        if !matches!(
            envelope.payload,
            RendezvousPayload::Close(_) | RendezvousPayload::Error(_)
        ) {
            return Err(RendezvousErrorCode::INVALID_STATE.into());
        }
        let message = envelope
            .to_protocol_message()
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RendezvousErrorCode::DELIVERY_UNAVAILABLE)?;
        let (target, next_session_state) = {
            let record = state
                .sessions
                .get(&envelope.session_id)
                .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
            let session = record
                .active()
                .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
            if session.metadata.expires_unix_secs <= now_unix_secs() {
                return Err(RendezvousErrorCode::EXPIRED.into());
            }
            let target =
                other_participant(session, authenticated.identity(), envelope.target.as_str())?
                    .clone();
            let mut next = session.state.clone();
            next.accept_metadata(
                &envelope.session_id,
                envelope.step,
                envelope.generation,
                envelope.expires_unix_secs,
                now_unix_secs(),
            )
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
            (target, next)
        };
        let permit = self.reserve_to(&target)?;
        state
            .sessions
            .get_mut(&envelope.session_id)
            .and_then(SessionRecord::active_mut)
            .expect("coordinator lock serializes the validated session")
            .state = next_session_state;
        tombstone_session(&mut state, envelope.session_id);
        drop(state);
        permit.send(message);
        Ok(())
    }

    pub async fn remove_device(&self, authenticated: &AuthenticatedClient) {
        let owner = SessionOwner::from_identity(authenticated);
        let removed = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            let owned: Vec<_> = state
                .sessions
                .iter()
                .filter_map(|(session_id, record)| {
                    record.active().and_then(|session| {
                        (session.consumer == owner || session.provider == owner)
                            .then_some(*session_id)
                    })
                })
                .collect();
            owned
                .into_iter()
                .filter_map(|session_id| tombstone_session(&mut state, session_id))
                .collect::<Vec<_>>()
        };
        for session in removed {
            let survivor = if session.consumer == owner {
                session.provider.clone()
            } else {
                session.consumer.clone()
            };
            self.send_server_notice(&session, &survivor, RendezvousErrorCode::PEER_DISCONNECTED);
        }
    }

    pub(crate) fn error_response(
        &self,
        request: &RendezvousEnvelope,
        error: RendezvousCoordinatorError,
    ) -> Message {
        server_notice(
            request.session_id,
            error.code,
            Some(request.target.as_str()),
        )
    }

    fn validate_origin(
        &self,
        authenticated: &ControlSessionGuard,
        envelope: &RendezvousEnvelope,
    ) -> Result<(), RendezvousCoordinatorError> {
        if !self.registry.is_active_session(authenticated.identity())
            || envelope.sender.as_str() != authenticated.identity().name()
            || envelope.version != authenticated.protocol_version()
        {
            return Err(RendezvousErrorCode::IDENTITY_MISMATCH.into());
        }
        if !supports_v02(envelope.version) {
            return Err(RendezvousErrorCode::UNSUPPORTED_PEER_VERSION.into());
        }
        if envelope.expires_unix_secs <= now_unix_secs() {
            return Err(RendezvousErrorCode::EXPIRED.into());
        }
        Ok(())
    }

    fn route_to(
        &self,
        owner: &SessionOwner,
        message: Message,
    ) -> Result<(), RendezvousCoordinatorError> {
        let active = self
            .registry
            .active_control_session(&owner.name)
            .ok_or(RendezvousErrorCode::PEER_OFFLINE)?;
        if !owner.matches(active.identity()) {
            return Err(RendezvousErrorCode::PEER_OFFLINE.into());
        }
        active
            .outbound()
            .try_send(message)
            .map_err(map_delivery_error)
    }

    fn reserve_to(
        &self,
        owner: &SessionOwner,
    ) -> Result<tokio::sync::mpsc::OwnedPermit<Message>, RendezvousCoordinatorError> {
        let active = self
            .registry
            .active_control_session(&owner.name)
            .ok_or(RendezvousErrorCode::PEER_OFFLINE)?;
        if !owner.matches(active.identity()) {
            return Err(RendezvousErrorCode::PEER_OFFLINE.into());
        }
        active
            .outbound()
            .clone()
            .try_reserve_owned()
            .map_err(map_delivery_error)
    }

    fn expire_sessions_batch(&self, now: u64) {
        let removed = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            let mut active = Vec::new();
            for _ in 0..EXPIRY_MAINTENANCE_BATCH {
                let Some(Reverse(next)) = state.expiry.peek().copied() else {
                    break;
                };
                if next.expires_unix_secs > now {
                    break;
                }
                state.expiry.pop();
                let matches_expiry = state
                    .sessions
                    .get(&next.session_id)
                    .is_some_and(|record| record.expires_unix_secs() == next.expires_unix_secs);
                if matches_expiry && let Some(record) = state.sessions.remove(&next.session_id) {
                    decrement_record_counts(&mut state.device_counts, &record);
                    if let SessionRecord::Active(session) = record {
                        active.push(*session);
                    }
                }
            }
            active
        };
        for session in removed {
            self.send_server_notice(&session, &session.consumer, RendezvousErrorCode::EXPIRED);
            self.send_server_notice(&session, &session.provider, RendezvousErrorCode::EXPIRED);
        }
    }

    fn send_server_notice(
        &self,
        session: &StoredSession,
        target: &SessionOwner,
        code: RendezvousErrorCode,
    ) {
        let message = server_notice(
            session.metadata.session_id,
            code,
            Some(if session.consumer == *target {
                &session.provider.name
            } else {
                &session.consumer.name
            }),
        );
        let _ = self.route_to(target, message);
    }
}

fn other_participant<'a>(
    session: &'a StoredSession,
    authenticated: &AuthenticatedClient,
    claimed_target: &str,
) -> Result<&'a SessionOwner, RendezvousCoordinatorError> {
    let target = if session.consumer.matches(authenticated) {
        &session.provider
    } else if session.provider.matches(authenticated) {
        &session.consumer
    } else {
        return Err(RendezvousErrorCode::NOT_PARTICIPANT.into());
    };
    if target.name != claimed_target {
        return Err(RendezvousErrorCode::IDENTITY_MISMATCH.into());
    }
    Ok(target)
}

fn tombstone_session(state: &mut CoordinatorState, session_id: SessionId) -> Option<StoredSession> {
    let record = state.sessions.remove(&session_id)?;
    match record {
        SessionRecord::Active(session) => {
            let session = *session;
            state.sessions.insert(
                session_id,
                SessionRecord::Tombstone(SessionTombstone::from_session(&session)),
            );
            Some(session)
        }
        SessionRecord::Tombstone(tombstone) => {
            state
                .sessions
                .insert(session_id, SessionRecord::Tombstone(tombstone));
            None
        }
    }
}

fn increment_device_count(counts: &mut HashMap<String, usize>, device: &str) {
    *counts.entry(device.to_owned()).or_insert(0) += 1;
}

fn decrement_record_counts(counts: &mut HashMap<String, usize>, record: &SessionRecord) {
    let (consumer, provider) = record.devices();
    for device in [consumer, provider] {
        if let Some(count) = counts.get_mut(device) {
            *count -= 1;
            if *count == 0 {
                counts.remove(device);
            }
        }
    }
}

fn supports_v02(version: ProtocolVersion) -> bool {
    version.major == ProtocolVersion::V0_2.major && version.minor >= ProtocolVersion::V0_2.minor
}

fn map_delivery_error<T>(error: TrySendError<T>) -> RendezvousCoordinatorError {
    match error {
        TrySendError::Closed(_) | TrySendError::Full(_) => {
            RendezvousErrorCode::DELIVERY_UNAVAILABLE.into()
        }
    }
}

fn server_notice(session_id: SessionId, code: RendezvousErrorCode, peer: Option<&str>) -> Message {
    Message::ServerNotice(ServerNotice {
        session_id: *session_id.as_bytes(),
        code: code.as_u16(),
        detail: BoundedString::<MAX_ERROR_DETAIL_BYTES>::try_from(code.detail())
            .expect("static rendezvous error detail is bounded"),
        peer: peer.map(|name| {
            BoundedString::try_from(name).expect("authenticated device names are bounded")
        }),
    })
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use rustgo_config::AuthorizedClient;
    use rustgo_protocol::{
        BoundedBytes, BoundedString, Heartbeat, Message, ProtocolVersion, TunnelProtocol,
    };
    use rustgo_rendezvous::{
        CandidateGeneration, ConnectivityResult, ProviderDecision, RendezvousClose,
        RendezvousEnvelope, RendezvousPayload, RendezvousRequest, SessionId,
    };
    use tokio::sync::{Barrier, mpsc};

    use super::{RendezvousCoordinator, RendezvousErrorCode, RendezvousLimits, now_unix_secs};
    use crate::{AuthenticatedClient, ClientRegistry, ControlSessionGuard};

    fn test_registry() -> ClientRegistry {
        ClientRegistry::new(8, 1, Ipv4Addr::LOCALHOST.into(), 8, Duration::from_secs(30)).unwrap()
    }

    fn identity(name: &str, marker: u8) -> AuthenticatedClient {
        AuthenticatedClient::verified(
            name.to_owned(),
            format!("fingerprint-{marker}"),
            vec![marker; 32],
        )
    }

    fn claim(
        registry: &ClientRegistry,
        name: &str,
        marker: u8,
        capacity: usize,
    ) -> (
        ControlSessionGuard,
        mpsc::Sender<Message>,
        mpsc::Receiver<Message>,
    ) {
        let (outbound, receiver) = mpsc::channel(capacity);
        let guard = registry
            .claim_with_outbound(
                identity(name, marker),
                outbound.clone(),
                ProtocolVersion::V0_2,
            )
            .unwrap();
        (guard, outbound, receiver)
    }

    fn test_coordinator(registry: ClientRegistry) -> RendezvousCoordinator {
        let clients = ["a", "b", "c"]
            .into_iter()
            .map(|name| AuthorizedClient {
                name: name.to_owned(),
                public_key: "unused-by-coordinator".to_owned(),
                enabled: true,
            })
            .collect::<Vec<_>>();
        RendezvousCoordinator::new(
            registry,
            &clients,
            RendezvousLimits {
                max_sessions: 8,
                max_sessions_per_device: 8,
                session_ttl: Duration::from_secs(60),
            },
        )
    }

    fn request(session: u8, sender: &str, target: &str) -> RendezvousEnvelope {
        envelope(
            session,
            sender,
            target,
            1,
            RendezvousPayload::Request(RendezvousRequest {
                export: BoundedString::try_from("ssh").unwrap(),
            }),
        )
    }

    fn envelope(
        session: u8,
        sender: &str,
        target: &str,
        step: u64,
        payload: RendezvousPayload,
    ) -> RendezvousEnvelope {
        RendezvousEnvelope {
            version: ProtocolVersion::V0_2,
            session_id: SessionId::from([session; 32]),
            sender: BoundedString::try_from(sender).unwrap(),
            target: BoundedString::try_from(target).unwrap(),
            step,
            generation: CandidateGeneration::INITIAL,
            expires_unix_secs: now_unix_secs() + 30,
            payload,
            signature: BoundedBytes::try_from([marker_for(session); 64].as_slice()).unwrap(),
        }
    }

    const fn marker_for(session: u8) -> u8 {
        session.wrapping_add(1)
    }

    #[tokio::test]
    async fn unavailable_generation_blocks_racing_admission_before_exact_cleanup() {
        let registry = test_registry();
        let coordinator = test_coordinator(registry.clone());
        let (mut a, _a_sender, mut a_outbound) = claim(&registry, "a", 1, 4);
        let (b, _b_sender, _b_outbound) = claim(&registry, "b", 2, 4);
        let (c, _c_sender, _c_outbound) = claim(&registry, "c", 3, 4);
        coordinator.request(&b, request(1, "b", "a")).await.unwrap();
        assert!(a_outbound.recv().await.is_some());

        let identity = a.identity().clone();
        let start = Arc::new(Barrier::new(2));
        let racing = tokio::spawn({
            let coordinator = coordinator.clone();
            let start = start.clone();
            async move {
                start.wait().await;
                coordinator.request(&c, request(2, "c", "a")).await
            }
        });
        a.mark_unavailable();
        start.wait().await;
        coordinator.remove_device(&identity).await;

        let error = racing.await.unwrap().unwrap_err();
        assert_eq!(error.code(), RendezvousErrorCode::PEER_OFFLINE);
        assert!(coordinator.session(SessionId::from([1; 32])).is_none());
        assert!(coordinator.session(SessionId::from([2; 32])).is_none());
    }

    #[tokio::test]
    async fn saturated_routes_leave_decision_forward_and_close_retryable() {
        let registry = test_registry();
        let coordinator = test_coordinator(registry.clone());
        let (a, a_sender, mut a_outbound) = claim(&registry, "a", 11, 1);
        let (b, b_sender, mut b_outbound) = claim(&registry, "b", 12, 1);
        coordinator
            .request(&a, request(10, "a", "b"))
            .await
            .unwrap();
        assert!(b_outbound.recv().await.is_some());

        a_sender
            .try_send(Message::Heartbeat(Heartbeat { sequence: 1 }))
            .unwrap();
        let decision = envelope(
            10,
            "b",
            "a",
            2,
            RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
        );
        assert_eq!(
            coordinator
                .provider_decision(&b, decision.clone())
                .await
                .unwrap_err()
                .code(),
            RendezvousErrorCode::DELIVERY_UNAVAILABLE
        );
        assert_eq!(
            a_outbound.recv().await,
            Some(Message::Heartbeat(Heartbeat { sequence: 1 }))
        );
        coordinator
            .provider_decision(&b, decision)
            .await
            .expect("decision remains retryable after queue capacity returns");
        assert!(a_outbound.recv().await.is_some());

        b_sender
            .try_send(Message::Heartbeat(Heartbeat { sequence: 2 }))
            .unwrap();
        let forwarded = envelope(
            10,
            "a",
            "b",
            3,
            RendezvousPayload::ConnectivityResult(ConnectivityResult {
                connected: false,
                transport: None,
                detail: None,
            }),
        );
        assert_eq!(
            coordinator
                .forward_envelope(&a, forwarded.clone())
                .await
                .unwrap_err()
                .code(),
            RendezvousErrorCode::DELIVERY_UNAVAILABLE
        );
        assert_eq!(
            b_outbound.recv().await,
            Some(Message::Heartbeat(Heartbeat { sequence: 2 }))
        );
        coordinator
            .forward_envelope(&a, forwarded)
            .await
            .expect("forward remains retryable after queue capacity returns");
        assert!(b_outbound.recv().await.is_some());

        a_sender
            .try_send(Message::Heartbeat(Heartbeat { sequence: 3 }))
            .unwrap();
        let close = envelope(
            10,
            "b",
            "a",
            4,
            RendezvousPayload::Close(RendezvousClose { detail: None }),
        );
        assert_eq!(
            coordinator
                .close_session(&b, close.clone())
                .await
                .unwrap_err()
                .code(),
            RendezvousErrorCode::DELIVERY_UNAVAILABLE
        );
        assert_eq!(
            a_outbound.recv().await,
            Some(Message::Heartbeat(Heartbeat { sequence: 3 }))
        );
        coordinator
            .close_session(&b, close)
            .await
            .expect("close remains retryable after queue capacity returns");
        assert!(a_outbound.recv().await.is_some());
        assert!(coordinator.session(SessionId::from([10; 32])).is_none());
    }

    #[tokio::test]
    async fn closed_routes_leave_decision_forward_and_close_state_unchanged() {
        let registry = test_registry();
        let coordinator = test_coordinator(registry.clone());
        let (a, _a_sender, a_outbound) = claim(&registry, "a", 21, 1);
        let (b, _b_sender, mut b_outbound) = claim(&registry, "b", 22, 1);
        coordinator
            .request(&a, request(20, "a", "b"))
            .await
            .unwrap();
        assert!(b_outbound.recv().await.is_some());
        drop(a_outbound);
        let decision = envelope(
            20,
            "b",
            "a",
            2,
            RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
        );
        for _ in 0..2 {
            assert_eq!(
                coordinator
                    .provider_decision(&b, decision.clone())
                    .await
                    .unwrap_err()
                    .code(),
                RendezvousErrorCode::DELIVERY_UNAVAILABLE
            );
        }

        let registry = test_registry();
        let coordinator = test_coordinator(registry.clone());
        let (a, _a_sender, mut a_outbound) = claim(&registry, "a", 31, 1);
        let (b, _b_sender, mut b_outbound) = claim(&registry, "b", 32, 1);
        coordinator
            .request(&a, request(30, "a", "b"))
            .await
            .unwrap();
        assert!(b_outbound.recv().await.is_some());
        coordinator
            .provider_decision(
                &b,
                envelope(
                    30,
                    "b",
                    "a",
                    2,
                    RendezvousPayload::ProviderDecision(ProviderDecision::accepted(
                        TunnelProtocol::TCP,
                    )),
                ),
            )
            .await
            .unwrap();
        assert!(a_outbound.recv().await.is_some());
        drop(b_outbound);
        let forwarded = envelope(
            30,
            "a",
            "b",
            3,
            RendezvousPayload::ConnectivityResult(ConnectivityResult {
                connected: false,
                transport: None,
                detail: None,
            }),
        );
        for _ in 0..2 {
            assert_eq!(
                coordinator
                    .forward_envelope(&a, forwarded.clone())
                    .await
                    .unwrap_err()
                    .code(),
                RendezvousErrorCode::DELIVERY_UNAVAILABLE
            );
        }

        let registry = test_registry();
        let coordinator = test_coordinator(registry.clone());
        let (a, _a_sender, mut a_outbound) = claim(&registry, "a", 41, 1);
        let (b, _b_sender, mut b_outbound) = claim(&registry, "b", 42, 1);
        coordinator
            .request(&a, request(40, "a", "b"))
            .await
            .unwrap();
        assert!(b_outbound.recv().await.is_some());
        coordinator
            .provider_decision(
                &b,
                envelope(
                    40,
                    "b",
                    "a",
                    2,
                    RendezvousPayload::ProviderDecision(ProviderDecision::accepted(
                        TunnelProtocol::TCP,
                    )),
                ),
            )
            .await
            .unwrap();
        assert!(a_outbound.recv().await.is_some());
        drop(a_outbound);
        let close = envelope(
            40,
            "b",
            "a",
            3,
            RendezvousPayload::Close(RendezvousClose { detail: None }),
        );
        for _ in 0..2 {
            assert_eq!(
                coordinator
                    .close_session(&b, close.clone())
                    .await
                    .unwrap_err()
                    .code(),
                RendezvousErrorCode::DELIVERY_UNAVAILABLE
            );
        }
        assert!(coordinator.session(SessionId::from([40; 32])).is_some());
    }
}
