use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustgo_config::AuthorizedClient;
use rustgo_protocol::{BoundedBytes, BoundedString, Message, ProtocolVersion, TunnelProtocol};
use rustgo_rendezvous::{
    CandidateGeneration, MAX_DEVICE_NAME_BYTES, MAX_ERROR_DETAIL_BYTES, RendezvousEnvelope,
    RendezvousError, RendezvousPayload, RendezvousState, SessionId,
};
use thiserror::Error;
use tokio::sync::mpsc::error::TrySendError;

use crate::{
    AuthenticatedClient,
    registry::{ClientRegistry, ControlSessionGuard},
};

const SERVER_EVENT_SENDER: &str = "rustgos";
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
    directory: Arc<HashMap<String, bool>>,
    limits: RendezvousLimits,
    state: Arc<Mutex<CoordinatorState>>,
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
    pub(crate) fn new(
        registry: ClientRegistry,
        clients: &[AuthorizedClient],
        limits: RendezvousLimits,
    ) -> Self {
        let directory = clients
            .iter()
            .map(|client| (client.name.clone(), client.enabled))
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
            Some(false) => return Err(RendezvousErrorCode::PEER_DISABLED.into()),
            Some(true) => {}
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
        let authoritative_expiry = envelope
            .expires_unix_secs
            .min(now.saturating_add(self.limits.session_ttl.as_secs()));
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
        provider
            .outbound()
            .try_send(message)
            .map_err(map_delivery_error)?;
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
            })),
        );
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
        let record = state
            .sessions
            .get_mut(&envelope.session_id)
            .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
        let session = record
            .active_mut()
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
        session
            .state
            .provider_decision(envelope.step, envelope.generation, decision.is_accepted())
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        let consumer = session.consumer.clone();
        if decision.is_accepted() {
            session.metadata.protocol = decision.protocol();
        }
        let delivery = self.route_to(&consumer, message);
        if !decision.is_accepted() {
            tombstone_session(&mut state, envelope.session_id);
        }
        delivery
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
        let record = state
            .sessions
            .get_mut(&envelope.session_id)
            .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
        let session = record
            .active_mut()
            .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
        if session.metadata.expires_unix_secs <= now_unix_secs() {
            return Err(RendezvousErrorCode::EXPIRED.into());
        }
        if session.metadata.protocol.is_none() {
            return Err(RendezvousErrorCode::INVALID_STATE.into());
        }
        let target =
            other_participant(session, authenticated.identity(), envelope.target.as_str())?.clone();
        session
            .state
            .accept_metadata(
                &envelope.session_id,
                envelope.step,
                envelope.generation,
                envelope.expires_unix_secs,
                now_unix_secs(),
            )
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        self.route_to(&target, message)
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
        let record = state
            .sessions
            .get_mut(&envelope.session_id)
            .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
        let session = record
            .active_mut()
            .ok_or(RendezvousErrorCode::UNKNOWN_SESSION)?;
        if session.metadata.expires_unix_secs <= now_unix_secs() {
            return Err(RendezvousErrorCode::EXPIRED.into());
        }
        let target =
            other_participant(session, authenticated.identity(), envelope.target.as_str())?.clone();
        session
            .state
            .accept_metadata(
                &envelope.session_id,
                envelope.step,
                envelope.generation,
                envelope.expires_unix_secs,
                now_unix_secs(),
            )
            .map_err(|_| RendezvousErrorCode::INVALID_STATE)?;
        let delivery = self.route_to(&target, message);
        tombstone_session(&mut state, envelope.session_id);
        delivery
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
        target: &str,
        error: RendezvousCoordinatorError,
    ) -> Message {
        server_notice(
            request.session_id,
            target,
            request.step,
            request.generation,
            request.expires_unix_secs,
            error.code,
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
            &target.name,
            session.state.last_step().saturating_add(1),
            session.state.generation(),
            session
                .metadata
                .expires_unix_secs
                .max(now_unix_secs().saturating_add(1)),
            code,
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

fn map_delivery_error(error: TrySendError<Message>) -> RendezvousCoordinatorError {
    match error {
        TrySendError::Closed(_) | TrySendError::Full(_) => {
            RendezvousErrorCode::DELIVERY_UNAVAILABLE.into()
        }
    }
}

fn server_notice(
    session_id: SessionId,
    target: &str,
    step: u64,
    generation: CandidateGeneration,
    expires_unix_secs: u64,
    code: RendezvousErrorCode,
) -> Message {
    RendezvousEnvelope {
        version: ProtocolVersion::V0_2,
        session_id,
        sender: BoundedString::<MAX_DEVICE_NAME_BYTES>::try_from(SERVER_EVENT_SENDER)
            .expect("server event sender is bounded"),
        target: BoundedString::<MAX_DEVICE_NAME_BYTES>::try_from(target)
            .expect("authenticated device names are bounded"),
        step,
        generation,
        expires_unix_secs,
        payload: RendezvousPayload::Error(RendezvousError {
            code: code.as_u16(),
            detail: BoundedString::<MAX_ERROR_DETAIL_BYTES>::try_from(code.detail())
                .expect("static rendezvous error detail is bounded"),
        }),
        signature: BoundedBytes::try_from(Vec::new()).expect("empty server signature is bounded"),
    }
    .to_protocol_message()
    .expect("bounded server notice is a valid rendezvous message")
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
