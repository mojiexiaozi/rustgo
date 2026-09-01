use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::mpsc;

use crate::{
    AuthenticatedClientIdentity, ClientSnapshot, HostMetrics, OverviewSnapshot, ServerSnapshot,
    SessionKind, SessionPath, SessionSnapshot, ShortSessionId, TrafficCounters,
};

pub const EVENT_QUEUE_CAPACITY: usize = 1024;
const MAX_INVENTORY_ITEMS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationEvent {
    ClientAuthenticated {
        client: AuthenticatedClientIdentity,
        version: String,
        authenticated_unix_millis: u64,
    },
    ClientDisconnected {
        client: AuthenticatedClientIdentity,
        disconnected_unix_millis: u64,
    },
    Heartbeat {
        client: AuthenticatedClientIdentity,
        received_unix_millis: u64,
    },
    ClientTelemetryAccepted {
        client: AuthenticatedClientIdentity,
        sequence: u64,
        received_unix_millis: u64,
        metrics: HostMetrics,
    },
    TunnelInventory {
        client: AuthenticatedClientIdentity,
        names: Vec<String>,
    },
    ExportInventory {
        client: AuthenticatedClientIdentity,
        names: Vec<String>,
    },
    ForwardInventory {
        client: AuthenticatedClientIdentity,
        names: Vec<String>,
    },
    TcpSessionOpened {
        client: AuthenticatedClientIdentity,
        session_id: ShortSessionId,
        tunnel: Option<String>,
        opened_unix_millis: u64,
    },
    TcpSessionClosed {
        client: AuthenticatedClientIdentity,
        session_id: ShortSessionId,
        closed_unix_millis: u64,
        terminal_reason: Option<String>,
    },
    UdpSessionOpened {
        client: AuthenticatedClientIdentity,
        session_id: ShortSessionId,
        tunnel: Option<String>,
        opened_unix_millis: u64,
    },
    UdpSessionClosed {
        client: AuthenticatedClientIdentity,
        session_id: ShortSessionId,
        closed_unix_millis: u64,
        terminal_reason: Option<String>,
    },
    P2pSessionOpened {
        client: AuthenticatedClientIdentity,
        session_id: ShortSessionId,
        peer: String,
        export: Option<String>,
        path: SessionPath,
        opened_unix_millis: u64,
    },
    P2pSessionClosed {
        client: AuthenticatedClientIdentity,
        session_id: ShortSessionId,
        closed_unix_millis: u64,
        terminal_reason: Option<String>,
    },
    ByteCounterDelta {
        client: AuthenticatedClientIdentity,
        session_id: Option<ShortSessionId>,
        counters: TrafficCounters,
    },
    ServerSample {
        metrics: HostMetrics,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishError {
    Full,
    Closed,
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => formatter.write_str("observability event queue is full"),
            Self::Closed => formatter.write_str("observability event queue is closed"),
        }
    }
}

impl std::error::Error for PublishError {}

#[derive(Default)]
struct QueueStats {
    depth: AtomicUsize,
    dropped: AtomicU64,
}

#[derive(Clone)]
pub struct ObservabilitySink {
    sender: mpsc::Sender<ObservationEvent>,
    stats: Arc<QueueStats>,
}

impl fmt::Debug for ObservabilitySink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservabilitySink")
            .field("capacity", &EVENT_QUEUE_CAPACITY)
            .field("remaining_capacity", &self.sender.capacity())
            .finish_non_exhaustive()
    }
}

impl ObservabilitySink {
    pub fn try_publish(&self, event: ObservationEvent) -> Result<(), PublishError> {
        self.stats.depth.fetch_add(1, Ordering::SeqCst);
        match self.sender.try_send(event) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.stats.depth.fetch_sub(1, Ordering::SeqCst);
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                match error {
                    mpsc::error::TrySendError::Full(_) => Err(PublishError::Full),
                    mpsc::error::TrySendError::Closed(_) => Err(PublishError::Closed),
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct ObservabilityStore {
    projection: Arc<RwLock<Projection>>,
    stats: Arc<QueueStats>,
}

impl fmt::Debug for ObservabilityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservabilityStore")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

pub struct ObservabilityWorker {
    receiver: mpsc::Receiver<ObservationEvent>,
    projection: Arc<RwLock<Projection>>,
    stats: Arc<QueueStats>,
}

impl fmt::Debug for ObservabilityWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservabilityWorker")
            .field("queue_capacity", &EVENT_QUEUE_CAPACITY)
            .finish_non_exhaustive()
    }
}

impl ObservabilityStore {
    pub fn new() -> (Self, ObservabilitySink, ObservabilityWorker) {
        let projection = Arc::new(RwLock::new(Projection::default()));
        let stats = Arc::new(QueueStats::default());
        let (sender, receiver) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        (
            Self {
                projection: Arc::clone(&projection),
                stats: Arc::clone(&stats),
            },
            ObservabilitySink {
                sender,
                stats: Arc::clone(&stats),
            },
            ObservabilityWorker {
                receiver,
                projection,
                stats,
            },
        )
    }

    pub fn snapshot(&self) -> OverviewSnapshot {
        let mut snapshot = self
            .projection
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot();
        snapshot.event_queue_depth = self.stats.depth.load(Ordering::SeqCst);
        snapshot.dropped_events = self.stats.dropped.load(Ordering::Relaxed);
        snapshot
    }
}

impl ObservabilityWorker {
    pub async fn run(mut self) {
        while let Some(event) = self.receiver.recv().await {
            self.stats.depth.fetch_sub(1, Ordering::SeqCst);
            self.projection
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .apply(event);
        }
    }
}

#[derive(Default)]
struct Projection {
    generated_unix_millis: u64,
    server_metrics: Option<HostMetrics>,
    server_traffic: TrafficCounters,
    clients: BTreeMap<String, ClientSnapshot>,
    sessions: BTreeMap<ShortSessionId, SessionSnapshot>,
}

impl Projection {
    fn apply(&mut self, event: ObservationEvent) {
        match event {
            ObservationEvent::ClientAuthenticated {
                client,
                version,
                authenticated_unix_millis,
            } => self.client_authenticated(client, version, authenticated_unix_millis),
            ObservationEvent::ClientDisconnected {
                client,
                disconnected_unix_millis,
            } => {
                let applied = if let Some(projected) = self.current_client_mut(&client) {
                    projected.online = false;
                    projected.disconnected_unix_millis = Some(disconnected_unix_millis);
                    true
                } else {
                    false
                };
                self.advance_if(applied, disconnected_unix_millis);
            }
            ObservationEvent::Heartbeat {
                client,
                received_unix_millis,
            } => {
                let applied = if let Some(projected) = self.online_client_mut(&client) {
                    projected.last_heartbeat_unix_millis = Some(received_unix_millis);
                    true
                } else {
                    false
                };
                self.advance_if(applied, received_unix_millis);
            }
            ObservationEvent::ClientTelemetryAccepted {
                client,
                sequence,
                received_unix_millis,
                metrics,
            } => {
                let applied = if let Some(projected) = self.online_client_mut(&client)
                    && projected
                        .telemetry_sequence
                        .is_none_or(|current| sequence > current)
                {
                    projected.telemetry_sequence = Some(sequence);
                    projected.telemetry_received_unix_millis = Some(received_unix_millis);
                    projected.metrics = Some(metrics);
                    true
                } else {
                    false
                };
                self.advance_if(applied, received_unix_millis);
            }
            ObservationEvent::TunnelInventory { client, names } => {
                if let Some(projected) = self.online_client_mut(&client) {
                    projected.tunnels = normalize_inventory(names);
                }
            }
            ObservationEvent::ExportInventory { client, names } => {
                if let Some(projected) = self.online_client_mut(&client) {
                    projected.exports = normalize_inventory(names);
                }
            }
            ObservationEvent::ForwardInventory { client, names } => {
                if let Some(projected) = self.online_client_mut(&client) {
                    projected.forwards = normalize_inventory(names);
                }
            }
            ObservationEvent::TcpSessionOpened {
                client,
                session_id,
                tunnel,
                opened_unix_millis,
            } => self.open_session(
                client,
                session_id,
                SessionKind::Tcp,
                SessionPath::Relay,
                None,
                tunnel,
                None,
                opened_unix_millis,
            ),
            ObservationEvent::TcpSessionClosed {
                client,
                session_id,
                closed_unix_millis,
                terminal_reason,
            } => self.close_session(
                &client,
                &session_id,
                SessionKind::Tcp,
                closed_unix_millis,
                terminal_reason,
            ),
            ObservationEvent::UdpSessionOpened {
                client,
                session_id,
                tunnel,
                opened_unix_millis,
            } => self.open_session(
                client,
                session_id,
                SessionKind::Udp,
                SessionPath::Relay,
                None,
                tunnel,
                None,
                opened_unix_millis,
            ),
            ObservationEvent::UdpSessionClosed {
                client,
                session_id,
                closed_unix_millis,
                terminal_reason,
            } => self.close_session(
                &client,
                &session_id,
                SessionKind::Udp,
                closed_unix_millis,
                terminal_reason,
            ),
            ObservationEvent::P2pSessionOpened {
                client,
                session_id,
                peer,
                export,
                path,
                opened_unix_millis,
            } => self.open_session(
                client,
                session_id,
                SessionKind::P2p,
                path,
                Some(peer),
                None,
                export,
                opened_unix_millis,
            ),
            ObservationEvent::P2pSessionClosed {
                client,
                session_id,
                closed_unix_millis,
                terminal_reason,
            } => self.close_session(
                &client,
                &session_id,
                SessionKind::P2p,
                closed_unix_millis,
                terminal_reason,
            ),
            ObservationEvent::ByteCounterDelta {
                client,
                session_id,
                counters,
            } => self.add_counters(&client, session_id.as_ref(), counters),
            ObservationEvent::ServerSample { metrics } => {
                self.generated_unix_millis =
                    self.generated_unix_millis.max(metrics.sampled_unix_millis);
                self.server_metrics = Some(metrics);
            }
        }
    }

    fn client_authenticated(
        &mut self,
        client: AuthenticatedClientIdentity,
        version: String,
        authenticated_unix_millis: u64,
    ) {
        if self
            .clients
            .get(client.name())
            .is_some_and(|current| current.generation >= client.generation())
        {
            return;
        }

        let previous = self.clients.remove(client.name());
        let (traffic, reconnects) = if let Some(previous) = previous {
            for session in self.sessions.values_mut().filter(|session| {
                session.client == client.name() && session.closed_unix_millis.is_none()
            }) {
                session.closed_unix_millis = Some(authenticated_unix_millis);
                session.terminal_reason = Some("generation_replaced".to_owned());
            }
            (previous.traffic, previous.reconnects.saturating_add(1))
        } else {
            (TrafficCounters::default(), 0)
        };

        self.clients.insert(
            client.name().to_owned(),
            ClientSnapshot {
                name: client.name().to_owned(),
                generation: client.generation(),
                version,
                online: true,
                authenticated_unix_millis,
                disconnected_unix_millis: None,
                last_heartbeat_unix_millis: None,
                telemetry_received_unix_millis: None,
                telemetry_sequence: None,
                metrics: None,
                traffic,
                tunnels: Vec::new(),
                exports: Vec::new(),
                forwards: Vec::new(),
                reconnects,
            },
        );
        self.generated_unix_millis = self.generated_unix_millis.max(authenticated_unix_millis);
    }

    #[allow(clippy::too_many_arguments)]
    fn open_session(
        &mut self,
        client: AuthenticatedClientIdentity,
        session_id: ShortSessionId,
        kind: SessionKind,
        path: SessionPath,
        peer: Option<String>,
        tunnel: Option<String>,
        export: Option<String>,
        opened_unix_millis: u64,
    ) {
        if self.online_client_mut(&client).is_none() {
            return;
        }
        self.sessions.insert(
            session_id.clone(),
            SessionSnapshot {
                id: session_id,
                client: client.name().to_owned(),
                peer,
                tunnel,
                export,
                kind,
                path,
                traffic: TrafficCounters::default(),
                opened_unix_millis,
                closed_unix_millis: None,
                terminal_reason: None,
            },
        );
        self.generated_unix_millis = self.generated_unix_millis.max(opened_unix_millis);
    }

    fn close_session(
        &mut self,
        client: &AuthenticatedClientIdentity,
        session_id: &ShortSessionId,
        expected_kind: SessionKind,
        closed_unix_millis: u64,
        terminal_reason: Option<String>,
    ) {
        if !self.is_current_client(client) {
            return;
        }
        let applied = if let Some(session) = self.sessions.get_mut(session_id)
            && session.client == client.name()
            && session.kind == expected_kind
            && session.closed_unix_millis.is_none()
        {
            session.closed_unix_millis = Some(closed_unix_millis);
            session.terminal_reason = terminal_reason;
            true
        } else {
            false
        };
        self.advance_if(applied, closed_unix_millis);
    }

    fn add_counters(
        &mut self,
        client: &AuthenticatedClientIdentity,
        session_id: Option<&ShortSessionId>,
        counters: TrafficCounters,
    ) {
        let Some(projected) = self.online_client_mut(client) else {
            return;
        };
        projected.traffic.saturating_add(counters);
        self.server_traffic.saturating_add(counters);
        if let Some(session_id) = session_id
            && let Some(session) = self.sessions.get_mut(session_id)
            && session.client == client.name()
            && session.closed_unix_millis.is_none()
        {
            session.traffic.saturating_add(counters);
        }
    }

    fn current_client_mut(
        &mut self,
        client: &AuthenticatedClientIdentity,
    ) -> Option<&mut ClientSnapshot> {
        self.clients
            .get_mut(client.name())
            .filter(|current| current.generation == client.generation())
    }

    fn online_client_mut(
        &mut self,
        client: &AuthenticatedClientIdentity,
    ) -> Option<&mut ClientSnapshot> {
        self.current_client_mut(client)
            .filter(|current| current.online)
    }

    fn is_current_client(&self, client: &AuthenticatedClientIdentity) -> bool {
        self.clients
            .get(client.name())
            .is_some_and(|current| current.generation == client.generation())
    }

    fn advance_if(&mut self, applied: bool, timestamp_unix_millis: u64) {
        if applied {
            self.generated_unix_millis = self.generated_unix_millis.max(timestamp_unix_millis);
        }
    }

    fn snapshot(&self) -> OverviewSnapshot {
        let clients = self.clients.values().cloned().collect::<Vec<_>>();
        let sessions = self.sessions.values().cloned().collect::<Vec<_>>();
        let online_clients = clients.iter().filter(|client| client.online).count();
        let active_tcp_sessions = active_sessions(&sessions, SessionKind::Tcp);
        let active_udp_sessions = active_sessions(&sessions, SessionKind::Udp);
        let active_p2p_sessions = active_sessions(&sessions, SessionKind::P2p);
        OverviewSnapshot {
            generated_unix_millis: self.generated_unix_millis,
            server: ServerSnapshot {
                metrics: self.server_metrics.clone(),
                traffic: self.server_traffic,
                online_clients,
                active_tcp_sessions,
                active_udp_sessions,
                active_p2p_sessions,
            },
            clients,
            sessions,
            event_queue_depth: 0,
            dropped_events: 0,
        }
    }
}

fn normalize_inventory(mut names: Vec<String>) -> Vec<String> {
    names.sort_unstable();
    names.dedup();
    names.truncate(MAX_INVENTORY_ITEMS);
    names
}

fn active_sessions(sessions: &[SessionSnapshot], kind: SessionKind) -> usize {
    sessions
        .iter()
        .filter(|session| session.kind == kind && session.closed_unix_millis.is_none())
        .count()
}
