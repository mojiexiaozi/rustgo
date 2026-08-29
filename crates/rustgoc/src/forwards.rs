use std::{
    collections::HashMap, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

use rustgo_config::{ForwardConfig, TunnelProtocol};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UdpSocket},
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

const ABSOLUTE_MAX_TCP_SESSIONS: usize = 1024;
const ABSOLUTE_MAX_UDP_SOURCE_SESSIONS: usize = 1024;
const UDP_SOURCE_QUEUE_CAPACITY: usize = 64;
const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub struct ForwardRuntimeOptions {
    pub protocol_timeout: Duration,
    pub session_open_timeout: Duration,
    pub udp_source_idle_timeout: Duration,
    pub max_tcp_sessions: usize,
    pub max_udp_source_sessions: usize,
}

impl Default for ForwardRuntimeOptions {
    fn default() -> Self {
        Self {
            protocol_timeout: Duration::from_secs(10),
            session_open_timeout: Duration::from_secs(10),
            udp_source_idle_timeout: Duration::from_secs(60),
            max_tcp_sessions: 128,
            max_udp_source_sessions: 256,
        }
    }
}

impl ForwardRuntimeOptions {
    fn validate(self) -> Result<Self, ForwardError> {
        if self.protocol_timeout.is_zero()
            || self.session_open_timeout.is_zero()
            || self.udp_source_idle_timeout.is_zero()
            || !(1..=ABSOLUTE_MAX_TCP_SESSIONS).contains(&self.max_tcp_sessions)
            || !(1..=ABSOLUTE_MAX_UDP_SOURCE_SESSIONS).contains(&self.max_udp_source_sessions)
        {
            return Err(ForwardError::InvalidOptions);
        }
        Ok(self)
    }
}

pub trait PeerIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> PeerIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub type BoxPeerStream = Box<dyn PeerIo>;
pub type PeerFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;
pub type BoxPeerDatagramSession = Box<dyn PeerDatagramSession>;

pub trait PeerDatagramSession: Send {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> PeerFuture<'a, ()>;
    fn receive<'a>(&'a mut self) -> PeerFuture<'a, Vec<u8>>;
}

pub trait ForwardConnector: Send + Sync + 'static {
    fn protocol<'a>(&'a self, peer: &'a str, export: &'a str) -> PeerFuture<'a, TunnelProtocol>;
    fn open_tcp<'a>(
        &'a self,
        peer: &'a str,
        export: &'a str,
        cancellation: CancellationToken,
    ) -> PeerFuture<'a, BoxPeerStream>;
    fn open_udp<'a>(
        &'a self,
        peer: &'a str,
        export: &'a str,
        cancellation: CancellationToken,
    ) -> PeerFuture<'a, BoxPeerDatagramSession>;
}

#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("invalid forward runtime resource limits or timeouts")]
    InvalidOptions,
    #[error("duplicate forward name")]
    DuplicateForward,
    #[error("invalid forward listen address")]
    InvalidListenAddress,
    #[error("forward listener could not bind")]
    Bind,
    #[error("peer export protocol could not be resolved")]
    Protocol,
    #[error("forward startup was cancelled")]
    Cancelled,
    #[error("peer export protocol discovery timed out")]
    ProtocolTimeout,
}

pub struct ForwardRuntime {
    local_addrs: HashMap<String, SocketAddr>,
    shutdown: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl ForwardRuntime {
    pub async fn start(
        forwards: Vec<ForwardConfig>,
        connector: Arc<dyn ForwardConnector>,
        cancellation: CancellationToken,
    ) -> Result<Self, ForwardError> {
        Self::start_with_options(
            forwards,
            connector,
            cancellation,
            ForwardRuntimeOptions::default(),
        )
        .await
    }

    pub async fn start_with_options(
        forwards: Vec<ForwardConfig>,
        connector: Arc<dyn ForwardConnector>,
        cancellation: CancellationToken,
        options: ForwardRuntimeOptions,
    ) -> Result<Self, ForwardError> {
        let options = options.validate()?;
        let shutdown = cancellation.child_token();
        let mut prepared = Vec::with_capacity(forwards.len());
        let mut names = std::collections::HashSet::with_capacity(forwards.len());
        for forward in forwards {
            if !names.insert(forward.name.clone()) {
                return Err(ForwardError::DuplicateForward);
            }
            let listen_addr: SocketAddr = forward
                .listen_addr
                .parse()
                .map_err(|_| ForwardError::InvalidListenAddress)?;
            let discovery = connector.protocol(&forward.peer, &forward.export);
            let protocol = tokio::select! {
                biased;
                () = shutdown.cancelled() => return Err(ForwardError::Cancelled),
                result = tokio::time::timeout(options.protocol_timeout, discovery) => {
                    result.map_err(|_| ForwardError::ProtocolTimeout)?
                        .map_err(|_| ForwardError::Protocol)?
                }
            };
            prepared.push((forward, listen_addr, protocol));
        }
        let mut local_addrs = HashMap::with_capacity(prepared.len());
        let mut tasks = Vec::with_capacity(prepared.len());
        for (forward, listen_addr, protocol) in prepared {
            match protocol {
                TunnelProtocol::Tcp => {
                    let listener = match TcpListener::bind(listen_addr).await {
                        Ok(listener) => listener,
                        Err(_) => {
                            cancel_started(&shutdown, tasks).await;
                            return Err(ForwardError::Bind);
                        }
                    };
                    local_addrs.insert(
                        forward.name.clone(),
                        listener.local_addr().map_err(|_| ForwardError::Bind)?,
                    );
                    tasks.push(tokio::spawn(run_tcp_forward(
                        listener,
                        forward,
                        connector.clone(),
                        shutdown.child_token(),
                        options,
                    )));
                }
                TunnelProtocol::Udp => {
                    let socket = match UdpSocket::bind(listen_addr).await {
                        Ok(socket) => Arc::new(socket),
                        Err(_) => {
                            cancel_started(&shutdown, tasks).await;
                            return Err(ForwardError::Bind);
                        }
                    };
                    local_addrs.insert(
                        forward.name.clone(),
                        socket.local_addr().map_err(|_| ForwardError::Bind)?,
                    );
                    tasks.push(tokio::spawn(run_udp_forward(
                        socket,
                        forward,
                        connector.clone(),
                        shutdown.child_token(),
                        options,
                    )));
                }
            }
        }
        Ok(Self {
            local_addrs,
            shutdown,
            tasks,
        })
    }

    pub fn local_addr(&self, name: &str) -> Option<SocketAddr> {
        self.local_addrs.get(name).copied()
    }

    pub async fn shutdown(mut self) {
        self.shutdown.cancel();
        drain_tasks(&mut self.tasks).await;
    }
}

async fn cancel_started(shutdown: &CancellationToken, tasks: Vec<JoinHandle<()>>) {
    shutdown.cancel();
    let mut tasks = tasks;
    drain_tasks(&mut tasks).await;
}

async fn drain_tasks(tasks: &mut Vec<JoinHandle<()>>) {
    let deadline = tokio::time::Instant::now() + RUNTIME_SHUTDOWN_TIMEOUT;
    for mut task in tasks.drain(..) {
        if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for ForwardRuntime {
    fn drop(&mut self) {
        self.shutdown.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn run_tcp_forward(
    listener: TcpListener,
    forward: ForwardConfig,
    connector: Arc<dyn ForwardConnector>,
    cancellation: CancellationToken,
    options: ForwardRuntimeOptions,
) {
    let mut sessions = JoinSet::new();
    let permits = Arc::new(Semaphore::new(options.max_tcp_sessions));
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => { let _ = joined; }
            accepted = listener.accept() => {
                let Ok((mut local, _)) = accepted else { break; };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(local);
                    continue;
                };
                let connector = connector.clone();
                let peer = forward.peer.clone();
                let export = forward.export.clone();
                let child = cancellation.child_token();
                sessions.spawn(async move {
                    let _permit = permit;
                    let open = connector.open_tcp(&peer, &export, child.clone());
                    let opened = tokio::select! {
                        biased;
                        () = child.cancelled() => return,
                        result = tokio::time::timeout(options.session_open_timeout, open) => result,
                    };
                    let Ok(Ok(mut remote)) = opened else { return; };
                    tokio::select! {
                        biased;
                        () = child.cancelled() => {}
                        _ = tokio::io::copy_bidirectional(&mut local, &mut remote) => {}
                    }
                });
            }
        }
    }
    cancellation.cancel();
    while sessions.join_next().await.is_some() {}
}

async fn run_udp_forward(
    socket: Arc<UdpSocket>,
    forward: ForwardConfig,
    connector: Arc<dyn ForwardConnector>,
    cancellation: CancellationToken,
    options: ForwardRuntimeOptions,
) {
    struct SourceEntry {
        generation: u64,
        sender: mpsc::Sender<Vec<u8>>,
    }
    let mut sources: HashMap<SocketAddr, SourceEntry> = HashMap::new();
    let mut sessions = JoinSet::new();
    let (completed, mut completions) = mpsc::channel(options.max_udp_source_sessions);
    let mut next_generation = 1_u64;
    let mut buffer = vec![0_u8; MAX_UDP_DATAGRAM_BYTES];
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            completed_source = completions.recv(), if !sources.is_empty() => {
                if let Some((source, generation)) = completed_source
                    && sources.get(&source).is_some_and(|entry| entry.generation == generation)
                {
                    sources.remove(&source);
                }
            }
            joined = sessions.join_next(), if !sessions.is_empty() => { let _ = joined; }
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, source)) = received else { break; };
                if !sources.contains_key(&source) {
                    if sources.len() >= options.max_udp_source_sessions { continue; }
                    let (sender, receiver) = mpsc::channel(UDP_SOURCE_QUEUE_CAPACITY);
                    let generation = next_generation;
                    next_generation = next_generation.wrapping_add(1).max(1);
                    sources.insert(source, SourceEntry { generation, sender });
                    let socket = socket.clone();
                    let connector = connector.clone();
                    let peer = forward.peer.clone();
                    let export = forward.export.clone();
                    let child = cancellation.child_token();
                    let completed = completed.clone();
                    let context = UdpSourceContext {
                        socket,
                        source,
                        connector,
                        peer,
                        export,
                        cancellation: child,
                        options,
                    };
                    sessions.spawn(async move {
                        run_udp_source(context, receiver).await;
                        let _ = completed.send((source, generation)).await;
                    });
                }
                if let Some(entry) = sources.get(&source)
                    && entry.sender.try_send(buffer[..length].to_vec()).is_err()
                    && entry.sender.is_closed()
                {
                    sources.remove(&source);
                }
            }
        }
    }
    drop(completions);
    cancellation.cancel();
    while sessions.join_next().await.is_some() {}
}

struct UdpSourceContext {
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    connector: Arc<dyn ForwardConnector>,
    peer: String,
    export: String,
    cancellation: CancellationToken,
    options: ForwardRuntimeOptions,
}

async fn run_udp_source(context: UdpSourceContext, mut outbound: mpsc::Receiver<Vec<u8>>) {
    let UdpSourceContext {
        socket,
        source,
        connector,
        peer,
        export,
        cancellation,
        options,
    } = context;
    let open = connector.open_udp(&peer, &export, cancellation.clone());
    let opened = tokio::select! {
        biased;
        () = cancellation.cancelled() => return,
        result = tokio::time::timeout(options.session_open_timeout, open) => result,
    };
    let Ok(Ok(mut session)) = opened else {
        return;
    };
    let idle = tokio::time::sleep(options.udp_source_idle_timeout);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            () = &mut idle => return,
            payload = outbound.recv() => {
                let Some(payload) = payload else { return; };
                let send = session.send(&payload);
                let sent = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return,
                    () = &mut idle => return,
                    result = tokio::time::timeout(options.session_open_timeout, send) => result,
                };
                if !matches!(sent, Ok(Ok(()))) { return; }
                idle.as_mut().reset(tokio::time::Instant::now() + options.udp_source_idle_timeout);
            }
            payload = session.receive() => {
                let Ok(payload) = payload else { return; };
                if payload.len() > MAX_UDP_DATAGRAM_BYTES { return; }
                if socket.send_to(&payload, source).await.is_err() { return; }
            }
        }
    }
}
