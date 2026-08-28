use std::{collections::HashMap, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use rustgo_config::{ForwardConfig, TunnelProtocol};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

const MAX_UDP_SOURCE_SESSIONS: usize = 256;
const UDP_SOURCE_QUEUE_CAPACITY: usize = 64;
const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;

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
    #[error("duplicate forward name")]
    DuplicateForward,
    #[error("invalid forward listen address")]
    InvalidListenAddress,
    #[error("forward listener could not bind")]
    Bind,
    #[error("peer export protocol could not be resolved")]
    Protocol,
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
            let protocol = connector
                .protocol(&forward.peer, &forward.export)
                .await
                .map_err(|_| ForwardError::Protocol)?;
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
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}

async fn cancel_started(shutdown: &CancellationToken, tasks: Vec<JoinHandle<()>>) {
    shutdown.cancel();
    for task in tasks {
        let _ = task.await;
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
) {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => { let _ = joined; }
            accepted = listener.accept() => {
                let Ok((mut local, _)) = accepted else { break; };
                let connector = connector.clone();
                let peer = forward.peer.clone();
                let export = forward.export.clone();
                let child = cancellation.child_token();
                sessions.spawn(async move {
                    let Ok(mut remote) = connector.open_tcp(&peer, &export, child.clone()).await else { return; };
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
) {
    let mut sources: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut sessions = JoinSet::new();
    let (completed, mut completions) = mpsc::channel(MAX_UDP_SOURCE_SESSIONS);
    let mut buffer = vec![0_u8; MAX_UDP_DATAGRAM_BYTES];
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            completed_source = completions.recv(), if !sources.is_empty() => {
                if let Some(source) = completed_source { sources.remove(&source); }
            }
            joined = sessions.join_next(), if !sessions.is_empty() => { let _ = joined; }
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, source)) = received else { break; };
                if !sources.contains_key(&source) {
                    if sources.len() >= MAX_UDP_SOURCE_SESSIONS { continue; }
                    let (sender, receiver) = mpsc::channel(UDP_SOURCE_QUEUE_CAPACITY);
                    sources.insert(source, sender);
                    let socket = socket.clone();
                    let connector = connector.clone();
                    let peer = forward.peer.clone();
                    let export = forward.export.clone();
                    let child = cancellation.child_token();
                    let completed = completed.clone();
                    sessions.spawn(async move {
                        run_udp_source(socket, source, receiver, connector, peer, export, child).await;
                        let _ = completed.send(source).await;
                    });
                }
                if let Some(sender) = sources.get(&source) {
                    let _ = sender.try_send(buffer[..length].to_vec());
                }
            }
        }
    }
    cancellation.cancel();
    while sessions.join_next().await.is_some() {}
}

async fn run_udp_source(
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    connector: Arc<dyn ForwardConnector>,
    peer: String,
    export: String,
    cancellation: CancellationToken,
) {
    let Ok(mut session) = connector
        .open_udp(&peer, &export, cancellation.clone())
        .await
    else {
        return;
    };
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            payload = outbound.recv() => {
                let Some(payload) = payload else { return; };
                if session.send(&payload).await.is_err() { return; }
            }
            payload = session.receive() => {
                let Ok(payload) = payload else { return; };
                if payload.len() > MAX_UDP_DATAGRAM_BYTES { return; }
                if socket.send_to(&payload, source).await.is_err() { return; }
            }
        }
    }
}
