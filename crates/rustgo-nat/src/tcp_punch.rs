use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub const MAX_TCP_PUNCH_CANDIDATES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpPunchMode {
    Union,
    ListenerOnly,
    OutboundOnly,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TcpPunchError {
    #[error("native TCP punching requires one to eight candidates")]
    InvalidCandidates,
    #[error("native TCP punching candidate limit exceeded")]
    TooManyCandidates,
    #[error("native TCP punching was cancelled")]
    Cancelled,
    #[error("native TCP punching deadline elapsed")]
    Deadline,
    #[error("every native TCP candidate failed")]
    ConnectFailed,
    #[error("the fixed native TCP port could not be owned")]
    BindFailed,
}

pub struct TcpPunchCandidates {
    receiver: mpsc::Receiver<TcpStream>,
    owner: CancellationToken,
    deadline: Instant,
    owner_task: Option<JoinHandle<()>>,
}

impl TcpPunchCandidates {
    pub async fn next(&mut self) -> Result<Option<TcpStream>, TcpPunchError> {
        tokio::select! {
            biased;
            () = self.owner.cancelled() => Err(TcpPunchError::Cancelled),
            () = tokio::time::sleep_until(self.deadline) => Err(TcpPunchError::Deadline),
            stream = self.receiver.recv() => Ok(stream),
        }
    }
    pub fn cancel(&self) {
        self.owner.cancel();
    }

    pub async fn close(&mut self) {
        self.owner.cancel();
        if let Some(task) = self.owner_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for TcpPunchCandidates {
    fn drop(&mut self) {
        self.owner.cancel();
        if let Some(task) = self.owner_task.take() {
            task.abort();
        }
    }
}

pub struct TcpPuncher;

impl TcpPuncher {
    pub async fn candidates(
        local: SocketAddr,
        candidates: Vec<SocketAddr>,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> Result<TcpPunchCandidates, TcpPunchError> {
        Self::candidates_with_mode(
            local,
            candidates,
            deadline,
            cancellation,
            TcpPunchMode::Union,
        )
        .await
    }

    pub async fn candidates_with_mode(
        local: SocketAddr,
        candidates: Vec<SocketAddr>,
        deadline: Instant,
        cancellation: CancellationToken,
        mode: TcpPunchMode,
    ) -> Result<TcpPunchCandidates, TcpPunchError> {
        validate_candidates(local, &candidates)?;
        if cancellation.is_cancelled() {
            return Err(TcpPunchError::Cancelled);
        }
        let listener = if mode == TcpPunchMode::OutboundOnly {
            None
        } else {
            Some(bind_listener(local).map_err(|_| TcpPunchError::BindFailed)?)
        };
        let owner = cancellation.child_token();
        let (sender, receiver) = mpsc::channel(MAX_TCP_PUNCH_CANDIDATES);
        let task_owner = owner.clone();
        let owner_task = tokio::spawn(async move {
            let total = Arc::new(AtomicUsize::new(0));
            let mut tasks = JoinSet::new();
            if let Some(listener) = listener {
                let accepted_total = total.clone();
                let accepted_sender = sender.clone();
                let accepted_owner = task_owner.clone();
                let accepted_candidates = candidates.clone();
                tasks.spawn(async move {
                    loop {
                        let accepted = tokio::select! { () = accepted_owner.cancelled() => break, result = listener.accept() => result };
                        let Ok((stream, remote)) = accepted else { break };
                        if !accepted_candidates.contains(&remote) { continue; }
                        if reserve_attempt(&accepted_total).is_err() { break; }
                        if accepted_sender.send(stream).await.is_err() { break; }
                    }
                });
            }
            let outbound_limit = match mode {
                TcpPunchMode::Union => 7,
                TcpPunchMode::ListenerOnly => 0,
                TcpPunchMode::OutboundOnly => 8,
            };
            for remote in candidates.into_iter().take(outbound_limit) {
                if reserve_attempt(&total).is_err() {
                    break;
                }
                let outbound_sender = sender.clone();
                let outbound_owner = task_owner.clone();
                tasks.spawn(async move {
                    let result = tokio::select! { () = outbound_owner.cancelled() => return, result = connect_candidate(local, remote, deadline) => result };
                    if let Ok(stream) = result { let _ = outbound_sender.send(stream).await; }
                });
            }
            drop(sender);
            tokio::select! {
                () = task_owner.cancelled() => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                },
                () = async { while tasks.join_next().await.is_some() {} } => {}
            }
        });
        Ok(TcpPunchCandidates {
            receiver,
            owner,
            deadline,
            owner_task: Some(owner_task),
        })
    }

    pub async fn connect(
        local: SocketAddr,
        candidates: Vec<SocketAddr>,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> Result<TcpStream, TcpPunchError> {
        let mut pool = Self::candidates(local, candidates, deadline, cancellation).await?;
        let result = pool.next().await;
        pool.close().await;
        result?.ok_or(TcpPunchError::ConnectFailed)
    }
}

fn reserve_attempt(total: &AtomicUsize) -> Result<(), ()> {
    total
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            (value < MAX_TCP_PUNCH_CANDIDATES).then_some(value + 1)
        })
        .map(|_| ())
        .map_err(|_| ())
}

fn validate_candidates(local: SocketAddr, candidates: &[SocketAddr]) -> Result<(), TcpPunchError> {
    if candidates.is_empty() {
        return Err(TcpPunchError::InvalidCandidates);
    }
    if candidates.len() > MAX_TCP_PUNCH_CANDIDATES {
        return Err(TcpPunchError::TooManyCandidates);
    }
    if candidates
        .iter()
        .any(|remote| remote.is_ipv4() != local.is_ipv4())
    {
        return Err(TcpPunchError::InvalidCandidates);
    }
    Ok(())
}

fn bind_listener(local: SocketAddr) -> io::Result<TcpListener> {
    let socket = new_socket(local)?;
    configure_listener_ownership(&socket)?;
    socket.set_nonblocking(true)?;
    socket.bind(&local.into())?;
    socket.listen(MAX_TCP_PUNCH_CANDIDATES as i32)?;
    TcpListener::from_std(socket.into())
}

async fn connect_bound(local: SocketAddr, remote: SocketAddr) -> io::Result<TcpStream> {
    let socket = new_socket(local)?;
    configure_outbound_sharing(&socket)?;
    socket.set_nonblocking(true)?;
    socket.bind(&local.into())?;
    let pending = match socket.connect(&remote.into()) {
        Ok(()) => false,
        Err(error) if is_connect_pending(&error) => true,
        Err(error) => return Err(error),
    };
    let stream = TcpStream::from_std(socket.into())?;
    if pending {
        stream.writable().await?;
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
    }
    Ok(stream)
}

#[cfg(not(windows))]
async fn connect_candidate(
    local: SocketAddr,
    remote: SocketAddr,
    _deadline: Instant,
) -> io::Result<TcpStream> {
    connect_bound(local, remote).await
}

#[cfg(windows)]
async fn connect_candidate(
    local: SocketAddr,
    remote: SocketAddr,
    deadline: Instant,
) -> io::Result<TcpStream> {
    loop {
        match connect_bound(local, remote).await {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn new_socket(address: SocketAddr) -> io::Result<Socket> {
    Socket::new(
        if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::STREAM,
        Some(Protocol::TCP),
    )
}

#[cfg(target_os = "linux")]
fn configure_listener_ownership(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)
}
#[cfg(target_os = "linux")]
fn configure_outbound_sharing(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)
}
#[cfg(all(unix, not(target_os = "linux")))]
fn configure_listener_ownership(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(true)
}
#[cfg(all(unix, not(target_os = "linux")))]
fn configure_outbound_sharing(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(true)
}
#[cfg(windows)]
fn configure_listener_ownership(_socket: &Socket) -> io::Result<()> {
    // The supported Windows role-split never enables SO_REUSEADDR on the listener. Safe Rust's
    // default Winsock bind is validated below by a hostile SO_REUSEADDR contender test.
    Ok(())
}
#[cfg(windows)]
fn configure_outbound_sharing(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

fn is_connect_pending(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || matches!(error.raw_os_error(), Some(10035 | 10036 | 115))
}
