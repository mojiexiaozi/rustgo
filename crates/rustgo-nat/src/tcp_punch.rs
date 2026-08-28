use std::{io, net::SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;
use tokio::{net::TcpStream, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

pub const MAX_TCP_PUNCH_CANDIDATES: usize = 8;

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
}

pub struct TcpPuncher;

impl TcpPuncher {
    pub async fn connect(
        local: SocketAddr,
        candidates: Vec<SocketAddr>,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> Result<TcpStream, TcpPunchError> {
        if candidates.is_empty() {
            return Err(TcpPunchError::InvalidCandidates);
        }
        if candidates.len() > MAX_TCP_PUNCH_CANDIDATES {
            return Err(TcpPunchError::TooManyCandidates);
        }
        if cancellation.is_cancelled() {
            return Err(TcpPunchError::Cancelled);
        }

        let mut attempts = JoinSet::new();
        for remote in candidates {
            attempts.spawn(connect_bound(local, remote));
        }

        loop {
            tokio::select! {
                () = cancellation.cancelled() => {
                    attempts.abort_all();
                    return Err(TcpPunchError::Cancelled);
                }
                () = tokio::time::sleep_until(deadline) => {
                    attempts.abort_all();
                    return Err(TcpPunchError::Deadline);
                }
                outcome = attempts.join_next() => match outcome {
                    Some(Ok(Ok(stream))) => {
                        attempts.abort_all();
                        return Ok(stream);
                    }
                    Some(_) if !attempts.is_empty() => {}
                    Some(_) | None => return Err(TcpPunchError::ConnectFailed),
                }
            }
        }
    }
}

async fn connect_bound(local: SocketAddr, remote: SocketAddr) -> io::Result<TcpStream> {
    if local.is_ipv4() != remote.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "address family mismatch",
        ));
    }
    let domain = if local.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
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

fn is_connect_pending(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || matches!(error.raw_os_error(), Some(10035 | 10036 | 115))
}
