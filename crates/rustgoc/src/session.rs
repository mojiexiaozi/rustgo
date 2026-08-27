use std::{future::Future, pin::Pin, sync::Arc};

use rustgo_protocol::{Heartbeat, Message, OpenTcpStream, OpenUdpChannel};
use tokio::{task::JoinSet, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::{ClientError, ControlSession};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionGeneration(u64);

impl SessionGeneration {
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn next(previous: u64) -> Result<Self, ClientError> {
        previous
            .checked_add(1)
            .map(Self)
            .ok_or(ClientError::GenerationExhausted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildSessionRequest {
    Tcp(OpenTcpStream),
    Udp(OpenUdpChannel),
}

#[derive(Clone)]
pub struct ChildSessionContext {
    generation: SessionGeneration,
    session_id: Arc<[u8]>,
}

impl ChildSessionContext {
    pub const fn generation(&self) -> SessionGeneration {
        self.generation
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
}

impl std::fmt::Debug for ChildSessionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChildSessionContext")
            .field("generation", &self.generation)
            .field("session_id", &"[REDACTED]")
            .finish()
    }
}

/// Task 8/9 seam: one future owns one data-session child for exactly one generation.
pub trait ChildSessionSupervisor: Send + Sync + 'static {
    fn run_child(
        &self,
        context: ChildSessionContext,
        request: ChildSessionRequest,
        shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

#[derive(Debug, Default)]
pub struct NoopChildSessionSupervisor;

impl ChildSessionSupervisor for NoopChildSessionSupervisor {
    fn run_child(
        &self,
        _context: ChildSessionContext,
        _request: ChildSessionRequest,
        shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async move { shutdown.cancelled().await })
    }
}

impl ControlSession {
    pub(crate) async fn run_generation<F>(
        mut self,
        generation: SessionGeneration,
        shutdown: CancellationToken,
        supervisor: Arc<dyn ChildSessionSupervisor>,
        on_inactive: F,
    ) -> Result<(), ClientError>
    where
        F: FnOnce(),
    {
        let child_shutdown = CancellationToken::new();
        let mut children = JoinSet::new();
        let child_context = ChildSessionContext {
            generation,
            session_id: Arc::from(self.session_id.clone()),
        };
        let result = self
            .run_control_loop(
                &child_context,
                &shutdown,
                &child_shutdown,
                &supervisor,
                &mut children,
            )
            .await;

        // No child teardown may retain a dead or backpressured generation's control socket.
        drop(self.framed);
        // The current view must lose its generation before child teardown can block.
        on_inactive();
        child_shutdown.cancel();
        let mut join_failed = false;
        while let Some(joined) = children.join_next().await {
            if joined.is_err() {
                join_failed = true;
            }
        }
        if join_failed {
            Err(ClientError::TaskJoin)
        } else {
            result
        }
    }

    async fn run_control_loop(
        &mut self,
        child_context: &ChildSessionContext,
        shutdown: &CancellationToken,
        child_shutdown: &CancellationToken,
        supervisor: &Arc<dyn ChildSessionSupervisor>,
        children: &mut JoinSet<()>,
    ) -> Result<(), ClientError> {
        let heartbeat_timeout = self
            .heartbeat_interval
            .checked_mul(2)
            .ok_or(ClientError::InvalidConfiguration)?;
        let first_tick = tokio::time::Instant::now()
            .checked_add(self.heartbeat_interval)
            .ok_or(ClientError::InvalidConfiguration)?;
        let mut heartbeat = tokio::time::interval_at(first_tick, self.heartbeat_interval);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_heartbeat_acknowledgement = tokio::time::Instant::now();
        let mut last_sent_sequence = 0_u64;
        let mut last_acknowledged_sequence = 0_u64;

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                joined = children.join_next(), if !children.is_empty() => {
                    if joined.is_some_and(|result| result.is_err()) {
                        return Err(ClientError::TaskJoin);
                    }
                }
                frame = self.framed.receive() => {
                    let frame = frame?;
                    if frame.version != self.version {
                        return Err(ClientError::InvalidState);
                    }
                    match frame.message {
                        Message::Heartbeat(acknowledgement) => {
                            if acknowledgement.sequence <= last_acknowledged_sequence
                                || acknowledgement.sequence > last_sent_sequence
                            {
                                return Err(ClientError::InvalidState);
                            }
                            last_acknowledged_sequence = acknowledgement.sequence;
                            last_heartbeat_acknowledgement = tokio::time::Instant::now();
                        }
                        Message::OpenTcpStream(request) => {
                            self.ensure_accepted_tunnel(request.tunnel_id)?;
                            children.spawn(supervisor.run_child(
                                child_context.clone(),
                                ChildSessionRequest::Tcp(request),
                                child_shutdown.child_token(),
                            ));
                        }
                        Message::OpenUdpChannel(request) => {
                            self.ensure_accepted_tunnel(request.tunnel_id)?;
                            children.spawn(supervisor.run_child(
                                child_context.clone(),
                                ChildSessionRequest::Udp(request),
                                child_shutdown.child_token(),
                            ));
                        }
                        Message::Error(error) => return Err(ClientError::Protocol(error.code)),
                        _ => return Err(ClientError::InvalidState),
                    }
                }
                _ = heartbeat.tick() => {
                    let now = tokio::time::Instant::now();
                    if now.saturating_duration_since(last_heartbeat_acknowledgement)
                        >= heartbeat_timeout
                    {
                        return Err(ClientError::HeartbeatTimeout);
                    }
                    last_sent_sequence = last_sent_sequence
                        .checked_add(1)
                        .ok_or(ClientError::SequenceExhausted)?;
                    let write = self.framed.send(
                        self.version,
                        Message::Heartbeat(Heartbeat {
                            sequence: last_sent_sequence,
                        }),
                    );
                    let result = tokio::select! {
                        biased;
                        () = shutdown.cancelled() => return Ok(()),
                        result = tokio::time::timeout(self.heartbeat_interval, write) => result,
                    };
                    result.map_err(|_| ClientError::ControlWriteTimeout)??;
                }
            }
        }
    }

    fn ensure_accepted_tunnel(&self, tunnel_id: u32) -> Result<(), ClientError> {
        if self
            .registered_tunnels()
            .iter()
            .any(|tunnel| tunnel.tunnel_id() == tunnel_id && tunnel.accepted())
        {
            Ok(())
        } else {
            Err(ClientError::InvalidState)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::io::{AsyncReadExt, duplex};
    use tokio_util::sync::CancellationToken;

    use super::{NoopChildSessionSupervisor, SessionGeneration};
    use crate::{CLIENT_VERSION, ControlSession, RegisteredTunnel, control::FramedControl};

    #[tokio::test(start_paused = true)]
    async fn shutdown_interrupts_a_backpressured_active_control_write() {
        let (client_stream, mut server_stream) = duplex(1);
        let session = ControlSession::new(
            FramedControl::new(client_stream),
            CLIENT_VERSION,
            vec![0x51; 32],
            Duration::from_millis(10),
            Arc::<[RegisteredTunnel]>::from([]),
        );
        let shutdown = CancellationToken::new();
        let runtime_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            session
                .run_generation(
                    SessionGeneration(1),
                    runtime_shutdown,
                    Arc::new(NoopChildSessionSupervisor),
                    || {},
                )
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        shutdown.cancel();
        let result = tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .expect("shutdown must interrupt a blocked active control write")
            .unwrap();
        assert!(result.is_ok());

        let mut written = Vec::new();
        tokio::time::timeout(
            Duration::from_millis(100),
            server_stream.read_to_end(&mut written),
        )
        .await
        .expect("the terminated generation must drop its control stream")
        .unwrap();
        assert!(!written.is_empty());
    }
}
