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
        let started_at = tokio::time::Instant::now();
        let first_tick = started_at
            .checked_add(self.heartbeat_interval)
            .ok_or(ClientError::InvalidConfiguration)?;
        let first_deadline = started_at
            .checked_add(heartbeat_timeout)
            .ok_or(ClientError::InvalidConfiguration)?;
        let mut heartbeat = tokio::time::interval_at(first_tick, self.heartbeat_interval);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let heartbeat_deadline = tokio::time::sleep_until(first_deadline);
        tokio::pin!(heartbeat_deadline);
        let mut last_sent_sequence = 0_u64;
        let mut last_acknowledged_sequence = 0_u64;

        loop {
            tokio::select! {
                biased;
                // Once the deadline is ready it wins over an acknowledgement in the same poll;
                // only acknowledgements processed strictly before expiry may extend liveness.
                () = shutdown.cancelled() => return Ok(()),
                () = &mut heartbeat_deadline => return Err(ClientError::HeartbeatTimeout),
                _ = heartbeat.tick() => {
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
                        () = &mut heartbeat_deadline => {
                            return Err(ClientError::HeartbeatTimeout);
                        }
                        result = tokio::time::timeout(self.heartbeat_interval, write) => result,
                    };
                    result.map_err(|_| ClientError::ControlWriteTimeout)??;
                }
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
                            let next_deadline = tokio::time::Instant::now()
                                .checked_add(heartbeat_timeout)
                                .ok_or(ClientError::InvalidConfiguration)?;
                            heartbeat_deadline.as_mut().reset(next_deadline);
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
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use rustgo_protocol::{
        BoundedBytes, Heartbeat, MAX_BINDING_TOKEN_BYTES, Message, OpenTcpStream, OpenUdpChannel,
        SocketAddress,
    };
    use tokio::io::{AsyncReadExt, duplex};
    use tokio_util::sync::CancellationToken;

    use super::{
        ChildSessionContext, ChildSessionRequest, ChildSessionSupervisor,
        NoopChildSessionSupervisor, SessionGeneration,
    };
    use crate::{
        CLIENT_VERSION, ClientError, ControlSession, RegisteredTunnel, control::FramedControl,
    };

    #[derive(Clone, Default)]
    struct CountingSupervisor {
        requested: Arc<AtomicUsize>,
        cancelled: Arc<AtomicUsize>,
    }

    impl ChildSessionSupervisor for CountingSupervisor {
        fn run_child(
            &self,
            _context: ChildSessionContext,
            _request: ChildSessionRequest,
            shutdown: CancellationToken,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            self.requested.fetch_add(1, Ordering::SeqCst);
            let cancelled = self.cancelled.clone();
            Box::pin(async move {
                shutdown.cancelled().await;
                cancelled.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let mut context = Context::from_waker(Waker::noop());
        future.poll(&mut context)
    }

    fn token(marker: u8) -> BoundedBytes<MAX_BINDING_TOKEN_BYTES> {
        BoundedBytes::try_from([marker; MAX_BINDING_TOKEN_BYTES].as_slice()).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn queued_business_frames_cannot_starve_the_heartbeat_deadline_or_child_join() {
        let (client_stream, server_stream) = duplex(256 * 1024);
        let mut peer = FramedControl::new(server_stream);
        let session = ControlSession::new(
            FramedControl::new(client_stream),
            CLIENT_VERSION,
            vec![0x61; 32],
            Duration::from_millis(10),
            Arc::from([RegisteredTunnel::accepted_for_test(1)]),
        );
        let supervisor = CountingSupervisor::default();
        let requested = supervisor.requested.clone();
        let cancelled = supervisor.cancelled.clone();
        let inactive = Arc::new(AtomicBool::new(false));
        let inactive_callback = inactive.clone();
        let mut runtime = Box::pin(session.run_generation(
            SessionGeneration(1),
            CancellationToken::new(),
            Arc::new(supervisor),
            move || inactive_callback.store(true, Ordering::SeqCst),
        ));

        peer.send(
            CLIENT_VERSION,
            Message::OpenTcpStream(OpenTcpStream {
                tunnel_id: 1,
                connection_id: 1,
                peer: SocketAddress::V4 {
                    octets: [203, 0, 113, 61],
                    port: 443,
                },
                binding_token: token(0x61),
            }),
        )
        .await
        .unwrap();
        assert!(poll_once(runtime.as_mut()).is_pending());
        assert_eq!(requested.load(Ordering::SeqCst), 1);

        for index in 0..64_u64 {
            let message = if index % 2 == 0 {
                Message::OpenTcpStream(OpenTcpStream {
                    tunnel_id: 1,
                    connection_id: index + 2,
                    peer: SocketAddress::V4 {
                        octets: [203, 0, 113, 62],
                        port: 443,
                    },
                    binding_token: token(0x62),
                })
            } else {
                Message::OpenUdpChannel(OpenUdpChannel {
                    tunnel_id: 1,
                    channel_id: index + 2,
                    binding_token: token(0x63),
                })
            };
            peer.send(CLIENT_VERSION, message).await.unwrap();
        }
        tokio::time::advance(Duration::from_millis(20)).await;

        assert!(poll_once(runtime.as_mut()).is_pending());
        assert!(inactive.load(Ordering::SeqCst));
        assert_eq!(
            requested.load(Ordering::SeqCst),
            1,
            "no queued business frame may be admitted after the deadline is ready"
        );
        let result = tokio::time::timeout(Duration::from_millis(100), runtime)
            .await
            .expect("deadline cancellation and child join must be bounded");
        assert!(matches!(result, Err(ClientError::HeartbeatTimeout)));
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn valid_ack_resets_a_future_deadline_but_cannot_revive_an_expired_one() {
        let (client_stream, server_stream) = duplex(4096);
        let mut peer = FramedControl::new(server_stream);
        let session = ControlSession::new(
            FramedControl::new(client_stream),
            CLIENT_VERSION,
            vec![0x71; 32],
            Duration::from_millis(10),
            Arc::<[RegisteredTunnel]>::from([]),
        );
        let inactive = Arc::new(AtomicBool::new(false));
        let inactive_callback = inactive.clone();
        let mut runtime = Box::pin(session.run_generation(
            SessionGeneration(1),
            CancellationToken::new(),
            Arc::new(NoopChildSessionSupervisor),
            move || inactive_callback.store(true, Ordering::SeqCst),
        ));

        assert!(poll_once(runtime.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(10)).await;
        assert!(poll_once(runtime.as_mut()).is_pending());
        let Message::Heartbeat(first) = peer.receive().await.unwrap().message else {
            panic!("expected first heartbeat");
        };
        assert_eq!(first.sequence, 1);

        tokio::time::advance(Duration::from_millis(9)).await;
        peer.send(
            CLIENT_VERSION,
            Message::Heartbeat(Heartbeat {
                sequence: first.sequence,
            }),
        )
        .await
        .unwrap();
        assert!(poll_once(runtime.as_mut()).is_pending());

        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(poll_once(runtime.as_mut()).is_pending());
        let Message::Heartbeat(second) = peer.receive().await.unwrap().message else {
            panic!("expected second heartbeat");
        };
        assert_eq!(second.sequence, 2);

        tokio::time::advance(Duration::from_millis(19)).await;
        peer.send(
            CLIENT_VERSION,
            Message::Heartbeat(Heartbeat {
                sequence: second.sequence,
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            poll_once(runtime.as_mut()),
            Poll::Ready(Err(ClientError::HeartbeatTimeout))
        ));
        assert!(inactive.load(Ordering::SeqCst));
    }

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
