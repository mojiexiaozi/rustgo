//! Cancellation-owned orchestration for one authenticated peer rendezvous session.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use rustgo_crypto::{PeerCryptoError, PeerFrameOpener, PeerFrameSealer, PeerSessionKeys};
use rustgo_path::{PathAttempt, PathError, PathKind, PathManager, PathManagerConfig, SelectedPath};
use rustgo_rendezvous::{PeerRelayFlags, PeerRelayFrame, SessionId};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const ABSOLUTE_MAX_PEER_SESSIONS: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct PeerSessionRuntimeOptions {
    pub max_sessions: usize,
    pub direct_timeout: Duration,
    pub relay_grace: Duration,
    pub attempt_timeout: Duration,
    pub recheck_interval: Duration,
}

impl Default for PeerSessionRuntimeOptions {
    fn default() -> Self {
        Self {
            max_sessions: 256,
            direct_timeout: Duration::from_secs(10),
            relay_grace: Duration::from_millis(750),
            attempt_timeout: Duration::from_secs(5),
            recheck_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Error)]
pub enum PeerRuntimeError {
    #[error("invalid peer runtime limits")]
    InvalidOptions,
    #[error("peer session already exists")]
    DuplicateSession,
    #[error("peer session capacity reached")]
    Capacity,
    #[error("peer session expired")]
    Expired,
    #[error("peer path failed: {0}")]
    Path(#[from] PathError),
    #[error("peer relay crypto failed: {0}")]
    Crypto(#[from] PeerCryptoError),
}

#[derive(Clone)]
pub struct PeerSessionRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    sessions: Mutex<HashMap<SessionId, CancellationToken>>,
    options: PeerSessionRuntimeOptions,
    shutdown: CancellationToken,
}

impl PeerSessionRuntime {
    pub fn new(
        options: PeerSessionRuntimeOptions,
        cancellation: CancellationToken,
    ) -> Result<Self, PeerRuntimeError> {
        if !(1..=ABSOLUTE_MAX_PEER_SESSIONS).contains(&options.max_sessions) {
            return Err(PeerRuntimeError::InvalidOptions);
        }
        PathManagerConfig::new(
            options.direct_timeout,
            options.relay_grace,
            options.attempt_timeout,
            options.recheck_interval,
        )?;
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                sessions: Mutex::new(HashMap::new()),
                options,
                shutdown: cancellation.child_token(),
            }),
        })
    }

    /// Races already constructed, mutually-authenticating direct adapters and an
    /// optional end-to-end encrypted relay. Callers must build adapters only from
    /// verified rendezvous envelopes and authenticated directory identities.
    pub async fn connect(
        &self,
        session_id: SessionId,
        expires_unix_secs: u64,
        mut attempts: Vec<Arc<dyn PathAttempt>>,
        relay: Option<Arc<PeerRelayChannel>>,
    ) -> Result<PeerSessionHandle, PeerRuntimeError> {
        if expires_unix_secs <= now_unix_secs() {
            return Err(PeerRuntimeError::Expired);
        }
        let cancellation = self.inner.shutdown.child_token();
        {
            let mut sessions = self
                .inner
                .sessions
                .lock()
                .expect("peer session mutex poisoned");
            if sessions.contains_key(&session_id) {
                return Err(PeerRuntimeError::DuplicateSession);
            }
            if sessions.len() >= self.inner.options.max_sessions {
                return Err(PeerRuntimeError::Capacity);
            }
            sessions.insert(session_id, cancellation.clone());
        }
        if let Some(relay) = relay {
            attempts.push(Arc::new(RelayPathAttempt { relay }));
        }
        let manager = Arc::new(PathManager::new(PathManagerConfig::new(
            self.inner.options.direct_timeout,
            self.inner.options.relay_grace,
            self.inner.options.attempt_timeout,
            self.inner.options.recheck_interval,
        )?));
        let selected = manager.connect(attempts, cancellation.clone()).await;
        let selected = match selected {
            Ok(path) => path,
            Err(error) => {
                self.inner
                    .sessions
                    .lock()
                    .expect("peer session mutex poisoned")
                    .remove(&session_id);
                return Err(error.into());
            }
        };
        let expiry = cancellation.clone();
        let runtime = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            let remaining = expires_unix_secs.saturating_sub(now_unix_secs());
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(remaining)) => expiry.cancel(),
                () = expiry.cancelled() => {}
            }
            if let Some(runtime) = runtime.upgrade() {
                runtime
                    .sessions
                    .lock()
                    .expect("peer session mutex poisoned")
                    .remove(&session_id);
            }
        });
        Ok(PeerSessionHandle {
            session_id,
            selected,
            manager,
            cancellation,
            runtime: Arc::downgrade(&self.inner),
        })
    }

    pub fn active_sessions(&self) -> usize {
        self.inner
            .sessions
            .lock()
            .expect("peer session mutex poisoned")
            .len()
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        let tokens = self
            .inner
            .sessions
            .lock()
            .expect("peer session mutex poisoned")
            .drain()
            .map(|(_, token)| token)
            .collect::<Vec<_>>();
        for token in tokens {
            token.cancel();
        }
    }
}

pub struct PeerSessionHandle {
    session_id: SessionId,
    selected: SelectedPath,
    manager: Arc<PathManager>,
    cancellation: CancellationToken,
    runtime: std::sync::Weak<RuntimeInner>,
}

impl PeerSessionHandle {
    pub fn selected_path(&self) -> &SelectedPath {
        &self.selected
    }
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub async fn report_failed(
        &mut self,
        attempts: Vec<Arc<dyn PathAttempt>>,
    ) -> Result<PathKind, PeerRuntimeError> {
        self.selected = self
            .manager
            .report_failed(attempts, self.cancellation.clone())
            .await?;
        Ok(self.selected.kind())
    }

    pub async fn close(self) {
        self.cancellation.cancel();
        let _ = self.manager.close().await;
        if let Some(runtime) = self.runtime.upgrade() {
            runtime
                .sessions
                .lock()
                .expect("peer session mutex poisoned")
                .remove(&self.session_id);
        }
    }
}

impl Drop for PeerSessionHandle {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(runtime) = self.runtime.upgrade() {
            runtime
                .sessions
                .lock()
                .expect("peer session mutex poisoned")
                .remove(&self.session_id);
        }
    }
}

/// One protocol/channel-scoped relay cipher. The relay server sees only the
/// bounded [`PeerRelayFrame`] and cannot recover application plaintext.
pub struct PeerRelayChannel {
    sealer: Mutex<PeerFrameSealer>,
    opener: Mutex<PeerFrameOpener>,
    datagram: bool,
}

impl PeerRelayChannel {
    pub fn stream(keys: &mut PeerSessionKeys, channel_id: u64) -> Result<Self, PeerRuntimeError> {
        Ok(Self {
            sealer: Mutex::new(keys.stream_sealer(channel_id)?),
            opener: Mutex::new(keys.stream_opener(channel_id)?),
            datagram: false,
        })
    }

    pub fn datagram(keys: &mut PeerSessionKeys, channel_id: u64) -> Result<Self, PeerRuntimeError> {
        Ok(Self {
            sealer: Mutex::new(keys.datagram_sealer(channel_id)?),
            opener: Mutex::new(keys.datagram_opener(channel_id)?),
            datagram: true,
        })
    }

    pub fn seal(&self, payload: &[u8], fin: bool) -> Result<PeerRelayFrame, PeerRuntimeError> {
        let flags = if self.datagram {
            PeerRelayFlags::DATAGRAM
        } else if fin {
            PeerRelayFlags::RELIABLE | PeerRelayFlags::FIN
        } else {
            PeerRelayFlags::RELIABLE
        };
        Ok(self
            .sealer
            .lock()
            .expect("relay sealer mutex poisoned")
            .seal(payload, flags)?)
    }

    pub fn open(&self, frame: &PeerRelayFrame) -> Result<Vec<u8>, PeerRuntimeError> {
        Ok(self
            .opener
            .lock()
            .expect("relay opener mutex poisoned")
            .open(frame)?)
    }
}

struct RelayPathAttempt {
    relay: Arc<PeerRelayChannel>,
}

#[async_trait::async_trait]
impl PathAttempt for RelayPathAttempt {
    fn kind(&self) -> PathKind {
        PathKind::Relay
    }
    async fn connect(&self, cancellation: CancellationToken) -> Result<SelectedPath, PathError> {
        if cancellation.is_cancelled() {
            return Err(PathError::Cancelled);
        }
        Ok(SelectedPath::authenticated_with(
            PathKind::Relay,
            self.relay.clone(),
        ))
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
