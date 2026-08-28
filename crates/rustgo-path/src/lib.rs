//! Transport-neutral authenticated peer path selection.
//!
//! A [`PathAttempt`] must return success only after connectivity checks and
//! mutual peer authentication have completed. This crate owns scheduling,
//! cancellation, state, and health decisions; adapters retain transport and
//! application semantics.

mod health;
mod race;
mod state;

use std::{
    any::Any,
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use thiserror::Error;
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;

pub use health::PathManagerConfig;
pub use state::{PathState, PathStateMachine};

pub(crate) type Attempt = Arc<dyn PathAttempt>;

const MAX_RECORDED_EVENTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    QuicV6,
    QuicV4,
    NativeTcp,
    Relay,
}

impl PathKind {
    pub const fn is_direct(self) -> bool {
        !matches!(self, Self::Relay)
    }
}

#[derive(Clone)]
pub struct SelectedPath {
    kind: PathKind,
    handle: Arc<dyn Any + Send + Sync>,
}

impl SelectedPath {
    /// Constructs a path whose adapter has completed peer authentication.
    pub fn authenticated(kind: PathKind) -> Self {
        Self::authenticated_with(kind, Arc::new(()))
    }

    /// Attaches an adapter-owned established path without exposing its type.
    pub fn authenticated_with<T>(kind: PathKind, handle: Arc<T>) -> Self
    where
        T: Any + Send + Sync,
    {
        Self { kind, handle }
    }

    pub const fn kind(&self) -> PathKind {
        self.kind
    }

    /// Recovers the established path when the caller knows its adapter type.
    pub fn handle<T>(&self) -> Option<Arc<T>>
    where
        T: Any + Send + Sync,
    {
        self.handle.clone().downcast().ok()
    }
}

impl fmt::Debug for SelectedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedPath")
            .field("kind", &self.kind)
            .field("handle", &"<opaque>")
            .finish()
    }
}

#[async_trait]
pub trait PathAttempt: Send + Sync {
    fn kind(&self) -> PathKind;

    /// Completes only after the peer is mutually authenticated.
    async fn connect(&self, cancellation: CancellationToken) -> Result<SelectedPath, PathError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEvent {
    StateChanged { from: PathState, to: PathState },
    AttemptStarted(PathKind),
    AttemptFailed(PathKind),
    Selected(PathKind),
    RelayFallback,
    RecheckStarted,
    RecheckScheduled,
    Promoted(PathKind),
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathError {
    #[error("illegal path transition from {from:?} to {to:?}")]
    IllegalTransition { from: PathState, to: PathState },
    #[error("invalid path manager timing configuration")]
    InvalidConfiguration,
    #[error("path attempt failed for {0:?}")]
    AttemptFailed(PathKind),
    #[error("path attempt timed out for {0:?}")]
    AttemptTimedOut(PathKind),
    #[error("path attempt task failed")]
    AttemptTaskFailed,
    #[error("no viable authenticated path")]
    NoViablePath,
    #[error("path selection cancelled")]
    Cancelled,
}

pub struct PathManager {
    inner: Arc<ManagerInner>,
}

pub(crate) struct ManagerInner {
    record: Mutex<ManagerRecord>,
    lifetime: CancellationToken,
    config: PathManagerConfig,
    operations_changed: Notify,
}

struct ManagerRecord {
    state: PathStateMachine,
    selected: Option<OwnedSelected>,
    recheck: Option<OwnedRecheck>,
    next_recheck_id: u64,
    active_operations: usize,
    events: VecDeque<PathEvent>,
}

pub(crate) struct OwnedRecheck {
    pub(crate) id: u64,
    pub(crate) cancellation: CancellationToken,
    pub(crate) handle: JoinHandle<()>,
}

struct OwnedSelected {
    path: SelectedPath,
    cancellation: CancellationToken,
    caller_watch: Option<JoinHandle<()>>,
}

struct OwnedResources {
    selected: Option<OwnedSelected>,
    recheck: Option<OwnedRecheck>,
}

struct OperationGuard {
    inner: Option<Arc<ManagerInner>>,
}

impl ManagerRecord {
    fn push_event(&mut self, event: PathEvent) {
        if self.events.len() == MAX_RECORDED_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn transition(&mut self, next: PathState) -> Result<(), PathError> {
        let from = self.state.current();
        self.state.transition(next)?;
        self.push_event(PathEvent::StateChanged { from, to: next });
        Ok(())
    }
}

impl OwnedSelected {
    fn new(winner: race::RaceWinner, caller: CancellationToken) -> Self {
        let cancellation = winner.cancellation;
        let observed_cancellation = cancellation.clone();
        let caller_watch = tokio::spawn(async move {
            tokio::select! {
                () = caller.cancelled() => observed_cancellation.cancel(),
                () = observed_cancellation.cancelled() => {}
            }
        });
        Self {
            path: winner.path,
            cancellation,
            caller_watch: Some(caller_watch),
        }
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    async fn shutdown(mut self) {
        self.cancel();
        if let Some(handle) = self.caller_watch.take() {
            let _ = handle.await;
        }
    }

    fn abort(mut self) {
        self.cancel();
        if let Some(handle) = self.caller_watch.take() {
            handle.abort();
        }
    }
}

impl OwnedRecheck {
    fn cancel(&self) {
        self.cancellation.cancel();
    }

    async fn shutdown(self) {
        self.cancel();
        let _ = self.handle.await;
    }

    fn abort(self) {
        self.cancel();
        self.handle.abort();
    }
}

impl ManagerInner {
    pub(crate) fn record_event(&self, event: PathEvent) {
        let mut record = self.record.lock().expect("path record mutex poisoned");
        if record.state.current() != PathState::Closed {
            record.push_event(event);
        }
    }

    fn state(&self) -> PathState {
        self.record
            .lock()
            .expect("path record mutex poisoned")
            .state
            .current()
    }

    fn begin(self: &Arc<Self>, next: PathState) -> Result<OperationGuard, PathError> {
        let mut record = self.record.lock().expect("path record mutex poisoned");
        record.transition(next)?;
        record.active_operations += 1;
        Ok(OperationGuard {
            inner: Some(self.clone()),
        })
    }

    fn begin_failure(self: &Arc<Self>) -> Result<(OwnedResources, OperationGuard), PathError> {
        let mut record = self.record.lock().expect("path record mutex poisoned");
        record.transition(PathState::Rechecking)?;
        record.active_operations += 1;
        if let Some(selected) = &record.selected {
            selected.cancel();
        }
        if let Some(recheck) = &record.recheck {
            recheck.cancel();
        }
        Ok((
            OwnedResources {
                selected: record.selected.take(),
                recheck: record.recheck.take(),
            },
            OperationGuard {
                inner: Some(self.clone()),
            },
        ))
    }

    fn close_atomic(&self) -> Result<OwnedResources, PathError> {
        let mut record = self.record.lock().expect("path record mutex poisoned");
        if record.state.current() != PathState::Closed {
            record.transition(PathState::Closed)?;
            record.push_event(PathEvent::Closed);
        }
        if let Some(selected) = &record.selected {
            selected.cancel();
        }
        if let Some(recheck) = &record.recheck {
            recheck.cancel();
        }
        Ok(OwnedResources {
            selected: record.selected.take(),
            recheck: record.recheck.take(),
        })
    }

    pub(crate) fn begin_background_recheck(&self, id: u64) -> bool {
        let mut record = self.record.lock().expect("path record mutex poisoned");
        let current_id = record.recheck.as_ref().map(|recheck| recheck.id);
        if current_id != Some(id) || record.state.current() != PathState::Relay {
            return false;
        }
        if record.transition(PathState::Rechecking).is_err() {
            return false;
        }
        record.push_event(PathEvent::RecheckStarted);
        true
    }

    pub(crate) fn finish_failed_recheck(&self, id: u64) -> bool {
        let mut record = self.record.lock().expect("path record mutex poisoned");
        let current_id = record.recheck.as_ref().map(|recheck| recheck.id);
        if current_id != Some(id) || record.state.current() != PathState::Rechecking {
            return false;
        }
        if record.transition(PathState::Relay).is_err() {
            return false;
        }
        record.push_event(PathEvent::RecheckScheduled);
        true
    }

    async fn wait_for_operations(&self) {
        loop {
            let notified = self.operations_changed.notified();
            if self
                .record
                .lock()
                .expect("path record mutex poisoned")
                .active_operations
                == 0
            {
                return;
            }
            notified.await;
        }
    }
}

impl OperationGuard {
    fn finish(mut self, expected: PathState) -> bool {
        let inner = self.inner.take().expect("operation guard is active");
        let mut record = inner.record.lock().expect("path record mutex poisoned");
        let published_before_close = record.state.current() == expected;
        record.active_operations = record.active_operations.saturating_sub(1);
        drop(record);
        inner.operations_changed.notify_waiters();
        published_before_close
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        if let Ok(mut record) = inner.record.lock() {
            record.active_operations = record.active_operations.saturating_sub(1);
        }
        inner.operations_changed.notify_waiters();
    }
}

impl PathManager {
    pub fn new(config: PathManagerConfig) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                record: Mutex::new(ManagerRecord {
                    state: PathStateMachine::new(),
                    selected: None,
                    recheck: None,
                    next_recheck_id: 1,
                    active_operations: 0,
                    events: VecDeque::with_capacity(MAX_RECORDED_EVENTS),
                }),
                lifetime: CancellationToken::new(),
                config,
                operations_changed: Notify::new(),
            }),
        }
    }

    pub fn state(&self) -> PathState {
        self.inner.state()
    }

    pub fn selected(&self) -> Option<SelectedPath> {
        self.inner
            .record
            .lock()
            .expect("path record mutex poisoned")
            .selected
            .as_ref()
            .map(|selected| selected.path.clone())
    }

    pub fn events(&self) -> Vec<PathEvent> {
        self.inner
            .record
            .lock()
            .expect("path record mutex poisoned")
            .events
            .iter()
            .cloned()
            .collect()
    }

    pub async fn connect(
        &self,
        attempts: Vec<Arc<dyn PathAttempt>>,
        caller_cancellation: CancellationToken,
    ) -> Result<SelectedPath, PathError> {
        let operation = self.inner.begin(PathState::Checking)?;
        let direct_attempts = direct_attempts(&attempts);
        let operation_cancellation = self.inner.lifetime.child_token();
        let winner = race::race_attempts(
            attempts,
            self.inner.config,
            caller_cancellation.clone(),
            operation_cancellation,
            self.inner.clone(),
        )
        .await;
        let winner = match winner {
            Ok(winner) => winner,
            Err(error) => {
                drop(operation);
                self.close().await?;
                return Err(error);
            }
        };
        let selected = match install_winner(
            &self.inner,
            PathState::Checking,
            None,
            winner,
            caller_cancellation.clone(),
        )
        .await
        {
            Ok(selected) => selected,
            Err(error) => {
                drop(operation);
                self.close().await?;
                return Err(error);
            }
        };
        if selected.kind() == PathKind::Relay {
            health::start_recheck(self.inner.clone(), direct_attempts, caller_cancellation).await;
        }
        let expected = if selected.kind().is_direct() {
            PathState::Direct
        } else {
            PathState::Relay
        };
        if operation.finish(expected) {
            Ok(selected)
        } else {
            Err(PathError::Cancelled)
        }
    }

    pub async fn report_failed(
        &self,
        attempts: Vec<Arc<dyn PathAttempt>>,
        caller_cancellation: CancellationToken,
    ) -> Result<SelectedPath, PathError> {
        let (resources, operation) = self.inner.begin_failure()?;
        shutdown_resources(resources).await;
        let direct_attempts = direct_attempts(&attempts);
        let operation_cancellation = self.inner.lifetime.child_token();
        let winner = race::race_attempts(
            attempts,
            self.inner.config,
            caller_cancellation.clone(),
            operation_cancellation,
            self.inner.clone(),
        )
        .await;
        let winner = match winner {
            Ok(winner) => winner,
            Err(error) => {
                drop(operation);
                self.close().await?;
                return Err(error);
            }
        };
        let selected = match install_winner(
            &self.inner,
            PathState::Rechecking,
            None,
            winner,
            caller_cancellation.clone(),
        )
        .await
        {
            Ok(selected) => selected,
            Err(error) => {
                drop(operation);
                self.close().await?;
                return Err(error);
            }
        };
        if selected.kind() == PathKind::Relay {
            health::start_recheck(self.inner.clone(), direct_attempts, caller_cancellation).await;
        }
        let expected = if selected.kind().is_direct() {
            PathState::Direct
        } else {
            PathState::Relay
        };
        if operation.finish(expected) {
            Ok(selected)
        } else {
            Err(PathError::Cancelled)
        }
    }

    pub async fn close(&self) -> Result<(), PathError> {
        let resources = self.inner.close_atomic()?;
        self.inner.lifetime.cancel();
        shutdown_resources(resources).await;
        self.inner.wait_for_operations().await;
        Ok(())
    }
}

pub(crate) async fn install_winner(
    inner: &Arc<ManagerInner>,
    expected: PathState,
    recheck_id: Option<u64>,
    winner: race::RaceWinner,
    caller_cancellation: CancellationToken,
) -> Result<SelectedPath, PathError> {
    let mut owner = Some(OwnedSelected::new(winner, caller_cancellation.clone()));
    if caller_cancellation.is_cancelled() || inner.lifetime.is_cancelled() {
        owner.take().expect("winner owner exists").shutdown().await;
        return Err(PathError::Cancelled);
    }
    let path = owner.as_ref().expect("winner owner exists").path.clone();
    let next = if path.kind().is_direct() {
        PathState::Direct
    } else {
        PathState::Relay
    };
    let installed = {
        let mut record = inner.record.lock().expect("path record mutex poisoned");
        let id_matches = recheck_id
            .is_none_or(|id| record.recheck.as_ref().map(|recheck| recheck.id) == Some(id));
        if record.state.current() != expected || !id_matches || record.transition(next).is_err() {
            Err(record.state.current())
        } else {
            let displaced = record
                .selected
                .replace(owner.take().expect("winner owner exists"));
            record.push_event(PathEvent::Selected(path.kind()));
            if next == PathState::Relay {
                record.push_event(PathEvent::RelayFallback);
            } else if recheck_id.is_some() {
                record.push_event(PathEvent::Promoted(path.kind()));
            }
            Ok(displaced)
        }
    };
    match installed {
        Ok(displaced) => {
            if let Some(displaced) = displaced {
                displaced.shutdown().await;
            }
            Ok(path)
        }
        Err(current) => {
            owner.take().expect("winner owner exists").shutdown().await;
            if current == PathState::Closed {
                Err(PathError::Cancelled)
            } else {
                Err(PathError::IllegalTransition {
                    from: current,
                    to: next,
                })
            }
        }
    }
}

async fn shutdown_resources(resources: OwnedResources) {
    if let Some(selected) = resources.selected {
        selected.shutdown().await;
    }
    if let Some(recheck) = resources.recheck {
        recheck.shutdown().await;
    }
}

fn direct_attempts(attempts: &[Attempt]) -> Vec<Attempt> {
    attempts
        .iter()
        .filter(|attempt| attempt.kind().is_direct())
        .cloned()
        .collect()
}

impl Drop for PathManager {
    fn drop(&mut self) {
        self.inner.lifetime.cancel();
        if let Ok(mut record) = self.inner.record.lock() {
            if record.state.current() != PathState::Closed {
                let _ = record.transition(PathState::Closed);
                record.push_event(PathEvent::Closed);
            }
            if let Some(selected) = record.selected.take() {
                selected.abort();
            }
            if let Some(recheck) = record.recheck.take() {
                recheck.abort();
            }
        }
    }
}
