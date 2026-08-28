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
use tokio_util::sync::CancellationToken;

pub use health::PathManagerConfig;
pub use state::{PathState, PathStateMachine};

pub(crate) type Attempt = Arc<dyn PathAttempt>;
pub(crate) type SharedEvents = Arc<Mutex<VecDeque<PathEvent>>>;

const MAX_RECORDED_EVENTS: usize = 256;

pub(crate) fn record_event(events: &SharedEvents, event: PathEvent) {
    let mut events = events.lock().expect("path event mutex poisoned");
    if events.len() == MAX_RECORDED_EVENTS {
        events.pop_front();
    }
    events.push_back(event);
}

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
    config: PathManagerConfig,
    cancellation: CancellationToken,
}

pub(crate) struct ManagerInner {
    state: Mutex<PathStateMachine>,
    selected: Mutex<Option<SelectedPath>>,
    events: SharedEvents,
}

impl ManagerInner {
    fn transition(&self, next: PathState) -> Result<(), PathError> {
        let mut state = self.state.lock().expect("path state mutex poisoned");
        let from = state.current();
        state.transition(next)?;
        drop(state);
        self.record(PathEvent::StateChanged { from, to: next });
        Ok(())
    }

    fn set_selected(&self, selected: SelectedPath) {
        *self.selected.lock().expect("selected path mutex poisoned") = Some(selected);
    }

    fn record(&self, event: PathEvent) {
        record_event(&self.events, event);
    }
}

impl PathManager {
    pub fn new(config: PathManagerConfig) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                state: Mutex::new(PathStateMachine::new()),
                selected: Mutex::new(None),
                events: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECORDED_EVENTS))),
            }),
            config,
            cancellation: CancellationToken::new(),
        }
    }

    pub fn state(&self) -> PathState {
        self.inner
            .state
            .lock()
            .expect("path state mutex poisoned")
            .current()
    }

    pub fn selected(&self) -> Option<SelectedPath> {
        self.inner
            .selected
            .lock()
            .expect("selected path mutex poisoned")
            .clone()
    }

    pub fn events(&self) -> Vec<PathEvent> {
        self.inner
            .events
            .lock()
            .expect("path event mutex poisoned")
            .iter()
            .cloned()
            .collect()
    }

    pub async fn connect(
        &self,
        attempts: Vec<Arc<dyn PathAttempt>>,
        caller_cancellation: CancellationToken,
    ) -> Result<SelectedPath, PathError> {
        self.inner.transition(PathState::Checking)?;
        self.select(attempts, caller_cancellation, PathState::Checking)
            .await
    }

    pub async fn report_failed(
        &self,
        attempts: Vec<Arc<dyn PathAttempt>>,
        caller_cancellation: CancellationToken,
    ) -> Result<SelectedPath, PathError> {
        self.inner.transition(PathState::Rechecking)?;
        self.select(attempts, caller_cancellation, PathState::Rechecking)
            .await
    }

    pub fn close(&self) -> Result<(), PathError> {
        self.inner.transition(PathState::Closed)?;
        self.inner.record(PathEvent::Closed);
        self.cancellation.cancel();
        Ok(())
    }

    async fn select(
        &self,
        attempts: Vec<Attempt>,
        caller_cancellation: CancellationToken,
        expected_state: PathState,
    ) -> Result<SelectedPath, PathError> {
        debug_assert_eq!(self.state(), expected_state);
        let direct_attempts: Vec<_> = attempts
            .iter()
            .filter(|attempt| attempt.kind().is_direct())
            .cloned()
            .collect();
        let selected = race::race_attempts(
            attempts,
            self.config,
            caller_cancellation.clone(),
            self.cancellation.clone(),
            self.inner.events.clone(),
        )
        .await?;
        let next = if selected.kind().is_direct() {
            PathState::Direct
        } else {
            PathState::Relay
        };
        self.inner.transition(next)?;
        self.inner.set_selected(selected.clone());
        self.inner.record(PathEvent::Selected(selected.kind()));
        if next == PathState::Relay {
            self.inner.record(PathEvent::RelayFallback);
            health::spawn_rechecks(
                Arc::downgrade(&self.inner),
                self.config,
                direct_attempts,
                caller_cancellation,
                self.cancellation.clone(),
            );
        }
        Ok(selected)
    }
}

impl Drop for PathManager {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
