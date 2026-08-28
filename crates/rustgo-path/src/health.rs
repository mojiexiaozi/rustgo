use std::{sync::Weak, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::{
    Attempt, ManagerInner, PathError, PathEvent, PathKind, PathState, race::race_attempts,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathManagerConfig {
    direct_timeout: Duration,
    relay_grace: Duration,
    attempt_timeout: Duration,
    recheck_interval: Duration,
}

impl PathManagerConfig {
    pub fn new(
        direct_timeout: Duration,
        relay_grace: Duration,
        attempt_timeout: Duration,
        recheck_interval: Duration,
    ) -> Result<Self, PathError> {
        if direct_timeout.is_zero()
            || relay_grace.is_zero()
            || relay_grace >= direct_timeout
            || attempt_timeout.is_zero()
            || recheck_interval.is_zero()
        {
            return Err(PathError::InvalidConfiguration);
        }
        Ok(Self {
            direct_timeout,
            relay_grace,
            attempt_timeout,
            recheck_interval,
        })
    }

    pub const fn direct_timeout(self) -> Duration {
        self.direct_timeout
    }

    pub const fn relay_grace(self) -> Duration {
        self.relay_grace
    }

    pub const fn attempt_timeout(self) -> Duration {
        self.attempt_timeout
    }

    pub const fn recheck_interval(self) -> Duration {
        self.recheck_interval
    }
}

pub(crate) fn spawn_rechecks(
    manager: Weak<ManagerInner>,
    config: PathManagerConfig,
    direct_attempts: Vec<Attempt>,
    caller_cancellation: CancellationToken,
    manager_cancellation: CancellationToken,
) {
    if direct_attempts.is_empty() {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = caller_cancellation.cancelled() => return,
                () = manager_cancellation.cancelled() => return,
                () = tokio::time::sleep(config.recheck_interval()) => {}
            }

            let Some(inner) = manager.upgrade() else {
                return;
            };
            if inner.transition(PathState::Rechecking).is_err() {
                return;
            }
            inner.record(PathEvent::RecheckStarted);
            let events = inner.events.clone();
            drop(inner);

            let outcome = race_attempts(
                direct_attempts.clone(),
                config,
                caller_cancellation.clone(),
                manager_cancellation.clone(),
                events,
            )
            .await;

            let Some(inner) = manager.upgrade() else {
                return;
            };
            match outcome {
                Ok(selected) if selected.kind() != PathKind::Relay => {
                    if inner.transition(PathState::Direct).is_err() {
                        return;
                    }
                    inner.set_selected(selected.clone());
                    inner.record(PathEvent::Promoted(selected.kind()));
                    return;
                }
                Err(PathError::Cancelled) => return,
                _ => {
                    if inner.transition(PathState::Relay).is_err() {
                        return;
                    }
                    inner.record(PathEvent::RecheckScheduled);
                }
            }
        }
    });
}
