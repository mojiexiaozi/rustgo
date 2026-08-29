use std::{sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::{
    ManagerInner, OwnedRecheck, PathError, PathState, RecheckAttemptFactory, install_winner,
    race::race_attempts,
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

pub(crate) async fn start_recheck(
    inner: Arc<ManagerInner>,
    factory: Arc<dyn RecheckAttemptFactory>,
    caller_cancellation: CancellationToken,
) {
    loop {
        let finished = {
            let mut record = inner.record.lock().expect("path record mutex poisoned");
            if record.state.current() != PathState::Relay {
                return;
            }
            match record.recheck.as_ref() {
                Some(recheck) if !recheck.handle.is_finished() => return,
                Some(_) => record.recheck.take(),
                None => {
                    let id = record.next_recheck_id;
                    record.next_recheck_id = record.next_recheck_id.wrapping_add(1).max(1);
                    let cancellation = inner.lifetime.child_token();
                    let task_cancellation = cancellation.clone();
                    let weak = Arc::downgrade(&inner);
                    let factory = factory.clone();
                    let caller = caller_cancellation.clone();
                    let config = inner.config;
                    let handle = tokio::spawn(async move {
                        recheck_loop(weak, id, config, factory, caller, task_cancellation).await;
                    });
                    record.recheck = Some(OwnedRecheck {
                        id,
                        cancellation,
                        handle,
                    });
                    return;
                }
            }
        };
        if let Some(finished) = finished {
            finished.shutdown().await;
        }
    }
}

async fn recheck_loop(
    manager: std::sync::Weak<ManagerInner>,
    id: u64,
    config: PathManagerConfig,
    factory: Arc<dyn RecheckAttemptFactory>,
    caller_cancellation: CancellationToken,
    recheck_cancellation: CancellationToken,
) {
    let mut generation = 1_u64;
    loop {
        tokio::select! {
            biased;
            () = caller_cancellation.cancelled() => return,
            () = recheck_cancellation.cancelled() => return,
            () = tokio::time::sleep(config.recheck_interval()) => {}
        }

        let Some(inner) = manager.upgrade() else {
            return;
        };
        if !inner.begin_background_recheck(id) {
            return;
        }
        let attempts = tokio::select! {
            biased;
            () = caller_cancellation.cancelled() => return,
            () = recheck_cancellation.cancelled() => return,
            result = factory.create(generation, recheck_cancellation.child_token()) => result,
        };
        generation = generation.wrapping_add(1).max(1);
        let direct_attempts = match attempts {
            Ok(attempts) if !attempts.is_empty() => attempts,
            Ok(_) | Err(PathError::Cancelled) => return,
            Err(_) => {
                if !inner.finish_failed_recheck(id) {
                    return;
                }
                continue;
            }
        };
        let winner = race_attempts(
            direct_attempts,
            config,
            caller_cancellation.clone(),
            recheck_cancellation.clone(),
            inner.clone(),
        )
        .await;
        match winner {
            Ok(winner) => {
                let _ = install_winner(
                    &inner,
                    PathState::Rechecking,
                    Some(id),
                    winner,
                    caller_cancellation.clone(),
                )
                .await;
                return;
            }
            Err(PathError::Cancelled) => return,
            Err(_) => {
                if !inner.finish_failed_recheck(id) {
                    return;
                }
            }
        }
    }
}
