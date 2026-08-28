use std::sync::Arc;

use tokio::{task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::{
    PathAttempt, PathError, PathEvent, PathKind, PathManagerConfig, SelectedPath, SharedEvents,
    record_event,
};

type Attempt = Arc<dyn PathAttempt>;

struct RunningAttempt {
    id: usize,
    cancellation: CancellationToken,
}

pub(crate) async fn race_attempts(
    attempts: Vec<Attempt>,
    config: PathManagerConfig,
    caller_cancellation: CancellationToken,
    manager_cancellation: CancellationToken,
    events: SharedEvents,
) -> Result<SelectedPath, PathError> {
    let mut groups: [Vec<Attempt>; 4] = std::array::from_fn(|_| Vec::new());
    for attempt in attempts {
        groups[group_index(attempt.kind())].push(attempt);
    }

    let has_direct = groups[..3].iter().any(|group| !group.is_empty());
    let direct_groups: Vec<Vec<Attempt>> = groups[..3]
        .iter_mut()
        .map(std::mem::take)
        .filter(|group| !group.is_empty())
        .collect();
    let relay_group = std::mem::take(&mut groups[3]);

    let now = Instant::now();
    let direct_deadline = now + config.direct_timeout();
    let relay_start = if has_direct {
        now + config.relay_grace()
    } else {
        now
    };

    let mut tasks = JoinSet::new();
    let mut running = Vec::<RunningAttempt>::new();
    let mut next_id = 0usize;
    let mut direct_active = 0usize;
    let mut relay_active = 0usize;
    let mut relay_started = false;

    let direct_attempt_deadline =
        std::cmp::min(direct_deadline, Instant::now() + config.attempt_timeout());
    for group in direct_groups {
        direct_active += group.len();
        spawn_group(
            group,
            &mut tasks,
            &mut running,
            &mut next_id,
            direct_attempt_deadline,
            &caller_cancellation,
            &events,
        );
    }

    loop {
        if !relay_started && Instant::now() >= relay_start {
            relay_started = true;
            relay_active = relay_group.len();
            spawn_group(
                relay_group.clone(),
                &mut tasks,
                &mut running,
                &mut next_id,
                Instant::now() + config.attempt_timeout(),
                &caller_cancellation,
                &events,
            );
        }

        let direct_done = direct_active == 0;
        let relay_done = relay_started && relay_active == 0;
        if direct_done && relay_done {
            cleanup(&mut tasks, &running).await;
            return Err(PathError::NoViablePath);
        }

        tokio::select! {
            biased;
            () = caller_cancellation.cancelled() => {
                cleanup(&mut tasks, &running).await;
                return Err(PathError::Cancelled);
            }
            () = manager_cancellation.cancelled() => {
                cleanup(&mut tasks, &running).await;
                return Err(PathError::Cancelled);
            }
            () = tokio::time::sleep_until(relay_start), if !relay_started => {}
            outcome = tasks.join_next(), if !tasks.is_empty() => {
                let Some(outcome) = outcome else {
                    cleanup(&mut tasks, &running).await;
                    return Err(PathError::NoViablePath);
                };
                let (id, kind, result) = match outcome {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        cleanup(&mut tasks, &running).await;
                        return Err(PathError::AttemptTaskFailed);
                    }
                };
                running.retain(|entry| entry.id != id);
                if kind == PathKind::Relay {
                    relay_active = relay_active.saturating_sub(1);
                } else {
                    direct_active = direct_active.saturating_sub(1);
                }

                match result {
                    Ok(selected) if selected.kind() == kind => {
                        cleanup(&mut tasks, &running).await;
                        return Ok(selected);
                    }
                    Ok(_) => {
                        record(&events, PathEvent::AttemptFailed(kind));
                    }
                    Err(_) => record(&events, PathEvent::AttemptFailed(kind)),
                }
            }
        }
    }
}

fn spawn_group(
    group: Vec<Attempt>,
    tasks: &mut JoinSet<(usize, PathKind, Result<SelectedPath, PathError>)>,
    running: &mut Vec<RunningAttempt>,
    next_id: &mut usize,
    deadline: Instant,
    caller_cancellation: &CancellationToken,
    events: &SharedEvents,
) {
    for attempt in group {
        let id = *next_id;
        *next_id += 1;
        let kind = attempt.kind();
        let cancellation = caller_cancellation.child_token();
        running.push(RunningAttempt {
            id,
            cancellation: cancellation.clone(),
        });
        record(events, PathEvent::AttemptStarted(kind));
        tasks.spawn(async move {
            let result = match tokio::time::timeout_at(
                deadline,
                attempt.connect(cancellation.clone()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    cancellation.cancel();
                    Err(PathError::AttemptTimedOut(kind))
                }
            };
            (id, kind, result)
        });
    }
}

async fn cleanup(
    tasks: &mut JoinSet<(usize, PathKind, Result<SelectedPath, PathError>)>,
    running: &[RunningAttempt],
) {
    for attempt in running {
        attempt.cancellation.cancel();
    }
    tokio::task::yield_now().await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

const fn group_index(kind: PathKind) -> usize {
    match kind {
        PathKind::QuicV6 => 0,
        PathKind::QuicV4 => 1,
        PathKind::NativeTcp => 2,
        PathKind::Relay => 3,
    }
}

fn record(events: &SharedEvents, event: PathEvent) {
    record_event(events, event);
}
