use std::sync::Arc;

use tokio::{
    task::{Id, JoinSet},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    ManagerInner, PathAttempt, PathError, PathEvent, PathKind, PathManagerConfig, SelectedPath,
};

type Attempt = Arc<dyn PathAttempt>;
type AttemptResult = (usize, PathKind, Result<SelectedPath, PathError>);

pub(crate) struct RaceWinner {
    pub(crate) path: SelectedPath,
    pub(crate) cancellation: CancellationToken,
}

struct RunningAttempt {
    id: usize,
    task_id: Id,
    kind: PathKind,
    cancellation: CancellationToken,
}

pub(crate) async fn race_attempts(
    attempts: Vec<Attempt>,
    config: PathManagerConfig,
    caller_cancellation: CancellationToken,
    operation_cancellation: CancellationToken,
    manager: Arc<ManagerInner>,
) -> Result<RaceWinner, PathError> {
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
            &manager,
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
                &manager,
            );
        }

        if direct_active == 0 && relay_started && relay_active == 0 {
            cleanup(&mut tasks, &running).await;
            return Err(PathError::NoViablePath);
        }

        tokio::select! {
            biased;
            () = caller_cancellation.cancelled() => {
                cleanup(&mut tasks, &running).await;
                return Err(PathError::Cancelled);
            }
            () = operation_cancellation.cancelled() => {
                cleanup(&mut tasks, &running).await;
                return Err(PathError::Cancelled);
            }
            () = manager.lifetime.cancelled() => {
                cleanup(&mut tasks, &running).await;
                return Err(PathError::Cancelled);
            }
            () = tokio::time::sleep_until(relay_start), if !relay_started => {}
            outcome = tasks.join_next_with_id(), if !tasks.is_empty() => {
                match outcome {
                    Some(Ok((_task_id, (id, kind, result)))) => {
                        let Some(position) = running.iter().position(|entry| entry.id == id) else {
                            continue;
                        };
                        let completed = running.swap_remove(position);
                        decrement_active(kind, &mut direct_active, &mut relay_active);
                        match result {
                            Ok(path) if path.kind() == kind => {
                                let winner = resolve_ready_ties(
                                    id,
                                    RaceWinner {
                                        path,
                                        cancellation: completed.cancellation,
                                    },
                                    &mut tasks,
                                    &mut running,
                                    &manager,
                                )
                                .await;
                                cleanup(&mut tasks, &running).await;
                                return Ok(winner);
                            }
                            Ok(_) | Err(_) => {
                                completed.cancellation.cancel();
                                manager.record_event(PathEvent::AttemptFailed(kind));
                            }
                        }
                    }
                    Some(Err(error)) => {
                        let task_id = error.id();
                        if let Some(position) = running.iter().position(|entry| entry.task_id == task_id) {
                            let failed = running.swap_remove(position);
                            failed.cancellation.cancel();
                            decrement_active(failed.kind, &mut direct_active, &mut relay_active);
                            manager.record_event(PathEvent::AttemptFailed(failed.kind));
                        }
                    }
                    None => {
                        cleanup(&mut tasks, &running).await;
                        return Err(PathError::NoViablePath);
                    }
                }
            }
        }
    }
}

async fn resolve_ready_ties(
    mut winner_id: usize,
    mut winner: RaceWinner,
    tasks: &mut JoinSet<AttemptResult>,
    running: &mut Vec<RunningAttempt>,
    manager: &Arc<ManagerInner>,
) -> RaceWinner {
    tokio::task::yield_now().await;
    while let Some(outcome) = tasks.try_join_next_with_id() {
        match outcome {
            Ok((_task_id, (id, kind, result))) => {
                let Some(position) = running.iter().position(|entry| entry.id == id) else {
                    continue;
                };
                let completed = running.swap_remove(position);
                match result {
                    Ok(path) if path.kind() == kind => {
                        if id < winner_id {
                            winner.cancellation.cancel();
                            winner_id = id;
                            winner = RaceWinner {
                                path,
                                cancellation: completed.cancellation,
                            };
                        } else {
                            completed.cancellation.cancel();
                        }
                    }
                    Ok(_) | Err(_) => {
                        completed.cancellation.cancel();
                        manager.record_event(PathEvent::AttemptFailed(kind));
                    }
                }
            }
            Err(error) => {
                let task_id = error.id();
                if let Some(position) = running.iter().position(|entry| entry.task_id == task_id) {
                    let failed = running.swap_remove(position);
                    failed.cancellation.cancel();
                    manager.record_event(PathEvent::AttemptFailed(failed.kind));
                }
            }
        }
    }
    winner
}

fn spawn_group(
    group: Vec<Attempt>,
    tasks: &mut JoinSet<AttemptResult>,
    running: &mut Vec<RunningAttempt>,
    next_id: &mut usize,
    deadline: Instant,
    manager: &Arc<ManagerInner>,
) {
    for attempt in group {
        let id = *next_id;
        *next_id += 1;
        let kind = attempt.kind();
        let cancellation = manager.lifetime.child_token();
        manager.record_event(PathEvent::AttemptStarted(kind));
        let task_cancellation = cancellation.clone();
        let abort = tasks.spawn(async move {
            let result =
                match tokio::time::timeout_at(deadline, attempt.connect(task_cancellation.clone()))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        task_cancellation.cancel();
                        Err(PathError::AttemptTimedOut(kind))
                    }
                };
            (id, kind, result)
        });
        running.push(RunningAttempt {
            id,
            task_id: abort.id(),
            kind,
            cancellation,
        });
    }
}

async fn cleanup(tasks: &mut JoinSet<AttemptResult>, running: &[RunningAttempt]) {
    for attempt in running {
        attempt.cancellation.cancel();
    }
    tokio::task::yield_now().await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

fn decrement_active(kind: PathKind, direct_active: &mut usize, relay_active: &mut usize) {
    if kind == PathKind::Relay {
        *relay_active = relay_active.saturating_sub(1);
    } else {
        *direct_active = direct_active.saturating_sub(1);
    }
}

const fn group_index(kind: PathKind) -> usize {
    match kind {
        PathKind::QuicV6 => 0,
        PathKind::QuicV4 => 1,
        PathKind::NativeTcp => 2,
        PathKind::Relay => 3,
    }
}
