use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use rustgo_path::{
    PathAttempt, PathError, PathEvent, PathKind, PathManager, PathManagerConfig, PathState,
    SelectedPath,
};
use tokio::task::yield_now;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
enum Outcome {
    SuccessAfter(Duration),
    SuccessAsAfter(Duration, PathKind),
    FailAfter(Duration),
    Hang,
    Panic,
}

struct FakeAttempt {
    kind: PathKind,
    outcomes: Mutex<VecDeque<Outcome>>,
    starts: AtomicUsize,
    active: Arc<AtomicUsize>,
    cancelled: AtomicBool,
    dropped: Arc<AtomicUsize>,
}

impl FakeAttempt {
    fn new(kind: PathKind, outcomes: impl IntoIterator<Item = Outcome>) -> Arc<Self> {
        Arc::new(Self {
            kind,
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            starts: AtomicUsize::new(0),
            active: Arc::new(AtomicUsize::new(0)),
            cancelled: AtomicBool::new(false),
            dropped: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn drop_probe(&self) -> Arc<AtomicUsize> {
        self.dropped.clone()
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for FakeAttempt {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl PathAttempt for FakeAttempt {
    fn kind(&self) -> PathKind {
        self.kind
    }

    async fn connect(&self, cancellation: CancellationToken) -> Result<SelectedPath, PathError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveGuard(self.active.clone());
        let outcome = self
            .outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Outcome::Hang);
        let attempt = async {
            match outcome {
                Outcome::SuccessAfter(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(SelectedPath::authenticated(self.kind))
                }
                Outcome::SuccessAsAfter(delay, kind) => {
                    tokio::time::sleep(delay).await;
                    Ok(SelectedPath::authenticated(kind))
                }
                Outcome::FailAfter(delay) => {
                    tokio::time::sleep(delay).await;
                    Err(PathError::AttemptFailed(self.kind))
                }
                Outcome::Hang => std::future::pending().await,
                Outcome::Panic => panic!("fake attempt panic"),
            }
        };

        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                self.cancelled.store(true, Ordering::SeqCst);
                Err(PathError::Cancelled)
            }
            result = attempt => result,
        }
    }
}

fn config() -> PathManagerConfig {
    PathManagerConfig::new(
        Duration::from_secs(8),
        Duration::from_secs(2),
        Duration::from_secs(3),
        Duration::from_secs(30),
    )
    .unwrap()
}

async fn settle() {
    for _ in 0..8 {
        yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn direct_groups_start_in_v6_v4_tcp_priority_order_before_relay() {
    let v6 = FakeAttempt::new(PathKind::QuicV6, [Outcome::Hang]);
    let v4 = FakeAttempt::new(PathKind::QuicV4, [Outcome::Hang]);
    let tcp = FakeAttempt::new(PathKind::NativeTcp, [Outcome::Hang]);
    let relay = FakeAttempt::new(PathKind::Relay, [Outcome::Hang]);
    let manager = Arc::new(PathManager::new(config()));
    let caller = CancellationToken::new();
    let task_manager = manager.clone();
    let task_relay = relay.clone();
    let task_tcp = tcp.clone();
    let task_v4 = v4.clone();
    let task_v6 = v6.clone();
    let task_caller = caller.clone();
    let connect = tokio::spawn(async move {
        task_manager
            .connect(vec![task_relay, task_tcp, task_v4, task_v6], task_caller)
            .await
    });

    settle().await;
    assert_eq!(v6.starts(), 1);
    assert_eq!(v4.starts(), 1);
    assert_eq!(tcp.starts(), 1);
    assert_eq!(relay.starts(), 0);
    assert_eq!(
        &manager.events()[1..4],
        &[
            PathEvent::AttemptStarted(PathKind::QuicV6),
            PathEvent::AttemptStarted(PathKind::QuicV4),
            PathEvent::AttemptStarted(PathKind::NativeTcp),
        ]
    );
    caller.cancel();
    assert_eq!(connect.await.unwrap().unwrap_err(), PathError::Cancelled);
}

#[tokio::test(start_paused = true)]
async fn first_authenticated_direct_completion_wins_across_priority_groups() {
    let v6 = FakeAttempt::new(PathKind::QuicV6, [Outcome::Hang]);
    let v4 = FakeAttempt::new(
        PathKind::QuicV4,
        [Outcome::SuccessAfter(Duration::from_secs(1))],
    );
    let tcp = FakeAttempt::new(
        PathKind::NativeTcp,
        [Outcome::SuccessAfter(Duration::from_secs(2))],
    );
    let manager = Arc::new(PathManager::new(config()));
    let task_manager = manager.clone();
    let task_tcp = tcp.clone();
    let task_v4 = v4.clone();
    let task_v6 = v6.clone();
    let connect = tokio::spawn(async move {
        task_manager
            .connect(vec![task_tcp, task_v4, task_v6], CancellationToken::new())
            .await
    });

    settle().await;
    assert_eq!(v4.starts(), 1);
    assert_eq!(tcp.starts(), 1);
    tokio::time::advance(Duration::from_secs(1)).await;

    assert_eq!(connect.await.unwrap().unwrap().kind(), PathKind::QuicV4);
    assert!(v6.is_cancelled());
    assert!(tcp.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn relay_waits_for_grace_then_can_win_while_direct_hangs() {
    let direct = FakeAttempt::new(PathKind::QuicV6, [Outcome::Hang]);
    let relay = FakeAttempt::new(PathKind::Relay, [Outcome::SuccessAfter(Duration::ZERO)]);
    let manager = Arc::new(PathManager::new(config()));
    let task_manager = manager.clone();
    let task_direct = direct.clone();
    let task_relay = relay.clone();
    let connect = tokio::spawn(async move {
        task_manager
            .connect(vec![task_direct, task_relay], CancellationToken::new())
            .await
    });

    settle().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    settle().await;
    assert_eq!(relay.starts(), 0);
    tokio::time::advance(Duration::from_secs(1)).await;
    let selected = connect.await.unwrap().unwrap();

    assert_eq!(selected.kind(), PathKind::Relay);
    assert!(direct.is_cancelled());
    assert_eq!(direct.active.load(Ordering::SeqCst), 0);
    assert_eq!(manager.state(), PathState::Relay);
}

#[tokio::test(start_paused = true)]
async fn first_authenticated_winner_cancels_and_joins_same_group_losers_only() {
    let winner = FakeAttempt::new(
        PathKind::QuicV6,
        [Outcome::SuccessAfter(Duration::from_secs(1))],
    );
    let loser = FakeAttempt::new(PathKind::QuicV6, [Outcome::Hang]);
    let manager = Arc::new(PathManager::new(config()));
    let caller = CancellationToken::new();
    let task_manager = manager.clone();
    let task_caller = caller.clone();
    let task_loser = loser.clone();
    let task_winner = winner.clone();
    let connect = tokio::spawn(async move {
        task_manager
            .connect(vec![task_loser, task_winner], task_caller)
            .await
    });

    settle().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(connect.await.unwrap().unwrap().kind(), PathKind::QuicV6);

    assert!(loser.is_cancelled());
    assert!(!winner.is_cancelled());
    assert!(!caller.is_cancelled());
    assert_eq!(loser.active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn all_hung_attempts_finish_within_the_configured_bound() {
    let direct = FakeAttempt::new(PathKind::QuicV6, [Outcome::Hang]);
    let relay = FakeAttempt::new(PathKind::Relay, [Outcome::Hang]);
    let manager = Arc::new(PathManager::new(config()));
    let task_manager = manager.clone();
    let task_direct = direct.clone();
    let task_relay = relay.clone();
    let connect = tokio::spawn(async move {
        task_manager
            .connect(vec![task_direct, task_relay], CancellationToken::new())
            .await
    });

    settle().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    let error = connect.await.unwrap().unwrap_err();

    assert_eq!(error, PathError::NoViablePath);
    assert_eq!(direct.active.load(Ordering::SeqCst), 0);
    assert_eq!(relay.active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn caller_cancellation_stops_and_joins_every_attempt() {
    let direct = FakeAttempt::new(PathKind::QuicV6, [Outcome::Hang]);
    let manager = Arc::new(PathManager::new(config()));
    let caller = CancellationToken::new();
    let task_manager = manager.clone();
    let task_caller = caller.clone();
    let task_direct = direct.clone();
    let connect =
        tokio::spawn(async move { task_manager.connect(vec![task_direct], task_caller).await });

    settle().await;
    caller.cancel();
    assert_eq!(connect.await.unwrap().unwrap_err(), PathError::Cancelled);
    assert!(direct.is_cancelled());
    assert_eq!(direct.active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn panicking_attempt_still_cancels_and_joins_its_peers() {
    let panic_attempt = FakeAttempt::new(PathKind::QuicV6, [Outcome::Panic]);
    let loser = FakeAttempt::new(PathKind::QuicV6, [Outcome::Hang]);
    let manager = PathManager::new(config());

    let error = manager
        .connect(vec![panic_attempt, loser.clone()], CancellationToken::new())
        .await
        .unwrap_err();

    assert_eq!(error, PathError::AttemptTaskFailed);
    assert!(loser.is_cancelled());
    assert_eq!(loser.active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn mismatched_adapter_result_cannot_suppress_a_valid_relay() {
    let malformed = FakeAttempt::new(
        PathKind::QuicV6,
        [Outcome::SuccessAsAfter(
            Duration::from_secs(3),
            PathKind::Relay,
        )],
    );
    let relay = FakeAttempt::new(
        PathKind::Relay,
        [Outcome::SuccessAfter(Duration::from_secs(2))],
    );
    let manager = PathManager::new(config());

    let selected = manager
        .connect(vec![malformed, relay], CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(selected.kind(), PathKind::Relay);
    assert_eq!(manager.state(), PathState::Relay);
}

#[tokio::test(start_paused = true)]
async fn direct_failure_reports_rechecking_then_falls_back_to_relay() {
    let initial = FakeAttempt::new(PathKind::QuicV6, [Outcome::SuccessAfter(Duration::ZERO)]);
    let manager = PathManager::new(config());
    manager
        .connect(vec![initial], CancellationToken::new())
        .await
        .unwrap();
    let retry_direct = FakeAttempt::new(PathKind::QuicV6, [Outcome::FailAfter(Duration::ZERO)]);
    let relay = FakeAttempt::new(PathKind::Relay, [Outcome::SuccessAfter(Duration::ZERO)]);

    let selected = manager
        .report_failed(vec![retry_direct, relay], CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(selected.kind(), PathKind::Relay);
    assert_eq!(manager.state(), PathState::Relay);
    assert!(manager.events().windows(2).any(|events| events
        == [
            PathEvent::StateChanged {
                from: PathState::Direct,
                to: PathState::Rechecking,
            },
            PathEvent::AttemptStarted(PathKind::QuicV6),
        ]));
    assert!(manager.events().contains(&PathEvent::RelayFallback));
}

#[tokio::test(start_paused = true)]
async fn relay_low_rate_recheck_promotes_a_new_authenticated_direct_path() {
    let direct = FakeAttempt::new(
        PathKind::QuicV6,
        [
            Outcome::FailAfter(Duration::ZERO),
            Outcome::SuccessAfter(Duration::ZERO),
        ],
    );
    let relay = FakeAttempt::new(PathKind::Relay, [Outcome::SuccessAfter(Duration::ZERO)]);
    let manager = PathManager::new(config());

    assert_eq!(
        manager
            .connect(vec![direct.clone(), relay], CancellationToken::new(),)
            .await
            .unwrap()
            .kind(),
        PathKind::Relay
    );
    assert_eq!(direct.starts(), 1);
    settle().await;

    tokio::time::advance(Duration::from_secs(29)).await;
    settle().await;
    assert_eq!(direct.starts(), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    settle().await;

    assert_eq!(direct.starts(), 2);
    assert_eq!(manager.state(), PathState::Direct);
    assert_eq!(manager.selected().unwrap().kind(), PathKind::QuicV6);
    assert!(
        manager
            .events()
            .contains(&PathEvent::Promoted(PathKind::QuicV6))
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_races_drop_every_attempt_and_background_recheck() {
    for _ in 0..64 {
        let direct = FakeAttempt::new(PathKind::QuicV6, [Outcome::FailAfter(Duration::ZERO)]);
        let relay = FakeAttempt::new(PathKind::Relay, [Outcome::SuccessAfter(Duration::ZERO)]);
        let direct_drop = direct.drop_probe();
        let relay_drop = relay.drop_probe();
        let manager = PathManager::new(config());

        manager
            .connect(
                vec![direct.clone(), relay.clone()],
                CancellationToken::new(),
            )
            .await
            .unwrap();
        settle().await;
        drop(manager);
        drop(direct);
        drop(relay);
        settle().await;

        assert_eq!(direct_drop.load(Ordering::SeqCst), 1);
        assert_eq!(relay_drop.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn repeated_failed_rechecks_keep_the_diagnostic_event_buffer_bounded() {
    let direct = FakeAttempt::new(
        PathKind::QuicV6,
        std::iter::repeat_n(Outcome::FailAfter(Duration::ZERO), 130),
    );
    let relay = FakeAttempt::new(PathKind::Relay, [Outcome::SuccessAfter(Duration::ZERO)]);
    let manager = PathManager::new(
        PathManagerConfig::new(
            Duration::from_secs(8),
            Duration::from_secs(2),
            Duration::from_secs(3),
            Duration::from_secs(1),
        )
        .unwrap(),
    );

    manager
        .connect(vec![direct, relay], CancellationToken::new())
        .await
        .unwrap();
    settle().await;
    for _ in 0..200 {
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
    }

    let event_count = manager.events().len();
    assert!(event_count <= 256, "recorded {event_count} events");
}

#[test]
fn configuration_rejects_unbounded_or_inverted_timing() {
    assert_eq!(
        PathManagerConfig::new(
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(30),
        ),
        Err(PathError::InvalidConfiguration)
    );
    assert_eq!(
        PathManagerConfig::new(
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::ZERO,
            Duration::from_secs(30),
        ),
        Err(PathError::InvalidConfiguration)
    );
}
