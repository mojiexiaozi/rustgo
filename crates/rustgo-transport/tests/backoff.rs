use std::cell::Cell;
use std::error::Error;
use std::rc::Rc;
use std::time::Duration;

use rustgo_transport::{Backoff, BackoffClock, BackoffConfig, BackoffError, JitterSource};

#[derive(Clone, Default)]
struct ManualClock(Rc<Cell<Duration>>);

impl ManualClock {
    fn advance(&self, duration: Duration) {
        self.0.set(self.0.get().saturating_add(duration));
    }
}

impl BackoffClock for ManualClock {
    fn now(&self) -> Duration {
        self.0.get()
    }
}

struct MinimumJitter;

impl JitterSource for MinimumJitter {
    fn sample(&mut self, _upper_inclusive_nanoseconds: u128) -> u128 {
        0
    }
}

struct MaximumJitter;

impl JitterSource for MaximumJitter {
    fn sample(&mut self, upper_inclusive_nanoseconds: u128) -> u128 {
        upper_inclusive_nanoseconds
    }
}

fn config(jitter: Duration) -> BackoffConfig {
    BackoffConfig {
        initial_delay: Duration::from_millis(100),
        maximum_delay: Duration::from_millis(500),
        jitter,
        stable_connection_reset_after: Duration::from_secs(10),
    }
}

#[test]
fn exponential_delay_grows_to_cap() -> Result<(), Box<dyn Error>> {
    let mut backoff = Backoff::with_sources(
        config(Duration::ZERO),
        MinimumJitter,
        ManualClock::default(),
    )?;

    let actual = (0..7).map(|_| backoff.next_delay()).collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(500),
            Duration::from_millis(500),
            Duration::from_millis(500),
            Duration::from_millis(500),
        ]
    );
    Ok(())
}

#[test]
fn injected_jitter_stays_inside_configured_interval_and_total_cap() -> Result<(), Box<dyn Error>> {
    let jitter = Duration::from_millis(20);
    let clock = ManualClock::default();
    let mut minimum = Backoff::with_sources(config(jitter), MinimumJitter, clock.clone())?;
    let mut maximum = Backoff::with_sources(config(jitter), MaximumJitter, clock)?;

    assert_eq!(minimum.next_delay(), Duration::from_millis(80));
    assert_eq!(maximum.next_delay(), Duration::from_millis(120));

    for _ in 0..4 {
        let low = minimum.next_delay();
        let high = maximum.next_delay();
        assert!(low <= high);
        assert!(high <= Duration::from_millis(500));
    }
    assert_eq!(minimum.next_delay(), Duration::from_millis(480));
    assert_eq!(maximum.next_delay(), Duration::from_millis(500));
    Ok(())
}

#[test]
fn only_a_stable_active_connection_resets_attempts() -> Result<(), Box<dyn Error>> {
    let clock = ManualClock::default();
    let mut backoff = Backoff::with_sources(config(Duration::ZERO), MinimumJitter, clock.clone())?;

    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    assert_eq!(backoff.next_delay(), Duration::from_millis(200));

    backoff.mark_connected();
    clock.advance(Duration::from_secs(9));
    assert_eq!(backoff.next_delay(), Duration::from_millis(400));

    backoff.mark_connected();
    clock.advance(Duration::from_secs(10));
    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    Ok(())
}

#[test]
fn time_after_disconnect_cannot_make_a_short_connection_stable() -> Result<(), Box<dyn Error>> {
    let clock = ManualClock::default();
    let mut backoff = Backoff::with_sources(config(Duration::ZERO), MinimumJitter, clock.clone())?;

    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    assert_eq!(backoff.next_delay(), Duration::from_millis(200));
    backoff.mark_connected();
    clock.advance(Duration::from_secs(9));
    backoff.mark_disconnected();
    clock.advance(Duration::from_secs(100));

    assert_eq!(backoff.next_delay(), Duration::from_millis(400));
    Ok(())
}

#[test]
fn repeated_attempts_cannot_overflow_duration_or_counter() -> Result<(), Box<dyn Error>> {
    let huge = BackoffConfig {
        initial_delay: Duration::MAX / 3,
        maximum_delay: Duration::MAX,
        jitter: Duration::MAX,
        stable_connection_reset_after: Duration::from_secs(1),
    };
    let mut backoff = Backoff::with_sources(huge, MaximumJitter, ManualClock::default())?;

    for _ in 0..10_000 {
        assert!(backoff.next_delay() <= Duration::MAX);
    }
    Ok(())
}

#[test]
fn invalid_backoff_ranges_are_rejected() {
    let invalid = BackoffConfig {
        initial_delay: Duration::ZERO,
        maximum_delay: Duration::from_secs(1),
        jitter: Duration::ZERO,
        stable_connection_reset_after: Duration::from_secs(1),
    };
    assert!(matches!(
        Backoff::with_sources(invalid, MinimumJitter, ManualClock::default()),
        Err(BackoffError::InvalidConfiguration)
    ));

    let invalid = BackoffConfig {
        initial_delay: Duration::from_secs(2),
        maximum_delay: Duration::from_secs(1),
        jitter: Duration::ZERO,
        stable_connection_reset_after: Duration::from_secs(1),
    };
    assert!(matches!(
        Backoff::with_sources(invalid, MinimumJitter, ManualClock::default()),
        Err(BackoffError::InvalidConfiguration)
    ));
}
