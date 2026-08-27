use std::time::{Duration, Instant};

use rand::Rng;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffConfig {
    pub initial_delay: Duration,
    pub maximum_delay: Duration,
    /// Additive jitter radius around the capped exponential delay.
    pub jitter: Duration,
    pub stable_connection_reset_after: Duration,
}

pub trait JitterSource {
    /// Samples an offset in `0..=upper_inclusive_nanoseconds`.
    fn sample(&mut self, upper_inclusive_nanoseconds: u128) -> u128;
}

pub trait BackoffClock {
    /// Returns monotonic time elapsed from a clock-specific origin.
    fn now(&self) -> Duration;
}

#[derive(Debug, Default)]
pub struct RandomJitter;

impl JitterSource for RandomJitter {
    fn sample(&mut self, upper_inclusive_nanoseconds: u128) -> u128 {
        rand::rng().random_range(0..=upper_inclusive_nanoseconds)
    }
}

#[derive(Debug, Clone)]
pub struct SystemBackoffClock {
    origin: Instant,
}

impl Default for SystemBackoffClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl BackoffClock for SystemBackoffClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

#[derive(Debug)]
pub struct Backoff<J = RandomJitter, C = SystemBackoffClock> {
    config: BackoffConfig,
    jitter_source: J,
    clock: C,
    next_exponential_delay: Duration,
    connected_since: Option<Duration>,
    completed_connection_was_stable: bool,
}

impl Backoff<RandomJitter, SystemBackoffClock> {
    pub fn new(config: BackoffConfig) -> Result<Self, BackoffError> {
        Self::with_sources(config, RandomJitter, SystemBackoffClock::default())
    }
}

impl<J: JitterSource, C: BackoffClock> Backoff<J, C> {
    pub fn with_sources(
        config: BackoffConfig,
        jitter_source: J,
        clock: C,
    ) -> Result<Self, BackoffError> {
        if config.initial_delay.is_zero()
            || config.initial_delay > config.maximum_delay
            || config.stable_connection_reset_after.is_zero()
        {
            return Err(BackoffError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            jitter_source,
            clock,
            next_exponential_delay: config.initial_delay,
            connected_since: None,
            completed_connection_was_stable: false,
        })
    }

    /// Records the start of an active authenticated connection.
    pub fn mark_connected(&mut self) {
        self.connected_since = Some(self.clock.now());
        self.completed_connection_was_stable = false;
    }

    /// Freezes the duration of the current active connection at control loss.
    /// Time spent draining connection-owned work must not contribute to stability.
    pub fn mark_disconnected(&mut self) {
        if let Some(connected_since) = self.connected_since.take() {
            self.completed_connection_was_stable = self.clock.now().saturating_sub(connected_since)
                >= self.config.stable_connection_reset_after;
        }
    }

    /// Returns the next capped exponential delay with bounded jitter.
    ///
    /// If the most recent active connection met the configured stability
    /// threshold, this call first resets the exponential attempt state.
    pub fn next_delay(&mut self) -> Duration {
        let active_connection_was_stable = self.connected_since.take().is_some_and(|since| {
            self.clock.now().saturating_sub(since) >= self.config.stable_connection_reset_after
        });
        let completed_connection_was_stable = self.completed_connection_was_stable;
        self.completed_connection_was_stable = false;
        if active_connection_was_stable || completed_connection_was_stable {
            self.reset_attempts();
        }

        let exponential = self.next_exponential_delay;
        self.next_exponential_delay = exponential.saturating_mul(2).min(self.config.maximum_delay);

        let lower = exponential.saturating_sub(self.config.jitter);
        let upper = exponential
            .saturating_add(self.config.jitter)
            .min(self.config.maximum_delay);
        let span = upper.saturating_sub(lower).as_nanos();
        let offset = self.jitter_source.sample(span).min(span);
        lower.saturating_add(duration_from_nanos(offset))
    }

    pub fn reset_attempts(&mut self) {
        self.next_exponential_delay = self.config.initial_delay;
        self.connected_since = None;
        self.completed_connection_was_stable = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BackoffError {
    #[error("invalid backoff configuration")]
    InvalidConfiguration,
}

fn duration_from_nanos(nanoseconds: u128) -> Duration {
    let seconds = (nanoseconds / 1_000_000_000) as u64;
    let subsecond_nanoseconds = (nanoseconds % 1_000_000_000) as u32;
    Duration::new(seconds, subsecond_nanoseconds)
}
