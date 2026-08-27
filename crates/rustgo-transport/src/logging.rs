use std::{
    fmt,
    sync::Mutex,
    time::{Duration, Instant},
};

use time::{OffsetDateTime, macros::format_description};
use tracing_subscriber::{
    EnvFilter,
    fmt::{self as tracing_fmt, format::Writer, time::FormatTime},
    prelude::*,
};

/// Initializes Rustgo's human-readable, single-line diagnostic output.
///
/// A global subscriber can only be installed once. Callers intentionally ignore a
/// repeated-init error so tests and embedded callers remain isolated.
pub fn init() {
    let _ = try_init();
}

/// Installs the Rustgo diagnostic subscriber.
pub fn try_init() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        // Dependency trace events may serialize handshake internals. Rustgo's
        // trace level is useful, but third-party wire traces are never operator
        // diagnostics and must not become a secret-disclosure path.
        .add_directive("rustls=warn".parse()?);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_fmt::layer()
                .compact()
                .with_ansi(false)
                .with_target(false)
                .with_timer(OffsetTimestamp),
        )
        .try_init()?;
    Ok(())
}

/// Reduces a public-key fingerprint to a stable, operator-friendly identifier.
#[must_use]
pub fn short_fingerprint(fingerprint: &str) -> String {
    let value = fingerprint.strip_prefix("sha256:").unwrap_or(fingerprint);
    let prefix: String = value.chars().take(12).collect();
    format!("sha256:{prefix}")
}

/// Escapes control characters before an untrusted value is used in a text log.
#[must_use]
pub fn safe_context(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            for byte in character.escape_default() {
                escaped.push(byte);
            }
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// A constant-memory limiter for repeated diagnostic events.
pub struct EventRateLimit {
    interval: Duration,
    last: Mutex<Option<Instant>>,
}

impl EventRateLimit {
    #[must_use]
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: Mutex::new(None),
        }
    }

    pub fn allow(&self) -> bool {
        let Ok(mut last) = self.last.lock() else {
            return false;
        };
        let now = Instant::now();
        if last.is_none_or(|previous| now.duration_since(previous) >= self.interval) {
            *last = Some(now);
            true
        } else {
            false
        }
    }
}

struct OffsetTimestamp;

impl FormatTime for OffsetTimestamp {
    fn format_time(&self, writer: &mut Writer<'_>) -> fmt::Result {
        let rendered = OffsetDateTime::now_utc()
            .format(&format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3][offset_hour sign:mandatory]:[offset_minute]"))
            .map_err(|_| fmt::Error)?;
        writer.write_str(&rendered)
    }
}
