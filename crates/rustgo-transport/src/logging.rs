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
                .with_writer(std::io::stderr)
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
    format!("sha256:{}", safe_display(&prefix))
}

/// Renders a connection or session identifier as compact diagnostic context.
#[must_use]
pub fn short_id(value: u64) -> String {
    format!("{:04x}", value & 0xffff)
}

/// Escapes control characters before an untrusted value is used in a text log.
#[must_use]
pub fn safe_context(value: &str) -> String {
    safe_display(value).to_string()
}

/// Wraps any displayable diagnostic value so control characters are escaped.
///
/// Use this at the tracing field boundary for text that can contain configured,
/// protocol-supplied, peer-derived, or error-derived content.
#[must_use]
pub const fn safe_display<T>(value: T) -> SafeDisplay<T> {
    SafeDisplay(value)
}

/// A display adapter that cannot emit literal control characters.
#[derive(Clone, Copy)]
pub struct SafeDisplay<T>(T);

impl<T> fmt::Debug for SafeDisplay<T>
where
    T: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl<T> fmt::Display for SafeDisplay<T>
where
    T: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct EscapingWriter<'a, 'b> {
            formatter: &'a mut fmt::Formatter<'b>,
        }

        impl fmt::Write for EscapingWriter<'_, '_> {
            fn write_str(&mut self, value: &str) -> fmt::Result {
                for character in value.chars() {
                    if character.is_control() {
                        for escaped in character.escape_default() {
                            fmt::Write::write_char(self.formatter, escaped)?;
                        }
                    } else {
                        fmt::Write::write_char(self.formatter, character)?;
                    }
                }
                Ok(())
            }
        }

        fmt::write(
            &mut EscapingWriter { formatter },
            format_args!("{}", self.0),
        )
    }
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

#[cfg(test)]
mod tests {
    use super::{safe_display, short_fingerprint};

    #[test]
    fn safe_display_escapes_controls_from_nested_display_values() {
        assert_eq!(
            safe_display("name\r\n\u{1b}\u{0085}").to_string(),
            r"name\r\n\u{1b}\u{85}"
        );
        assert_eq!(
            format!("{:?}", safe_display("name\r\n\u{1b}\u{0085}")),
            r"name\r\n\u{1b}\u{85}"
        );
    }

    #[test]
    fn short_fingerprint_escapes_the_untrusted_prefix() {
        assert_eq!(
            short_fingerprint("sha256:fp\r\nFORGED\u{1b}!suffix"),
            r"sha256:fp\r\nFORGED\u{1b}!"
        );
    }
}
