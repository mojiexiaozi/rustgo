#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const MAX_LOG_LINES: usize = 1000;

#[derive(Clone, Debug)]
pub struct LogLine {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

struct LogRingInner {
    lines: VecDeque<LogLine>,
    dropped: u64,
}

#[derive(Clone)]
pub struct LogRing {
    inner: Arc<Mutex<LogRingInner>>,
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new()
    }
}

impl LogRing {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LogRingInner {
                lines: VecDeque::with_capacity(MAX_LOG_LINES),
                dropped: 0,
            })),
        }
    }

    pub fn snapshot(&self) -> (Vec<LogLine>, u64) {
        let guard = self.inner.lock().unwrap();
        (guard.lines.iter().cloned().collect(), guard.dropped)
    }

    pub fn push(&self, line: LogLine) {
        let mut guard = self.inner.lock().unwrap();
        if guard.lines.len() >= MAX_LOG_LINES {
            guard.lines.pop_front();
            guard.dropped += 1;
        }
        guard.lines.push_back(line);
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogRing {
    type Writer = LogRingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogRingWriter {
            ring: self.clone(),
            buffer: Vec::new(),
        }
    }
}

pub struct LogRingWriter {
    ring: LogRing,
    buffer: Vec<u8>,
}

impl Write for LogRingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            let message = String::from_utf8_lossy(&self.buffer).to_string();
            let parts: Vec<&str> = message.trim().splitn(4, ' ').collect();

            let (timestamp, level, target, msg) = if parts.len() >= 4 {
                (
                    parts[0].to_string(),
                    parts[1].to_string(),
                    parts[2].to_string(),
                    parts[3].to_string(),
                )
            } else {
                let now = OffsetDateTime::now_utc();
                let ts = now
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".to_string());
                (
                    ts,
                    "INFO".to_string(),
                    "gui".to_string(),
                    message.trim().to_string(),
                )
            };

            self.ring.push(LogLine {
                timestamp,
                level,
                target,
                message: msg,
            });
            self.buffer.clear();
        }
        Ok(())
    }
}

impl Drop for LogRingWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tracing_subscriber::fmt::MakeWriter;

    #[test]
    fn test_ring_capacity_and_drop_oldest() {
        let ring = LogRing::new();

        for i in 0..1200 {
            ring.push(LogLine {
                timestamp: format!("2026-09-03T00:00:{:02}Z", i % 60),
                level: "INFO".to_string(),
                target: "test".to_string(),
                message: format!("Message {}", i),
            });
        }

        let (lines, dropped) = ring.snapshot();
        assert_eq!(lines.len(), MAX_LOG_LINES);
        assert_eq!(dropped, 200);
        assert!(lines[0].message.contains("Message 200"));
        assert!(lines[999].message.contains("Message 1199"));
    }

    #[test]
    fn test_drop_counter() {
        let ring = LogRing::new();

        for i in 0..1050 {
            ring.push(LogLine {
                timestamp: "2026-09-03T00:00:00Z".to_string(),
                level: "INFO".to_string(),
                target: "test".to_string(),
                message: format!("Line {}", i),
            });
        }

        let (_, dropped) = ring.snapshot();
        assert_eq!(dropped, 50);
    }

    #[test]
    fn test_make_writer_integration() {
        let ring = LogRing::new();

        {
            let mut writer = ring.make_writer();
            write!(writer, "2026-09-03T00:00:00Z INFO test First message").unwrap();
            writer.flush().unwrap();
        }

        {
            let mut writer = ring.make_writer();
            write!(writer, "2026-09-03T00:00:01Z WARN test Second message").unwrap();
            writer.flush().unwrap();
        }

        let (lines, dropped) = ring.snapshot();
        assert_eq!(lines.len(), 2);
        assert_eq!(dropped, 0);
        assert!(lines[0].message.contains("First"));
        assert!(lines[1].message.contains("Second"));
    }

    #[test]
    fn test_concurrent_writes() {
        let ring = LogRing::new();
        let handles: Vec<_> = (0..10)
            .map(|thread_id| {
                let ring = ring.clone();
                std::thread::spawn(move || {
                    for i in 0..100 {
                        ring.push(LogLine {
                            timestamp: "2026-09-03T00:00:00Z".to_string(),
                            level: "INFO".to_string(),
                            target: format!("thread{}", thread_id),
                            message: format!("Message {} from thread {}", i, thread_id),
                        });
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let (lines, _) = ring.snapshot();
        assert_eq!(lines.len(), MAX_LOG_LINES);
    }
}
