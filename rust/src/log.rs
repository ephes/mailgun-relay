//! JSON line logger (PLAN.md 2.11, section 4, D-13).
//!
//! One compact JSON object per line on stdout, written and flushed per
//! record: `ts` (UTC, RFC 3339 seconds), `level`, `logger`, `event`, then the
//! record's fields in declaration order, as `relay:logging_setup.py` emits
//! them.

use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::Level;

pub const SERVICE_LOGGER: &str = "mailgun_relay.service";

#[derive(Serialize)]
struct Record<'a, T: Serialize> {
    ts: String,
    level: &'static str,
    logger: &'a str,
    event: &'a str,
    #[serde(flatten)]
    fields: &'a T,
}

#[derive(Debug, Clone, Copy)]
pub struct Logger {
    threshold: Level,
    /// Tests collect the lines here instead of on stdout.
    capture: Option<&'static Mutex<Vec<String>>>,
}

impl Logger {
    pub fn new(threshold: Level) -> Self {
        Logger {
            threshold,
            capture: None,
        }
    }

    /// A logger whose lines go to the returned buffer (tests).
    #[cfg(test)]
    pub fn capturing(threshold: Level) -> (Self, &'static Mutex<Vec<String>>) {
        let lines: &'static Mutex<Vec<String>> = Box::leak(Box::default());
        let logger = Logger {
            threshold,
            capture: Some(lines),
        };
        (logger, lines)
    }

    pub fn threshold(&self) -> Level {
        self.threshold
    }

    /// Render one record, or `None` below the threshold.
    pub fn render<T: Serialize>(
        &self,
        level: Level,
        logger: &str,
        event: &str,
        fields: &T,
    ) -> Option<Vec<u8>> {
        if level < self.threshold {
            return None;
        }
        let record = Record {
            ts: utc_timestamp(SystemTime::now()),
            level: level.name(),
            logger,
            event,
            fields,
        };
        let mut line = serde_json::to_vec(&record).expect("log records serialise");
        line.push(b'\n');
        Some(line)
    }

    /// Write one record to stdout and flush it. A failed write (closed
    /// stdout) is ignored: logging never takes the service down.
    pub fn emit<T: Serialize>(&self, level: Level, logger: &str, event: &str, fields: &T) {
        if let Some(line) = self.render(level, logger, event, fields) {
            if let Some(lines) = self.capture {
                let text = String::from_utf8_lossy(&line).into_owned();
                lines.lock().unwrap_or_else(|e| e.into_inner()).push(text);
                return;
            }
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(&line).and_then(|()| out.flush());
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, proleptic Gregorian).
pub fn utc_timestamp(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn timestamps() {
        let at = |secs| utc_timestamp(UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_792_065_599), "2026-10-15T11:59:59Z");
    }

    #[test]
    fn records_are_compact_ordered_and_filtered() {
        #[derive(Serialize)]
        struct Fields {
            b: u8,
            a: &'static str,
        }
        let logger = Logger::new(Level::Warning);
        let fields = Fields { b: 1, a: "ü" };
        assert!(logger.render(Level::Info, "x", "e", &fields).is_none());
        let line = logger.render(Level::Error, "x", "e", &fields).unwrap();
        let text = String::from_utf8(line).unwrap();
        let rest = text.split_once(",\"level\"").unwrap().1;
        assert_eq!(
            rest,
            ":\"ERROR\",\"logger\":\"x\",\"event\":\"e\",\"b\":1,\"a\":\"ü\"}\n"
        );
        assert_eq!(Level::from_name("warning"), Some(Level::Warning));
        assert_eq!(Level::from_name("WARN"), None);
    }
}
