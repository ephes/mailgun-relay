//! JSON line logger (PLAN.md 2.11, section 4, D-13).
//!
//! One compact JSON object per line on stdout, written and flushed per
//! record: `ts` (UTC, RFC 3339 seconds), `level`, `logger`, `event`, then the
//! record's fields in declaration order, as `relay:logging_setup.py` emits
//! them.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// A fixed count AND byte envelope. Oversize and newest overflow records drop.
const LOG_QUEUE_RECORDS: usize = 256;
pub(crate) const MAX_LOG_RECORD_BYTES: usize = 65_536;

struct RecordBuffer(Vec<u8>);

impl Write for RecordBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = self.0.len();
        if bytes.len() > MAX_LOG_RECORD_BYTES - len {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "log record exceeds byte limit",
            ));
        }
        let required = len + bytes.len();
        let capacity = self.0.capacity();
        if required > capacity {
            // Grow geometrically without reserving past the record limit.
            let next_capacity = required.max(capacity * 2).min(MAX_LOG_RECORD_BYTES);
            self.0.reserve_exact(next_capacity - len);
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct Writer {
    sender: mpsc::SyncSender<Box<[u8]>>,
    stopping: Arc<AtomicBool>,
    finished: Mutex<mpsc::Receiver<()>>,
}

impl Writer {
    fn new(mut sink: impl Write + Send + 'static, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Box<[u8]>>(capacity);
        let (done, finished) = mpsc::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let stopped = stopping.clone();
        // A dedicated OS thread: a live blocked sink cannot occupy Tokio's
        // runtime or its bounded blocking pool. It is detached on drain expiry.
        std::thread::spawn(move || {
            loop {
                match receiver.recv_timeout(Duration::from_millis(10)) {
                    Ok(line) => {
                        let _ = sink.write_all(&line).and_then(|()| sink.flush());
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) if stopped.load(Ordering::Acquire) => {
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            let _ = done.send(());
        });
        Self {
            sender,
            stopping,
            finished: Mutex::new(finished),
        }
    }

    fn send(&self, line: Vec<u8>) -> bool {
        line.len() <= MAX_LOG_RECORD_BYTES
            && !self.stopping.load(Ordering::Acquire)
            && self.sender.try_send(line.into_boxed_slice()).is_ok()
    }

    fn shutdown(&self, budget: Duration) {
        self.stopping.store(true, Ordering::Release);
        let _ = self
            .finished
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recv_timeout(budget);
    }
}

#[derive(Debug, Clone)]
pub struct Logger {
    threshold: Level,
    writer: Option<Arc<Writer>>,
    /// Tests collect the lines here instead of on stdout.
    capture: Option<&'static Mutex<Vec<String>>>,
}

impl Logger {
    pub fn new(threshold: Level) -> Self {
        Logger {
            threshold,
            writer: Some(Arc::new(Writer::new(std::io::stdout(), LOG_QUEUE_RECORDS))),
            capture: None,
        }
    }

    /// A logger whose lines go to the returned buffer (tests).
    #[cfg(test)]
    pub fn capturing(threshold: Level) -> (Self, &'static Mutex<Vec<String>>) {
        let lines: &'static Mutex<Vec<String>> = Box::leak(Box::default());
        let logger = Logger {
            threshold,
            writer: None,
            capture: Some(lines),
        };
        (logger, lines)
    }

    /// Stop admission and drain for a bounded interval after request shutdown.
    /// A stalled sink may lose the queued tail when the process exits.
    pub fn shutdown(&self, budget: Duration) {
        if let Some(writer) = &self.writer {
            writer.shutdown(budget);
        }
    }

    pub fn threshold(&self) -> Level {
        self.threshold
    }

    /// Render one complete line, or `None` if filtered or encoding fails.
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
        let mut line = RecordBuffer(Vec::with_capacity(128));
        serde_json::to_writer(&mut line, &record).ok()?;
        line.write_all(b"\n").ok()?;
        Some(line.0)
    }

    /// Serialize and enqueue without waiting for stdout. Failed writes, full
    /// queues and records over 64 KiB are best effort drops, never send retries.
    pub fn emit<T: Serialize>(&self, level: Level, logger: &str, event: &str, fields: &T) {
        if let Some(line) = self.render(level, logger, event, fields) {
            if let Some(lines) = self.capture {
                let text = String::from_utf8_lossy(&line).into_owned();
                lines.lock().unwrap_or_else(|e| e.into_inner()).push(text);
                return;
            }
            if let Some(writer) = &self.writer {
                let _ = writer.send(line);
            }
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
    fn blocked_sink_has_fixed_queue_and_bounded_drain() {
        struct Sink {
            entered: Option<mpsc::Sender<()>>,
            release: mpsc::Receiver<()>,
            lines: Arc<Mutex<Vec<Vec<u8>>>>,
        }
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if let Some(entered) = self.entered.take() {
                    entered.send(()).unwrap();
                    self.release.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                self.lines.lock().unwrap().push(bytes.to_vec());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer::new(
            Sink {
                entered: Some(entered_tx),
                release: release_rx,
                lines: lines.clone(),
            },
            2,
        );
        assert!(writer.send(vec![1]));
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(writer.send(vec![2]));
        assert!(writer.send(vec![3]));
        assert!(!writer.send(vec![4])); // Newest overflow is dropped.
        assert!(!writer.send(vec![0; MAX_LOG_RECORD_BYTES + 1]));
        let start = std::time::Instant::now();
        writer.shutdown(Duration::from_millis(30));
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(!writer.send(vec![5]));
        release_tx.send(()).unwrap();
        writer.shutdown(Duration::from_secs(2));
        assert_eq!(*lines.lock().unwrap(), [vec![1], vec![2], vec![3]]);
    }

    #[test]
    fn timestamps() {
        let at = |secs| utc_timestamp(UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_792_065_599), "2026-10-15T11:59:59Z");
    }

    #[test]
    fn encoded_record_limit_includes_escaping_and_newline() {
        #[derive(Serialize)]
        struct Fields<'a> {
            value: &'a str,
        }

        let (logger, capture) = Logger::capturing(Level::Info);
        let render = |value: &str| logger.render(Level::Info, "x", "e", &Fields { value });
        let overhead = render("").unwrap().len();
        let room = MAX_LOG_RECORD_BYTES - overhead;
        let mut value = "\n".repeat(room / 2);
        if !room.is_multiple_of(2) {
            value.push('x');
        }
        let at_limit = render(&value).unwrap();
        assert_eq!(at_limit.len(), MAX_LOG_RECORD_BYTES);
        assert_eq!(at_limit.capacity(), MAX_LOG_RECORD_BYTES);
        assert_eq!(at_limit.last(), Some(&b'\n'));
        logger.emit(Level::Info, "x", "e", &Fields { value: &value });

        // The JSON object still fits by itself, but its line terminator would not.
        value.push('x');
        assert!(render(&value).is_none());
        // Now the escaped JSON object itself exceeds the budget.
        value.push('\n');
        assert!(render(&value).is_none());
        logger.emit(Level::Info, "x", "e", &Fields { value: &value });

        let lines = capture.lock().unwrap();
        assert_eq!(lines.len(), 1);
        // The timestamp can roll over between render and emit.
        let at_limit = std::str::from_utf8(&at_limit).unwrap();
        assert_eq!(
            lines[0].split_once(',').unwrap().1,
            at_limit.split_once(',').unwrap().1
        );
    }

    #[test]
    fn encoded_record_limit_stops_serializing_remaining_fields() {
        struct Tail<'a>(&'a std::cell::Cell<bool>);

        impl Serialize for Tail<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.set(true);
                serializer.serialize_bool(true)
            }
        }

        #[derive(Serialize)]
        struct Fields<'a> {
            value: &'a str,
            tail: Tail<'a>,
        }

        let (logger, _) = Logger::capturing(Level::Info);
        let visited_tail = std::cell::Cell::new(false);
        let value = "\n".repeat(MAX_LOG_RECORD_BYTES / 2);
        let fields = Fields {
            value: &value,
            tail: Tail(&visited_tail),
        };
        logger.emit(Level::Info, "x", "e", &fields);
        assert!(!visited_tail.get());
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
        assert_eq!(Level::from_name("trace"), Some(Level::Trace));
        assert!(Level::Trace < Level::Debug);
    }
}
