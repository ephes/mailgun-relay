//! JSON line logger (PLAN.md 2.11, section 4, D-13).
//!
//! One compact JSON object per line on stdout, written and flushed per
//! record: `ts` (UTC, RFC 3339 seconds), `level`, `logger`, `event`, then the
//! record's fields in declaration order, as `relay:logging_setup.py` emits
//! them.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
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
    sender: Mutex<Option<mpsc::SyncSender<Box<[u8]>>>>,
    finished: Arc<(Mutex<bool>, Condvar)>,
    losses: Arc<LossCounters>,
}

#[derive(Debug, Default)]
struct LossCounters {
    encoding: AtomicU64,
    queue_full: AtomicU64,
    queue_unavailable: AtomicU64,
    sink_io: AtomicU64,
}

impl Writer {
    fn new(mut sink: impl Write + Send + 'static, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Box<[u8]>>(capacity);
        let finished = Arc::new((Mutex::new(false), Condvar::new()));
        let writer_finished = finished.clone();
        let losses = Arc::new(LossCounters::default());
        let writer_losses = losses.clone();
        // A dedicated OS thread: a live blocked sink cannot occupy Tokio's
        // runtime or its bounded blocking pool. It is detached on drain expiry.
        std::thread::spawn(move || {
            // The channel yields all accepted records before disconnecting.
            let mut needs_boundary = false;
            for line in receiver {
                // A failed write may have left a prefix in the stream.
                if needs_boundary && sink.write_all(b"\n").is_err() {
                    writer_losses.sink_io.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                needs_boundary = sink.write_all(&line).is_err();
                if needs_boundary || sink.flush().is_err() {
                    writer_losses.sink_io.fetch_add(1, Ordering::Relaxed);
                }
            }
            let (completed, notify) = &*writer_finished;
            *completed.lock().unwrap_or_else(|e| e.into_inner()) = true;
            notify.notify_all();
        });
        Self {
            sender: Mutex::new(Some(sender)),
            finished,
            losses,
        }
    }

    fn send(&self, line: impl Into<Box<[u8]>>) -> bool {
        let line = line.into();
        if line.len() > MAX_LOG_RECORD_BYTES {
            self.losses.encoding.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let result = {
            let sender = self.sender.lock().unwrap_or_else(|e| e.into_inner());
            match sender.as_ref() {
                Some(sender) => sender.try_send(line),
                None => Err(mpsc::TrySendError::Disconnected(line)),
            }
        };
        let counter = match result {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Full(_)) => &self.losses.queue_full,
            Err(mpsc::TrySendError::Disconnected(_)) => &self.losses.queue_unavailable,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        false
    }

    fn shutdown(&self, budget: Duration) -> bool {
        let sender = self.sender.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(sender);
        let (completed, notify) = &*self.finished;
        let completed = completed.lock().unwrap_or_else(|e| e.into_inner());
        let (completed, _) = notify
            .wait_timeout_while(completed, budget, |completed| !*completed)
            .unwrap_or_else(|e| e.into_inner());
        *completed
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct LogLosses {
    pub encoding: u64,
    pub queue_full: u64,
    pub queue_unavailable: u64,
    pub sink_io: u64,
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

    pub fn losses(&self) -> LogLosses {
        self.writer
            .as_ref()
            .map_or_else(LogLosses::default, |writer| {
                let losses = &writer.losses;
                LogLosses {
                    encoding: losses.encoding.load(Ordering::Relaxed),
                    queue_full: losses.queue_full.load(Ordering::Relaxed),
                    queue_unavailable: losses.queue_unavailable.load(Ordering::Relaxed),
                    sink_io: losses.sink_io.load(Ordering::Relaxed),
                }
            })
    }

    pub fn threshold(&self) -> Level {
        self.threshold
    }

    /// Render one complete line, or `Ok(None)` if filtered.
    fn render<T: Serialize>(
        &self,
        level: Level,
        logger: &str,
        event: &str,
        fields: &T,
    ) -> io::Result<Option<Vec<u8>>> {
        if level < self.threshold {
            return Ok(None);
        }
        let record = Record {
            ts: utc_timestamp(SystemTime::now()),
            level: level.name(),
            logger,
            event,
            fields,
        };
        let mut line = RecordBuffer(Vec::with_capacity(128));
        serde_json::to_writer(&mut line, &record)?;
        line.write_all(b"\n")?;
        Ok(Some(line.0))
    }

    /// Serialize and enqueue without waiting for stdout or retrying lost records.
    pub fn emit<T: Serialize>(&self, level: Level, logger: &str, event: &str, fields: &T) {
        match self.render(level, logger, event, fields) {
            Ok(Some(line)) => {
                if let Some(lines) = self.capture {
                    let text = String::from_utf8_lossy(&line).into_owned();
                    lines.lock().unwrap_or_else(|e| e.into_inner()).push(text);
                } else if let Some(writer) = &self.writer {
                    writer.send(line);
                }
            }
            Err(_) => {
                if let Some(writer) = &self.writer {
                    writer.losses.encoding.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(None) => {}
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

    struct BlockingSink {
        entered: Option<mpsc::Sender<()>>,
        release: mpsc::Receiver<()>,
        lines: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    impl Write for BlockingSink {
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

    #[test]
    fn blocked_sink_has_fixed_queue_and_bounded_drain() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer::new(
            BlockingSink {
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
    fn concurrent_log_shutdowns_have_independent_budgets_and_share_completion() {
        let (entered, writing) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let writer = Writer::new(
            BlockingSink {
                entered: Some(entered),
                release: released,
                lines: Arc::default(),
            },
            1,
        );
        assert!(writer.send(b"{}\n".to_vec()));
        writing.recv_timeout(Duration::from_secs(2)).unwrap();

        let (short_completed, elapsed, long_completed) = std::thread::scope(|scope| {
            let long = scope.spawn(|| writer.shutdown(Duration::from_millis(1500)));
            let start = std::time::Instant::now();
            while writer.sender.lock().unwrap().is_some() {
                assert!(start.elapsed() < Duration::from_secs(1));
                std::thread::yield_now();
            }
            let start = std::time::Instant::now();
            let short_completed = writer.shutdown(Duration::from_millis(20));
            let elapsed = start.elapsed();
            release.send(()).unwrap();
            (short_completed, elapsed, long.join().unwrap())
        });

        assert!(!short_completed);
        assert!(
            elapsed < Duration::from_millis(600),
            "short wait took {elapsed:?}"
        );
        assert!(long_completed);
        assert!(writer.shutdown(Duration::ZERO));
        assert!(writer.shutdown(Duration::ZERO));
    }

    #[test]
    fn shutdown_refuses_paused_producer_and_drains_accepted_records() {
        struct PausedRecord {
            ready: mpsc::Sender<()>,
            resume: mpsc::Receiver<()>,
        }

        impl From<PausedRecord> for Box<[u8]> {
            fn from(record: PausedRecord) -> Self {
                record.ready.send(()).unwrap();
                record.resume.recv_timeout(Duration::from_secs(2)).unwrap();
                Box::new([3])
            }
        }

        let (entered, writing) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer::new(
            BlockingSink {
                entered: Some(entered),
                release: released,
                lines: lines.clone(),
            },
            2,
        );
        assert!(writer.send(vec![1]));
        writing.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(writer.send(vec![2]));

        let late_accepted = std::thread::scope(|scope| {
            let (ready, preparing) = mpsc::channel();
            let (resume, paused) = mpsc::channel();
            let producer = scope.spawn(|| {
                writer.send(PausedRecord {
                    ready,
                    resume: paused,
                })
            });
            preparing.recv_timeout(Duration::from_secs(2)).unwrap();
            writer.shutdown(Duration::ZERO);
            // The sink is still blocked and the queue has a spare slot.
            resume.send(()).unwrap();
            producer.join().unwrap()
        });
        release.send(()).unwrap();
        writer.shutdown(Duration::from_secs(2));

        assert!(!late_accepted);
        assert_eq!(*lines.lock().unwrap(), [vec![1], vec![2]]);
        assert_eq!(writer.losses.queue_unavailable.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_partial_log_write_leaves_the_next_record_on_its_own_line() {
        struct PartialSink {
            writes: usize,
            fail_first_separator: bool,
            output: Arc<Mutex<Vec<u8>>>,
        }

        impl Write for PartialSink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                match self.writes {
                    1 => {
                        self.output.lock().unwrap().extend_from_slice(&bytes[..1]);
                        return Ok(1);
                    }
                    2 => return Err(io::ErrorKind::BrokenPipe.into()),
                    _ if self.fail_first_separator && bytes == b"\n" => {
                        self.fail_first_separator = false;
                        return Err(io::ErrorKind::BrokenPipe.into());
                    }
                    _ => {}
                }
                self.output.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        for fail_first_separator in [false, true] {
            let output = Arc::new(Mutex::new(Vec::new()));
            let writer = Writer::new(
                PartialSink {
                    writes: 0,
                    fail_first_separator,
                    output: output.clone(),
                },
                3,
            );
            assert!(writer.send(b"{\"first\":1}\n".to_vec()));
            if fail_first_separator {
                assert!(writer.send(b"{\"dropped\":2}\n".to_vec()));
            }
            assert!(writer.send(b"{\"healthy\":3}\n".to_vec()));
            assert!(writer.shutdown(Duration::from_secs(2)));

            let output = output.lock().unwrap();
            let mut lines = output.split(|byte| *byte == b'\n');
            assert_eq!(lines.next().unwrap(), b"{");
            let recovered = serde_json::from_slice::<serde_json::Value>(lines.next().unwrap());
            assert_eq!(recovered.unwrap(), serde_json::json!({"healthy": 3}));
            assert_eq!(lines.next(), Some(b"".as_slice()));
            assert_eq!(lines.next(), None);
            assert_eq!(
                writer.losses.sink_io.load(Ordering::Relaxed),
                1 + u64::from(fail_first_separator)
            );
        }
    }

    #[test]
    fn counts_log_losses_across_clones_without_counting_filtered_records() {
        struct FailingSink {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        }

        impl Write for FailingSink {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(2)).unwrap();
                Err(io::ErrorKind::BrokenPipe.into())
            }

            fn flush(&mut self) -> io::Result<()> {
                unreachable!("flush after a failed write")
            }
        }

        let (entered, writing) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let logger = Logger {
            threshold: Level::Warning,
            writer: Some(Arc::new(Writer::new(
                FailingSink {
                    entered,
                    release: released,
                },
                1,
            ))),
            capture: None,
        };
        let producer = logger.clone();
        let fields = serde_json::json!({});
        let oversized = serde_json::json!({"value": "x".repeat(MAX_LOG_RECORD_BYTES)});
        producer.emit(Level::Warning, "x", "writing", &fields);
        writing.recv_timeout(Duration::from_secs(2)).unwrap();
        producer.emit(Level::Warning, "x", "queued", &fields);
        producer.emit(Level::Info, "x", "filtered", &oversized);
        producer.emit(Level::Info, "x", "filtered", &fields);
        assert_eq!(logger.losses(), LogLosses::default());

        producer.emit(Level::Warning, "x", "oversized", &oversized);
        producer.emit(Level::Warning, "x", "overflow", &fields);
        let before_drain = logger.losses();
        for _ in 0..2 {
            release.send(()).unwrap();
        }
        logger.shutdown(Duration::from_secs(2));
        assert_eq!(
            before_drain,
            LogLosses {
                encoding: 1,
                queue_full: 1,
                ..LogLosses::default()
            }
        );
        assert_eq!(
            logger.losses(),
            LogLosses {
                sink_io: 2,
                ..before_drain
            }
        );
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
        let overhead = render("").unwrap().unwrap().len();
        let room = MAX_LOG_RECORD_BYTES - overhead;
        let mut value = "\n".repeat(room / 2);
        if !room.is_multiple_of(2) {
            value.push('x');
        }
        let at_limit = render(&value).unwrap().unwrap();
        assert_eq!(at_limit.len(), MAX_LOG_RECORD_BYTES);
        assert_eq!(at_limit.capacity(), MAX_LOG_RECORD_BYTES);
        assert_eq!(at_limit.last(), Some(&b'\n'));
        logger.emit(Level::Info, "x", "e", &Fields { value: &value });

        // The JSON object still fits by itself, but its line terminator would not.
        value.push('x');
        assert!(render(&value).is_err());
        // Now the escaped JSON object itself exceeds the budget.
        value.push('\n');
        assert!(render(&value).is_err());
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
        assert!(
            logger
                .render(Level::Info, "x", "e", &fields)
                .unwrap()
                .is_none()
        );
        let line = logger
            .render(Level::Error, "x", "e", &fields)
            .unwrap()
            .unwrap();
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
