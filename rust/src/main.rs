//! mailgun-relay: Mailgun send API adapter for Anymail (Rust port, PLAN.md).
//!
//! `mailgun-relay` serves; `--version` prints the version and commit;
//! `--check-config` loads the environment and the secrets file exactly as the
//! server does, binds nothing, and exits 0 (valid) or 1 (invalid). Unknown
//! arguments exit 2.

mod address;
mod auth;
mod config;
mod domain;
mod form;
mod headers;
mod http;
mod log;
mod mime;
mod pipeline;
mod policy;
mod pystr;
mod secrets;
mod smtp;
mod yaml;

use std::collections::HashSet;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::task::TaskTracker;

use crate::config::{ConfigError, Level, Settings};
use crate::log::{DrainOutcome, LogLosses, Logger, SERVICE_LOGGER};
use crate::secrets::Secrets;
use crate::smtp::{SmtpConfig, SmtpSubmitter};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("MAILGUN_RELAY_GIT_COMMIT");

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => serve(),
        [arg] if arg == "--version" => {
            println!("mailgun-relay {VERSION} ({COMMIT})");
            ExitCode::SUCCESS
        }
        [arg] if arg == "--check-config" => match load_config() {
            Ok((settings, secrets, _)) => {
                // Counts only: through a YAML alias a label may hold a secret.
                println!(
                    "mailgun-relay: configuration OK (bind {}:{}, log level {}, {} token(s))",
                    settings.bind_host,
                    settings.bind_port,
                    settings.log_level.name(),
                    secrets.tokens.len()
                );
                ExitCode::SUCCESS
            }
            Err(error) => config_failure(&error),
        },
        _ => {
            eprintln!("usage: mailgun-relay [--version | --check-config]");
            ExitCode::from(2)
        }
    }
}

/// The environment, then the secrets file it names (`relay:app.py`), then
/// the SMTP settings with the TLS roots and `SMTP_CA_FILE`.
fn load_config() -> Result<(Settings, Secrets, SmtpConfig), ConfigError> {
    let settings = Settings::from_env(std::env::vars_os())?;
    let secrets = secrets::load(Path::new(&settings.secrets_path))?;
    let smtp = SmtpConfig::load(&settings, &secrets.smtp)?;
    Ok((settings, secrets, smtp))
}

fn config_failure(error: &ConfigError) -> ExitCode {
    eprintln!("mailgun-relay: configuration error: {error}");
    ExitCode::FAILURE
}

fn serve() -> ExitCode {
    let (settings, secrets, smtp) = match load_config() {
        Ok(loaded) => loaded,
        Err(error) => return config_failure(&error),
    };
    let level = settings.log_level;
    serve_with(
        || Logger::new(level),
        |logger| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(2)
                .thread_keep_alive(Duration::from_secs(10))
                .build()
                .map_err(|error| format!("cannot start the runtime: {error}"))?;
            runtime.block_on(async {
                let listeners = bind_all(&settings.bind_host, settings.bind_port).await;
                run(settings, secrets, smtp, logger.clone(), listeners).await
            })
        },
    )
}

fn serve_with(
    start_logger: impl FnOnce() -> io::Result<Logger>,
    run_service: impl FnOnce(&Logger) -> Result<(), String>,
) -> ExitCode {
    let Ok(logger) = start_logger() else {
        let _ = writeln!(
            io::stderr().lock(),
            "mailgun-relay: cannot start the log writer"
        );
        return ExitCode::FAILURE;
    };
    let result = run_service(&logger);
    if let Some(summary) = log_shutdown_summary(&logger, Duration::from_secs(1)) {
        report_log_shutdown(summary);
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("mailgun-relay: {message}");
            ExitCode::FAILURE
        }
    }
}

fn log_shutdown_summary(logger: &Logger, budget: Duration) -> Option<String> {
    let drain = logger.shutdown(budget);
    let losses = logger.losses();
    let mut summary = String::new();
    if losses != LogLosses::default() {
        let LogLosses {
            encoding,
            queue_full,
            queue_unavailable,
            sink_io,
        } = losses;
        summary = format!(
            "log records lost: encoding={encoding} queue_full={queue_full} queue_unavailable={queue_unavailable} sink_io={sink_io}"
        );
    }
    let unconfirmed = match drain {
        DrainOutcome::Completed => None,
        DrainOutcome::TimedOut => Some("log drain unconfirmed (deadline expired)"),
        DrainOutcome::WriterExited => Some("log drain unconfirmed (writer exited unexpectedly)"),
    };
    if let Some(unconfirmed) = unconfirmed {
        if !summary.is_empty() {
            summary.push(' ');
        }
        summary.push_str(unconfirmed);
    }
    (!summary.is_empty()).then_some(summary)
}

fn report_log_shutdown(summary: String) {
    // Stderr can share the same stalled destination as stdout.
    let (done, finished) = mpsc::channel();
    let _ = std::thread::Builder::new().spawn(move || {
        let _ = writeln!(io::stderr().lock(), "mailgun-relay: {summary}");
        let _ = done.send(());
    });
    let _ = finished.recv_timeout(Duration::from_millis(100));
}

async fn run(
    settings: Settings,
    secrets: Secrets,
    smtp: SmtpConfig,
    logger: Logger,
    listeners: std::io::Result<Vec<TcpListener>>,
) -> Result<(), String> {
    let bind = format!("{}:{}", settings.bind_host, settings.bind_port);
    let listeners = listeners.map_err(|error| format!("cannot bind {bind}: {error}"))?;
    // Handlers are in place before the startup record announces the process.
    let mut shutdown = Shutdown::register().map_err(|error| format!("signals: {error}"))?;
    log_startup(&logger, &settings, &secrets, &bind);

    let relay = Arc::new(pipeline::Relay::new(
        settings,
        secrets.tokens,
        logger.clone(),
        Box::new(SmtpSubmitter::new(smtp, logger)),
    ));
    let state = Arc::new(http::AppState {
        relay: Arc::clone(&relay),
    });
    let (stop, stopped) = watch::channel(false);
    let mut servers = JoinSet::new();
    for listener in listeners {
        let app = http::router(Arc::clone(&state))
            .into_make_service_with_connect_info::<http::Connection>();
        let mut stopped = stopped.clone();
        servers.spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.wait_for(|stop| *stop).await;
                })
                .await
        });
    }
    supervise_listeners(servers, stop, &relay.tasks, shutdown.recv()).await
}

async fn supervise_listeners(
    mut servers: JoinSet<std::io::Result<()>>,
    stop: watch::Sender<bool>,
    tasks: &TaskTracker,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    let mut outcome = tokio::select! {
        () = shutdown => Ok(()),
        Some(result) = servers.join_next() => Err(format!("server stopped: {result:?}")),
    };
    let _ = stop.send(true);
    while let Some(result) = servers.join_next().await {
        if outcome.is_ok() {
            outcome = result
                .map_err(|error| format!("server task: {error}"))
                .and_then(|result| result.map_err(|error| format!("server error: {error}")));
        }
    }
    // Requests whose client went away may still be submitting.
    tasks.close();
    tasks.wait().await;
    outcome
}

/// Bind every address the host resolves to, as asyncio's `create_server`
/// does for uvicorn: `localhost` gets an IPv4 and an IPv6 listener, IPv6
/// sockets are IPv6-only, `SO_REUSEADDR` is set, uvicorn's backlog.
async fn bind_all(host: &str, port: u16) -> std::io::Result<Vec<TcpListener>> {
    bind_addresses(tokio::net::lookup_host((host, port)).await?)
}

fn unique_bind_addresses(resolved: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    resolved
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect()
}

/// Acquire a nonempty, complete listener set before startup can announce success.
/// Dropping the local vector on any error rolls back earlier binds.
fn bind_addresses(
    resolved: impl IntoIterator<Item = SocketAddr>,
) -> std::io::Result<Vec<TcpListener>> {
    let addresses = unique_bind_addresses(resolved);
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no addresses to listen on",
        ));
    }
    let mut listeners = Vec::with_capacity(addresses.len());
    for address in addresses {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        socket.listen(2048)?;
        listeners.push(TcpListener::from_std(socket.into())?);
    }
    Ok(listeners)
}

/// SIGTERM (systemd stop) or SIGINT end the server after in-flight requests.
/// Both handlers are installed by [`Shutdown::register`], not on first poll.
struct Shutdown {
    term: Signal,
    interrupt: Signal,
}

impl Shutdown {
    fn register() -> std::io::Result<Self> {
        Ok(Shutdown {
            term: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

/// The record every start writes (`relay:app.py` `log_startup`, plus `impl`):
/// the effective configuration, token labels only, no credentials.
#[derive(Serialize)]
struct Startup<'a> {
    version: &'a str,
    #[serde(rename = "impl")]
    implementation: &'a str,
    bind: &'a str,
    public_host: &'a str,
    smtp_host: &'a str,
    smtp_port: u16,
    smtp_starttls: bool,
    smtp_custom_ca: bool,
    smtp_max_concurrency: u32,
    fail_on_partial_refusal: bool,
    log_level: &'a str,
    token_labels: Vec<&'a str>,
    max_body_bytes: i64,
    max_recipients: i64,
}

fn startup_record<'a>(settings: &'a Settings, secrets: &'a Secrets, bind: &'a str) -> Startup<'a> {
    let mut token_labels: Vec<&str> = secrets.tokens.iter().map(|t| t.label.as_str()).collect();
    token_labels.sort_unstable();
    Startup {
        version: VERSION,
        implementation: "rust",
        bind,
        public_host: &settings.public_host,
        smtp_host: &settings.smtp_host,
        smtp_port: settings.smtp_port,
        smtp_starttls: settings.smtp_starttls,
        smtp_custom_ca: !settings.smtp_ca_file.is_empty(),
        smtp_max_concurrency: settings.smtp_max_concurrency,
        fail_on_partial_refusal: settings.fail_on_partial_refusal,
        log_level: settings.log_level.name(),
        token_labels,
        max_body_bytes: settings.max_body_bytes,
        max_recipients: settings.max_recipients,
    }
}

/// Logged at INFO, or at the configured level if that is higher, so a
/// quieter `LOG_LEVEL` never hides the start.
fn log_startup(logger: &Logger, settings: &Settings, secrets: &Secrets, bind: &str) {
    let level = logger.threshold().max(Level::Info);
    let record = startup_record(settings, secrets, bind);
    logger.emit(level, SERVICE_LOGGER, "startup", &record);
}

#[cfg(test)]
mod bind_tests {
    use super::*;

    #[test]
    fn large_resolver_sequence_deduplicates_in_first_seen_order() {
        let first_seen: Vec<_> = (0..100_000u32)
            .rev()
            .map(|index| SocketAddr::from(((0x7f00_0000 + index).to_be_bytes(), 8080)))
            .collect();
        let start = std::time::Instant::now();
        // A generous deadline catches quadratic scans without letting a
        // regression run all the way through billions of comparisons.
        let resolved = first_seen
            .iter()
            .flat_map(|&address| [address, first_seen[0], address])
            .inspect(|_| {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "resolver deduplication exceeded the test budget"
                );
            });
        assert_eq!(unique_bind_addresses(resolved), first_seen);
    }

    #[tokio::test]
    async fn empty_listener_inventory_fails_before_startup() {
        let settings =
            Settings::from_env([("MAILGUN_RELAY_SMTP_STARTTLS".into(), "false".into())]).unwrap();
        let secrets = Secrets {
            smtp: secrets::SmtpCredentials {
                username: "relay@example.org".into(),
                password: "synthetic-password".into(),
            },
            tokens: vec![],
        };
        let smtp = SmtpConfig::load(&settings, &secrets.smtp).unwrap();
        let (logger, records) = Logger::capturing(Level::Info);
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            run(settings, secrets, smtp, logger, bind_addresses([])),
        )
        .await;
        assert!(
            records.lock().unwrap().is_empty(),
            "announced startup without listeners"
        );
        let error = result.expect("startup did not terminate").unwrap_err();
        assert!(error.contains("no addresses to listen on"), "{error}");
    }

    #[tokio::test]
    async fn partial_bind_failure_releases_earlier_listeners_and_allows_retry() {
        // Explicit IPv4 addresses avoid DNS order and IPv6 availability.
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let first_address = first.local_addr().unwrap();
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second_address = busy.local_addr().unwrap();
        let resolved = [first_address, first_address, second_address, first_address];
        drop(first);
        let error = bind_addresses(resolved).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        // The first bind succeeded before the second failed. Its listener
        // must have been dropped, before startup could publish success.
        let rebound = std::net::TcpListener::bind(first_address).unwrap();
        drop(rebound);
        drop(busy);
        let listeners = bind_addresses(resolved).unwrap();
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].local_addr().unwrap(), first_address);
        assert_eq!(listeners[1].local_addr().unwrap(), second_address);
        drop(listeners);
        for address in [first_address, second_address] {
            assert!(std::net::TcpListener::bind(address).is_ok());
        }
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn listener_exit_stops_other_listeners_and_drains_submissions() {
        let (stop, mut stopped) = watch::channel(false);
        let (listener_stopped, observe_stop) = oneshot::channel();
        let mut servers = JoinSet::new();
        servers.spawn(async { Err(std::io::Error::other("initiating listener failure")) });
        servers.spawn(async move {
            stopped.wait_for(|stop| *stop).await.unwrap();
            listener_stopped.send(()).unwrap();
            Err(std::io::Error::other("secondary listener failure"))
        });

        let tasks = TaskTracker::new();
        let (finish, finish_submission) = oneshot::channel();
        let submission = tasks.spawn(async { finish_submission.await.unwrap() });
        let service = supervise_listeners(servers, stop, &tasks, std::future::pending());
        tokio::pin!(service);

        let deadline = Duration::from_secs(2);
        tokio::select! {
            result = &mut service => panic!("returned before stopping peer listener: {result:?}"),
            stopped = tokio::time::timeout(deadline, observe_stop) => stopped.unwrap().unwrap(),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut service)
                .await
                .is_err(),
            "returned before the tracked submission completed"
        );
        finish.send(()).unwrap();
        let error = tokio::time::timeout(deadline, service)
            .await
            .unwrap()
            .unwrap_err();
        assert!(submission.is_finished());
        assert!(error.contains("initiating listener failure"), "{error}");
        assert!(!error.contains("secondary listener failure"), "{error}");
    }
}
