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

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::config::{ConfigError, Level, Settings};
use crate::log::{Logger, SERVICE_LOGGER};
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .thread_keep_alive(Duration::from_secs(10))
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(run(settings, secrets, smtp)),
        Err(error) => Err(format!("cannot start the runtime: {error}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("mailgun-relay: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(settings: Settings, secrets: Secrets, smtp: SmtpConfig) -> Result<(), String> {
    let bind = format!("{}:{}", settings.bind_host, settings.bind_port);
    let listeners = bind_all(&settings.bind_host, settings.bind_port)
        .await
        .map_err(|error| format!("cannot bind {bind}: {error}"))?;
    // Handlers are in place before the startup record announces the process.
    let mut shutdown = Shutdown::register().map_err(|error| format!("signals: {error}"))?;
    let logger = Logger::new(settings.log_level);
    log_startup(&logger, &settings, &secrets, &bind);

    let state = Arc::new(http::AppState {
        relay: Arc::new(pipeline::Relay {
            settings,
            tokens: secrets.tokens,
            logger,
            submitter: Box::new(SmtpSubmitter::new(smtp, logger)),
        }),
    });
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut servers = tokio::task::JoinSet::new();
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
    tokio::select! {
        () = shutdown.recv() => {}
        Some(result) = servers.join_next() => {
            return Err(format!("server stopped: {result:?}"));
        }
    }
    let _ = stop.send(true);
    while let Some(result) = servers.join_next().await {
        result
            .map_err(|error| format!("server task: {error}"))?
            .map_err(|error| format!("server error: {error}"))?;
    }
    Ok(())
}

/// Bind every address the host resolves to, as asyncio's `create_server`
/// does for uvicorn: `localhost` gets an IPv4 and an IPv6 listener, IPv6
/// sockets are IPv6-only, `SO_REUSEADDR` is set, uvicorn's backlog.
async fn bind_all(host: &str, port: u16) -> std::io::Result<Vec<TcpListener>> {
    let mut addresses: Vec<SocketAddr> = Vec::new();
    for address in tokio::net::lookup_host((host, port)).await? {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
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
