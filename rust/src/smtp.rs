//! SMTP submission (PLAN.md 2.3 step 10, 2.4; `relay:smtp_client.py`
//! `submit`) on lettre's connection-level API.
//!
//! One new connection per message: banner and EHLO, STARTTLS with chain and
//! hostname verification, AUTH, `MAIL`, one `RCPT` per recipient (a refused
//! recipient does not end the session), `DATA`, the message, `QUIT`. The
//! protocol is lettre's (`AsyncSmtpConnection`); this module decides which
//! reply means which HTTP status, as `smtplib` and the Python relay do:
//!
//! - a reply code decides: 4xx is temporary (503), anything else permanent
//!   (502); a positive reply other than the one `smtplib` requires (MAIL
//!   250, RCPT 250 or 251, DATA 354, end of data 250, AUTH 235) counts as
//!   that code;
//! - every failure without a reply code (connect, timeout, disconnect, TLS,
//!   certificate, STARTTLS or AUTH not offered, a reply lettre cannot parse)
//!   is temporary (Q3, D-3);
//! - AUTH: PLAIN, then LOGIN, as `smtplib.login` tries them; refused with
//!   codes (but 421) by both, permanent; credentials are never sent without
//!   TLS (permanent);
//! - a refused EHLO is judged by the step Python would fail next (2.4).
//!
//! Cleanup: `QUIT` after every outcome unless the server already closed the
//! channel (421, transport failure); a failed `QUIT` never changes the
//! outcome and is logged as `smtp_cleanup_failed`. The socket closes when
//! the connection is dropped.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use lettre::Address;
use lettre::transport::smtp::Error;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{
    AsyncSmtpConnection, AsyncTokioStream, Certificate, TlsParameters,
};
use lettre::transport::smtp::commands::{Data, Mail, Quit, Rcpt};
use lettre::transport::smtp::extension::ClientId;
use lettre::transport::smtp::response::Response;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_io_timeout::TimeoutStream;

use crate::config::{ConfigError, Level, Settings};
use crate::log::{Logger, SERVICE_LOGGER};
use crate::mime::BuiltMessage;
use crate::pipeline::{Refusal, Submission, SubmitError, Submitter};
use crate::secrets::SmtpCredentials;

/// The message goes to lettre in pieces of this size, so its dot-stuffing
/// copy never holds the whole message a second time.
const MESSAGE_CHUNK: usize = 64 * 1024;
/// Wire bytes, including TLS records/handshake, across the entire session.
const INBOUND_BYTES: usize = 16 * 1024 * 1024;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Everything a submission needs, checked at start (`--check-config` too).
pub struct SmtpConfig {
    host: String,
    port: u16,
    /// `Some` when `SMTP_STARTTLS` is on: the system roots plus
    /// `SMTP_CA_FILE`, verifying chain and hostname (`SMTP_HOST`).
    tls: Option<TlsParameters>,
    credentials: Credentials,
    timeout: Duration,
    session_timeout: Duration,
    /// `None` is the null sender `MAIL FROM:<>` (empty `ENVELOPE_SENDER`).
    sender: Option<Address>,
}

impl SmtpConfig {
    /// Python reads `SMTP_CA_FILE` at each submission and answers 503 for
    /// every message when it is unusable; the Rust port reads it once and
    /// refuses to start (fail closed, D-22).
    pub fn load(settings: &Settings, smtp: &SmtpCredentials) -> Result<Self, ConfigError> {
        let sender = match settings.envelope_sender.as_str() {
            "" => None,
            sender => Some(envelope_address(sender).ok_or_else(|| {
                ConfigError("MAILGUN_RELAY_ENVELOPE_SENDER: not an ASCII address".to_owned())
            })?),
        };
        Ok(SmtpConfig {
            host: settings.smtp_host.clone(),
            port: settings.smtp_port,
            tls: tls_parameters(settings)?,
            credentials: Credentials::new(smtp.username.clone(), smtp.password.clone()),
            timeout: Duration::from_secs_f64(settings.smtp_timeout_s),
            session_timeout: Duration::from_secs_f64(settings.smtp_session_timeout_s),
            sender,
        })
    }
}

fn tls_parameters(settings: &Settings) -> Result<Option<TlsParameters>, ConfigError> {
    let ca_error = |reason: String| {
        ConfigError(format!(
            "MAILGUN_RELAY_SMTP_CA_FILE {:?}: {reason} (PLAN.md D-22)",
            settings.smtp_ca_file
        ))
    };
    let mut builder = TlsParameters::builder(settings.smtp_host.clone());
    if !settings.smtp_ca_file.is_empty() {
        let pem = std::fs::read(&settings.smtp_ca_file)
            .map_err(|error| ca_error(format!("cannot read: {error}")))?;
        // Every certificate of the bundle, as `load_verify_locations`
        // reads it; a file without one is an error there too.
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ca_error("not a valid PEM certificate bundle".to_owned()))?;
        if certificates.is_empty() {
            return Err(ca_error("no PEM certificate".to_owned()));
        }
        for certificate in certificates {
            let certificate = Certificate::from_der(certificate.to_vec())
                .map_err(|error| ca_error(format!("unusable certificate: {error}")))?;
            builder = builder.add_root_certificate(certificate);
        }
    } else if !settings.smtp_starttls {
        return Ok(None);
    }
    // Also with STARTTLS off: a configured CA file must be usable.
    let parameters = builder
        .build_rustls()
        .map_err(|error| ca_error(format!("unusable certificate: {error}")))?;
    Ok(settings.smtp_starttls.then_some(parameters))
}

/// An envelope address for lettre. Our own validation decided it (S2, S4);
/// lettre's `Address` parser is not used as a validator (it refuses a
/// 65-character local part Python accepts). Only ASCII without whitespace
/// or angle brackets is accepted, so no `SMTPUTF8` is ever needed (Q2).
fn envelope_address(address: &str) -> Option<Address> {
    let printable = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_graphic() && b != b'<' && b != b'>')
    };
    let (local, domain) = address.rsplit_once('@')?;
    (printable(local) && printable(domain)).then(|| Address::new_dangerous(local, domain))
}

pub struct SmtpSubmitter {
    config: SmtpConfig,
    hello: ClientId,
    logger: Logger,
}

impl SmtpSubmitter {
    pub fn new(config: SmtpConfig, logger: Logger) -> Self {
        SmtpSubmitter {
            config,
            // The host name (`EHLO macmini`); Python sends an address
            // literal. Free (PLAN.md 2.12).
            hello: ClientId::default(),
            logger,
        }
    }
}

impl Submitter for SmtpSubmitter {
    fn submit(&self, message: BuiltMessage) -> Submission<'_> {
        Box::pin(async move { self.session(&message).await })
    }
}

/// A failed step: the outcome, and whether the channel is still open for
/// `QUIT`.
struct Failure {
    error: SubmitError,
    open: bool,
}

fn by_code(code: u16) -> SubmitError {
    if (400..500).contains(&code) {
        SubmitError::Temporary
    } else {
        SubmitError::Permanent
    }
}

fn code(error: &Error) -> Option<u16> {
    error.status().map(u16::from)
}

/// A negative reply decides by its code; 421 closes the channel. Without a
/// code (transport, TLS, a reply lettre cannot parse) the failure is
/// temporary and the channel is treated as gone, except for lettre's own
/// refusals before a command is sent (an extension not offered).
fn failure(error: &Error) -> Failure {
    match code(error) {
        Some(code) => Failure {
            error: by_code(code),
            open: code != 421,
        },
        None => Failure {
            error: SubmitError::Temporary,
            open: error.is_client(),
        },
    }
}

/// A positive reply other than the one `smtplib` requires: permanent.
fn require(response: &Response, wanted: &[u16]) -> Result<(), Failure> {
    if wanted.contains(&u16::from(response.code())) {
        Ok(())
    } else {
        Err(Failure {
            error: SubmitError::Permanent,
            open: true,
        })
    }
}

#[derive(Serialize)]
struct CleanupFailed {
    error_class: &'static str,
}

impl SmtpSubmitter {
    #[cfg(test)]
    pub(crate) fn set_session_timeout_for_test(&mut self, seconds: f64) {
        self.config.session_timeout = Duration::from_secs_f64(seconds);
    }

    async fn session(&self, message: &BuiltMessage) -> Result<Vec<Refusal>, SubmitError> {
        let recipients: Vec<(Address, &str)> = message
            .envelope
            .iter()
            .map(|address| envelope_address(address).map(|a| (a, address.as_str())))
            .collect::<Option<_>>()
            // `smtplib` without SMTPUTF8: SMTPNotSupportedError, 503.
            .ok_or(SubmitError::Temporary)?;

        // The timed future owns the stream/connection, so expiry closes it.
        // Stop this deadline at the DATA outcome; QUIT has its own budget.
        let (mut connection, outcome) = tokio::time::timeout(self.config.session_timeout, async {
            let written = Arc::new(AtomicBool::new(false));
            let stream = self
                .connect(Arc::clone(&written))
                .await
                .map_err(|_| SubmitError::Temporary)?;
            let mut connection =
                match AsyncSmtpConnection::connect_with_transport(Box::new(stream), &self.hello)
                    .await
                {
                    Ok(connection) => connection,
                    Err(error) if !written.load(Ordering::SeqCst) => {
                        return Err(failure(&error).error);
                    }
                    Err(error) => return Err(self.ehlo_failure(&error)),
                };
            let outcome = self
                .transaction(&mut connection, &recipients, message)
                .await;
            Ok((connection, outcome))
        })
        .await
        .map_err(|_| SubmitError::Temporary)??;
        let open = match &outcome {
            Ok(_) => true,
            Err(failure) => failure.open,
        };
        // lettre itself sent QUIT and closed when it gave up (`abort`).
        if open && !connection.has_broken() {
            self.quit(&mut connection).await;
        }
        drop(connection);
        outcome.map_err(|failure| failure.error)
    }

    /// One budget for resolution and all TCP address attempts. Socket I/O
    /// after connection retains its separate per-operation timeout.
    async fn connect(&self, written: Arc<AtomicBool>) -> io::Result<RelayStream> {
        let config = &self.config;
        let tcp = connect_with_budget(
            config.timeout,
            tokio::net::lookup_host((config.host.as_str(), config.port)),
            TcpStream::connect,
        )
        .await?;
        // Avoid delayed ACK waits between the small DATA/TLS writes.
        let _ = tcp.set_nodelay(true);
        Ok(RelayStream::new(tcp, config.timeout, written))
    }

    /// Python ignores the EHLO reply (`smtp_client.py` `smtp.ehlo()`), so
    /// the next step decides (2.4): with STARTTLS it finds no STARTTLS
    /// (503), without it the credentials are refused in cleartext (502). A
    /// transport failure during EHLO is 503 either way.
    fn ehlo_failure(&self, error: &Error) -> SubmitError {
        match code(error) {
            Some(_) if self.config.tls.is_none() => SubmitError::Permanent,
            _ => SubmitError::Temporary,
        }
    }

    async fn transaction(
        &self,
        connection: &mut AsyncSmtpConnection,
        recipients: &[(Address, &str)],
        message: &BuiltMessage,
    ) -> Result<Vec<Refusal>, Failure> {
        let config = &self.config;
        if let Some(tls) = &config.tls
            && let Err(error) = connection.starttls(tls.clone(), &self.hello).await
        {
            return Err(if connection.is_encrypted() {
                // EHLO after the handshake failed: `login` then finds no
                // AUTH extension (SMTPNotSupportedError, 503).
                Failure {
                    error: SubmitError::Temporary,
                    open: false,
                }
            } else {
                failure(&error)
            });
        }
        if !connection.is_encrypted() {
            // Never send the credentials in cleartext (always configured).
            return Err(Failure {
                error: SubmitError::Permanent,
                open: true,
            });
        }
        self.login(connection).await?;

        // No MAIL parameters: the envelope is ASCII and the message 7-bit.
        let mail = connection.command(Mail::new(config.sender.clone(), vec![]));
        require(&mail.await.map_err(|e| failure(&e))?, &[250])?;

        let mut accepted = 0;
        let mut refused = Vec::new();
        let mut closed = false;
        for (address, raw) in recipients {
            let reply = match connection.command(Rcpt::new(address.clone(), vec![])).await {
                Ok(response) => u16::from(response.code()),
                Err(error) => match code(&error) {
                    Some(code) => code,
                    None => return Err(failure(&error)),
                },
            };
            if matches!(reply, 250 | 251) {
                accepted += 1;
                continue;
            }
            refused.push(Refusal {
                address: (*raw).to_owned(),
                code: Some(reply),
            });
            if reply == 421 {
                // `smtplib` closes and reports the refusals so far, even
                // when earlier recipients were accepted.
                closed = true;
                break;
            }
        }
        if accepted == 0 || closed {
            // SMTPRecipientsRefused: one temporary refusal makes it 503.
            let temporary = refused
                .iter()
                .any(|r| r.code.is_some_and(|c| (400..500).contains(&c)));
            return Err(Failure {
                error: if temporary {
                    SubmitError::Temporary
                } else {
                    SubmitError::Permanent
                },
                open: !closed,
            });
        }

        let data = connection.command(Data).await.map_err(|e| failure(&e))?;
        require(&data, &[354])?;
        // lettre ends the data with CRLF "." CRLF; the message's own final
        // CRLF is that first CRLF (as `smtplib` sends it), not an empty line.
        let formatted = &message.formatted;
        let body = formatted.strip_suffix(b"\r\n").unwrap_or(formatted);
        let end = connection
            .message_iter(body.chunks(MESSAGE_CHUNK))
            .await
            .map_err(|e| failure(&e))?;
        require(&end, &[250])?;
        Ok(refused)
    }

    /// `smtplib.login`: each offered mechanism in turn (PLAIN, then LOGIN;
    /// lettre has no CRAM-MD5, D-4) until one is answered with 235. A
    /// refusal with a code moves on to the next mechanism; when all were
    /// refused, SMTPAuthenticationError: 502. 421 (the server closed) and
    /// failures without a code end the session: 503.
    async fn login(&self, connection: &mut AsyncSmtpConnection) -> Result<(), Failure> {
        let offered: Vec<Mechanism> = [Mechanism::Plain, Mechanism::Login]
            .into_iter()
            .filter(|m| connection.server_info().supports_auth_mechanism(*m))
            .collect();
        if offered.is_empty() {
            // No AUTH extension or no common mechanism: SMTPException, 503.
            return Err(Failure {
                error: SubmitError::Temporary,
                open: true,
            });
        }
        for mechanism in offered {
            match connection
                .auth(&[mechanism], &self.config.credentials)
                .await
            {
                Ok(response) if u16::from(response.code()) == 235 => return Ok(()),
                Ok(_) => {}
                Err(error) if code(&error).is_none_or(|c| c == 421) => {
                    return Err(failure(&error));
                }
                Err(_) => {}
            }
        }
        Err(Failure {
            error: SubmitError::Permanent,
            open: true,
        })
    }

    /// `QUIT` must be answered with 221; anything else is logged and
    /// ignored (`smtp_client.py` cleanup).
    async fn quit(&self, connection: &mut AsyncSmtpConnection) {
        let error_class = match tokio::time::timeout(
            self.config.timeout.min(CLEANUP_TIMEOUT),
            connection.command(Quit),
        )
        .await
        {
            Ok(Ok(response)) if u16::from(response.code()) == 221 => return,
            Ok(Ok(_)) => "UnexpectedReply",
            Ok(Err(error)) if code(&error).is_some() => "NegativeReply",
            Err(_) => "Timeout",
            Ok(Err(error)) if error.is_timeout() => "Timeout",
            Ok(Err(_)) => "Disconnected",
        };
        self.logger.emit(
            Level::Warning,
            SERVICE_LOGGER,
            "smtp_cleanup_failed",
            &CleanupFailed { error_class },
        );
    }
}

/// The resolver and connector are futures so tests need no DNS or sockets.
async fn connect_with_budget<T, A, R, C, F>(
    budget: Duration,
    resolve: R,
    mut connect: C,
) -> io::Result<T>
where
    A: IntoIterator<Item = SocketAddr>,
    R: std::future::Future<Output = io::Result<A>>,
    C: FnMut(SocketAddr) -> F,
    F: std::future::Future<Output = io::Result<T>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    tokio::time::timeout_at(deadline, async {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        let addresses: Vec<_> = resolve.await?.into_iter().collect();
        for (index, address) in addresses.iter().enumerate() {
            // Reserve a share for later addresses when an earlier one hangs.
            let left = u32::try_from(addresses.len() - index).unwrap_or(u32::MAX);
            let share = deadline.saturating_duration_since(tokio::time::Instant::now()) / left;
            match tokio::time::timeout(share, connect(*address)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => last = error,
                Err(_) => last = io::ErrorKind::TimedOut.into(),
            }
        }
        Err(last)
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// The TCP stream lettre talks over: read and write timeouts per socket
/// operation (`SMTP_TIMEOUT_S`, Python's socket timeout; rustls wraps this
/// stream, so they also hold under TLS) and a flag set by the first write,
/// which tells a banner failure from an EHLO failure.
struct RelayStream {
    inner: Pin<Box<TimeoutStream<TcpStream>>>,
    written: Arc<AtomicBool>,
    inbound_remaining: usize,
}

impl RelayStream {
    fn new(tcp: TcpStream, timeout: Duration, written: Arc<AtomicBool>) -> Self {
        let mut inner = TimeoutStream::new(tcp);
        inner.set_read_timeout(Some(timeout));
        inner.set_write_timeout(Some(timeout));
        RelayStream {
            inner: Box::pin(inner),
            written,
            inbound_remaining: INBOUND_BYTES,
        }
    }
}

impl std::fmt::Debug for RelayStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayStream")
    }
}

impl AsyncRead for RelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.inbound_remaining == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP inbound byte limit",
            )));
        }
        let limit = buf.remaining().min(self.inbound_remaining);
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(limit));
        let result = self.inner.as_mut().poll_read(cx, &mut limited);
        let read = limited.filled().len();
        buf.advance(read);
        self.inbound_remaining -= read;
        result
    }
}

impl AsyncWrite for RelayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.store(true, Ordering::SeqCst);
        self.inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

impl AsyncTokioStream for RelayStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.get_ref().peer_addr()
    }
}

#[cfg(test)]
#[path = "smtp_tests.rs"]
pub(crate) mod tests;
