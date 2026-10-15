//! S1b spike: lettre's connection-level API for the mailgun-relay port.
//!
//! Modes (all arguments `key=value`):
//!   submit host= port= [starttls=true] [ca_file=] [user=] [pass_env=VAR]
//!          from= to=a@x,b@y [timeout_s=30] [roots=native|webpki|none]
//!   ehlo   host= port= [roots=native|webpki|none]   (EHLO, STARTTLS, EHLO, QUIT only)
//!   addr   value                               (lettre Address round-trip)
//!
//! Only public lettre API is used: `AsyncSmtpConnection` plus lettre's
//! command types (`Mail`, `Rcpt`, `Data`, `Rset`) and `message()`.

use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use lettre::{
    Address, Message,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        Error as SmtpError,
        authentication::{Credentials, Mechanism},
        client::{AsyncSmtpConnection, AsyncTokioStream, Certificate, CertificateStore, TlsParameters},
        commands::{Data, Mail, Rcpt, Rset},
        extension::{ClientId, Extension},
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_io_timeout::TimeoutStream;

/// TCP stream with per-operation read/write timeouts (Python's socket
/// timeout semantics) that also records whether anything was written yet.
/// "Nothing written" when `connect_with_transport` fails means the banner
/// failed; otherwise the EHLO reply failed.
struct RelayStream {
    inner: Pin<Box<TimeoutStream<TcpStream>>>,
    wrote: Arc<AtomicBool>,
}

impl fmt::Debug for RelayStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayStream")
    }
}

impl AsyncRead for RelayStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for RelayStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.wrote.store(true, Ordering::SeqCst);
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

struct Cfg {
    host: String,
    port: u16,
    starttls: bool,
    ca_file: Option<String>,
    creds: Option<Credentials>,
    timeout: Duration,
    roots: String,
}

#[derive(Debug)]
struct Outcome {
    status: u16,
    phase: &'static str,
    accepted: Vec<String>,
    refused: Vec<(String, u16)>,
    error: Option<String>,
    quit: &'static str,
}

impl Outcome {
    fn fail(status: u16, phase: &'static str, e: Option<&SmtpError>) -> Self {
        Outcome {
            status,
            phase,
            accepted: vec![],
            refused: vec![],
            error: e.map(describe),
            quit: "-",
        }
    }
}

fn describe(e: &SmtpError) -> String {
    let kind = if e.is_transient() || e.is_permanent() {
        "code"
    } else if e.is_tls() {
        "tls"
    } else if e.is_client() {
        "client"
    } else if e.is_response() {
        "response"
    } else if e.is_timeout() {
        "timeout"
    } else {
        "network/connection"
    };
    format!("{kind}: {e}")
}

fn code(e: &SmtpError) -> Option<u16> {
    e.status().map(u16::from)
}

/// Python rule: 4xx -> 503, every other reply code -> 502; no reply code
/// (transport, TLS, missing extension, ...) -> 503 (D-3).
fn status_for(e: &SmtpError) -> u16 {
    match code(e) {
        Some(c) if (400..500).contains(&c) => 503,
        Some(_) => 502,
        None => 503,
    }
}

fn tls_params(cfg: &Cfg) -> Result<TlsParameters, SmtpError> {
    let store = match cfg.roots.as_str() {
        "webpki" => CertificateStore::WebpkiRoots,
        "none" => CertificateStore::None, // only ca_file (e.g. a copy of the Ubuntu bundle)
        _ => CertificateStore::Default, // rustls-native-certs: system store
    };
    let mut b = TlsParameters::builder(cfg.host.clone()).certificate_store(store);
    if let Some(path) = &cfg.ca_file {
        let pem = std::fs::read(path).expect("read ca_file");
        b = b.add_root_certificate(Certificate::from_pem(&pem)?);
    }
    b.build_rustls()
}

async fn open(cfg: &Cfg, hello: &ClientId) -> Result<AsyncSmtpConnection, Outcome> {
    let tcp = match tokio::time::timeout(cfg.timeout, TcpStream::connect((cfg.host.as_str(), cfg.port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let mut o = Outcome::fail(503, "connect", None);
            o.error = Some(format!("io: {e}"));
            return Err(o);
        }
        Err(_) => {
            let mut o = Outcome::fail(503, "connect", None);
            o.error = Some("connect timeout".into());
            return Err(o);
        }
    };
    let mut ts = TimeoutStream::new(tcp);
    ts.set_read_timeout(Some(cfg.timeout));
    ts.set_write_timeout(Some(cfg.timeout));
    let wrote = Arc::new(AtomicBool::new(false));
    let stream = RelayStream { inner: Box::pin(ts), wrote: wrote.clone() };
    match AsyncSmtpConnection::connect_with_transport(Box::new(stream), hello).await {
        Ok(c) => Ok(c),
        Err(e) if !wrote.load(Ordering::SeqCst) => Err(Outcome::fail(status_for(&e), "banner", Some(&e))),
        Err(e) => {
            // EHLO refused: Python ignores the EHLO reply and the next step
            // decides. With STARTTLS on that is "STARTTLS not offered" (503);
            // with STARTTLS off and credentials it is the cleartext refusal
            // (502). A transport failure during EHLO is 503 either way.
            let status = match (code(&e), cfg.starttls, cfg.creds.is_some()) {
                (None, _, _) => 503,
                (Some(_), true, _) => 503,
                (Some(_), false, true) => 502,
                (Some(c), false, false) => if (400..500).contains(&c) { 503 } else { 502 }, // not reachable in prod: creds are mandatory
            };
            Err(Outcome::fail(status, "ehlo", Some(&e)))
        }
    }
}

/// QUIT unless the server already closed the channel (421 or transport loss).
async fn cleanup(conn: &mut AsyncSmtpConnection, server_closed: bool) -> &'static str {
    if server_closed {
        return "skipped";
    }
    match conn.quit().await {
        Ok(_) => "ok",
        Err(_) => "smtp_cleanup_failed",
    }
}

fn closed(e: &SmtpError) -> bool {
    code(e) == Some(421) || (code(e).is_none() && !e.is_client())
}

async fn submit(cfg: &Cfg, from: Option<Address>, rcpts: &[Address], body: &[u8]) -> Outcome {
    let hello = ClientId::default();
    let mut conn = match open(cfg, &hello).await {
        Ok(c) => c,
        Err(o) => return o,
    };

    if cfg.starttls {
        let params = match tls_params(cfg) {
            Ok(p) => p,
            Err(e) => return Outcome::fail(503, "tls_config", Some(&e)),
        };
        if let Err(e) = conn.starttls(params, &hello).await {
            if conn.is_encrypted() {
                // EHLO after STARTTLS refused: Python's login() then finds no
                // AUTH extension -> SMTPNotSupportedError -> 503.
                return Outcome::fail(503, "ehlo_tls", Some(&e));
            }
            return Outcome::fail(status_for(&e), "starttls", Some(&e));
        }
    }

    if let Some(creds) = &cfg.creds {
        if !conn.is_encrypted() {
            let mut o = Outcome::fail(502, "auth_cleartext_refused", None);
            o.quit = cleanup(&mut conn, false).await;
            return o;
        }
        if let Err(e) = conn.auth(&[Mechanism::Plain, Mechanism::Login], creds).await {
            // AUTH refused with any reply code -> 502 (SMTPAuthenticationError);
            // no common mechanism / no AUTH offered / transport -> 503.
            let status = if code(&e).is_some() { 502 } else { 503 };
            let mut o = Outcome::fail(status, "auth", Some(&e));
            o.quit = cleanup(&mut conn, closed(&e)).await;
            return o;
        }
    }

    // No SMTPUTF8 / 8BITMIME parameters: addresses are ASCII (A-labels, Q2)
    // and the body is 7-bit clean (D-14).
    if let Err(e) = conn.command(Mail::new(from, vec![])).await {
        let mut o = Outcome::fail(status_for(&e), "mail", Some(&e));
        o.quit = cleanup(&mut conn, closed(&e)).await;
        return o;
    }

    let mut accepted = vec![];
    let mut refused = vec![];
    let mut channel_closed = false;
    for rcpt in rcpts {
        match conn.command(Rcpt::new(rcpt.clone(), vec![])).await {
            Ok(_) => accepted.push(rcpt.to_string()),
            Err(e) => match code(&e) {
                Some(c) => {
                    refused.push((rcpt.to_string(), c));
                    if c == 421 {
                        // smtplib closes and raises SMTPRecipientsRefused with the
                        // refusals so far, even if earlier recipients were accepted.
                        channel_closed = true;
                        break;
                    }
                }
                None => return Outcome::fail(503, "rcpt", Some(&e)),
            },
        }
    }

    if accepted.is_empty() || channel_closed {
        let status = if refused.iter().any(|(_, c)| (400..500).contains(c)) { 503 } else { 502 };
        if !channel_closed {
            let _ = conn.command(Rset).await;
        }
        let quit = cleanup(&mut conn, channel_closed).await;
        return Outcome { status, phase: "rcpt_all_refused", accepted, refused, error: None, quit };
    }

    if let Err(e) = conn.command(Data).await {
        let mut o = Outcome::fail(status_for(&e), "data", Some(&e));
        o.quit = cleanup(&mut conn, closed(&e)).await;
        return o;
    }
    if let Err(e) = conn.message(body).await {
        let mut o = Outcome::fail(status_for(&e), "data_end", Some(&e));
        o.quit = cleanup(&mut conn, closed(&e)).await;
        return o;
    }
    let quit = cleanup(&mut conn, false).await;
    Outcome { status: 200, phase: "done", accepted, refused, error: None, quit }
}

async fn ehlo_probe(cfg: &Cfg) {
    let hello = ClientId::default();
    println!("hello_name={hello}");
    let mut conn = match open(cfg, &hello).await {
        Ok(c) => c,
        Err(o) => return println!("{o:?}"),
    };
    println!("pre_tls server_info: {}", conn.server_info());
    let params = tls_params(cfg).expect("tls params");
    match conn.starttls(params, &hello).await {
        Ok(()) => {
            let info = conn.server_info();
            println!("post_tls encrypted={} server_info: {info}", conn.is_encrypted());
            for m in [Mechanism::Plain, Mechanism::Login, Mechanism::Xoauth2] {
                println!("  auth {m:?}: {}", info.supports_auth_mechanism(m));
            }
            println!("  SMTPUTF8: {}", info.supports_feature(Extension::SmtpUtfEight));
            println!("  8BITMIME: {}", info.supports_feature(Extension::EightBitMime));
            println!("  peer chain certs: {}", conn.certificate_chain().map(|c| c.len()).unwrap_or(0));
        }
        Err(e) => println!("starttls failed: {}", describe(&e)),
    }
    println!("quit: {}", cleanup(&mut conn, false).await);
}

fn sample_message(from: &str, to: &[Address]) -> Vec<u8> {
    let mut b = Message::builder()
        .from(Mailbox::from_str(from).expect("from"))
        .subject("s1b spike");
    for t in to {
        b = b.to(Mailbox::new(None, t.clone()));
    }
    b.header(ContentType::TEXT_PLAIN).body(String::from("spike body\n")).expect("message").formatted()
}

fn parse_args() -> (String, HashMap<String, String>, Vec<String>) {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let mut kv = HashMap::new();
    let mut pos = vec![];
    for a in args {
        match a.split_once('=') {
            Some((k, v)) if !k.contains('@') => {
                kv.insert(k.to_string(), v.to_string());
            }
            _ => pos.push(a),
        }
    }
    (mode, kv, pos)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (mode, kv, pos) = parse_args();
    let get = |k: &str| kv.get(k).cloned();
    if mode == "addr" {
        for v in pos {
            match Address::from_str(&v) {
                Ok(a) => println!("ok   {v:?} -> {:?} (user={:?} domain={:?})", a.to_string(), a.user(), a.domain()),
                Err(e) => println!("err  {v:?}: {e}"),
            }
        }
        return;
    }
    let creds = get("user").map(|u| {
        let pass = std::env::var(get("pass_env").unwrap_or_else(|| "S1B_SMTP_PASS".into())).unwrap_or_default();
        Credentials::new(u, pass)
    });
    let cfg = Cfg {
        host: get("host").unwrap_or_else(|| "localhost".into()),
        port: get("port").and_then(|p| p.parse().ok()).unwrap_or(587),
        starttls: get("starttls").map(|v| v == "true").unwrap_or(true),
        ca_file: get("ca_file"),
        creds,
        timeout: Duration::from_secs_f64(get("timeout_s").and_then(|v| v.parse().ok()).unwrap_or(30.0)),
        roots: get("roots").unwrap_or_else(|| "native".into()),
    };
    match mode.as_str() {
        "ehlo" => ehlo_probe(&cfg).await,
        "submit" => {
            let from = get("from").unwrap_or_else(|| "sender@example.com".into());
            let rcpts: Vec<Address> = get("to")
                .unwrap_or_default()
                .split(',')
                .map(|a| Address::from_str(a).expect("rcpt address"))
                .collect();
            let envelope_from = Some(Address::from_str(&from).expect("from address"));
            let body = sample_message(&from, &rcpts);
            let o = submit(&cfg, envelope_from, &rcpts, &body).await;
            println!(
                "status={} phase={} accepted={:?} refused={:?} quit={} error={}",
                o.status,
                o.phase,
                o.accepted,
                o.refused,
                o.quit,
                o.error.unwrap_or_else(|| "-".into())
            );
            if get("hold_s").is_some() {
                // keep the process alive for an RSS reading
                tokio::time::sleep(Duration::from_secs(get("hold_s").unwrap().parse().unwrap())).await;
            }
        }
        _ => eprintln!("usage: s1b-spike submit|ehlo|addr key=value ..."),
    }
}

/// Compile-time check: the submission future is `Send`, so axum handlers
/// and `tokio::spawn` can drive it on a multi-threaded runtime as well.
#[allow(dead_code)]
fn assert_submit_is_send(cfg: &'static Cfg, rcpts: &'static [Address], body: &'static [u8]) {
    fn is_send<T: Send>(_: T) {}
    is_send(submit(cfg, None, rcpts, body));
}
