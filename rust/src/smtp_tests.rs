//! Submission tests against the scripted fake SMTP server: the Rust
//! counterparts of `tests/test_smtp_submission.py` and
//! `tests/test_smtp_outcomes.py` (submit side), TLS with a test CA through
//! `SMTP_CA_FILE`, and the cleanup rules of PLAN.md 2.4.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use serde_json::{Value as Json, json};

use super::*;
use crate::config::Settings;

#[path = "../tests/support/fake_smtp.rs"]
pub(crate) mod fake_smtp;

use fake_smtp::{FakeSmtp, Pki, Session};

pub(crate) static PKI: LazyLock<Pki> = LazyLock::new(Pki::new);

/// The test CA as a file, for `SMTP_CA_FILE`.
static CA_FILE: LazyLock<tempfile::NamedTempFile> = LazyLock::new(|| {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &PKI.ca_pem).unwrap();
    file
});

/// The system roots plus the test CA, built once (loading the system roots
/// is slow on macOS).
static TLS: LazyLock<TlsParameters> = LazyLock::new(|| {
    tls_parameters(&settings(0, true, Some(ca_path())))
        .unwrap()
        .unwrap()
});

pub(crate) fn ca_path() -> String {
    CA_FILE.path().to_str().unwrap().to_owned()
}

/// Settings for a fake server on `localhost:<port>`.
pub(crate) fn settings(port: u16, starttls: bool, ca_file: Option<String>) -> Settings {
    Settings {
        smtp_host: "localhost".to_owned(),
        smtp_port: port,
        smtp_starttls: starttls,
        smtp_timeout_s: 5.0,
        smtp_ca_file: ca_file.unwrap_or_default(),
        envelope_sender: "sender@example.com".to_owned(),
        ..Settings::from_env([]).unwrap()
    }
}

fn credentials() -> SmtpCredentials {
    SmtpCredentials {
        username: "relay".to_owned(),
        password: "not-a-real-password".to_owned(),
    }
}

/// A submitter for the fake server, with the shared TLS parameters.
pub(crate) fn submitter(
    port: u16,
    starttls: bool,
    timeout_s: f64,
    logger: Logger,
) -> SmtpSubmitter {
    let mut config = SmtpConfig::load(&settings(port, false, None), &credentials()).unwrap();
    config.tls = starttls.then(|| TLS.clone());
    config.timeout = Duration::from_secs_f64(timeout_s);
    SmtpSubmitter::new(config, logger)
}

fn message(recipients: &[&str]) -> BuiltMessage {
    BuiltMessage {
        message_id: "<abc@example.test>".to_owned(),
        envelope: recipients.iter().map(|r| (*r).to_owned()).collect(),
        formatted: b"From: Alice <alice@example.test>\r\nTo: bob@example.test\r\n\
                     Subject: hi\r\nMessage-Id: <abc@example.test>\r\n\r\nhello\r\n"
            .to_vec(),
    }
}

/// One submission against a fresh fake server.
struct Run {
    outcome: Result<Vec<Refusal>, SubmitError>,
    sessions: Vec<Session>,
    logs: Vec<Json>,
}

impl Run {
    fn session(&self) -> &Session {
        assert_eq!(self.sessions.len(), 1, "{:?}", self.sessions);
        &self.sessions[0]
    }

    fn commands(&self) -> Vec<String> {
        self.session().commands()
    }

    fn cleanup_records(&self) -> Vec<&Json> {
        self.logs
            .iter()
            .filter(|r| r["event"] == "smtp_cleanup_failed")
            .collect()
    }
}

async fn run_with(
    scenario: Json,
    certificate: &str,
    recipients: &[&str],
    starttls: bool,
    timeout_s: f64,
) -> Run {
    let server = FakeSmtp::start(&scenario, Some(PKI.by_name(certificate))).await;
    let (logger, lines) = Logger::capturing(Level::Info);
    let submitter = submitter(server.port, starttls, timeout_s, logger);
    let outcome = submitter.submit(message(recipients)).await;
    // The server records the end of a session after the client closed.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let logs = lines
        .lock()
        .unwrap()
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    Run {
        outcome,
        sessions: server.sessions(),
        logs,
    }
}

async fn run(scenario: Json, recipients: &[&str]) -> Run {
    run_with(scenario, "good", recipients, true, 5.0).await
}

fn status_of(outcome: &Result<Vec<Refusal>, SubmitError>) -> u16 {
    match outcome {
        Ok(_) => 200,
        Err(SubmitError::Temporary) => 503,
        Err(SubmitError::Permanent) => 502,
    }
}

const THREE: [&str; 3] = ["ok1@example.com", "bad@example.com", "ok2@example.com"];

/// `test_smtp_submission.py`: the happy path over STARTTLS with AUTH, the
/// envelope, partial and complete refusal, no credentials in cleartext,
/// connection refused and a timeout.
#[tokio::test]
async fn python_smtp_submission_tests() {
    let ok = run(json!({}), &["bob@example.test", "secret@example.test"]).await;
    assert_eq!(ok.outcome, Ok(Vec::new()));
    let session = ok.session();
    assert!(session.tls);
    assert_eq!(
        ok.commands(),
        [
            "EHLO", "STARTTLS", "EHLO", "AUTH", "MAIL", "RCPT", "RCPT", "DATA", "QUIT"
        ]
    );
    assert!(session.log.contains(&"S: <auth PLAIN>".to_owned()));
    assert_eq!(session.mail_from.as_deref(), Some("sender@example.com"));
    assert_eq!(
        session.data_for.as_deref(),
        Some(
            &[
                "bob@example.test".to_owned(),
                "secret@example.test".to_owned()
            ][..]
        )
    );
    assert_eq!(
        session.message.as_deref(),
        Some(&message(&[]).formatted[..])
    );
    assert!(ok.cleanup_records().is_empty());

    // Partial refusal: the refused recipient with its code, DATA for the rest.
    let partial = run(
        json!({"rcpt": {"nope": 550}}),
        &["bob@example.test", "nope@refused.test"],
    )
    .await;
    assert_eq!(
        partial.outcome,
        Ok(vec![Refusal {
            address: "nope@refused.test".to_owned(),
            code: Some(550),
        }])
    );
    assert_eq!(
        partial.session().data_for.as_deref(),
        Some(&["bob@example.test".to_owned()][..])
    );
    let all = run(json!({"rcpt": {"nope": 550}}), &["nope@refused.test"]).await;
    assert_eq!(all.outcome, Err(SubmitError::Permanent));
    assert_eq!(all.session().message, None);

    // No STARTTLS: the credentials are never sent, nothing is submitted.
    let cleartext = run_with(json!({"offer_starttls": false}), "good", &THREE, false, 5.0).await;
    assert_eq!(cleartext.outcome, Err(SubmitError::Permanent));
    assert_eq!(cleartext.commands(), ["EHLO", "QUIT"]);

    // Connection refused: a port nobody listens on.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let (logger, _) = Logger::capturing(Level::Info);
    let refused = submitter(port, true, 5.0, logger)
        .submit(message(&THREE))
        .await;
    assert_eq!(refused, Err(SubmitError::Temporary));

    // A silent server: the per-operation timeout, then 503.
    let started = Instant::now();
    let silent = run_with(
        json!({"fault": {"banner": "hang"}}),
        "good",
        &THREE,
        true,
        0.2,
    )
    .await;
    assert_eq!(silent.outcome, Err(SubmitError::Temporary));
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// One case per row of PLAN.md 2.4 (statuses as Python's `submit` maps
/// the same server): STARTTLS on unless `"tls": false` is given, the
/// three recipients unless `"single"` is set.
#[tokio::test]
async fn every_row_of_the_outcome_table() {
    let off = false;
    for (case, status) in [
        (json!({}), 200),
        (json!({"rcpt": {"bad": 550}}), 200),
        (json!({"rcpt": {"ok1": 550, "bad": 450, "ok2": 550}}), 503),
        (json!({"rcpt": {"ok1": 550, "bad": 553, "ok2": 550}}), 502),
        (json!({"rcpt": {"bad": 421}}), 503),
        (json!({"rcpt": {"ok1": 252}, "single": true}), 502),
        (json!({"banner": 421}), 503),
        (json!({"banner": 554}), 502),
        (json!({"starttls": 454}), 503),
        (json!({"starttls": 554}), 502),
        (json!({"mail": 451}), 503),
        (json!({"mail": 550}), 502),
        (json!({"mail": 251}), 502),
        (json!({"data": 451}), 503),
        (json!({"data": 554}), 502),
        (json!({"data_end": 450}), 503),
        (json!({"data_end": 552}), 502),
        (json!({"data_end": 251}), 502),
        // EHLO: the next step decides.
        (json!({"ehlo": 550}), 503),
        (json!({"ehlo": 421}), 503),
        (json!({"ehlo_tls": 550}), 503),
        (json!({"ehlo": 550, "offer_starttls": off, "tls": off}), 502),
        (json!({"ehlo": 421, "offer_starttls": off, "tls": off}), 502),
        // AUTH: any code is 502, but 421 is a disconnect for `smtplib`.
        (json!({"auth": 535}), 502),
        (json!({"auth": 454}), 502),
        (json!({"auth": 250}), 502),
        (json!({"auth": 421}), 503),
        // `smtplib.login` falls back from PLAIN to LOGIN.
        (json!({"auth_plain": 535}), 200),
        (json!({"auth_plain": 250}), 200),
        (json!({"auth_plain": 535, "auth_login": 454}), 502),
        (json!({"auth_plain": 421}), 503),
        (json!({"auth_offer": "LOGIN"}), 200),
        // Credentials without TLS: never sent.
        (json!({"offer_starttls": off, "tls": off}), 502),
        // Transport failures and missing extensions (Q3).
        (json!({"offer_starttls": off}), 503),
        (json!({"auth_offer": ""}), 503),
        (json!({"auth_offer": "CRAM-MD5"}), 503),
        (json!({"fault": {"mail": "close"}}), 503),
        (json!({"fault": {"rcpt": "close"}}), 503),
        // A reply without a code: 503 where `smtplib` says 502 (D-3).
        (json!({"fault": {"mail": "garbage"}}), 503),
        // QUIT is cleanup only.
        (json!({"quit": 500}), 200),
    ] {
        let mut scenario = case.clone();
        let fields = scenario.as_object_mut().unwrap();
        let starttls = fields.remove("tls").is_none_or(|v| v == true);
        let single = fields.remove("single").is_some();
        let recipients = if single { &THREE[..1] } else { &THREE[..] };
        let run = run_with(scenario, "good", recipients, starttls, 5.0).await;
        assert_eq!(status_of(&run.outcome), status, "{case}");
    }
}

/// The null sender, the exact positive codes `smtplib` requires, and the
/// ASCII envelope (Q2: lettre never adds SMTPUTF8).
#[tokio::test]
async fn envelope_and_reply_codes() {
    let server = FakeSmtp::start(&json!({}), Some(PKI.by_name("good"))).await;
    let (logger, _) = Logger::capturing(Level::Info);
    let mut null = submitter(server.port, true, 5.0, logger);
    null.config.sender = None;
    assert_eq!(
        null.submit(message(&["a@example.test"])).await,
        Ok(Vec::new())
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(server.sessions()[0].mail_from.as_deref(), Some(""));

    for envelope in [
        &["jörg@example.test"][..],
        &["a@exämple.test"],
        &["a b@example.test"],
    ] {
        let server = FakeSmtp::start(&json!({}), Some(PKI.by_name("good"))).await;
        let (logger, _) = Logger::capturing(Level::Info);
        let reply = submitter(server.port, true, 5.0, logger)
            .submit(message(envelope))
            .await;
        assert_eq!(reply, Err(SubmitError::Temporary), "{envelope:?}");
        assert!(server.sessions().is_empty(), "{envelope:?}");
    }
    // A 65-character local part (accepted by Python, refused by lettre's
    // own parser) goes out unchanged.
    let long = format!("{}@example.test", "a".repeat(65));
    let accepted = run(json!({}), &[&long]).await;
    assert_eq!(accepted.outcome, Ok(Vec::new()));
    assert_eq!(accepted.session().data_for, Some(vec![long]));
    assert!(envelope_address("<a@b>").is_none() && envelope_address("ab").is_none());
}

/// PLAN.md 2.4 session rules and `test_smtp_outcomes.py`: QUIT after every
/// outcome while the channel is open, never after 421 or a lost
/// connection; a failed QUIT never changes the outcome and is logged as
/// `smtp_cleanup_failed` without reply texts.
#[tokio::test]
async fn cleanup_never_changes_the_outcome() {
    for (scenario, recipients, outcome) in [
        (
            json!({"quit": 500}),
            &["a@example.test"][..],
            Ok(Vec::new()),
        ),
        (
            json!({"fault": {"quit": "close"}}),
            &["a@example.test"],
            Ok(Vec::new()),
        ),
        (
            json!({"quit": 500, "rcpt": {"nope": 550}}),
            &["a@example.test", "nope@example.test"],
            Ok(vec![Refusal {
                address: "nope@example.test".to_owned(),
                code: Some(550),
            }]),
        ),
        (
            json!({"quit": 500, "data": 451}),
            &["a@example.test"],
            Err(SubmitError::Temporary),
        ),
    ] {
        let run = run(scenario.clone(), recipients).await;
        assert_eq!(run.outcome, outcome, "{scenario}");
        assert_eq!(run.commands().last().unwrap(), "QUIT", "{scenario}");
        let records = run.cleanup_records();
        assert_eq!(records.len(), 1, "{scenario}");
        assert_eq!(records[0]["level"], "WARNING");
        assert_eq!(records[0]["logger"], "mailgun_relay.service");
        assert!(records[0]["error_class"].is_string());
        let text = serde_json::to_string(&run.logs).unwrap();
        assert!(
            !text.contains("bye") && !text.contains("example.test"),
            "{text}"
        );
    }

    // The server already closed the channel: no QUIT, no record.
    for scenario in [
        json!({"data": 421}),
        json!({"data_end": 421}),
        json!({"mail": 421}),
        json!({"rcpt": {"a": 421}}),
        json!({"fault": {"data_end": "close"}}),
        json!({"fault": {"mail": "close"}}),
    ] {
        let run = run(scenario.clone(), &["a@example.test"]).await;
        assert_eq!(run.outcome, Err(SubmitError::Temporary), "{scenario}");
        assert!(!run.commands().contains(&"QUIT".to_owned()), "{scenario}");
        assert!(run.cleanup_records().is_empty(), "{scenario}");
    }
    let timeout = run_with(
        json!({"fault": {"data_end": "hang"}}),
        "good",
        &THREE,
        true,
        0.2,
    )
    .await;
    assert_eq!(timeout.outcome, Err(SubmitError::Temporary));
    assert!(!timeout.commands().contains(&"QUIT".to_owned()));
    assert!(timeout.cleanup_records().is_empty());

    // Refusals before the transaction still end with QUIT (S1b condition
    // 5: also when STARTTLS is not offered).
    for (scenario, status) in [
        (json!({"offer_starttls": false}), 503),
        (json!({"auth_offer": ""}), 503),
        (json!({"auth": 535}), 502),
        (json!({"mail": 550}), 502),
        (json!({"rcpt": {"a": 550}}), 502),
        (json!({"data": 554}), 502),
        (json!({"data_end": 552}), 502),
        (json!({"data": 250}), 502),
    ] {
        let run = run(scenario.clone(), &["a@example.test"]).await;
        assert_eq!(status_of(&run.outcome), status, "{scenario}");
        assert_eq!(
            run.commands().iter().filter(|c| *c == "QUIT").count(),
            1,
            "{scenario}: {:?}",
            run.commands()
        );
    }
}

/// TLS: a private CA through `SMTP_CA_FILE` (added to the system roots),
/// chain and hostname verification that cannot be switched off, and a CA
/// file that must be usable at start (D-22).
#[tokio::test]
async fn tls_with_the_ca_file() {
    // With the CA file: delivered over TLS.
    let ok = run(json!({}), &["a@example.test"]).await;
    assert_eq!(ok.outcome, Ok(Vec::new()));
    assert!(ok.session().tls);
    // The same server without the CA file: unknown issuer, 503.
    let server = FakeSmtp::start(&json!({}), Some(PKI.by_name("good"))).await;
    let (logger, _) = Logger::capturing(Level::Info);
    let config = SmtpConfig::load(&settings(server.port, true, None), &credentials()).unwrap();
    let reply = SmtpSubmitter::new(config, logger)
        .submit(message(&["a@example.test"]))
        .await;
    assert_eq!(reply, Err(SubmitError::Temporary));
    // Signed by the CA, but for another name; self-signed: 503, nothing sent.
    for certificate in ["wrongname", "selfsigned"] {
        let run = run_with(json!({}), certificate, &["a@example.test"], true, 5.0).await;
        assert_eq!(run.outcome, Err(SubmitError::Temporary), "{certificate}");
        assert!(
            !run.commands().contains(&"AUTH".to_owned()),
            "{certificate}"
        );
    }

    // The CA file is read at start: unusable → configuration error.
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, content: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let broken = PKI.ca_pem.replacen("MII", "MIX", 1);
    for (path, starttls) in [
        (
            dir.path().join("missing.pem").to_str().unwrap().to_owned(),
            true,
        ),
        (write("empty.pem", ""), true),
        (write("text.pem", "not a certificate\n"), true),
        (write("broken.pem", &broken), true),
        (write("broken-off.pem", &broken), false),
        (
            write("commented.pem", "# -----BEGIN CERTIFICATE-----\n"),
            true,
        ),
    ] {
        let error = SmtpConfig::load(&settings(25, starttls, Some(path.clone())), &credentials())
            .err()
            .unwrap_or_else(|| panic!("{path} loaded"));
        assert!(
            error.0.contains("SMTP_CA_FILE") && error.0.contains("D-22"),
            "{error}"
        );
    }
    let bundle = write(
        "bundle.pem",
        &format!("comment\n{}{}", PKI.ca_pem, PKI.ca_pem),
    );
    assert!(SmtpConfig::load(&settings(25, true, Some(bundle)), &credentials()).is_ok());
    let plain = SmtpConfig::load(&settings(25, false, None), &credentials()).unwrap();
    assert!(plain.tls.is_none());
    assert!(
        SmtpConfig::load(&settings(25, false, Some(ca_path())), &credentials())
            .unwrap()
            .tls
            .is_none()
    );
}

/// The message goes out in chunks; lettre's dot-stuffing keeps its state
/// across them, so lines starting with a dot arrive intact also where a
/// chunk boundary falls before the dot, inside the CRLF or before it.
#[tokio::test]
async fn long_messages_survive_chunking() {
    let mut formatted = b"Subject: dots\r\n\r\n".to_vec();
    for (boundary, offset) in [(1, 0), (2, 1), (3, 2)] {
        // Fill up to the boundary minus `offset` with dotted lines, so the
        // CRLF before the next dotted line straddles it as wanted.
        let end = boundary * MESSAGE_CHUNK - 2 + offset;
        let mut length = 1;
        while formatted.len() + 102 < end {
            formatted.extend_from_slice(format!(".{}\r\n", "x".repeat(length % 97)).as_bytes());
            length += 1;
        }
        let fill = end - formatted.len() - 2;
        formatted.extend_from_slice(format!("{}\r\n", "y".repeat(fill)).as_bytes());
        formatted.extend_from_slice(b".dot at a boundary\r\n");
    }
    formatted.extend_from_slice(b".\r\n..\r\nend\r\n");
    let server = FakeSmtp::start(&json!({}), Some(PKI.by_name("good"))).await;
    let (logger, _) = Logger::capturing(Level::Info);
    let built = BuiltMessage {
        formatted: formatted.clone(),
        ..message(&["a@example.test"])
    };
    let reply = submitter(server.port, true, 5.0, logger)
        .submit(built)
        .await;
    assert_eq!(reply, Ok(Vec::new()));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        server.sessions()[0].message.as_deref(),
        Some(&formatted[..])
    );
}
