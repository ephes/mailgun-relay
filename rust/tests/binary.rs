//! Process-level tests of the built binary (PLAN.md 2.7, 2.9, 2.11):
//! command line, configuration failures, the startup record, `/health` over
//! a real socket and graceful shutdown on SIGTERM.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

const BINARY: &str = env!("CARGO_BIN_EXE_mailgun-relay");
const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn secrets_file(dir: &Path, mode: u32) -> PathBuf {
    let path = dir.join("secrets.yml");
    let body = format!(
        "smtp: {{username: relay, password: hunter2}}\ntokens:\n  - label: zeta\n    \
         token_sha256: '{SHA}'\n    mailgun_domains: [mg.example.org]\n    \
         allowed_from_domains: [example.org]\n  - label: alpha\n    token_sha256: '{SHA}'\n    \
         mailgun_domains: [mg.example.org]\n    allowed_from_domains: [example.org]\n"
    );
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// The binary with a clean environment: only the given variables.
fn relay(args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(BINARY);
    command.args(args).env_clear().envs(env.iter().copied());
    command
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    relay(args, env).output().unwrap()
}

#[test]
fn version_and_usage() {
    let output = run(&["--version"], &[]);
    assert!(output.status.success());
    let line = String::from_utf8(output.stdout).unwrap();
    let rest = line.strip_prefix("mailgun-relay 0.2.1 (").unwrap();
    let commit = rest.strip_suffix(")\n").unwrap();
    assert!(
        commit == "unknown"
            || (7..=40).contains(&commit.len()) && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "{line}"
    );
    for args in [
        &["--bogus"][..],
        &["--version", "--check-config"],
        &["serve"],
    ] {
        assert_eq!(run(args, &[]).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn check_config_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let path = secrets_file(dir.path(), 0o640);
    let path = path.to_str().unwrap();
    let ok = run(&["--check-config"], &[("MAILGUN_RELAY_SECRETS_PATH", path)]);
    assert_eq!(ok.status.code(), Some(0), "{ok:?}");
    assert_eq!(String::from_utf8(ok.stdout).unwrap().lines().count(), 1);

    let failures: [&[(&str, &str)]; 5] = [
        &[("MAILGUN_RELAY_SECRETS_PATH", "/nonexistent/secrets.yml")],
        &[
            ("MAILGUN_RELAY_SECRETS_PATH", path),
            ("MAILGUN_RELAY_MAX_RECIPIENTS", ""),
        ],
        &[
            ("MAILGUN_RELAY_SECRETS_PATH", path),
            ("MAILGUN_RELAY_LOG_LEVEL", "warn"),
        ],
        &[
            ("MAILGUN_RELAY_SECRETS_PATH", path),
            ("MAILGUN_RELAY_SMTP_TIMEOUT_S", "nan"),
        ],
        &[
            ("MAILGUN_RELAY_SECRETS_PATH", path),
            ("mailgun_relay_secrets_path", path),
        ],
    ];
    for env in failures {
        let output = run(&["--check-config"], env);
        assert_eq!(output.status.code(), Some(1), "{env:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        assert!(
            !stderr.contains("hunter2") && !stderr.contains(SHA),
            "{stderr}"
        );
        // A configuration error stops `serve` the same way, before binding.
        assert_eq!(run(&[], env).status.code(), Some(1), "{env:?}");
    }

    std::fs::set_permissions(
        dir.path().join("secrets.yml"),
        PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    let output = run(&["--check-config"], &[("MAILGUN_RELAY_SECRETS_PATH", path)]);
    assert_eq!(output.status.code(), Some(1));
}

fn get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn serves_health_logs_startup_and_stops_on_sigterm() {
    let dir = tempfile::tempdir().unwrap();
    let path = secrets_file(dir.path(), 0o600);
    let mut server = start(&[
        ("MAILGUN_RELAY_SECRETS_PATH", path.to_str().unwrap()),
        ("MAILGUN_RELAY_LOG_LEVEL", "error"),
    ]);
    let (port, line) = (server.port, server.startup.clone());
    let record: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert!(line.starts_with("{\"ts\":") && line.ends_with("}\n") && !line.contains(": "));
    // Logged at the configured level when that is above INFO.
    assert_eq!(record["level"], "ERROR");
    assert_eq!(record["logger"], "mailgun_relay.service");
    assert_eq!(record["event"], "startup");
    assert_eq!(record["version"], "0.2.1");
    assert_eq!(record["impl"], "rust");
    assert_eq!(record["bind"], format!("127.0.0.1:{port}"));
    assert_eq!(record["token_labels"], serde_json::json!(["alpha", "zeta"]));
    assert_eq!(record["log_level"], "ERROR");
    assert!(!line.contains("hunter2") && !line.contains(SHA), "{line}");

    let response = get(port, "/health");
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert!(
        response.ends_with("\r\n\r\n{\"status\":\"ok\"}"),
        "{response}"
    );
    assert!(get(port, "/health/").contains("\r\nlocation: http://relay.test/health\r\n"));

    let mut stderr = server.child.stderr.take().unwrap();
    let status = terminate(&mut server.child);
    assert!(status.success(), "{status:?}");
    // Nothing else was logged: /health and the fallbacks write no records.
    let mut rest = String::new();
    server.stdout.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "");
    let mut errors = String::new();
    stderr.read_to_string(&mut errors).unwrap();
    assert_eq!(errors, "");
}

#[test]
fn bind_failure_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let path = secrets_file(dir.path(), 0o600);
    let busy = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port().to_string();
    let output = run(
        &[],
        &[
            ("MAILGUN_RELAY_SECRETS_PATH", path.to_str().unwrap()),
            ("MAILGUN_RELAY_BIND_PORT", &port),
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running server, its port and its stdout after the startup record.
struct Server {
    child: std::process::Child,
    port: u16,
    startup: String,
    stdout: BufReader<std::process::ChildStdout>,
}

/// Start the server on a free port and wait for its startup record. The
/// port can be taken by another test between `free_port` and the bind;
/// then the server exits 1 and another port is tried.
fn start(env: &[(&str, &str)]) -> Server {
    for _ in 0..10 {
        let port = free_port();
        let mut child = relay(&[], env)
            .env("MAILGUN_RELAY_BIND_PORT", port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut startup = String::new();
        stdout.read_line(&mut startup).unwrap();
        if startup.contains("\"event\":\"startup\"") {
            return Server {
                child,
                port,
                startup,
                stdout,
            };
        }
        assert_eq!(child.wait().unwrap().code(), Some(1), "{startup}");
    }
    panic!("no free port for the server");
}

fn terminate(child: &mut std::process::Child) -> std::process::ExitStatus {
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    child.wait().unwrap()
}

#[test]
fn sigterm_right_after_the_startup_record_is_graceful() {
    let dir = tempfile::tempdir().unwrap();
    let path = secrets_file(dir.path(), 0o600);
    for _ in 0..10 {
        let mut server = start(&[("MAILGUN_RELAY_SECRETS_PATH", path.to_str().unwrap())]);
        let status = terminate(&mut server.child);
        assert!(status.success(), "{status:?}");
    }
}

#[test]
fn binds_every_resolved_address_and_ipv6_only() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        return; // no IPv6 loopback on this host
    }
    let dir = tempfile::tempdir().unwrap();
    let path = secrets_file(dir.path(), 0o600);
    let secrets = path.to_str().unwrap();

    // `localhost`: one listener per address family, as asyncio binds.
    let mut server = start(&[
        ("MAILGUN_RELAY_SECRETS_PATH", secrets),
        ("MAILGUN_RELAY_BIND_HOST", "localhost"),
    ]);
    let port = server.port;
    for address in ["127.0.0.1", "::1"] {
        let mut stream = TcpStream::connect((address, port)).unwrap();
        write!(
            stream,
            "GET /health HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200 "),
            "{address}: {response}"
        );
    }
    assert!(terminate(&mut server.child).success());

    // `::` is IPv6 only; IPv4 clients are not served.
    let mut server = start(&[
        ("MAILGUN_RELAY_SECRETS_PATH", secrets),
        ("MAILGUN_RELAY_BIND_HOST", "::"),
    ]);
    let port = server.port;
    assert!(TcpStream::connect(("::1", port)).is_ok());
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert!(terminate(&mut server.child).success());
}

#[path = "support/fake_smtp.rs"]
mod fake_smtp;

/// A raw HTTP request; the response as text.
fn request(port: u16, head: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{head}\r\nHost: relay.test\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// PLAN.md 2.3 steps 10–11 end to end: the binary submits over STARTTLS to
/// a server whose certificate a test CA from `SMTP_CA_FILE` signed, with
/// AUTH, and answers 200 with the Message-Id it sent.
#[test]
fn delivers_over_starttls_with_the_ca_file() {
    let pki = fake_smtp::Pki::new();
    let smtp = fake_smtp::FakeSmtp::start_in_thread(
        serde_json::json!({"rcpt": {"gone": 550}}),
        Some(pki.good.clone()),
    );
    let dir = tempfile::tempdir().unwrap();
    let secrets = secrets_file(dir.path(), 0o600);
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, &pki.ca_pem).unwrap();
    let smtp_port = smtp.port.to_string();
    let env = [
        ("MAILGUN_RELAY_SECRETS_PATH", secrets.to_str().unwrap()),
        ("MAILGUN_RELAY_SMTP_HOST", "localhost"),
        ("MAILGUN_RELAY_SMTP_PORT", &smtp_port),
        ("MAILGUN_RELAY_SMTP_CA_FILE", ca.to_str().unwrap()),
        ("MAILGUN_RELAY_ENVELOPE_SENDER", "relay@example.org"),
    ];
    let check = run(&["--check-config"], &env);
    assert_eq!(check.status.code(), Some(0), "{check:?}");
    let mut server = start(&env);

    // `api:test` matches the token hash of the secrets file.
    let body = "from=Relay+%3Crelay%40example.org%3E&to=a%40example.net\
                &cc=gone%40example.net&bcc=b%40example.com&subject=Hallo&text=Gr%C3%BC%C3%9Fe";
    let response = request(
        server.port,
        "POST /v3/mg.example.org/messages HTTP/1.1\r\nAuthorization: Basic YXBpOnRlc3Q=\r\n\
         Content-Type: application/x-www-form-urlencoded",
        body,
    );
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    let json: serde_json::Value =
        serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(json["message"], "Queued. Thank you.");
    let id = json["id"].as_str().unwrap();

    let sessions = smtp.sessions();
    assert_eq!(sessions.len(), 1);
    let session = &sessions[0];
    assert!(session.tls);
    assert_eq!(
        session.commands(),
        [
            "EHLO", "STARTTLS", "EHLO", "AUTH", "MAIL", "RCPT", "RCPT", "RCPT", "DATA", "QUIT"
        ]
    );
    assert_eq!(session.mail_from.as_deref(), Some("relay@example.org"));
    assert_eq!(
        session.data_for,
        Some(vec!["a@example.net".to_owned(), "b@example.com".to_owned()])
    );
    let message = String::from_utf8(session.message.clone().unwrap()).unwrap();
    assert!(
        message.contains(&format!("Message-ID: {id}\r\n")),
        "{message}"
    );
    assert!(!message.contains("b@example.com"), "{message}");

    let status = terminate(&mut server.child);
    assert!(status.success(), "{status:?}");
    let mut records = String::new();
    server.stdout.read_to_string(&mut records).unwrap();
    let records: Vec<serde_json::Value> = records
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let events: Vec<&str> = records
        .iter()
        .map(|r| r["event"].as_str().unwrap())
        .collect();
    assert_eq!(events, ["recipients_refused", "request"]);
    assert_eq!(
        records[0]["refused"],
        serde_json::json!([{"domain": "example.net", "code": 550}])
    );
    assert_eq!(records[1]["result"], "partial_refusal");
    assert_eq!(records[1]["token_label"], "alpha");
    assert_eq!(records[1]["message_id"], id);
    assert_eq!(records[1]["recipient_count"], 3);

    // An unusable CA file stops `--check-config` and the server (D-22).
    std::fs::write(&ca, "no certificate\n").unwrap();
    let output = run(&["--check-config"], &env);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("SMTP_CA_FILE"), "{stderr}");
    assert_eq!(run(&[], &env).status.code(), Some(1));
}

/// PLAN.md 2.3 step 10: a client that goes away neither cancels its
/// submission nor loses its record, and SIGTERM waits for the submission.
#[test]
fn shutdown_waits_for_a_submission_whose_client_left() {
    let pki = fake_smtp::Pki::new();
    let smtp = fake_smtp::FakeSmtp::start_in_thread(
        serde_json::json!({"fault": {"data_end": "hang"}}),
        Some(pki.good.clone()),
    );
    let dir = tempfile::tempdir().unwrap();
    let secrets = secrets_file(dir.path(), 0o600);
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, &pki.ca_pem).unwrap();
    let smtp_port = smtp.port.to_string();
    let mut server = start(&[
        ("MAILGUN_RELAY_SECRETS_PATH", secrets.to_str().unwrap()),
        ("MAILGUN_RELAY_SMTP_HOST", "localhost"),
        ("MAILGUN_RELAY_SMTP_PORT", &smtp_port),
        ("MAILGUN_RELAY_SMTP_CA_FILE", ca.to_str().unwrap()),
        ("MAILGUN_RELAY_SMTP_TIMEOUT_S", "1"),
    ]);
    let body = "from=a%40example.org&to=b%40example.net&subject=s&text=t";
    let mut client = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    write!(
        client,
        "POST /v3/mg.example.org/messages HTTP/1.1\r\nHost: relay.test\r\n\
         Authorization: Basic YXBpOnRlc3Q=\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let started = std::time::Instant::now();
    while smtp.sessions().first().is_none_or(|s| s.message.is_none()) {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no message arrived"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(client);
    let status = terminate(&mut server.child);
    assert!(status.success(), "{status:?}");
    let mut records = String::new();
    server.stdout.read_to_string(&mut records).unwrap();
    let record: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
    assert_eq!(record["event"], "request");
    assert_eq!(record["result"], "smtp_temporary");
    assert_eq!(record["status_code"], 503);
}
