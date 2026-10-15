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
    let rest = line.strip_prefix("mailgun-relay 0.2.0 (").unwrap();
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
            ("MAILGUN_RELAY_LOG_LEVEL", "trace"),
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
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let port_text = port.to_string();
    let mut child = relay(
        &[],
        &[
            ("MAILGUN_RELAY_SECRETS_PATH", path.to_str().unwrap()),
            ("MAILGUN_RELAY_BIND_PORT", &port_text),
            ("MAILGUN_RELAY_LOG_LEVEL", "error"),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();

    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let record: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert!(line.starts_with("{\"ts\":") && line.ends_with("}\n") && !line.contains(": "));
    // Logged at the configured level when that is above INFO.
    assert_eq!(record["level"], "ERROR");
    assert_eq!(record["logger"], "mailgun_relay.service");
    assert_eq!(record["event"], "startup");
    assert_eq!(record["version"], "0.2.0");
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

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let status = child.wait().unwrap();
    assert!(status.success(), "{status:?}");
    // Nothing else was logged: /health and the fallbacks write no records.
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(stderr, "");
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

/// Start the server and wait for its startup record.
fn start(env: &[(&str, &str)]) -> std::process::Child {
    let mut child = relay(&[], env)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("\"event\":\"startup\""), "{line}");
    child
}

fn terminate(mut child: std::process::Child) -> std::process::ExitStatus {
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
        let port = free_port().to_string();
        let child = start(&[
            ("MAILGUN_RELAY_SECRETS_PATH", path.to_str().unwrap()),
            ("MAILGUN_RELAY_BIND_PORT", &port),
        ]);
        let status = terminate(child);
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
    let port = free_port();
    let port_text = port.to_string();
    let child = start(&[
        ("MAILGUN_RELAY_SECRETS_PATH", secrets),
        ("MAILGUN_RELAY_BIND_HOST", "localhost"),
        ("MAILGUN_RELAY_BIND_PORT", &port_text),
    ]);
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
    assert!(terminate(child).success());

    // `::` is IPv6 only; IPv4 clients are not served.
    let port = free_port();
    let port_text = port.to_string();
    let child = start(&[
        ("MAILGUN_RELAY_SECRETS_PATH", secrets),
        ("MAILGUN_RELAY_BIND_HOST", "::"),
        ("MAILGUN_RELAY_BIND_PORT", &port_text),
    ]);
    assert!(TcpStream::connect(("::1", port)).is_ok());
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert!(terminate(child).success());
}
