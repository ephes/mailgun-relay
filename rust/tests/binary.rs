//! Process-level tests of the built binary (PLAN.md 2.7): the command line
//! and configuration failures.

use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_mailgun-relay");

/// The binary with a clean environment: only the given variables.
fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(BINARY)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .unwrap()
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
    let ok = run(&["--check-config"], &[("MAILGUN_RELAY_LOG_LEVEL", "debug")]);
    assert_eq!(ok.status.code(), Some(0), "{ok:?}");
    let stdout = String::from_utf8(ok.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout}");

    let failures: [&[(&str, &str)]; 4] = [
        &[("MAILGUN_RELAY_MAX_RECIPIENTS", "")],
        &[("MAILGUN_RELAY_LOG_LEVEL", "trace")],
        &[("MAILGUN_RELAY_SMTP_TIMEOUT_S", "nan")],
        &[
            ("mailgun_relay_smtp_port", "25"),
            ("Mailgun_Relay_Smtp_Port", "26"),
        ],
    ];
    for env in failures {
        let output = run(&["--check-config"], env);
        assert_eq!(output.status.code(), Some(1), "{env:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
    }
}
