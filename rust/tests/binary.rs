//! Process-level tests of the built binary (PLAN.md 2.7, 2.8): the command
//! line and configuration failures.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
    }

    std::fs::set_permissions(
        dir.path().join("secrets.yml"),
        PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    let output = run(&["--check-config"], &[("MAILGUN_RELAY_SECRETS_PATH", path)]);
    assert_eq!(output.status.code(), Some(1));
}
