//! mailgun-relay: Mailgun send API adapter for Anymail (Rust port, PLAN.md).
//!
//! `--version` prints the version and commit; `--check-config` loads the
//! environment exactly as the server does, binds nothing, and exits 0
//! (valid) or 1 (invalid). Unknown arguments exit 2. Slice S1a: the secrets
//! file (S1c) and serving (S1d) follow.

mod config;
mod domain;
mod pystr;

use std::process::ExitCode;

use crate::config::Settings;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("MAILGUN_RELAY_GIT_COMMIT");

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => {
            eprintln!("mailgun-relay: serving is not implemented yet (PLAN.md slice S1d)");
            ExitCode::FAILURE
        }
        [arg] if arg == "--version" => {
            println!("mailgun-relay {VERSION} ({COMMIT})");
            ExitCode::SUCCESS
        }
        [arg] if arg == "--check-config" => match Settings::from_env(std::env::vars_os()) {
            Ok(settings) => {
                println!(
                    "mailgun-relay: configuration OK (bind {}:{}, log level {})",
                    settings.bind_host,
                    settings.bind_port,
                    settings.log_level.name()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("mailgun-relay: configuration error: {error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: mailgun-relay [--version | --check-config]");
            ExitCode::from(2)
        }
    }
}
