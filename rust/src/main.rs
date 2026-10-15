//! mailgun-relay: Mailgun send API adapter for Anymail (Rust port, PLAN.md).
//!
//! `--version` prints the version and commit; `--check-config` loads the
//! environment and the secrets file exactly as the server does, binds
//! nothing, and exits 0 (valid) or 1 (invalid). Unknown arguments exit 2.
//! Serving follows in slice S1d.

mod config;
mod domain;
mod pystr;
mod secrets;
mod yaml;

use std::path::Path;
use std::process::ExitCode;

use crate::config::{ConfigError, Settings};
use crate::secrets::Secrets;

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
        [arg] if arg == "--check-config" => match load_config() {
            Ok((settings, secrets)) => {
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

/// The environment, then the secrets file it names (`relay:app.py`).
fn load_config() -> Result<(Settings, Secrets), ConfigError> {
    let settings = Settings::from_env(std::env::vars_os())?;
    let secrets = secrets::load(Path::new(&settings.secrets_path))?;
    Ok((settings, secrets))
}
