//! Environment settings (PLAN.md 2.7; `relay:config.py` `Settings` and the
//! reads in `relay:__main__.py`).
//!
//! Values are parsed as pydantic 2 parses strings, pinned by
//! `fixtures/config_env.json`. Fail-closed differences: one reader for every
//! variable (D-7) and the range checks of D-18.

use std::ffi::OsString;
use std::fmt;

use crate::domain::normalize_config_domain;

#[derive(Debug, PartialEq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Python `logging` levels; the names are the accepted `LOG_LEVEL` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

const LEVELS: [(Level, &str); 5] = [
    (Level::Debug, "DEBUG"),
    (Level::Info, "INFO"),
    (Level::Warning, "WARNING"),
    (Level::Error, "ERROR"),
    (Level::Critical, "CRITICAL"),
];

impl Level {
    pub fn from_name(name: &str) -> Option<Level> {
        LEVELS
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(name))
            .map(|(level, _)| *level)
    }

    pub fn name(self) -> &'static str {
        LEVELS[self as usize].1
    }
}

const PREFIX: &str = "MAILGUN_RELAY_";

/// Largest `SMTP_TIMEOUT_S` (D-18); Python fails each submission from about
/// 9.2e9 s on.
const MAX_TIMEOUT_S: f64 = 1e9;

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub bind_host: String,
    pub bind_port: u16,
    pub public_host: String,
    pub secrets_path: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_starttls: bool,
    pub smtp_timeout_s: f64,
    pub smtp_ca_file: String,
    pub smtp_max_concurrency: u32,
    pub envelope_sender: String,
    pub fail_on_partial_refusal: bool,
    pub max_body_bytes: i64,
    pub max_attachments: i64,
    pub max_attachment_bytes: i64,
    pub max_recipients: i64,
    pub max_header_value_length: i64,
    pub log_level: Level,
}

impl Settings {
    /// Read the settings from environment variables (`std::env::vars_os()`).
    pub fn from_env(
        vars: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Result<Self, ConfigError> {
        let vars: Vec<(String, OsString)> = vars
            .into_iter()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value)))
            .filter(|(name, _)| {
                name.len() > PREFIX.len()
                    && name.as_bytes()[..PREFIX.len()].eq_ignore_ascii_case(PREFIX.as_bytes())
            })
            .collect();
        let env = Env(&vars);
        let settings = Settings {
            bind_host: env.str("BIND_HOST", "127.0.0.1")?,
            bind_port: env.parsed("BIND_PORT", "8085", parse_port_strict)?,
            public_host: env.str("PUBLIC_HOST", "mailgun.home.xn--wersdrfer-47a.de")?,
            secrets_path: env.str("SECRETS_PATH", "/etc/mailgun-relay/secrets.yml")?,
            smtp_host: env.str("SMTP_HOST", "smtp.home.xn--wersdrfer-47a.de")?,
            smtp_port: env.parsed("SMTP_PORT", "587", |v| range(parse_int(v)?, 0, 65535))?,
            smtp_starttls: env.parsed("SMTP_STARTTLS", "true", parse_bool)?,
            smtp_timeout_s: env.parsed("SMTP_TIMEOUT_S", "30.0", parse_timeout)?,
            smtp_ca_file: env.str("SMTP_CA_FILE", "")?,
            smtp_max_concurrency: env.parsed("SMTP_MAX_CONCURRENCY", "8", |v| {
                range(parse_int(v)?, 1, u32::MAX.into())
            })?,
            envelope_sender: env.parsed("ENVELOPE_SENDER", "", envelope_sender)?,
            fail_on_partial_refusal: env.parsed("FAIL_ON_PARTIAL_REFUSAL", "false", parse_bool)?,
            max_body_bytes: env.parsed("MAX_BODY_BYTES", "26214400", parse_int)?,
            max_attachments: env.parsed("MAX_ATTACHMENTS", "10", parse_int)?,
            max_attachment_bytes: env.parsed("MAX_ATTACHMENT_BYTES", "10485760", parse_int)?,
            max_recipients: env.parsed("MAX_RECIPIENTS", "100", parse_int)?,
            max_header_value_length: env.parsed("MAX_HEADER_VALUE_LENGTH", "998", parse_int)?,
            log_level: env.parsed("LOG_LEVEL", "INFO", |v| {
                Level::from_name(v).ok_or_else(|| "one of CRITICAL ERROR WARNING INFO DEBUG".into())
            })?,
        };
        if settings.bind_host.is_empty() {
            // Python would bind every interface (D-18).
            return Err(ConfigError(
                "MAILGUN_RELAY_BIND_HOST must not be empty".to_owned(),
            ));
        }
        Ok(settings)
    }
}

struct Env<'a>(&'a [(String, OsString)]);

impl Env<'_> {
    /// D-7: the one variable whose name matches case-insensitively. Python
    /// would take the last of several case variants (and validate only that
    /// one), so several variants, the exact name included, are an error.
    fn lookup(&self, field: &str) -> Result<Option<(String, String)>, ConfigError> {
        let exact = format!("{PREFIX}{field}");
        let mut matches = self
            .0
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(&exact));
        let Some(found) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(ConfigError(format!(
                "{exact}: several case variants are set (PLAN.md D-7)"
            )));
        }
        let value = found.1.to_str().ok_or_else(|| {
            ConfigError(format!(
                "{}: value is not valid UTF-8 (PLAN.md D-18)",
                found.0
            ))
        })?;
        Ok(Some((found.0.clone(), value.to_owned())))
    }

    fn str(&self, field: &str, default: &str) -> Result<String, ConfigError> {
        Ok(self
            .lookup(field)?
            .map_or_else(|| default.to_owned(), |(_, value)| value))
    }

    fn parsed<T>(
        &self,
        field: &str,
        default: &str,
        parse: impl Fn(&str) -> Result<T, String>,
    ) -> Result<T, ConfigError> {
        match self.lookup(field)? {
            None => Ok(parse(default).expect("valid default")),
            Some((name, value)) => {
                parse(&value).map_err(|reason| ConfigError(format!("{name}: {reason}")))
            }
        }
    }
}

/// pydantic's integer from a string, without the decimal-zero form: Unicode
/// whitespace trimmed, an optional sign, ASCII digits with single `_`
/// between digits; within `i64` (D-18).
fn parse_int_strict(value: &str) -> Result<i64, String> {
    let trimmed = value.trim();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let well_formed = !digits.is_empty()
        && digits
            .split('_')
            .all(|group| !group.is_empty() && group.bytes().all(|b| b.is_ascii_digit()));
    if !well_formed {
        return Err("not a valid integer".to_owned());
    }
    let digits = digits.replace('_', "");
    let significant = digits.trim_start_matches('0');
    // i64::MAX has 19 digits.
    if significant.len() > 19 {
        return Err("integer out of range (PLAN.md D-18)".to_owned());
    }
    let magnitude: i128 = significant.parse().unwrap_or(0);
    let signed = if negative { -magnitude } else { magnitude };
    i64::try_from(signed).map_err(|_| "integer out of range (PLAN.md D-18)".to_owned())
}

/// pydantic's integer from a string: also `"8085.0"`, `"8085.00"`.
fn parse_int(value: &str) -> Result<i64, String> {
    parse_int_strict(value).or_else(|error| match value.trim().rsplit_once('.') {
        // No whitespace between the digits and the fraction (`"1 .0"`).
        Some((int, zeros))
            if !zeros.is_empty() && zeros.bytes().all(|b| b == b'0') && int.trim() == int =>
        {
            parse_int_strict(int)
        }
        _ => Err(error),
    })
}

/// `BIND_PORT` is read by pydantic and by Python's `int()` in `__main__`;
/// only spellings both accept start the service, so no decimal form.
fn parse_port_strict(value: &str) -> Result<u16, String> {
    range(parse_int_strict(value)?, 0, 65535)
}

fn range<T: TryFrom<i64>>(value: i64, min: i64, max: i64) -> Result<T, String> {
    if !(min..=max).contains(&value) {
        return Err(format!("must be between {min} and {max}"));
    }
    T::try_from(value).map_err(|_| "out of range".to_owned())
}

/// pydantic's boolean from a string: no trimming, ASCII case-insensitive.
fn parse_bool(value: &str) -> Result<bool, String> {
    const TRUE: [&str; 6] = ["1", "on", "t", "true", "y", "yes"];
    const FALSE: [&str; 6] = ["0", "off", "f", "false", "n", "no"];
    if TRUE.iter().any(|t| value.eq_ignore_ascii_case(t)) {
        Ok(true)
    } else if FALSE.iter().any(|f| value.eq_ignore_ascii_case(f)) {
        Ok(false)
    } else {
        Err("not a valid boolean".to_owned())
    }
}

/// pydantic's float from a string (trimmed, `_` only between characters,
/// Rust's `f64` grammar), then finite and in `0..=1e9` seconds (D-18).
fn parse_timeout(value: &str) -> Result<f64, String> {
    let trimmed = value.trim();
    if trimmed.starts_with('_') || trimmed.ends_with('_') || trimmed.contains("__") {
        return Err("not a valid number".to_owned());
    }
    let seconds: f64 = trimmed
        .replace('_', "")
        .parse()
        .map_err(|_| "not a valid number".to_owned())?;
    if !(0.0..=MAX_TIMEOUT_S).contains(&seconds) {
        return Err(format!(
            "must be between 0 and {MAX_TIMEOUT_S} seconds (PLAN.md D-18)"
        ));
    }
    Ok(seconds)
}

/// `_envelope_sender_ascii`: ASCII unchanged, otherwise an ASCII local part
/// and a domain converted to its A-label (D-15, D-10).
fn envelope_sender(value: &str) -> Result<String, String> {
    if value.is_ascii() {
        return Ok(value.to_owned());
    }
    match value.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && local.is_ascii() => {
            Ok(format!("{local}@{}", normalize_config_domain(domain)?))
        }
        _ => Err("only the domain may be non-ASCII (SMTPUTF8 is not used)".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn settings_json(s: &Settings) -> Value {
        json!({
            "bind_host": s.bind_host, "bind_port": s.bind_port, "public_host": s.public_host,
            "secrets_path": s.secrets_path, "smtp_host": s.smtp_host, "smtp_port": s.smtp_port,
            "smtp_starttls": s.smtp_starttls, "smtp_timeout_s": s.smtp_timeout_s,
            "smtp_ca_file": s.smtp_ca_file, "smtp_max_concurrency": s.smtp_max_concurrency,
            "envelope_sender": s.envelope_sender,
            "fail_on_partial_refusal": s.fail_on_partial_refusal,
            "max_body_bytes": s.max_body_bytes, "max_attachments": s.max_attachments,
            "max_attachment_bytes": s.max_attachment_bytes, "max_recipients": s.max_recipients,
            "max_header_value_length": s.max_header_value_length,
            "log_level": s.log_level.name(),
        })
    }

    /// Every case of `fixtures/config_env.json` (Python oracle, D-7/D-10/D-18
    /// cases carry the Rust expectation).
    #[test]
    fn config_env_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/config_env.json")).unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() >= 60);
        let mut mismatches = Vec::new();
        for case in cases {
            let env = case["env"].as_array().unwrap().iter().map(|pair| {
                let text = |i: usize| OsString::from(pair[i].as_str().unwrap());
                (text(0), text(1))
            });
            let actual = Settings::from_env(env).ok().map(|s| settings_json(&s));
            let expected = Some(&case["expected"]).filter(|v| !v.is_null()).cloned();
            if actual != expected {
                mismatches.push(format!("{}: {actual:?} != {expected:?}", case["name"]));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    #[test]
    fn integers_follow_pydantic() {
        for (input, expected) in [
            (" 8085\n", Some(8085)),
            ("+8_085", Some(8085)),
            ("0_1", Some(1)),
            ("-0", Some(0)),
            ("8085.00", Some(8085)),
            ("00000000000000000000000000005", Some(5)),
            ("8085.", None),
            ("1 .0", None),
            ("1\t.0", None),
            ("1__0", None),
            ("+_1", None),
            ("_1", None),
            ("1.0_0", None),
            ("0x10", None),
            ("\u{1c}1", None),
            ("9223372036854775808", None),
        ] {
            assert_eq!(parse_int(input).ok(), expected, "{input:?}");
        }
        assert!(parse_port_strict("8085.0").is_err());
    }

    #[test]
    fn unrelated_unicode_names_are_ignored() {
        let vars = [(OsString::from("aaaaaaaaaaaaaüx"), OsString::from("1"))];
        assert!(Settings::from_env(vars).is_ok());
    }
}
