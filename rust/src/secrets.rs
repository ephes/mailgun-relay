//! Secrets file loader (PLAN.md 2.8; `relay:config.py` `load_secrets`).
//!
//! Same schema and checks as Python. Fail-closed differences: an unquoted
//! all-digit or boolean `token_sha256` (D-5), the YAML features of D-6,
//! domains outside the D-10 character set and non-ASCII local parts in
//! `allowed_from_addresses` (D-17) fail the load. Error messages never
//! contain the password or a token hash.

use std::collections::BTreeSet;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config::ConfigError;
use crate::domain::{normalize_config_address, normalize_config_domain};
use crate::pystr::py_strip;
use crate::yaml::{self, Node};

/// Placeholders the ops template must never render (`_FORBIDDEN_VALUES`).
const FORBIDDEN_VALUES: [&str; 4] = ["CHANGEME", "changeme", "replace-me", ""];

/// World access and group write/execute (`_FORBIDDEN_SECRET_MODE_BITS`).
const FORBIDDEN_MODE_BITS: u32 = 0o037;

pub struct SmtpCredentials {
    pub username: String,
    #[cfg_attr(not(test), expect(dead_code, reason = "used by the SMTP slice S5"))]
    pub password: String,
}

impl fmt::Debug for SmtpCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpCredentials")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

pub struct TokenPolicy {
    pub label: String,
    pub token_sha256: String,
    pub mailgun_domains: BTreeSet<String>,
    pub allowed_from_domains: BTreeSet<String>,
    /// `None`: the domain rule alone decides.
    pub allowed_from_addresses: Option<BTreeSet<String>>,
}

impl fmt::Debug for TokenPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenPolicy")
            .field("label", &self.label)
            .field("mailgun_domains", &self.mailgun_domains)
            .field("allowed_from_domains", &self.allowed_from_domains)
            .field("allowed_from_addresses", &self.allowed_from_addresses)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Secrets {
    #[cfg_attr(not(test), expect(dead_code, reason = "used by the SMTP slice S5"))]
    pub smtp: SmtpCredentials,
    pub tokens: Vec<TokenPolicy>,
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

/// Check the mode, then read and validate the file.
pub fn load(path: &Path) -> Result<Secrets, ConfigError> {
    let shown = path.display();
    let metadata =
        std::fs::metadata(path).map_err(|e| invalid(format!("secrets file {shown}: {e}")))?;
    let mode = metadata.permissions().mode();
    if mode & FORBIDDEN_MODE_BITS != 0 {
        return Err(invalid(format!(
            "secrets file {shown} is world-accessible or group-writable (mode {:o}); \
             restrict it to 0640 or stricter",
            mode & 0o777
        )));
    }
    let bytes = std::fs::read(path).map_err(|e| invalid(format!("secrets file {shown}: {e}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| invalid(format!("secrets file {shown} is not valid UTF-8")))?;
    from_yaml(&text)
}

pub fn from_yaml(text: &str) -> Result<Secrets, ConfigError> {
    let data = yaml::parse(text).map_err(|e| invalid(format!("secrets file: {e}")))?;
    if !matches!(*data, Node::Map(_)) {
        return Err(invalid("secrets file must be a top-level mapping"));
    }
    let smtp = load_smtp(data.get("smtp"))?;
    let entries = match data.get("tokens") {
        Some(Node::Seq(items)) if !items.is_empty() => items,
        _ => return Err(invalid("tokens must be a non-empty list")),
    };
    let mut tokens: Vec<TokenPolicy> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let policy = load_policy(entry, &format!("tokens[{index}]"))?;
        if tokens.iter().any(|t| t.label == policy.label) {
            return Err(invalid(format!("tokens[{index}]: duplicate token label")));
        }
        tokens.push(policy);
    }
    Ok(Secrets { smtp, tokens })
}

// Errors name the field by its position, never by a value: through a YAML
// alias any field can hold the password or a token hash.

fn reject_placeholder(field: &str, value: &str) -> Result<(), ConfigError> {
    if FORBIDDEN_VALUES.contains(&value) {
        return Err(invalid(format!("{field}: refuses placeholder/empty value")));
    }
    Ok(())
}

fn as_str(node: Option<&Node>) -> Option<&str> {
    match node {
        Some(Node::Str(value)) => Some(value),
        _ => None,
    }
}

fn load_smtp(raw: Option<&Node>) -> Result<SmtpCredentials, ConfigError> {
    let Some(raw @ Node::Map(_)) = raw else {
        return Err(invalid("smtp section must be a mapping"));
    };
    let username = as_str(raw.get("username"))
        .filter(|u| !py_strip(u).is_empty())
        .ok_or_else(|| invalid("smtp.username must be a non-empty string"))?;
    let password =
        as_str(raw.get("password")).ok_or_else(|| invalid("smtp.password must be a string"))?;
    reject_placeholder("smtp.username", username)?;
    reject_placeholder("smtp.password", password)?;
    Ok(SmtpCredentials {
        username: username.to_owned(),
        password: password.to_owned(),
    })
}

fn load_policy(raw: &Node, at: &str) -> Result<TokenPolicy, ConfigError> {
    if !matches!(raw, Node::Map(_)) {
        return Err(invalid(format!("{at}: each token entry must be a mapping")));
    }
    let label = as_str(raw.get("label"))
        .filter(|l| !py_strip(l).is_empty())
        .ok_or_else(|| invalid(format!("{at}.label must be a non-empty string")))?;
    reject_placeholder(&format!("{at}.label"), label)?;

    // D-5: an int (or bool) is refused, not converted to hex as in Python.
    let sha = match raw.get("token_sha256") {
        Some(Node::Str(value)) => value,
        other => {
            let found = other.map_or("nothing", Node::type_name);
            return Err(invalid(format!(
                "{at}.token_sha256 must be a quoted hex string, found {found} (PLAN.md D-5)"
            )));
        }
    };
    reject_placeholder(&format!("{at}.token_sha256"), sha)?;
    let sha = py_strip(sha).to_lowercase();
    if sha.len() != 64 || !sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(invalid(format!(
            "{at}.token_sha256 must be 64 lowercase hex chars (sha256)"
        )));
    }

    let mailgun_domains = string_list(raw, at, "mailgun_domains", normalize_config_domain)?
        .ok_or_else(|| invalid(format!("{at}.mailgun_domains must be a non-empty list")))?;
    let allowed_from_domains =
        string_list(raw, at, "allowed_from_domains", normalize_config_domain)?.ok_or_else(
            || {
                invalid(format!(
                    "{at}.allowed_from_domains must be a non-empty list"
                ))
            },
        )?;
    let allowed_from_addresses = match raw.get("allowed_from_addresses") {
        None | Some(Node::Null) => None,
        Some(Node::Seq(_)) => {
            string_list(raw, at, "allowed_from_addresses", normalize_config_address)?
        }
        Some(_) => {
            return Err(invalid(format!(
                "{at}.allowed_from_addresses must be a list when present"
            )));
        }
    };
    Ok(TokenPolicy {
        label: label.to_owned(),
        token_sha256: sha,
        mailgun_domains,
        allowed_from_domains,
        allowed_from_addresses,
    })
}

/// A list of non-empty strings, each normalised; `None` when the key is
/// missing, not a list, or an empty list.
fn string_list(
    raw: &Node,
    at: &str,
    key: &str,
    normalize: fn(&str) -> Result<String, String>,
) -> Result<Option<BTreeSet<String>>, ConfigError> {
    let Some(Node::Seq(items)) = raw.get(key) else {
        return Ok(None);
    };
    if items.is_empty() {
        return Ok(None);
    }
    let mut values = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let field = format!("{at}.{key}[{index}]");
        match item.as_ref() {
            Node::Str(value) if !py_strip(value).is_empty() => {
                let normalized =
                    normalize(value).map_err(|reason| invalid(format!("{field}: {reason}")))?;
                values.insert(normalized);
            }
            _ => return Err(invalid(format!("{field} must be a non-empty string"))),
        }
    }
    Ok(Some(values))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn secrets_json(secrets: &Secrets) -> Value {
        let tokens: Vec<Value> = secrets
            .tokens
            .iter()
            .map(|t| {
                json!({
                    "label": t.label, "token_sha256": t.token_sha256,
                    "mailgun_domains": t.mailgun_domains,
                    "allowed_from_domains": t.allowed_from_domains,
                    "allowed_from_addresses": t.allowed_from_addresses,
                })
            })
            .collect();
        json!({
            "smtp": {"username": secrets.smtp.username, "password": secrets.smtp.password},
            "tokens": tokens,
        })
    }

    #[test]
    fn errors_never_echo_values() {
        // The anchors are defined in `smtp` and in the first token; the second
        // token aliases them into the field under test.
        let pw = "hunter2_secret!";
        let sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let doc = |second: &str| {
            format!(
                "smtp: {{username: relay, password: &pw '{pw}'}}\ntokens:\n  - label: first\n    \
                 token_sha256: &sha '{sha}'\n    mailgun_domains: [a.de]\n    \
                 allowed_from_domains: [a.de]\n  - {{label: second, token_sha256: '{sha}', \
                 mailgun_domains: [a.de], allowed_from_domains: [a.de], {second}}}\n"
            )
        };
        let cases = [
            (
                "allowed_from_addresses: [*pw]",
                "tokens[1].allowed_from_addresses[0]",
            ),
            (
                "allowed_from_addresses: [*sha]",
                "tokens[1].allowed_from_addresses[0]",
            ),
            ("mailgun_domains: [*pw]", "tokens[1].mailgun_domains[0]"),
            (
                "allowed_from_domains: [*sha]",
                "tokens[1].allowed_from_domains[0]",
            ),
            (
                "label: *pw, label: first",
                "tokens[1]: duplicate token label",
            ),
        ];
        for (second, expected) in cases {
            let error = from_yaml(&doc(second)).unwrap_err().0;
            assert!(error.starts_with(expected), "{second}: {error}");
            assert!(!error.contains(pw) && !error.contains(sha), "{error}");
        }
        // Both aliases resolve: a label aliased from the password loads.
        assert!(from_yaml(&doc("label: *pw")).is_ok());
    }

    /// Every case of `fixtures/config_secrets.json`: the YAML written with
    /// the case's file mode, then loaded as the server does.
    #[test]
    fn config_secrets_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/config_secrets.json")).unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() >= 40);
        let dir = tempfile::tempdir().unwrap();
        let mut mismatches = Vec::new();
        for (index, case) in cases.iter().enumerate() {
            let path = dir.path().join(format!("{index}.yml"));
            std::fs::write(&path, case["yaml"].as_str().unwrap()).unwrap();
            let mode = u32::try_from(case["mode"].as_u64().unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let actual = load(&path).ok().map(|s| secrets_json(&s));
            let expected = Some(&case["expected"]).filter(|v| !v.is_null()).cloned();
            if actual != expected {
                mismatches.push(format!("{}: {actual:?} != {expected:?}", case["name"]));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    #[test]
    fn debug_redacts_password_and_token_hash() {
        let secrets = from_yaml(
            "smtp: {username: relay, password: hunter2}\ntokens:\n  - label: t\n    \
             token_sha256: 'ABCDEF0000000000000000000000000000000000000000000000000000000000'\n    \
             mailgun_domains: [a.de]\n    allowed_from_domains: [a.de]\n",
        )
        .unwrap();
        let shown = format!("{secrets:?}");
        assert!(
            shown.contains("relay") && shown.contains("\"t\""),
            "{shown}"
        );
        assert!(!shown.contains("hunter2") && !shown.to_lowercase().contains("abcdef"));
        assert_eq!(secrets.tokens[0].token_sha256[..6], *"abcdef");
    }
}
