//! The token policy (PLAN.md 2.3 step 5; `relay:policy.py` `enforce_policy`).
//!
//! Order and statuses are Python's: path domain invalid → 400, not a
//! `mailgun_domains` entry → 403; `from` invalid → 400; from domain not in
//! `allowed_from_domains` → 403; `allowed_from_addresses` set and the
//! address not in it → 403. The 403 texts are kept verbatim (PLAN.md 2.2).
//! Pinned by `fixtures/policy.json`.

use crate::address::{Mailbox, parse_mailbox};
use crate::domain::normalize_domain;
use crate::secrets::TokenPolicy;

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// 400: the path domain or the `from` value is malformed.
    BadRequest,
    /// 403 with the response message.
    Forbidden(String),
}

/// Check one request against the matched token's policy; on success the
/// parsed `from` mailbox, which also builds the From header.
pub fn enforce_policy(
    policy: &TokenPolicy,
    path_domain: &str,
    from: &str,
) -> Result<Mailbox, PolicyError> {
    let path = normalize_domain(path_domain).map_err(|_| PolicyError::BadRequest)?;
    if !policy.mailgun_domains.contains(&path) {
        return Err(forbidden("path domain", &path));
    }
    let mailbox = parse_mailbox(from).map_err(|_| PolicyError::BadRequest)?;
    if !policy.allowed_from_domains.contains(&mailbox.domain) {
        return Err(forbidden("from domain", &mailbox.domain));
    }
    let address = mailbox.policy_address();
    if let Some(allowed) = &policy.allowed_from_addresses
        && !allowed.contains(&address)
    {
        return Err(forbidden("from address", &address));
    }
    Ok(mailbox)
}

fn forbidden(what: &str, value: &str) -> PolicyError {
    PolicyError::Forbidden(format!("token not allowed for {what} {}", py_repr(value)))
}

/// Python's `repr` of the ASCII strings these messages contain: single
/// quotes, double quotes when the value holds a `'` (an address local part
/// may; `"` and `\` never pass validation).
fn py_repr(value: &str) -> String {
    if value.contains('\'') {
        format!("\"{value}\"")
    } else {
        format!("'{value}'")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::*;
    use crate::domain::normalize_config_address;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    fn policy(mailgun: &[&str], from_domains: &[&str], addresses: Option<&[&str]>) -> TokenPolicy {
        TokenPolicy {
            label: "t".to_owned(),
            token_sha256: "0".repeat(64),
            mailgun_domains: set(mailgun),
            allowed_from_domains: set(from_domains),
            allowed_from_addresses: addresses.map(set),
        }
    }

    fn status(policy: &TokenPolicy, path: &str, from: &str) -> u16 {
        match enforce_policy(policy, path, from) {
            Ok(_) => 200,
            Err(PolicyError::BadRequest) => 400,
            Err(PolicyError::Forbidden(_)) => 403,
        }
    }

    /// Every case of `fixtures/policy.json` (Python oracle; D-10 and D-11
    /// cases carry the Rust expectation).
    #[test]
    fn policy_fixture() {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/policy.json")).unwrap();
        let strings = |v: &Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_owned())
                .collect()
        };
        let policies: Vec<(String, TokenPolicy)> = fixture["policies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                let token = TokenPolicy {
                    label: p["label"].as_str().unwrap().to_owned(),
                    token_sha256: "0".repeat(64),
                    mailgun_domains: strings(&p["mailgun_domains"]).into_iter().collect(),
                    allowed_from_domains: strings(&p["allowed_from_domains"]).into_iter().collect(),
                    allowed_from_addresses: (!p["allowed_from_addresses"].is_null())
                        .then(|| strings(&p["allowed_from_addresses"]).into_iter().collect()),
                };
                (token.label.clone(), token)
            })
            .collect();
        let cases = fixture["cases"].as_array().unwrap();
        let mut mismatches = Vec::new();
        for case in cases {
            let (_, policy) = policies
                .iter()
                .find(|(label, _)| label == case["policy"].as_str().unwrap())
                .unwrap();
            let path = case["path"].as_str().unwrap();
            let from = case["from"].as_str().unwrap();
            let actual = match enforce_policy(policy, path, from) {
                Ok(m) => (200, Value::String(m.policy_address())),
                Err(PolicyError::BadRequest) => (400, Value::Null),
                Err(PolicyError::Forbidden(message)) => (403, Value::String(message)),
            };
            let expected = (
                case["expected"]["status"].as_u64().unwrap() as u16,
                case["expected"]["detail"].clone(),
            );
            if actual != expected {
                mismatches.push(format!("{case}: {actual:?}"));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    /// The counterparts of `tests/test_policy.py`.
    #[test]
    fn python_policy_tests() {
        assert_eq!(
            normalize_domain("wersdörfer.de").unwrap(),
            "xn--wersdrfer-47a.de"
        );
        assert_eq!(
            normalize_domain("XN--wersdrfer-47a.DE").unwrap(),
            "xn--wersdrfer-47a.de"
        );
        assert!(normalize_domain("").is_err());
        assert_eq!(
            normalize_config_address("Some.User@wersdörfer.de").unwrap(),
            "some.user@xn--wersdrfer-47a.de"
        );
        assert!(normalize_config_address("noatsign").is_err());

        let plain = policy(&["wersdoerfer.de"], &["wersdoerfer.de"], None);
        let idn = policy(&["xn--wersdrfer-47a.de"], &["xn--wersdrfer-47a.de"], None);
        assert_eq!(status(&plain, "wersdoerfer.de", "x@wersdoerfer.de"), 200);
        assert_eq!(status(&idn, "wersdörfer.de", "someone@wersdörfer.de"), 200);
        assert_eq!(status(&plain, "evil.test", "x@wersdoerfer.de"), 403);
        assert_eq!(status(&plain, "wersdoerfer.de", "x@evil.test"), 403);
        let listed = policy(
            &["wersdoerfer.de"],
            &["wersdoerfer.de"],
            Some(&["jochen-homepage@wersdoerfer.de"]),
        );
        assert_eq!(
            status(&listed, "wersdoerfer.de", "Jochen-Homepage@wersdoerfer.de"),
            200
        );
        assert_eq!(
            status(&listed, "wersdoerfer.de", "someone-else@wersdoerfer.de"),
            403
        );
        let idn_listed = policy(
            &["xn--wersdrfer-47a.de"],
            &["xn--wersdrfer-47a.de"],
            Some(&["jochen@xn--wersdrfer-47a.de"]),
        );
        assert_eq!(
            status(
                &idn_listed,
                "wersdörfer.de",
                "Jochen <jochen@wersdörfer.de>"
            ),
            200
        );
        assert_eq!(status(&plain, "wersdoerfer.de", "not-an-email"), 400);
        assert_eq!(
            status(
                &plain,
                "wersdoerfer.de",
                "ok@wersdoerfer.de\nBcc: evil@wersdoerfer.de"
            ),
            400
        );
        // EAI senders are 400 whatever the policy says, but only after the
        // path domain check.
        assert_eq!(
            status(&plain, "wersdoerfer.de", "Jörg <jörg@wersdoerfer.de>"),
            400
        );
        assert_eq!(status(&plain, "example.org", "jörg@wersdoerfer.de"), 403);
        for sender in [
            "a@wersdörfer.de",
            "a@xn--wersdrfer-47a.de",
            "A <a@WERSDÖRFER.DE>",
        ] {
            assert_eq!(status(&idn, "xn--wersdrfer-47a.de", sender), 200);
        }
        assert_eq!(
            status(&idn, "xn--wersdrfer-47a.de", "a@wersdoerfer.de"),
            403
        );
    }

    #[test]
    fn forbidden_messages_are_python_reprs() {
        let listed = policy(
            &["mg.wersdoerfer.de"],
            &["wersdoerfer.de"],
            Some(&["a@wersdoerfer.de"]),
        );
        let message = |path: &str, from: &str| match enforce_policy(&listed, path, from) {
            Err(PolicyError::Forbidden(m)) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            message("MG.python-podcast.de", "a@wersdoerfer.de"),
            "token not allowed for path domain 'mg.python-podcast.de'"
        );
        assert_eq!(
            message("mg.wersdoerfer.de", "a@evil.test"),
            "token not allowed for from domain 'evil.test'"
        );
        assert_eq!(
            message("mg.wersdoerfer.de", "O'Brien <o'brien@wersdoerfer.de>"),
            "token not allowed for from address \"o'brien@wersdoerfer.de\""
        );
    }
}
