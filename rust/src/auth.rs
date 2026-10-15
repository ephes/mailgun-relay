//! HTTP Basic authentication against the configured token hashes (PLAN.md
//! 2.3 step 2; `relay:auth.py` `authenticate`).
//!
//! Every failure is the same 401 to the client, so the error carries no
//! detail. Pinned by `fixtures/auth.json`.

use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::pystr::py_strip;
use crate::secrets::TokenPolicy;

/// `base64.b64decode(validate=True)`: standard alphabet, no whitespace,
/// canonical padding required, non-zero trailing bits accepted (`YR==`).
const PY_STRICT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

#[derive(Debug, PartialEq, Eq)]
pub struct AuthError;

/// Resolve the first `Authorization` header (raw bytes, `None` when absent)
/// to the matching token policy. The password's SHA-256 is compared in
/// constant time against every policy without an early exit; the last match
/// wins, as in Python.
pub fn authenticate<'a>(
    authorization: Option<&[u8]>,
    policies: &'a [TokenPolicy],
) -> Result<&'a TokenPolicy, AuthError> {
    // Starlette decodes header values as latin-1: one char per byte.
    let header: String = authorization
        .ok_or(AuthError)?
        .iter()
        .map(|&b| char::from(b))
        .collect();
    let encoded = py_strip(header.strip_prefix("Basic ").ok_or(AuthError)?);
    // A non-ASCII char fails here too (Python: ValueError, also 401).
    let decoded = PY_STRICT_BASE64.decode(encoded).map_err(|_| AuthError)?;
    let decoded = String::from_utf8(decoded).map_err(|_| AuthError)?;
    let (username, password) = decoded.split_once(':').ok_or(AuthError)?;

    let username_ok: bool = username.as_bytes().ct_eq(b"api").into();
    let digest = hex_lower(&Sha256::digest(password.as_bytes()));
    let mut matched = None;
    for policy in policies {
        if bool::from(policy.token_sha256.as_bytes().ct_eq(digest.as_bytes())) {
            matched = Some(policy);
        }
    }
    match matched {
        Some(policy) if username_ok => Ok(policy),
        _ => Err(AuthError),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::*;

    fn policy(label: &str, token: &str) -> TokenPolicy {
        TokenPolicy {
            label: label.to_owned(),
            token_sha256: hex_lower(&Sha256::digest(token.as_bytes())),
            mailgun_domains: BTreeSet::from(["wersdoerfer.de".to_owned()]),
            allowed_from_domains: BTreeSet::from(["wersdoerfer.de".to_owned()]),
            allowed_from_addresses: None,
        }
    }

    fn basic(user: &str, password: &str) -> Vec<u8> {
        let raw = format!("{user}:{password}");
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
        .into_bytes()
    }

    fn label(header: Option<&[u8]>, policies: &[TokenPolicy]) -> Option<String> {
        authenticate(header, policies).ok().map(|p| p.label.clone())
    }

    /// Every case of `fixtures/auth.json` (Python oracle).
    #[test]
    fn auth_fixture() {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/auth.json")).unwrap();
        let policies: Vec<TokenPolicy> = fixture["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| TokenPolicy {
                label: t["label"].as_str().unwrap().to_owned(),
                token_sha256: t["token_sha256"].as_str().unwrap().to_owned(),
                mailgun_domains: BTreeSet::new(),
                allowed_from_domains: BTreeSet::new(),
                allowed_from_addresses: None,
            })
            .collect();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() >= 60);
        let mut mismatches = Vec::new();
        for case in cases {
            // Header bytes are stored as their latin-1 decoding.
            let header: Option<Vec<u8>> = case["header"].as_str().map(|text| {
                text.chars()
                    .map(|c| u8::try_from(u32::from(c)).unwrap())
                    .collect()
            });
            let actual = label(header.as_deref(), &policies);
            let expected = case["expected"].as_str().map(str::to_owned);
            if actual != expected {
                mismatches.push(format!("{}: {actual:?} != {expected:?}", case["name"]));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    /// The counterparts of `tests/test_auth.py`.
    #[test]
    fn python_auth_tests() {
        let good = [policy("h", "good-token")];
        assert_eq!(label(None, &good), None);
        assert_eq!(label(Some(b"Bearer xyz"), &good), None);
        assert_eq!(label(Some(&basic("notapi", "good-token")), &good), None);
        assert_eq!(label(Some(&basic("api", "wrong-token")), &good), None);
        let staging = [policy("homepage-staging", "good-token")];
        assert_eq!(
            label(Some(&basic("api", "good-token")), &staging).as_deref(),
            Some("homepage-staging")
        );
        let many = [
            policy("a", "token-a"),
            policy("b", "token-b"),
            policy("c", "token-c"),
        ];
        assert_eq!(
            label(Some(&basic("api", "token-b")), &many).as_deref(),
            Some("b")
        );
        assert_eq!(label(Some(b"Basic !!!notbase64!!!"), &good), None);
        assert_eq!(label(Some(b"Basic anVzdHVzZXI="), &good), None);
    }

    #[test]
    fn last_match_wins_and_trailing_bits_decode() {
        let dup = [policy("first", "t"), policy("second", "t")];
        assert_eq!(
            label(Some(&basic("api", "t")), &dup).as_deref(),
            Some("second")
        );
        // "api:t" is YXBpOnQ=; the trailing bits of `Q` may be non-zero (`R`).
        assert_eq!(
            label(Some(b"Basic YXBpOnR="), &dup).as_deref(),
            Some("second")
        );
        assert_eq!(label(Some(b"Basic YXBpOnQ"), &dup), None);
        assert_eq!(
            label(Some(b"Basic \x85YXBpOnQ=\xa0"), &dup).as_deref(),
            Some("second")
        );
        assert_eq!(label(Some(b"Basic \xe9YXBpOnQ="), &dup), None);
    }
}
