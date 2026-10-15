//! Subject and custom header validation (PLAN.md 2.3 steps 6 and 7;
//! `relay:headers.py` `validate_subject`, `validate_custom_headers`,
//! `contains_forbidden_control_chars`). Pinned by `fixtures/headers.json`.

use crate::pystr::py_strip;

/// Every failure is a 400; the kinds mirror Python's exception classes
/// (the `error_class` of the request record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    Injection,
    TooLong,
    Dangerous,
}

impl HeaderError {
    pub fn class(self) -> &'static str {
        match self {
            HeaderError::Injection => "HeaderInjectionError",
            HeaderError::TooLong => "HeaderTooLongError",
            HeaderError::Dangerous => "DangerousHeaderError",
        }
    }
}

/// `_FORBIDDEN_CONTROL_RE`: C0 and C1 controls except TAB, DEL, U+2028 and
/// U+2029. Shared by the subject, `h:*` values and the address parsers.
pub fn contains_forbidden_control_chars(value: &str) -> bool {
    value.chars().any(|c| {
        matches!(c, '\0'..='\x08' | '\n'..='\x1f' | '\x7f'..='\u{9f}' | '\u{2028}' | '\u{2029}')
    })
}

/// Headers the relay sets itself, structural MIME headers and receipt
/// requests (`_DANGEROUS_HEADER_NAMES`), compared case-insensitively; every
/// `resent-*` name as well.
const DANGEROUS: &[&str] = &[
    "bcc",
    "received",
    "return-path",
    "message-id",
    "date",
    "from",
    "to",
    "cc",
    "subject",
    "sender",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "content-disposition",
    "content-id",
    "disposition-notification-to",
    "return-receipt-to",
];

fn is_dangerous(name: &str) -> bool {
    let lowered = name.to_lowercase();
    DANGEROUS.contains(&lowered.as_str()) || lowered.starts_with("resent-")
}

/// `^[A-Za-z][A-Za-z0-9-]*$` as a full match (`fullmatch` in Python, so a
/// final newline is refused on both sides, D-19).
fn is_header_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Python's `len()`: code points. A negative maximum refuses every value.
fn longer_than(value: &str, max: i64) -> bool {
    i64::try_from(value.chars().count()).map_or(true, |len| len > max)
}

/// The subject as sent: stripped, then checked for control characters and
/// length. An empty subject is allowed.
pub fn validate_subject(value: &str, max_length: i64) -> Result<String, HeaderError> {
    let stripped = py_strip(value);
    if contains_forbidden_control_chars(stripped) {
        return Err(HeaderError::Injection);
    }
    if longer_than(stripped, max_length) {
        return Err(HeaderError::TooLong);
    }
    Ok(stripped.to_owned())
}

/// The `h:*` headers in map order, first error wins: name syntax, denylist,
/// control characters in the value, value length.
pub fn validate_custom_headers(
    headers: &[(String, String)],
    max_value_length: i64,
) -> Result<(), HeaderError> {
    for (name, value) in headers {
        if !is_header_name(name) {
            return Err(HeaderError::Injection);
        }
        if is_dangerous(name) {
            return Err(HeaderError::Dangerous);
        }
        if contains_forbidden_control_chars(value) {
            return Err(HeaderError::Injection);
        }
        if longer_than(value, max_value_length) {
            return Err(HeaderError::TooLong);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn one(name: &str, value: &str) -> Result<(), HeaderError> {
        validate_custom_headers(&[(name.to_owned(), value.to_owned())], 998)
    }

    /// `tests/test_headers.py`, the subject and custom header tests.
    #[test]
    fn python_header_tests() {
        assert_eq!(validate_subject("Hello there", 998).unwrap(), "Hello there");
        assert_eq!(validate_subject("  Hello  ", 998).unwrap(), "Hello");
        assert_eq!(
            validate_subject("Hello\tthere", 998).unwrap(),
            "Hello\tthere"
        );
        for bad in ["Hi\nBcc: evil@x.com", "Hi\rEvil"] {
            assert_eq!(validate_subject(bad, 998), Err(HeaderError::Injection));
        }
        assert_eq!(
            validate_subject(&"a".repeat(1000), 998),
            Err(HeaderError::TooLong)
        );
        for bad in ["\0", "\x0b", "\x0c", "\u{85}", "\u{2028}", "\u{2029}"] {
            let subject = format!("Hi{bad}World");
            assert_eq!(validate_subject(&subject, 998), Err(HeaderError::Injection));
        }
        for name in [
            "Sender",
            "MIME-Version",
            "Content-Type",
            "Content-Transfer-Encoding",
            "Content-Disposition",
            "Content-ID",
            "Disposition-Notification-To",
            "Return-Receipt-To",
            "Bcc",
            "bCc",
            "Received",
            "Return-Path",
            "Resent-From",
            "Message-Id",
            "From",
            "To",
            "Cc",
            "Subject",
            "Date",
        ] {
            assert_eq!(
                one(name, "x@example.test"),
                Err(HeaderError::Dangerous),
                "{name}"
            );
        }
        assert_eq!(one("X-Thing", "a\0b"), Err(HeaderError::Injection));
        assert_eq!(one("Reply-To", "support@example.test"), Ok(()));
        assert_eq!(
            one("X-Custom", "ok\nBcc: evil@x.com"),
            Err(HeaderError::Injection)
        );
        assert_eq!(one("X-Long", &"x".repeat(1000)), Err(HeaderError::TooLong));
        assert_eq!(one("X Bad Name", "ok"), Err(HeaderError::Injection));
    }

    #[test]
    fn first_error_wins_in_map_order() {
        let headers = [
            ("X-Long".to_owned(), "x".repeat(10)),
            ("Bcc".to_owned(), "a@b.de".to_owned()),
        ];
        assert_eq!(
            validate_custom_headers(&headers, 5),
            Err(HeaderError::TooLong)
        );
        assert_eq!(
            validate_custom_headers(&headers, 10),
            Err(HeaderError::Dangerous)
        );
        assert_eq!(validate_subject("", -1), Err(HeaderError::TooLong));
        assert_eq!(HeaderError::Dangerous.class(), "DangerousHeaderError");
    }

    fn status(result: Result<(), HeaderError>) -> &'static str {
        match result {
            Ok(()) => "ok",
            Err(HeaderError::Injection) => "injection",
            Err(HeaderError::TooLong) => "too_long",
            Err(HeaderError::Dangerous) => "dangerous",
        }
    }

    #[test]
    fn headers_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/headers.json")).unwrap();
        let max = fixture["max_length"].as_i64().unwrap();
        let mut checked = 0;
        for case in fixture["subjects"].as_array().unwrap() {
            let value = case["value"].as_str().unwrap();
            let result = validate_subject(value, max);
            let expected = &case["expected"];
            match expected["subject"].as_str() {
                Some(subject) => assert_eq!(result.as_deref(), Ok(subject), "{value:?}"),
                None => assert_eq!(
                    status(result.map(|_| ())),
                    expected["error"].as_str().unwrap(),
                    "{value:?}"
                ),
            }
            checked += 1;
        }
        for case in fixture["headers"].as_array().unwrap() {
            let headers: Vec<(String, String)> = case["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    let pair = pair.as_array().unwrap();
                    (
                        pair[0].as_str().unwrap().to_owned(),
                        pair[1].as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            let result = status(validate_custom_headers(&headers, max));
            assert_eq!(result, case["expected"].as_str().unwrap(), "{headers:?}");
            checked += 1;
        }
        for case in fixture["control"].as_array().unwrap() {
            let value = case["value"].as_str().unwrap();
            let expected = case["expected"].as_bool().unwrap();
            assert_eq!(
                contains_forbidden_control_chars(value),
                expected,
                "{value:?}"
            );
            checked += 1;
        }
        assert!(checked > 200, "{checked}");
    }
}
