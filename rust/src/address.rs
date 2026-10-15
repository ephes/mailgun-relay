//! Mailbox parsing and address validation (PLAN.md 2.6, D-11).
//!
//! Python decides with `email.utils.parseaddr`/`getaddresses` (strict mode)
//! and `email_validator` (`relay:policy.py` `parse_email_strict`,
//! `relay:headers.py` `parse_address_list`, `parse_header_address_list`).
//! This module implements a strict subset of what they accept and is pinned
//! by the corpus in `fixtures/address.json`: every value it accepts, Python
//! accepts with the same address and display name; exotic forms Python also
//! accepts (whitespace or comments inside the addr-spec, unclosed `<`,
//! groups, nested comments, a backslash outside quotes, domains outside the
//! Latin set of [`crate::domain`]) are refused (D-11, fail closed).
//!
//! A value is parsed once; the result serves the policy decision and the
//! message headers.

use crate::domain::address_domain;

/// One mailbox: the display name as Python's parser returns it (comments
/// included as Python includes them) and the addr-spec with an A-label
/// domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub display_name: String,
    /// ASCII local part as sent; RFC 2142 role names lowercased, as
    /// `email_validator` does.
    pub local: String,
    /// Lowercase A-label.
    pub domain: String,
}

impl Mailbox {
    /// The addr-spec for headers and the envelope (`ascii_email`).
    pub fn addr_spec(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }

    /// The form the policy compares with `allowed_from_addresses`.
    pub fn policy_address(&self) -> String {
        format!("{}@{}", self.local.to_ascii_lowercase(), self.domain)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidAddress;

/// `relay:headers.py` `_FORBIDDEN_CONTROL_RE`: C0 and C1 controls except
/// TAB, DEL, U+2028 and U+2029.
pub fn contains_forbidden_control_chars(value: &str) -> bool {
    value.chars().any(|c| {
        matches!(c, '\0'..='\x08' | '\n'..='\x1f' | '\x7f'..='\u{9f}' | '\u{2028}' | '\u{2029}')
    })
}

/// One mailbox per value (`from`, `to`, `cc`, `bcc`): `addr`,
/// `Name <addr>`, `"Quoted, Name" <addr>`, `<addr>`, `addr (comment)`.
pub fn parse_mailbox(value: &str) -> Result<Mailbox, InvalidAddress> {
    if contains_forbidden_control_chars(value) {
        return Err(InvalidAddress);
    }
    let chars: Vec<char> = value.chars().collect();
    mailbox(&chars)
}

/// An address list (`h:Reply-To`): mailboxes separated by commas outside
/// quoted strings; no empty elements, no groups.
pub fn parse_mailbox_list(value: &str) -> Result<Vec<Mailbox>, InvalidAddress> {
    if contains_forbidden_control_chars(value) {
        return Err(InvalidAddress);
    }
    let chars: Vec<char> = value.chars().collect();
    let mut mailboxes = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (i, &c) in chars.iter().enumerate() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                mailboxes.push(mailbox(&chars[start..i])?);
                start = i + 1;
            }
            _ => {}
        }
    }
    mailboxes.push(mailbox(&chars[start..])?);
    Ok(mailboxes)
}

/// A bare addr-spec without display name, comments or whitespace
/// (`ENVELOPE_SENDER`, D-15).
pub fn parse_addr_spec(value: &str) -> Result<Mailbox, InvalidAddress> {
    if !value.chars().all(is_addr_char) {
        return Err(InvalidAddress);
    }
    validate(value, String::new())
}

fn is_wsp(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Characters of an unquoted display-name word: everything but whitespace
/// and `()<>@,:;"[]\`; `.` is allowed (obsolete phrase syntax, as Python).
fn is_word_char(c: char) -> bool {
    !is_wsp(c) && !"()<>@,:;\"[]\\".contains(c)
}

/// Characters of an addr-spec token; its parts are validated afterwards.
fn is_addr_char(c: char) -> bool {
    !is_wsp(c) && !"()<>,:;\"[]\\".contains(c)
}

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn take_while(&mut self, accept: impl Fn(char) -> bool) -> String {
        let start = self.pos;
        while self.peek().is_some_and(&accept) {
            self.pos += 1;
        }
        self.chars[start..self.pos].iter().collect()
    }

    /// Whitespace and comments; comment texts are appended to `comments`.
    /// A comment holds no `(`, `)`, `\`, `"` or `,` and must be closed.
    fn skip_cfws(&mut self, comments: &mut Vec<String>) -> Result<(), InvalidAddress> {
        loop {
            match self.peek() {
                Some(c) if is_wsp(c) => self.pos += 1,
                Some('(') => {
                    self.pos += 1;
                    let text = self.take_while(|c| !"()\\\",".contains(c));
                    if self.peek() != Some(')') {
                        return Err(InvalidAddress);
                    }
                    self.pos += 1;
                    comments.push(text);
                }
                _ => return Ok(()),
            }
        }
    }

    /// A quoted string with backslash escapes, unquoted.
    fn quoted(&mut self) -> Result<String, InvalidAddress> {
        self.pos += 1;
        let mut text = String::new();
        loop {
            match self.peek() {
                None => return Err(InvalidAddress),
                Some('"') => {
                    self.pos += 1;
                    return Ok(text);
                }
                Some('\\') => {
                    text.push(
                        self.chars
                            .get(self.pos + 1)
                            .copied()
                            .ok_or(InvalidAddress)?,
                    );
                    self.pos += 2;
                }
                Some(c) => {
                    text.push(c);
                    self.pos += 1;
                }
            }
        }
    }
}

fn mailbox(chars: &[char]) -> Result<Mailbox, InvalidAddress> {
    let mut p = Parser { chars, pos: 0 };
    let mut comments = Vec::new();
    p.skip_cfws(&mut comments)?;
    let start = p.pos;

    // `addr [CFWS]`: the display name is the comments, joined.
    let token = p.take_while(is_addr_char);
    if token.contains('@') {
        p.skip_cfws(&mut comments)?;
        if p.peek().is_some() {
            return Err(InvalidAddress);
        }
        return validate(&token, comments.join(" "));
    }

    // `[phrase] < addr > [CFWS]`: words joined by one space, then the
    // comments before `<` in parentheses. Comments after `>` are dropped.
    p.pos = start;
    let mut words = Vec::new();
    loop {
        p.skip_cfws(&mut comments)?;
        match p.peek() {
            Some('"') => words.push(p.quoted()?),
            Some(c) if is_word_char(c) => words.push(p.take_while(is_word_char)),
            Some('<') => break,
            _ => return Err(InvalidAddress),
        }
    }
    let mut display_name = words.join(" ");
    if !comments.is_empty() {
        display_name = format!("{display_name} ({})", comments.join(" "));
    }
    p.pos += 1;
    p.take_while(is_wsp);
    let token = p.take_while(is_addr_char);
    p.take_while(is_wsp);
    if p.peek() != Some('>') {
        return Err(InvalidAddress);
    }
    p.pos += 1;
    p.skip_cfws(&mut Vec::new())?;
    if p.peek().is_some() {
        return Err(InvalidAddress);
    }
    validate(&token, display_name)
}

/// `email_validator` 2.3 characters of an unquoted local part.
fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c)
}

/// RFC 2142 role names `email_validator` lowercases.
const CASE_INSENSITIVE_MAILBOX_NAMES: [&str; 15] = [
    "info",
    "marketing",
    "sales",
    "support",
    "abuse",
    "noc",
    "security",
    "postmaster",
    "hostmaster",
    "usenet",
    "news",
    "webmaster",
    "www",
    "uucp",
    "ftp",
];

/// The addr-spec rules of PLAN.md 2.6: an ASCII dot-atom local part (no
/// quoted or EAI local parts), the domain rules of
/// [`address_domain`], and `email_validator`'s length limit of 254 UTF-8
/// bytes for the input, the Unicode and the ASCII form.
fn validate(token: &str, display_name: String) -> Result<Mailbox, InvalidAddress> {
    let (local, raw_domain) = token.split_once('@').ok_or(InvalidAddress)?;
    let dot_atom = !local.is_empty()
        && local
            .split('.')
            .all(|atom| !atom.is_empty() && atom.chars().all(is_atext));
    if !dot_atom {
        return Err(InvalidAddress);
    }
    let domain = address_domain(raw_domain).ok_or(InvalidAddress)?;
    let (unicode, _) = idna::domain_to_unicode(&domain);
    let longest = raw_domain.len().max(unicode.len()).max(domain.len());
    if local.len() + 1 + longest > 254 {
        return Err(InvalidAddress);
    }
    let local = if CASE_INSENSITIVE_MAILBOX_NAMES.contains(&local.to_ascii_lowercase().as_str()) {
        local.to_ascii_lowercase()
    } else {
        local.to_owned()
    };
    Ok(Mailbox {
        display_name,
        local,
        domain,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::domain::normalize_config_address;

    fn mailbox_json(m: &Mailbox) -> Value {
        json!([m.display_name, m.addr_spec(), m.policy_address()])
    }

    /// Every case of `fixtures/address.json` (≥ 400 values), and the
    /// fail-closed property against the stored Python results: whatever
    /// Rust accepts, Python accepts with the same address and display name.
    #[test]
    fn address_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/address.json")).unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() >= 400);
        let mut mismatches = Vec::new();
        for case in cases {
            let input = case["input"].as_str().unwrap();
            let python = &case["python"];
            let mailbox = parse_mailbox(input).ok().map(|m| mailbox_json(&m));
            let list = parse_mailbox_list(input)
                .ok()
                .map(|l| Value::Array(l.iter().map(mailbox_json).collect()));
            let normalized = normalize_config_address(input).ok().map(Value::String);
            let actual = json!({
                "mailbox": mailbox, "mailbox_list": list, "normalize_address": normalized,
            });
            if actual != case["expected"] {
                mismatches.push(format!("{input:?}: {actual} != {}", case["expected"]));
            }
            if let Some(m) = &mailbox {
                assert_eq!(python["parse_email_strict"], m[2], "{input:?}");
                assert_eq!(
                    python["parse_address_list"],
                    json!([[m[0], m[1]]]),
                    "{input:?}"
                );
            }
            if let Some(Value::Array(l)) = &list {
                let pairs: Vec<Value> = l.iter().map(|m| json!([m[0], m[1]])).collect();
                assert_eq!(
                    python["parse_header_address_list"],
                    json!(pairs),
                    "{input:?}"
                );
            }
            if let Some(n) = &normalized {
                assert_eq!(&python["normalize_address"], n, "{input:?}");
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    fn single(value: &str) -> Option<(String, String)> {
        parse_mailbox(value)
            .ok()
            .map(|m| (m.display_name.clone(), m.addr_spec()))
    }

    /// The address parts of `tests/test_headers.py`.
    #[test]
    fn python_header_tests() {
        let both = |v: &str| single(v).map(|(_, a)| a);
        assert_eq!(both("a@x.test").as_deref(), Some("a@x.test"));
        assert_eq!(
            single("Alice <alice@x.test>"),
            Some(("Alice".to_owned(), "alice@x.test".to_owned()))
        );
        for bad in [
            "alice@x.test\nBcc: evil@y.test",
            "not an address",
            "bad@bad domain",
            "a@x..test",
            "foo@",
            "@bar.com",
            "user@-.example.com",
            "no-at-sign",
        ] {
            assert_eq!(single(bad), None, "{bad:?}");
        }
        let list = parse_mailbox_list("\"Doe, Jane\" <jane@example.test>").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].display_name, "Doe, Jane");
        let list = parse_mailbox_list("a@x.test, b@y.test, Carol <c@z.test>").unwrap();
        let specs: Vec<String> = list.iter().map(Mailbox::addr_spec).collect();
        assert_eq!(specs, ["a@x.test", "b@y.test", "c@z.test"]);
        assert!(parse_mailbox_list("a@x.test,\nb@y.test").is_err());
        assert!(parse_mailbox_list("a@x.test, bad@bad domain").is_err());
        for idn in [
            "foo@wersdörfer.de",
            "foo@WERSDÖRFER.de",
            "foo@xn--wersdrfer-47a.de",
            "Jörg <foo@wersdörfer.de>",
        ] {
            assert_eq!(both(idn).as_deref(), Some("foo@xn--wersdrfer-47a.de"));
            let list = parse_mailbox_list(idn).unwrap();
            assert_eq!(list[0].addr_spec(), "foo@xn--wersdrfer-47a.de");
        }
        assert_eq!(
            both("Some.User@Example.TEST").as_deref(),
            Some("Some.User@example.test")
        );
    }

    #[test]
    fn display_names_follow_python() {
        let display = |v: &str| single(v).map(|(d, _)| d);
        assert_eq!(display("a@x.de (Kommentar)").as_deref(), Some("Kommentar"));
        assert_eq!(display("(c1) a@x.de (c2)").as_deref(), Some("c1 c2"));
        assert_eq!(
            display("Jane (c) <a@x.de> (d)").as_deref(),
            Some("Jane (c)")
        );
        assert_eq!(
            display("Jane \"Q\" Doe <a@x.de>").as_deref(),
            Some("Jane Q Doe")
        );
        assert_eq!(
            display("\"Jane \\\"Q\\\"\" <a@x.de>").as_deref(),
            Some("Jane \"Q\"")
        );
        assert_eq!(display("Dr.  Jane <a@x.de>").as_deref(), Some("Dr. Jane"));
        assert_eq!(display("< a@x.de >").as_deref(), Some(""));
        assert_eq!(
            single("Info <INFO@X.DE>").map(|(_, a)| a).as_deref(),
            Some("info@x.de")
        );
    }

    #[test]
    fn exotic_forms_are_refused() {
        for bad in [
            "a . b@x.de",
            "a @x.de",
            "<a@x.de",
            "grp: a@x.de;",
            "a@x.de, b@x.de",
            "(a (b)) a@x.de",
            "(a, b) a@x.de",
            "a\\b <a@x.de>",
            "\"Jane <a@x.de>",
            "Jane <a@x.de> x",
            "a@αβ.gr",
            "jörg@x.de",
            "\"a b\"@x.de",
        ] {
            assert_eq!(single(bad), None, "{bad:?}");
        }
        assert!(parse_mailbox_list("a@x.de,").is_err());
        assert!(parse_mailbox_list("a@x.de,,b@x.de").is_err());
    }
}
