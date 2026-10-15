//! Domain and allowlist-address normalisation (PLAN.md 2.6, D-10, D-17).
//!
//! S1 needs the configuration side: `relay:policy.py` `normalize_domain` and
//! `normalize_address` as `relay:config.py` applies them to the secrets file
//! and to `ENVELOPE_SENDER`. Configuration never accepts more than Python, so
//! configured domains are restricted to a Latin character set (D-10) and
//! configured addresses to ASCII local parts (D-17). S2 pins the runtime
//! normalisation against the `domain.json` corpus.

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

use crate::pystr::py_strip;

/// `normalize_domain`: `strip().lower()`, UTS46 non-transitional mapping,
/// IDNA validity checks and DNS lengths (root dot allowed); the A-label.
/// Errors here and below never contain the value: in the secrets file it
/// may be a YAML alias of the password.
pub fn normalize_domain(value: &str) -> Result<String, String> {
    let lowered = py_strip(value).to_lowercase();
    if lowered.is_empty() {
        return Err("empty domain".to_owned());
    }
    Uts46::new()
        .to_ascii(
            lowered.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::Check,
            DnsLength::VerifyAllowRootDot,
        )
        .map(|ascii| ascii.into_owned())
        .map_err(|_| "invalid domain".to_owned())
}

/// Code points a configured domain may contain after `strip().lower()`
/// (D-10): ASCII letters, digits, `-`, `.`, the Latin letters of Latin-1,
/// Latin Extended-A/B, IPA Extensions and Latin Extended Additional, and the
/// combining diacritical marks. Python's IDNA2008 tables accept all of them
/// wherever UTS46 does, so a domain that passes here and in `idna` also loads
/// in Python.
fn is_config_domain_char(c: char) -> bool {
    matches!(c,
        'a'..='z' | '0'..='9' | '-' | '.'
        | '\u{c0}'..='\u{d6}' | '\u{d8}'..='\u{f6}' | '\u{f8}'..='\u{24f}'
        | '\u{250}'..='\u{2af}' | '\u{300}'..='\u{36f}' | '\u{1e00}'..='\u{1eff}')
}

/// A domain from the configuration: the D-10 character set, then
/// [`normalize_domain`]. The set applies to the input and to the Unicode form of the result, so
/// neither a mapping (`ŀ` → `l·`) nor an A-label input (`xn--n3h`) can
/// bring in a character outside it.
pub fn normalize_config_domain(value: &str) -> Result<String, String> {
    let outside =
        || "domain contains characters outside the supported set (PLAN.md D-10)".to_owned();
    if !py_strip(value)
        .to_lowercase()
        .chars()
        .all(is_config_domain_char)
    {
        return Err(outside());
    }
    let ascii = normalize_domain(value)?;
    let (unicode, result) = idna::domain_to_unicode(&ascii);
    if result.is_err() || !unicode.chars().all(is_config_domain_char) {
        return Err(outside());
    }
    Ok(ascii)
}

/// `normalize_address` for `allowed_from_addresses`: strip, split at the last
/// `@`, local part lowercased, domain normalised. A non-ASCII local part can
/// never match a sender (Q2), so it fails the load (D-17).
pub fn normalize_config_address(value: &str) -> Result<String, String> {
    let stripped = py_strip(value);
    let Some((local, domain)) = stripped.rsplit_once('@') else {
        return Err("address missing '@'".to_owned());
    };
    if local.is_empty() {
        return Err("address missing local part".to_owned());
    }
    if !local.is_ascii() {
        return Err(
            "address has a non-ASCII local part, which never matches (PLAN.md D-17)".to_owned(),
        );
    }
    Ok(format!(
        "{}@{}",
        local.to_ascii_lowercase(),
        normalize_config_domain(domain)?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_domains() {
        let ok = |v: &str| normalize_config_domain(v).unwrap();
        assert_eq!(ok(" WERSDÖRFER.DE "), "xn--wersdrfer-47a.de");
        assert_eq!(ok("ß.de"), "xn--zca.de");
        assert_eq!(ok("mg.wersdoerfer.de."), "mg.wersdoerfer.de.");
        assert_eq!(ok("localhost"), "localhost");
        for bad in [
            "",
            "a_b.de",
            "a..b",
            "-x.de",
            "xn--abc.de",
            "ⅻ.de",
            "ü.δ",
            "😀.de",
            "ŀ.de",
            "xn--n3h.ü",
        ] {
            assert!(normalize_config_domain(bad).is_err(), "{bad:?}");
        }
        assert_eq!(normalize_domain("ⅻ.de").unwrap(), "xii.de");
    }

    #[test]
    fn config_addresses() {
        let ok = |v: &str| normalize_config_address(v).unwrap();
        assert_eq!(ok(" Info@WERSDÖRFER.de"), "info@xn--wersdrfer-47a.de");
        assert_eq!(ok("a@b@c.de"), "a@b@c.de");
        for bad in ["a.de", "@a.de", "a@", "jörg@a.de", "a@xn--n3h.de"] {
            assert!(normalize_config_address(bad).is_err(), "{bad:?}");
        }
    }
}
