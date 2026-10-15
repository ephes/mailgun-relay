//! Domain normalisation (PLAN.md 2.6, D-10).
//!
//! S1 needs the configuration side: `relay:policy.py` `normalize_domain` as
//! `relay:config.py` applies it to `ENVELOPE_SENDER` (and, from S1c, to the
//! secrets file). Configuration never accepts more than Python, so configured
//! domains are restricted to a Latin character set (D-10). S2 pins the
//! runtime normalisation against the `domain.json` corpus.

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

use crate::pystr::py_strip;

/// `normalize_domain`: `strip().lower()`, UTS46 non-transitional mapping,
/// IDNA validity checks and DNS lengths (root dot allowed); the A-label.
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
        .map_err(|_| format!("invalid domain: {value:?}"))
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
/// [`normalize_domain`].
/// The set applies to the input and to the Unicode form of the result, so
/// neither a mapping (`ŀ` → `l·`) nor an A-label input (`xn--n3h`) can
/// bring in a character outside it.
pub fn normalize_config_domain(value: &str) -> Result<String, String> {
    let outside =
        || format!("domain {value:?} contains characters outside the supported set (PLAN.md D-10)");
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
}
