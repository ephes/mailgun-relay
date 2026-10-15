//! Python `str` semantics the contract depends on (PLAN.md 2.3, 2.8).

/// Python's `str.isspace()`: Unicode bidi classes WS, B, S and category Zs.
/// Wider than Rust's `char::is_whitespace` (it includes `\x1c`–`\x1f`).
pub fn is_py_space(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\x1c'..='\x20'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Python's `str.strip()` without arguments.
pub fn py_strip(value: &str) -> &str {
    value.trim_matches(is_py_space)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_matches_python_whitespace_set() {
        assert_eq!(py_strip("\x1c\x1d a b \u{85}\u{a0}\u{3000}"), "a b");
        assert_eq!(py_strip("\u{200b}a"), "\u{200b}a");
        assert!(!is_py_space('\u{180e}'));
    }
}
