//! The YAML 1.1 subset of PyYAML `safe_load` that the secrets file needs
//! (PLAN.md 2.8, D-6).
//!
//! `yaml-rust2` parses (YAML 1.2 syntax, but it reports scalar styles and
//! tags); this module applies PyYAML's implicit types to plain scalars, so a
//! plain `yes`, `0777` or `2026-10-15` is never a string, and it rejects what
//! PyYAML rejects or what this subset does not reproduce: unsupported tags,
//! merge keys, duplicate anchors, unconstructible timestamps, non-printable
//! characters. Anchors and aliases share nodes through `Rc`, so alias
//! expansion costs no memory.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::LazyLock;

use regex::Regex;
use yaml_rust2::parser::{Event, Parser, Tag};
use yaml_rust2::scanner::{Scanner, TScalarStyle, TokenType};

/// Nesting limit; deeper documents are rejected (fail closed, D-6).
const MAX_DEPTH: usize = 64;

#[derive(Debug, PartialEq)]
pub enum Node {
    Str(String),
    Null,
    /// A plain scalar of another YAML 1.1 type (`bool`, `int`, `float`,
    /// `timestamp`); never equal to a string.
    Other(&'static str),
    Seq(Vec<Rc<Node>>),
    /// Entries in document order; only string keys can be looked up.
    Map(Vec<(Option<String>, Rc<Node>)>),
}

impl Node {
    /// `dict.get(key)` on a mapping: the last entry wins, as in PyYAML.
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(entries) => entries
                .iter()
                .rev()
                .find(|(k, _)| k.as_deref() == Some(key))
                .map(|(_, v)| v.as_ref()),
            _ => None,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Node::Str(_) => "str",
            Node::Null => "null",
            Node::Other(name) => name,
            Node::Seq(_) => "list",
            Node::Map(_) => "mapping",
        }
    }
}

macro_rules! re {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
    };
}

// PyYAML 6 `resolver.py`, rewritten without verbose mode.
re!(
    BOOL,
    r"^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$"
);
re!(
    FLOAT,
    r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
);
re!(
    INT,
    r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$"
);
re!(NULL, r"^(?:~|null|Null|NULL|)$");
// PyYAML `constructor.py` `timestamp_regexp`; the resolver's pattern only
// differs in requiring two-digit month and day for a date without time.
re!(
    TIMESTAMP_RESOLVE,
    r"^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$"
);
re!(
    TIMESTAMP_PARTS,
    r"^([0-9]{4})-([0-9][0-9]?)-([0-9][0-9]?)(?:(?:[Tt]|[ \t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\.[0-9]*)?(?:[ \t]*(?:Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?)?$"
);

/// The type PyYAML gives a plain scalar, or the error its constructor raises.
fn resolve_plain(value: String) -> Result<Node, String> {
    if NULL.is_match(&value) {
        Ok(Node::Null)
    } else if BOOL.is_match(&value) {
        Ok(Node::Other("bool"))
    } else if FLOAT.is_match(&value) {
        Ok(Node::Other("float"))
    } else if INT.is_match(&value) {
        // `construct_yaml_int` drops `_` and fails on a bare `0b`/`0x`
        // prefix, and Python's `int()` refuses more than 4300 decimal digits
        // (`sys.get_int_max_str_digits()`; bases 2, 8, 16 are exempt).
        let digits = value.trim_start_matches(['-', '+']).replace('_', "");
        if digits == "0b" || digits == "0x" {
            return Err("unconstructible int scalar".to_owned());
        }
        let power_of_two_base = digits.starts_with("0b")
            || digits.starts_with("0x")
            || (digits.starts_with('0') && digits.len() > 1 && !digits.contains(':'));
        if !power_of_two_base && digits.split(':').any(|part| part.len() > 4300) {
            return Err("int scalar exceeds Python's 4300-digit limit".to_owned());
        }
        Ok(Node::Other("int"))
    } else if TIMESTAMP_RESOLVE.is_match(&value) {
        if !timestamp_is_valid(&value) {
            return Err("invalid timestamp scalar".to_owned());
        }
        Ok(Node::Other("timestamp"))
    } else if value == "<<" {
        Err("merge keys are not supported (PLAN.md D-6)".to_owned())
    } else if value == "=" {
        Err("the YAML 1.1 value type `=` cannot be constructed".to_owned())
    } else {
        Ok(Node::Str(value))
    }
}

/// Whether Python's `datetime.date`/`datetime`/`timezone` accept the fields.
fn timestamp_is_valid(value: &str) -> bool {
    let Some(caps) = TIMESTAMP_PARTS.captures(value) else {
        return false;
    };
    let num = |i: usize| {
        caps.get(i)
            .map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(u32::MAX))
    };
    let (year, month, day) = (num(1), num(2), num(3));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    let date_ok = (1..=9999).contains(&year) && (1..=days).contains(&day);
    let time_ok = num(4) <= 23 && num(5) <= 59 && num(6) <= 59;
    // `timezone(timedelta(hours=h, minutes=m))` needs |offset| < 24 h.
    let tz_ok = num(8) * 60 + num(9) < 24 * 60;
    date_ok && time_ok && tz_ok
}

fn is_str_tag(tag: &Tag) -> bool {
    format!("{}{}", tag.handle, tag.suffix) == "tag:yaml.org,2002:str"
}

/// Characters PyYAML's reader accepts, minus the YAML 1.1 line breaks NEL,
/// LS and PS that the YAML 1.2 parser would read differently, and minus TAB,
/// whose rules differ between the two parsers (D-6). Errors give positions
/// only: the text may be a secret.
fn check_characters(text: &str) -> Result<(), String> {
    for (index, c) in text.char_indices() {
        let printable = matches!(c,
            '\n' | '\r' | '\x20'..='\x7e' | '\u{a0}'..='\u{2027}'
            | '\u{202a}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..);
        if !printable || (c == '\u{feff}' && index > 0) {
            return Err(format!(
                "unsupported character at byte {index} (PLAN.md D-6)"
            ));
        }
    }
    Ok(())
}

/// PyYAML refuses a document that defines the same anchor twice; directives
/// (`%YAML`, `%TAG`) are refused because the parsers accept different ones.
fn check_tokens(text: &str) -> Result<(), String> {
    let mut seen = HashSet::new();
    for token in Scanner::new(text.chars()) {
        match token.1 {
            TokenType::Anchor(name) => {
                if !seen.insert(name) {
                    return Err("duplicate anchor".to_owned());
                }
            }
            TokenType::VersionDirective(..) | TokenType::TagDirective(..) => {
                return Err("YAML directives are not supported (PLAN.md D-6)".to_owned());
            }
            _ => {}
        }
    }
    Ok(())
}

enum Frame {
    Seq(usize, Vec<Rc<Node>>),
    /// Anchor, entries, and the key waiting for its value.
    Map(
        usize,
        Vec<(Option<String>, Rc<Node>)>,
        Option<Option<String>>,
    ),
}

/// Parse one document. Line endings are normalised first, as Python's
/// `Path.read_text` does; a leading BOM is skipped, as PyYAML's scanner does.
pub fn parse(text: &str) -> Result<Rc<Node>, String> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    check_characters(text)?;
    check_tokens(text)?;

    let mut parser = Parser::new_from_str(text);
    let mut anchors: HashMap<usize, Rc<Node>> = HashMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut documents = 0;
    let mut root: Option<Rc<Node>> = None;
    loop {
        let (event, mark) = parser.next_token().map_err(|e| {
            let at = e.marker();
            format!(
                "not valid YAML at line {} column {}",
                at.line(),
                at.col() + 1
            )
        })?;
        let (node, anchor) = match event {
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err("expected a single document".to_owned());
                }
                continue;
            }
            Event::SequenceStart(anchor, ref tag) | Event::MappingStart(anchor, ref tag) => {
                if tag.is_some() {
                    return Err(format!("unsupported tag at line {}", mark.line()));
                }
                if stack.len() >= MAX_DEPTH {
                    return Err("nesting too deep".to_owned());
                }
                stack.push(if matches!(event, Event::SequenceStart(..)) {
                    Frame::Seq(anchor, Vec::new())
                } else {
                    Frame::Map(anchor, Vec::new(), None)
                });
                continue;
            }
            Event::SequenceEnd | Event::MappingEnd => match stack.pop() {
                Some(Frame::Seq(anchor, items)) => (Rc::new(Node::Seq(items)), anchor),
                Some(Frame::Map(anchor, entries, None)) => (Rc::new(Node::Map(entries)), anchor),
                _ => return Err("unbalanced YAML events".to_owned()),
            },
            Event::Scalar(value, style, anchor, tag) => {
                // An empty implicit key (`{: x}`) is an error in PyYAML.
                let is_key = matches!(stack.last(), Some(Frame::Map(_, _, None)));
                if is_key && value.is_empty() && style == TScalarStyle::Plain && tag.is_none() {
                    return Err(format!("empty mapping key at line {}", mark.line()));
                }
                let node = match tag {
                    Some(tag) if is_str_tag(&tag) => Node::Str(value),
                    Some(_) => return Err(format!("unsupported tag at line {}", mark.line())),
                    None if style == TScalarStyle::Plain => resolve_plain(value)?,
                    None => Node::Str(value),
                };
                (Rc::new(node), anchor)
            }
            Event::Alias(id) => match anchors.get(&id) {
                Some(node) => (Rc::clone(node), 0),
                // The anchored node is still open: a recursive structure.
                None => return Err("alias to an unfinished node".to_owned()),
            },
            _ => continue,
        };
        if anchor != 0 {
            anchors.insert(anchor, Rc::clone(&node));
        }
        match stack.last_mut() {
            None => root = Some(node),
            Some(Frame::Seq(_, items)) => items.push(node),
            Some(Frame::Map(_, entries, pending)) => match pending.take() {
                Some(key) => entries.push((key, node)),
                None => {
                    *pending = Some(match node.as_ref() {
                        Node::Str(key) => Some(key.clone()),
                        Node::Null | Node::Other(_) => None,
                        // PyYAML: "found unhashable key".
                        Node::Seq(_) | Node::Map(_) => {
                            return Err("collection used as a mapping key".to_owned());
                        }
                    });
                }
            },
        }
    }
    Ok(root.unwrap_or_else(|| Rc::new(Node::Null)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(value: &str) -> Node {
        resolve_plain(value.to_owned()).unwrap()
    }

    #[test]
    fn plain_scalars_follow_yaml_1_1() {
        for value in [
            "yes",
            "On",
            "0777",
            "1_000",
            "0x1F",
            "1:20",
            "1.5",
            ".inf",
            "2026-10-15",
        ] {
            assert!(matches!(plain(value), Node::Other(_)), "{value}");
        }
        for value in ["~", "null", ""] {
            assert_eq!(plain(value), Node::Null);
        }
        for value in ["y", "n", "abc", "0xZ", "1-2", "2026-1-5", "08"] {
            assert_eq!(plain(value), Node::Str(value.to_owned()), "{value}");
        }
        for value in [
            "0b_",
            "0x_",
            "2026-02-29",
            "2026-13-01",
            "0000-01-01",
            "<<",
            "=",
        ] {
            assert!(resolve_plain(value.to_owned()).is_err(), "{value}");
        }
        assert!(timestamp_is_valid("2024-02-29 23:59:59.5 +23:59"));
        assert!(!timestamp_is_valid("2024-02-29 24:00:00"));
        assert!(!timestamp_is_valid("2024-02-29T10:00:00-24:00"));
    }

    #[test]
    fn documents() {
        let doc = parse("a: &x [1, 'b']\nb: *x\na: !!str yes\n").unwrap();
        assert!(
            parse(&format!(
                "a: {}\nb: 0{}\n",
                "1".repeat(4300),
                "7".repeat(5000)
            ))
            .is_ok()
        );
        assert_eq!(doc.get("a"), Some(&Node::Str("yes".to_owned())));
        assert!(matches!(doc.get("b"), Some(Node::Seq(items)) if items.len() == 2));
        assert_eq!(*parse("").unwrap(), Node::Null);
        for bad in [
            "a: 1\n---\nb: 2\n",
            "a: &x 1\nb: &x 2\n",
            "a: &x [*x]\n",
            "a: !!int 1\n",
            "? [a]\n: b\n",
            "a: \"\u{85}\"\n",
            "a: \x01\n",
            "<<: {a: 1}\n",
            "a: \tb\n",
            "a: {: x}\n",
            "%YAML 1.1\n---\na: 1\n",
            &format!("a: {}\n", "1".repeat(4301)),
            &format!("a: {}:30\n", "1".repeat(4301)),
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse(&"[".repeat(MAX_DEPTH + 1)).is_err());
    }
}
