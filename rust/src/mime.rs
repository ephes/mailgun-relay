//! Message construction (PLAN.md 2.3 step 9 and 2.10; `relay:mime_build.py`
//! `build_message`).
//!
//! The pipeline hands over the validated form fields ([`MessageInput`]) and
//! gets back the message bytes and the SMTP envelope ([`BuiltMessage`]), or
//! [`InvalidMessage`] (always 400). Every step-9 check lives here: the empty body
//! (D-1), the `to`/`cc`/`bcc` and Reply-To addresses (EAI local parts are
//! refused by [`crate::address`], Q2), a To/Cc/Reply-To display name that
//! decodes to CR/LF (D-16), and the inline filenames.
//!
//! lettre builds the MIME tree, the transfer encodings and the parameter
//! encodings; this module decides what goes into each header. Python's header
//! registry parses every header value it is given, decoding RFC 2047 encoded
//! words, and re-encodes the result. Where a value is printable ASCII this
//! module writes it as received (display names quoted the way Python's
//! `Address.__str__` quotes them), so a receiver's parser decodes exactly
//! what Python's decoded. Other values are written as RFC 2047 encoded words
//! of their text. A value that needs encoding and also holds an encoded word
//! is refused (D-21), because encoding it would turn the encoded word into
//! literal text where Python decodes it.

use std::collections::HashSet;
use std::fmt::{self, Write as _};

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use email_encoding::headers::rfc2047;
use email_encoding::headers::writer::EmailWriter;
use lettre::message::header::{
    self, ContentTransferEncoding, ContentType, Header, HeaderName, HeaderValue, Headers,
};
use lettre::message::{
    Attachment as LettreAttachment, Body, MultiPart, MultiPartBuilder, SinglePart,
};

use crate::address::{Mailbox, parse_mailbox, parse_mailbox_list};
use crate::pystr::py_strip;

/// An uploaded `attachment` or `inline` file. The pipeline applies the
/// defaults of Python's form layer (`relay:routes.py` `_read_upload`): an
/// empty filename becomes `attachment`, an empty content type
/// `application/octet-stream`; the content type may still be malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// The validated request (PLAN.md 2.3 steps 4–8 done).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageInput {
    /// The mailbox [`crate::policy::enforce_policy`] returned.
    pub from: Mailbox,
    /// Raw `to`/`cc`/`bcc` values in form order, parsed here (step 9).
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    /// Stripped and validated (step 6).
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub amp_html: Option<String>,
    /// Validated `h:*` headers (step 7): names without `h:`, in map order.
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<Attachment>,
    pub inline: Vec<Attachment>,
    /// `PUBLIC_HOST`, the domain of the Message-Id.
    pub public_host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltMessage {
    /// `<32 hex@PUBLIC_HOST>` (Python: `uuid4().hex`), the Message-Id
    /// header and the response `id`.
    pub message_id: String,
    /// `RCPT TO` addresses: to, cc, bcc, de-duplicated by exact string,
    /// first occurrence kept; ASCII (A-label domains).
    pub envelope: Vec<String>,
    /// The message: CRLF line endings, 7-bit, lines ≤ 998 octets.
    pub formatted: Vec<u8>,
}

/// Every step-9 failure is a 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessage;

/// Build the message (`build_message` in `relay:mime_build.py`). Bcc
/// recipients go into the envelope only, never into a header.
pub fn build(input: MessageInput) -> Result<BuiltMessage, InvalidMessage> {
    let text = input.text.filter(|t| !t.is_empty());
    let html = input.html.filter(|h| !h.is_empty());
    let amp_html = input.amp_html.filter(|a| !a.is_empty());
    if text.is_none() && html.is_none() {
        // D-1: an empty `text` (Anymail's empty Django body) without html.
        return Err(InvalidMessage);
    }

    let to = parse_recipients(&input.to)?;
    let cc = parse_recipients(&input.cc)?;
    let bcc = parse_recipients(&input.bcc)?;
    if input
        .to
        .iter()
        .chain(&input.cc)
        .any(|v| may_decode_to_line_break(v))
    {
        // D-16: Python's header registry refuses such a display name.
        return Err(InvalidMessage);
    }

    let mut headers = Headers::new();
    headers.insert_raw(address_header("From", std::slice::from_ref(&input.from))?);
    if !to.is_empty() {
        headers.insert_raw(address_header("To", &to)?);
    }
    if !cc.is_empty() {
        headers.insert_raw(address_header("Cc", &cc)?);
    }
    headers.insert_raw(unstructured_header("Subject", &input.subject)?);
    let message_id = format!("<{}@{}>", crate::pipeline::random_hex(), input.public_host);
    headers.set(header::MessageId::from(message_id.clone()));
    headers.set(header::Date::now());
    headers.set(header::MIME_VERSION_1_0);
    let mut head = headers.to_string();
    // `Headers` holds one header per name; `h:X-A` and `h:x-a` are two
    // headers in Python, so the custom headers are rendered one by one.
    head.push_str(&custom_headers(&input.headers)?);

    let tree = body_tree(text, html, amp_html, input.inline, input.attachments)?;
    let body = tree.formatted();
    let mut formatted = Vec::with_capacity(head.len() + body.len());
    formatted.extend_from_slice(head.as_bytes());
    formatted.extend_from_slice(&body);

    let mut seen = HashSet::new();
    let envelope = to
        .iter()
        .chain(&cc)
        .chain(&bcc)
        .map(Mailbox::addr_spec)
        .filter(|addr| seen.insert(addr.clone()))
        .collect();
    Ok(BuiltMessage {
        message_id,
        envelope,
        formatted,
    })
}

fn parse_recipients(values: &[String]) -> Result<Vec<Mailbox>, InvalidMessage> {
    values
        .iter()
        .map(|v| parse_mailbox(v).map_err(|_| InvalidMessage))
        .collect()
}

// ------------------------------------------------------------------ headers

/// RFC 5322 line limit without CRLF.
const MAX_LINE: usize = 998;

/// Room an address and its brackets and separator may take on a line.
const ADDRESS_ROOM: usize = 260;

/// `email.headerregistry.Address.__str__` quotes a display name holding one
/// of these.
const SPECIALS: &str = "()<>@,:;.\"[]\\";

/// Whether `value` can be written as received: printable ASCII or TAB, and
/// every run of spaces plus the following word fits a line after a
/// `reserve`-byte prefix.
fn is_plain(value: &str, reserve: usize) -> bool {
    if !value
        .bytes()
        .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
    {
        return false;
    }
    let mut run = 0;
    let mut in_word = false;
    for b in value.bytes() {
        if b == b' ' && in_word {
            run = 0;
            in_word = false;
        }
        in_word |= b != b' ';
        run += 1;
        if reserve + run > MAX_LINE {
            return false;
        }
    }
    true
}

/// One `=?charset?cte?text?=` with a `q`/`b` cte: the shape Python's
/// `get_encoded_word` decodes, found wherever it occurs (a superset of the
/// words Python decodes in a given position).
struct EncodedWord<'a> {
    /// Byte range of the whole word in the value.
    start: usize,
    end: usize,
    charset: &'a str,
    base64: bool,
    text: &'a str,
}

fn encoded_words(value: &str) -> Vec<EncodedWord<'_>> {
    let bytes = value.as_bytes();
    let marks: Vec<usize> = (0..bytes.len()).filter(|&i| bytes[i] == b'?').collect();
    let mut words = Vec::new();
    for (k, &q0) in marks.iter().enumerate() {
        if q0 == 0 || bytes[q0 - 1] != b'=' {
            continue;
        }
        let (Some(&q1), Some(&q2), Some(&q3)) =
            (marks.get(k + 1), marks.get(k + 2), marks.get(k + 3))
        else {
            break;
        };
        if bytes.get(q3 + 1) != Some(&b'=') {
            continue;
        }
        let base64 = match &value[q1 + 1..q2] {
            "b" | "B" => true,
            "q" | "Q" => false,
            _ => continue,
        };
        words.push(EncodedWord {
            start: q0 - 1,
            end: q3 + 2,
            charset: &value[q0 + 1..q1],
            base64,
            text: &value[q2 + 1..q3],
        });
    }
    words
}

/// The charset of an encoded word, without an RFC 2231 language, normalised
/// like Python's `encodings.normalize_encoding`.
fn charset_name(charset: &str) -> String {
    charset
        .split('*')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Charsets whose decoders keep ASCII bytes as they are (CR and LF only
/// from 0x0D and 0x0A, `=?` only from `=?`, space and TAB only from 0x20
/// and 0x09), so the decoded bytes tell what Python's codec yields.
fn is_ascii_compatible_charset(name: &str) -> bool {
    let numbered = |prefix: &str, low: u32, high: u32| {
        name.strip_prefix(prefix).is_some_and(|suffix| {
            suffix
                .parse::<u32>()
                .is_ok_and(|n| (low..=high).contains(&n) && n.to_string() == suffix)
        })
    };
    matches!(
        name,
        "utf_8" | "utf8" | "us_ascii" | "ascii" | "latin_1" | "latin1" | "l1"
    ) || numbered("iso_8859_", 1, 16)
        || numbered("iso8859_", 1, 16)
        || numbered("windows_", 1250, 1258)
        || numbered("cp", 1250, 1258)
}

/// The bytes of an encoded word in an ASCII-compatible charset; `None` for
/// another charset or base64 text Python would have to repair.
fn decode_word(word: &EncodedWord<'_>) -> Option<Vec<u8>> {
    if !is_ascii_compatible_charset(&charset_name(word.charset)) {
        return None;
    }
    if !word.base64 {
        return Some(decode_q(word.text));
    }
    let engine = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    engine.decode(word.text.trim_end_matches('=')).ok()
}

/// Whether Python could decode an encoded word in `value` to CR or LF
/// (D-16). Fail closed: an encoded word [`decode_word`] cannot read counts
/// as a line break.
fn may_decode_to_line_break(value: &str) -> bool {
    encoded_words(value).iter().any(|word| {
        decode_word(word).is_none_or(|bytes| bytes.contains(&b'\r') || bytes.contains(&b'\n'))
    })
}

/// RFC 2047's limit for one encoded word.
const MAX_ENCODED_WORD: usize = 75;

/// A printable value as it can be forwarded: a receiver's parser must read
/// its encoded words as Python's registry did after its own re-encoding.
/// Refused (D-21): an encoded word [`decode_word`] cannot read, one whose
/// text holds `=?` (Python writes that text raw, so it is decoded twice) or
/// starts or ends with whitespace (Python's output drops or collapses it).
/// In a display name (`phrase`) also one whose text is ASCII and holds a
/// special such as `,` (Python writes that text raw and its parser reads a
/// different address list). An encoded word longer than RFC 2047 allows is
/// split into words of whole characters when whitespace delimits it outside
/// a quoted string, and refused otherwise.
fn forwardable(value: &str, phrase: bool, quoted: bool) -> Result<String, InvalidMessage> {
    let refused = || InvalidMessage;
    let mut out = String::with_capacity(value.len());
    let mut copied = 0;
    for word in encoded_words(value) {
        let bytes = decode_word(&word).ok_or_else(refused)?;
        let blank = |b: Option<&u8>| matches!(b, Some(b' ' | b'\t'));
        let special = |b: &u8| SPECIALS.as_bytes().contains(b);
        if bytes.windows(2).any(|w| w == b"=?")
            || blank(bytes.first())
            || blank(bytes.last())
            || (phrase && bytes.is_ascii() && bytes.iter().any(special))
        {
            return Err(refused());
        }
        if word.end - word.start <= MAX_ENCODED_WORD {
            continue;
        }
        let delimited = (word.start == 0 || value[..word.start].ends_with([' ', '\t']))
            && (word.end == value.len() || value[word.end..].starts_with([' ', '\t']));
        if quoted || !delimited || word.start < copied {
            return Err(refused());
        }
        out.push_str(&value[copied..word.start]);
        out.push_str(&split_word(word.charset, &bytes).ok_or_else(refused)?);
        copied = word.end;
    }
    out.push_str(&value[copied..]);
    Ok(out)
}

/// `bytes` as base64 encoded words of at most [`MAX_ENCODED_WORD`]
/// characters in `charset`, split on UTF-8 character boundaries.
fn split_word(charset: &str, bytes: &[u8]) -> Option<String> {
    let room = (MAX_ENCODED_WORD.checked_sub(charset.len() + "=???b?=".len())? / 4) * 3;
    let utf8 = matches!(charset_name(charset).as_str(), "utf_8" | "utf8");
    let text = if utf8 {
        Some(std::str::from_utf8(bytes).ok()?)
    } else {
        None
    };
    let mut words = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let mut cut = rest.len().min(room);
        if let Some(text) = text {
            let offset = bytes.len() - rest.len();
            while cut > 0 && !text.is_char_boundary(offset + cut) {
                cut -= 1;
            }
        }
        if cut == 0 {
            return None;
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(&rest[..cut]);
        words.push(format!("=?{charset}?b?{encoded}?="));
        rest = &rest[cut..];
    }
    Some(words.join(" "))
}

/// Python's `_encoded_words.decode_q`: `_` is a space, `=XX` a byte.
fn decode_q(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
            .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
        match (bytes[i], hex) {
            (b'=', Some(byte)) => {
                out.push(byte);
                i += 3;
                continue;
            }
            (b'_', _) => out.push(b' '),
            (byte, _) => out.push(byte),
        }
        i += 1;
    }
    out
}

/// Run `write` against a header writer positioned after `Name: `.
fn render(
    name: &str,
    write: impl FnOnce(&mut EmailWriter<'_>) -> Result<(), InvalidMessage>,
) -> Result<String, InvalidMessage> {
    let mut encoded = String::new();
    {
        let mut w = EmailWriter::new(&mut encoded, name.len() + 2, 0, false);
        write(&mut w)?;
    }
    Ok(encoded)
}

/// Writing to a `String` cannot fail.
fn infallible(result: fmt::Result) {
    result.expect("writing a header to a String");
}

/// From, To, Cc, Reply-To: `Name <addr>` or `addr` per mailbox. A plain
/// display name is written as Python's `str(Address)` writes it; any other
/// one as encoded words of the text Python's parser would read from that
/// form (quoted: exact; unquoted: whitespace runs collapsed, ends stripped).
fn address_header(
    name: &'static str,
    mailboxes: &[Mailbox],
) -> Result<HeaderValue, InvalidMessage> {
    let encoded = render(name, |w| {
        for (i, mailbox) in mailboxes.iter().enumerate() {
            if i > 0 {
                infallible(w.write_char(','));
                w.space();
            }
            write_mailbox(w, name.len() + 2, mailbox)?;
        }
        Ok(())
    })?;
    let raw = mailboxes
        .iter()
        .map(Mailbox::addr_spec)
        .collect::<Vec<_>>()
        .join(", ");
    Ok(HeaderValue::dangerous_new_pre_encoded(
        HeaderName::new_from_ascii_str(name),
        raw,
        encoded,
    ))
}

fn write_mailbox(
    w: &mut EmailWriter<'_>,
    prefix: usize,
    mailbox: &Mailbox,
) -> Result<(), InvalidMessage> {
    if !encoded_words(&mailbox.local).is_empty() {
        // Python decodes it in the header, not in the envelope (D-21).
        return Err(InvalidMessage);
    }
    let display = mailbox.display_name.as_str();
    let addr = mailbox.addr_spec();
    if display.is_empty() {
        infallible(w.folding().write_str(&addr));
        return Ok(());
    }
    let quoted = display.chars().any(|c| SPECIALS.contains(c));
    let quote = |text: &str| {
        if quoted {
            format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
        } else {
            text.to_owned()
        }
    };
    if is_plain(&quote(display), prefix + ADDRESS_ROOM) {
        let shown = quote(&forwardable(display, true, quoted)?);
        infallible(w.folding().write_str(&shown));
    } else if !encoded_words(display).is_empty() {
        return Err(InvalidMessage);
    } else if quoted {
        infallible(rfc2047::encode(display, w));
    } else {
        let words: Vec<&str> = display
            .split([' ', '\t'])
            .filter(|s| !s.is_empty())
            .collect();
        infallible(rfc2047::encode(&words.join(" "), w));
    }
    w.space();
    infallible(w.write_char('<'));
    infallible(w.write_str(&addr));
    infallible(w.write_char('>'));
    Ok(())
}

/// Subject and the unstructured `h:*` headers. Leading whitespace is
/// dropped from encoded values, as a parser drops it after the colon.
fn unstructured_header(name: &str, value: &str) -> Result<HeaderValue, InvalidMessage> {
    let header_name = HeaderName::new_from_ascii(name.to_owned()).map_err(|_| InvalidMessage)?;
    if is_plain(value, name.len() + 2) {
        return Ok(HeaderValue::new(
            header_name,
            forwardable(value, false, false)?,
        ));
    }
    if !encoded_words(value).is_empty() {
        return Err(InvalidMessage);
    }
    let encoded = render(name, |w| {
        infallible(rfc2047::encode(value.trim_start_matches([' ', '\t']), w));
        Ok(())
    })?;
    Ok(HeaderValue::dangerous_new_pre_encoded(
        header_name,
        value.to_owned(),
        encoded,
    ))
}

/// The `h:*` headers in map order. Reply-To is an address list; Python's
/// registry allows Reply-To, In-Reply-To and References once, so two case
/// variants of one of them are a 400. In-Reply-To and References must be
/// lists of plain message ids: Python refuses a value that decodes to
/// non-ASCII (it cannot write it without SMTPUTF8) and repairs a malformed
/// list; Rust refuses anything but [`is_message_id_list`] (D-21).
/// `h:Orig-Date` is refused (D-21): Python rewrites a parseable date and
/// empties any other value.
fn custom_headers(headers: &[(String, String)]) -> Result<String, InvalidMessage> {
    let mut out = String::new();
    let mut unique = HashSet::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "orig-date" {
            return Err(InvalidMessage);
        }
        if matches!(lower.as_str(), "reply-to" | "in-reply-to" | "references")
            && !unique.insert(lower.clone())
        {
            return Err(InvalidMessage);
        }
        let message_ids = matches!(lower.as_str(), "in-reply-to" | "references");
        if message_ids && (!is_message_id_list(value) || !encoded_words(value).is_empty()) {
            return Err(InvalidMessage);
        }
        let rendered = if lower == "reply-to" {
            let list = parse_mailbox_list(value).map_err(|_| InvalidMessage)?;
            if may_decode_to_line_break(value) {
                return Err(InvalidMessage);
            }
            address_header("Reply-To", &list)?
        } else {
            unstructured_header(name, value)?
        };
        let mut one = Headers::new();
        one.insert_raw(rendered);
        out.push_str(&one.to_string());
    }
    Ok(out)
}

/// `<left@right>` ids separated by spaces or TABs, both sides RFC 5322
/// dot-atom text: the form Python's registry passes on unchanged.
fn is_message_id_list(value: &str) -> bool {
    let dot_atom = |s: &str| {
        s.split('.').all(|atom| {
            !atom.is_empty()
                && atom
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c))
        })
    };
    let mut ids = value
        .split([' ', '\t'])
        .filter(|s| !s.is_empty())
        .peekable();
    ids.peek().is_some()
        && ids.all(|id| {
            id.strip_prefix('<')
                .and_then(|id| id.strip_suffix('>'))
                .and_then(|id| id.split_once('@'))
                .is_some_and(|(left, right)| dot_atom(left) && dot_atom(right))
        })
}

// --------------------------------------------------------------------- body

/// The MIME tree before lettre renders it.
enum Tree {
    Leaf(SinglePart),
    Alternative(Vec<Tree>),
    Related(Vec<Tree>),
    Mixed(Vec<Tree>),
}

impl Tree {
    fn formatted(self) -> Vec<u8> {
        match self {
            Tree::Leaf(part) => {
                // lettre ends a part with the CRLF that belongs to the next
                // boundary; in a single-part message it would be an extra
                // line of the body.
                let mut bytes = part.formatted();
                if bytes.ends_with(b"\r\n\r\n") {
                    bytes.truncate(bytes.len() - 2);
                }
                bytes
            }
            multi => multi.into_multipart().formatted(),
        }
    }

    fn into_multipart(self) -> MultiPart {
        let (builder, children): (MultiPartBuilder, _) = match self {
            Tree::Alternative(c) => (MultiPart::alternative(), c),
            Tree::Related(c) => (MultiPart::related(), c),
            Tree::Mixed(c) => (MultiPart::mixed(), c),
            Tree::Leaf(part) => return MultiPart::mixed().singlepart(part),
        };
        children
            .into_iter()
            .fold(builder.build(), |multi, child| match child {
                Tree::Leaf(part) => multi.singlepart(part),
                tree => multi.multipart(tree.into_multipart()),
            })
    }
}

/// Python's structure: text and html as `multipart/alternative` (amp-html
/// last); inline parts with the html part in `multipart/related`, or in the
/// top-level `multipart/mixed` without html; attachments after them in
/// `multipart/mixed`.
fn body_tree(
    text: Option<String>,
    html: Option<String>,
    amp_html: Option<String>,
    inline: Vec<Attachment>,
    attachments: Vec<Attachment>,
) -> Result<Tree, InvalidMessage> {
    let has_html = html.is_some();
    let mut inline_parts = inline
        .into_iter()
        .map(|upload| upload_part(upload, true))
        .collect::<Result<Vec<_>, _>>()?;
    let mut alternatives = Vec::new();
    if let Some(text) = text {
        alternatives.push(Tree::Leaf(text_part(ContentType::TEXT_PLAIN, &text)));
    }
    if let Some(html) = html {
        let part = Tree::Leaf(text_part(ContentType::TEXT_HTML, &html));
        alternatives.push(if inline_parts.is_empty() {
            part
        } else {
            let mut related = vec![part];
            related.append(&mut inline_parts);
            Tree::Related(related)
        });
    }
    if let Some(amp) = amp_html {
        let amp_type =
            ContentType::parse("text/x-amp-html; charset=utf-8").expect("static content type");
        alternatives.push(Tree::Leaf(text_part(amp_type, &amp)));
    }
    let mut tree = if alternatives.len() == 1 {
        alternatives.remove(0)
    } else {
        Tree::Alternative(alternatives)
    };
    if !has_html && !inline_parts.is_empty() {
        let mut mixed = vec![tree];
        mixed.append(&mut inline_parts);
        tree = Tree::Mixed(mixed);
    }
    if !attachments.is_empty() {
        let mut mixed = match tree {
            Tree::Mixed(parts) => parts,
            other => vec![other],
        };
        for upload in attachments {
            mixed.push(upload_part(upload, false)?);
        }
        tree = Tree::Mixed(mixed);
    }
    Ok(tree)
}

/// A text body as Python's `set_content` stores it: CRLF, CR and LF
/// (`bytes.splitlines`) become CRLF and the text ends with one. Control
/// characters other than TAB force base64, so a 7-bit body never carries
/// them raw.
fn text_part(content_type: ContentType, text: &str) -> SinglePart {
    let mut lines = String::with_capacity(text.len() + 2);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                chars.next_if_eq(&'\n');
                lines.push_str("\r\n");
            }
            '\n' => lines.push_str("\r\n"),
            c => lines.push(c),
        }
    }
    if !lines.ends_with("\r\n") {
        lines.push_str("\r\n");
    }
    let controls = lines
        .chars()
        .any(|c| c.is_ascii_control() && !matches!(c, '\t' | '\r' | '\n'));
    let body = if controls {
        base64_body(lines.into_bytes())
    } else {
        Body::new(lines)
    };
    SinglePart::builder().header(content_type).body(body)
}

fn base64_body(data: Vec<u8>) -> Body {
    Body::new_with_encoding(data, ContentTransferEncoding::Base64).unwrap_or_else(Body::new)
}

/// The Content-ID of an inline part, rendered like an unstructured header:
/// lettre's own `ContentId` writes a long value on one line.
#[derive(Clone)]
struct ContentId(HeaderValue);

impl Header for ContentId {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("Content-ID")
    }

    fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self(HeaderValue::new(Self::name(), s.to_owned())))
    }

    fn display(&self) -> HeaderValue {
        self.0.clone()
    }
}

/// Line boundaries of Python's `str.splitlines`: a header value holding one
/// is refused by the email package (400). An attachment filename with any
/// non-ASCII character is written RFC 2231-encoded and passes whatever it
/// holds; an inline filename is also the Content-ID, which is never encoded.
fn has_line_boundary(value: &str, inline: bool) -> bool {
    (inline || value.is_ascii())
        && value.chars().any(|c| {
            matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e')
                || (inline && matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}'))
        })
}

/// An attachment or inline part: base64, the content type reduced to
/// `main/sub`, Python's filename checks.
fn upload_part(upload: Attachment, inline: bool) -> Result<Tree, InvalidMessage> {
    let filename = upload.filename;
    if has_line_boundary(&filename, inline) {
        return Err(InvalidMessage);
    }
    let content_type = leaf_content_type(&upload.content_type);
    let body = base64_body(upload.data);
    let part = if inline {
        // `_content_id`: the filename is the Content-ID, used as-is.
        let malformed = py_strip(&filename) != filename
            || filename
                .chars()
                .any(|c| c == '<' || c == '>' || c < ' ' || c == '\x7f');
        if malformed {
            return Err(InvalidMessage);
        }
        let content_id = unstructured_header("Content-ID", &format!("<{filename}>"))?;
        SinglePart::builder()
            .header(ContentId(content_id))
            .header(header::ContentDisposition::inline_with_name(&filename))
            .header(content_type)
            .body(body)
    } else {
        LettreAttachment::new(filename).body(body, content_type)
    };
    Ok(Tree::Leaf(part))
}

/// `_split_ct`: `main/sub`, lowercased, parameters dropped. Containers
/// (`multipart/*`, `message/*`) and empty parts become
/// `application/octet-stream`, and so do types that are not two RFC 7230
/// tokens of at most 127 characters (RFC 6838), which Python would pass on
/// raw (D-21).
fn leaf_content_type(raw: &str) -> ContentType {
    let octet_stream =
        || ContentType::parse("application/octet-stream").expect("static content type");
    let (main, rest) = raw.split_once('/').unwrap_or((raw, ""));
    let main = py_strip(main).to_lowercase();
    let sub = py_strip(rest.split(';').next().unwrap_or_default()).to_lowercase();
    let token = |s: &str| {
        !s.is_empty()
            && s.len() <= 127
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
    };
    if !token(&main) || !token(&sub) || main == "multipart" || main == "message" {
        return octet_stream();
    }
    ContentType::parse(&format!("{main}/{sub}")).unwrap_or_else(|_| octet_stream())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use mail_parser::{
        HeaderName as ParsedName, HeaderValue as Parsed, MessageParser, MessagePart, MimeHeaders,
        PartType,
    };
    use serde_json::{Value, json};

    use super::*;

    const HOST: &str = "relay.example.test";

    fn strings(value: &Value) -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect()
    }

    /// Uploads with the pipeline's defaults (`pipeline::read_upload`).
    fn uploads(value: &Value) -> Vec<Attachment> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|u| Attachment {
                filename: Some(u["filename"].as_str().unwrap())
                    .filter(|f| !f.is_empty())
                    .unwrap_or("attachment")
                    .to_owned(),
                content_type: Some(u["content_type"].as_str().unwrap())
                    .filter(|t| !t.is_empty())
                    .unwrap_or("application/octet-stream")
                    .to_owned(),
                data: STANDARD.decode(u["data"].as_str().unwrap()).unwrap(),
            })
            .collect()
    }

    fn input(case: &Value) -> MessageInput {
        let text = |key: &str| case[key].as_str().map(str::to_owned);
        MessageInput {
            from: parse_mailbox(case["from"].as_str().unwrap()).unwrap(),
            to: strings(&case["to"]),
            cc: strings(&case["cc"]),
            bcc: strings(&case["bcc"]),
            subject: case["subject"].as_str().unwrap().to_owned(),
            text: text("text"),
            html: text("html"),
            amp_html: text("amp_html"),
            headers: case["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    (
                        h[0].as_str().unwrap().to_owned(),
                        h[1].as_str().unwrap().to_owned(),
                    )
                })
                .collect(),
            attachments: uploads(&case["attachments"]),
            inline: uploads(&case["inline"]),
            public_host: HOST.to_owned(),
        }
    }

    fn base(overrides: Value) -> MessageInput {
        let mut case = json!({
            "from": "Alice <alice@example.test>", "to": ["bob@example.test"], "cc": [],
            "bcc": [], "subject": "hi", "text": "hello", "html": null, "amp_html": null,
            "headers": [], "attachments": [], "inline": [],
        });
        for (key, value) in overrides.as_object().unwrap() {
            case[key] = value.clone();
        }
        input(&case)
    }

    /// The RFC conformance of 2.10: ASCII, CRLF only, lines ≤ 998 octets,
    /// no Bcc header, the Message-Id is the response id, a Date.
    fn assert_conformant(built: &BuiltMessage) -> String {
        let text = String::from_utf8(built.formatted.clone()).unwrap();
        assert!(text.is_ascii(), "{text}");
        assert!(text.ends_with("\r\n"));
        for line in text.split("\r\n") {
            assert!(!line.contains(['\r', '\n']), "bare CR or LF: {line:?}");
            assert!(line.len() <= MAX_LINE, "line of {} octets", line.len());
        }
        let head = &text[..text.find("\r\n\r\n").unwrap() + 2];
        assert!(!head.to_ascii_lowercase().contains("\r\nbcc:") && !head.starts_with("Bcc"));
        assert!(head.contains(&format!("\r\nMessage-ID: {}\r\n", built.message_id)));
        assert!(head.contains("\r\nDate: "));
        text
    }

    fn header_text(value: &Parsed<'_>) -> Value {
        match value {
            Parsed::Address(address) => Value::Array(
                address
                    .iter()
                    .map(|a| {
                        json!([
                            a.name.as_deref().unwrap_or_default(),
                            a.address.as_deref().unwrap_or_default()
                        ])
                    })
                    .collect(),
            ),
            Parsed::Text(text) => json!(text),
            Parsed::TextList(list) => json!(list.join(" ")),
            Parsed::Empty => json!(""),
            other => json!(format!("{other:?}")),
        }
    }

    /// The semantic view of `generate.py` `semantic_message`, read with
    /// mail-parser: addresses and MIME headers parsed, every other header
    /// (Content-ID included) as decoded text. Unstructured values are
    /// compared trimmed; `check_mime.py` compares exactly with Python's
    /// parser.
    fn semantic(bytes: &[u8]) -> Value {
        let message = MessageParser::new()
            .with_mime_headers()
            .with_address_headers()
            .header_text(ParsedName::ContentId)
            .default_header_text()
            .parse(bytes)
            .unwrap();
        let root = &message.parts[0];
        let mut headers = Vec::new();
        for header in &root.headers {
            let name = header.name.as_str().to_ascii_lowercase();
            if [
                "message-id",
                "date",
                "mime-version",
                "content-type",
                "content-transfer-encoding",
            ]
            .contains(&name.as_str())
            {
                continue;
            }
            headers.push(json!([name, header_text(&header.value)]));
        }
        headers.sort_by_key(|h| h.to_string());
        json!({"headers": headers, "body": node(&message.parts, root)})
    }

    fn node(parts: &[MessagePart<'_>], part: &MessagePart<'_>) -> Value {
        let content_type = part.content_type().map_or("text/plain".to_owned(), |ct| {
            format!(
                "{}/{}",
                ct.c_type,
                ct.c_subtype.as_deref().unwrap_or_default()
            )
            .to_lowercase()
        });
        let mut node = json!({"type": content_type});
        if let PartType::Multipart(children) = &part.body {
            node["parts"] = children.iter().map(|&i| node_of(parts, i)).collect();
            return node;
        }
        let disposition = part.content_disposition().map(|d| d.c_type.to_lowercase());
        if let Some(disposition) = &disposition {
            node["disposition"] = json!(disposition);
            node["filename"] = json!(part.attachment_name());
        }
        if let Some(id) = part.content_id() {
            node["content_id"] = json!(id.trim());
        }
        if content_type.starts_with("text/") && disposition.is_none() {
            node["charset"] = json!(part.content_type().and_then(|ct| ct.attribute("charset")));
            let text = part.text_contents().unwrap().replace("\r\n", "\n");
            node["text"] = json!(text.strip_suffix('\n').unwrap_or(&text));
        } else {
            node["data"] = json!(STANDARD.encode(part.contents()));
        }
        node
    }

    fn node_of(parts: &[MessagePart<'_>], id: u32) -> Value {
        node(parts, &parts[id as usize])
    }

    /// What the mail-parser comparison leaves to `check_mime.py`: the ends
    /// of unstructured values and whitespace runs in display names (Python
    /// collapses them in an unquoted phrase, mail-parser does not). A From
    /// Python's registry cannot parse (CR/LF in the display name) is stored
    /// as `["unparsable", "<name> <addr>"]`.
    fn trimmed(mut message: Value) -> Value {
        let collapse = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        for header in message["headers"].as_array_mut().unwrap() {
            if let Some(text) = header[1].as_str() {
                header[1] = json!(text.trim());
                continue;
            }
            if header[1][0] == "unparsable" {
                let text = header[1][1].as_str().unwrap();
                let (name, addr) = text.rsplit_once(" <").unwrap();
                header[1] = json!([[name, addr.trim_end_matches('>')]]);
            }
            for mailbox in header[1].as_array_mut().unwrap() {
                mailbox[0] = json!(collapse(mailbox[0].as_str().unwrap()));
            }
        }
        message
    }

    /// Every case of `fixtures/mime.json`: status, envelope, RFC
    /// conformance, and the semantic view against Python's. With
    /// `MIME_FIXTURE_DUMP=<dir>` the messages are written there for
    /// `fixtures/check_mime.py`.
    #[test]
    fn mime_fixture() {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/mime.json")).unwrap();
        let dump = std::env::var_os("MIME_FIXTURE_DUMP").map(std::path::PathBuf::from);
        let mut mismatches = Vec::new();
        for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
            let name = case["name"].as_str().unwrap();
            let expected = &case["expected"];
            let result = build(input(&case["input"]));
            if expected["status"] == 400 {
                if result.is_ok() {
                    mismatches.push(format!("{name}: built, expected 400"));
                }
                continue;
            }
            let built = match result {
                Ok(built) => built,
                Err(e) => {
                    mismatches.push(format!("{name}: {e:?}"));
                    continue;
                }
            };
            assert_conformant(&built);
            if let Some(dir) = &dump {
                std::fs::write(dir.join(format!("{index}.eml")), &built.formatted).unwrap();
            }
            if json!(built.envelope) != expected["envelope"] {
                mismatches.push(format!("{name}: envelope {:?}", built.envelope));
            }
            // mail-parser reads an encoded word in a local part differently
            // from Python's parser; check_mime.py covers that case.
            if name == "encoded local part" {
                continue;
            }
            let actual = trimmed(semantic(&built.formatted));
            let wanted = trimmed(expected["message"].clone());
            if actual != wanted {
                mismatches.push(format!("{name}:\n  rust   {actual}\n  python {wanted}"));
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    fn parse(built: &BuiltMessage) -> mail_parser::Message<'_> {
        MessageParser::default()
            .parse(&built.formatted[..])
            .unwrap()
    }

    fn content_types(message: &mail_parser::Message<'_>) -> Vec<String> {
        message
            .parts
            .iter()
            .map(|p| {
                let ct = p.content_type().unwrap();
                format!(
                    "{}/{}",
                    ct.c_type,
                    ct.c_subtype.as_deref().unwrap_or_default()
                )
            })
            .collect()
    }

    fn png(name: &str) -> Value {
        json!({"filename": name, "content_type": "image/png", "data": STANDARD.encode(b"\x89PNG\r\n")})
    }

    fn build_with(overrides: Value) -> Result<BuiltMessage, InvalidMessage> {
        build(base(overrides))
    }

    /// The counterparts of `tests/test_mime_build.py`.
    #[test]
    fn python_mime_build_tests() {
        let built = build_with(json!({})).unwrap();
        let text = assert_conformant(&built);
        assert_eq!(built.envelope, ["bob@example.test"]);
        assert!(text.starts_with("From: Alice <alice@example.test>\r\n"));
        assert!(text.contains("\r\nTo: bob@example.test\r\n"));
        let message = parse(&built);
        assert_eq!(content_types(&message), ["text/plain"]);
        assert_eq!(message.body_text(0).unwrap().trim_end(), "hello");

        let html_only = build_with(json!({"text": null, "html": "<p>hi</p>"})).unwrap();
        assert_eq!(content_types(&parse(&html_only)), ["text/html"]);
        let both = build_with(json!({"html": "<p>hi</p>"})).unwrap();
        assert_eq!(
            content_types(&parse(&both)),
            ["multipart/alternative", "text/plain", "text/html"]
        );

        let cc = build_with(json!({"to": ["a@example.test"], "cc": ["c@example.test"]})).unwrap();
        assert!(String::from_utf8_lossy(&cc.formatted).contains("\r\nCc: c@example.test\r\n"));
        assert_eq!(cc.envelope, ["a@example.test", "c@example.test"]);

        let bcc = build_with(json!({
            "to": ["a@example.test"], "bcc": ["secret@example.test", "secret2@example.test"],
        }))
        .unwrap();
        assert!(!String::from_utf8_lossy(&bcc.formatted).contains("secret"));
        assert_eq!(
            bcc.envelope,
            [
                "a@example.test",
                "secret@example.test",
                "secret2@example.test"
            ]
        );

        let reply = build_with(json!({"headers": [["Reply-To", "ops@example.test"]]})).unwrap();
        assert!(
            String::from_utf8_lossy(&reply.formatted)
                .contains("\r\nReply-To: ops@example.test\r\n")
        );

        let attached = build_with(json!({"attachments": [
            {"filename": "hello.txt", "content_type": "text/plain",
             "data": STANDARD.encode(b"hello attachment")},
        ]}))
        .unwrap();
        let message = parse(&attached);
        let part = message.attachment(0).unwrap();
        assert_eq!(part.attachment_name(), Some("hello.txt"));
        assert_eq!(part.contents(), b"hello attachment");

        let podcast =
            build_with(json!({"from": "Python Podcast <noreply@mg.python-podcast.de>"})).unwrap();
        assert!(
            String::from_utf8_lossy(&podcast.formatted)
                .contains("From: Python Podcast <noreply@mg.python-podcast.de>\r\n")
        );

        // Inline parts: bracketed Content-ID, related with html, mixed without.
        let inline = build_with(json!({
            "html": "<img src=\"cid:logo.png\">", "inline": [png("logo.png")],
            "attachments": [{"filename": "a.pdf", "content_type": "application/pdf",
                             "data": STANDARD.encode(b"%PDF")}],
        }))
        .unwrap();
        assert!(
            String::from_utf8_lossy(&inline.formatted).contains("\r\nContent-ID: <logo.png>\r\n")
        );
        assert_eq!(
            content_types(&parse(&inline)),
            [
                "multipart/mixed",
                "multipart/alternative",
                "text/plain",
                "multipart/related",
                "text/html",
                "image/png",
                "application/pdf"
            ]
        );
        let related_root =
            build_with(json!({"text": null, "html": "<img>", "inline": [png("logo.png")]}));
        assert_eq!(
            content_types(&parse(&related_root.unwrap())),
            ["multipart/related", "text/html", "image/png"]
        );
        let amp = build_with(json!({
            "html": "<p>x</p>", "amp_html": "<html amp4email></html>", "inline": [png("logo.png")],
        }));
        assert_eq!(
            content_types(&parse(&amp.unwrap())),
            [
                "multipart/alternative",
                "text/plain",
                "multipart/related",
                "text/html",
                "image/png",
                "text/x-amp-html"
            ]
        );
        let text_only = build_with(json!({"inline": [png("logo.png")]}));
        assert_eq!(
            content_types(&parse(&text_only.unwrap())),
            ["multipart/mixed", "text/plain", "image/png"]
        );
        for name in [
            "a\r\nb.png",
            "<logo.png>",
            "<logo.png",
            "logo.png>",
            "\tlogo.png",
            " logo.png",
            "a\x7f.png",
        ] {
            assert!(
                build_with(json!({"html": "<p>x</p>", "inline": [png(name)]})).is_err(),
                "{name:?}"
            );
        }
        for container in ["multipart/mixed", "message/rfc822", "Multipart/Related"] {
            let built = build_with(json!({"attachments": [
                {"filename": "a.bin", "content_type": container, "data": STANDARD.encode(b"payload")},
            ]}))
            .unwrap();
            let message = parse(&built);
            assert_eq!(
                content_types(&message),
                ["multipart/mixed", "text/plain", "application/octet-stream"]
            );
            assert_eq!(message.attachment(0).unwrap().contents(), b"payload");
        }

        // D-1 and D-16 (Q1), Q2.
        for bodies in [
            json!({"text": ""}),
            json!({"text": null, "html": ""}),
            json!({"text": "", "html": ""}),
            json!({"text": "", "amp_html": "a"}),
        ] {
            assert!(build_with(bodies).is_err());
        }
        let html = build_with(json!({"text": "", "html": "<p>hi</p>"})).unwrap();
        assert_eq!(content_types(&parse(&html)), ["text/html"]);
        for field in ["to", "cc"] {
            let crlf = json!({ field: ["=?utf-8?B?YQ0KYg==?= <x@example.test>"] });
            assert!(build_with(crlf).is_err(), "{field}");
        }
        let idn = build_with(json!({
            "from": "Jörg <sender@wersdörfer.de>", "to": ["to@wersdörfer.de"],
            "cc": ["Cc <cc@bü.test>"], "bcc": ["bcc@wersdörfer.de"],
            "headers": [["Reply-To", "reply@wersdörfer.de"]],
        }))
        .unwrap();
        let text = assert_conformant(&idn);
        assert!(text.contains("<sender@xn--wersdrfer-47a.de>\r\n"));
        assert!(text.contains("\r\nTo: to@xn--wersdrfer-47a.de\r\n"));
        assert!(text.contains("\r\nCc: Cc <cc@xn--b-eha.test>\r\n"));
        assert!(text.contains("\r\nReply-To: reply@xn--wersdrfer-47a.de\r\n"));
        assert_eq!(
            idn.envelope,
            [
                "to@xn--wersdrfer-47a.de",
                "cc@xn--b-eha.test",
                "bcc@xn--wersdrfer-47a.de"
            ]
        );
        for field in [
            json!({"to": ["jörg@example.test"]}),
            json!({"cc": ["jörg@example.test"]}),
            json!({"bcc": ["jörg@example.test"]}),
            json!({"headers": [["Reply-To", "jörg@example.test"]]}),
        ] {
            assert!(build_with(field).is_err());
        }
    }

    #[test]
    fn message_id_is_32_hex_digits_at_the_public_host() {
        let id = build_with(json!({})).unwrap().message_id;
        let hex = id
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix(&format!("@{HOST}>")))
            .unwrap();
        assert_eq!(hex.len(), 32);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(id, build_with(json!({})).unwrap().message_id);
    }

    #[test]
    fn line_break_detection_fails_closed() {
        for value in [
            "=?utf-8?B?YQ0KYg==?= <a@x.de>",
            "=?UTF-8?b?YQ0KYg?= <a@x.de>",
            "=?utf-8?q?a=0Db?= <a@x.de>",
            "=?utf-8?q?=0A?= <a@x.de>",
            "=?iso-8859-1*de?Q?a=0Ab?= <a@x.de>",
            "\"x =?utf-8?B?YQ0KYg==?=\" <a@x.de>",
            "a=?utf-8?B?YQ0KYg==?=b <a@x.de>",
            "=?utf-7?q?+AA0-?= <a@x.de>",
            "=?utf-16?b?DQA=?= <a@x.de>",
            "=?utf-8?b?YQ0*?= <a@x.de>",
            "=?utf-8?b?Y?= <a@x.de>",
        ] {
            assert!(may_decode_to_line_break(value), "{value:?}");
        }
        for value in [
            "=?utf-8?q?J=C3=B6rg?= <a@x.de>",
            "=?utf-8?B?SsO2cmc=?= <a@x.de>",
            "=?windows-1252?q?J=F6rg?= <a@x.de>",
            "=?utf-8?x?YQ0KYg==?= <a@x.de>",
            "=?utf-8?q?=+A?= <a@x.de>",
            "=?utf-8?B?YQ0KYg== <a@x.de>",
            "1+1=? (a?b?c) <a@x.de>",
            "a@x.de",
        ] {
            assert!(!may_decode_to_line_break(value), "{value:?}");
        }
    }

    #[test]
    fn upload_content_types() {
        let main_sub = |raw: &str| {
            let mut headers = Headers::new();
            headers.set(leaf_content_type(raw));
            headers.get_raw("Content-Type").unwrap().to_owned()
        };
        assert_eq!(main_sub("IMAGE/PNG"), "image/png");
        assert_eq!(main_sub("image/png; name=a"), "image/png");
        assert_eq!(main_sub(" text/plain ;charset=x"), "text/plain");
        assert_eq!(main_sub("image/svg+xml"), "image/svg+xml");
        for broken in [
            "",
            "image",
            "image/",
            "/png",
            "a b/c",
            "image/png/x",
            "tä/x",
            "multipart/mixed",
            "message/rfc822",
        ] {
            assert_eq!(main_sub(broken), "application/octet-stream", "{broken:?}");
        }
    }

    /// Lines stay within 998 octets for long values in every header kind,
    /// and a 1 MiB binary attachment is base64.
    #[test]
    fn long_values_stay_conformant() {
        let word = "y".repeat(2000);
        let built = build_with(json!({
            "from": format!("{word} <a@x.de>"),
            "to": [format!("\"{word}\" <b@x.de>"), format!("Jörg{word} <c@x.de>")],
            "subject": format!("a {word} b"),
            "headers": [["X-Long", format!(" {word}")], ["Reply-To", format!("{word} <r@x.de>")]],
            "attachments": [{"filename": "big.bin", "content_type": "application/octet-stream",
                             "data": STANDARD.encode(vec![0u8; 1 << 20])}],
        }))
        .unwrap();
        assert_conformant(&built);
        let message = parse(&built);
        assert_eq!(message.attachment(0).unwrap().contents().len(), 1 << 20);
        assert_eq!(message.subject(), Some(format!("a {word} b").as_str()));
    }

    /// Display names are written as Python's `str(Address)` writes them
    /// (S2 open point 4): quoted when they hold a special, comments kept.
    #[test]
    fn display_names_are_quoted_like_python() {
        let built = build_with(json!({"to": [
            "Jane (c) <a@x.de>", "(c) <b@x.de>", "a@x.de (Kommentar)", "\"Doe, Jane\" <d@x.de>",
            "\"a\\\\b\" <s@x.de>", "=?utf-8?q?J=C3=B6rg?= <j@x.de>", "Jörg <k@x.de>",
        ]}))
        .unwrap();
        let text = assert_conformant(&built);
        let to = &text[text.find("\r\nTo: ").unwrap() + 6..];
        let to = to[..to.find("\r\nSubject").unwrap()].replace("\r\n", "");
        assert_eq!(
            to,
            "\"Jane (c)\" <a@x.de>, \" (c)\" <b@x.de>, Kommentar <a@x.de>, \"Doe, Jane\" \
             <d@x.de>, \"a\\\\b\" <s@x.de>, =?utf-8?q?J=C3=B6rg?= <j@x.de>, =?utf-8?b?SsO2cmc=?= \
             <k@x.de>"
        );
    }

    /// The Rust-stricter refusals of D-21 and the message-id headers.
    #[test]
    fn exotic_headers() {
        let refused = [
            json!({"headers": [["Orig-Date", "Mon, 1 Jan 2024 10:00:00 +0000"]]}),
            json!({"headers": [[format!("X-{}", "a".repeat(80)), "v"]]}),
            json!({"subject": "Grüße =?utf-8?q?J=C3=B6rg?="}),
            json!({"headers": [["X-Mixed", "Grüße =?utf-8?q?J=C3=B6rg?="]]}),
            json!({"to": ["Jörg =?utf-8?q?J=C3=B6rg?= <b@x.de>"]}),
            json!({"from": "Jörg =?utf-8?q?J=C3=B6rg?= <b@x.de>"}),
            json!({"to": ["=?bogus?q?abc?= <b@x.de>"]}),
            json!({"headers": [["References", "<jörg@x.test>"]]}),
            json!({"headers": [["In-Reply-To", "=?utf-8?q?abc?="]]}),
            json!({"headers": [["In-Reply-To", "<a@b"]]}),
            json!({"headers": [["References", "<a@b>,<c@d>"]]}),
            json!({"headers": [["References", "<a..b@c>"]]}),
            json!({"headers": [["References", "garbage"]]}),
            json!({"to": ["=?utf-8?q?Doe=2C_Jane?= <bob@example.test>"]}),
            json!({"from": "=?utf-8?q?a_=28c=29?= <a@x.de>"}),
            json!({"headers": [["Reply-To", "=?utf-8?q?a=3Cb?= <r@x.de>"]]}),
            json!({"headers": [["In-Reply-To", "<a@b>"], ["in-reply-to", "<c@d>"]]}),
            json!({"headers": [["Reply-To", "a@x.de"], ["reply-to", "b@x.de"]]}),
            json!({"headers": [["Reply-To", "=?utf-8?B?YQ0KYg==?= <r@x.de>"]]}),
            json!({"from": "=?bogus?q?abc?= <a@x.de>"}),
            json!({"subject": "=?utf-8?q?=3D=3Futf-8=3Fq=3Fhello=3F=3D?="}),
            json!({"subject": "=?utf-8?q?_a?="}),
            json!({"to": ["=?utf-8?q?a_?= <b@x.de>"]}),
            json!({"headers": [["X-A", "=?utf-8?b?YQ*?="]]}),
            json!({"to": ["=?utf-8?q?J=C3=B6rg?=@x.de"]}),
            json!({"subject": format!("x=?utf-8?q?{}?=", "a".repeat(80))}),
            json!({"to": [format!("\"x. =?utf-8?q?{}?=\" <b@x.de>", "a".repeat(80))]}),
            json!({"attachments": [{"filename": "a\nb.txt", "content_type": "", "data": ""}]}),
            json!({"attachments": [{"filename": "a\x0cb.txt", "content_type": "", "data": ""}]}),
            json!({"html": "<p>x</p>", "inline": [png("a\u{2028}b.png")]}),
            json!({"html": "<p>x</p>", "inline": [png("a\u{85}b.png")]}),
        ];
        for overrides in refused {
            assert!(build_with(overrides.clone()).is_err(), "{overrides}");
        }
        let built = build_with(json!({
            "subject": "=?utf-8?B?YQ0KYg==?=",
            "to": ["=?utf-8?q?Doe=2C_J=C3=B6rg?= <bob@example.test>"],
            "headers": [["X-A", "one"], ["x-a", "two"], ["References", " <a@b>  <c.d@e.f>"],
                        ["X-Umlaut", " Grüße "]],
        }))
        .unwrap();
        let text = assert_conformant(&built);
        assert!(text.contains("\r\nSubject: =?utf-8?B?YQ0KYg==?=\r\n"));
        let filename = build_with(json!({"attachments": [
            {"filename": "é\x0cb.txt", "content_type": "", "data": ""},
        ]}))
        .unwrap();
        let message = parse(&filename);
        assert_eq!(
            message.attachment(0).unwrap().attachment_name(),
            Some("é\x0cb.txt")
        );
        assert!(text.contains("\r\nX-A: one\r\nx-a: two\r\nReferences:  <a@b>  <c.d@e.f>\r\n"));
        let to = parse(&built)
            .to()
            .unwrap()
            .first()
            .unwrap()
            .name()
            .map(str::to_owned);
        assert_eq!(to.as_deref(), Some("Doe, Jörg"));
        assert!(text.contains("\r\nX-Umlaut: =?utf-8?b?R3LDvMOfZSA=?=\r\n"));
    }

    /// An encoded word longer than RFC 2047 allows (Anymail writes a long
    /// non-ASCII display name as one) is split on character boundaries; a
    /// long inline filename or content type stays within the line limit.
    #[test]
    fn long_encoded_words_and_upload_headers() {
        let name = "Benachrichtigungen für Jörg Müller aus Köln";
        let word = format!("=?utf-8?b?{}?=", STANDARD.encode(name));
        let long = "y".repeat(1100);
        let built = build_with(json!({
            "from": format!("{word} <a@x.de>"),
            "subject": format!("Re: {word}"),
            "html": "<p>x</p>",
            "inline": [png(&format!("{long}.png"))],
            "attachments": [{"filename": "a.bin", "content_type": format!("image/{long}"),
                             "data": STANDARD.encode(b"x")}],
        }))
        .unwrap();
        let text = assert_conformant(&built);
        for (start, _) in text.match_indices("=?utf-8?b?") {
            let end = start + 10 + text[start + 10..].find("?=").unwrap() + 2;
            assert!(end - start <= MAX_ENCODED_WORD, "{}", &text[start..end]);
        }
        let message = parse(&built);
        assert_eq!(message.from().unwrap().first().unwrap().name(), Some(name));
        assert_eq!(message.subject(), Some(format!("Re: {name}").as_str()));
        assert_eq!(
            content_types(&message),
            [
                "multipart/mixed",
                "multipart/alternative",
                "text/plain",
                "multipart/related",
                "text/html",
                "image/png",
                "application/octet-stream"
            ]
        );
    }
}
