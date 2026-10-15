//! Request body parsing (PLAN.md 2.3 step 3): Starlette's `request.form()`
//! as `relay:routes.py` calls it, over the buffered body.
//!
//! Both encodings are parsed by this module, not by a crate, because the
//! decisions must not widen what Python accepts: the urlencoded decoding is
//! Starlette's (latin-1, then `unquote_plus`), and the multipart framing is
//! the one of python-multipart 0.0.31 (strict start boundary, token header
//! names, at most 8 headers of 4224 bytes per part, a delimiter followed by
//! anything but CRLF or `--` is data, a truncated body ends the form and
//! drops the unfinished part). Pinned by `fixtures/form_decoding.json`.

use crate::pystr::{is_py_space, py_strip};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormError {
    /// 400: malformed body (Starlette's `MultiPartException` and parser
    /// errors without a limit marker).
    BadRequest,
    /// 413: one of Starlette's limits (too many files or fields, a part too
    /// large).
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    /// As sent (decoded with the request charset); may be empty.
    pub filename: String,
    /// The part's first `Content-Type` header, decoded as latin-1.
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    File(Upload),
}

/// The parser limits as the route passes them: `max_files`
/// (`max_attachments + 1`), `max_fields` (`max_recipients + 100`) and
/// `max_part_size` (`max_body_bytes`).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_files: i64,
    pub max_fields: i64,
    pub max_part_size: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Utf8,
    Latin1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encoding {
    Urlencoded,
    Multipart {
        boundary: Vec<u8>,
        charset: Charset,
    },
    /// Any other content type: an empty form, the body is not read.
    None,
}

/// python-multipart's `MAX_BOUNDARY_LENGTH`, `DEFAULT_MAX_HEADER_COUNT`
/// and `DEFAULT_MAX_HEADER_SIZE`.
const MAX_BOUNDARY_LENGTH: usize = 256;
const MAX_HEADER_COUNT: usize = 8;
const MAX_HEADER_SIZE: usize = 4096 + 128;

/// One char per byte, as Starlette decodes header values.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// The bytes of a string whose chars all come from [`latin1`].
fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(c).unwrap_or(b'?'))
        .collect()
}

/// Decide from the request's first `Content-Type` header (raw bytes) how
/// the body is parsed, before it is read: Starlette `_get_form` and the
/// preamble of `MultiPartParser.parse`.
pub fn encoding(content_type: Option<&[u8]>) -> Result<Encoding, FormError> {
    let header = content_type.map(latin1);
    let (essence, params) = options_header(header.as_deref());
    match essence.as_str() {
        "application/x-www-form-urlencoded" => Ok(Encoding::Urlencoded),
        "multipart/form-data" => {
            let charset = match param(&params, "charset") {
                None => Charset::Utf8,
                Some(name) => charset(name).ok_or(FormError::BadRequest)?,
            };
            let boundary = latin1_bytes(param(&params, "boundary").ok_or(FormError::BadRequest)?);
            if boundary.len() > MAX_BOUNDARY_LENGTH {
                return Err(FormError::BadRequest);
            }
            Ok(Encoding::Multipart { boundary, charset })
        }
        _ => Ok(Encoding::None),
    }
}

/// The request charsets Python decodes and Rust implements (D-9): UTF-8
/// and latin-1 spellings, and ASCII, which with Python's per-item latin-1
/// fallback decodes like latin-1. Every other name is refused.
fn charset(name: &str) -> Option<Charset> {
    match name.to_ascii_lowercase().as_str() {
        "utf-8" | "utf8" | "utf_8" => Some(Charset::Utf8),
        "latin-1" | "latin1" | "iso-8859-1" | "iso8859-1" | "iso_8859_1" | "l1" | "ascii"
        | "us-ascii" => Some(Charset::Latin1),
        _ => None,
    }
}

/// Starlette `_user_safe_decode`: the charset, latin-1 on a decoding error.
fn decode(bytes: &[u8], charset: Charset) -> String {
    match charset {
        Charset::Utf8 => String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| latin1(bytes)),
        Charset::Latin1 => latin1(bytes),
    }
}

/// Parse the buffered body into the ordered form items.
pub fn parse(
    encoding: &Encoding,
    body: &[u8],
    limits: Limits,
) -> Result<Vec<(String, Value)>, FormError> {
    match encoding {
        Encoding::Urlencoded => urlencoded(body, limits),
        Encoding::Multipart { boundary, charset } => multipart(body, boundary, *charset, limits),
        Encoding::None => Ok(Vec::new()),
    }
}

fn exceeds(len: usize, max: i64) -> bool {
    i64::try_from(len).map_or(true, |len| len > max)
}

/// Starlette `FormParser` over python-multipart's `QuerystringParser`
/// (not strict): `&`-separated fields, empty ones skipped, the name up to
/// the first `=`; each name and value decoded with
/// `unquote_plus(bytes.decode("latin-1"))`.
fn urlencoded(body: &[u8], limits: Limits) -> Result<Vec<(String, Value)>, FormError> {
    let mut items = Vec::new();
    for field in body.split(|&b| b == b'&').filter(|f| !f.is_empty()) {
        let (name, value) = match field.iter().position(|&b| b == b'=') {
            Some(eq) => (&field[..eq], &field[eq + 1..]),
            None => (field, &field[field.len()..]),
        };
        // The size callbacks only run for non-empty data.
        if (!name.is_empty() && exceeds(name.len(), limits.max_part_size))
            || (!value.is_empty() && exceeds(name.len() + value.len(), limits.max_part_size))
        {
            return Err(FormError::TooLarge);
        }
        if exceeds(items.len() + 1, limits.max_fields) {
            return Err(FormError::TooLarge);
        }
        items.push((
            unquote_plus(&latin1(name)),
            Value::Text(unquote_plus(&latin1(value))),
        ));
    }
    Ok(items)
}

/// `urllib.parse.unquote_plus` with UTF-8 and `errors="replace"`: `+` is a
/// space; only runs of ASCII characters are percent-decoded, a valid `%XX`
/// sequence becomes a byte, anything else stays literal.
pub fn unquote_plus(text: &str) -> String {
    let text = text.replace('+', " ");
    if !text.contains('%') {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let ascii = rest.find(|c: char| !c.is_ascii()).unwrap_or(rest.len());
        out.push_str(&String::from_utf8_lossy(&unquote_to_bytes(&rest[..ascii])));
        rest = &rest[ascii..];
        let other = rest.find(|c: char| c.is_ascii()).unwrap_or(rest.len());
        out.push_str(&rest[..other]);
        rest = &rest[other..];
    }
    out
}

fn unquote_to_bytes(ascii: &str) -> Vec<u8> {
    let mut bits = ascii.as_bytes().split(|&b| b == b'%');
    let mut out = bits.next().unwrap_or_default().to_vec();
    for bit in bits {
        let hex = |i: usize| bit.get(i).and_then(|&b| char::from(b).to_digit(16));
        match (hex(0), hex(1)) {
            (Some(high), Some(low)) => {
                out.push((high << 4 | low) as u8);
                out.extend_from_slice(&bit[2..]);
            }
            _ => {
                out.push(b'%');
                out.extend_from_slice(bit);
            }
        }
    }
    out
}

/// python-multipart `parse_options_header` on a latin-1 decoded header:
/// the lowercased value when it has no `;`, else the first `_parseparam`
/// segment as is (not lowercased) and the parameters (keys lowercased, a
/// key containing `*` skipped, one level of quotes removed, the IE6 path of
/// a `filename` cut to its last component).
fn options_header(value: Option<&str>) -> (String, Vec<(String, String)>) {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return (String::new(), Vec::new());
    };
    if !value.contains(';') {
        return (py_strip(&value.to_lowercase()).to_owned(), Vec::new());
    }
    let mut segments = parseparam(value).into_iter();
    let essence = segments.next().unwrap_or_default();
    let mut params = Vec::new();
    for segment in segments {
        let (key, value) = segment.split_once('=').unwrap_or((&segment, ""));
        if key.contains('*') {
            continue;
        }
        let chars: Vec<char> = value.chars().collect();
        let mut value = value.to_owned();
        if chars.len() >= 2 && chars[0] == '"' && chars[chars.len() - 1] == '"' {
            value = chars[1..chars.len() - 1]
                .iter()
                .collect::<String>()
                .replace("\\\\", "\\")
                .replace("\\\"", "\"");
        }
        let chars: Vec<char> = value.chars().collect();
        if key == "filename" && (chars.get(1..3) == Some(&[':', '\\']) || value.starts_with("\\\\"))
        {
            value = value.rsplit('\\').next().unwrap_or_default().to_owned();
        }
        params.push((key.to_owned(), value));
    }
    (essence, params)
}

/// A parameter as Python's dict holds it: the last one wins.
fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// `_parseparam` (vendored from `email.message`), reproduced step by step
/// with Python's index semantics: split at `;` outside double quotes.
fn parseparam(text: &str) -> Vec<String> {
    let s: Vec<char> = std::iter::once(';').chain(text.chars()).collect();
    let n = s.len() as isize;
    let clamp = |i: isize| -> usize { (if i < 0 { (i + n).max(0) } else { i.min(n) }) as usize };
    let find = |c: char, start: isize, end: isize| -> isize {
        let (a, b) = (clamp(start), clamp(end));
        if a > b {
            return -1;
        }
        s[a..b]
            .iter()
            .position(|&x| x == c)
            .map_or(-1, |p| (a + p) as isize)
    };
    let count = |pattern: &[char], start: isize, end: isize| -> isize {
        let (a, b) = (clamp(start), clamp(end));
        let mut total = 0;
        let mut i = a;
        while i + pattern.len() <= b {
            if s[i..i + pattern.len()] == *pattern {
                total += 1;
                i += pattern.len();
            } else {
                i += 1;
            }
        }
        total
    };
    let mut plist = Vec::new();
    let mut start: isize = 0;
    while find(';', start, n) == start {
        start += 1;
        let mut end = find(';', start, n);
        let (mut ind, mut diff) = (start, 0isize);
        while end > 0 {
            diff += count(&['"'], ind, end) - count(&['\\', '"'], ind, end);
            if diff.rem_euclid(2) == 0 {
                break;
            }
            let next = find(';', end + 1, n);
            (end, ind) = (ind, next);
        }
        if end < 0 {
            end = n;
        }
        let segment =
            |a: isize, b: isize| -> String { s[clamp(a)..clamp(b).max(clamp(a))].iter().collect() };
        let i = find('=', start, end);
        let f = if i == -1 {
            segment(start, end)
        } else {
            let key = segment(start, i);
            let value = segment(i + 1, end);
            format!(
                "{}={}",
                key.trim_end_matches(is_py_space).to_lowercase(),
                value.trim_start_matches(is_py_space)
            )
        };
        plist.push(py_strip(&f).to_owned());
        start = end;
    }
    plist
}

fn find_byte(body: &[u8], byte: u8, from: usize) -> Option<usize> {
    body.get(from..)?
        .iter()
        .position(|&b| b == byte)
        .map(|p| from + p)
}

fn find_seq(body: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    body.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// RFC 7230 token characters, python-multipart's `TOKEN_CHARS`.
fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Starlette `MultiPartParser` over python-multipart's `MultipartParser`,
/// fed the whole body at once. A body that ends early is not an error: the
/// parts completed so far are the form.
fn multipart(
    body: &[u8],
    boundary: &[u8],
    charset: Charset,
    limits: Limits,
) -> Result<Vec<(String, Value)>, FormError> {
    use FormError::{BadRequest, TooLarge};
    let delimiter = [b"\r\n--".as_slice(), boundary].concat();
    let mut items = Vec::new();
    let (mut files, mut fields) = (0usize, 0usize);

    // Leading CR and LF are skipped. python-multipart skips from a leading
    // CR or LF to the next '-' *within the chunk it was given*, so other
    // bytes there pass or fail depending on where the chunks end; they are
    // refused here (D-20). Then "--boundary", followed by CRLF (first part)
    // or "--" (an empty form).
    let mut i = body
        .iter()
        .position(|&b| b != b'\r' && b != b'\n')
        .unwrap_or(body.len());
    if i > 0 && i < body.len() && body[i] != b'-' {
        return Err(BadRequest);
    }
    for &expected in &delimiter[2..] {
        match body.get(i) {
            None => return Ok(items),
            Some(&b) if b == expected => i += 1,
            Some(_) => return Err(BadRequest),
        }
    }
    match (body.get(i), body.get(i + 1)) {
        (None, _) | (Some(b'-' | b'\r'), None) => return Ok(items),
        (Some(b'-'), Some(b'-')) => return Ok(items),
        (Some(b'\r'), Some(b'\n')) => i += 2,
        _ => return Err(BadRequest),
    }

    loop {
        // Part headers: Starlette keeps the last Content-Disposition; the
        // upload's content type is the first Content-Type.
        let mut disposition: Option<&[u8]> = None;
        let mut content_type: Option<&[u8]> = None;
        let mut count = 0;
        loop {
            match (body.get(i), body.get(i + 1)) {
                (None, _) | (Some(b'\r'), None) => return Ok(items),
                (Some(b'\r'), Some(b'\n')) => {
                    i += 2;
                    break;
                }
                (Some(b'\r'), Some(_)) => return Err(BadRequest),
                _ => {}
            }
            count += 1;
            if count > MAX_HEADER_COUNT {
                return Err(BadRequest);
            }
            let colon = find_byte(body, b':', i);
            let end = colon.unwrap_or(body.len());
            let mut size = end - i + usize::from(colon.is_some());
            let name = &body[i..end];
            if size > MAX_HEADER_SIZE || !name.iter().all(|&b| is_token(b)) {
                return Err(BadRequest);
            }
            let Some(colon) = colon else {
                return Ok(items);
            };
            if name.is_empty() {
                return Err(BadRequest);
            }
            i = colon + 1;
            while body.get(i) == Some(&b' ') {
                size += 1;
                i += 1;
                if size > MAX_HEADER_SIZE {
                    return Err(BadRequest);
                }
            }
            let cr = find_byte(body, b'\r', i);
            size += cr.unwrap_or(body.len()) - i;
            if size > MAX_HEADER_SIZE {
                return Err(BadRequest);
            }
            let Some(cr) = cr else {
                return Ok(items);
            };
            let value = &body[i..cr];
            if name.eq_ignore_ascii_case(b"content-disposition") {
                disposition = Some(value);
            } else if name.eq_ignore_ascii_case(b"content-type") && content_type.is_none() {
                content_type = Some(value);
            }
            match body.get(cr + 1) {
                None => return Ok(items),
                Some(b'\n') => i = cr + 2,
                Some(_) => return Err(BadRequest),
            }
        }

        // Headers finished: the name is required, then the file or field
        // count is checked.
        let header = disposition.map(latin1);
        let (_, params) = options_header(header.as_deref());
        let name = decode(
            &latin1_bytes(param(&params, "name").ok_or(BadRequest)?),
            charset,
        );
        let filename = param(&params, "filename").map(|f| decode(&latin1_bytes(f), charset));
        if filename.is_some() {
            files += 1;
            if exceeds(files, limits.max_files) {
                return Err(TooLarge);
            }
        } else {
            fields += 1;
            if exceeds(fields, limits.max_fields) {
                return Err(TooLarge);
            }
        }

        // Part data up to a delimiter followed by CRLF or "--"; any other
        // continuation is data.
        let start = i;
        let mut search = i;
        let (end, last) = loop {
            let Some(at) = find_seq(body, &delimiter, search) else {
                return Ok(items);
            };
            let after = at + delimiter.len();
            match (body.get(after), body.get(after + 1)) {
                (None, _) | (Some(b'\r' | b'-'), None) => return Ok(items),
                (Some(b'\r'), Some(b'\n')) => break (at, false),
                (Some(b'-'), Some(b'-')) => break (at, true),
                (Some(b'\r' | b'-'), Some(_)) => search = after + 1,
                _ => search = after,
            }
        };
        let data = &body[start..end];
        let value = match filename {
            Some(filename) => Value::File(Upload {
                filename,
                content_type: content_type.map(latin1),
                data: data.to_vec(),
            }),
            None => {
                if !data.is_empty() && exceeds(data.len(), limits.max_part_size) {
                    return Err(TooLarge);
                }
                Value::Text(decode(data, charset))
            }
        };
        items.push((name, value));
        if last {
            return Ok(items);
        }
        i = end + delimiter.len() + 2;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value as Json, json};

    use super::*;

    const LIMITS: Limits = Limits {
        max_files: 4,
        max_fields: 110,
        max_part_size: 1 << 20,
    };

    fn multipart_body(boundary: &str, parts: &[(&str, &str)]) -> Vec<u8> {
        let mut body = String::new();
        for (headers, data) in parts {
            body.push_str(&format!("--{boundary}\r\n{headers}\r\n\r\n{data}\r\n"));
        }
        body.push_str(&format!("--{boundary}--\r\n"));
        body.into_bytes()
    }

    fn texts(items: &[(String, Value)]) -> Vec<(&str, &str)> {
        items
            .iter()
            .map(|(name, value)| match value {
                Value::Text(text) => (name.as_str(), text.as_str()),
                Value::File(upload) => (name.as_str(), upload.filename.as_str()),
            })
            .collect()
    }

    /// The production shapes: Anymail urlencoded, the recorder's multipart.
    #[test]
    fn production_shapes() {
        let body = b"from=Homepage+%3Cjochen-homepage%40wersdoerfer.de%3E&to=a%40b.de\
                     &subject=%5BDjango%5D+Fehler+%C3%BC&text=x%0Ay&h%3AAuto-Submitted=auto-generated";
        let items = parse(&Encoding::Urlencoded, body, LIMITS).unwrap();
        assert_eq!(
            texts(&items),
            [
                ("from", "Homepage <jochen-homepage@wersdoerfer.de>"),
                ("to", "a@b.de"),
                ("subject", "[Django] Fehler ü"),
                ("text", "x\ny"),
                ("h:Auto-Submitted", "auto-generated")
            ]
        );
        let encoding = encoding(Some(b"multipart/form-data; boundary=0a1b2c")).unwrap();
        let body = multipart_body(
            "0a1b2c",
            &[
                (
                    "Content-Disposition: form-data; name=\"subject\"",
                    "Anmeldung",
                ),
                ("Content-Disposition: form-data; name=\"to\"", "x@y.de"),
                (
                    "Content-Disposition: form-data; name=\"attachment\"; filename=\"a.txt\"\r\nContent-Type: text/plain",
                    "data",
                ),
            ],
        );
        let items = parse(&encoding, &body, LIMITS).unwrap();
        assert_eq!(
            texts(&items),
            [
                ("subject", "Anmeldung"),
                ("to", "x@y.de"),
                ("attachment", "a.txt")
            ]
        );
        let Value::File(upload) = &items[2].1 else {
            panic!("file expected")
        };
        assert_eq!(
            (upload.content_type.as_deref(), upload.data.as_slice()),
            (Some("text/plain"), b"data".as_slice())
        );
    }

    #[test]
    fn decoding_follows_unquote_plus() {
        assert_eq!(unquote_plus("a+b%20c%zz%4"), "a b c%zz%4");
        assert_eq!(unquote_plus("%C3%A4%C3"), "ä\u{fffd}");
        // Raw non-ASCII (latin-1 chars) is never percent-decoded into.
        assert_eq!(unquote_plus("%C3\u{e4}%A4"), "\u{fffd}\u{e4}\u{fffd}");
    }

    #[test]
    fn content_type_decisions() {
        assert_eq!(encoding(None), Ok(Encoding::None));
        assert_eq!(encoding(Some(b"text/plain")), Ok(Encoding::None));
        assert_eq!(
            encoding(Some(b" Application/X-WWW-Form-Urlencoded ")),
            Ok(Encoding::Urlencoded)
        );
        // With parameters the type is compared as written.
        assert_eq!(
            encoding(Some(b"Multipart/Form-Data; boundary=x")),
            Ok(Encoding::None)
        );
        assert_eq!(
            encoding(Some(b"multipart/form-data")),
            Err(FormError::BadRequest)
        );
        assert_eq!(
            encoding(Some(b"multipart/form-data; charset=cp1252; boundary=x")),
            Err(FormError::BadRequest)
        );
        let long = format!("multipart/form-data; boundary={}", "b".repeat(257));
        assert_eq!(encoding(Some(long.as_bytes())), Err(FormError::BadRequest));
        assert_eq!(
            encoding(Some(
                b"multipart/form-data; BOUNDARY=\"a;b\"; charset=Latin-1"
            )),
            Ok(Encoding::Multipart {
                boundary: b"a;b".to_vec(),
                charset: Charset::Latin1
            })
        );
    }

    #[test]
    fn limits() {
        let tight = Limits {
            max_files: 1,
            max_fields: 2,
            max_part_size: 5,
        };
        assert_eq!(
            parse(&Encoding::Urlencoded, b"a=1&b=2&c=3", tight),
            Err(FormError::TooLarge)
        );
        assert_eq!(
            parse(&Encoding::Urlencoded, b"a=12345", tight),
            Err(FormError::TooLarge)
        );
        assert!(parse(&Encoding::Urlencoded, b"&&a=1234&&b&", tight).is_ok());
        let encoding = Encoding::Multipart {
            boundary: b"b".to_vec(),
            charset: Charset::Utf8,
        };
        let file = "Content-Disposition: form-data; name=\"attachment\"; filename=\"\"";
        let body = multipart_body("b", &[(file, "x"), (file, "y")]);
        assert_eq!(parse(&encoding, &body, tight), Err(FormError::TooLarge));
        let field = "Content-Disposition: form-data; name=\"text\"";
        let body = multipart_body("b", &[(field, "123456")]);
        assert_eq!(parse(&encoding, &body, tight), Err(FormError::TooLarge));
    }

    /// Every case of the fixture: content type, body, limits → items, or
    /// the status of the error.
    #[test]
    fn form_decoding_fixture() {
        let fixture: Json =
            serde_json::from_str(include_str!("../fixtures/form_decoding.json")).unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        for case in cases {
            let bytes = |key: &str| case[key].as_str().map(latin1_bytes);
            let limits = &case["limits"];
            let limits = Limits {
                max_files: limits["max_files"].as_i64().unwrap(),
                max_fields: limits["max_fields"].as_i64().unwrap(),
                max_part_size: limits["max_part_size"].as_i64().unwrap(),
            };
            let content_type = bytes("content_type");
            let body = bytes("body").unwrap();
            let result = encoding(content_type.as_deref()).and_then(|e| parse(&e, &body, limits));
            let actual = match result {
                Ok(items) => json!({"items": items.iter().map(|(name, value)| match value {
                    Value::Text(text) => json!([name, {"text": text}]),
                    Value::File(upload) => json!([name, {"file": {
                        "filename": upload.filename,
                        "content_type": upload.content_type,
                        "data": latin1(&upload.data),
                    }}]),
                }).collect::<Vec<_>>()}),
                Err(FormError::BadRequest) => json!({"status": 400}),
                Err(FormError::TooLarge) => json!({"status": 413}),
            };
            assert_eq!(actual, case["expected"], "{}", case["name"]);
        }
        assert!(cases.len() >= 100, "{}", cases.len());
    }
}
