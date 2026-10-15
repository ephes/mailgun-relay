//! Message construction (PLAN.md 2.3 step 9, 2.10). **Stub until slice S4**,
//! which replaces this file behind the same interface: it makes the step-9
//! decisions that need no MIME encoding (empty bodies, recipient and
//! Reply-To addresses, headers the Python registry allows once, inline
//! filenames) and the envelope, and builds no message bytes. The decoding
//! of RFC 2047 display names (D-16) comes with S4.

use crate::address::{Mailbox, parse_mailbox, parse_mailbox_list};

/// An uploaded file; the filename defaults to `attachment` and the content
/// type to `application/octet-stream` (`relay:routes.py` `_read_upload`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// The validated request (steps 4–8).
#[derive(Debug, Clone)]
#[expect(dead_code, reason = "the message itself is built by slice S4")]
pub struct MessageInput {
    /// Parsed once by the policy check.
    pub from: Mailbox,
    /// Raw form values in input order.
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    /// Stripped and validated.
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub amp_html: Option<String>,
    /// The validated `h:*` headers without the prefix, in map order.
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<Attachment>,
    pub inline: Vec<Attachment>,
    pub public_host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltMessage {
    /// `<32 hex@PUBLIC_HOST>`, also the response `id`.
    pub message_id: String,
    /// `RCPT TO` addresses: to, cc, bcc, de-duplicated, first kept.
    pub envelope: Vec<String>,
    /// The RFC 5322 message (S4).
    pub formatted: Vec<u8>,
}

/// Every step-9 failure is a 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessage;

/// Headers a custom header may name that Python's header registry allows
/// once (case-insensitive); two case variants are a 400.
const UNIQUE: &[&str] = &["reply-to", "in-reply-to", "references", "orig-date"];

pub fn build(input: MessageInput) -> Result<BuiltMessage, InvalidMessage> {
    let present = |body: &Option<String>| body.as_deref().is_some_and(|b| !b.is_empty());
    if !present(&input.text) && !present(&input.html) {
        return Err(InvalidMessage);
    }
    let parse = |values: &[String]| -> Result<Vec<Mailbox>, InvalidMessage> {
        values
            .iter()
            .map(|v| parse_mailbox(v).map_err(|_| InvalidMessage))
            .collect()
    };
    let to = parse(&input.to)?;
    let cc = parse(&input.cc)?;
    for unique in UNIQUE {
        let count = input
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(unique))
            .count();
        if count > 1 {
            return Err(InvalidMessage);
        }
    }
    for (name, value) in &input.headers {
        if name.eq_ignore_ascii_case("reply-to") {
            parse_mailbox_list(value).map_err(|_| InvalidMessage)?;
        }
    }
    for inline in &input.inline {
        let name = &inline.filename;
        if name.is_empty()
            || crate::pystr::py_strip(name) != name
            || name.contains(['<', '>'])
            || name.chars().any(|c| c < '\x20' || c == '\x7f')
        {
            return Err(InvalidMessage);
        }
    }
    let bcc = parse(&input.bcc)?;
    let mut envelope: Vec<String> = Vec::new();
    for address in to.iter().chain(&cc).chain(&bcc).map(Mailbox::addr_spec) {
        if !envelope.contains(&address) {
            envelope.push(address);
        }
    }
    Ok(BuiltMessage {
        message_id: format!("<{}@{}>", crate::pipeline::random_hex(), input.public_host),
        envelope,
        formatted: Vec::new(),
    })
}
