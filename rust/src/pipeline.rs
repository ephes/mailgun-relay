//! `POST /v3/{domain}/messages` (PLAN.md 2.3 steps 2–11; `relay:routes.py`
//! `post_messages`, `_parse_form`): the decision order, the error mapping,
//! the response JSON and the `event=request` record.
//!
//! Step 1 (a declared `Content-Length` over the limit) is the layer in
//! [`crate::http`]. Message construction is [`crate::mime`] (step 9), the
//! submission a [`Submitter`] (step 10, [`crate::smtp`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;

use crate::auth::authenticate;
use crate::config::{Level, Settings};
use crate::domain::normalize_domain;
use crate::form::{self, FormError, Limits, Upload, Value};
use crate::headers::{validate_custom_headers, validate_subject};
use crate::log::Logger;
use crate::mime::{self, Attachment, BuiltMessage, MessageInput};
use crate::policy::{PolicyError, enforce_policy};
use crate::secrets::TokenPolicy;

pub const ACCESS_LOGGER: &str = "mailgun_relay.access";

/// Room above `max_recipients` for the other fields of a message
/// (`_FORM_FIELD_HEADROOM`).
const FORM_FIELD_HEADROOM: i64 = 100;

/// The logged `from` is capped (`_FROM_LOG_MAX_LEN`, code points).
const FROM_LOG_MAX_LEN: usize = 320;

const KNOWN_FIELDS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "text",
    "html",
    "amp-html",
    "attachment",
    "inline",
];

/// A recipient the SMTP server refused while it accepted the message for
/// the others; only the domain and the code are ever logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub address: String,
    pub code: Option<u16>,
}

/// A failed submission: 503 (`TEMPORARY`) or 502 (`PERMANENT`, `AUTH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    Temporary,
    Permanent,
}

pub type Submission<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<Refusal>, SubmitError>> + Send + 'a>>;

/// Step 10: hand a built message to the SMTP backend; the refused
/// recipients on success ([`crate::smtp::SmtpSubmitter`]).
pub trait Submitter: Send + Sync {
    fn submit(&self, message: BuiltMessage) -> Submission<'_>;
}

/// What the route needs: the settings, the token policies, the logger, the
/// submitter, the SMTP slots and the request tasks.
pub struct Relay {
    pub settings: Settings,
    pub tokens: Vec<TokenPolicy>,
    pub logger: Logger,
    pub submitter: Box<dyn Submitter>,
    /// `SMTP_MAX_CONCURRENCY` sessions at a time; further submissions wait
    /// without a timeout (`_smtp_limiter`).
    smtp_slots: Semaphore,
    /// Every request runs in a task of its own; shutdown waits for them, so
    /// a submission whose client went away is still finished.
    pub tasks: TaskTracker,
}

impl Relay {
    pub fn new(
        settings: Settings,
        tokens: Vec<TokenPolicy>,
        logger: Logger,
        submitter: Box<dyn Submitter>,
    ) -> Self {
        let slots = usize::try_from(settings.smtp_max_concurrency)
            .unwrap_or(usize::MAX)
            .min(Semaphore::MAX_PERMITS);
        Relay {
            settings,
            tokens,
            logger,
            submitter,
            smtp_slots: Semaphore::new(slots),
            tasks: TaskTracker::new(),
        }
    }
}

/// One failed decision: the status, the record's `result` and
/// `error_class`, and the response message.
#[derive(Debug)]
struct Failure {
    status: StatusCode,
    result: &'static str,
    class: &'static str,
    message: String,
}

impl Failure {
    fn bad_request(class: &'static str, message: impl Into<String>) -> Self {
        Failure {
            status: StatusCode::BAD_REQUEST,
            result: "bad_request",
            class,
            message: message.into(),
        }
    }

    fn too_large(message: impl Into<String>) -> Self {
        Failure {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            result: "too_large",
            class: "PayloadTooLargeError",
            message: message.into(),
        }
    }
}

/// The `event=request` record, written exactly once per request that
/// reaches the route: when it is dropped, so also when the request task
/// panics (then with Python's `internal_error` and 500).
struct Record {
    logger: Logger,
    start: Instant,
    request_id: String,
    token_label: String,
    path_domain: String,
    from: String,
    recipient_count: usize,
    refused_count: usize,
    message_id: Option<String>,
    result: &'static str,
    status_code: u16,
    error_class: Option<&'static str>,
}

#[derive(Serialize)]
struct RequestFields<'a> {
    request_id: &'a str,
    token_label: &'a str,
    path_domain: &'a str,
    from: &'a str,
    recipient_count: usize,
    refused_count: usize,
    message_id: &'a str,
    result: &'a str,
    status_code: u16,
    error_class: Option<&'a str>,
    duration_ms: u128,
}

impl Drop for Record {
    fn drop(&mut self) {
        let fields = RequestFields {
            request_id: &self.request_id,
            token_label: &self.token_label,
            path_domain: &self.path_domain,
            from: &self.from,
            recipient_count: self.recipient_count,
            refused_count: self.refused_count,
            message_id: self.message_id.as_deref().unwrap_or("-"),
            result: self.result,
            status_code: self.status_code,
            error_class: self.error_class,
            duration_ms: self.start.elapsed().as_millis(),
        };
        self.logger
            .emit(Level::Info, ACCESS_LOGGER, "request", &fields);
    }
}

#[derive(Serialize)]
struct RefusedEntry<'a> {
    domain: &'a str,
    code: Option<u16>,
}

#[derive(Serialize)]
struct RecipientsRefused<'a> {
    request_id: &'a str,
    token_label: &'a str,
    path_domain: &'a str,
    message_id: &'a str,
    recipient_count: usize,
    refused_count: usize,
    refused: Vec<RefusedEntry<'a>>,
}

/// 128 random bits as lowercase hex (`uuid.uuid4().hex` serves the same
/// purpose in Python).
pub fn random_hex() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The route handler. The request runs in its own task, so a client that
/// disconnects neither cancels it nor loses its record; a panic is a 500.
pub async fn post_messages(
    relay: Arc<Relay>,
    domain: String,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let task = relay
        .tasks
        .clone()
        .spawn(process(relay, domain, headers, body));
    match task.await {
        Ok(response) => response,
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
    }
}

async fn process(relay: Arc<Relay>, domain: String, headers: HeaderMap, body: Body) -> Response {
    let mut record = Record {
        logger: relay.logger,
        start: Instant::now(),
        request_id: random_hex(),
        token_label: "-".to_owned(),
        // Normalised for the log; the raw value when it is no domain.
        path_domain: normalize_domain(&domain).unwrap_or_else(|_| domain.clone()),
        from: "-".to_owned(),
        recipient_count: 0,
        refused_count: 0,
        message_id: None,
        result: "internal_error",
        status_code: 500,
        error_class: Some("Panic"),
    };
    let response = match decide(&relay, &domain, &headers, body, &mut record).await {
        Ok(response) => {
            record.error_class = None;
            response
        }
        Err(failure) => {
            record.result = failure.result;
            record.error_class = Some(failure.class);
            let mut response = error_response(failure.status, &failure.message);
            if failure.status == StatusCode::UNAUTHORIZED {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"MG API\""),
                );
            }
            response
        }
    };
    record.status_code = response.status().as_u16();
    response
}

fn json_response(status: StatusCode, body: &impl Serialize) -> Response {
    let body = serde_json::to_vec(body).expect("responses serialise");
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    #[derive(Serialize)]
    struct Error<'a> {
        message: &'a str,
    }
    json_response(status, &Error { message })
}

/// The parsed form (`_ParsedForm`); the custom headers keep Python's dict
/// order: first position, last value.
#[derive(Default)]
struct ParsedForm {
    from: Vec<String>,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: Option<String>,
    text: Option<String>,
    html: Option<String>,
    amp_html: Option<String>,
    headers: Vec<(String, String)>,
    attachments: Vec<Attachment>,
    inline: Vec<Attachment>,
}

/// Steps 2–11; `Ok` is the 200 (or the configured 502 for a partial
/// refusal), `Err` every other decision.
async fn decide(
    relay: &Relay,
    domain: &str,
    headers: &HeaderMap,
    body: Body,
    record: &mut Record,
) -> Result<Response, Failure> {
    let settings = &relay.settings;

    // Step 2: the first Authorization header; the body is not read on failure.
    let authorization = headers
        .get(header::AUTHORIZATION)
        .map(HeaderValue::as_bytes);
    let policy = authenticate(authorization, &relay.tokens).map_err(|_| Failure {
        status: StatusCode::UNAUTHORIZED,
        result: "auth_error",
        class: "AuthError",
        message: "Unauthorized".to_owned(),
    })?;
    record.token_label.clone_from(&policy.label);

    // Step 3: the content type decides whether and how the body is read.
    let content_type = headers.get(header::CONTENT_TYPE).map(HeaderValue::as_bytes);
    let encoding = form::encoding(content_type).map_err(form_failure)?;
    let bytes = match encoding {
        form::Encoding::None => Vec::new(),
        _ => read_body(body, settings.max_body_bytes).await?,
    };
    let limits = Limits {
        max_files: settings.max_attachments.saturating_add(1),
        max_fields: settings.max_recipients.saturating_add(FORM_FIELD_HEADROOM),
        max_part_size: settings.max_body_bytes,
    };
    let items = form::parse(&encoding, &bytes, limits).map_err(form_failure)?;
    drop(bytes);

    // Step 4.
    let parsed = parse_form(items, settings)?;
    let from = parsed.from.into_iter().next().unwrap_or_default();
    record.from = from.chars().take(FROM_LOG_MAX_LEN).collect();

    // Step 5.
    let mailbox = enforce_policy(policy, domain, &from).map_err(|error| match error {
        PolicyError::BadRequest => Failure::bad_request("InvalidAddressError", "invalid address"),
        PolicyError::Forbidden(message) => Failure {
            status: StatusCode::FORBIDDEN,
            result: "policy_error",
            class: "PolicyError",
            message,
        },
    })?;

    // Steps 6 and 7.
    let header_failure =
        |error: crate::headers::HeaderError| Failure::bad_request(error.class(), "invalid header");
    let subject = validate_subject(
        parsed.subject.as_deref().unwrap_or_default(),
        settings.max_header_value_length,
    )
    .map_err(header_failure)?;
    validate_custom_headers(&parsed.headers, settings.max_header_value_length)
        .map_err(header_failure)?;

    // Step 8: counted before de-duplication.
    let envelope_count = parsed.to.len() + parsed.cc.len() + parsed.bcc.len();
    if envelope_count == 0 {
        return Err(Failure::bad_request(
            "BadRequestError",
            "at least one of to/cc/bcc is required",
        ));
    }
    if exceeds(envelope_count, settings.max_recipients) {
        return Err(Failure::too_large(format!(
            "too many recipients (max {})",
            settings.max_recipients
        )));
    }

    // Step 9, off the runtime thread: encoding large attachments is CPU work.
    let input = MessageInput {
        from: mailbox,
        to: parsed.to,
        cc: parsed.cc,
        bcc: parsed.bcc,
        subject,
        text: parsed.text,
        html: parsed.html,
        amp_html: parsed.amp_html,
        headers: parsed.headers,
        attachments: parsed.attachments,
        inline: parsed.inline,
        public_host: settings.public_host.clone(),
    };
    let message = tokio::task::spawn_blocking(move || mime::build(input))
        .await
        .map_err(|_| Failure {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            result: "internal_error",
            class: "Panic",
            message: "Internal Server Error".to_owned(),
        })?
        .map_err(|_| Failure::bad_request("HeaderInjectionError", "invalid message"))?;
    let message_id = message.message_id.clone();
    record.message_id = Some(message_id.clone());
    record.recipient_count = message.envelope.len();

    // Step 10, behind the concurrency cap (never closed).
    let slot = relay.smtp_slots.acquire().await;
    let submitted = relay.submitter.submit(message).await;
    drop(slot);
    let refused = submitted.map_err(|error| match error {
        SubmitError::Temporary => Failure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            result: "smtp_temporary",
            class: "SmtpSubmitError",
            message: "Upstream SMTP temporarily unavailable".to_owned(),
        },
        SubmitError::Permanent => Failure {
            status: StatusCode::BAD_GATEWAY,
            result: "smtp_permanent",
            class: "SmtpSubmitError",
            message: "Upstream SMTP rejected the message".to_owned(),
        },
    })?;

    // Step 11, with the partial refusal of 2.4.
    record.result = "ok";
    if !refused.is_empty() {
        record.refused_count = refused.len();
        log_partial_refusal(relay, record, &message_id, &refused);
        record.result = "partial_refusal";
        if settings.fail_on_partial_refusal {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!(
                    "Upstream SMTP refused {} of {} recipients; the message was sent to the others",
                    record.refused_count, record.recipient_count
                ),
            ));
        }
    }
    #[derive(Serialize)]
    struct Queued<'a> {
        id: &'a str,
        message: &'a str,
    }
    Ok(json_response(
        StatusCode::OK,
        &Queued {
            id: &message_id,
            message: "Queued. Thank you.",
        },
    ))
}

fn form_failure(error: FormError) -> Failure {
    match error {
        FormError::BadRequest => Failure::bad_request("BadRequestError", "malformed form"),
        FormError::TooLarge => Failure::too_large("request exceeds multipart limits"),
    }
}

fn exceeds(len: usize, max: i64) -> bool {
    i64::try_from(len).map_or(true, |len| len > max)
}

/// The body up to `max_body_bytes` (the byte count of
/// `BodySizeLimitMiddleware`, also for a chunked body); a read error is the
/// 400 Python gives a client disconnect inside `request.form()`.
async fn read_body(mut body: Body, max_body_bytes: i64) -> Result<Vec<u8>, Failure> {
    let too_large = || Failure::too_large(format!("request body exceeds {max_body_bytes} bytes"));
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| Failure::bad_request("BadRequestError", "malformed form"))?;
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
            if exceeds(bytes.len(), max_body_bytes) {
                return Err(too_large());
            }
        }
    }
    // Python counts at least one (possibly empty) chunk.
    if exceeds(bytes.len(), max_body_bytes) {
        return Err(too_large());
    }
    Ok(bytes)
}

fn require_text(key: &str, value: Value) -> Result<String, Failure> {
    match value {
        Value::Text(text) => Ok(text),
        Value::File(_) => Err(Failure::bad_request(
            "BadRequestError",
            format!("field {key:?} must be a string"),
        )),
    }
}

/// `_read_upload`: the size limit, then Python's defaults for the filename
/// and the content type.
fn read_upload(value: Value, settings: &Settings) -> Result<Attachment, Failure> {
    let Value::File(Upload {
        filename,
        content_type,
        data,
    }) = value
    else {
        return Err(Failure::bad_request(
            "BadRequestError",
            "attachment/inline must be an uploaded file",
        ));
    };
    if exceeds(data.len(), settings.max_attachment_bytes) {
        return Err(Failure::too_large("attachment exceeds max size"));
    }
    Ok(Attachment {
        filename: if filename.is_empty() {
            "attachment".to_owned()
        } else {
            filename
        },
        content_type: content_type
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "application/octet-stream".to_owned()),
        data,
    })
}

/// Step 4 (`_parse_form`): the fields in form order, first error wins.
fn parse_form(items: Vec<(String, Value)>, settings: &Settings) -> Result<ParsedForm, Failure> {
    let mut parsed = ParsedForm::default();
    let mut total: usize = 0;
    let aggregate = |total: usize| -> Result<(), Failure> {
        if exceeds(total, settings.max_body_bytes) {
            return Err(Failure::too_large(format!(
                "aggregate body size exceeds {} bytes",
                settings.max_body_bytes
            )));
        }
        Ok(())
    };
    for (key, value) in items {
        if key.starts_with("v:")
            || key.starts_with("o:")
            || key.starts_with("t:")
            || key == "recipient-variables"
            || key == "template"
        {
            return Err(Failure::bad_request(
                "BadRequestError",
                format!("unsupported field: {key}"),
            ));
        }
        if let Some(name) = key.strip_prefix("h:") {
            let Value::Text(text) = value else {
                return Err(Failure::bad_request(
                    "BadRequestError",
                    format!("header {key} must be a string"),
                ));
            };
            match parsed.headers.iter_mut().find(|(n, _)| n == name) {
                Some(entry) => entry.1 = text,
                None => parsed.headers.push((name.to_owned(), text)),
            }
            continue;
        }
        if !KNOWN_FIELDS.contains(&key.as_str()) {
            return Err(Failure::bad_request(
                "BadRequestError",
                format!("unknown field: {key}"),
            ));
        }
        match key.as_str() {
            "from" => parsed.from.push(require_text(&key, value)?),
            "to" => parsed.to.push(require_text(&key, value)?),
            "cc" => parsed.cc.push(require_text(&key, value)?),
            "bcc" => parsed.bcc.push(require_text(&key, value)?),
            "subject" => parsed.subject = Some(require_text(&key, value)?),
            "text" | "html" | "amp-html" => {
                let text = require_text(&key, value)?;
                total += text.len();
                aggregate(total)?;
                let slot = match key.as_str() {
                    "text" => &mut parsed.text,
                    "html" => &mut parsed.html,
                    _ => &mut parsed.amp_html,
                };
                *slot = Some(text);
            }
            _ => {
                let attachment = read_upload(value, settings)?;
                total += attachment.data.len();
                aggregate(total)?;
                if key == "attachment" {
                    parsed.attachments.push(attachment);
                } else {
                    parsed.inline.push(attachment);
                }
                // Attachments and inline parts share the cap.
                if exceeds(
                    parsed.attachments.len() + parsed.inline.len(),
                    settings.max_attachments,
                ) {
                    return Err(Failure::too_large(format!(
                        "too many attachments+inline (max {})",
                        settings.max_attachments
                    )));
                }
            }
        }
    }
    if parsed.from.len() != 1 {
        return Err(Failure::bad_request(
            "BadRequestError",
            "exactly one 'from' is required",
        ));
    }
    if parsed.subject.is_none() {
        return Err(Failure::bad_request(
            "BadRequestError",
            "subject is required",
        ));
    }
    if parsed.text.is_none() && parsed.html.is_none() {
        return Err(Failure::bad_request(
            "BadRequestError",
            "at least one of 'text' or 'html' is required",
        ));
    }
    Ok(parsed)
}

/// One WARNING per partly refused request: refused domains and codes only,
/// unique and sorted (`_log_partial_refusal`).
fn log_partial_refusal(relay: &Relay, record: &Record, message_id: &str, refused: &[Refusal]) {
    let mut entries: Vec<(String, Option<u16>)> = refused
        .iter()
        .map(|refusal| {
            let domain = match refusal.address.rsplit_once('@') {
                Some((_, domain)) if !domain.is_empty() => domain.to_lowercase(),
                _ => "-".to_owned(),
            };
            (domain, refusal.code)
        })
        .collect();
    entries.sort_by_key(|(domain, code)| (domain.clone(), code.map_or(-1, i32::from)));
    entries.dedup();
    let fields = RecipientsRefused {
        request_id: &record.request_id,
        token_label: &record.token_label,
        path_domain: &record.path_domain,
        message_id,
        recipient_count: record.recipient_count,
        refused_count: refused.len(),
        refused: entries
            .iter()
            .map(|(domain, code)| RefusedEntry {
                domain,
                code: *code,
            })
            .collect(),
    };
    relay
        .logger
        .emit(Level::Warning, ACCESS_LOGGER, "recipients_refused", &fields);
}

#[cfg(test)]
#[path = "pipeline_tests.rs"]
pub mod tests;
