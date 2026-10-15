//! Route tests: the Rust counterparts of `tests/test_messages_endpoint.py`
//! (without SMTP) and `tests/test_body_limit.py`, the decision order of
//! PLAN.md 2.3 with multi-fault cases, both encodings, and the client shapes
//! of production. The submitter records the built message.

use std::collections::BTreeSet;
use std::sync::Mutex;

use axum::http::{HeaderMap, Request};
use base64::Engine;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::*;
use crate::config::Settings;
use crate::http::{AppState, router};

const HOMEPAGE_TOKEN: &str = "homepage-token-secret";
const PODCAST_TOKEN: &str = "podcast-token-secret";
const RECORDER_TOKEN: &str = "recorder-token-secret";
const SMTP_PASSWORD: &str = "not-a-real-password";

/// Records each submission and answers with the configured outcome.
pub struct Recorder {
    pub calls: Mutex<Vec<BuiltMessage>>,
    pub outcome: Mutex<Result<Vec<Refusal>, SubmitError>>,
}

struct Shared(Arc<Recorder>);

impl Submitter for Shared {
    fn submit(&self, message: BuiltMessage) -> Submission<'_> {
        self.0.calls.lock().unwrap().push(message);
        let outcome = self.0.outcome.lock().unwrap().clone();
        Box::pin(async move { outcome })
    }
}

fn token(label: &str, token: &str, mailgun: &str, from: &str, addresses: &[&str]) -> TokenPolicy {
    let set = |values: &[&str]| {
        values
            .iter()
            .map(|v| (*v).to_owned())
            .collect::<BTreeSet<_>>()
    };
    TokenPolicy {
        label: label.to_owned(),
        token_sha256: Sha256::digest(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        mailgun_domains: set(&[mailgun]),
        allowed_from_domains: set(&[from]),
        allowed_from_addresses: (!addresses.is_empty()).then(|| set(addresses)),
    }
}

/// `tests/conftest.py`: its two tokens plus the recorder's domain-only one.
fn tokens() -> Vec<TokenPolicy> {
    vec![
        token(
            "homepage-staging",
            HOMEPAGE_TOKEN,
            "mg.wersdoerfer.de",
            "wersdoerfer.de",
            &["jochen-homepage@wersdoerfer.de"],
        ),
        token(
            "python-podcast-staging",
            PODCAST_TOKEN,
            "mg.python-podcast.de",
            "mg.python-podcast.de",
            &["noreply@mg.python-podcast.de"],
        ),
        token(
            "recorder",
            RECORDER_TOKEN,
            "mg.wersdoerfer.de",
            "wersdoerfer.de",
            &[],
        ),
    ]
}

/// The settings of `tests/conftest.py`.
fn settings() -> Settings {
    Settings {
        public_host: "mailgun.home.xn--wersdrfer-47a.de".to_owned(),
        envelope_sender: "mailgun-relay@xn--wersdrfer-47a.de".to_owned(),
        max_body_bytes: 1_048_576,
        max_attachments: 3,
        max_attachment_bytes: 524_288,
        max_recipients: 10,
        max_header_value_length: 998,
        ..Settings::from_env([]).unwrap()
    }
}

/// A relay with the test tokens, a capturing logger and a recorder that
/// accepts every message.
pub fn relay(settings: Settings) -> (Arc<Relay>, Arc<Recorder>, &'static Mutex<Vec<String>>) {
    let (logger, lines) = Logger::capturing(Level::Info);
    let recorder = Arc::new(Recorder {
        calls: Mutex::new(Vec::new()),
        outcome: Mutex::new(Ok(Vec::new())),
    });
    let relay = Relay {
        settings,
        tokens: tokens(),
        logger,
        submitter: Box::new(Shared(Arc::clone(&recorder))),
    };
    (Arc::new(relay), recorder, lines)
}

struct Harness {
    relay: Arc<Relay>,
    recorder: Arc<Recorder>,
    logs: &'static Mutex<Vec<String>>,
}

impl Harness {
    fn new() -> Self {
        Self::with(settings())
    }

    fn with(settings: Settings) -> Self {
        let (relay, recorder, logs) = relay(settings);
        Harness {
            relay,
            recorder,
            logs,
        }
    }

    fn records(&self, event: &str) -> Vec<Json> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .map(|line| serde_json::from_str::<Json>(line).unwrap())
            .filter(|record| record["event"] == event)
            .collect()
    }

    async fn send(&self, request: Request<Body>) -> Reply {
        let state = Arc::new(AppState {
            relay: Arc::clone(&self.relay),
        });
        let response = router(state).oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = serde_json::from_slice(&body).unwrap_or(Json::Null);
        Reply {
            status,
            headers,
            json,
        }
    }

    async fn post(&self, auth: Option<&str>, domain: &str, body: Encoded) -> Reply {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v3/{domain}/messages"))
            .header("content-length", body.body.len());
        if let Some(content_type) = &body.content_type {
            request = request.header("content-type", content_type);
        }
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        self.send(request.body(Body::from(body.body)).unwrap())
            .await
    }

    /// The homepage token on its path.
    async fn homepage(&self, body: Encoded) -> Reply {
        self.post(
            Some(&basic("api", HOMEPAGE_TOKEN)),
            "mg.wersdoerfer.de",
            body,
        )
        .await
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    json: Json,
}

impl Reply {
    fn status(&self) -> u16 {
        self.status.as_u16()
    }
}

fn basic(user: &str, password: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {encoded}")
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Encoding {
    Urlencoded,
    Multipart,
}

const ENCODINGS: [Encoding; 2] = [Encoding::Urlencoded, Encoding::Multipart];

struct Encoded {
    content_type: Option<String>,
    body: Vec<u8>,
}

/// Form fields in order.
type Fields<'a> = Vec<(&'a str, &'a str)>;

/// `(field, filename, content type, data)`.
type File<'a> = (&'a str, &'a str, &'a str, &'a [u8]);

/// `urllib.parse.urlencode` (`quote_plus`).
fn urlencode(fields: &[(&str, &str)]) -> Vec<u8> {
    let quote = |text: &str| -> String {
        text.bytes()
            .map(|b| match b {
                b' ' => "+".to_owned(),
                b if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) => char::from(b).to_string(),
                b => format!("%{b:02X}"),
            })
            .collect()
    };
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", quote(k), quote(v)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

/// A multipart body as `requests` and Go's `mime/multipart` write it.
fn multipart(fields: &[(&str, &str)], files: &[File<'_>]) -> Encoded {
    let boundary = "relay-test-boundary";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    for (name, filename, content_type, data) in files {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; \
                 filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Encoded {
        content_type: Some(format!("multipart/form-data; boundary={boundary}")),
        body,
    }
}

fn encode(encoding: Encoding, fields: &[(&str, &str)]) -> Encoded {
    match encoding {
        Encoding::Urlencoded => Encoded {
            content_type: Some("application/x-www-form-urlencoded".to_owned()),
            body: urlencode(fields),
        },
        Encoding::Multipart => multipart(fields, &[]),
    }
}

const MINIMUM: [(&str, &str); 4] = [
    ("from", "Jochen <jochen-homepage@wersdoerfer.de>"),
    ("to", "admin@wersdoerfer.de"),
    ("subject", "hi"),
    ("text", "hello"),
];

/// The minimum form with `extra` fields appended.
fn with<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    MINIMUM
        .iter()
        .copied()
        .chain(extra.iter().copied())
        .collect()
}

/// The minimum form without the named fields, then `extra`.
fn without<'a>(names: &[&str], extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    MINIMUM
        .iter()
        .copied()
        .filter(|(name, _)| !names.contains(name))
        .chain(extra.iter().copied())
        .collect()
}

fn assert_queued(reply: &Reply) {
    assert_eq!(reply.status(), 200, "{}", reply.json);
    let object = reply.json.as_object().unwrap();
    assert_eq!(object.len(), 2, "{}", reply.json);
    let message = object["message"].as_str().unwrap();
    assert!(message.starts_with("Queued"), "{message}");
    assert!(!message.contains("Mailgun Magnificent API"));
    let id = object["id"].as_str().unwrap();
    assert!(
        id.starts_with('<') && id.ends_with("@mailgun.home.xn--wersdrfer-47a.de>"),
        "{id}"
    );
}

fn assert_error(reply: &Reply, status: u16) {
    assert_eq!(reply.status(), status, "{}", reply.json);
    let object = reply.json.as_object().unwrap();
    assert_eq!(object.len(), 1, "{}", reply.json);
    let message = object["message"].as_str().unwrap();
    assert!(!message.contains("Domain not found"), "{message}");
    assert_eq!(
        reply.headers.get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn happy_path_in_both_encodings() {
    for encoding in ENCODINGS {
        let h = Harness::new();
        let reply = h.homepage(encode(encoding, &MINIMUM)).await;
        assert_queued(&reply);
        let calls = h.recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].envelope, ["admin@wersdoerfer.de"]);
        assert_eq!(reply.json["id"], calls[0].message_id.as_str());
        let records = h.records("request");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["logger"], "mailgun_relay.access");
        assert_eq!(record["level"], "INFO");
        assert_eq!(record["token_label"], "homepage-staging");
        assert_eq!(record["result"], "ok");
        assert_eq!(record["status_code"], 200);
        assert_eq!(record["recipient_count"], 1);
        assert_eq!(record["refused_count"], 0);
        assert_eq!(record["message_id"], reply.json["id"]);
        assert_eq!(record["from"], "Jochen <jochen-homepage@wersdoerfer.de>");
        assert_eq!(record["path_domain"], "mg.wersdoerfer.de");
        assert_eq!(record["error_class"], Json::Null);
        let keys: Vec<&str> = record
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for key in ["request_id", "duration_ms", "event", "ts", "refused_count"] {
            assert!(keys.contains(&key), "{key}");
        }
    }
}

#[tokio::test]
async fn authentication_failures_are_401_with_realm() {
    let cases = [
        None,
        Some(basic("api", "nope")),
        Some(basic("notapi", HOMEPAGE_TOKEN)),
        Some(format!("Bearer {HOMEPAGE_TOKEN}")),
    ];
    for auth in cases {
        let h = Harness::new();
        let reply = h
            .post(
                auth.as_deref(),
                "mg.wersdoerfer.de",
                encode(Encoding::Urlencoded, &MINIMUM),
            )
            .await;
        assert_error(&reply, 401);
        assert_eq!(reply.json["message"], "Unauthorized");
        assert_eq!(
            reply.headers.get("www-authenticate").unwrap(),
            "Basic realm=\"MG API\""
        );
        let record = &h.records("request")[0];
        assert_eq!(
            (
                &record["result"],
                &record["token_label"],
                &record["status_code"]
            ),
            (&json!("auth_error"), &json!("-"), &json!(401))
        );
        assert!(h.recorder.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn policy_decisions() {
    let homepage = basic("api", HOMEPAGE_TOKEN);
    let podcast = basic("api", PODCAST_TOKEN);
    let podcast_form = [
        ("from", "Python Podcast <noreply@mg.python-podcast.de>"),
        ("to", "jochen-pythonpodcast@wersdoerfer.de"),
        ("subject", "ack"),
        ("text", "body"),
    ];
    let other_sender = without(
        &["from"],
        &[("from", "Someone <someone-else@wersdoerfer.de>")],
    );
    let other_domain = without(&["from"], &[("from", "x@evil.test")]);
    let cases: Vec<(&str, &str, Fields<'_>, u16, Option<&str>)> = vec![
        (&homepage, "mg.wersdoerfer.de", MINIMUM.to_vec(), 200, None),
        // Path domain not allowed, the parent domain included.
        (
            &homepage,
            "evil.test",
            MINIMUM.to_vec(),
            403,
            Some("token not allowed for path domain 'evil.test'"),
        ),
        (
            &homepage,
            "wersdoerfer.de",
            MINIMUM.to_vec(),
            403,
            Some("token not allowed for path domain 'wersdoerfer.de'"),
        ),
        (
            &homepage,
            "mg.python-podcast.de",
            podcast_form.to_vec(),
            403,
            Some("token not allowed for path domain 'mg.python-podcast.de'"),
        ),
        (
            &homepage,
            "mg.wersdoerfer.de",
            other_sender,
            403,
            Some("token not allowed for from address 'someone-else@wersdoerfer.de'"),
        ),
        (
            &homepage,
            "mg.wersdoerfer.de",
            other_domain,
            403,
            Some("token not allowed for from domain 'evil.test'"),
        ),
        (
            &podcast,
            "mg.python-podcast.de",
            podcast_form.to_vec(),
            200,
            None,
        ),
        // The path domain is normalised: case and IDN forms.
        (&homepage, "MG.Wersdoerfer.DE", MINIMUM.to_vec(), 200, None),
        // Invalid path domain: 400 at the policy step.
        (&homepage, "a..b", MINIMUM.to_vec(), 400, None),
    ];
    for (auth, domain, fields, status, message) in cases {
        for encoding in ENCODINGS {
            let h = Harness::new();
            let reply = h.post(Some(auth), domain, encode(encoding, &fields)).await;
            assert_eq!(reply.status(), status, "{domain} {fields:?} {}", reply.json);
            if let Some(message) = message {
                assert_eq!(reply.json["message"], message);
                assert_eq!(h.records("request")[0]["result"], "policy_error");
            }
        }
    }
}

/// One code point more than `MAX_HEADER_VALUE_LENGTH` (998).
static LONG_VALUE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| "ü".repeat(999));

#[tokio::test]
async fn field_rules_are_400() {
    let bad_from_crlf = "jochen-homepage@wersdoerfer.de\nBcc: evil@wersdoerfer.de";
    let cases: Vec<Vec<(&str, &str)>> = vec![
        with(&[("o:tag", "x")]),
        with(&[("v:my-var", "x")]),
        with(&[("t:version", "x")]),
        with(&[("template", "x")]),
        with(&[("recipient-variables", "{}")]),
        with(&[("unknown", "x")]),
        with(&[("from", "Second <jochen-homepage@wersdoerfer.de>")]),
        without(&["from"], &[]),
        without(&["subject"], &[]),
        without(&["text"], &[]),
        with(&[("h:Bcc", "evil@x.com")]),
        with(&[("h:X Bad", "x")]),
        with(&[("h:X-Custom", "ok\nBcc: evil@x.com")]),
        with(&[("h:X-Foo\n", "x")]),
        with(&[("h:X-Long", &LONG_VALUE)]),
        without(&["subject"], &[("subject", &LONG_VALUE)]),
        without(&["subject"], &[("subject", "Hi\r\nBcc: evil@x.com")]),
        without(&["to"], &[]),
        without(&["from"], &[("from", "not-an-email")]),
        without(&["from"], &[("from", "bad@bad domain")]),
        without(&["from"], &[("from", bad_from_crlf)]),
        without(&["from"], &[("from", "jörg@wersdoerfer.de")]),
        without(&["to"], &[("to", "bad@bad domain")]),
        without(&["to"], &[("to", "a@x.de, b@x.de")]),
        with(&[("cc", "jörg@example.org")]),
        with(&[("bcc", "not-an-email")]),
        with(&[("h:Reply-To", "bad@bad domain")]),
        with(&[("h:Reply-To", "a@x.de"), ("h:reply-to", "b@x.de")]),
        with(&[("h:References", "<a@x>"), ("h:REFERENCES", "<b@x>")]),
        // D-1: an empty text without another body.
        without(&["text"], &[("text", "")]),
        without(&["text"], &[("html", "")]),
        without(&["text"], &[("text", ""), ("html", "")]),
    ];
    for fields in &cases {
        for encoding in ENCODINGS {
            let h = Harness::new();
            let reply = h.homepage(encode(encoding, fields)).await;
            assert_error(&reply, 400);
            let record = &h.records("request")[0];
            assert_eq!(record["result"], "bad_request", "{fields:?}");
            assert!(h.recorder.calls.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn accepted_variants() {
    let cases: Vec<Vec<(&str, &str)>> = vec![
        // An empty subject is allowed; text="" next to html is dropped.
        without(&["subject"], &[("subject", "")]),
        without(&["text"], &[("text", ""), ("html", "<p>x</p>")]),
        with(&[("html", "")]),
        // Last value wins; repeated recipients; Cc/Bcc; custom headers.
        with(&[("subject", "second"), ("text", "second")]),
        with(&[
            ("h:Reply-To", "\"Doe, Jane\" <jane@example.test>, b@x.de"),
            ("h:Auto-Submitted", "auto-generated"),
            ("h:X-Mailer", "a"),
            ("h:X-Mailer", "b"),
        ]),
        with(&[("subject", "  [Django] ERROR\t  ")]),
    ];
    for fields in &cases {
        for encoding in ENCODINGS {
            let h = Harness::new();
            assert_queued(&h.homepage(encode(encoding, fields)).await);
        }
    }
}

#[tokio::test]
async fn envelope_order_and_deduplication() {
    let fields = with(&[
        ("to", "Other <Admin@Wersdoerfer.de>"),
        ("cc", "c@example.org"),
        ("bcc", "hidden@example.net"),
        ("bcc", "admin@wersdoerfer.de"),
        ("cc", "Jörg <joerg@wersdörfer.de>"),
    ]);
    let h = Harness::new();
    assert_queued(&h.homepage(encode(Encoding::Multipart, &fields)).await);
    let calls = h.recorder.calls.lock().unwrap();
    assert_eq!(
        calls[0].envelope,
        [
            "admin@wersdoerfer.de",
            "Admin@wersdoerfer.de",
            "c@example.org",
            "joerg@xn--wersdrfer-47a.de",
            "hidden@example.net"
        ]
    );
    assert_eq!(h.records("request")[0]["recipient_count"], 5);
}

#[tokio::test]
async fn limits_are_413() {
    let file = |field, name| (field, name, "text/plain", b"x".as_slice());
    let big = vec![b'x'; 600_000];
    // MAX_ATTACHMENT_BYTES is 524,288: equal passes, one byte more is 413.
    let at_limit = vec![b'x'; 524_288];
    let over_limit = vec![b'x'; 524_289];
    let cases: Vec<(Vec<File<'_>>, u16)> = vec![
        (
            vec![("attachment", "a.bin", "application/octet-stream", &at_limit)],
            200,
        ),
        (
            vec![(
                "attachment",
                "a.bin",
                "application/octet-stream",
                &over_limit,
            )],
            413,
        ),
        (vec![("inline", "i.png", "image/png", &at_limit)], 200),
        (vec![("inline", "i.png", "image/png", &over_limit)], 413),
        (
            vec![("attachment", "hello.txt", "text/plain", b"hello".as_slice())],
            200,
        ),
        (
            vec![("attachment", "big.bin", "application/octet-stream", &big)],
            413,
        ),
        ((0..3).map(|_| file("attachment", "f.txt")).collect(), 200),
        ((0..4).map(|_| file("attachment", "f.txt")).collect(), 413),
        // A flood past Starlette's max_files is still 413.
        ((0..20).map(|_| file("attachment", "f.txt")).collect(), 413),
        ((0..4).map(|_| file("inline", "f.txt")).collect(), 413),
        (
            vec![
                file("attachment", "a"),
                file("attachment", "b"),
                file("inline", "c"),
                file("inline", "d"),
            ],
            413,
        ),
    ];
    for (files, status) in cases {
        let h = Harness::new();
        let reply = h.homepage(multipart(&MINIMUM, &files)).await;
        assert_eq!(reply.status(), status, "{}", files.len());
        if status == 413 {
            assert_error(&reply, 413);
            assert_eq!(h.records("request")[0]["result"], "too_large");
        }
    }
    // The aggregate counts UTF-8 bytes of the decoded texts: 600,000 bytes
    // that are no UTF-8 decode as latin-1 to 1,200,000 bytes, more than
    // MAX_BODY_BYTES in a body that is not.
    let mut body = multipart(&without(&["text"], &[]), &[]);
    body.body
        .truncate(body.body.len() - b"--relay-test-boundary--\r\n".len());
    body.body.extend_from_slice(
        b"--relay-test-boundary\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\n",
    );
    body.body.extend(std::iter::repeat_n(0xe4, 600_000));
    body.body
        .extend_from_slice(b"\r\n--relay-test-boundary--\r\n");
    let h = Harness::new();
    assert_error(&h.homepage(body).await, 413);
    // Recipients: 10 pass, 11 are 413; counted before de-duplication.
    let ten: Vec<(&str, &str)> = (0..10).map(|_| ("to", "a@wersdoerfer.de")).collect();
    let eleven: Vec<(&str, &str)> = (0..11).map(|_| ("bcc", "a@wersdoerfer.de")).collect();
    for encoding in ENCODINGS {
        let h = Harness::new();
        assert_queued(&h.homepage(encode(encoding, &without(&["to"], &ten))).await);
        let reply = h
            .homepage(encode(encoding, &without(&["to"], &eleven)))
            .await;
        assert_error(&reply, 413);
    }
    // Starlette's field cap: max_recipients + 100 non-file fields.
    let many: Vec<(&str, &str)> = (0..106).map(|_| ("h:X-A", "x")).collect();
    let too_many: Vec<(&str, &str)> = (0..107).map(|_| ("h:X-A", "x")).collect();
    for encoding in ENCODINGS {
        let h = Harness::new();
        assert_queued(&h.homepage(encode(encoding, &with(&many))).await);
        assert_error(&h.homepage(encode(encoding, &with(&too_many))).await, 413);
    }
}

#[tokio::test]
async fn inline_filenames() {
    for (filename, status) in [
        ("logo.png", 200),
        ("<logo.png>", 400),
        ("<logo.png", 400),
        ("logo.png>", 400),
        (" logo.png", 400),
        ("", 200),
    ] {
        let h = Harness::new();
        let files = [("inline", filename, "image/png", b"\x89PNG".as_slice())];
        let reply = h
            .homepage(multipart(
                &with(&[("html", "<img src=\"cid:logo.png\">")]),
                &files,
            ))
            .await;
        assert_eq!(reply.status(), status, "{filename:?}");
    }
    // Files where strings belong and strings where files belong.
    let h = Harness::new();
    let files = [("subject", "s.txt", "text/plain", b"x".as_slice())];
    assert_error(
        &h.homepage(multipart(&without(&["subject"], &[]), &files))
            .await,
        400,
    );
    let files = [("h:X-A", "s.txt", "text/plain", b"x".as_slice())];
    assert_error(&h.homepage(multipart(&MINIMUM, &files)).await, 400);
    assert_error(
        &h.homepage(encode(Encoding::Urlencoded, &with(&[("attachment", "x")])))
            .await,
        400,
    );
}

#[tokio::test]
async fn body_reading() {
    let h = Harness::new();
    // Malformed multipart: no boundary, broken framing.
    for content_type in ["multipart/form-data", "multipart/form-data; boundary=zzz"] {
        let mut body = encode(Encoding::Multipart, &MINIMUM);
        body.content_type = Some(content_type.to_owned());
        assert_error(&h.homepage(body).await, 400);
    }
    // Other content types give an empty form: 400 for the missing `from`.
    for content_type in [None, Some("text/plain"), Some("application/json")] {
        let mut body = encode(Encoding::Urlencoded, &MINIMUM);
        body.content_type = content_type.map(str::to_owned);
        assert_error(&h.homepage(body).await, 400);
    }
    // A chunked body over the limit: counted while read, 413 with a record.
    let h = Harness::with(Settings {
        max_body_bytes: 100,
        ..settings()
    });
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![Ok(vec![b'a'; 60]), Ok(vec![b'b'; 60])];
    let request = Request::builder()
        .method("POST")
        .uri("/v3/mg.wersdoerfer.de/messages")
        .header("authorization", basic("api", HOMEPAGE_TOKEN))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from_stream(futures_util::stream::iter(chunks)))
        .unwrap();
    let reply = h.send(request).await;
    assert_error(&reply, 413);
    assert_eq!(h.records("request")[0]["result"], "too_large");
    // Within the limit it is read; a declared length over it is the layer's
    // 413, before auth and without a record.
    let reply = h
        .post(
            None,
            "mg.wersdoerfer.de",
            Encoded {
                content_type: None,
                body: vec![b'x'; 101],
            },
        )
        .await;
    assert_eq!(reply.json, json!({"message": "Payload Too Large"}));
    assert_eq!(h.records("request").len(), 1);
}

#[tokio::test]
async fn decision_order() {
    let homepage = basic("api", HOMEPAGE_TOKEN);
    let big = vec![b'x'; 600_000];
    // (path domain, fields, files, status)
    let tag = ("o:tag", "x");
    let cases: Vec<(&str, Fields<'_>, Vec<File<'_>>, u16)> = vec![
        // Field rules (step 4) before the policy (step 5).
        ("evil.test", with(&[tag]), vec![], 400),
        ("evil.test", without(&["text"], &[]), vec![], 400),
        // First error in form order wins within step 4.
        (
            "mg.wersdoerfer.de",
            MINIMUM.to_vec(),
            vec![("attachment", "big.bin", "application/octet-stream", &big)],
            413,
        ),
        // Policy before subject, headers and recipients.
        (
            "evil.test",
            without(&["subject"], &[("subject", "a\nb")]),
            vec![],
            403,
        ),
        ("evil.test", with(&[("h:Bcc", "x@y.de")]), vec![], 403),
        ("evil.test", without(&["to"], &[]), vec![], 403),
        // Path domain (400 or 403) before the from address.
        (
            "evil.test",
            without(&["from"], &[("from", "not-an-email")]),
            vec![],
            403,
        ),
        (
            "a..b",
            without(&["from"], &[("from", "x@evil.test")]),
            vec![],
            400,
        ),
        // Subject (6) before custom headers (7) before recipients (8).
        (
            "mg.wersdoerfer.de",
            without(&["subject", "to"], &[("subject", "a\rb"), ("h:Bcc", "x")]),
            vec![],
            400,
        ),
        (
            "mg.wersdoerfer.de",
            {
                let mut f = with(&[("h:Bcc", "x")]);
                f.extend((0..11).map(|_| ("cc", "a@wersdoerfer.de")));
                f
            },
            vec![],
            400,
        ),
        // Recipient count (8) before the addresses (9).
        (
            "mg.wersdoerfer.de",
            (0..11)
                .map(|_| ("to", "bad@bad domain"))
                .chain(without(&["to"], &[]))
                .collect(),
            vec![],
            413,
        ),
        // D-1 at step 9: after the policy.
        (
            "evil.test",
            without(&["text"], &[("text", "")]),
            vec![],
            403,
        ),
    ];
    for (domain, fields, files, status) in &cases {
        let h = Harness::new();
        let reply = h
            .post(Some(&homepage), domain, multipart(fields, files))
            .await;
        assert_eq!(
            reply.status(),
            *status,
            "{domain} {fields:?} {}",
            reply.json
        );
        if files.is_empty() {
            let reply = h
                .post(
                    Some(&homepage),
                    domain,
                    encode(Encoding::Urlencoded, fields),
                )
                .await;
            assert_eq!(reply.status(), *status, "urlencoded {domain} {fields:?}");
        }
    }
    // An oversized attachment after o:tag is 400; before it, 413.
    let h = Harness::new();
    let files = [(
        "attachment",
        "big.bin",
        "application/octet-stream",
        big.as_slice(),
    )];
    let mut body = multipart(&with(&[tag]), &files);
    assert_error(&h.homepage(body).await, 400);
    body = multipart(&[], &files);
    let tail = multipart(&with(&[tag]), &[]).body;
    body.body
        .truncate(body.body.len() - b"--relay-test-boundary--\r\n".len());
    body.body.extend_from_slice(&tail);
    assert_error(&h.homepage(body).await, 413);
    // Bad auth wins over a malformed or oversized body.
    for content_type in ["multipart/form-data", "multipart/form-data; boundary=x"] {
        let body = Encoded {
            content_type: Some(content_type.to_owned()),
            body: b"garbage".to_vec(),
        };
        let reply = h
            .post(Some(&basic("api", "nope")), "mg.wersdoerfer.de", body)
            .await;
        assert_error(&reply, 401);
    }
}

#[tokio::test]
async fn submission_outcomes() {
    let refusal = |address: &str, code| Refusal {
        address: address.to_owned(),
        code,
    };
    for (outcome, status, result) in [
        (Err(SubmitError::Temporary), 503, "smtp_temporary"),
        (Err(SubmitError::Permanent), 502, "smtp_permanent"),
    ] {
        let h = Harness::new();
        *h.recorder.outcome.lock().unwrap() = outcome;
        let reply = h.homepage(encode(Encoding::Urlencoded, &MINIMUM)).await;
        assert_error(&reply, status);
        let record = &h.records("request")[0];
        assert_eq!(record["result"], result);
        assert!(record["message_id"].as_str().unwrap().starts_with('<'));
    }
    // Partial refusal: 200 and a WARNING with domains and codes only, or
    // 502 when FAIL_ON_PARTIAL_REFUSAL is set.
    let fields = with(&[
        ("to", "gone-user@Example.org"),
        ("bcc", "hidden-user@example.net"),
    ]);
    for strict in [false, true] {
        let h = Harness::with(Settings {
            fail_on_partial_refusal: strict,
            ..settings()
        });
        *h.recorder.outcome.lock().unwrap() = Ok(vec![
            refusal("gone-user@Example.org", Some(550)),
            refusal("hidden-user@example.net", Some(450)),
            refusal("x@example.org", Some(550)),
        ]);
        let reply = h.homepage(encode(Encoding::Urlencoded, &fields)).await;
        if strict {
            assert_error(&reply, 502);
        } else {
            assert_queued(&reply);
        }
        let warning = &h.records("recipients_refused")[0];
        assert_eq!(warning["level"], "WARNING");
        assert_eq!(warning["refused_count"], 3);
        assert_eq!(warning["recipient_count"], 3);
        assert_eq!(
            warning["refused"],
            json!([
                {"domain": "example.net", "code": 450},
                {"domain": "example.org", "code": 550}
            ])
        );
        let text = h.logs.lock().unwrap().join("");
        assert!(!text.contains("gone-user") && !text.contains("hidden-user"));
        let record = &h.records("request")[0];
        assert_eq!(record["result"], "partial_refusal");
        assert_eq!(record["refused_count"], 3);
        assert_eq!(record["status_code"], if strict { 502 } else { 200 });
    }
    // The submitter of this slice never claims a message as queued.
    let reply = Unavailable.submit(BuiltMessage {
        message_id: String::new(),
        envelope: Vec::new(),
        formatted: Vec::new(),
    });
    assert_eq!(reply.await, Err(SubmitError::Temporary));
}

#[tokio::test]
async fn records_follow_the_information_boundary() {
    let h = Harness::new();
    assert_queued(&h.homepage(encode(Encoding::Urlencoded, &MINIMUM)).await);
    // Python test: a U-label path domain is logged as its A-label.
    let reply = h
        .post(
            Some(&basic("api", HOMEPAGE_TOKEN)),
            "wersd%C3%B6rfer.de",
            encode(Encoding::Urlencoded, &MINIMUM),
        )
        .await;
    assert_eq!(reply.status(), 403);
    let lines = h.logs.lock().unwrap().join("");
    let header = basic("api", HOMEPAGE_TOKEN);
    let encoded = header.trim_start_matches("Basic ");
    for secret in [HOMEPAGE_TOKEN, SMTP_PASSWORD, encoded, header.as_str()] {
        assert!(!lines.contains(secret), "{secret}");
    }
    let records = h.records("request");
    assert_eq!(records[1]["path_domain"], "xn--wersdrfer-47a.de");
    assert_eq!(records[1]["result"], "policy_error");
    assert_eq!(records[1]["error_class"], "PolicyError");
    // The logged `from` is capped at 320 characters.
    let long = format!("{}@wersdoerfer.de", "ä".repeat(400));
    let h = Harness::new();
    h.homepage(encode(
        Encoding::Urlencoded,
        &without(&["from"], &[("from", &long)]),
    ))
    .await;
    let from = h.records("request")[0]["from"].as_str().unwrap().to_owned();
    assert_eq!(from.chars().count(), 320);
    // No record below the configured level.
    let (logger, lines) = Logger::capturing(Level::Warning);
    let quiet = Relay {
        settings: settings(),
        tokens: tokens(),
        logger,
        submitter: Box::new(Unavailable),
    };
    let state = Arc::new(AppState {
        relay: Arc::new(quiet),
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v3/mg.wersdoerfer.de/messages")
        .body(Body::empty())
        .unwrap();
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(lines.lock().unwrap().is_empty());
}

#[tokio::test]
async fn route_matching() {
    let h = Harness::new();
    let request = |method: &str, uri: &str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    };
    let reply = h
        .send(request("GET", "/v3/mg.wersdoerfer.de/messages"))
        .await;
    assert_eq!(reply.status(), 405);
    assert_eq!(reply.headers.get("allow").unwrap(), "POST");
    let reply = h
        .send(request("HEAD", "/v3/mg.wersdoerfer.de/messages"))
        .await;
    assert_eq!(reply.status(), 405);
    let reply = h
        .send(request("POST", "/v3/mg.wersdoerfer.de/messages/"))
        .await;
    assert_eq!(reply.status(), 307);
    for uri in [
        "/v3/a%2Fb/messages",
        "/v3//messages",
        "/v3/mg.wersdoerfer.de/messages.mime",
        "/v3/mg.wersdoerfer.de/events",
    ] {
        let reply = h.send(request("POST", uri)).await;
        assert_eq!(reply.json, json!({"detail": "Not Found"}), "{uri}");
    }
    // The decoded path and `$` before a final newline, as Starlette.
    let reply = h
        .send(request("POST", "/v3/mg.wersdoerfer.de/messages%0A"))
        .await;
    assert_eq!(reply.status(), 401);
    assert!(h.records("request").len() == 1);
}

/// The client shapes of production (`handoff/phase1-code-clients.md`):
/// Anymail 15.2 urlencoded, the recorder's multipart in every field order.
#[tokio::test]
async fn production_shapes() {
    let anymail = [
        ("from", "Homepage <jochen-homepage@wersdoerfer.de>"),
        ("to", "admin@wersdoerfer.de"),
        ("to", "Jörg Ö <joerg@example.org>"),
        (
            "subject",
            "[Django] ERROR (EXTERNAL IP): Internal Server Error: /über/",
        ),
        ("h:Auto-Submitted", "auto-generated"),
        (
            "text",
            "Traceback (most recent call last):\n  File \"x\", line 1\n",
        ),
        ("html", "<p>Grüße</p>"),
    ];
    let h = Harness::new();
    assert_queued(&h.homepage(encode(Encoding::Urlencoded, &anymail)).await);
    assert_queued(
        &h.homepage(encode(Encoding::Urlencoded, &anymail[..6]))
            .await,
    );
    let recorder = [
        ("from", "Recorder <recorder@wersdoerfer.de>"),
        ("to", "jochen@wersdoerfer.de"),
        ("subject", "Dein Anmeldelink"),
        (
            "text",
            "Hallo,\n\nhier ist dein Link: https://example.test/x?y=1&z=2\n",
        ),
    ];
    let auth = basic("api", RECORDER_TOKEN);
    let mut orders = 0;
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                if a == b || a == c || b == c {
                    continue;
                }
                let d = 6 - a - b - c;
                let fields = [recorder[a], recorder[b], recorder[c], recorder[d]];
                let reply = h
                    .post(Some(&auth), "mg.wersdoerfer.de", multipart(&fields, &[]))
                    .await;
                assert_queued(&reply);
                orders += 1;
            }
        }
    }
    assert_eq!(orders, 24);
}

struct Panicking;

impl Submitter for Panicking {
    fn submit(&self, _message: BuiltMessage) -> Submission<'_> {
        Box::pin(async { panic!("submitter failure") })
    }
}

/// A panic in the request task is a 500 and still writes the one record.
#[tokio::test]
async fn panics_are_500_with_a_record() {
    let (logger, lines) = Logger::capturing(Level::Info);
    let relay = Relay {
        settings: settings(),
        tokens: tokens(),
        logger,
        submitter: Box::new(Panicking),
    };
    let h = Harness {
        relay: Arc::new(relay),
        recorder: relay_recorder(),
        logs: lines,
    };
    let reply = h.homepage(encode(Encoding::Urlencoded, &MINIMUM)).await;
    assert_error(&reply, 500);
    let records = h.records("request");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["result"], "internal_error");
    assert_eq!(records[0]["status_code"], 500);
    assert_eq!(records[0]["token_label"], "homepage-staging");
}

fn relay_recorder() -> Arc<Recorder> {
    Arc::new(Recorder {
        calls: Mutex::new(Vec::new()),
        outcome: Mutex::new(Ok(Vec::new())),
    })
}
