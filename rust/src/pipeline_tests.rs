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
