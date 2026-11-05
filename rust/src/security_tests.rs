//! Bypass attempts against the safety boundary (`docs/security.md`): every
//! test here tries to get a message past authentication, the token policy
//! or the header checks, or to make the relay leak data, and asserts that
//! nothing reaches the submitter. Each threat of the document names the test
//! that covers it.
//!
//! A child module of the route tests, so it shares their harness, tokens
//! and form encoders.

use super::*;

/// Every case refused before the submitter, with the expected status.
async fn refused(h: &Harness, auth: Option<&str>, domain: &str, fields: &[(&str, &str)]) -> Reply {
    let reply = h
        .post(auth, domain, encode(Encoding::Urlencoded, fields))
        .await;
    assert!(
        h.recorder.calls.lock().unwrap().is_empty(),
        "{domain} {fields:?} reached the submitter"
    );
    reply
}

/// T2: spellings of the credentials that must not authenticate. Only
/// `Basic base64("api:<token>")` does; the scheme and the user are
/// case-sensitive, nothing is trimmed inside the credentials, and the token
/// is never taken from another header, the query or the stored hash.
#[tokio::test]
async fn credential_variants_are_401() {
    let encoded = |raw: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    };
    let token_hash: String = Sha256::digest(HOMEPAGE_TOKEN.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let cases = [
        // An empty user, a user in another case or with whitespace.
        basic("", HOMEPAGE_TOKEN),
        basic("API", HOMEPAGE_TOKEN),
        basic(" api", HOMEPAGE_TOKEN),
        basic("api ", HOMEPAGE_TOKEN),
        // An empty password, no separator, the token as the user.
        basic("api", ""),
        encoded("api"),
        encoded(HOMEPAGE_TOKEN),
        basic(HOMEPAGE_TOKEN, ""),
        // The token with whitespace, a prefix or a suffix.
        basic("api", &format!("{HOMEPAGE_TOKEN}\n")),
        basic("api", &format!(" {HOMEPAGE_TOKEN}")),
        basic("api", &HOMEPAGE_TOKEN[..HOMEPAGE_TOKEN.len() - 1]),
        basic("api", &format!("{HOMEPAGE_TOKEN}x")),
        // The configured SHA-256, upper and lower case, is not the token.
        basic("api", &token_hash),
        basic("api", &token_hash.to_uppercase()),
        // The scheme is case-sensitive and needs its single space.
        basic("api", HOMEPAGE_TOKEN).replacen("Basic ", "basic ", 1),
        basic("api", HOMEPAGE_TOKEN).replacen("Basic ", "BASIC ", 1),
        basic("api", HOMEPAGE_TOKEN).replacen("Basic ", "Basic", 1),
        // The raw token or `api:token` unencoded.
        format!("Basic {HOMEPAGE_TOKEN}"),
        format!("Basic api:{HOMEPAGE_TOKEN}"),
        format!("Bearer {HOMEPAGE_TOKEN}"),
        HOMEPAGE_TOKEN.to_owned(),
    ];
    for auth in &cases {
        let h = Harness::new();
        let reply = refused(&h, Some(auth), "mg.wersdoerfer.de", &MINIMUM).await;
        assert_error(&reply, 401);
        assert_eq!(h.records("request")[0]["result"], "auth_error", "{auth}");
    }

    // The token anywhere but the Authorization header.
    let form = urlencode(&MINIMUM);
    for (uri, name) in [
        (
            format!("/v3/mg.wersdoerfer.de/messages?api_key={HOMEPAGE_TOKEN}"),
            "x-api-key",
        ),
        (
            "/v3/mg.wersdoerfer.de/messages".to_owned(),
            "proxy-authorization",
        ),
    ] {
        let h = Harness::new();
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .header(name, basic("api", HOMEPAGE_TOKEN))
            .body(Body::from(form.clone()))
            .unwrap();
        assert_error(&h.send(request).await, 401);
        assert!(h.recorder.calls.lock().unwrap().is_empty());
    }
}

/// T2: only the first `Authorization` header is read, so a second, valid
/// one never rescues a wrong first one.
#[tokio::test]
async fn only_the_first_authorization_header_counts() {
    let form = urlencode(&MINIMUM);
    let request = |first: String, second: String| {
        Request::builder()
            .method("POST")
            .uri("/v3/mg.wersdoerfer.de/messages")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", first)
            .header("authorization", second)
            .body(Body::from(form.clone()))
            .unwrap()
    };
    let good = basic("api", HOMEPAGE_TOKEN);
    let h = Harness::new();
    let reply = h.send(request(basic("api", "wrong"), good.clone())).await;
    assert_error(&reply, 401);
    assert!(h.recorder.calls.lock().unwrap().is_empty());
    let reply = h.send(request(good, basic("api", "wrong"))).await;
    assert_queued(&reply);
}

/// T3: a valid token outside its scope. Each token is bound to its path
/// domains, its from domains and (when set) its from addresses; another
/// application's token, path or sender is a 403 before any submission.
#[tokio::test]
async fn tokens_stay_inside_their_scope() {
    let homepage = basic("api", HOMEPAGE_TOKEN);
    let podcast = basic("api", PODCAST_TOKEN);
    let recorder = basic("api", RECORDER_TOKEN);
    let podcast_from = without(&["from"], &[("from", "noreply@mg.python-podcast.de")]);
    let cases: Vec<(&str, &str, Fields<'_>, &str)> = vec![
        // The podcast token on the homepage's path and with its sender.
        (
            &podcast,
            "mg.wersdoerfer.de",
            MINIMUM.to_vec(),
            "token not allowed for path domain 'mg.wersdoerfer.de'",
        ),
        (
            &podcast,
            "mg.python-podcast.de",
            MINIMUM.to_vec(),
            "token not allowed for from domain 'wersdoerfer.de'",
        ),
        // The homepage token with the podcast's sender on its own path.
        (
            &homepage,
            "mg.wersdoerfer.de",
            podcast_from.clone(),
            "token not allowed for from domain 'mg.python-podcast.de'",
        ),
        // A domain-only token is still bound to its domains.
        (
            &recorder,
            "mg.python-podcast.de",
            podcast_from,
            "token not allowed for path domain 'mg.python-podcast.de'",
        ),
        // Path domains: no parent, child, suffix or trailing-dot match.
        (
            &homepage,
            "wersdoerfer.de",
            MINIMUM.to_vec(),
            "token not allowed for path domain 'wersdoerfer.de'",
        ),
        (
            &homepage,
            "x.mg.wersdoerfer.de",
            MINIMUM.to_vec(),
            "token not allowed for path domain 'x.mg.wersdoerfer.de'",
        ),
        (
            &homepage,
            "mg.wersdoerfer.de.evil.test",
            MINIMUM.to_vec(),
            "token not allowed for path domain 'mg.wersdoerfer.de.evil.test'",
        ),
        (
            &homepage,
            "mg.wersdoerfer.de.",
            MINIMUM.to_vec(),
            "token not allowed for path domain 'mg.wersdoerfer.de.'",
        ),
    ];
    for (auth, domain, fields, message) in cases {
        let h = Harness::new();
        let reply = refused(&h, Some(auth), domain, &fields).await;
        assert_error(&reply, 403);
        assert_eq!(reply.json["message"], message, "{domain} {fields:?}");
        assert_eq!(h.records("request")[0]["result"], "policy_error");
    }
}

/// T4: `from` values that try to pass the allowlist with another sender:
/// display names and comments holding the allowed address, lookalike and
/// suffix domains, Unicode confusables, sub-addresses, address lists and
/// literal or quoted forms. The address-list token (`homepage`) allows
/// only `jochen-homepage@wersdoerfer.de`; the domain-only token
/// (`recorder`) allows any local part at `wersdoerfer.de`.
#[tokio::test]
async fn sender_spoofing_attempts_are_refused() {
    let homepage = basic("api", HOMEPAGE_TOKEN);
    let recorder = basic("api", RECORDER_TOKEN);
    let cases: Vec<(&str, &str, u16)> = vec![
        // The allowed address only in a display name or comment.
        (
            &homepage,
            "\"jochen-homepage@wersdoerfer.de\" <evil@evil.test>",
            403,
        ),
        (
            &homepage,
            "evil@evil.test (jochen-homepage@wersdoerfer.de)",
            403,
        ),
        (
            &homepage,
            "jochen-homepage@wersdoerfer.de <evil@evil.test>",
            400,
        ),
        // Two addresses in one value, or a second `@`.
        (
            &homepage,
            "jochen-homepage@wersdoerfer.de, evil@evil.test",
            400,
        ),
        (
            &homepage,
            "<jochen-homepage@wersdoerfer.de>, <evil@evil.test>",
            400,
        ),
        (&homepage, "jochen-homepage@wersdoerfer.de@evil.test", 400),
        (&homepage, "jochen-homepage@evil.test@wersdoerfer.de", 400),
        // Suffix, trailing dot, IP literal, quoted local part.
        (&homepage, "jochen-homepage@wersdoerfer.de.evil.test", 403),
        (&homepage, "jochen-homepage@wersdoerfer.de.", 400),
        (&homepage, "jochen-homepage@[127.0.0.1]", 400),
        (&homepage, "\"jochen-homepage\"@wersdoerfer.de", 400),
        // Other local parts of the allowed domain.
        (&homepage, "jochen-homepage-evil@wersdoerfer.de", 403),
        (&homepage, "jochen-homepage+evil@wersdoerfer.de", 403),
        (&homepage, "jochen@wersdoerfer.de", 403),
        // Unicode confusables: Cyrillic `е`, fullwidth `ｗ`, a zero-width
        // joiner; the IDN `wersdörfer.de` is another domain.
        (&homepage, "jochen-homepage@w\u{435}rsdoerfer.de", 400),
        (&homepage, "jochen-homepage@\u{ff57}ersdoerfer.de", 400),
        (&homepage, "jochen-homepage@wers\u{200d}doerfer.de", 400),
        (&recorder, "x@wersd\u{f6}rfer.de", 403),
        (&recorder, "x@xn--wersdrfer-47a.de", 403),
        // A domain-only token: no subdomain, parent or lookalike.
        (&recorder, "x@sub.wersdoerfer.de", 403),
        (&recorder, "x@doerfer.de", 403),
        (&recorder, "x@de", 400),
        // Control characters next to an allowed address.
        (&homepage, "jochen-homepage@wersdoerfer.de\0", 400),
        (&homepage, "jochen-homepage@wersdoerfer.de\u{2028}", 400),
    ];
    for (auth, from, status) in cases {
        let h = Harness::new();
        let fields = without(&["from"], &[("from", from)]);
        let reply = refused(&h, Some(auth), "mg.wersdoerfer.de", &fields).await;
        assert_error(&reply, status);
        let result = if status == 403 {
            "policy_error"
        } else {
            "bad_request"
        };
        assert_eq!(h.records("request")[0]["result"], result, "{from:?}");
    }
}

/// T4: case is not a bypass but is normalised. The allowlist compares the
/// lowercased local part and the A-label domain, so these are the allowed
/// sender; the From header keeps the spelling of the request.
#[tokio::test]
async fn sender_case_variants_match_the_allowed_address() {
    for from in [
        "JOCHEN-HOMEPAGE@WERSDOERFER.DE",
        "Jochen-Homepage@Wersdoerfer.De",
        "<jochen-homepage@WERSDOERFER.de>",
    ] {
        let h = Harness::new();
        let fields = without(&["from"], &[("from", from)]);
        assert_queued(&h.homepage(encode(Encoding::Urlencoded, &fields)).await);
        let calls = h.recorder.calls.lock().unwrap();
        let message = String::from_utf8_lossy(&calls[0].formatted).to_lowercase();
        assert!(
            message.contains("from: jochen-homepage@wersdoerfer.de\r\n"),
            "{from}: {message}"
        );
    }
}

/// T6: `h:*` headers that would set the sender, the recipients, the
/// relay's own headers or the MIME structure are refused case-insensitively.
#[tokio::test]
async fn identity_and_structure_headers_are_refused() {
    for name in [
        "h:From",
        "h:FROM",
        "h:from",
        "h:Sender",
        "h:Return-Path",
        "h:Resent-From",
        "h:resent-sender",
        "h:To",
        "h:Cc",
        "h:BCC",
        "h:Subject",
        "h:Message-Id",
        "h:Date",
        "h:Received",
        "h:MIME-Version",
        "h:Content-Type",
        "h:Content-Transfer-Encoding",
        "h:Disposition-Notification-To",
        "h:Return-Receipt-To",
    ] {
        let h = Harness::new();
        let fields = with(&[(name, "evil@evil.test")]);
        let reply = refused(
            &h,
            Some(&basic("api", HOMEPAGE_TOKEN)),
            "mg.wersdoerfer.de",
            &fields,
        )
        .await;
        assert_error(&reply, 400);
        assert_eq!(
            h.records("request")[0]["error_class"],
            "DangerousHeaderError",
            "{name}"
        );
    }
}

/// T6: line breaks and other control characters in every field that ends
/// up in a header are a 400 before the submitter, whatever the field.
#[tokio::test]
async fn line_breaks_in_header_fields_are_refused() {
    let cases: Vec<Vec<(&str, &str)>> = vec![
        without(
            &["to"],
            &[("to", "admin@wersdoerfer.de\rBcc: evil@evil.test")],
        ),
        without(
            &["to"],
            &[("to", "admin@wersdoerfer.de\u{85}Bcc: evil@evil.test")],
        ),
        without(
            &["to"],
            &[("to", "Admin\r\nBcc: evil@evil.test <admin@wersdoerfer.de>")],
        ),
        with(&[("cc", "c@example.org\nBcc: evil@evil.test")]),
        with(&[("bcc", "b@example.org\r\nX-Injected: 1")]),
        without(
            &["from"],
            &[(
                "from",
                "Jochen\r\nBcc: evil@evil.test <jochen-homepage@wersdoerfer.de>",
            )],
        ),
        without(
            &["subject"],
            &[("subject", "hi\u{2029}Bcc: evil@evil.test")],
        ),
        without(&["subject"], &[("subject", "hi\0")]),
        with(&[("h:Reply-To", "a@example.org\nBcc: evil@evil.test")]),
        with(&[("h:X-Custom", "ok\rBcc: evil@evil.test")]),
        with(&[("h:X-Custom", "ok\u{2028}x")]),
        with(&[("h:X-Custom", "ok\0x")]),
        with(&[("h:X-Custom\r\nBcc", "evil@evil.test")]),
        with(&[("h:X-Custom: x\r\nBcc", "evil@evil.test")]),
        // Encoded words that decode to a line break in a display name (D-16).
        without(
            &["to"],
            &[(
                "to",
                "=?utf-8?q?A=0D=0ABcc:_evil@evil.test?= <admin@wersdoerfer.de>",
            )],
        ),
    ];
    for fields in &cases {
        for encoding in ENCODINGS {
            let h = Harness::new();
            let reply = h.homepage(encode(encoding, fields)).await;
            assert_error(&reply, 400);
            assert!(
                h.recorder.calls.lock().unwrap().is_empty(),
                "{fields:?} reached the submitter"
            );
        }
    }
}

/// T6: an upload's filename and content type never become headers of their
/// own: line breaks in an ASCII filename are a 400, and a content type is
/// reduced to `main/sub` (parameters dropped, containers refused).
#[tokio::test]
async fn upload_metadata_cannot_inject_headers() {
    // A CR or LF cannot get past the multipart parser (the part header line
    // ends there); the other line boundaries reach `mime::upload_part`.
    for (filename, layer) in [
        ("a\rBcc: evil@evil.test.txt", "BadRequestError"),
        ("a\x0bBcc: evil@evil.test.txt", "HeaderInjectionError"),
        ("a\x0cBcc: evil@evil.test.txt", "HeaderInjectionError"),
        ("a\x1cBcc: evil@evil.test.txt", "HeaderInjectionError"),
    ] {
        let h = Harness::new();
        let files = [("attachment", filename, "text/plain", b"x".as_slice())];
        assert_error(&h.homepage(multipart(&MINIMUM, &files)).await, 400);
        assert!(h.recorder.calls.lock().unwrap().is_empty());
        assert_eq!(
            h.records("request")[0]["error_class"],
            layer,
            "{filename:?}"
        );
    }

    for content_type in [
        "text/plain; charset=\"x\"; Bcc: evil@evil.test",
        "multipart/mixed; boundary=evil",
        "message/rfc822",
    ] {
        let h = Harness::new();
        let files = [("attachment", "a.txt", content_type, b"x".as_slice())];
        assert_queued(&h.homepage(multipart(&MINIMUM, &files)).await);
        let calls = h.recorder.calls.lock().unwrap();
        let message = String::from_utf8_lossy(&calls[0].formatted).to_lowercase();
        // Only fixed strings: the Message-Id and boundaries are random.
        assert!(
            !message.contains("evil@evil.test"),
            "{content_type}: {message}"
        );
        assert!(!message.contains("\r\nbcc:"), "{content_type}: {message}");
        assert!(!message.contains("boundary=evil"), "{content_type}");
        assert!(!message.contains("message/rfc822"), "{content_type}");
        assert!(
            message.contains("content-type: application/octet-stream")
                || message.contains("content-type: text/plain\r\n"),
            "{content_type}: {message}"
        );
    }
}

/// T5 and T1: the envelope. `MAIL FROM` is the configured envelope sender,
/// never the request's `from` or a header; the recipients are exactly the
/// parsed `to`/`cc`/`bcc`; a Bcc address never appears in the message.
#[tokio::test]
async fn the_envelope_comes_from_the_configuration_and_the_recipient_fields() {
    let (h, server) = smtp_harness(json!({}), settings()).await;
    let fields = with(&[
        ("bcc", "hidden@example.net"),
        ("h:Reply-To", "reply@example.org"),
    ]);
    assert_queued(&h.homepage(encode(Encoding::Urlencoded, &fields)).await);
    let sessions = server.sessions();
    assert_eq!(sessions.len(), 1);
    let session = &sessions[0];
    assert!(session.tls);
    // `smtp::tests::submitter` configures this envelope sender.
    assert_eq!(session.mail_from.as_deref(), Some("sender@example.com"));
    assert_eq!(
        session.data_for.as_deref(),
        Some(
            [
                "admin@wersdoerfer.de".to_owned(),
                "hidden@example.net".to_owned()
            ]
            .as_slice()
        )
    );
    let message = String::from_utf8_lossy(session.message.as_deref().unwrap()).to_lowercase();
    assert!(message.contains("from: jochen <jochen-homepage@wersdoerfer.de>"));
    assert!(!message.contains("hidden@example.net"), "{message}");
    assert!(!message.contains("\r\nbcc:"), "{message}");
}

/// T7: the relay never fetches anything a request names. An `attachment`
/// or `inline` given as text (a URL) is a 400; remote references in the
/// HTML are passed on as text, unchanged and unfetched (the crate has no
/// HTTP client).
#[tokio::test]
async fn remote_content_is_never_fetched() {
    for field in ["attachment", "inline"] {
        let h = Harness::new();
        let fields = with(&[(field, "http://169.254.169.254/latest/meta-data/")]);
        assert_error(
            &h.homepage(encode(Encoding::Urlencoded, &fields)).await,
            400,
        );
        assert!(h.recorder.calls.lock().unwrap().is_empty());
    }
    let html = "<img src=\"http://127.0.0.1:8085/health\">";
    let h = Harness::new();
    assert_queued(
        &h.homepage(encode(Encoding::Urlencoded, &with(&[("html", html)])))
            .await,
    );
    let calls = h.recorder.calls.lock().unwrap();
    assert!(String::from_utf8_lossy(&calls[0].formatted).contains("127.0.0.1:8085/health"));
    // The route made no request of its own: only the one submission.
    assert_eq!(calls.len(), 1);
}

/// T8: the records carry labels, counts and the sender, never the
/// credentials, the recipients, the subject, the bodies, custom header
/// values or upload names; a partial refusal logs refused domains only.
#[tokio::test]
async fn records_never_carry_message_content_or_recipients() {
    let h = Harness::new();
    *h.recorder.outcome.lock().unwrap() = Ok(vec![Refusal {
        address: "refused-local@example.net".to_owned(),
        code: Some(550),
    }]);
    let fields = without(
        &["to", "subject", "text"],
        &[
            ("to", "visible-recipient@wersdoerfer.de"),
            ("cc", "copied-recipient@example.org"),
            ("bcc", "refused-local@example.net"),
            ("subject", "secret-subject"),
            ("text", "secret-text-body"),
            ("html", "<p>secret-html-body</p>"),
            ("h:X-Secret", "secret-header-value"),
        ],
    );
    let files = [(
        "attachment",
        "secret-file-name.txt",
        "text/plain",
        b"secret-file-data".as_slice(),
    )];
    let auth = basic("api", HOMEPAGE_TOKEN);
    let mut request = Request::builder()
        .method("POST")
        .uri("/v3/mg.wersdoerfer.de/messages");
    let body = multipart(&fields, &files);
    request = request
        .header("content-type", body.content_type.unwrap())
        .header("authorization", &auth);
    let reply = h.send(request.body(Body::from(body.body)).unwrap()).await;
    assert_queued(&reply);
    let lines = h.logs.lock().unwrap().join("\n");
    for secret in [
        HOMEPAGE_TOKEN,
        auth.as_str(),
        auth.trim_start_matches("Basic "),
        SMTP_PASSWORD,
        "visible-recipient",
        "copied-recipient",
        "refused-local",
        "secret-subject",
        "secret-text-body",
        "secret-html-body",
        "secret-header-value",
        "secret-file-name",
        "secret-file-data",
    ] {
        assert!(!lines.contains(secret), "{secret} in {lines}");
    }
    let refusal = &h.records("recipients_refused")[0];
    assert_eq!(
        refusal["refused"],
        json!([{"domain": "example.net", "code": 550}])
    );
    assert_eq!(h.records("request")[0]["recipient_count"], 3);

    // A failed authentication logs no part of what was sent.
    let h = Harness::new();
    let wrong = basic("api", "wrong-secret-token");
    let reply = refused(&h, Some(&wrong), "mg.wersdoerfer.de", &MINIMUM).await;
    assert_error(&reply, 401);
    let lines = h.logs.lock().unwrap().join("\n");
    assert!(!lines.contains("wrong-secret-token"), "{lines}");
    assert!(
        !lines.contains(wrong.trim_start_matches("Basic ")),
        "{lines}"
    );
}

/// T10: replay. The relay keeps no request state, so a replayed request is
/// sent again with a new Message-Id; protection is TLS at the proxy and the
/// token's narrow scope (`docs/security.md`). This test pins that
/// behaviour so a change to it is a deliberate one.
#[tokio::test]
async fn a_replayed_request_is_a_new_message() {
    let h = Harness::new();
    let first = h.homepage(encode(Encoding::Urlencoded, &MINIMUM)).await;
    let second = h.homepage(encode(Encoding::Urlencoded, &MINIMUM)).await;
    assert_queued(&first);
    assert_queued(&second);
    assert_ne!(first.json["id"], second.json["id"]);
    assert_eq!(h.recorder.calls.lock().unwrap().len(), 2);
}
