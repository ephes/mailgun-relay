# API Compatibility

This document defines the Mailgun subset implemented for Django Anymail compatibility. Behavior was verified against the upstream `django-anymail` 15.x Mailgun backend during implementation; re-verify against these references when bumping Anymail:

- Anymail Mailgun docs: https://anymail.dev/en/stable/esps/mailgun/
- Mailgun Messages API docs: https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages

## Compatibility Goal

The target client is `django-anymail` using:

```python
EMAIL_BACKEND = "anymail.backends.mailgun.EmailBackend"
ANYMAIL = {
    "MAILGUN_API_KEY": "...",
    "MAILGUN_API_URL": "https://mailgun.home.xn--wersdrfer-47a.de/v3",
    "MAILGUN_SENDER_DOMAIN": "...",
}
```

Anymail's docs state that `MAILGUN_API_URL` is the base URL and should not include the sender domain or `/messages`. The service should therefore expose endpoints under `/v3`.

## Authentication

Mailgun-style Basic auth:

- Username: `api`
- Password: service-issued token

Behavior:

- Missing or invalid auth returns `401`, also for malformed credentials
  (wrong scheme, invalid base64, non-ASCII bytes, invalid UTF-8, no `:`).
- Basic credentials are capped at 4,096 decoded UTF-8 bytes (including `api:`)
  and 5,464 encoded ASCII bytes, inclusive. The whole Authorization value,
  including scheme and surrounding whitespace, is capped at 5,470 wire bytes.
  Python and Rust reject excess before Base64 allocation or token hashing,
  including decoded excess that fits in the last encoded quartet. Direct
  authentication helpers enforce these limits too; excess returns the same 401.
- Username other than `api` returns `401`.
- Valid token with disallowed domain or sender returns `403`.
- Responses must not reveal whether a token label exists.
- `WWW-Authenticate` should use Mailgun parity, `Basic realm="MG API"`, unless implementation testing shows Anymail does not care and another realm is deliberately chosen.

## Endpoint: `POST /v3/{domain}/messages`

Purpose: Main Anymail send endpoint for form-based messages.

Content type: multipart form data or compatible form submission as sent by Anymail.

Path:

- `{domain}` is the Mailgun sender domain selected by Anymail.
- The domain must be allowed by the authenticated token.
- IDN domains should be configured in punycode.

Required fields:

- `from`: sender address with optional display name.
- At least one recipient across `to`, `cc`, or `bcc`.
- At least one non-empty `text` or `html`. A request that carries only empty ones (`text=""`, `html=""`, or `text=""` with only `amp-html`) is `400`; `text=""` with a non-empty `html` omits the plain-text part.

At field admission, unknown form keys return `{"message":"unknown field"}`
with HTTP 400;
unsupported `v:*`, `o:*`, `t:*`, `template` and `recipient-variables` keys return
`{"message":"unsupported field"}`. Both runtimes use these fixed, value-free
categories regardless of key length or control characters, before SMTP. No
caller-supplied field-name description is included in these refusals. Earlier
multipart decoder limits can instead return the existing fixed `malformed form`
refusal (for example, for a near-request-limit multipart header).

Supported fields:

| Field | Support | Notes |
| --- | --- | --- |
| `from` | Yes | Parsed and validated against token sender policy. |
| `to` | Yes | Repeated values supported. Included in headers and SMTP envelope. |
| `cc` | Yes | Repeated values supported. Included in headers and SMTP envelope. |
| `bcc` | Yes | Repeated values supported. SMTP envelope only; no BCC header. |
| `subject` | Yes | Header injection rejected. |
| `text` | Yes | Text body. |
| `html` | Yes | HTML body, combined with text as multipart alternative when both exist. |
| `amp-html` | Yes | Added as `text/x-amp-html` in `multipart/alternative`, after plain text and before the HTML fallback when those parts are present. Inline files stay with the HTML part in `multipart/related`. |
| `h:Reply-To` | Yes | Parsed via RFC 5322 address-list parser (quoted commas in display names preserved). |
| `h:*` custom headers | Yes | Strict ASCII header-name regex (full match), a 76-byte name limit excluding `h:`, CR/LF rejection and a dangerous-header denylist. An oversize name returns `400` with diagnostic class `HeaderTooLongError` before MIME assembly or SMTP. `h:In-Reply-To` and `h:References` must be ASCII after RFC 2047 decoding (`400` otherwise; such a value used to fail the SMTP submission with `502`). |
| `attachment` | Yes | Per-file and aggregate body-size caps. A declared `multipart/*` or `message/*` content type is sent as `application/octet-stream`, because the upload is always one leaf part. |
| `inline` | Yes | Counted toward the same `max_attachments` cap as `attachment`. Sent with `Content-ID: <filename>` (RFC 2392 angle-bracket form, as Mailgun does), so HTML references it as `cid:filename`. With an HTML body, inline parts are grouped with it in `multipart/related`; with a text-only body they go into the top-level `multipart/mixed` with `Content-Disposition: inline`. Filenames with control characters, `<>`, or leading/trailing whitespace are rejected with 400 (the filename is never rewritten). Same `multipart/*` / `message/*` downgrade as `attachment`. |
| `o:*` options | Reject (400) | Phase-0 audit found neither homepage nor python-podcast emits any in default-settings sends; adding selective accept-and-ignore is a future change with its own audit. |
| `v:*` variables | Reject (400) | No events/templates metadata support. |
| `recipient-variables` | Reject (400) | Batch personalization out of scope. |
| `template` / `t:*` | Reject (400) | Stored Mailgun templates out of scope. |

## Duplicate fields and upload metadata

Both implementations reject duplicate inline Content-IDs with HTTP 400 before
SMTP. HTTP inline IDs come from filenames. For callers of the Python MIME
helper, an explicit ID may be bare or enclosed in a single pair of angle
brackets, with optional surrounding whitespace. A single opening or closing
bracket is invalid. IDs are compared exactly after normalization. Ordinary
attachments may share filenames. Upload filenames and raw content types
(including parameters, after empty-value defaults) must each fit
`MAX_HEADER_VALUE_LENGTH` Unicode code points, inclusive. Oversize metadata
returns a fixed, value-free 400 before MIME assembly. Unicode filenames within
the limit remain supported.

Python MIME upload rejections return HTTP 400 with a fixed diagnostic:
`invalid inline filename`, `invalid inline file`, or `invalid attachment`.
The response omits upload filenames and email library exception text.

`from` must occur exactly once. `subject`, `text`, `html` and `amp-html` may each
occur at most once, even for identical or empty values. Every `h:*` name is unique
case-insensitively, including extension headers such as `X-Tag`; duplicates return
400 at form admission. Repeated `to`, `cc`, `bcc`, `attachment` and `inline` fields
remain supported subject to existing limits and inline-ID uniqueness.

Both runtimes allow up to 200,000 UTF-8 bytes in the decoded `amp-html` field,
measured before MIME construction. Oversized AMP markup returns HTTP 413 with
`{"message":"amp-html exceeds 200000 UTF-8 bytes"}` before SMTP submission.
The configured request and aggregate body limits still apply, including to
ordinary `text` and `html`. [AMP for Email format](https://amp.dev/documentation/guides-and-tutorials/email/learn/email-spec/amp-email-format)

Uploaded leaf media types in both runtimes use two ASCII RFC 7230 tokens of
1–127 characters each. Parameters are stripped; malformed types and container
`multipart/*` or `message/*` types become `application/octet-stream`, preserving
the filename and bytes. The raw metadata length limit applies before stripping.

### Addresses

Every address field (`from`, `to`, `cc`, `bcc`, `h:Reply-To`) holds RFC 5322 mailboxes; `to`, `cc` and `bcc` take exactly one per value.

- **IDN domains are sent as A-labels.** `foo@wersdörfer.de` and `foo@xn--wersdrfer-47a.de` are the same address; both appear as `foo@xn--wersdrfer-47a.de` in the message headers and in `RCPT TO`, and duplicates of the two spellings collapse to one envelope recipient. The relay never submits with SMTPUTF8; the generated message headers are ASCII.
- **Non-ASCII local parts are rejected with `400`** (`jörg@example.org`, SMTPUTF8/EAI addresses). For `from` this happens at the sender-policy step, after the path-domain check; for the other fields when the message is built, after the subject, custom-header and recipient-count checks.
- **Display names are decoded.** RFC 2047 encoded words in display names are decoded and re-encoded. A `to`, `cc` or `h:Reply-To` display name that decodes to CR or LF is `400`.
- `MAILGUN_RELAY_ENVELOPE_SENDER` follows the same rule at startup: an IDN domain is converted to its A-label, a non-ASCII local part stops the process, empty means the null sender `MAIL FROM:<>`.

Success response:

```json
{
  "id": "generated-message-id",
  "message": "Queued. Thank you."
}
```

The `id` should be unique enough for logs and client correlation. Prefer generating one Message-Id-shaped value, using it as the SMTP `Message-Id:` header, and returning the same value in the JSON response. Final SMTP delivery status is not represented by this response.

### Partial recipient refusal

The submission server can accept a message for some envelope recipients and refuse others at `RCPT TO`. `smtplib` raises only when *every* recipient is refused (503 if any refusal is 4xx, otherwise 502; see the error table); otherwise it returns the refused ones, and the relay acts on them:

- **Default: `200` with the unchanged success body.** The message has already been accepted for the other recipients, so an error status would make a retrying caller send it to them twice. Real Mailgun has no synchronous partial-failure response either: its only 200 is `{"id", "message": "Queued. Thank you."}`, and per-recipient rejections surface later through events and webhooks. `django-anymail` parses exactly that shape (it requires `id` and a `message` starting with `Queued`) and marks every recipient `queued`; the relay therefore does not add fields to the body.
- **Always logged.** The relay emits one `WARNING` record `event=recipients_refused` with `refused_count` and a `refused` list of `{domain, code}` pairs, and the request record gets `refused_count` and `result=partial_refusal`. Local parts of refused addresses and the SMTP reply text (which usually echoes the address) are never logged.
- **Opt-in hard failure: `MAILGUN_RELAY_FAIL_ON_PARTIAL_REFUSAL=true`** maps a partial refusal to `502` with `{"message": "Upstream SMTP refused N of M recipients; the message was sent to the others"}`. Anymail raises `AnymailRequestsAPIError` for it. Callers that enable this must not blindly retry, because the accepted recipients already have the message.

Recipients the server accepts but later bounces are outside the relay's view; those bounces go to the envelope sender like any other SMTP submission.

## Endpoint: `POST /v3/{domain}/messages.mime`

Status: not implemented. Out of scope.

Purpose: Accept a raw MIME message if Anymail or future callers require it.

Phase-0 source audit confirmed neither `homepage` nor `python-podcast` uses `send_mime_message` or raw MIME submission; the endpoint will only be added when a real caller needs it.

Requirements before implementation:

- Verify Anymail uses this endpoint for a real current app behavior.
- Audit `homepage` and `python-podcast` for `send_mime_message`, raw MIME usage, or other code paths that could require this endpoint.
- Define how envelope recipients are provided and validated.
- Parse MIME headers to enforce `from` policy.
- Preserve BCC privacy.
- Enforce message size and header limits.

Until implemented, return a clear unsupported response such as `404` or `400` as chosen during implementation and documented in tests.

## Unsupported Field Policy

MVP compatibility uses an allowlist/reject policy:

- Accept documented core fields and selected safe `h:*` headers.
- Accept and ignore only a documented allowlist of `o:*` fields that Phase 0 proves are emitted by current Anymail usage and harmless as no-ops.
- Reject unknown `o:*` fields and behavior-affecting `o:*` fields, such as scheduled delivery or delivery security options, unless a later design explicitly implements them.
- Reject `v:*`, `recipient-variables`, `template`, and `t:*` fields.

Before coding, verify exact `o:*` keys emitted by ordinary `EmailMessage`, `EmailMultiAlternatives`, attachments, extra headers, tags, metadata, tracking flags, and any Anymail mixins used by the two target apps.

## Error Mapping

Verified against `django-anymail` 15.x (`anymail/backends/mailgun.py`,
`anymail/backends/base_requests.py`): every non-2xx response raises the same
`AnymailRequestsAPIError` with the HTTP status code on the exception. The
table below is therefore the contract the relay implements:

| Condition | HTTP status | Notes |
| --- | --- | --- |
| Missing auth | 401 | Include `WWW-Authenticate` header if framework supports it. |
| Invalid username/token | 401 | Do not reveal token existence. |
| Token not allowed for path domain | 403 | Authenticated but forbidden. |
| Token not allowed for `from` sender | 403 | Authenticated but forbidden. |
| Missing required field | 400 | Include concise field error. |
| Malformed address/header | 400 | Reject header injection. |
| Unsupported required feature | 400 | Avoid pretending unsupported Mailgun behavior worked. |
| Rust form upload exceeds 30 seconds total | 408 | No MIME or SMTP; admission is released. |
| Request too large | 413 | Body, attachment, or recipient limits. |
| Rate limited | 429 | Per-token or global. |
| Admission capacity exhausted before body parsing | 503 | `Relay busy; retry later`; no send attempted. Retry with backoff. No application wait queue. |
| SMTP temporary failure (4xx sender/HELO/DATA or any all-refused recipient reply), timeout/connection refused | 503 | Anymail does not retry on its own; the caller surfaces the status as `AnymailRequestsAPIError.status_code`. |
| SMTP permanent rejection (5xx response; all recipients refused without any 4xx reply) | 502 | Same Anymail exception shape; permanent vs. temporary is informational for callers that inspect `.status_code`. |
| Some (not all) recipients refused | 200 (default) or 502 | 200 with the normal success body plus a `recipients_refused` WARNING log; 502 only with `MAILGUN_RELAY_FAIL_ON_PARTIAL_REFUSAL=true`. See *Partial recipient refusal*. |
| SMTP authentication failure (relay → backend) | 502 | Treated as a permanent upstream failure. Never exposes the credential. |
| Internal error | 500 | Body is `{"message": "Internal Server Error"}`; no secrets or message bodies in response. |

Both runtimes emit the single structured `event=request` record at ERROR for
HTTP 5xx, including internal errors, upstream failures, overload and strict
partial refusal; other statuses use INFO. `MAILGUN_RELAY_LOG_LEVEL=WARNING`
therefore suppresses ordinary request records while retaining failures. The
safe field set and separate partial-refusal WARNING are unchanged. Configured
token labels must not equal the SMTP password or any loaded token digest
(digest comparison trims whitespace and ignores case); startup refuses these
with positional, value-free diagnostics before labels can enter logs.

Response body shape is `{"message": "<human readable>"}` on all non-2xx. `django-anymail`'s `AnymailRequestsAPIError` stores the full body so callers can log it; the relay never includes credential material in that message.

Python supervisor/control-flow exceptions (`KeyboardInterrupt`, `SystemExit`,
`asyncio.CancelledError`) propagate from the synchronous SMTP helper after its
owned socket cleanup, including when raised during cleanup. Constructor failures
own no returned SMTP object. Only operational `Exception` failures become
`SmtpSubmitError`; cancellation is never a delivery-failure category.

Once DATA is accepted, an operational failure of QUIT setup, QUIT or connection
close preserves the accepted result, including partial-refusal policy. Cleanup is attempted without retrying
the send. A safe `smtp_cleanup_failed` warning records only the exception class,
never SMTP reply text or recipient addresses. Pre-acceptance failures retain their
original error category even if cleanup also fails. If the QUIT timer cannot
start, the adapter skips QUIT and still closes the owned socket.

The retained Python rollback adapter also isolates multipart teardown: under a
cancellation shield the request attempts each parsed upload's close once after
its workers finish, even after validation or submission fails. A close failure
produces an `upload_cleanup_failed` warning with only the exception class
(capped at 80 characters), preserving the HTTP result and attempting the
remaining uploads.
Failed resources are not retried; a close attempt cannot guarantee release if
the underlying file operation itself fails.

Python request, partial-refusal and cleanup logging is best effort. Exceptions
from a custom handler/filter/formatter do not change the submission result or
retain admission capacity. A failed log call attempts only the fixed stderr
line `{"event":"diagnostic_logging_failed"}`, without record fields or exception
details; failure of that fallback is ignored. The send is never retried.
The JSON formatter uses this fallback when a diagnostic field contains a
nonfinite number.

## Compatibility Assumptions to Verify

- Anymail posts to `{MAILGUN_API_URL}/{sender_domain}/messages`.
- Anymail accepts the Mailgun success body with `id` and `message`.
- Anymail does not require any domains API calls for sending.
- Existing apps do not depend on Mailgun templates, tracking, webhooks, stored metadata, scheduled delivery, tags, test mode, or batch personalization.
- Existing app attachments, if any, are represented through standard Mailgun `attachment` fields with filenames.
- Inspect Anymail's current `MAILGUN_SENDER_DOMAIN` enforcement, including warnings or errors for path-domain and `from`-domain mismatches, before relying on cross-domain mapping.
- `mg.python-podcast.de` is not part of the currently documented backend-hosted domain list. Token policy and app migration must not assume it is accepted by the self-hosted mail stack without a separate ops decision.

## Unsupported Mailgun Features

The service is not expected to implement:

- Domains API.
- Events API.
- Webhooks or webhook signing.
- Tracking, opens, clicks, unsubscribes, suppressions, complaints, or analytics.
- Stored templates or template rendering.
- Batch sending and recipient variables.
- Inbound routing.
- Message search.
- Dedicated IP pools or delivery-time optimization.
- Mailgun account, key, billing, or user management.
- Mailgun-specific archive, test mode, or advanced delivery options unless a later planning slice approves a narrow subset.

## Rust acquisition deadlines

Rust bounds form-body acquisition to 30 seconds total after admission, including
trickling uploads. A full 25 MiB upload needs roughly 7 Mbit/s sustained throughput. Expiry returns HTTP 408 (`BodyTimeoutError`), drops the body
and releases the admission slot before MIME or SMTP. Overload still returns 503
before reading the body. Python rollback has no application body deadline.
Rust also uses one `MAILGUN_RELAY_SMTP_TIMEOUT_S` budget for DNS resolution and
all TCP connection attempts together, sharing remaining time equally among
remaining addresses so a stalled address permits fallback; expiry is retryable HTTP 503. Later SMTP
socket operations retain their individual timeouts. In addition,
`MAILGUN_RELAY_SMTP_SESSION_TIMEOUT_S` (default 120 seconds, finite and
`0 < value <= 1e9`) bounds DNS, connect, banner, EHLO, STARTTLS, AUTH and DATA
through the delivery outcome together. Expiry closes the connection and returns
retryable HTTP 503, releasing admission. If DATA was interrupted before its final
250 was received, delivery is ambiguous: the upstream may have accepted it;
retrying can duplicate mail. There is no automatic retry.

QUIT has a separate total budget of `min(SMTP_TIMEOUT_S, 5 seconds)` and never
changes an already determined outcome, including accepted DATA. Rust also caps
inbound wire bytes at 16 MiB per connection, counted before TLS decryption and
including the handshake, TLS overhead, replies and cleanup. This conservative
ceiling bounds lettre's allocation even for a reply without a newline; it can
refuse unusually verbose sessions (including those with raised recipient limits).
Exhaustion maps to the same safe transport failure (503 before the outcome;
cleanup warning only after acceptance), without logging reply contents. OS socket
buffers and TLS's bounded internal buffers are separate from this wire-read cap.
Python rollback now also validates and applies `SMTP_SESSION_TIMEOUT_S` (the
same default and bounds) through the SMTP outcome, including TCP attempts,
trickling replies, STARTTLS and recipient/DATA operations. A session-owned socket
shutdown interrupts blocking reads and TLS; QUIT has its own
`min(SMTP_TIMEOUT_S, 5 seconds)` total budget. Confirmed DATA acceptance survives
a later deadline check or cleanup failure once the complete final 250 reply
has been read. A timeout or truncated reply without a complete final DATA
result returns HTTP 503 and can leave delivery uncertain. Neither runtime
automatically retries it.
Python's blocking libc DNS calls (remote resolution and local EHLO hostname
lookup) cannot be interrupted by socket shutdown. Their elapsed time consumes
the budget and late results are refused before further SMTP work; admission stays
owned until resolution actually returns. Python has no Rust wire-byte ceiling.
These source changes require an explicit runtime update; no deployment is performed.

Tokio's system resolver may keep a blocking `getaddrinfo` call alive after its
waiting future expires. The deadline releases request admission but cannot
cancel that OS call; repeated resolver stalls can pressure the blocking pool.

## Secret file identity and bounds

Both runtimes open secrets once with nonblocking and no-follow flags, validate
that descriptor is a regular file with mode 0640 or stricter, and read at most
1 MiB (1,048,576 bytes). Oversize/invalid UTF-8 documents fail startup with
value-free errors. A final-component symlink is refused; operator-controlled
parent directories may contain symlinks. Path replacement after open cannot
substitute unchecked file bytes. This interface targets the supported POSIX
relay environments; it performs no real secret or host access in tests.

Each token digest must be unique after trimming and lowercase normalization,
even across labels with different scopes. Use one credential per policy identity;
rotation must use a new digest. Duplicate digests fail startup with positional, value-free diagnostics;
this check never prints a digest. This intentionally rejects
previously ambiguous configurations. Adoption requires a runtime update/restart;
these source changes do not deploy anything.

## Fail-closed secret schema and diagnostics

Startup accepts only these string keys: root `smtp`, `tokens`; SMTP `username`,
`password`; each token `label`, `token_sha256`, `mailgun_domains`,
`allowed_from_domains`, `allowed_from_addresses`. Unknown or non-string keys
fail startup with positional, value-free diagnostics. Optional sender addresses
may still be omitted, null or empty (domain-only authority); a misspelling now
fails instead of silently broadening that authority.

Both YAML loaders refuse duplicate mapping keys before schema lookup, including
root sections, SMTP passwords and policy restrictions. Anchors and ordinary
aliases remain supported. Python also refuses conflicting keys introduced by
YAML merges; Rust retains its existing merge-key refusal (PLAN D-6). Previously
ignored fields and ambiguous duplicate-key documents must be corrected before
updating/restarting either runtime.

Python parser and schema errors now use fixed messages or trusted field/index
positions, suppressing parser snippets and chained value-bearing exceptions.
Aliases cannot turn a password/hash into an error field name. Exceptions and
ordinary startup stdout/stderr are tested with invented secret markers; Rust
retains the same value-free diagnostic boundary. Adoption needs a runtime
update/restart; no deployment is part of this change.

STARTTLS authentication uses only the latest encrypted EHLO capabilities; a
pre-TLS AUTH offer never authorizes sending credentials after upgrade. Each
submission opens a fresh session. Synthetic TLS tests vary AUTH by phase and
session (PLAIN → LOGIN, then no AUTH, then PLAIN) and prove removed mechanisms
cannot leak into authentication or message submission.

A disconnect after complete DATA but before the final 250 is an **uncertain
submission**, returned as retryable HTTP 503 (`smtp_temporary`). The peer may
already have stored/delivered the message. The relay never retries internally,
keeps no durable replay queue and performs no unsolicited SMTP transaction on
restart. A caller retry may therefore duplicate delivery; this adapter does not
provide durable exactly-once delivery. This differs from a consumed final 250:
a subsequent QUIT failure still returns success. A full-binary loopback test
records one DATA per explicit HTTP request, reuses admission after a lost ACK,
and observes an idle restart without replay.

## Multipart completion

The Rust relay requires a `multipart/form-data` boundary of 1–256 bytes.
A missing or empty boundary returns HTTP 400 (`malformed form`) before the
request body is read.
Rust limits each multipart part header line to 4,224 bytes, including the
colon and leading value spaces and excluding the terminating CRLF. Malformed
or oversized lines return HTTP 400 (`malformed form`).

Both runtimes require the multipart parser to reach the complete closing
boundary before accepting a send request. A text field whose data exceeds its
byte limit returns HTTP 413 even if a later delimiter is missing or incomplete.
Truncation within the applicable limits returns HTTP 400 with
`{"message":"malformed form"}`. Both errors occur before SMTP submission.
Python closes all already-spooled uploads, including an unfinished last upload.
Complete multipart bodies with epilogues remain supported. HTTP Content-Length
completeness alone does not establish MIME completeness.

## HTTP singleton headers

`Authorization` and `Content-Type` may each occur at most once on a send
request. Both runtimes reject repeated fields with HTTP 400 and
`{"message":"duplicate singleton HTTP header"}` before authentication, body
reads or SMTP admission. Header names are compared case-insensitively; identical
repeated values are also refused. Single-header Anymail requests remain supported.
