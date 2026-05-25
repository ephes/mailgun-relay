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

- Missing or invalid auth returns `401`.
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
- At least one content part, usually `text` or `html`.

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
| `amp-html` | Yes | Added as `multipart/alternative` part with `text/x-amp-html` subtype. |
| `h:Reply-To` | Yes | Parsed via RFC 5322 address-list parser (quoted commas in display names preserved). |
| `h:*` custom headers | Yes | Strict header-name regex; CR/LF rejection; dangerous-header denylist. |
| `attachment` | Yes | Per-file and aggregate body-size caps. |
| `inline` | Yes | Counted toward the same `max_attachments` cap as `attachment`. |
| `o:*` options | Reject (400) | Phase-0 audit found neither homepage nor python-podcast emits any in default-settings sends; adding selective accept-and-ignore is a future change with its own audit. |
| `v:*` variables | Reject (400) | No events/templates metadata support. |
| `recipient-variables` | Reject (400) | Batch personalization out of scope. |
| `template` / `t:*` | Reject (400) | Stored Mailgun templates out of scope. |

Success response:

```json
{
  "id": "generated-message-id",
  "message": "Queued. Thank you."
}
```

The `id` should be unique enough for logs and client correlation. Prefer generating one Message-Id-shaped value, using it as the SMTP `Message-Id:` header, and returning the same value in the JSON response. Final SMTP delivery status is not represented by this response.

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
| Request too large | 413 | Body, attachment, or recipient limits. |
| Rate limited | 429 | Per-token or global. |
| SMTP temporary failure/timeout/connection refused | 503 | Anymail does not retry on its own; the caller surfaces the status as `AnymailRequestsAPIError.status_code`. |
| SMTP permanent rejection (5xx response, recipients refused, sender refused, helo failure) | 502 | Same Anymail exception shape; permanent vs. temporary is informational for callers that inspect `.status_code`. |
| SMTP authentication failure (relay → backend) | 502 | Treated as a permanent upstream failure. Never exposes the credential. |
| Internal error | 500 | Body is `{"message": "Internal Server Error"}`; no secrets or message bodies in response. |

Response body shape is `{"message": "<human readable>"}` on all non-2xx. `django-anymail`'s `AnymailRequestsAPIError` stores the full body so callers can log it; the relay never includes credential material in that message.

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
