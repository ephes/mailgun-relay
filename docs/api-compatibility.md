# API Compatibility Plan

This document defines the planned Mailgun subset for Django Anymail compatibility. It must be re-verified against current upstream docs before implementation:

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

Planned supported fields:

| Field | Support | Notes |
| --- | --- | --- |
| `from` | MVP | Parsed and validated against token sender policy. |
| `to` | MVP | Repeated values supported. Included in headers and SMTP envelope. |
| `cc` | MVP | Repeated values supported. Included in headers and SMTP envelope. |
| `bcc` | MVP | Repeated values supported. SMTP envelope only; no BCC header. |
| `subject` | MVP | Header injection rejected. |
| `text` | MVP | Text body. |
| `html` | MVP | HTML body, combined with text as multipart alternative when both exist. |
| `h:Reply-To` | MVP candidate | Accept if safely parsed as a header address. |
| `h:*` custom headers | MVP candidate | Allowlist or strict validation required. |
| `attachment` | MVP if needed | Use uploaded file metadata; enforce size/count limits. |
| `inline` | Future if needed | Only after verifying current app usage. |
| `o:*` options | Allowlist only | Accept and ignore only Phase-0-verified harmless no-op options; reject unknown or behavior-affecting options. |
| `v:*` variables | Reject | No events/templates metadata support in MVP. |
| `recipient-variables` | Reject | Batch personalization is out of scope initially. |
| `template` / `t:*` | Reject | Stored Mailgun templates are out of scope. |

Success response:

```json
{
  "id": "generated-message-id",
  "message": "Queued. Thank you."
}
```

The `id` should be unique enough for logs and client correlation. Prefer generating one Message-Id-shaped value, using it as the SMTP `Message-Id:` header, and returning the same value in the JSON response. Final SMTP delivery status is not represented by this response.

## Endpoint: `POST /v3/{domain}/messages.mime`

Status: optional future endpoint.

Purpose: Accept a raw MIME message if Anymail or future callers require it.

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
| SMTP temporary failure/timeout | 503 candidate | Retry semantics to verify with Anymail before finalizing. |
| SMTP permanent rejection | 502 or 400 candidate | Final decision requires Anymail behavior verification. |
| Internal error | 500 | No secrets or message bodies in response. |

Response body format should be consistent and close enough for Anymail to surface useful errors. Exact error JSON should be verified against Anymail's Mailgun error handling before implementation is finalized.

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
