# Security: threat model and runbook

This document is the threat model of the Rust relay (`rust/`), the
implementation in production. The retained Python implementation (`src/`)
enforces the same boundary: the Rust port is pinned to it by the fixtures and
the parity harness (`rust/TESTMAP.md`) for request policy. Startup numeric
bounds differ as documented in `rust/PLAN.md` D-18.
The bypass tests below run against the Rust relay only.

It covers the risks of the backlog item *Phase 2 → Security review*. Each
threat names the code that enforces the boundary and the tests that try to
cross it. Test names are Rust test paths under `rust/src`; the bypass
attempts written for this review live in `rust/src/security_tests.rs`
(module `pipeline::tests::security`).

## Assets and trust boundaries

- **Mail reputation of the home domains.** The relay submits mail with an
  authenticated SMTP login to the home Postfix, which DKIM-signs it. Whoever
  can make the relay send can send as the allowed `From:` addresses.
- **Relay tokens.** One per application and environment. The application
  holds the raw token (in its own SOPS file as `django_mailgun_api_key`); the
  relay holds only its SHA-256 (`token_sha256` in
  `ops-control/secrets/prod/mailgun-relay.yml`).
- **SMTP credentials** of the relay mailbox (`smtp_username`,
  `smtp_password`), in the same secrets file.
- **Message content and recipients** of the applications' mail.

Trust boundaries:

1. Client → Traefik (HTTPS, public certificate) → relay on `127.0.0.1:8085`
   (`MAILGUN_RELAY_BIND_HOST` defaults to loopback). Every request is
   untrusted until the token is verified.
2. Relay → SMTP backend: STARTTLS with chain and hostname verification, then
   AUTH. The backend is trusted to enforce its own sender/login binding.
3. Secrets file on the host → relay process at startup.

## Threats

| # | Threat | Enforced in | Covered by |
| --- | --- | --- | --- |
| T1 | Open relay | `pipeline::decide` step 2, `http::router` | `authentication_failures_are_401_with_realm`, `security::credential_variants_are_401`, `http::tests::health_and_fallbacks`, `route_matching` |
| T2 | Authentication bypass, token guessing | `auth::authenticate` | `auth::tests::*` (fixture `auth.json`), `security::credential_variants_are_401`, `security::only_the_first_authorization_header_counts` |
| T3 | Token leakage, a token used outside its scope | `policy::enforce_policy`, `secrets::load_policy` | `policy_decisions`, `policy::tests::*`, `security::tokens_stay_inside_their_scope` |
| T4 | Sender spoofing (`From:`) | `policy::enforce_policy`, `address::parse_mailbox`, `domain::address_domain` | `policy::tests::policy_fixture` (fixture `policy.json`), `address::tests::address_fixture`, `security::sender_spoofing_attempts_are_refused`, `security::sender_case_variants_match_the_allowed_address` |
| T5 | SMTP sender/login binding, envelope `MAIL FROM` | `smtp::SmtpConfig::load`, `config::envelope_sender`, `mime::build` | `smtp::tests::python_smtp_submission_tests`, `::envelope_and_reply_codes`, `security::the_envelope_comes_from_the_configuration_and_the_recipient_fields` |
| T6 | Header injection | `headers::*`, `address::*`, `mime::build`, `mime::upload_part` | `headers::tests::headers_fixture`, `mime::tests::*`, `field_rules_are_400`, `inline_filenames`, `security::identity_and_structure_headers_are_refused`, `security::line_breaks_in_header_fields_are_refused`, `security::upload_metadata_cannot_inject_headers` |
| T7 | SSRF through attachments or remote content | `pipeline::read_upload`, no HTTP client in the crate | `security::remote_content_is_never_fetched` |
| T8 | Log leakage | `pipeline::Record`, `log_partial_refusal`, `secrets` `Debug` | `records_follow_the_information_boundary`, `secrets::tests::debug_redacts_password_and_token_hash`, `binary.rs::serves_health_logs_startup_and_stops_on_sigterm`, `security::records_never_carry_message_content_or_recipients` |
| T9 | Secret file leakage | `secrets::load` (mode check), `secrets::from_yaml` | `secrets::tests::config_secrets_fixture` (mode bits), `::errors_never_echo_values`, `binary.rs::check_config_exit_codes` |
| T10 | Replay | none in the relay (see below) | `security::a_replayed_request_is_a_new_message` |
| T11 | Volume abuse with a valid token | size and count limits; **rate limits not enforced** | `limits_are_413`, `body_reading` |

### T1 Open relay

An open relay would send for anyone. The only route that sends is
`POST /v3/{domain}/messages`, and its first decision is authentication: no
`Authorization` header, a wrong scheme, user or token is a `401` before the
body is read (`decide`, step 2). Every other path is `404`/`405`/`307`, and
`/health` never touches SMTP.

The relay does not restrict **recipients**: an authenticated application may
send to any address, as with Mailgun. The relay is therefore exactly as open
as its tokens are secret and narrow (T3), and as its volume limits (T11).

### T2 Authentication bypass and token guessing

`auth::authenticate` accepts only `Authorization: Basic <base64>` of
`api:<token>`: the scheme and the user are case-sensitive, the base64 must be
canonical, and nothing inside the credentials is trimmed. The token's SHA-256
is compared in constant time with **every** configured hash (no early exit),
and the user check runs after the comparison, so timing does not reveal which
part failed. Only the first `Authorization` header is read. Every failure is
the same `401` with `WWW-Authenticate: Basic realm="MG API"`.

The hashes are unsalted SHA-256, which is sound only for high-entropy tokens.
Generate tokens with at least 256 random bits (see the runbook); never use a
memorable value. The stored hash is not a credential: sending it as the
password is a `401`.

Covered: an empty user, `API`, users with whitespace, an empty password, no
`:` separator, the token with whitespace, a prefix or a suffix, the stored
hash, `basic`/`BASIC`/`Basic` without a space, the token unencoded or as a
bearer token, the token in the query string or another header, and a valid
second `Authorization` header after a wrong first one.

### T3 Token leakage and scope

A leaked token lets its holder send as that token's senders. The damage is
bounded by the token's policy (`secrets.yml`):

- `mailgun_domains`: the path domains it may use (exact match after IDNA
  normalisation; no parent, child, suffix or trailing-dot match).
- `allowed_from_domains`: the `From:` domains (exact match).
- `allowed_from_addresses`: when set, the exact `From:` addresses
  (local part compared lowercased). When absent the token may use **any**
  local part of its from domains; prefer an address list for every token.

Failures are `403` with the decisive value in the message. Tokens never
appear in logs, error messages, `--check-config` output or the startup
record (T8). Rotation and revocation are in the runbook below.

### T4 Sender spoofing

The `from` field is parsed once (`address::parse_mailbox`), and the same
parsed mailbox is both checked by the policy and written as the `From:`
header, so the checked address is the sent address. The parser is a strict
subset of what Python's `email` package and `email_validator` accept; exotic
forms (groups, unclosed `<`, comments inside the address, quoted or non-ASCII
local parts, IP literals) are `400`. Address domains are restricted to a Latin
character set before IDNA mapping (D-10, D-11), so fullwidth letters,
Cyrillic lookalikes and zero-width characters are `400`; a real IDN such as
`wersdörfer.de` is its own A-label (`xn--wersdrfer-47a.de`) and must be
configured as such.

A display name or comment holding an allowed address does not make the
sender allowed: the policy reads only the addr-spec. Case variants of an
allowed address are the same address and are accepted. `Sender:`,
`Resent-*` and `From:` cannot be added through `h:*` (T6).

Not bound by the policy: `h:Reply-To` may name any valid address. Replies
can be redirected by an application, which is a normal feature; it does not
change the authenticated sender.

### T5 SMTP sender/login binding and envelope `MAIL FROM`

The envelope sender is configuration, never request data:
`MAILGUN_RELAY_ENVELOPE_SENDER` (validated at startup, D-15) is the
`MAIL FROM` of every submission; empty is the null sender. The production
value is the relay mailbox `mailgun-relay@xn--wersdrfer-47a.de`, which is
also the SMTP login, because the backend enforces `smtpd_sender_login_maps`
(login and envelope sender must match). Bounces go to that mailbox. The
envelope recipients are exactly the parsed `to`, `cc` and `bcc`, de-duplicated;
`bcc` never appears in the message.

The relay always authenticates and refuses to send credentials without TLS:
STARTTLS is required (with `SMTP_STARTTLS` off and credentials set, the
submission fails closed), the certificate chain and the host name are
verified, and an unusable `SMTP_CA_FILE` stops the process at startup (D-22).

The backend's binding is a second line of defence: it prevents the relay
login from using another envelope sender, but it does not check the `From:`
header. The `From:` boundary is the relay's token policy (T4); DKIM signing
on the backend then signs whatever `From:` the relay allowed.

### T6 Header injection

- The subject, every `h:*` value and every address field refuse C0 and C1
  controls (TAB excepted), DEL, U+2028 and U+2029 (`contains_forbidden_control_chars`).
- `h:*` names must match `^[A-Za-z][A-Za-z0-9-]*$`; a denylist refuses,
  case-insensitively, the headers the relay sets and the identity and
  structure headers: `Bcc`, `Received`, `Return-Path`, `Message-Id`, `Date`,
  `From`, `To`, `Cc`, `Subject`, `Sender`, `MIME-Version`, `Content-Type`,
  `Content-Transfer-Encoding`, `Content-Disposition`, `Content-ID`,
  `Disposition-Notification-To`, `Return-Receipt-To` and every `Resent-*`.
- RFC 2047 encoded words in `to`/`cc` display names that decode to a line
  break are refused (D-16).
- Upload filenames with a line break are refused: CR and LF already by the
  multipart parser (they end the part header line), the other line
  boundaries (VT, FF, FS, GS, RS) when the message is built; non-ASCII
  filenames are RFC 2231-encoded. Inline filenames, which become the `Content-ID`, refuse
  `<`, `>`, controls and surrounding whitespace. Upload content types are
  reduced to `main/sub` tokens; parameters are dropped and `multipart/*` or
  `message/*` become `application/octet-stream`.
- `v:*`, `o:*`, `t:*`, `template`, `recipient-variables` and unknown fields
  are `400`.

Residual: headers outside the denylist pass unchanged, for example
`List-Unsubscribe`, `Auto-Submitted`, but also `DKIM-Signature`,
`ARC-*` or `Authentication-Results`. A forged signature fails verification
and receivers replace their own authentication results, so this is not a
sender bypass, but the denylist could be extended to those names (open
point).

### T7 SSRF through attachments or remote content

The relay never makes an outbound request other than its SMTP submission.
Attachments and inline parts must be uploaded files; an `attachment` or
`inline` given as text (for example a URL) is a `400`. URLs inside `html` or
`amp-html` are message content and are passed on unchanged, never fetched.
The crate has no HTTP client dependency (`rust/Cargo.toml`); adding one
needs a review of this section.

### T8 Log leakage

The `event=request` record holds the request id, token label, path domain,
the `from` value (capped at 320 characters), counts, the Message-Id, the
result, the status and the duration. It never holds the token, the
`Authorization` header, the SMTP password, recipients, the subject, bodies,
custom header values, upload names or content. A partial refusal logs the
refused **domains** and reply codes only. SMTP failures log error classes and
codes, never reply texts. The startup record names the effective configuration and the
token labels, never secrets; `Debug` of the secrets redacts the password and
the hashes.

The logged `from` is personal data of the sender role address; it is
needed to diagnose policy failures and is not a secret.

### T9 Secret file leakage

The relay refuses to start when the secrets file is group-writable or
accessible by others (`mode & 0o037 != 0`); the deploy renders it
`0640 root:mailgun-relay`. Load errors name the field, never its value (also
through YAML aliases), and placeholder values (`changeme`, `CHANGEME`,
`replace-me`, empty) are refused. The file holds only token hashes; the raw
tokens live in the applications' secrets. The SMTP password is the one
plaintext secret on the relay host.

### T10 Replay

The relay keeps no request state: a captured request replayed within the
token's lifetime is sent again, with a new Message-Id. This matches Mailgun's
API, which has no idempotency key either. Mitigations: HTTPS to Traefik
(capture needs a TLS break or a compromised client or proxy host), the
token's narrow scope (T3) and revocation (runbook). A replay window or
idempotency key would need client support that Anymail does not offer;
none is planned.

### T11 Volume abuse (out of scope here)

Request size, attachment count and size, recipient count and header length
are limited (`MAX_*` settings, `413`). Rate limiting (`429`) is reserved but
**not enforced**, by the relay or the proxy. It is tracked by the backlog item
*Rate limiting and abuse controls*; the limits need an owner decision, and the
Python rollback window (until 2026-11-16) keeps both implementations'
behaviour aligned until then.

## Runbook: rotation and revocation

The relay reads the secrets file only at startup. Every change below takes
effect when the deploy restarts the service, which the ordinary deployment
does when a rendered input (the secrets file included) changes. Run deploys
from `ops-control` with `just deploy-one mailgun_relay` (see
`docs/ops-integration.md`); the application side is that application's
ordinary deploy. Never paste raw tokens or passwords into tickets, logs,
commits or shell history that is kept.

### Generate a token

```bash
python3 -c "import secrets,hashlib; t=secrets.token_urlsafe(32); print('token', t); print('sha256', hashlib.sha256(t.encode()).hexdigest())"
```

The raw token goes into the application's SOPS file
(`django_mailgun_api_key`), the hash into the relay's
`ops-control/secrets/prod/mailgun-relay.yml` (`token_sha256`, 64 lowercase
hex characters). Do not reuse a token across applications or environments.

### Rotate a token without downtime

1. Add a second entry to `tokens:` with a new `label` (labels must be
   unique, for example `homepage-production-2026-11`), the new hash and the
   **same** `mailgun_domains`, `allowed_from_domains` and
   `allowed_from_addresses` as the old entry. Deploy the relay.
2. Put the new raw token into the application's SOPS file and deploy the
   application.
3. Check the relay's `event=request` records: the application's sends now
   carry the new `token_label`, and none the old one.
4. Remove the old entry and deploy the relay. The old token is now a `401`.

### Revoke a token

Remove the token's entry from `tokens:` (or replace its `token_sha256`) and
deploy the relay. From the restart on, the token is a `401` with
`result=auth_error`. The application keeps failing until it gets a new token
(rotation steps 1–2). If a token leaked, revoke first, then rotate, then
review the records for sends with that `token_label` before the revocation.

### Rotate the SMTP credentials

1. Set a new password for the relay mailbox in PostfixAdmin.
2. Put it into `smtp_password` in the relay's SOPS file and deploy the
   relay.

Between the two steps submissions fail with `502` (`smtp_permanent`, backend
AUTH refused), and Anymail raises; do both steps together in a quiet period.
If the mailbox itself changes, `smtp_username` and `envelope_sender` change
together, because the backend binds the login to the envelope sender (T5).

### Verify after any change

- `curl -fsS https://mailgun.home.xn--wersdrfer-47a.de/health` returns
  `{"status":"ok"}`.
- A request with a wrong token is `401`, one with a foreign `from` is `403`.
- One controlled send per affected application succeeds and its record shows
  the expected `token_label`.

## Open points

- Rate limiting (T11): limits and placement (relay or proxy) need an owner
  decision; deliberately not part of this review.
- Denylist extension (T6): consider refusing `DKIM-Signature`, `ARC-*` and
  `Authentication-Results` in `h:*`; check the applications' Anymail output
  first.
- Domain-only tokens (T3): any token without `allowed_from_addresses` may use
  every local part of its domains; consider requiring an address list.

## Rust acquisition deadlines

Rust bounds form-body acquisition to 30 seconds total after admission, including
trickling uploads. A full 25 MiB upload needs roughly 7 Mbit/s sustained throughput. Expiry returns HTTP 408 (`BodyTimeoutError`), drops the body
and releases the admission slot before MIME or SMTP. Overload still returns 503
before reading the body. Python rollback has no application body deadline.
Rust also uses one `MAILGUN_RELAY_SMTP_TIMEOUT_S` budget for DNS resolution and
all TCP connection attempts together, sharing remaining time equally among
remaining addresses so a stalled address permits fallback; expiry is retryable HTTP 503. Later SMTP
socket operations retain their individual timeouts, including DATA and QUIT;
this is not a total SMTP-session deadline. Python retains its resolver and
per-address connect behavior. These changes require a future runtime update;
no deployment is performed by the source changes.

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
