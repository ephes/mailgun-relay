# Changelog

All notable changes to mailgun-relay are documented here.

## Unreleased

### Security

- Update the Rust SMTP certificate verifier `rustls-webpki` from 0.103.15 to
  0.103.16 for [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html).
  This rejects compromised emSign intermediate keys even when configured trust
  anchors permit a path. The Rust relay uses native/configured roots, not a
  bundled Mozilla store; the dependency change does not prove live exposure.
- Use uv 0.13.4 in all CI jobs and establish the hosted Rust runner's patched
  trust/Rustup baseline before any toolchain download.

- Update the locked certifi CA bundle of the Python implementation to
  2026.10.19 for the eMudhra/emSign CA compromise
  ([GHSA-6q48-6c7w-9gw2](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2)). Lock-only change; it applies when the
  Python implementation is deployed, for example on a rollback from Rust.

### Rust production cutover and rollback drill (S10)

- Switched macmini to the existing Rust 0.2.1 release on 2026-10-17,
  exercised a role-managed return to Python, and returned to Rust at
  15:51:36 UTC (17:51:36 CEST). Health and 401/403 policy checks passed
  at all three stages; two controlled probe mails per stage each arrived
  exactly once with DKIM pass. These were controlled probe mails.
- On 2026-10-18 the owner replaced the original seven-day acceptance
  wait with a clean 24-hour resource/error/probe/restart review no earlier
  than 2026-10-18 15:51:36 UTC, plus at least one real application mail
  traced from client through relay acceptance to Postfix delivery.
  The later evidence review and owner acceptance are recorded below.
  The following week is normal operation with existing 15-minute
  monitoring; there is no mandatory +7-day measurement or verified review
  scheduler. The +1-hour checkpoint was missed and is not reconstructed.
  Python remains the rollback path until at least 2026-11-16 15:51:36 UTC.
- The 2026-10-19 08:15:10 UTC review, 40.39 hours after the final Rust
  return, found the same process with no restarts, 5.30 MiB RSS/VmHWM,
  one thread and 0.533 CPU seconds total (about 0.0132 CPU-s/h). The
  relay/probe and Traefik history since T0 was clean; retained nyxmon
  history starts on 2026-10-18 and also had no failures. This is a current
  review, not an invented historical +24-hour measurement.
- One controlled Homepage production test on 2026-10-19 at
  08:19:26–08:19:29 UTC verified Django/Anymail → relay HTTP 200 →
  Postfix delivery → exactly one IMAP message. It establishes application
  transport, not natural user traffic. The additional DKIM verification
  initially could not retrieve the DNS key. At that stage neither DKIM
  pass nor a bad signature was established;
  the missing key alone did not establish a Rust regression.
- On 2026-10-19 at 09:11 UTC the existing BIND role published the DKIM
  public key; both authoritative nameservers returned serial 2026101901
  and the configured key. Normal verification of the same original
  application mail still failed key retrieval because macmini retained a
  negative DNS answer (3311 seconds TTL remaining at 09:11:48 UTC).
  DKIM verification was still open at that recheck. No further mail or
  relay restart occurred;
  the +40-hour resource and transport evidence above remains unchanged.
- Normal, unmodified DKIM verification of the same original Homepage
  mail passed on 2026-10-19 at 11:28:49 UTC (`opendkim-testmsg` exit 0,
  empty stdout/stderr; `d=wersdoerfer.de`, `s=mail`, `a=rsa-sha256`).
  The first recheck at 11:27:18 UTC had still failed key retrieval; the
  brief transition is not fully explained. No new mail, resolver override,
  cache/configuration change or relay restart was used. Technical
  stability, application transport and DKIM criteria are now fulfilled;
  the owner explicitly accepted the Rust migration and DKIM fix on
  2026-10-19. **S10 is complete.** Normal monitoring continues; the Python
  rollback path remains until at least 2026-11-16 15:51:36 UTC and
  retirement is a separate task.
- The initial 120-second production sample after the final Rust return
  had 5.27 MiB median RSS and no restarts. It precedes the +1-hour
  checkpoint and does not complete any soak measurement.
- Recorded the preceding 24-hour S9 shadow baseline (Rust 0.2.0):
  26 corpus passes with no unexplained differences; 5.4 MiB idle RSS
  versus Python's 70.9 MiB (about 92% lower), and 0.00 versus
  3.61 idle CPU-s/h. The 25-MiB request reached 73.8 MiB VmHWM and
  recovered to 5.6 MiB RSS after 60 seconds. Its 75.2-MiB MemoryPeak
  exceeded the 40-MiB target; the separate maximum-request and recovery
  budgets passed. These shadow results are separate from the later
  production observations.

### Custom header names with a final newline are 400 (D-19)

- Behaviour change for clients: 200 → 400. An `h:*` field whose header
  name ends in a line break (`h:X-Foo%0A`, also `h:Bcc%0A`) passed the
  name check, because `re.match` with `$` also matches before a final
  newline, and the message went out with the name written as an encoded
  word. The name must now match `^[A-Za-z][A-Za-z0-9-]*$` in full and such
  a request answers 400, as the Rust port already does. `rust/PLAN.md`
  D-19 is no longer a divergence. Takes effect with the next relay deploy.

### Custom message-id headers: non-ASCII values are 400 (slice S4a)

- `h:In-Reply-To` or `h:References` whose value is not ASCII after RFC 2047
  decoding now answers 400 when the message is built. It answered 502 after
  the SMTP login before: the message could not be serialised without
  SMTPUTF8. No request that was delivered before is affected.

### Authentication: malformed non-ASCII credentials are 401 (slice S2a)

- Behaviour change for clients: 500 → 401.
  `Authorization: Basic …` whose credentials contain a non-ASCII character
  (a header byte ≥ 0x80) now answers 401 `Unauthorized` like every other
  malformed credential. It answered 500 before: `base64.b64decode` raised a
  plain `ValueError` that the auth check did not catch. No request that
  authenticated before is affected.

### Rust port plan

- Added `rust/PLAN.md` and a `rust/TESTMAP.md` sketch: the plan for
  re-implementing the relay as a small Rust binary in `rust/` and switching
  production to it through the `mailgun_relay_deploy` role. It fixes the
  compatibility scope (HTTP contract, policy and rejection decisions,
  configuration and `/health` exact; MIME byte form and message texts free),
  records the owner decisions of 2026-10-15 on the intentional divergences,
  including the Python fix that shipped first (see "Mailgun API
  compatibility" below), and defines slices, the Python-as-oracle fixtures,
  the parity harness, release, shadow run, cutover and rollback. The plan
  itself changes no runtime behaviour.

### Mailgun decommission status (re-established 2026-08-04)

The 0.1.0 *Operator follow-ups* section claimed the commercial Mailgun API key
"was rotated out during this migration" and only needed revoking. That was true
of `homepage` and `python-podcast` and of nothing else, and it has been read
since as "the Mailgun account is done". It is not. What the Mailgun API and the
deployed hosts actually say:

- **The Mailgun account is live and carrying traffic.** `GET /v3/domains`
  returns seven domains, six of them `active`. Account-wide `GET
  /v3/stats/total?duration=30d` reports 1180 `accepted` against 28 `delivered`
  in the last 30 days, which is what pushed a 1000-message Flex allowance to
  1356 of 1000 in the billing period. Almost all of that volume is retried mail
  that never lands.
- **Only two applications still send through Mailgun, and neither can use this
  relay.** Takahe (`fedi.python-podcast.de`) and Mastodon
  (`fedi.wersdoerfer.de`), in production *and* staging, speak plain SMTP to
  `smtp.mailgun.org:587`. This service is an HTTP shim for the Mailgun Messages
  API; it has no SMTP listener, so it is the wrong tool for them. They move to
  the home backend's submission service instead — see
  `ops-control/runbooks/mail-fedi-smtp-cutover.md`.
- All four of those deployments authenticate as the *same* Mailgun SMTP login,
  `postmaster@mg.wersdoerfer.de`, with the same 50-character password
  (confirmed by comparing SHA-256 of the deployed values across both hosts).
  That password was disclosed in cleartext during an operator session and has
  to be rotated in the Mailgun control panel, which is a four-deployment change.
- **The commercial API key is still live.** One private API key — shared by
  `dotcom` prod, `lead` prod and staging, `ohrkanal` prod and `registry`
  staging — authenticates successfully against `GET /v3/domains` today. Two
  further values found in deployed `.env` files (`django-chat` staging,
  `konektom` staging) are dead: both regions answer `401` on `GET /v3/domains`
  *and* on `POST /v3/{domain}/messages`, so they are not scoped domain sending
  keys either, and at 22 and 9 characters they are nowhere near the 36
  characters of a real Mailgun private key.
- `homepage` and `python-podcast` (both environments), `villakunterbunt`
  staging and `recorder` are confirmed on relay tokens: their deployed `.env`
  carries `MAILGUN_API_URL=https://mailgun.home.xn--wersdrfer-47a.de/v3`.

The ordered decommission plan, the manual steps and the verification gate live
in `ops-control/runbooks/mailgun-decommission.md`. Nothing in this repository
has to change for it.

### Mailgun API compatibility

- **IDN addresses are sent as ASCII; non-ASCII local parts are rejected.** An
  address with an internationalized domain (`foo@wersdörfer.de`) was written
  into `To`/`Cc`/`From`/`Reply-To` with an RFC 2047 encoded word inside the
  domain (not valid RFC 5322), sent as the U-label in `RCPT TO`, and made
  `smtplib` switch the whole submission to SMTPUTF8 (a `503` against a server
  without it). Every IDN domain, in the headers and in the envelope, is now
  sent as its A-label (`foo@xn--wersdrfer-47a.de`); the relay never uses
  SMTPUTF8. An address whose local part is not ASCII (`jörg@example.org`)
  cannot be sent that way and is now a `400`: in `from` at the sender-policy
  step (so a foreign path domain is still `403` first), in `to`, `cc`, `bcc`
  and `h:Reply-To` when the message is built. Such a sender used to pass the
  policy (domain-only tokens) or get `403` (address allowlist); it is `400` in
  both cases now. Recipients are often typed in by outside visitors (Django
  allauth mails "unknown account" notices to any address entered in the
  password-reset form), so this path was reachable from outside. Token,
  path-domain and sender-domain decisions are otherwise unchanged.
- **`MAILGUN_RELAY_ENVELOPE_SENDER` is kept ASCII at startup.** An IDN domain
  is converted to its A-label; a value with a non-ASCII local part stops the
  process at startup instead of forcing SMTPUTF8 on every submission. Empty
  (the null sender `MAIL FROM:<>`) and ASCII values are used unchanged.
- **Empty bodies and CR/LF display names are a `400`, not a `500`.** `text=""`
  (what Anymail sends for a Django message with an empty body) or `html=""`
  without another non-empty `text`/`html` raised an unhandled error. A `to` or
  `cc` display name whose RFC 2047 encoded word decodes to CR or LF
  (`=?utf-8?B?YQ0KYg==?= <a@example.org>`) did the same. Both are now `400`
  with the usual `{"message": ...}` body, at the same point of the request
  checks, so a request with an additional earlier fault keeps that fault's
  status. `text=""` together with a non-empty `html` is still accepted and
  sent as HTML only.
- **Inline images now resolve in strict clients.** An `inline` upload was sent
  with a bare `Content-ID: logo.png` and attached to the top-level
  `multipart/mixed` next to the body. It now gets the RFC 2392 form
  `Content-ID: <logo.png>` (what Mailgun sends, and what `cid:logo.png` in the
  HTML refers to), and with an HTML body it is grouped with the HTML part in
  `multipart/related` inside the `multipart/alternative`. Text-only messages
  keep inline parts in `multipart/mixed`. An inline filename with control
  characters or `<>` is now a `400` instead of an unhandled error.
- **`multipart/*` and `message/*` uploads no longer produce broken parts.** An
  `attachment` or `inline` file declared as, say, `multipart/mixed` or
  `message/rfc822` became a base64 part of that type with no boundary or
  embedded message. Such uploads are now sent as `application/octet-stream`.
- Inline parts are now added before regular attachments in the MIME tree.
- homepage and python-podcast send no inline files today, so this is
  compatibility hardening; it takes effect on the next mailgun-relay redeploy.

### Delivery reliability

- Classify temporary sender, HELO, and all-recipient SMTP refusals as HTTP 503.
  Mixed all-refused 4xx/5xx replies are temporary; pure permanent refusals remain 502.
- Preserve accepted and partially accepted sends when SMTP QUIT/close fails,
  with safe cleanup warnings; retain original pre-acceptance failures.


- **Partially refused recipients are no longer dropped silently.** When the
  submission server accepted a message for some recipients and refused others
  at `RCPT TO`, `smtplib` returned the refused ones instead of raising, the
  relay discarded that return value, answered `200 "Queued. Thank you."` and
  logged nothing about it. The relay still answers `200` by default — the
  message was accepted for the others, a client retry would duplicate it, and
  real Mailgun reports per-recipient failures only asynchronously — but now
  logs one `WARNING` record `event=recipients_refused` with the refused
  *domains* and SMTP codes (never local parts or reply text), and the request
  record gains `refused_count` and `result=partial_refusal`. A refusal of every
  recipient returns `503` if any refusal is 4xx, otherwise `502`.
- **New setting `MAILGUN_RELAY_FAIL_ON_PARTIAL_REFUSAL` (default `false`).**
  When `true`, a partial refusal answers `502` instead of `200`. Callers that
  enable it must not blindly retry. The value is included in the `startup` log
  line.
- Operators who alert on `result != "ok"` in the access log will now also see
  `partial_refusal` on `200` responses; that is intended.

### Development

- `[tool.mypy] files` now includes `tests`, so a bare `uv run mypy` (README
  quickstart and CI) type-checks the tests as well as the package.

### Availability

- **A slow SMTP backend no longer freezes the relay.** `POST
  /v3/{domain}/messages` is an async route, but it called the blocking
  `smtplib` submitter directly on the event loop. The service runs a single
  uvicorn process, so while the home submission backend was slow or
  unreachable every other send *and* `/health` waited behind it — up to
  `MAILGUN_RELAY_SMTP_TIMEOUT_S` (30 s) per SMTP step — and monitoring saw the
  relay as down. The submission now runs in a worker thread, so the event loop,
  `/health` and other requests stay responsive while a send is in flight.
  Status codes and the SMTP error mapping (503 temporary, 502 permanent) are
  unchanged, and the relay still does not retry on its own.
- **New setting `MAILGUN_RELAY_SMTP_MAX_CONCURRENCY` (default `8`, minimum
  `1`).** It caps how many SMTP sessions the relay opens at once; further sends
  wait for a free slot instead of opening an unbounded number of connections to
  the backend. `/health` never waits on it. The value is included in the
  `startup` log line.

### Observability

- **The service now logs a `startup` line.** Previously the relay only logged
  per request, so a relay that had simply not been asked to send anything was
  indistinguishable from a relay whose logging was broken — and that ambiguity
  led to a wrong diagnosis ("the relay logs nothing to journald"). Every
  process start now emits one structured record with `event=startup` carrying
  the version, bind address, public host, SMTP host/port/STARTTLS, whether a
  custom CA bundle is in use, the effective log level, the configured token
  *labels*, and the body/recipient caps. It obeys the same information
  boundary as the access log: no token values or hashes, no SMTP credentials.
  It is emitted at INFO or at the configured level, whichever is higher, so
  raising `MAILGUN_RELAY_LOG_LEVEL` to quieten the per-request records cannot
  take the anchor away with them.
- **No buffering fix was needed, and the reason is now pinned by a test.**
  `logging.StreamHandler.emit` flushes its stream after every record, so log
  lines reach journald as they are emitted even though systemd gives the
  process a block-buffered stdout pipe. `PYTHONUNBUFFERED` is not required for
  the relay's own log output. `tests/test_logging.py` asserts the per-record
  flush so the guarantee cannot silently regress.

### Security hardening

Findings from a full security review of the service, fixed in this change. No
public request/response contract changes except the two noted under *Behavior*.

- **SMTP TLS is now verified.** STARTTLS uses `ssl.create_default_context()`,
  so the relay→SMTP hop verifies the server certificate chain and hostname.
  Previously STARTTLS ran with no verification, so an active MITM on that hop
  could capture the SMTP credentials and message contents. A private-CA backend
  can be pointed at its bundle via the new `MAILGUN_RELAY_SMTP_CA_FILE` setting;
  verification can never be turned off.
- **Credentials are never sent over a non-TLS connection.** If SMTP AUTH would
  run without STARTTLS (`smtp_starttls=false`) the submission now fails closed
  instead of sending the username/password in cleartext.
- **Request bodies are bounded at the ASGI layer.** A new body-size-limit
  middleware rejects requests over `max_body_bytes` (413) using the declared
  `Content-Length` and, for chunked/streamed bodies, a cumulative byte count —
  before `request.form()` buffers the body. The multipart parser is now also
  bounded (`max_files`, `max_fields`, `max_part_size`) to the relay's own
  limits, and oversized attachments are rejected by spooled size before being
  read into memory.
- **Header validation hardened.** Custom-header value checks now reject NUL and
  all C0/C1 control characters plus the Unicode line/paragraph separators
  (previously only CR/LF). The dangerous-header denylist gained `Sender`,
  `MIME-Version`, `Content-*`, `Content-ID`, `Disposition-Notification-To`, and
  `Return-Receipt-To` to block identity spoofing, receipt exfiltration, and
  structural-header duplication. Residual MIME-construction `ValueError`s now
  map to a clean 400 instead of 500.
- **IDN sender allowlist fixed.** `from`-address comparison normalizes the
  domain to its A-label (punycode) form, matching the stored allowlist; IDN
  senders were previously rejected because the parsed value was a U-label.
- **Secrets file permissions are enforced.** `load_secrets` refuses to read a
  secrets file that is world-accessible or group-writable (requires `0640` or
  stricter); the deployment's `0640 root:mailgun-relay` layout is accepted.
- **Token hash validation tightened.** `token_sha256` must be canonical
  64-char lowercase hex; non-canonical spellings (`0x…`, signs, `_`) that could
  silently produce a dead token are rejected.
- **Log line bounded.** The attacker-controlled `from` value in the access log
  is truncated to 320 chars. `log_level` from settings/env is now actually
  applied to the structured logger (was hardcoded to INFO).

#### Behavior

- `GET /health` now returns `{"status":"ok"}` without the service version
  (the version was an unauthenticated info-disclosure hint).
- Oversized requests may now be rejected with 413 at the ASGI layer (before the
  route runs), in addition to the existing per-field 413 checks. A multipart
  request that trips the parser's file/field/part-size caps also maps to 413
  (not 400), matching the documented "too large" contract.
- A malformed or header-injected `from` address now returns **400** (bad
  request) instead of 403; it is rejected as a parse/injection error before any
  authorization decision, so a CR/LF-bearing `from` can no longer be silently
  reinterpreted by lenient address parsing.

### CI

- Add a GitHub Actions workflow that runs the quickstart checks (ruff check,
  ruff format --check, mypy, pytest) on every push and pull request.

### Dependency security refresh (2026-10-06)

- Lock the minimal fixed versions of four runtime dependencies with known
  advisories: `python-multipart` 0.0.29 -> 0.0.31 (PYSEC-2026-3036/3037/3040;
  the relay parses multipart request bodies), `starlette` 1.1.0 -> 1.3.1
  (PYSEC-2026-248/249), `anyio` 4.13.0 -> 4.14.2 (PYSEC-2026-4024/4025) and
  `pydantic-settings` 2.14.1 -> 2.14.2 (CVE-2026-58203). `pip-audit` on the
  exported runtime lock reports no known vulnerabilities.
- starlette 1.3 deprecates `httpx` for `TestClient` in favour of `httpx2`. The
  pytest config ignores exactly that warning so `filterwarnings = error` keeps
  catching everything else; no new dependency is added.
- No code or API changes. Redeploy the relay to pick up the new lock.

## rs-v0.2.1 — 2026-10-17

Bug-fix release of the Rust port (crate version 0.2.1), tag `rs-v0.2.1`
on `88170df`. The GitHub release carries
`mailgun-relay-0.2.1-x86_64-unknown-linux-gnu.tar.gz` and its `.sha256`.
Production still runs the Python service until the cutover (`rust/PLAN.md`
S10).

### Rust port 0.2.1: SMTP without Nagle delay (S9)

- The Rust relay opens its SMTP connection with `TCP_NODELAY`. lettre writes
  the end of DATA (`CRLF . CRLF`) and rustls the end of the STARTTLS
  handshake as separate small writes before reading the reply; with Nagle,
  each of them waited for the server's delayed ACK. On macmini's load
  profile that added about 40-90 ms per message (text+html request p50
  86.8 ms against Python's 14.7 ms). Measured on Linux against the capture
  sink: 90.0 ms -> 2.8 ms (text+html), 47.7 ms -> 3.7 ms (35 KB error
  mail). Contract, responses and messages are unchanged.

### Parity harness: folded Message-ID in the shadow run (S9)

- `run_parity.py` compared the parsed `Message-ID` of a captured message
  with the response `id` as is. With the production `PUBLIC_HOST` the Python
  relay folds that header (the line is longer than 78 characters), and the
  parser of Python 3.12.3, the `python3` of the shadow host, keeps the
  folding space. So every queued case of the first shadow run on macmini
  failed on Python's side. The check now ignores surrounding white space.
  No relay change.
- `rust/PLAN.md` 10.1 and 10.2: the Rust shadow uses port 8089 (8086 is taken
  on macmini by the graphyard InfluxDB container). The shadows' stdout goes
  only to the log files. The sinks' certificates are valid for two days.

## rs-v0.2.0 — 2026-10-16

First release of the Rust port in `rust/` (crate version 0.2.0), tag
`rs-v0.2.0` on `2e845a5`. The GitHub release carries
`mailgun-relay-0.2.0-x86_64-unknown-linux-gnu.tar.gz` and its `.sha256`.
Nothing runs it in production yet: production stays on the Python service
until the role is switched (`rust/PLAN.md` section 9). The Python service
keeps its own version (0.1.0); its changes since then are under
"Unreleased" above.

### Rust port: parity harness (slice S6b)

- `rust/parity/run_parity.py` starts the Python relay (real uvicorn) and
  the Rust release binary as processes, each with a fake SMTP server
  (STARTTLS with a throwaway CA, AUTH, scripted replies), sends 474 request
  cases byte for byte to both and compares what the parity contract fixes:
  status, contract headers and JSON, the SMTP envelope, the message as
  Python's parser reads it, and the `request`/`recipients_refused` and
  `startup` records. The corpus covers every production client shape
  (Anymail urlencoded and multipart, the recorder's multipart in random
  field order), the twelve production policies with fake tokens, every
  decision of `rust/PLAN.md` 2.3, every limit at N and N+1, all SMTP
  scenarios of `smtp_outcomes.json` through the endpoint, and 8 startup
  configurations. Expected differences name their divergence (D-3, D-4,
  D-9 to D-11, D-20 to D-22); any other difference fails. CI runs it in
  the new `parity` job (about 30 s). With `--targets` it runs against two
  running instances whose SMTP goes to capture sinks, for the shadow run.
- Found by the harness: `MAILGUN_RELAY_LOG_LEVEL=trace` starts the Python
  service (uvicorn registers the level before the app sets it), but the
  Rust port refused to start. The Rust port now accepts `TRACE` too; the
  fixture model of the Python start includes it.

### Rust port: shared parity harness modules (slice S6a)

- `rust/parity/smtp_fake.py` (the scripted fake SMTP server, now also
  recording TLS, login, envelope and the message, and usable as a capture
  sink) and `rust/parity/semantic.py` (the semantic view of a message and
  the RFC checks) move out of `rust/fixtures/generate.py` and
  `check_mime.py`, standard library only, for the parity harness of S6b.
  The fixtures are unchanged.

### Rust port: release pipeline (slice S7)

- `.github/workflows/rust-release.yml` builds the Rust binary on
  ubuntu-22.04 (glibc 2.35) for `x86_64-unknown-linux-gnu` from a clean
  state (pinned toolchain and action SHAs, no cargo cache) and gates it with
  `rust/scripts/release_checks.py`: the tag `rs-v<semver>` must equal the
  crate version, no glibc symbol above 2.35 and only glibc/libgcc linked,
  `--version` names version and full commit, `--check-config` accepts a test
  configuration in the role's shape. The archive
  `mailgun-relay-<ver>-x86_64-unknown-linux-gnu.tar.gz` holds exactly
  `mailgun-relay` and `LICENSE` and is deterministic for a given binary;
  its `.sha256` is checked with `sha256sum --check`. A tag push publishes
  both files as a GitHub release (a pre-release version as a pre-release);
  `workflow_dispatch` uploads them as a workflow artifact only. The first
  release is `rs-v0.2.0` (this section).

### Rust port: submission in the route (slice S5b)

- The Rust port caps concurrent SMTP sessions at `SMTP_MAX_CONCURRENCY`
  (further messages wait, `/health` never does) and finishes a submission
  whose client went away; SIGTERM waits for it, as uvicorn does.
- `rust/fixtures/smtp_outcomes.json` pins the status of 109 SMTP scenarios
  (every row of `rust/PLAN.md` 2.4) from the Python client run against a
  scripted fake server; the Rust tests run the same scenarios. Process tests
  deliver a message end to end over STARTTLS with a test CA.
- Memory: the message is not copied again for SMTP or for its head. A
  request at the 25 MiB limit peaks at 73 MiB when glibc's dynamic mmap
  threshold is fixed (`MALLOC_MMAP_THRESHOLD_=131072`, planned for the
  systemd drop-in); with glibc's defaults it peaks at 100–135 MiB and keeps
  up to 100 MiB resident.

### Rust port: SMTP submission (slice S5a)

- `rust/src/smtp.rs` submits the built message with lettre's
  connection-level API, so the Rust binary now delivers: STARTTLS with
  chain and hostname verification against the system roots plus
  `SMTP_CA_FILE`, AUTH PLAIN or LOGIN (never without TLS), one `RCPT` per
  recipient, so a partly refused message reaches the others as in Python,
  and the statuses of PLAN.md 2.4 (a reply code decides 503 or 502, every
  failure without one is 503). `QUIT` failures never change the outcome
  and are logged as `smtp_cleanup_failed`; no `QUIT` after 421 or a lost
  connection. The timeout applies per socket operation.
- The Rust port reads `SMTP_CA_FILE` at start; an unusable file stops the
  start and `--check-config` (PLAN.md D-22, fail closed). Python reads it
  per message and answers 503.

### Rust port: semantic MIME fixture (slice S4b)

- `rust/fixtures/mime.json` (124 cases from the Python oracle) holds what a
  receiver's parser reads from the message Python builds for each input:
  decoded headers, the MIME tree, decoded bodies, attachments and inline
  parts, the envelope, or the 400. The Rust tests build every case and
  compare; `rust/fixtures/check_mime.py` reads the Rust messages with
  Python's parser and checks that they arrive the same, 7-bit, CRLF only,
  lines of at most 998 octets, encoded words of at most 75 characters and
  no parser defects beyond Python's own. CI runs both in the `rust` job.

### Rust port: message construction (slice S4a)

- `rust/src/mime.rs` builds the message with lettre as the Python service
  does (PLAN.md 2.10): text, html and amp-html alternatives, inline parts
  with the html part in `multipart/related` (or in `multipart/mixed`
  without html), attachments, Reply-To lists, custom headers, Message-Id and
  Date, Bcc in the envelope only, the envelope de-duplicated. IDN domains are
  A-labels and EAI local parts are refused (Q2). Header values that are
  printable ASCII are written as received, so encoded words arrive decoded
  exactly as Python decodes them; other values become RFC 2047 encoded
  words. The output is 7-bit, CRLF only, lines of at most 998 octets. It
  replaces the step-9 stub of S3 behind the same interface; the SMTP
  submitter follows in S5.
- Exotic header input the Python service rewrites is refused with 400 by
  the Rust port (PLAN.md D-21, fail closed): text that needs encoding mixed
  with encoded words, encoded words Rust cannot check (other charsets than
  UTF-8, ASCII and the ISO-8859/windows-125x families, broken base64) or
  whose text Python would change (`=?` inside, whitespace at the ends, an
  ASCII special like `,` in a display name), encoded words in local parts,
  `h:In-Reply-To` and `h:References` that are not plain message-id lists,
  `h:Orig-Date`, header names over 76 characters. Encoded words longer than
  RFC 2047 allows are split; an ASCII attachment filename with a line break
  is 400 as in Python.

### Rust port: route tests (slice S3d)

- The remaining Rust counterparts of `test_messages_endpoint.py` (without
  SMTP) and `test_body_limit.py`: the 413 limits at N and N+1, body reading
  (non-form content types, malformed multipart, a chunked body over the
  limit), multi-fault cases for the decision order in both encodings,
  records and their information boundary, route matching, the production
  client shapes (Anymail urlencoded, the recorder's multipart in every field
  order) and a panicking request (500, one record). This completes S3.

### Rust port: the messages route (slice S3c)

- `POST /v3/{domain}/messages` exists in the Rust binary
  (`rust/src/pipeline.rs`): the decision order of the Python route
  (authentication, form, field rules, policy, subject, custom headers,
  recipient count, message checks), its statuses and JSON shapes, and one
  `event=request` record per request with Python's fields and `result`
  values, also when a request task panics (500). Partial refusals log
  `event=recipients_refused` with domains and codes only.
- Message construction is a stub (`rust/src/mime.rs`) that makes the
  step-9 decisions without MIME encoding until slice S4; the SMTP
  submitter comes with S5. Until then the binary answers every accepted
  message with 503, so it never reports a message as queued that was not
  sent.

### Rust port: form parsing (slice S3b)

- `rust/src/form.rs` parses request bodies as the Python service does:
  urlencoded with Starlette's decoding (latin-1, then `unquote_plus`) and
  multipart with python-multipart's framing (strict first boundary, token
  header names, at most 8 headers of 4,224 bytes per part, a truncated body
  keeps the completed parts), the request charset, and the 413 limits for
  files, fields and part size. It is its own parser rather than `multer`,
  which would accept bodies Python refuses (`rust/PLAN.md` section 5).
  Where Python's decision depends on how the body arrives in chunks (bytes
  other than CR/LF before the first boundary; a chunked body over the size
  limit that is also malformed), Rust refuses (D-20). Not wired to a route
  yet (S3c).
- New fixture from the Python oracle: `form_decoding.json` (the real
  `request.form(...)` with the route's 400/413 mapping on 350 bodies, each
  delivered in one piece and in four chunkings, among them a body cut at
  every byte).

### Rust port: subject and header validation (slice S3a)

- `rust/src/headers.rs` validates the subject and the `h:*` headers as the
  Python service does (control characters, the denylist including every
  `resent-*` name, the name pattern, lengths in code points; the first error
  in map order wins). The control-character rule moves there from
  `address.rs`. Not wired to a route yet (S3c).
- A header name with a final newline (`h:X-Foo%0A`), which Python's pattern
  lets through, is refused (`rust/PLAN.md` D-19, fail closed). The Python
  service is unchanged.
- New fixture from the Python oracle: `headers.json` (196 subjects, 100
  header lists, 168 control-character probes).

### Rust port: the token policy (slice S2c)

- `rust/src/policy.rs` enforces the token policy in Python's order and with
  Python's statuses: path domain invalid 400, not allowed 403; `from`
  invalid 400; from domain or address not allowed 403, with the 403 texts
  kept verbatim. It returns the parsed `from` mailbox for the headers. Not
  wired to a route yet (S3).
- `policy.json` (1,430 cases from the Python oracle) runs the production
  policy shapes (homepage with its two senders, python-podcast with a
  second from domain, registry, a domain-only token, an IDN allowlist)
  against production-like paths and senders; Python tests pin the same
  shapes. This completes S2.

### Rust port: addresses and the envelope sender (slice S2b)

- `rust/src/address.rs` parses `from`/`to`/`cc`/`bcc` values and Reply-To
  lists once for policy and headers: a strict subset of Python's
  `parseaddr`/`getaddresses` plus the `email_validator` rules (ASCII
  dot-atom local parts, IDN domains as A-labels, special-use names, lengths),
  with Python's display names for phrases, quoted strings and comments. Not
  wired to a route yet (S3).
- `address.json` (1,570 values from the Python oracle) pins every decision;
  the Rust tests check that whatever Rust accepts, Python accepts with the
  same address and display name. Exotic forms Python accepts (whitespace
  inside the address, unclosed `<`, groups, address domains outside the
  Latin set) are refused (`rust/PLAN.md` D-11, fail closed).
- The Rust binary refuses to start with an `ENVELOPE_SENDER` that is not a
  valid bare address (D-15); production's value passes. The Python service
  is unchanged.

### Rust port: authentication and path domains (slice S2a)

- `rust/src/auth.rs` authenticates as the Python service does (`Basic `
  prefix, `str.strip()` whitespace, strict base64 with canonical padding and
  lenient trailing bits, strict UTF-8, username `api`, constant-time
  comparison of the SHA-256 against every token, the last match wins). It is
  not wired to a route yet (S3).
- New fixtures from the Python oracle: `auth.json` (121 headers) and
  `domain.json` (1,003 path-domain inputs, among them every character of the
  Latin set configured domains may use). Path domains Python refuses but the
  `idna` crate maps (symbols, emoji, CONTEXTO characters) keep the decided
  403 instead of 400 (`rust/PLAN.md` D-10).
- `rust/PLAN.md` D-7 now says plainly that several case variants of a
  variable fail the start even when one is the exact name.

### Rust port: `/health` and the startup record (slice S1d)

- `mailgun-relay` without arguments now serves on `BIND_HOST:BIND_PORT`
  (axum, one runtime thread; every address the host resolves to, IPv6
  sockets IPv6-only, as uvicorn binds): `GET /health` → `{"status":"ok"}` without a
  version, `HEAD`/`POST /health` → 405 with `allow: GET`, unknown paths → 404,
  a trailing slash on a route → 307 as Starlette builds it, a declared
  `Content-Length` above `MAX_BODY_BYTES` → 413 on every path. It logs the
  Python startup record (plus `"impl":"rust"`, UTC `ts`) and stops gracefully
  on SIGTERM/SIGINT. It still has no `POST /v3/{domain}/messages`.
- Release builds use `opt-level = "s"`: idle RSS 2.6 MiB, binary 1.6 MB
  (Linux, glibc). The Python service is unchanged.

### Rust port: secrets file (slice S1c)

- The Rust binary loads the secrets YAML as the Python service does (same
  schema, placeholders, duplicate labels, IDN domains as A-labels, the mode
  check before reading) with the YAML 1.1 types of PyYAML's `safe_load`
  (`yes`, `0777`, `2026-10-15` are never strings). `--check-config` now
  validates the environment and the secrets file.
- Fail closed where Python would start (`rust/PLAN.md` D-5, D-6, D-10, D-17):
  a non-string `token_sha256`, merge keys, tags other than `!!str`,
  directives, recursive aliases, deep nesting, empty plain keys, TAB and
  NEL/LS/PS characters, domains outside the Latin set (also after IDNA
  mapping), and non-ASCII local parts in `allowed_from_addresses`. Error
  messages name fields by position and never repeat a configured value.
- `rust/fixtures/config_secrets.json` (130 documents from the Python oracle)
  pins the decisions. The Python service is unchanged.

### Rust port: skeleton and environment settings (slice S1a)

- The repository is now MIT-licensed (`LICENSE`).
- `rust/` holds the Rust port as one Cargo package (`mailgun-relay` 0.2.0,
  pinned toolchain 1.99.0, `cargo-deny` policy). So far the binary reads the
  same `MAILGUN_RELAY_*` settings as the Python service: `--version`, and
  `--check-config` validates the environment and exits 0 or 1. It cannot
  serve yet and is not deployed. Exotic settings Python would accept make it
  refuse to start (fail closed; `rust/PLAN.md` D-7, D-10, D-18).
- Fixtures generated from the Python code (`rust/fixtures/generate.py`) pin
  the settings decisions; `tests/test_rust_fixtures.py` fails when they are
  stale. CI gains a `rust` job (fmt, clippy, cargo-deny, tests, release
  build).
- `rust/PLAN.md` records the S1b spike result (lettre connection API, live
  EHLO of the SMTP backend: `AUTH PLAIN LOGIN`, no `SMTPUTF8`), its
  conditions for the SMTP slice, the broken-reply case of D-3, the new
  entries D-17 and D-18, and the split of S1 into S1a, S1c and S1d.
  `.gitignore` ignores `rust/target/`.
- The Python service is unchanged.

## 0.1.0 — 2026-05-25

Initial implementation: Mailgun-API-compatible HTTP→SMTP adapter for
django-anymail clients.

### Service

- `POST /v3/{domain}/messages` accepts the Mailgun multipart subset
  django-anymail emits (`from`, `to`, `cc`, `bcc`, `subject`, `text`, `html`,
  `amp-html`, `h:Reply-To`, `h:*` custom headers, `attachment`, `inline`).
- HTTP Basic auth with username `api`, constant-time SHA-256 token verifier
  (all tokens compared per request to avoid timing leaks).
- Per-token policy enforces `{domain}` path, `from`-domain, and (when
  configured) exact `from`-address allowlist. IDN domains normalized to A-labels.
- MIME constructed via Python's stdlib `email.message.EmailMessage`. BCC
  recipients go on the envelope only; never written to the serialized message.
- Authenticated STARTTLS SMTP submission to a configured backend (default:
  `smtp.home.xn--wersdrfer-47a.de:587`). Envelope `MAIL FROM` = relay-controlled
  PostfixAdmin mailbox (required because the backend enforces
  `smtpd_sender_login_maps`).
- Success body: `{"id": "<msg-id@public_host>", "message": "Queued. Thank you."}`.
  The `id` matches the SMTP `Message-Id:` header on the submitted message.
- Error mapping verified against Anymail's `AnymailRequestsAPIError` handling:
  401 (auth), 403 (policy), 400 (bad request / header injection / unsupported
  field), 413 (payload too large), 502 (SMTP permanent / auth), 503 (SMTP
  temporary), 500 (internal).
- `GET /health` returns `{"status":"ok","version":...}` without touching SMTP.
  **Superseded:** the version field was removed under *Unreleased → Security
  hardening → Behavior*; the current contract is `{"status":"ok"}`.
- Structured JSON access log per request with `request_id, token_label,
  path_domain, from, recipient_count, message_id, result, status_code,
  error_class, duration_ms`. Never logs token values, the SMTP password,
  message bodies, attachment content, or the `Authorization` header.
- Rejects (with 400) any `v:*`, `o:*`, `t:*`, `template`,
  `recipient-variables`, or unknown form field — verified against the actual
  fields the current homepage + python-podcast Anymail integration emit.

### Test coverage

97 tests pass; `ruff check .` + `ruff format --check .` + `mypy src` all clean.

### Deployment

- `ops-library` role `mailgun_relay_deploy` installs the FastAPI service via
  uv, renders `/etc/mailgun-relay/{mailgun-relay.env, secrets.yml}` (0640
  root:mailgun-relay), installs the systemd unit with hardened sandboxing
  (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`),
  and runs an HTTP health check against the bind port.
- `ops-library` role `mailgun_relay_ingress_deploy` renders Traefik dynamic
  config exposing the relay at `https://mailgun.home.xn--wersdrfer-47a.de`
  with Let's Encrypt-issued TLS via the existing traefik resolver.
- `ops-control` playbook `playbooks/deploy-mailgun-relay.yml` and Justfile
  entry `just deploy-one mailgun-relay` deploy both roles together.

### Pre-deploy operator checklist

The role refuses to deploy until SOPS contains real values.

1. **Provision a relay PostfixAdmin mailbox.** Create
   `mailgun-relay@xn--wersdrfer-47a.de` (or another mailbox on a backend-hosted
   domain) with a strong password via PostfixAdmin or direct SQL. This mailbox
   is the SMTP login AND the envelope `MAIL FROM` — the backend's
   `smtpd_sender_login_maps` requires those to match (mailbox username OR
   alias mapped to the login user).
2. **Generate four tokens** (one per app per environment):
   ```bash
   python -c "import secrets,hashlib; t=secrets.token_urlsafe(32); print('token=',t); print('sha256=',hashlib.sha256(t.encode()).hexdigest())"
   ```
3. **Edit `ops-control/secrets/prod/mailgun-relay.yml`** with `sops edit`:
   set `smtp_username`, `smtp_password`, `envelope_sender` (the relay mailbox
   address), and each token's `token_sha256`.
4. **Deploy**: `just deploy-one mailgun-relay`. Verify
   `curl -fsS https://mailgun.home.xn--wersdrfer-47a.de/health` returns
   `{"status":"ok"}` and check `journalctl -u mailgun-relay`
   for the first structured log line (it should show `event=request` if you
   probed it).

### App migration

`ops-library` role `wagtail_deploy` gained a new optional variable
`wagtail_mailgun_api_url` (default empty). When non-empty, the rendered
Wagtail env file emits `MAILGUN_API_URL`, which steers django-anymail's
Mailgun backend at the relay instead of `https://api.mailgun.net/v3`.

Both `deploy-homepage.yml` and `deploy-python-podcast.yml` now forward
`service_secrets.mailgun_api_url | default('')` through to the role.

**Per-environment migration:**

For each of `homepage` and `python_podcast`, in each of `staging` and `prod`:

1. `sops edit ops-control/secrets/<env>/<app>.yml`.
2. Set `mailgun_api_url: "https://mailgun.home.xn--wersdrfer-47a.de/v3"`.
3. Replace `django_mailgun_api_key` value with the matching raw token
   generated in step 2 of the relay checklist above.
4. Leave `mailgun_sender_domain` at the app's existing value — that's the
   value already in the SOPS file and it must match the relay token's
   `mailgun_domains` policy:
   - `homepage`: `mg.wersdoerfer.de`
   - `python-podcast`: `mg.python-podcast.de`
5. Redeploy the app: `just deploy-one homepage staging`
   (or `python-podcast staging`). The new `.env` on the target host will
   contain `MAILGUN_API_URL=https://mailgun.home.xn--wersdrfer-47a.de/v3` and
   the relay token (the commercial Mailgun key is replaced, not augmented).
6. Repeat for the production environment once staging is validated.

### Rollback

Revert is a one-line SOPS edit: clear `mailgun_api_url` (or set it to
`https://api.mailgun.net/v3`) and restore the original commercial Mailgun key
in `django_mailgun_api_key`. Redeploy. The Wagtail env file template only
writes `MAILGUN_API_URL` when the value is non-empty, so an empty string
restores the upstream Mailgun behavior on the next deploy.

Per-environment rollback affects only that environment's `.env` file; no
relay-side change is required.

### App settings migration

The `homepage` and `python-podcast` Django settings each grew an
`MAILGUN_API_URL` entry under `ANYMAIL` (defaulting to
`https://api.mailgun.net/v3` if unset). Anymail did not previously read
`MAILGUN_API_URL` from env at all, so the relay's URL would not have taken
effect without this change. The fallback default keeps the upstream Mailgun
URL active when SOPS leaves `mailgun_api_url` unset, so the same code can
run on environments not migrated to the relay yet.

### Acceptance evidence (2026-05-25)

Both staging environments delivered real mail to their respective
`ADMINS` mailbox via the relay. Both responses' `id` matched the SMTP
`Message-Id:` header observed on the home mail stack.

> **`jochen-<tag>@` addresses below are real, not typos.** Postfix and Dovecot
> on the home backend are both configured with `recipient_delimiter = -`, so
> `jochen-homepage@wersdoerfer.de` and `jochen-pythonpodcast@wersdoerfer.de`
> are tagged forms of the `jochen@` mailbox and deliver to it. The tag is how
> the operator traces which application sent a message, and the LMTP lines
> below show exactly that. Do not "fix" them to the untagged address —
> that mistake has already been made once while auditing this file, and it
> discards the only routing evidence in the record. Note that the delimiter is
> `-`, not the `+` that Gmail and most providers use.

Outgoing send: `homepage` staging
- relay `request_id`: `37ece89243734e0cab6b3adc6b31c767`
- relay `message_id`: `<73528a08bbef4c87967da86e12159336@mailgun.home.xn--wersdrfer-47a.de>`
- timestamp: `2026-05-25T10:22:44+0200`
- token_label: `homepage-staging`
- from: `Jochen <jochen-homepage@wersdoerfer.de>`
- recipient_count: 1
- duration_ms: 378
- postfix queue id: `B553556CCBA`
- lmtp delivery: `jochen-homepage@wersdoerfer.de` -> `jochen-homepage@opaq.de` INBOX (saved by Dovecot at `10:22:44.090439+02:00`)

Outgoing send: `python-podcast` staging
- relay `request_id`: `80d967211fa948a4b7f2799afb38bc5a`
- relay `message_id`: `<7046e13389b54c829930ef4d55a9012d@mailgun.home.xn--wersdrfer-47a.de>`
- timestamp: `2026-05-25T10:22:46+0200`
- token_label: `python-podcast-staging`
- from: `Python Podcast <noreply@mg.python-podcast.de>`
- recipient_count: 1
- duration_ms: 330
- postfix queue id: `25FCA56CCBA`
- lmtp delivery: `jochen-pythonpodcast@wersdoerfer.de` -> `jochen-pythonpodcast@opaq.de` INBOX (saved by Dovecot at `10:22:46.490954+02:00`)

The acceptance sends used `EmailMessage` with the explicit `from_email`
matching each token's allow-list (not `mail_admins`, which uses
`SERVER_EMAIL=jochen-django@wersdoerfer.de` and would have been
correctly rejected as `PolicyError` because neither token allows that
sender). The relay's `policy_error` log lines from the rejected attempts
are evidence of the policy enforcement.

### Operator follow-ups

- The commercial Mailgun API key previously shared across `homepage` and
  `python-podcast` (staging + prod SOPS files) was rotated out during this
  migration. Each app now uses its own relay-issued token; the old commercial
  key likely still exists at Mailgun.com. **Revoke it at Mailgun's control
  panel** to close that surface. The value is intentionally not reproduced
  here — retrieve it from git history of `ops-control/secrets/{staging,prod}/{homepage,python-podcast}.yml`
  prior to the rotation if needed for the revocation lookup.

  **Superseded, and it was wrong in a way that mattered.** Rotating these two
  applications did not disarm the key: the same private API key is deployed in
  five other places that this migration never touched (`dotcom` prod, `lead`
  prod, `lead` staging, `ohrkanal` prod, `registry` staging), and as of
  2026-08-04 it still authenticates against the Mailgun API. Revoking it therefore breaks
  those consumers rather than merely closing a surface, and it is not the last
  step either — Takahe and Mastodon still send over Mailgun *SMTP*, which no
  API-key revocation touches. See *Unreleased → Mailgun decommission status*
  above and `ops-control/runbooks/mailgun-decommission.md` for the ordered
  procedure. `ops-control/docs/MAILGUN_CREDENTIAL_DISARM.md` has the per-key
  breakdown.
- `mailgun-relay@xn--wersdrfer-47a.de` PostfixAdmin mailbox was created
  during this migration with the password supplied to the provisioning
  script. If the mailbox needs to be rotated, run the provisioning
  script again with a new password and update the PostfixAdmin
  mailbox row (`UPDATE mailbox SET password = ... WHERE username = ...`).

  Still true. Worth knowing: because it was created out-of-band it is *not* in
  `ops-control/secrets/prod/mail-users.yml`, so `just mail-users-sync` will
  neither recreate nor rotate it.
- The `homepage` + `python-podcast` Justfile entries in `ops-control`
  pass `-l "$host"` but not `-e target_host="$host"`, which makes
  `just deploy-one homepage staging` a no-op (no hosts match). Until the
  Justfile is updated, deploy staging with
  `ansible-playbook ... -e target_host=staging`.

  Still true as of 2026-08-04, for a slightly different reason than described:
  the recipe now defaults the host, but still passes only `-l`, and
  `inventories/prod/hosts.yml` puts just `production` in the `homepage` and
  `python_podcast` groups. `-l staging` therefore still matches no host.
- Production rollout: after smoke-testing the staging behavior, the
  `prod` SOPS files already contain the relay token + `mailgun_api_url`,
  so `just deploy-one homepage` and `just deploy-one python-podcast` will
  pick up the relay automatically.

  Done. Both production `.env` files on the edge host carry
  `MAILGUN_API_URL=https://mailgun.home.xn--wersdrfer-47a.de/v3` and a relay
  token, and neither has produced a Mailgun event in the retention window.

### Non-goals (explicit, not deferred)

- `POST /v3/{domain}/messages.mime` — neither current app uses raw MIME
  submission (verified via source audit of homepage + python-podcast).
- Mailgun domains/events/webhooks/tracking/templates/suppressions/inbound/
  analytics APIs.
- Adding new sender domains to the home mail stack.
