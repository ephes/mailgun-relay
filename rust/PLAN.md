# Rust port of mailgun-relay — implementation plan

Status: in implementation. Campaign `mailgun-relay-rust`, phase 2.
Owner decisions of 2026-10-15 are incorporated (section 13); the plan starts
with the Python fix slice S0-py (section 6), which is merged on `main` as
`bc8880e` (336 Python tests); its deploy to macmini is approved by the owner
and follows the 403 fix. The spike S1b is done (GO with
conditions, section 6 "S1b result"). S1 is split by size into S1a
(repository plumbing, environment settings, fixture generator), S1c (secrets
file) and S1d (server, `/health`, startup record); all three are merged, so
S1 is done (report `handoff/s1-result.md`). S2 is split by size into S2a
(authentication, path domains), S2b (addresses, `ENVELOPE_SENDER` validity)
and S2c (the token policy); all three are merged, so S2 is done (report
`handoff/s2-result.md`). S3 and S4 are next.

This document is the contract for re-implementing the FastAPI service in
`src/mailgun_relay` (1,744 lines, `origin/main` `13e274f`, run on macmini as
the systemd unit `mailgun-relay` on `127.0.0.1:8085`) as a small Rust binary
in `rust/`, and for switching production to it. It is written for the
implementers of the slices in section 6 and for the reviewers of each slice.

The binding rule is `handoff/parity-contract.md` (owner decision of
2026-10-15): **no byte parity**. The target is the contract plus semantic
parity. Section 2.1 quotes its central part verbatim. Python is the oracle for
the HTTP contract and the policy decisions only. Lessons from the nyxmon port
apply: no re-implementations of Python libraries, no hand-rolled SMTP, no
byte-for-byte MIME. Where this plan states Python behaviour it cites the code;
when the plan and the code disagree, the code wins and the plan is corrected.

Facts about the live system come from the read-only phase-1 measurements of
2026-10-15 (`handoff/phase1-measure-deploy.md`, `phase1-code-clients.md`,
`fix-403-diagnosis.md`): Ubuntu 24.04.5, x86_64, glibc 2.39, no Rust toolchain
on the host, Postfix 3.8.6 on the same host as SMTP backend (submission 587,
STARTTLS mandatory, Let's Encrypt wildcard for `*.home.xn--wersdrfer-47a.de`),
Traefik in front of the relay (body buffer 25 MiB), Python relay RSS 76.4 MiB.

Citations: `relay:` is this repository, `ops-library:` and `ops-control:` are
the ops repositories, `nyxmon:` is `github.com/ephes/nyxmon` `origin/main`.

---

## 0. Where the Rust code lives (decision)

The Rust code lives in **`rust/` in this repository** (one Cargo package,
binary `mailgun-relay`), next to the Python package it replaces. This follows
nyxmon (`nyxmon:agent-rs/`). Reasons:

- **Python as oracle in the same tree.** The fixture generator imports
  `src/mailgun_relay` directly, the drift test runs in the existing `pytest`
  job, and the parity harness starts both implementations from one checkout.
  A separate repository would have to pin a Python commit and keep a second
  copy of the cases.
- **Tests on both sides of the security boundary** (`relay:AGENTS.md`):
  token, domain and sender rules change in one pull request for both
  implementations, and a reviewer sees both sides in one diff.
- **One release location.** Tags `rs-v<semver>` publish to
  `github.com/ephes/mailgun-relay/releases`, so the role's release URL is
  `https://github.com/ephes/mailgun-relay/releases/download/rs-v<ver>/mailgun-relay-<ver>-x86_64-unknown-linux-gnu.tar.gz`.
  The repository is public, so no token is needed to download.
- **One CI and one CHANGELOG.** `.github/workflows/ci.yml` gains Rust jobs;
  the release workflow is a separate file triggered by `rs-v*` tags only.

Merging Rust code to `main` is safe at any time: nothing deploys `rust/`
until the role is switched (section 9). One precondition: the role's rsync
excludes (`ops-library:roles/mailgun_relay_deploy/defaults/main.yml:27-39`)
do not exclude build output, so a local `cargo build` would ship
`rust/target/` (gigabytes) to macmini on the next `just deploy-one
mailgun-relay`. S1 adds `rust/target/` to those excludes and to `.gitignore`
(section 6).

Layout:

```
rust/
  Cargo.toml            # package mailgun-relay, edition 2024, publish = false, license = "MIT" (Q6)
  Cargo.lock            # committed; every build --locked
  rust-toolchain.toml   # pinned stable toolchain (1.99.0, as nyxmon), equal to rust-version
  deny.toml             # cargo-deny policy (licenses, advisories, crates.io only)
  PLAN.md  TESTMAP.md  README.md
  build.rs              # embeds the commit (MAILGUN_RELAY_GIT_COMMIT, else git rev-parse, else "unknown")
  src/
    main.rs             # argv (--version, --check-config), runtime, signals, startup record
    config.rs           # env settings (2.7)
    secrets.rs  yaml.rs # secrets loader and its YAML 1.1 subset (2.8)
    pystr.rs            # Python str.strip() whitespace
    auth.rs  policy.rs  address.rs  domain.rs  headers.rs
    form.rs             # urlencoded + multipart into an ordered item list
    pipeline.rs         # the decision order of section 2.3
    mime.rs             # message construction (lettre builder)
    smtp.rs             # submission (lettre connection API)
    log.rs              # JSON line logger
    http.rs             # axum router, body-limit layer, fallbacks
  tests/                # process-level tests against the built binary (binary.rs)
  fixtures/             # Python-generated JSON fixtures + generator (section 7.2)
  parity/               # differential harness and shadow tools (sections 7.4, 10)
  scripts/release_checks.py
```

One package is enough for a service of this size (estimated 3–4k lines of
Rust including tests). `unsafe_code = "forbid"`.

Versioning: the Rust crate starts at **0.2.0** (Python stays 0.1.0), so the
`version` field of the startup record tells operators which implementation
runs. Naming and paths were decided with Q7 (section 13).

---

## 1. Goal and baseline

Replace the Python process with a Rust binary that behaves identically on the
contract of section 2, needs far less memory and CPU, and is deployed and
rolled back by a switch variable in the existing role.

Baseline (Python, macmini, 2026-10-15, `phase1-measure-deploy.md` 1.1–1.3):

| Metric | Python | Rust target |
| --- | --- | --- |
| RSS idle (`smaps_rollup`) | 76.4 MiB (78,256 kB) | ≤ 15 MiB, goal ≤ 10 MiB |
| VmHWM (process peak) | 91.6 MiB | ≤ 120 MiB for one maximum-size (25 MiB) request; ≤ 30 MiB again 60 s later |
| cgroup MemoryPeak (incl. page cache) | 108.0 MiB | ≤ 40 MiB under the typical load profile (section 12) |
| CPU idle | 3.89 CPU-s/h (uvicorn loop ticks) | ≤ 0.5 CPU-s/h |
| Threads | 6 | 1 runtime thread + a lazily started blocking pool (≤ 2) |
| On-disk | 35 MB venv | stripped binary ≤ 10 MiB |
| Start to listening | not measured | ≤ 200 ms |

Traffic is tiny: 44 requests in 16 days, all policy 403s caused by the
`SERVER_EMAIL` gap that a separate item fixes (`fix-403-diagnosis.md`).
Requests are 30–38 KB urlencoded Django error mails; p95 32 ms. The memory
peak is therefore dominated by the largest request the limits allow, not by
volume. Section 12 defines the measurement.

---

## 2. Compatibility scope

### 2.1 Was exakt passen muss / was frei ist

Verbatim from `handoff/parity-contract.md` (binding; the concretisation in
2.2–2.12 must not contradict it):

#### Muss exakt übereinstimmen
- Der für Anymail sichtbare HTTP-Vertrag: Routen, Auth, Statuscodes und die JSON-Struktur der
  Antworten (Felder, die Clients auswerten, z. B. `id`, `message`).
- Die Token-/Domain-/Absender-Policy und jede Ablehnungsentscheidung (gleiche Eingabe → gleiche
  Annahme/Ablehnung, gleicher Statuscode).
- Die Konfigurationsschnittstelle: MAILGUN_RELAY_*-Umgebungsvariablen (Namen, Defaults,
  Validierung) und das Schema der Secrets-YAML.
- `/health` (Route, Status, Antwortform).

#### Darf abweichen
- Fehler- und Logtexte. Logs bleiben strukturiertes JSON; Feldnamen dürfen sich ändern, sofern
  nichts von ihnen abhängt. Konsumenten (Monitoring, Alerts, Dashboards) vorher prüfen und im Plan
  festhalten.
- MIME-Details (Header-Reihenfolge, Folding, Encoding-Wahl, Boundaries, Message-ID-Format usw.),
  solange die Mail korrekt zugestellt wird und RFC-konform ist (Absender, Empfänger inkl. Bcc nur im
  Envelope, Betreff, Text/HTML, Anhänge und Inline-Bilder, Header wie Reply-To kommen semantisch
  gleich an).

#### Umsetzung
- Standard-Crates bevorzugen (axum, serde/serde_json, lettre, …). Keine Nachbauten von
  Python-Bibliotheken, kein selbstgebautes SMTP.
- Python ist Orakel nur für den Vertrag und die Policy-Entscheidungen. MIME-Vergleich semantisch
  (geparste Struktur), nicht bytegenau.

Every deviation from the "exact" list is in section 3 and needs an owner
decision. Reviewer findings about byte form, header order, encodings or
message texts are out of scope unless a consumer of section 4 depends on them.

### 2.2 HTTP surface (exact: route, method, status, JSON shape)

| Request | Status | Body / headers that are contract |
| --- | --- | --- |
| `GET /health` | 200 | `{"status":"ok"}`, `content-type: application/json`; no `version` key; no auth, no SMTP, no log line (`relay:routes.py:86-90`) |
| `HEAD /health`, `POST /health` | 405 | `allow: GET`; body `{"detail":"Method Not Allowed"}` kept (free, but free to keep) |
| `POST /v3/{domain}/messages` | see 2.3 | main route (`routes.py:92-306`) |
| any other method on `/v3/{domain}/messages` | 405 | `allow: POST`, body as above |
| `<route>/` (trailing slash of `/health` or `/v3/{domain}/messages`, any method) | 307 | `location: http://<Host header><path without slash>[?query]`, empty body (Starlette `redirect_slashes`) |
| anything else, incl. `/v3/{domain}/messages.mime`, `GET /`, `/v3//messages` | 404 | `{"detail":"Not Found"}` |
| any path, `Content-Length` > `max_body_bytes` | 413 | `{"message":"Payload Too Large"}`, before routing and auth (`relay:app.py:37-51`) |

Notes for the implementation:

- `{domain}` is one path segment, percent-decoded as UTF-8. Starlette routes
  on the decoded path, so `%2F` in the domain splits the segment and the
  request is 404. axum routes on the raw path; the handler therefore answers
  404 when the decoded segment contains `/`.
- axum's `get()` also serves `HEAD`. FastAPI does not, so `/health` is
  registered with a GET-only method filter and HEAD gets 405.
- The 307 rule is cheap and kept although no client uses it (phase 1 marks it
  free). Rust builds the `location` as Starlette 1.3 does: scheme `http`, or
  the single `X-Forwarded-Proto` value (`http`, `https`, `ws`, `wss`) when the
  peer is `127.0.0.1` (uvicorn's proxy headers, the Traefik case); netloc
  from the `Host` header when it matches Starlette's `_HOST_RE`, else the
  listening address; the decoded path without trailing slashes; the raw
  query; the whole URL through `urllib.parse.quote` with Starlette's safe
  set. The route patterns match as Python's `re` does, so `$` also matches
  before one final newline (`/health%0A` is `/health`).
- Response headers `server`, `date` and the reason phrase are free.
- Fixed texts are kept verbatim because they cost nothing:
  `Unauthorized`, `Payload Too Large`, `Queued. Thank you.`,
  `Upstream SMTP temporarily unavailable`, `Upstream SMTP rejected the message`,
  `Internal Server Error`, and the policy texts
  `token not allowed for path domain '<d>'`, `… from domain '<d>'`,
  `… from address '<a>'` (single-quoted ASCII as Python `repr` renders
  them). The policy texts stay because the 403 diagnosis read the rejection
  reason off Traefik's response sizes (`fix-403-diagnosis.md` 1.2). Texts
  derived from `email_validator`, Starlette exceptions or Python `repr` of
  non-trivial values are free.
- A response `message` never contains `Domain not found` (404) or
  `Mailgun Magnificent API` (200); Anymail special-cases both
  (`anymail/backends/mailgun.py:46,63`).

### 2.3 Decision order of `POST /v3/{domain}/messages` (exact)

The order decides the status when a request has several faults; it is part of
the contract. Each step names its Python source.

1. **Body limit, declared length** (layer, all paths): `Content-Length`
   present and `> max_body_bytes` → 413. Unparseable or negative values are
   rejected by the HTTP server before the app in both implementations (see
   D-12).
2. **Auth** (`relay:auth.py:22-54`), headers only; the body is not read on
   failure. Any failure → 401 `{"message":"Unauthorized"}` with
   `WWW-Authenticate: Basic realm="MG API"`.
   - The first `Authorization` header, decoded as latin-1, must start with
     `Basic ` (case-sensitive).
   - The rest is stripped with Python `str.strip()` semantics (the whitespace
     set of `str.isspace` over latin-1, including `\x1c`–`\x1f`, `\x85`,
     `\xa0`).
   - Base64 per `base64.b64decode(validate=True)`: standard alphabet only, no
     embedded whitespace, padding required and canonical (`YQ` and `YQ===`
     fail), **non-zero trailing bits accepted** (`YR==` decodes like `YQ==`).
     Rust: `base64` engine with `decode_allow_trailing_bits(true)` and
     `DecodePaddingMode::RequireCanonical`. A non-ASCII character the strip
     leaves (a header byte ≥ 0x80; NEL and NBSP are whitespace only at the
     ends) fails here: 401. Python answered 500 before S2a (`b64decode` raised a plain
     `ValueError` that `auth.py` did not catch); S2a fixed Python to 401 at
     the same position, so it is no divergence (coordinator decision
     2026-10-15, as Q1).
   - Strict UTF-8; a `:` must be present; split at the first `:`; the username
     must be exactly `api`.
   - `sha256(password_utf8)` as lowercase hex is compared in constant time
     against **every** configured `token_sha256`, no early exit; the **last**
     match wins (label used for logging).
3. **Body read and form parse** (`routes.py:121-142`). The whole form is
   parsed before any field is checked.
   - Streamed bytes beyond `max_body_bytes` → 413 (`request body exceeds N
     bytes`).
   - Content type (essence, case-insensitive) `multipart/form-data` or
     `application/x-www-form-urlencoded`; anything else, or none, gives an
     empty form (→ 400 in step 4 for the missing `from`).
   - Parser limits as Starlette is called: non-file fields
     `> max_recipients + 100` → 413; file parts `> max_attachments + 1` → 413;
     a non-file field value `> max_body_bytes` → 413.
   - Malformed multipart: no boundary parameter, a part without
     `Content-Disposition` `name`, or a framing error python-multipart detects
     → 400. A body that **ends inside a part** (missing final boundary,
     truncated trailing part) is not an error in Python: the completed parts
     are kept, the unfinished part is dropped, and the request continues
     (measured: 200 when the completed parts form a valid message). Rust keeps
     that behaviour (multer's incomplete-stream error after the last complete
     part is treated as end of form). The harness pins truncation at each
     position (before the first boundary, in part headers, in part data,
     before the closing boundary); any residual difference is Rust-stricter
     (D-11 rule).
   - A multipart part is a file iff its `Content-Disposition` carries a
     `filename` parameter (also `filename=""`).
   - Decoding, reproduced exactly (pinned by `form_decoding.json`):
     urlencoded name and value bytes are decoded as latin-1, then
     `urllib.parse.unquote_plus` semantics apply (`+` → space; only ASCII runs
     are percent-decoded; consecutive `%XX` bytes decode as UTF-8 with
     replacement; an invalid `%` sequence stays literal). Raw non-ASCII bytes
     therefore become latin-1 characters, as in Python (Starlette
     `formparsers.py:139-140`). Multipart names, values and filenames are
     decoded with the `charset` parameter of the **request's** Content-Type
     (default UTF-8), falling back to latin-1 per item on a decoding error or
     an unknown codec (`formparsers.py:44-49,249-253`); D-9 covers declared
     charsets Rust does not implement.
4. **Field rules in form order, first error wins** (`routes.py:381-471`):
   - `v:*`, `o:*`, `t:*`, `recipient-variables`, `template` → 400;
   - `h:<name>`: must be a string (400 otherwise); stored in a map keyed by the
     exact name, last value wins, case variants are separate entries;
   - other names outside `from to cc bcc subject text html amp-html attachment
     inline` → 400;
   - `from`/`to`/`cc`/`bcc` repeatable; `subject`/`text`/`html`/`amp-html`
     last wins; a file in a string field → 400;
   - running UTF-8 byte total of `text`/`html`/`amp-html` plus attachment
     sizes `> max_body_bytes` → 413;
   - `attachment`/`inline` must be files (400); a file larger than
     `max_attachment_bytes` → 413; `attachments + inline > max_attachments`
     → 413 (checked after each file);
   - after the loop: not exactly one `from` → 400; no `subject` → 400 (an
     empty subject is allowed); neither `text` nor `html` present → 400.
5. **Policy** (`relay:policy.py:79-99`):
   - path domain normalised (2.6); invalid → 400; not in `mailgun_domains`
     → 403;
   - `from` parsed and validated (2.6); invalid → 400;
   - from domain (A-label) not in `allowed_from_domains` → 403;
   - `allowed_from_addresses` set and the normalised address not in it → 403.
6. **Subject** (`relay:headers.py:85-90`): `strip()`; forbidden control
   characters → 400; more than `max_header_value_length` code points → 400.
7. **Custom headers** (`headers.py:93-116`), in map order: name not
   `^[A-Za-z][A-Za-z0-9-]*$` → 400; name on the denylist (case-insensitive:
   `bcc received return-path message-id date from to cc subject sender
   mime-version content-type content-transfer-encoding content-disposition
   content-id disposition-notification-to return-receipt-to`, and every
   `resent-*`) → 400; control characters in the value → 400; value longer than
   `max_header_value_length` code points → 400.
8. **Recipient count** (`routes.py:177-183`): `len(to)+len(cc)+len(bcc)`
   before de-duplication; 0 → 400; `> max_recipients` → 413.
9. **Message construction** (`relay:mime_build.py:97-201`), which in Python
   also validates:
   - neither `text` nor `html` non-empty → 400 (D-1; Python answered 500
     before S0-py);
   - a `to`/`cc` display name that decodes to CR/LF → 400 (D-16; Python
     answered 500 before S0-py);
   - a non-ASCII local part in `to`/`cc`/`bcc`/Reply-To → 400 (D-2, Q2);
   - `from`, each `to`, each `cc` must be exactly one valid address → 400;
   - `h:Reply-To` (any case) is an address list, every element valid → 400;
     two case variants of a header the Python registry allows once
     (`Reply-To`, `In-Reply-To`, `References`, `Orig-Date`) → 400 (measured:
     `h:Reply-To` + `h:reply-to` → 400);
   - inline filename empty, with surrounding whitespace, `<`, `>`, or a
     control character (`< 0x20`, `0x7f`) → 400;
   - each `bcc` must be one valid address → 400.
   With the decided fixes for D-1 and D-16 (Q1, in Python via S0-py) all of
   these are 400, so their internal order does not change a status. The
   multi-fault case "To display name decoding to CR/LF plus an invalid Cc"
   (Python before S0-py: 400; with a valid Cc: 500) stays in the parity
   corpus to show both now give 400.
10. **SMTP submission** (2.4), capped by `smtp_max_concurrency` (waiters
    queue without timeout). A client disconnect does not cancel a submission
    already started; the access record is still written.
11. **Success**: 200 `{"id":"<message-id>","message":"Queued. Thank you."}`;
    the `Message-Id` header of the sent mail equals `id`.

### 2.4 SMTP outcome → HTTP status (exact)

From `relay:smtp_client.py:67-85,107-179` and `routes.py:206-277`:

| Outcome | Status |
| --- | --- |
| all recipients accepted, DATA accepted | 200 |
| some recipients refused, DATA accepted | 200 + `recipients_refused` WARNING record; 502 when `FAIL_ON_PARTIAL_REFUSAL` is true |
| all recipients refused, at least one 4xx (421 included) | 503 |
| all recipients refused, only 5xx | 502 |
| banner, STARTTLS, MAIL or DATA reply 4xx | 503 |
| same replies 5xx | 502 |
| EHLO rejected (any code) | not classified by its code: `submit` ignores the EHLO reply (`smtp_client.py:129,135`), so the next step decides. Production settings (STARTTLS on, credentials set): STARTTLS is then "not offered" → 503 (reproduced by the reviewer for EHLO 550). STARTTLS off with credentials: cleartext refusal → 502. A failing EHLO after STARTTLS: `smtplib.ehlo` records the reply even on failure (`smtplib.py:466`), so no HELO fallback happens and `login` finds no AUTH extension → 503. Without credentials (test settings only) the session continues to `MAIL` and that reply decides; that configuration is unreachable, because the secrets schema always provides credentials (2.8), so lettre ending the session at the rejected EHLO changes no reachable status (S1b). The fake-SMTP cases pin every EHLO code for the production settings (STARTTLS on → 503, STARTTLS off with credentials → 502). |
| AUTH rejected (any code) | 502 |
| credentials configured but TLS not active | 502, credentials never sent |
| connection refused, timeout, disconnect, and every other transport-level failure: TLS handshake or certificate/hostname failure, STARTTLS or AUTH not offered, no common AUTH mechanism, SMTPUTF8 needed but not offered | 503 (Python: every `OSError`, which includes `smtplib.SMTPException`; see Q3) |
| any other failure inside the submission | 502 |
| any unexpected failure in the route | 500 |

Session rules (exact): one new connection per request; STARTTLS mandatory when
`SMTP_STARTTLS` is true, with chain and hostname verification against
`SMTP_HOST`, never disableable; login only when credentials are configured
(always, given the secrets schema); no retry; QUIT and close failures never
change the outcome (logged as `smtp_cleanup_failed`); no QUIT when the server
already closed the connection. The timeout `SMTP_TIMEOUT_S` applies per
network operation, not to the whole session.

### 2.5 JSON shapes (exact)

- 200: object with exactly `id` (string) and `message` (string starting with
  `Queued`).
- every 4xx/5xx of the route and the 413 layer: object with exactly `message`.
- 404/405 fallbacks: `{"detail": "..."}` (kept).
- All JSON with `content-type: application/json`, UTF-8, compact.

### 2.6 Policy and address rules (exact decisions)

- **Domain normalisation** (`policy.py:23-34`): `strip().lower()`, then IDNA
  UTS46 non-transitional without STD3 mapping, then IDNA2008 label checks
  (hyphen rules, valid `xn--`, joiners, bidi, label ≤ 63, name ≤ 253), result
  lowercase A-label. Measured: `WERSDÖRFER.DE` → `xn--wersdrfer-47a.de`,
  `ß.de` → `xn--zca.de`, `ⅻ.de` → `xii.de`, trailing dot kept
  (`mg.wersdoerfer.de.` → 403), `localhost` valid, `a_b.de`, `xn--abc.de`,
  `a..b`, `-x.de` invalid (400).
- **from**: control characters (2.7) → 400; one mailbox (`Name <addr>` or
  bare `addr`) per value, otherwise 400; the addr-spec must pass the address
  rules below (400); the policy compares `local.lower() + "@" + A-label`.
- **Address rules** (the decisions `email_validator` 2.3.0 makes with
  `check_deliverability=False, test_environment=True`, measured in phase 1
  B 1.4): dot-atom local part (no quoted local part, no leading/trailing or
  double dot), **non-ASCII (EAI) local parts rejected with 400** (Q2; Python
  accepted them before S0-py), domain must
  contain a dot and must not be all-numeric in the last label, no domain
  literals, no IP addresses, special-use names rejected (`.local`,
  `.invalid`, `.onion`, `.arpa`, `.localhost`, `home.arpa`; `.test` allowed),
  length limits as measured (a 65-character local part was accepted; the
  address may have 254 UTF-8 bytes in its input, Unicode and ASCII form),
  RFC 2142 role names (`info`, `postmaster`, …) lowercased as
  `email_validator` does. The
  Rust module implements these rules directly; it is not a port of
  `email_validator`. The fixture corpus (7.2) is the oracle; residual
  differences follow the fail-closed rule of D-11.
- **Mailbox grammar of the Rust port** (`src/address.rs`, S2b), a strict
  subset of Python's parser: optional whitespace (space, TAB) and comments
  around either `addr-spec` or `[phrase] <addr-spec>`; a phrase is words
  (runs without whitespace and `()<>@,:;"[]\`, `.` allowed) and quoted
  strings with backslash escapes, joined by one space; whitespace but no
  comments inside `<…>`; the addr-spec is one token without whitespace.
  Display names follow Python: in the bare form the comments joined by a
  space, in the phrase form the phrase plus ` (<comments before "<">)`;
  comments after `>` are dropped. Comments must be closed and hold no `(`,
  `)`, `\`, `"` or `,`.
- **Address lists**: each `to`/`cc`/`bcc` value is exactly one mailbox
  (`"a@x, b@x"` → 400; `"Doe, Jane" <x@y.z>` is one); `h:Reply-To` is an
  RFC 5322 list. Rust parses each value **once** and uses the same parse for
  the policy decision and the header (Python parses `from` twice, with
  `parseaddr` for the policy and `getaddresses` for the header; the generator
  asserts that both give Rust's result wherever Rust accepts; where they
  disagree, e.g. a comment containing a comma, which `getaddresses` counts as
  a separator, Rust refuses, see D-11).
- **Allowlist** entries in the secrets are normalised with
  `normalize_address` (`policy.py:37-45`): `strip`, split at the last `@`,
  local part lowercased, domain normalised.
- **Control characters** (`headers.py:28`): `[\x00-\x08\x0a-\x1f\x7f-\x9f  ]`;
  TAB allowed. Applies to subject, `h:*` values, `from` and address list
  values. Lengths are counted in code points.

### 2.7 Environment variables (exact: names, defaults, validation)

Prefix `MAILGUN_RELAY_`, names case-insensitive (pydantic-settings), unknown
`MAILGUN_RELAY_*` names ignored, empty values are values (an empty int is a
start failure). Booleans accept `true/false/1/0/yes/no/on/off` and `t/f/y/n`
as pydantic does, case-insensitive; the exact accepted spellings of ints,
floats and bools are pinned by the `config_env.json` fixture. A value that
does not validate stops the process with exit status 1 and no bind.

| Variable | Type | Default | Validation |
| --- | --- | --- | --- |
| `BIND_HOST` | str | `127.0.0.1` | bind failure → exit 1. Every resolved address is bound, IPv6 sockets IPv6-only (asyncio `create_server` under uvicorn: `localhost` serves 127.0.0.1 and ::1, `::` no IPv4) |
| `BIND_PORT` | int | `8085` | bind failure → exit 1 |
| `PUBLIC_HOST` | str | `mailgun.home.xn--wersdrfer-47a.de` | – (domain of the Message-Id) |
| `SECRETS_PATH` | str | `/etc/mailgun-relay/secrets.yml` | file must load (2.8) |
| `SMTP_HOST` | str | `smtp.home.xn--wersdrfer-47a.de` | – |
| `SMTP_PORT` | int | `587` | – |
| `SMTP_STARTTLS` | bool | `true` | – |
| `SMTP_TIMEOUT_S` | float | `30.0` | – |
| `SMTP_CA_FILE` | str | `""` | empty: system store; else added to the system store |
| `SMTP_MAX_CONCURRENCY` | int | `8` | `>= 1` |
| `ENVELOPE_SENDER` | str | `""` | Python since S0-py (`config.py` `_envelope_sender_ascii`): empty → `MAIL FROM:<>`; any ASCII string passes unchanged (not validated, not lowercased); a non-ASCII value must be `<ASCII local>@<domain>`, the domain becomes its A-label, otherwise the start fails. Rust additionally requires a valid bare address (D-15, Rust-stricter) |
| `FAIL_ON_PARTIAL_REFUSAL` | bool | `false` | – |
| `MAX_BODY_BYTES` | int | `26214400` | none (negative allowed) |
| `MAX_ATTACHMENTS` | int | `10` | – |
| `MAX_ATTACHMENT_BYTES` | int | `10485760` | – |
| `MAX_RECIPIENTS` | int | `100` | – |
| `MAX_HEADER_VALUE_LENGTH` | int | `998` | – |
| `LOG_LEVEL` | str | `INFO` | case-insensitive one of `CRITICAL ERROR WARNING INFO DEBUG` (the intersection uvicorn and `logging` accept); else exit 1 |

Production sets every variable except `SMTP_CA_FILE`,
`SMTP_MAX_CONCURRENCY` and `FAIL_ON_PARTIAL_REFUSAL`
(`phase1-measure-deploy.md` 2).

New CLI flags (additions, not part of the env contract): `--version` prints
`mailgun-relay <version> (<commit>)`; `--check-config` loads env and secrets
exactly as the server does, binds nothing, connects nowhere, prints one line
and exits 0 (valid) or 1 (invalid); unknown arguments exit 2.

### 2.8 Secrets YAML (exact schema)

From `relay:config.py:82-225`, rendered by
`ops-library:roles/mailgun_relay_deploy/templates/secrets.yml.j2`:

```yaml
smtp:
  username: <non-empty string>           # not CHANGEME/changeme/replace-me/""
  password: <string>                     # not a placeholder, not empty
tokens:                                  # non-empty list
  - label: <non-empty string, unique, not a placeholder>
    token_sha256: <string>               # strip().lower() must match ^[0-9a-f]{64}$
    mailgun_domains: [<non-empty string>, ...]        # non-empty; normalize_domain
    allowed_from_domains: [<non-empty string>, ...]   # non-empty; normalize_domain
    allowed_from_addresses: [<non-empty string>, ...] # optional; absent/null/[] → domain rule only; normalize_address; non-ASCII local part: Rust start failure (D-17)
```

- Top level must be a mapping; unknown keys are ignored at every level.
- The file is refused when `mode & 0o037 != 0` (world access, group write or
  execute); `0640`, `0600`, `0400` pass (`config.py:173-196`). The check runs
  before the file is read.
- PyYAML `safe_load` is YAML 1.1: plain scalars such as `yes`, `on`, `1_000`,
  `0777`, `2026-10-15` are not strings, so in a string field they make the
  load fail. Rust uses a YAML parser that reports scalar styles and applies
  the YAML 1.1 implicit types to plain scalars, so a config Python rejects is
  never accepted. Python's one coercion, an unquoted all-digit
  `token_sha256` turned into hex (`config.py:135-136`), is not reproduced
  (D-5).
- Error messages never contain secret values.
- `token_sha256` stays the sha256 hex of the raw token; the decommission
  runbook compares digests of deployed `.env` values against it
  (`ops-control:runbooks/mailgun-decommission.md:454ff`).

### 2.9 `/health` (exact)

`GET /health` → 200, `{"status":"ok"}`, `application/json`, no version, no
auth, no SMTP, no log record, answered while submissions hang (Python test
`tests/test_nonblocking_submit.py`). The 413 layer applies to it as to every
path. The ops-library health task asserts status 200, `json.status == "ok"`
and no `version` key (`ops-library:roles/mailgun_relay_deploy/tasks/health.yml:8-27`).

### 2.10 Mail semantics (exact meaning, free byte form)

What must arrive the same (checked by the semantic comparison of 7.4):

- **Envelope**: `MAIL FROM` = `ENVELOPE_SENDER`; `RCPT TO` = to, then cc,
  then bcc, each the normalised addr-spec with an A-label domain (Q2), de-duplicated by exact string,
  first occurrence kept.
- **From** with display name; **To**, **Cc** with display names, in input
  order; **no Bcc header**; **Subject** (stripped); **Reply-To** list;
  other `h:*` headers with name and value (unicode values encoded per
  RFC 2047); **Message-Id** equal to the response `id`; **Date** present.
- **Incoming RFC 2047 encoded words are decoded**, as Python's header
  registry does when it parses the assigned values: in display names
  (`=?utf-8?q?J=C3=B6rg?= <a@example.com>` arrives as display name `Jörg`),
  in the Subject and in unstructured `h:*` values. Rust decodes them (crate
  `rfc2047-decoder`) before building the header.
- **Explicit header encoding path.** lettre's ordinary constructors are not
  relied on for decoded text: lettre 0.11.23 writes a decoded U+0001 in a
  Subject raw and panics on a display name containing CR/LF (review round 2).
  Rust therefore renders every header value whose (decoded) text contains
  anything other than printable ASCII, space or TAB itself: UTF-8,
  RFC 2047 B-encoding, encoded words ≤ 75 characters split on character
  boundaries, display names rendered as an encoded-word phrase in front of
  `<addr-spec>`; the result is inserted with lettre's pre-encoded header
  value API. Printable-ASCII values go through lettre normally (quoted where
  the display name needs it). The control-character check of 2.6 still runs
  on the raw input, as in Python. Decoded control characters keep Python's
  **field-specific statuses** (measured on `13e274f`, review round 3):

  | Decoded content | From | To / Cc | Bcc | Reply-To | Subject, `h:*` |
  | --- | --- | --- | --- | --- | --- |
  | CR/LF (`=?utf-8?B?YQ0KYg==?=`) in display name or value | 200 | **400** (D-16; Python before S0-py: 500) | 200 (not in headers) | 400 | 200 |
  | other control, e.g. `\x01` | 200 | 200 | 200 | 200 | 200 |

  Python writes `\x01` raw into the header (not RFC-conformant); Rust emits
  an encoded word instead, which is the same decoded text (MIME, free). S4
  tests every cell with the Python status, no raw control character in the
  Rust output, and decoded text equal to Python's. A panic anywhere in message construction is a bug, not a
  500 path (the handler catches it only as a last resort).
- **Bodies**: only text → `text/plain`; only html → `text/html`; both →
  `multipart/alternative` [plain, html]; `amp-html` adds `text/x-amp-html` as
  the last alternative. Charset UTF-8. Decoded content equal up to line-ending
  normalisation and one trailing newline.
- **Attachments**: filename (RFC 2231 for non-ASCII), decoded bytes, content
  type reduced to `main/sub`; `multipart/*`, `message/*`, empty or broken
  types become `application/octet-stream`; filename defaults to `attachment`.
- **Inline parts**: `Content-ID: <filename>`, `Content-Disposition: inline`
  with filename; with HTML they sit with the HTML part in
  `multipart/related` inside the alternative; without HTML in the top-level
  `multipart/mixed`; inline parts before attachments.
- **RFC conformance** of the Rust output: CRLF only, lines ≤ 998 octets,
  7-bit clean headers (no SMTPUTF8 is ever needed, Q2), and no defects reported
  by Python's `email` parser (`policy=default`).
- Message-Id form stays `<32 hex@PUBLIC_HOST>` (free, kept for log
  correlation).

### 2.11 Logging (minimum contract, section 4)

Treated as **exact** because the decommission runbook depends on it
(`ops-control:runbooks/mailgun-decommission.md:1008-1024,1144-1166`): unit
and `SyslogIdentifier` `mailgun-relay`, compact JSON lines, `event=request`
with `token_label` and `result` (`ok` on success), and `event=startup` on
every start.

One compact JSON object per line on stdout, flushed per record; the unit keeps
`SyslogIdentifier=mailgun-relay`. Records `event=startup` (each start, at
INFO or the configured level if higher), `event=request` (exactly one per
`POST /v3/{domain}/messages` that reaches the route, none for the 413 layer),
`event=recipients_refused` (WARNING), `event=smtp_cleanup_failed` (WARNING).
Field sets and `result` values as in Python (`relay:app.py:96-132`,
`routes.py:288-358`); section 4 says which parts are load-bearing.
Information boundary (exact, security): no token values or hashes, no
`Authorization` header, no SMTP credentials, no bodies or attachment content,
for refused recipients only domain and code.

### 2.12 Free

Error texts other than those kept in 2.2; FastAPI default bodies (kept
anyway); `server`/`date` headers and reason phrases; log field order, `ts`
format, logger names, `ensure_ascii`, uvicorn's stderr lines; all MIME byte
details (header order, folding, encoded-word choice, transfer encodings,
boundaries, `MIME-Version` in sub-parts, Date format); SMTP wording (verb case,
EHLO name, AUTH mechanism as long as login succeeds, `SIZE`); HTTP
keep-alive and header-size limits; graceful-shutdown timing.

---

## 3. Divergence list (intentional, exhaustive)

Everything that differs and is not listed here or in 2.12 is a bug. The
owner decided every entry on 2026-10-15 (section 13). D-1, D-2 and D-16 are
fixed in Python first (slice S0-py), so after S0-py they are no longer
differences between the implementations: the oracle, the fixtures and the
harness use the fixed Python. Entries D-5 to D-12, D-15, D-17 and D-18 only
affect exotic input or configuration (Q4); their common rule is **fail closed**: where Rust
and Python disagree, Rust may reject what Python accepts (or fail at start
where Python starts), never the reverse.

| # | Python behaviour (at `13e274f`) | Decided behaviour | Status |
| --- | --- | --- | --- |
| D-1 | `text=""` (or `html=""`) with no other non-empty body passes step 4, then `build_message` raises `ValueError` → **500** (`mime_build.py:103-104`; measured). Reachable from Anymail: a Django message with an empty body sends `text=""`. `text=""` together with a non-empty `html` is accepted and the empty text is dropped (200, html only). | **400** at the same position (step 9), so every other decision is unchanged; the empty-text-plus-html case stays 200 html-only. Same fix in Python (S0-py). | Decided 2026-10-15 (Q1); Python via S0-py |
| D-2 | IDN recipient domains are normalised to U-labels: the header gets an RFC-violating encoded word in the domain (`foo@=?utf-8?q?wersd=C3=B6rfer?=.de`), the envelope gets the U-label, `smtplib` switches the whole message to SMTPUTF8 (raw UTF-8 headers); without server SMTPUTF8 → 503. The same applies to an IDN `from` in the header. Non-ASCII local parts (EAI) behave the same way and genuinely need SMTPUTF8. **Security-relevant: externally triggerable.** allauth's "unknown account" mail (`ACCOUNT_EMAIL_UNKNOWN_ACCOUNTS=True`) goes to any address an outside visitor types into the password-reset form of homepage or python-podcast, so anyone can make the relay emit RFC-violating headers and take the SMTPUTF8 path (or a 503) on demand. It does not bypass the token/domain/sender policy. | IDN domains as A-labels in every header address (From, To, Cc, Reply-To) and in the envelope; no SMTPUTF8. EAI local parts → **400** in every address field (`from` at the policy step, the others at step 9), fail closed. Fixed in Python **first** (S0-py, own deploy, before the Rust port), which closes the externally triggerable path now. | Decided 2026-10-15 (Q2); Python via S0-py |
| D-3 | Every `OSError` is TEMPORARY → 503, including `SMTPException` subclasses: STARTTLS not offered, no AUTH, no common mechanism, SMTPUTF8 unsupported, certificate or hostname failure (`smtp_client.py:83-84`). A syntactically broken server reply without a parsable code (no three-digit code, line too long) is code −1 or 500 in `smtplib` → **502** (a refused recipient with −1 at `RCPT`). | **503** as Python: every lettre error without an SMTP reply code maps to 503. Exception, a deliberate divergence: a broken reply without a parsable code is a lettre error without a code, so Rust answers **503** where Python answers 502. Postfix never sends such replies, so production cannot trigger it (S1b: 2 of 42 spike scenarios). | Decided 2026-10-15 (Q3); broken replies: divergence decided by the coordinator 2026-10-15 |
| D-4 | `smtplib.login` prefers CRAM-MD5 > PLAIN > LOGIN. | lettre offers PLAIN and LOGIN only. A server offering only CRAM-MD5 would give Rust 503 where Python logs in. Gate: the read-only EHLO pre-flight on `smtp.home…:587` (S1b) must show PLAIN or LOGIN after STARTTLS; otherwise stop and escalate. S1b: Postfix offers `AUTH PLAIN LOGIN` after STARTTLS, no CRAM-MD5; both implementations use PLAIN. | no-op, verified (S1b) |
| D-5 | Unquoted all-digit `token_sha256` is a YAML int and is converted with `format(x, "064x")` (`config.py:135-136`), i.e. a different hash than written; a plain `yes`/`true` is a `bool`, which Python also treats as an int (hash `0…01`). The ops template quotes the value. | Startup failure for every non-string `token_sha256` (`--check-config` catches it before any switch). Pinned by `config_secrets.json`. | Decided 2026-10-15 (Q4) |
| D-6 | PyYAML `safe_load` accepts anchors/aliases, merge keys `<<`, explicit tags, recursive aliases, any nesting depth, and treats NEL, LS and PS (U+0085, U+2028, U+2029) as YAML 1.1 line breaks. | Anchors/aliases and `!!str` supported; merge keys and other tags (also `!!seq`/`!!map`) → startup failure. The parser (`yaml-rust2`, YAML 1.2 syntax) is wrapped fail-closed (S1, `src/yaml.rs`): an alias to a node that is still open (recursion), nesting deeper than 64 levels, the characters NEL/LS/PS and TAB anywhere (the parsers' tab rules differ), `%YAML`/`%TAG` directives, and empty plain mapping keys → startup failure. Reproduced as Python: PyYAML's implicit types for plain scalars (bool, int, float, null, timestamp; never a string), the failures of its constructors (invalid dates, `0b_`, decimal ints over Python's 4300-digit limit, `=`, `<<` as a value, collection keys), duplicate anchors, non-printable characters, one document only, last duplicate key wins, universal newlines and a leading BOM. Pinned by `config_secrets.json`. | Decided 2026-10-15 (Q4); parser details S1 |
| D-7 | pydantic reads env names case-insensitively, but `__main__.py:8-19` reads `BIND_HOST`, `BIND_PORT`, `LOG_LEVEL` again, case-sensitively and with Python `int()`, so a lowercase or oddly spelled value can make the logged and the real bind differ. With several case variants of one name, pydantic takes the last in environment order. | One reader for everything: a setting is read from the single variable whose name matches case-insensitively, and the logged value is the used value. Several case variants of one name are a startup failure, also when one of them is the exact upper-case name, because Python would use and validate only the last of them in environment order (S1a review; this supersedes the first wording "the exact name wins"; confirmed by the coordinator 2026-10-15 under Q4 fail closed). `BIND_PORT` accepts only spellings both Python readers accept (no `8085.0`), `LOG_LEVEL` only the five names both accept, so with exact names Rust starts exactly when Python starts. `config_env.json` marks the cases that still differ (lower-case names, `warn` under a lower-case name, several variants). | Decided 2026-10-15 (Q4); several variants: coordinator 2026-10-15 (Q4 fail closed) |
| D-8 | (withdrawn in review round 1) urlencoded decoding is reproduced exactly (latin-1, then `unquote_plus`; 2.3 step 3). Decoding raw UTF-8 as UTF-8 instead would have widened acceptance: with `bü.de` allowed, a raw-byte `from=a@bü.de` is 400 in Python (mojibake domain) but would pass in Rust. | – | no divergence |
| D-9 | Multipart decoding uses the `charset` parameter of the request Content-Type with any Python codec (`cp1252`, `utf-16`, `iso-8859-15`, …), falling back to latin-1 on a decoding error or an unknown codec name. | Absent, UTF-8 spellings (`utf-8`, `utf8`, `utf_8`, case-insensitive) and latin-1 spellings (`latin-1`, `latin1`, `iso-8859-1`, `iso8859-1`, `iso_8859_1`, `l1`) and `ascii`/`us-ascii` behave as in Python (incl. the latin-1 fallback). Any other declared charset → **400** (Rust-stricter; recorder and Anymail send no charset). | Decided 2026-10-15 (Q4) |
| D-10 | `idna` 3.16 applies IDNA2008 code point classes; labels that UTS46 allows but IDNA2008 disallows (symbols, emoji, some CONTEXTO cases) are invalid: path domain → 400, and a secrets file containing such a domain fails to load. | Runtime path domains: the `idna` crate (UTS46 + STD3 + hyphen + bidi + joiner + DNS length checks) maps them to an A-label → 403 instead of 400. Configuration must not accept more than Python: a domain entry (in `mailgun_domains`, `allowed_from_domains`, the domain part of `allowed_from_addresses` and of a non-ASCII `ENVELOPE_SENDER`) whose stripped, lower-cased form contains anything other than ASCII letters and digits, `-`, `.`, the letters of Latin-1, Latin Extended-A/B, IPA Extensions and Latin Extended Additional, and the combining diacritical marks U+0300–U+036F is a startup error (S1, `src/domain.rs`); the set applies to the input and to the Unicode form of the resulting A-label, so neither a UTS46 mapping (`ŀ` → `l·`, CONTEXTO in IDNA2008) nor an A-label input (`xn--n3h` = `☃`) brings in another character. So every configured domain is one Python also loads (all production domains are ASCII). Compatibility forms Python maps (`ⅻ.de`, fullwidth letters) and other scripts are therefore refused in the configuration. Because both sides apply the same UTS46 mapping before comparing, a runtime input can then only match a configured domain if Python's mapped form matches it too, so acceptance cannot widen; only the 400/403 split for garbage path domains differs. `config_secrets.json` includes emoji, symbol and mixed-script domains. `domain.json` (S2a) pins the runtime side: every case where Rust maps a domain Python refuses carries `D-10` and the Rust A-label, which the configuration side refuses; it also checks every character of the Latin set in a label, at runtime and as a configured domain. | Decided 2026-10-15 (Q4) |
| D-11 | Address acceptance comes from `email_validator`, `parseaddr` and `getaddresses` (strict mode); comments become display names (`j@x.de (Kommentar)` → `Kommentar <j@x.de>`). | Address rules implemented directly (2.6), pinned by a corpus of ≥ 400 addresses and ≥ 100 domains generated from Python. Corpus cases must match; residual differences found later must be Rust-stricter (400 where Python accepted), and are added to the corpus and this table. The mailbox parser reproduces Python's display-name result for comments (a comment becomes the display name when there is no phrase), pinned by the corpus. S2b: `address.json` (1,570 values: Python test inputs, production senders, each mailbox rule, every Latin-set character in a domain label, every combining mark where a domain or label starts, lengths at the limits, 240 seeded mutations) pins 1,022 accepted mailboxes with Python's address and display name. Rust-stricter residuals (marked `D-11`, 48 values): whitespace or comments inside the addr-spec (`a . b@x.de`, `a(c)@x.de`), an unclosed `<` or quoted string, groups (`grp: a@x.de;`), nested comments and comments holding `\`, `"` or `,`, a backslash outside quotes, address domains outside the Latin set (Greek, Cyrillic, CJK, mixed script) or mapped out of it by UTS46 (`ⅻ`, fullwidth forms, `ŉ`, `·`), and values the two Python parses judge differently (a comment with a comma: Python 400 at step 9 instead of step 5; only the step differs). The `normalize_address` rows of the same corpus carry D-10/D-17 as in S1. | Decided 2026-10-15 (Q4); grammar and residuals S2b |
| D-12 | The ASGI middleware maps unparseable or negative `Content-Length` to 413 (`app.py:42-51`), but in the deployed process uvicorn/httptools rejects such requests before the app. | hyper rejects them before the app as well. The harness compares against real uvicorn; if the status differs it is listed here. | expected no-op |
| D-13 | Logs: local-time `ts` without milliseconds, `ensure_ascii=True`, uvicorn plain-text lines on stderr. | `ts` in UTC RFC 3339 seconds, raw UTF-8, no stderr chatter; the startup record gains `"impl":"rust"`. | free (section 4) |
| D-14 | MIME byte form (Python `email` folding, CTE heuristic, boundaries, `MIME-Version` in sub-parts, Date `+0000`). | lettre's form, 7-bit clean transfer encodings for non-ASCII bodies (no `8BITMIME` dependency). | free |
| D-15 | `ENVELOPE_SENDER` is not validated; any string is sent in `MAIL FROM:<…>`; an IDN or non-ASCII value switches `smtplib` to SMTPUTF8 even for ASCII recipients (verified in the final review). | Empty → null sender (as Python). Python since S0-py: an ASCII value passes unchanged; a non-ASCII value has its domain converted to an A-label and a non-ASCII local part fails the start, so Q2's "no SMTPUTF8" also holds for `MAIL FROM`. Rust applies the same IDN/EAI rule and **additionally** requires a syntactically valid address (fail at start), the remaining divergence: a bare addr-spec by the address rules of 2.6 (no display name, angle brackets or whitespace; special-use names such as `localhost` and dotless domains refused); an ASCII value is used unchanged (no lowercasing). Production renders `mailgun-relay@xn--wersdrfer-47a.de`. `config_env.json` marks the senders Python accepts and Rust refuses `D-15` (S2b). | Decided 2026-10-15 (Q2, Q4); IDN/EAI part via S0-py; validity check S2b |
| D-16 | A `to` or `cc` display name that decodes to CR or LF (`=?utf-8?B?YQ0KYg==?= <a@example.org>`) raises `ValueError` in the email package → **500**; the same in `h:Reply-To` is 400, in `from` 200 (measured). | **400** at the same position (step 9), like Reply-To. Same fix in Python (S0-py). | Decided 2026-10-15 (Q1); Python via S0-py |
| D-17 | `allowed_from_addresses` entries with a non-ASCII (EAI) local part load fine (`normalize_address` only lowercases the local part), but since S0-py an EAI `from` is always 400 before the allowlist check, so such an entry can never match. Python stays unchanged. | The Rust config loader rejects such an entry and the start fails (`--check-config` reports it before any switch). Fail closed under Q4; the production policy contains no such entry today. Pinned in `config_secrets.json`. | Decided 2026-10-15 (coordinator, under Q4); implemented with the secrets loader (S1c) |
| D-18 | pydantic accepts any integer size, any float (`inf`, `nan`, negatives) and any string; Python then fails per request or binds every interface: with `SMTP_PORT` outside 0–65535 every submission fails (`getaddrinfo` error → 503), a non-finite, negative or too large (from about 9.2e9 s) `SMTP_TIMEOUT_S` makes every submission raise `ValueError`/`OverflowError` (502), `BIND_HOST=""` binds all interfaces, huge integers are kept. | Startup failure for: empty `BIND_HOST`; `SMTP_PORT` outside 0–65535; integer settings outside 64-bit; `SMTP_TIMEOUT_S` not finite or outside 0–1e9 s; `SMTP_MAX_CONCURRENCY` above 2^32−1; a value that is not valid UTF-8. Pinned by `config_env.json`. | Q4 (fail closed), added in S1 |

Not divergences, recorded so nobody "fixes" them: empty subject accepted;
recipient limit counted before de-duplication; header name case variants are
separate headers; partial refusal is 200 by default; `/health` has no
version; the 307 trailing-slash redirect; duplicate token hashes resolve to
the last label.

---

## 4. Consumers of log fields and error texts

Checked by grep over ops-control, ops-library, nyxmon, homelab and the
client repositories (`phase1-code-clients.md` 3.3, re-checked for this plan).

| Consumer | Depends on | Consequence |
| --- | --- | --- |
| `ops-control:runbooks/mailgun-decommission.md:1008-1024` (verification gate) | `journalctl -u mailgun-relay` lines matching `'"event":"request"'` (compact, no space), JSON fields `token_label`, `result`, value `ok` | keep: compact JSON, `event`, `token_label`, `result` with Python's values |
| same runbook `:1144-1146`, `:1164-1166` | example line with `ts`, `level`, `logger`; `"event":"startup"` on every start | keep `event=startup`; `ts`/`logger` only illustrative |
| `ops-control:docs/MAILGUN_CREDENTIAL_DISARM.md:349` | names a `policy_error` record as evidence | keep `result=policy_error` |
| `ops-library:roles/mailgun_relay_deploy/README.md:100-139` | documents event types and fields, `journalctl -u` and `-t mailgun-relay` | keep fields; unit keeps `SyslogIdentifier` (role, not binary) |
| `relay:README.md` "Observability", `docs/architecture.md:100-103`, `docs/api-compatibility.md:93` | describe the records and the information boundary | keep; document the Rust differences of D-13 |
| `fix-403-diagnosis.md` 1.2 | inferred the 403 reason from Traefik response sizes | keep policy 403 texts verbatim (2.2) |
| Anymail | `id`, `message` prefix `Queued`; special strings | 2.2, 2.5 |
| recorder (`mailgun.go:75-78`) | first 512 bytes of an error body, display only | free |
| E2E probe (separate item) | HTTP status of its POST, IMAP arrival | contract only, no log fields |
| nyxmon, homelab, Traefik dashboards | no reference to relay log fields (homelab only links `GET /`) | none |

Decision: the Rust logger keeps every event name, every field name and every
`result` value of Python (`ok`, `partial_refusal`, `auth_error`,
`bad_request`, `policy_error`, `too_large`, `smtp_temporary`,
`smtp_permanent`, `error`, `internal_error`), the field order and compact
separators. `error_class` carries Rust error names (free; values are
documented, not consumed). Only D-13 differs. Before cutover the coordinator
asks once whether any generic journald forwarding filters on relay fields
(none found).

---

## 5. Crate choices

Principles: standard crates, minimal features, one runtime thread, no
re-implementation of Python libraries, no hand-rolled protocol code.

| Need | Crate (features) | Notes |
| --- | --- | --- |
| runtime | `tokio` (`rt`, `net`, `time`, `signal`, `sync`, `macros`, `io-util`), **current_thread** | One thread is enough for a few requests a week and keeps RSS low. CPU-heavy steps (MIME encoding of large attachments) run in `spawn_blocking` with `max_blocking_threads(2)`; idle blocking threads exit after 10 s. `getaddrinfo` also runs there. |
| HTTP server | `axum` 0.8 (`default-features = false`, `http1`, `tokio`) on hyper 1 | No HTTP/2, no JSON/form extractors (bodies are parsed by our code). Body-limit layer via `middleware::from_fn`; one fallback handler routes on the decoded path as Starlette does (2.2) and answers 404/405/307. Graceful shutdown on SIGTERM/SIGINT; submissions run in tasks tracked by `tokio_util::task::TaskTracker` (`tokio-util`, `rt`) so a disconnected client neither cancels nor loses them. |
| multipart | `multer` 3 with size constraints | Streams parts; we count fields/files ourselves (Starlette limits, 2.3 step 3). |
| urlencoded | none (own ~40-line splitter and decoder) | Python's exact decoding (latin-1, then `unquote_plus` semantics, 2.3 step 3) is a small rule; `form_urlencoded` decodes raw bytes as UTF-8, which would widen acceptance (review round 1). Pinned by `form_decoding.json`. |
| JSON | `serde` (derive), `serde_json` | Responses and log records from structs; declaration order = field order. |
| YAML | `yaml-rust2` 0.13 (`default-features = false`, event parser and scanner only) | Gives scalar style, tags and anchor names, which the YAML 1.1 subset of 2.8 needs. `serde_yaml` is archived and YAML 1.2. A small typed tree is built from events (`src/yaml.rs`, fail-closed details in D-6). |
| SMTP + MIME | `lettre` `=0.11.23` (`default-features = false`; `builder`, `smtp-transport`, `tokio1`, `tokio1-rustls`, `rustls-native-certs`, `ring`, `hostname`; confirmed in S1b, `rustls-native-certs` is an implicit feature of the optional dependency) | Message builder for 2.10. Submission uses lettre's **connection-level API**, because the high-level `send` aborts on the first refused recipient and cannot express partial refusal (2.4): `AsyncSmtpConnection::connect_with_transport` over our own stream wrapper (banner + EHLO), `starttls`, `auth(&[Plain, Login])`, `command(Mail)`, `command(Rcpt)` per recipient, `command(Data)`, `message`, `quit`. The wrapper sets the per-operation timeouts and a "written" flag that tells a banner failure from an EHLO failure (S1b result). This is lettre's protocol code, not our own. lettre's `Address` is lax and only carries addresses our own validation accepted. |
| SMTP timeouts | `tokio-io-timeout` 1.2 | Read/write timeout per socket operation inside the stream wrapper, the semantics of `SMTP_TIMEOUT_S` in Python; rustls wraps the wrapper, so it also applies under TLS. The TCP connect is bounded with `tokio::time::timeout`. |
| TLS | `rustls` 0.23 (`ring`, `std`, `tls12`) and `rustls-native-certs`, both through lettre; the CA file is read by lettre's `Certificate::from_pem` (bundles with several certificates), so no own `rustls-pki-types` code | No OpenSSL, so the binary links only glibc/libgcc (release check). Roots from the system store, like Python's `create_default_context()` on Ubuntu (`/etc/ssl/certs`, maintained by `ca-certificates`); this matters because the Postfix certificate chains to Let's Encrypt's newer hierarchy (issuer YE2), which a bundled `webpki-roots` snapshot might lag. `SMTP_CA_FILE` adds to the system roots (`TlsParameters::builder(host).add_root_certificate`), as `load_verify_locations` does. Hostname verified against `SMTP_HOST`; no `dangerous_*` call. S1b validated the live chain with the exact Ubuntu bundle of macmini (which lacks ISRG Root YE and builds the path through the cross-signs). `ring` instead of `aws-lc-rs` avoids cmake/nasm in the build. Built once at startup. |
| auth | `base64` 0.22 (custom engine, 2.3), `sha2`, `subtle` (constant-time equality) | |
| IDNA | `idna` 1 (UTS46 non-transitional, STD3 deny list, hyphen and DNS-length checks, root dot allowed) | Residual: D-10. |
| Unicode | `unicode-normalization` (NFC for local parts) | |
| RFC 2047 | `rfc2047-decoder` | decoding of incoming encoded words (2.10); encoding is lettre's |
| patterns | `regex` (`std` only) | YAML 1.1 implicit-type table and Starlette's host pattern; all patterns are ASCII. Env parsing, header-name and control-character checks are plain code. |
| randomness | `getrandom` | 128-bit hex for `request_id` and Message-Id. |
| logging | none (own ~60-line JSON line writer on stdout, flush per record) | `tracing-subscriber`'s JSON layout does not give these field names without a custom formatter; a direct writer is smaller. UTC timestamp formatting is ~15 lines (no time crate). |
| CLI | none (three flags, manual argv) | |
| tests | `tempfile`, `rcgen` (test CA/certs), `tokio` test utilities; a scripted fake SMTP server in the tests | |

Build profile: `opt-level = "s"`, decided by measurement in S1 (Linux
aarch64 container, glibc, release build of S1: 1.58 MB and 2.6 MiB idle RSS
against 1.77 MB and 2.9 MiB with `opt-level = 3`; one thread; S5
re-measures with TLS), `lto = "thin"`, `codegen-units = 1`, `strip = true`,
`panic = "unwind"` (a panic in one request must not kill the process; it maps
to 500).

Target: `x86_64-unknown-linux-gnu`, glibc floor 2.35, not musl. Reason as in
`nyxmon:agent-rs/PLAN.md` 8.1: `SMTP_HOST` is a split-horizon name resolved
through glibc `getaddrinfo` and `nsswitch.conf` in Python; musl's resolver
behaves differently with several nameservers.

Memory notes: request bodies are buffered in memory up to `MAX_BODY_BYTES`
(Python spools files over 1 MiB to `/tmp`; the unit has `PrivateTmp` and
empty `ReadWritePaths`, so Rust does not use disk). If glibc keeps freed large
buffers resident after a big request (dynamic mmap threshold), the drop-in
gets `Environment=MALLOC_ARENA_MAX=2` and `MALLOC_MMAP_THRESHOLD_=131072`,
decided by the measurement of section 12, not up front (`unsafe` is
forbidden, so no `malloc_trim` call).

---

## 6. Slices

Order: S0-py and S1/S1b start in parallel; S2 waits for S0-py on `main`.

Rules (as nyxmon): one branch per slice (`rust/sNN-<name>`; S0-py uses
`fix/s0-py-idn-eai-empty-body`), reviewed with
the codex review loop (`gpt-6.1-sol`, high) with `handoff/parity-contract.md`
as context, merged to `main`. Every slice keeps the Python checks green
(`uv run pytest -q`, `ruff`, `mypy`) and the Rust checks green
(`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
`cargo test --locked`, `cargo deny check`), updates `rust/TESTMAP.md`, and
names the Python functions it covers in its review context. Target ≤ 1.5k
changed lines per slice excluding generated fixtures.

| # | Slice | Scope | Depends on |
| --- | --- | --- | --- |
| S0-py | Python fix before the port (Q1, Q2) | Python-only change in `src/mailgun_relay` (branch `fix/s0-py-idn-eai-empty-body`): empty `text`/`html` without another body → 400 (D-1); To/Cc display name decoding to CR/LF → 400 (D-16); IDN domains as A-labels in From/To/Cc/Reply-To and the envelope, so `smtplib` never switches to SMTPUTF8 (D-2); EAI local parts → 400 in `from` (policy step) and in `to`/`cc`/`bcc`/Reply-To (step 9); `ENVELOPE_SENDER` normalised at startup (IDN domain → A-label, non-ASCII local part → start failure, empty stays the null sender, D-15); tests for each (both encodings, the allauth-style external IDN recipient, multi-fault order); `docs/api-compatibility.md`, README if affected, CHANGELOG; own review, own deploy to macmini | – (first; parallel to S1). **Status: merged on `main` as `bc8880e`, deploy approved (after the 403 fix)** |
| S1 | Skeleton, config, `/health` | MIT `LICENSE` at the repository root (Q6); package, toolchain, `deny.toml`, CI `rust` job; env settings (2.7), secrets loader with YAML 1.1 subset and mode check (2.8); `--version`, `--check-config`; startup record; axum server, `/health`, 404/405/307 fallbacks, 413 layer, graceful shutdown; fixture generator skeleton + drift test; `rust/README.md`; `.gitignore`; ops-library: `rust/target/` rsync exclude | – **Status: split by size into S1a (plumbing, CI, `LICENSE`, env settings, `--version`/`--check-config`, fixture generator + drift test, `.gitignore`, ops-library exclude; merged), S1c (secrets loader, YAML subset, D-17; merged), S1d (server, `/health`, fallbacks, 413, startup record, graceful shutdown; merged); one review and merge each. Done** |
| S1b | Spike: lettre and the live SMTP server | throwaway branch: lettre connection API can send MAIL + individual RCPT + DATA with partial refusal and expose reply codes; addresses the corpus accepts round-trip through lettre `Address`; feature names; **read-only** EHLO on macmini (`openssl s_client -starttls smtp`, EHLO, QUIT): `AUTH` mechanisms after STARTTLS, `SMTPUTF8`, `SIZE`. Result recorded in this plan. | – (parallel to S1). **Status: done, GO with conditions (`rust/spike-s1b` @ `78f3254`)** |
| S2 | Auth and policy (security boundary) | Split by size: **S2a** `auth.rs`, `auth.json`, `domain.json` (runtime `normalize_domain`), Python fix of the auth 500 (2.3 step 2); **S2b** `address.rs`, `address.json`, the D-15 check; **S2c** `policy.rs`, `policy.json`, production shapes. Scope: `auth.rs`, `domain.rs`, `address.rs`, `policy.rs`; fixtures `auth.json`, `domain.json`, `address.json` (corpus), `policy.json`; Rust counterparts of `test_auth.py`, `test_policy.py`, the address parts of `test_headers.py`; Python tests added for every corpus case that pins a new boundary decision; config loader rejects allowlist entries with a non-ASCII local part (D-17; implemented with the secrets loader in S1c); the D-15 validity check of `ENVELOPE_SENDER` (S1 applies only the IDN/EAI rule; `config_env.json` then marks the invalid senders D-15) | S1, S0-py merged (the oracle must already carry the Q1/Q2 behaviour). **Status: S2a, S2b and S2c merged; done** |
| S3 | Request parsing and pipeline | `form.rs` (both encodings, limits), `pipeline.rs` (2.3 steps 1–9 with a stub submitter), header/subject validation, error mapping, response JSON, `event=request` record; fixtures `headers.json`; counterparts of `test_messages_endpoint.py` (non-SMTP), `test_headers.py`, `test_body_limit.py` | S2 |
| S4 | MIME construction | `mime.rs` with lettre builder (2.10), envelope and de-duplication, Message-Id/Date, inline/related/mixed, container downgrade, Reply-To; IDN as A-labels, EAI rejected (Q2); semantic tests by parsing the output; counterparts of `test_mime_build.py` | S2 (parallel to S3) |
| S5 | SMTP submission | `smtp.rs` on lettre's connection API: STARTTLS with system roots + CA file, AUTH, per-recipient RCPT, partial refusal, classification of 2.4, QUIT/close cleanup records, concurrency semaphore, per-operation timeout, `recipients_refused` and `smtp_cleanup_failed` records; scripted fake SMTP server tests mirroring `test_smtp_submission.py`, `test_smtp_outcomes.py`, `test_nonblocking_submit.py`; the S1b conditions (see "S1b result") | S1b, S3, S4 |
| S6 | Parity harness | `rust/parity/` (7.4): fake SMTP with STARTTLS/AUTH, case corpus, runner for both implementations, semantic MIME comparison, CI job `parity`; process-level tests of the binary | S5 |
| S7 | Release pipeline | `.github/workflows/rust-release.yml`, `scripts/release_checks.py` + tests (adapted from nyxmon), first tag `rs-v0.2.0` after S6 | S6 (tag) |
| S8 | Role and inventory | ops-library `mailgun_relay_deploy` changes (9.1) with tests and molecule; ops-control host vars (impl `python`, version pinned), playbook gate, runbook `docs/MAILGUN_RELAY_RUST.md`; deploy to macmini: binary installed, `--check-config` green against production files, nothing switched | S7 |
| S9 | Shadow | section 10 phases A and B on macmini, report in ops-control docs | S8, S0-py deployed, E2E probe item |
| S10 | Cutover and soak | sections 10.4–10.6 incl. rollback drill, docs final state in all three repos | S9 |

Acceptance criteria (in addition to the green checks):

- **S0-py**: `uv run pytest -q`, `ruff check`, `ruff format --check`,
  `mypy` green; new tests: `text=""` alone → 400 and `text=""` + html → 200
  html-only; `html=""` alone → 400; encoded CR/LF in a To and in a Cc
  display name → 400 (and with an additionally invalid Cc → 400); a recipient
  `foo@xn--wersdrfer-47a.de` and `foo@wersdörfer.de` → 200 with
  `foo@xn--wersdrfer-47a.de` in the To header and in `RCPT TO`, no
  `SMTPUTF8` on `MAIL FROM` (aiosmtpd test offering SMTPUTF8); IDN `from`
  and Reply-To rendered as A-labels; EAI local part in `from`, `to`, `cc`,
  `bcc`, Reply-To → 400; `ENVELOPE_SENDER=relay@wersdörfer.de` is sent as
  `MAIL FROM:<relay@xn--wersdrfer-47a.de>` without `SMTPUTF8`, a non-ASCII
  local part in it fails the start, an empty value still gives
  `MAIL FROM:<>`; all other existing tests unchanged. Reviewed with
  the codex review loop (contract as context). Deployed with `just deploy-one
  mailgun-relay` from ops-control in tmux after owner approval of the restart
  (coordinate with other relay deploys of the campaign): `/health` 200,
  startup record present, the E2E probe (once live) green. The relay CHANGELOG records the behaviour change for clients
  (400 instead of 500; IDN headers now ASCII; EAI recipients rejected).

- **S1**: `config_env.json` and `config_secrets.json` cases all match
  (≥ 60 env sets incl. every bool spelling, int/float spellings, empty values,
  case variants; ≥ 40 YAML documents incl. each schema error, YAML 1.1
  plain-scalar types, placeholders, duplicate labels, mode bits);
  `/health` 200 without `version`, `HEAD /health` 405, `GET /` 404,
  `/health/` 307, 413 for an over-limit `Content-Length` on `/health` and on a
  404 path; `--check-config` exit 0/1, `--version` format; the drift test fails
  when a fixture is edited by hand; idle RSS of a local release build
  recorded.
- **S1b**: a short written result in this plan: API calls used, partial
  refusal demonstrated against a scripted server, the EHLO capabilities of
  macmini:587 (no credentials used, QUIT after EHLO), and any blocker. A
  blocker (no per-recipient handling, no PLAIN/LOGIN) stops the campaign at
  this point for an owner decision; no fallback to hand-rolled SMTP.
- **S2**: every fixture case matches; a secrets file with an EAI entry in
  `allowed_from_addresses` fails the start and `--check-config` (D-17); corpus sizes as in D-11; a property
  test over the corpus asserts "Rust accepts ⇒ Python accepts" for
  addresses, domains and auth; Python and Rust both test the production
  policy shapes (cross-domain path vs from, address allowlist, IDN allowlist).
- **S3**: the decision order of 2.3 is covered by multi-fault cases
  (e.g. foreign path domain + `o:tag` → 400; oversized attachment before
  `o:tag` → 413; bad auth + malformed multipart → 401); every status of 2.3
  steps 1–9 has a Rust test; both encodings tested explicitly.
- **S4**: semantic tests for every row of 2.10 parse the produced bytes and
  assert structure, decoded bodies, headers, no Bcc, CRLF, line length.
- **S5**: every row of 2.4 has a fake-server test incl. 421/450/451/550 on
  each phase (EHLO/HELO per the EHLO row, with STARTTLS on and off), the
  statuses taken from the Python run of the same script, all-refused mixtures, QUIT failure after accepted DATA,
  already closed connection, TLS with an `rcgen` CA via `SMTP_CA_FILE`,
  wrong hostname → 503, no TLS with credentials → 502; `/health` answers
  while a submission hangs; the concurrency cap queues. The S1b conditions
  hold: the 42 scenarios of `rust/spikes/s1b/fake/run_matrix.py` (branch
  `rust/spike-s1b`) are the template and give Python's status except the
  documented D-3 and D-4 cases; positive replies are checked for the exact
  codes `smtplib` requires (MAIL 250, RCPT 250/251, DATA 354, end of data
  250); QUIT is sent after "STARTTLS not offered"; envelope addresses are
  checked to be ASCII before `MAIL`/`RCPT` (lettre adds no `SMTPUTF8`
  itself, Q2); `deny.toml` gains ISC for `ring`.
- **S6**: `parity` CI job green with zero unexplained differences on the
  full case corpus (≥ 150 request cases); runtime ≤ 5 min.
- **S7**: archive + sha256 from `workflow_dispatch`; glibc floor ≤ 2.35;
  release `rs-v0.2.0` exists.
- **S8**: ops-library and ops-control `just test`, `just lint`,
  `just typecheck`; deploy with `impl: python`: binary under
  `/opt/mailgun-relay/0.2.0/`, `--check-config` OK, no drop-in, unit still
  Python (argv check), no restart when nothing else changed.
- **S9, S10**: as in sections 10 and 12, with numbers recorded.

### S1b result (2026-10-15)

GO with conditions; no blocker, no owner stop (`handoff/s1b-spike-result.md`,
prototype on `rust/spike-s1b` @ `78f3254`, not merged).

- **Partial refusal works** with public lettre 0.11.23 calls:
  `connect_with_transport` → `starttls` → `auth` → `command(Mail)` →
  `command(Rcpt)` per recipient (a refusal is `Err` with `status()` = the
  code, the connection stays usable because `command` does not abort) →
  `command(Data)` → `message` → `quit`. Demonstrated against a scripted
  server and against aiosmtpd with mandatory STARTTLS and AUTH.
- **Status classes:** 39 of 42 scenarios give Python's status (oracle: the
  real `smtp_client.submit` against the same scripted server). The three
  others: CRAM-MD5-only (D-4, unreachable on Postfix) and two broken replies
  without a parsable code (D-3, 503 instead of 502).
- **EHLO of `smtp.home.xn--wersdrfer-47a.de:587`** (read-only: banner,
  EHLO, STARTTLS, EHLO, QUIT; no credentials): Postfix 3.8.6; before TLS
  `PIPELINING, SIZE 52428800, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES,
  8BITMIME, DSN, CHUNKING` without AUTH; after STARTTLS (TLS 1.3) the same
  with `AUTH PLAIN LOGIN` instead of STARTTLS. No CRAM-MD5 (D-4 no-op), no
  `SMTPUTF8` (confirms Q2), `SIZE` 50 MiB. The chain validates with rustls
  and the system roots, including the exact Ubuntu bundle of macmini.
  Python sends `EHLO [127.0.1.1]`, lettre `EHLO macmini`; the EHLO name is
  free (2.12) and passes `reject_invalid_helo_hostname`.
- **Resources:** a full submit with STARTTLS and AUTH peaks at 4.1 MB VmHWM
  (Linux, glibc, `current_thread`); the spike release binary is 3.5 MB and
  links only libc and libgcc_s.
- **Conditions** for S5 (taken into its scope and acceptance above): exact
  positive codes, QUIT after "STARTTLS not offered", ASCII envelope check,
  stream wrapper for timeouts and banner/EHLO attribution, test
  certificates with AKI/SKI for Python's `VERIFY_X509_STRICT` (also S6).
  Not reproduced, recorded only: an AUTH reply 503 ("already
  authenticated") counts as success in `smtplib` and as 502 in lettre
  (unreachable).

---

## 7. Test strategy

### 7.1 Rust tests

Unit tests per module (fixture-driven where Python is the oracle) and
integration tests in `rust/tests/` that start the router in-process or the
built binary on a loopback port, with a scripted fake SMTP server (TCP,
optional STARTTLS with `rcgen` certificates, scripted replies per command).
No test reaches the network.

Security boundary on both sides (`relay:AGENTS.md`): every auth, domain and
sender rule has a Python test (existing, or added in S2) **and** a Rust test
or fixture case. A rule change touches both in one pull request.

### 7.2 Fixtures: Python as oracle for contract and policy

`rust/fixtures/generate.py` (`uv run python rust/fixtures/generate.py`)
imports `src/mailgun_relay` and writes deterministic JSON (sorted keys,
stable inputs). Rust loads them with `include_str!`.

| Fixture | Python source | Content |
| --- | --- | --- |
| `auth.json` | `auth.authenticate` | raw `Authorization` header bytes × token set → matched label or reject (incl. trailing-bit, padding, whitespace, `:` in password, non-UTF-8, `API`, duplicate hashes) |
| `domain.json` | `policy.normalize_domain` | input → A-label or invalid |
| `address.json` | `policy.parse_email_strict`, `headers.parse_address_list`, `parse_header_address_list`, `policy.normalize_address` | input → accept/reject per function, normalised addr-spec (compared in A-label form), display name (exotic cases: decision only) |
| `policy.json` | `policy.enforce_policy` | policy × path × from → ok / 400 / 403, with the 403 message or the policy address (S2c: 5 production-shaped policies × 13 paths × 22 senders, D-10/D-11 marked) |
| `headers.json` | `headers.validate_subject`, `validate_custom_headers`, `contains_forbidden_control_chars` | value → ok / 400 |
| `form_decoding.json` | Starlette `FormParser` / `MultiPartParser` decoding (`unquote_plus(x.decode("latin-1"))`, `_user_safe_decode`) | raw urlencoded bodies and multipart bodies × request charset → ordered items (D-9 marked) |
| `config_env.json` | `config.Settings` + the `__main__` reads | env set → settings or start failure (D-7 marked) |
| `config_secrets.json` | `config.load_secrets` | YAML text × file mode → policies or failure (D-5, D-6 marked) |

Only decisions and normalised values are stored, never message texts
(free). Divergent cases carry `"divergence": "D-n"` and the expected Rust
result, so the table in section 3 and the fixtures cannot drift apart.

Drift guard: `tests/test_rust_fixtures.py` regenerates in memory and asserts
equality with the committed files, so a Python behaviour change cannot merge
without regenerating, and the Rust tests then show what Rust must change.

### 7.3 Corpus generation

The address and domain corpora combine hand-written boundary cases (each rule
of 2.6), all production policy shapes (labels, domains, senders of
`fix-403-diagnosis.md` 1.3, without tokens), every Python test input, and a
seeded generator that mutates valid addresses (dots, quotes, comments,
brackets, Unicode letters and symbols, lengths 63–66 and 253–255, special-use
suffixes, IDN in both forms). The seed is fixed and the output committed.

### 7.4 Differential parity harness (process level)

`rust/parity/run_parity.py` (stdlib only, so it also runs on macmini;
started in CI via `uv run`):

- Starts the Python relay with real uvicorn (`python -m mailgun_relay`) and
  the Rust binary on two loopback ports with identical env and a test secrets
  file (dummy tokens, production-shaped policies, mode 0640).
- Each implementation gets its own fake SMTP server (`parity/smtp_fake.py`,
  stdlib: STARTTLS with a throwaway CA made by `openssl` at start, AUTH
  PLAIN/LOGIN accepted, scripted replies per case, records envelope and DATA).
  `SMTP_CA_FILE` points at the throwaway CA, `SMTP_HOST=localhost`.
- Sends every case of `parity/cases/*.yaml` byte-identically to both (fields
  ordered; urlencoded, multipart or raw body; raw headers for auth cases).
- Compares: status; contract headers (`www-authenticate`, `allow`,
  `location` path, `content-type`); JSON keys and the `Queued` prefix;
  whether an SMTP session happened; `MAIL FROM`; the ordered `RCPT TO` list
  (A-label normalised, D-2); DATA parsed for both with Python
  `email.message_from_bytes(policy=default)`: From/To/Cc/Reply-To as
  (display name, A-label addr-spec), Subject decoded, `h:*` headers
  decoded, absence of Bcc, Message-Id equal to the response `id`, Date
  present, the content-type tree, decoded bodies (line endings normalised, one
  trailing newline tolerated), parts (disposition, filename, Content-ID,
  content type, sha256); for the Rust message additionally no parser defects,
  CRLF only, lines ≤ 998; the `event=request` record (`token_label`,
  `result`, `status_code`).
- Masks nothing else; error texts and non-contract headers are not compared.
- Cases expected to differ carry `divergence: D-n` and the Rust expectation.

The case corpus covers P1–P12 of `phase1-code-clients.md` (Anymail
urlencoded shapes of homepage, python-podcast and ggs, recorder multipart in
random field order, Django error mails with long subjects and tracebacks,
German allauth/Wagtail texts, `Auto-Submitted`, text+html, attachments,
inline with and without HTML, amp-html, Reply-To lists, Cc/Bcc with
duplicates), every row of 2.3 and 2.4, multi-fault ordering cases, limits at
N and N+1, the D-entries, and the exotic list of phase 1 B 4.2.

CI: job `parity` (needs the `python` and `rust` jobs) builds the binary and
runs the harness. The existing `python` job runs the drift test.

### 7.5 TESTMAP

`rust/TESTMAP.md` maps every Python test (222 at `13e274f`) to its Rust
counterpart, fixture or harness case, with status per slice (sketch
committed with this plan).

---

## 8. Release

Adapted 1:1 from nyxmon (`nyxmon:.github/workflows/agent-rs-release.yml`,
`agent-rs/scripts/release_checks.py`):

- Workflow `.github/workflows/rust-release.yml`, trigger: tag `rs-v<semver>`
  (release) or `workflow_dispatch` (artifact only). `permissions: contents:
  read`, `contents: write` only in the release job. Actions pinned to commit
  SHAs. No cargo cache.
- Build on `ubuntu-22.04` (glibc 2.35), toolchain from
  `rust/rust-toolchain.toml`: tag equals crate version; `cargo fmt --check`,
  `clippy -D warnings`, `cargo test --locked`, `cargo build --release
  --locked --target x86_64-unknown-linux-gnu`.
- `release_checks.py glibc-floor --max 2.35`: no symbol newer than
  `GLIBC_2.35`, `NEEDED` only glibc/libgcc. macmini has 2.39.
- `smoke`: `--version` prints `mailgun-relay <version> (<full commit>)`;
  additionally `--check-config` against a test env and secrets file exits 0.
- `pack`: deterministic `mailgun-relay-<ver>-x86_64-unknown-linux-gnu.tar.gz`
  with exactly `mailgun-relay` and `LICENSE` (root-owned, commit time as
  mtime, gzip without name) plus `.sha256`, verified with `sha256sum --check`.
- `gh release create --verify-tag`; a pre-release version becomes a GitHub
  pre-release.
- `LICENSE` (MIT, as nyxmon) is added at the repository root in S1 (Q6).
- CI job `rust` in `ci.yml` additionally runs `cargo deny check` with a
  pinned `cargo-deny` (sha256-verified, as `nyxmon:.github/workflows/ci.yml:78-130`)
  and reports the binary size.

---

## 9. Deployment through the role

### 9.1 ops-library `mailgun_relay_deploy`

Modelled on `nyxmon_deploy` (`phase1-measure-deploy.md` 4.1, 5.1–5.7):

```yaml
mailgun_relay_impl: python                 # python | rust
mailgun_relay_rust_version: ""             # e.g. "0.2.0"; required for rust
mailgun_relay_rust_sha256: ""              # sha256 of the release archive, 64 lowercase hex
mailgun_relay_rust_release_url: >-
  https://github.com/ephes/mailgun-relay/releases/download/rs-v{{ mailgun_relay_rust_version }}/mailgun-relay-{{ mailgun_relay_rust_version }}-x86_64-unknown-linux-gnu.tar.gz
mailgun_relay_rust_local_archive: ""       # controller path (development), replaces the download
mailgun_relay_rust_install_root: /opt/mailgun-relay
mailgun_relay_rust_keep_versions: 3
```

Order in `tasks/main.yml`:

1. Validation assert of the new variables before `user.yml` (impl value,
   semver, 64-hex sha256, version needs sha256 or local archive, rust needs a
   version, absolute install root ≠ `/`, keep ≥ 1).
2. `user.yml`, `source_*.yml`, `python.yml`, `config.yml` unchanged and run
   for both implementations: the venv is the rollback path and env/secrets are
   shared. `mailgun_relay_rsync_excludes` gains `rust/target/` (S1).
3. New `rust.yml` after `config.yml`, before `service.yml`, when a version is
   set (also with impl `python`, to install ahead of the switch): staging,
   checksum-verified download or local archive, member check (exactly the
   regular files `mailgun-relay` and `LICENSE`), unpack to
   `<root>/<version>/` root:root 0755, `.archive-sha256`, atomic move, never
   modify an installed version.
4. Candidate validation by the versioned path: `--version` as the service
   user, then `--check-config` under the unit's identity and environment:
   `systemd-run --wait --pipe --collect -p User=mailgun-relay -p
   Group=mailgun-relay -p EnvironmentFile=/etc/mailgun-relay/mailgun-relay.env
   <root>/<version>/mailgun-relay --check-config`. Failure: `rescue` removes a
   freshly installed version; drop-in and running unit untouched.
   **Rollback must not depend on Rust**: with `impl: python` the drop-in is
   removed (step 5) *before* `rust.yml` runs, and a failure in steps 3–4
   (download, archive check, `--version`, `--check-config` rejecting a
   configuration Python accepts) is reported as a warning and the run
   continues to restart and verify Python. Only with `impl: rust` are these
   failures fatal. Molecule covers it: a broken archive and a
   `--check-config` failure with `impl: python` still end with Python
   running and no drop-in.
5. Drop-in `/etc/systemd/system/mailgun-relay.service.d/impl.conf` only for
   `rust` (`ExecStart=` reset, then the versioned binary; `WorkingDirectory`
   unchanged while the venv exists); for `python` it is removed early (see
   step 4). Version or impl change → reload and
   restart; otherwise no restart. Base unit, hardening, `EnvironmentFile`,
   `SyslogIdentifier` unchanged. No extra hardening in the first release.
6. `.previous-version` as rollback target.
7. After `flush_handlers` and the unchanged `health.yml`: live verification
   with retries: rust → `readlink /proc/<pid>/exe` equals the versioned
   binary; python → argv contains `…/.venv/bin/python` and `-m mailgun_relay`
   (`/proc/<pid>/exe` points at the uv-managed interpreter).
8. Pruning only after verification; keeps pinned, running, previous and the
   newest N versions; touches only version-shaped directories.

Existing task and handler names stay (`tests/test_deploy_restart_notifications.py:90-98`).
New `tests/test_mailgun_relay_deploy.py` (defaults, release URL, drop-in
rendering, task order, `when`/`notify`). Molecule scenario (the first for this
role) with fake archives built from a small C program that answers
`--version`, `--check-config` and `GET /health` on `MAILGUN_RELAY_BIND_PORT`:
switch, version change with pruning, wrong version rejected, different archive
for an installed version rejected, symlink member rejected, rollback to
Python. README section, CHANGELOG, minor version bump.

### 9.2 ops-control

- `inventories/prod/host_vars/macmini.yml`: block with `mailgun_relay_impl`,
  `mailgun_relay_rust_version`, `mailgun_relay_rust_sha256`, comment and
  runbook link. Not in the playbook's role `vars:`
  (`playbooks/deploy-mailgun-relay.yml:53-60`), which would override host vars.
- `playbooks/deploy-mailgun-relay.yml`: pre-task asserting the ops-library
  version that knows `mailgun_relay_impl` (pattern of
  `deploy-nyxmon.yml:17-32`).
- Runbook `docs/MAILGUN_RELAY_RUST.md` modelled on `docs/NYXMON_RUST_AGENT.md`:
  how the switch works, before you start (tmux, `show-path-overrides`,
  `install-local-library`, `$PROJECTS_ROOT/mailgun-relay` must exist even for
  rust because the venv is still built), install without switching, shadow,
  cutover, verification, rollback, deploy log.
- `software-estate.yml:155-164` and `docs/SOFTWARE_ESTATE_COVERAGE.md:55`:
  the probe describes the implementation actually running.
- CHANGELOG entries in ops-library and ops-control.

---

## 10. Shadow operation, cutover

No double delivery at any time: the production unit keeps serving
`127.0.0.1:8085`; shadow instances bind other loopback ports, are not behind
Traefik, and either talk to a local capture sink or (phase B only) send to the
monitor mailbox.

Prerequisites: S8 deployed (binary installed, impl `python`); the E2E probe
item live (POST with its own token to the monitor mailbox every 15 min,
checked by nyxmon `json-metrics` and IMAP); the 403 policy fix and S0-py deployed; owner
approval for the shadow run and for the controlled test mails of phase B
(bundled by the coordinator).

### 10.1 Phase A: capture shadow with production configuration (≥ 24 h)

On macmini, in tmux, as transient units with the production hardening and the
service user:

- Two capture sinks (`rust/parity/smtp_fake.py`, stdlib, run by the host's
  `python3`) on `localhost:2526` (for Python) and `localhost:2527` (for Rust),
  STARTTLS with a throwaway CA created in `/var/lib/mailgun-relay-shadow`
  (0700, owner `mailgun-relay`), AUTH accepted, recording envelope and DATA
  there.
- Shadow secrets: a copy of `/etc/mailgun-relay/secrets.yml` (0640) plus one
  shadow-only test token (random, hash only in the copy) whose policy covers
  the test shapes. So the real production policies are loaded and exercised
  (401/403 paths with real labels), and the 200 paths run with the test token.
- `mailgun-relay-shadow-py` (venv `python -m mailgun_relay`, port 8087) and
  `mailgun-relay-shadow-rs` (`/opt/mailgun-relay/<v>/mailgun-relay`, port
  8086), each with `EnvironmentFile=/etc/mailgun-relay/mailgun-relay.env` plus
  overrides `BIND_PORT`, `SECRETS_PATH`, `SMTP_HOST=localhost`, `SMTP_PORT`,
  `SMTP_CA_FILE`.
- `run_parity.py --targets 127.0.0.1:8087,127.0.0.1:8086 --sinks …` replays
  the full case corpus of 7.4 against both and compares exactly as in CI, but
  with the production env, the production policies and the real host
  (glibc resolver, systemd hardening, file modes).
- The Rust shadow then stays up for ≥ 24 h idle with a light synthetic load
  (one corpus pass per hour) to measure RSS/CPU (section 12).

Acceptance: zero unexplained differences; RSS/CPU targets of section 1 met
or a measured explanation; `--check-config` and startup record correct.

### 10.2 Phase B: controlled real mails through Rust

The Rust shadow is restarted on port 8086 with the production SMTP settings
(real Postfix, real STARTTLS/AUTH). Only the probe token is used, and only to
the monitor mailbox:

- the probe request itself (the probe item exposes its POST as a script with
  a URL override; it is run once against `127.0.0.1:8086`);
- four further shapes from the same probe sender to the monitor mailbox:
  text only with German umlauts and a long subject; text + html; one
  attachment with a non-ASCII filename; an inline image with HTML.

Verification: HTTP 200 with `id`; Postfix log shows the relay's SASL login
and delivery; IMAP shows each message with intact subject, bodies, parts, and
`Authentication-Results` with `dkim=pass`. The existing cleanup timer removes
the mails after a day.

### 10.3 Production traffic mirroring (decided: none)

Decided 2026-10-15 (Q5): no mirroring of production traffic. Phases A and B
(synthetic corpus with the production configuration, controlled mails to the
monitor mailbox) and the E2E probe after cutover replace it. Rejected:
Traefik mirroring for 7 days or a 48 h window (ingress change; real tokens
and mail content would reach the shadow process).

### 10.4 Cutover

1. Announce, owner approves the deploy (restarts the relay for all clients;
   ~1–2 s; Anymail does not retry, so a send in that window is lost; at a few
   mails a week acceptable).
2. Set `mailgun_relay_impl: rust` in macmini host vars; `just deploy-one
   mailgun-relay` in tmux. The role installs nothing new, runs
   `--check-config`, writes the drop-in, restarts, checks `/health` and
   `/proc/<pid>/exe`.
3. Record cutover time T1.

### 10.5 Verification after cutover

- `systemctl status mailgun-relay`: active, MainPID exe under
  `/opt/mailgun-relay/<v>/`; `journalctl -t mailgun-relay` shows the startup
  record with `"impl":"rust"` and the production token labels.
- `GET https://mailgun.home.xn--wersdrfer-47a.de/health` → 200 via Traefik.
- E2E probe: the next two runs green (json-metrics status 200, IMAP fresh).
- An unauthenticated POST via Traefik → 401 with realm; a POST with the probe
  token and a foreign from → 403 (no mail).
- Traefik log after T1: statuses of real clients (200 for Django error mails
  after the fix).
- RSS/CPU after 1 h and 24 h (section 12).
- **Rollback drill**: flip to `python`, deploy, probe green; flip back to
  `rust`, deploy, probe green.

### 10.6 Soak and abort criteria

Soak 7 days, daily: probe history, Traefik 5xx count on the relay router,
`NRestarts`, RSS trend, `result` distribution in the journal (≈ 19 h
retention, so read daily). Roll back immediately on: a probe failure not
explained by Postfix/Dovecot, any 500, a 502/503 not explained by the SMTP
backend, a status for a real client request that differs from what Python
would answer (judged against the harness), `NRestarts > 0`, RSS above budget
trend. After the soak, retirement of the Python implementation is a separate
step (Q8: the venv stays the rollback path for 30 days after cutover,
then a separate item sets `mailgun_relay_python_enabled: false`).

---

## 11. Rollback

The relay holds no state, so every rollback is a restart.

- **Normal**: `mailgun_relay_impl: python` in host vars, `just deploy-one
  mailgun-relay` (tmux). The role removes the drop-in first; the unit
  restarts with the venv; the binary stays installed. This works even when
  the pinned Rust release is broken or rejects the configuration: with
  `impl: python`, Rust install and validation failures are warnings, not
  errors (9.1 step 4).
- **Emergency without Ansible**: `rm /etc/systemd/system/mailgun-relay.service.d/impl.conf
  && systemctl daemon-reload && systemctl restart mailgun-relay`; then fix the
  host vars, or the next deploy writes the drop-in again.
- **Bad Rust release**: pin the previous version and sha256 and deploy; the
  directory is kept by `.previous-version`.
- **Forward again**: flip back to `rust`; the installed binary is reused.

Precondition for all of them: the Python venv is still built by every deploy
(9.1 step 2) until Q8 retires it.

---

## 12. Resource measurement (before and after)

Same commands for both implementations, read-only, recorded in the ops-control
runbook's deploy log:

- `smaps_rollup` (RSS, PSS, Private_Dirty), `/proc/<pid>/status` (VmHWM,
  Threads), `systemctl show -p MemoryCurrent,MemoryPeak,CPUUsageNSec,NRestarts`.
- **Idle**: 13 samples at 10 s, then hourly over 24 h; CPU-s/h from
  `CPUUsageNSec` deltas.
- **Load profile** (phase A, both shadows, identical): 100 urlencoded 35 KB
  error-mail requests at 1/s; 10 text+html requests; 5 requests with a 5 MiB
  attachment; 1 request at the 25 MiB limit; then 5 min idle. Record peak RSS
  (`VmHWM`), RSS 60 s after the last request, p50/p95 latency, CPU seconds.
- Python baseline from the production process (section 1) plus the Python
  shadow under the same load profile, so peak values are compared like for like.
- Decision on `MALLOC_*` environment (section 5) from the "60 s after"
  numbers.
- After cutover: idle at 1 h, 24 h, 7 days; the numbers go into the campaign
  report and the relay CHANGELOG.

---

## 13. Decided questions (2026-10-15)

The owner answered the questions of `handoff/p2-owner-questions.md` on
2026-10-15 and chose the recommendation every time
(`handoff/p2-owner-decisions.md`):

- **Q1** Python 500s on client input (D-1 empty `text`/`html` without another
  body, D-16 CR/LF decoded from a To/Cc display name): **400** at the same
  position of the decision order; Python gets the same fix (S0-py).
- **Q2** IDN/EAI addresses (D-2, security-relevant, externally triggerable):
  **IDN as A-labels** in headers and envelope, no SMTPUTF8; **EAI local parts
  → 400** (fail closed); fixed in Python first (S0-py, own deploy).
- **Q3** transport-level SMTP failures (D-3): **503** as Python.
- **Q4** exotic input and configuration (D-5–D-11, D-15, D-17 by
  coordinator decision and D-18 from S1 under the same rule): **corpus-pinned
  parity** (≥ 400 addresses, ≥ 100 domains, config corpus from Python) with
  the fail-closed rule; every residual difference is listed in section 3; no
  re-implementation of `email_validator`, `idna` or PyYAML.
- **Q5** production mirroring: **none** (10.3).
- **Q6** license: **MIT `LICENSE`** in the repository (S1); the archive holds
  the binary and `LICENSE`.
- **Q7** naming: `rust/`, tags `rs-v<semver>`, crate from **0.2.0** (Python
  stays 0.1.0), installation under `/opt/mailgun-relay/<version>/mailgun-relay`.
- **Q8** Python retirement: the venv stays the rollback path and keeps being
  built for **30 days** after cutover; then a separate item sets
  `mailgun_relay_python_enabled: false`.

Open facts (resolved by slices, not by the owner): AUTH mechanisms and
SMTPUTF8 of `smtp.home…:587` (S1b: PLAIN/LOGIN, no SMTPUTF8); lettre
connection API details (S1b: section 6 "S1b result");
whether glibc keeps large buffers resident (S9).

Risks:

- **R1 Address/IDNA acceptance drift** (D-10, D-11): the largest contract
  surface; mitigated by the corpus, the fail-closed property test and the
  harness; residuals are owner-visible.
- **R2 lettre limits** (partial refusal, CRAM-MD5, EAI): front-loaded into the
  S1b spike with a hard stop instead of hand-rolled SMTP.
- **R3 No production traffic to observe**: synthetic corpus, phase B mails and
  the E2E probe replace it.
- **R4 Journal retention ≈ 19 h** on macmini: soak checks must be daily; a
  retention change is a host topic outside this campaign.
- **R5 Restarts by Python deploys while Rust runs**: the venv is still
  synced, so Python code changes restart the unit; documented in the runbook.
- **R6 Path confusion** `/opt/mailgun-relay` (Rust) vs
  `/opt/apps/mailgun-relay` (Python home): Q7 kept `/opt/mailgun-relay`; the
  runbook names both paths.
- **R7 Supply chain**: `Cargo.lock`, `--locked`, `cargo deny`, pinned action
  SHAs, sha256 pinned in ops-control.
