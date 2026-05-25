# Ship mailgun-relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship mailgun-relay at `https://mailgun.home.xn--wersdrfer-47a.de` and migrate homepage + python-podcast staging away from the commercial Mailgun API, with real verified sends.

**Architecture:** Narrow FastAPI HTTP→SMTP adapter. Accepts the Mailgun multipart subset django-anymail actually emits; validates token + path domain + from-domain + from-address policy; constructs MIME; submits authenticated STARTTLS SMTP to `smtp.home.xn--wersdrfer-47a.de:587` with envelope MAIL FROM = relay-controlled PostfixAdmin mailbox; returns Mailgun-shaped JSON whose `id` equals the SMTP `Message-Id:` header.

**Tech Stack:** Python 3.12 / FastAPI / uvicorn / uv / pytest / ruff / mypy / standard `email` package for MIME / `smtplib` for SMTP / `aiosmtpd` for SMTP tests.

---

## Decision Log (locked from Phase 0 audits)

1. **Envelope MAIL FROM**: dedicated PostfixAdmin mailbox `mailgun-relay@xn--wersdrfer-47a.de`. Header `From:` preserved from the validated app request. PostfixAdmin enforces login-bound senders via `smtpd_sender_login_maps`, so this mailbox must exist on the home stack before deploy. **Ops action** (out-of-band, called out in docs and release notes): create that mailbox via PostfixAdmin and store the password in SOPS.
2. **SMTP login**: same mailbox `mailgun-relay@xn--wersdrfer-47a.de`.
3. **Bounce destination**: same mailbox (default `MAIL FROM` is the bounce target).
4. **Token labels**: `homepage-staging`, `homepage-production`, `python-podcast-staging`, `python-podcast-production`. Per-app per-environment so we can rotate independently.
5. **Token policy per app** (final shipped values; pre-deploy plan said
   `wersdoerfer.de` but live SOPS inspection during deploy showed homepage's
   actual `MAILGUN_SENDER_DOMAIN` is `mg.wersdoerfer.de`. The values below
   match `ops-control/secrets/prod/mailgun-relay.yml` and the homepage
   acceptance log in `CHANGELOG.md`):
   - `homepage-*`: `mailgun_domains: [mg.wersdoerfer.de]`, `allowed_from_domains: [wersdoerfer.de]`, `allowed_from_addresses: [jochen-homepage@wersdoerfer.de]`. Path subdomain differs from from-domain because Mailgun callers send via a subdomain while the actual `From:` is on the parent domain.
   - `python-podcast-*`: `mailgun_domains: [mg.python-podcast.de]`, `allowed_from_domains: [mg.python-podcast.de]`, `allowed_from_addresses: [noreply@mg.python-podcast.de]`. (Path `/v3/mg.python-podcast.de/messages`. Note: the home mail stack does NOT host `mg.python-podcast.de`, but the relay does not need it to: the relay only submits via SMTP to the local stack; the message `From:` will not be DKIM-signed by the home stack because OpenDKIM only signs hosted domains. For acceptance (delivery to internal `jochen-pythonpodcast@wersdoerfer.de`) this is fine.)
6. **HTTP status mapping** (consistent with `docs/api-compatibility.md`, status code interpretation verified against `anymail/backends/mailgun.py`):
   - `200` + `{"id":"<msg-id@host>","message":"Queued. Thank you."}` — success
   - `401` — missing auth, wrong username, invalid token
   - `403` — token not allowed for path domain or from-address
   - `400` — malformed form, missing required fields, header injection, dangerous custom header, malformed addresses, oversized header
   - `413` — body or attachment over configured limit
   - `502` — SMTP permanent failure (5xx SMTP code from backend or auth failure to backend)
   - `503` — SMTP temp failure, connection error, or timeout
   - `500` — unexpected internal error (no secrets/body in response)
7. **Accepted form fields (MVP allowlist)**:
   - Required: `from`, at least one of `to`/`cc`/`bcc`, at least one of `text`/`html`.
   - Accepted: `from`, `to`, `cc`, `bcc`, `subject`, `text`, `html`, `amp-html`, `h:Reply-To`, other `h:*` headers (regex `^[A-Za-z][A-Za-z0-9-]*$`, value: no CR/LF, ≤ 998 chars).
   - Accepted files: `attachment`, `inline`.
   - **Rejected with 400**: `v:*`, `recipient-variables`, `template`, `t:*`, any `o:*` (since neither current app emits these by default), and any unknown form field.
   - **Rejected dangerous headers** (case-insensitive, even via `h:*`): `Bcc`, `Received`, `Return-Path`, `Resent-*`, `Message-Id`, `Date`, `From`, `To`, `Cc`, `Subject`, `Reply-To` (because relay generates these from form fields and accepts Reply-To only via `h:Reply-To`).
8. **Limits**: max total request body 25 MB; max attachments count 10; max single attachment 10 MB; max recipients (to+cc+bcc) 100; max header value length 998.
9. **Message-Id**: relay generates `<{uuid4().hex}@mailgun.home.xn--wersdrfer-47a.de>` and uses identical value for both response `id` and SMTP `Message-Id:` header.
10. **Logs**: structured JSON to stdout. Fields: `ts`, `request_id`, `event`, `token_label`, `path_domain`, `from`, `recipient_count`, `message_id`, `result`, `duration_ms`, `error_class` (no error message bodies). Never log: token values, SMTP passwords, message bodies, attachment content, raw `Authorization` header.
11. **WWW-Authenticate**: `Basic realm="MG API"` on 401 (Mailgun parity per docs; Anymail ignores it but harmless).

---

## File Structure (mailgun-relay repo)

**Create:**
```
pyproject.toml                          # uv + project config
uv.lock                                 # auto-generated by uv
ruff.toml                               # lint/format config
mypy.ini                                # type-check config
.gitignore                              # standard Python + .env*
.python-version                         # 3.12
CHANGELOG.md                            # release notes (acceptance evidence goes here)
src/mailgun_relay/__init__.py
src/mailgun_relay/__main__.py           # `python -m mailgun_relay`
src/mailgun_relay/app.py                # FastAPI app factory
src/mailgun_relay/config.py             # Settings + token policy loader + validation
src/mailgun_relay/auth.py               # HTTP Basic + constant-time token verify
src/mailgun_relay/policy.py             # path-domain + from-domain + from-address checks, IDN normalize
src/mailgun_relay/headers.py            # header-injection rejection, dangerous-header allowlist
src/mailgun_relay/mime_build.py         # MIME composition from form fields
src/mailgun_relay/smtp_client.py        # STARTTLS SMTP submission, error → HTTP mapping
src/mailgun_relay/routes.py             # POST /v3/{domain}/messages + GET /health
src/mailgun_relay/logging_setup.py      # structured logger with secret redaction
src/mailgun_relay/errors.py             # Mailgun-shaped error responses
src/mailgun_relay/version.py            # __version__ string
tests/conftest.py                       # FastAPI TestClient fixtures, fake SMTP fixture, token policy fixture
tests/test_health.py
tests/test_auth.py
tests/test_policy.py
tests/test_headers.py
tests/test_mime_build.py
tests/test_messages_endpoint.py         # end-to-end via TestClient with fake SMTP
tests/test_smtp_submission.py           # SMTP layer + error mapping
tests/test_logging.py                   # secret redaction
tests/fixtures/                         # tiny binary fixtures for attachment tests
```

**Modify in mailgun-relay later:**
- `README.md` — add quickstart, env vars, deploy reference
- `docs/CHANGELOG.md` or `CHANGELOG.md` — acceptance evidence (request ids + timestamps)
- existing `docs/*.md` — fix anything that turns out wrong during implementation (per goal: "fix a spec doc if it is wrong")

**Outside mailgun-relay repo:**
- `ops-library/roles/mailgun_relay_deploy/` (new role)
- `ops-control/playbooks/deploy-mailgun-relay.yml`
- `ops-control/secrets/prod/mailgun-relay.yml` (SOPS)
- `ops-control/inventories/prod/host_vars/macmini.yml` — add the relay vars
- `homepage/deploy/templates/env.template.j2` — append `MAILGUN_API_URL=...`
- `python-podcast/deploy/templates/env.template.j2` — append `MAILGUN_API_URL=...`
- `ops-control/secrets/staging/homepage.yml` and `secrets/prod/homepage.yml` — add `mailgun_api_url`, rotate `django_mailgun_api_key` to relay token
- `ops-control/secrets/staging/python-podcast.yml` and `secrets/prod/python-podcast.yml` — same shape
- `homelab/src/apps/core/management/commands/add_default_services.py` — new tile

---

## Task Breakdown (each task = small commits; TDD where applicable)

### Task A: Scaffold

- [ ] `uv init --package src/mailgun_relay` style layout; add `pyproject.toml` with deps: `fastapi`, `uvicorn[standard]`, `python-multipart`, `email-validator`, `pydantic-settings`, `pyyaml`. Dev deps: `pytest`, `pytest-asyncio`, `httpx`, `ruff`, `mypy`, `aiosmtpd`, `types-PyYAML`.
- [ ] `ruff.toml` with line-length 100, target-version py312, select [E,F,W,I,B,UP,S,N], format = black-style.
- [ ] `mypy.ini` strict for `src/mailgun_relay/`.
- [ ] `.gitignore` for Python + `.venv` + `dist`.
- [ ] `src/mailgun_relay/version.py` with `__version__ = "0.1.0"`.
- [ ] `src/mailgun_relay/app.py` — `create_app()` returning `FastAPI`.
- [ ] `src/mailgun_relay/__main__.py` runs uvicorn pointing at `app:create_app()`.
- [ ] `src/mailgun_relay/routes.py` — register a stub `GET /health` returning `{"status":"ok"}`.
- [ ] `tests/conftest.py` with `client` fixture wrapping FastAPI TestClient.
- [ ] `tests/test_health.py::test_health_ok`.
- [ ] `make` targets via `justfile` or doc the commands in README: `uv sync`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`.
- [ ] Verify `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src` all pass.
- [ ] Commit.

### Task B: Config + token policy loader

- [ ] `tests/test_config.py`: load token policy from YAML; reject missing fields; reject `CHANGEME`; normalize IDN U-labels in `mailgun_domains`/`allowed_from_domains` to A-labels (`xn--…`); reject if no tokens defined.
- [ ] Implement `src/mailgun_relay/config.py`:
  - `Settings` (pydantic-settings) reads env: `MAILGUN_RELAY_BIND_HOST`, `MAILGUN_RELAY_BIND_PORT`, `MAILGUN_RELAY_SECRETS_PATH`, `MAILGUN_RELAY_SMTP_HOST`, `MAILGUN_RELAY_SMTP_PORT`, `MAILGUN_RELAY_SMTP_USERNAME`, `MAILGUN_RELAY_SMTP_PASSWORD`, `MAILGUN_RELAY_SMTP_STARTTLS=true`, `MAILGUN_RELAY_SMTP_TIMEOUT_S=30`, `MAILGUN_RELAY_ENVELOPE_SENDER`, `MAILGUN_RELAY_PUBLIC_HOST`, `MAILGUN_RELAY_MAX_BODY_BYTES=26214400`, `MAILGUN_RELAY_MAX_ATTACHMENTS=10`, `MAILGUN_RELAY_MAX_RECIPIENTS=100`, `MAILGUN_RELAY_LOG_LEVEL=INFO`. SMTP password may also be `MAILGUN_RELAY_SMTP_PASSWORD_FILE`.
  - `TokenPolicy` dataclass: `label`, `token_sha256` (hex), `mailgun_domains` (set of A-labels), `allowed_from_domains` (set), `allowed_from_addresses` (set or None).
  - `load_policy(path) -> list[TokenPolicy]`: parses YAML, normalizes via `idna.encode(...).decode("ascii")`, validates.
- [ ] `src/mailgun_relay/policy.py` — `normalize_domain(s)` helper using stdlib `idna` (Python 3.12 stdlib `encodings.idna` + lowercase).
- [ ] Verify mypy + ruff + pytest pass.
- [ ] Commit.

### Task C: Auth (HTTP Basic + constant-time verify)

- [ ] `tests/test_auth.py`: missing Authorization → 401 + `WWW-Authenticate`; wrong scheme → 401; username != `api` → 401; invalid token → 401; valid token → returns matched `TokenPolicy`. Response body doesn't reveal label existence.
- [ ] Implement `src/mailgun_relay/auth.py`:
  - `authenticate(authorization: str|None, policies: list[TokenPolicy]) -> TokenPolicy`
  - Decode Basic creds, enforce username == `"api"`, compute SHA-256 of password, compare to each `token_sha256` using `hmac.compare_digest` (run all comparisons to avoid timing leak; do not short-circuit).
  - Raise `MailgunAuthError` on any failure.
- [ ] Verify tests pass.
- [ ] Commit.

### Task D: Policy validation (path domain + from)

- [ ] `tests/test_policy.py`: path domain matches token → ok; path domain not in token's mailgun_domains → `PolicyError`; from-domain not in allowed_from_domains → `PolicyError`; from-address with allowed_from_addresses set and address not in set → `PolicyError`; mixed-case domain + IDN U-label inputs both pass after normalization; invalid email (no `@`) → `PolicyError`.
- [ ] Implement `src/mailgun_relay/policy.py::enforce_policy(token, path_domain, from_address) -> None` using `email_validator.validate_email` for parsing; `normalize_domain` for both path and from-domain.
- [ ] Verify tests.
- [ ] Commit.

### Task E: Header validation

- [ ] `tests/test_headers.py`: subject with `\n` or `\r` → reject; `h:` header name regex; `h:Reply-To` accepted, parsed as address; `h:Bcc`, `h:Received`, `h:Return-Path`, `h:Resent-*`, `h:From`, `h:To`, `h:Cc`, `h:Subject`, `h:Message-Id`, `h:Date` rejected; value > 998 chars rejected; CR/LF in value rejected.
- [ ] Implement `src/mailgun_relay/headers.py`:
  - `DANGEROUS_HEADERS` constant (case-insensitive set).
  - `validate_subject(s) -> str` (strip + reject CR/LF + len ≤ 998).
  - `validate_custom_headers(items: dict[str,str]) -> dict[str,str]` (name regex; not in DANGEROUS; value sanity).
  - `parse_address_list(values: list[str]) -> list[Address]` (rejects header injection in display name).
- [ ] Verify tests.
- [ ] Commit.

### Task F: MIME construction

- [ ] `tests/test_mime_build.py`: text-only message; html-only message; multipart/alternative for text+html; CC included in headers and envelope; BCC in envelope but **not** in serialized MIME bytes; single attachment with filename/content-type; reply-to via `h:Reply-To` ends up as `Reply-To:` header; generated `Message-Id:` is present and matches the returned message_id; `From:` is the app-provided address.
- [ ] Implement `src/mailgun_relay/mime_build.py`:
  - `build_message(*, from_address, to, cc, bcc, subject, text, html, amp_html, custom_headers, attachments, inline, public_host) -> tuple[EmailMessage, str, list[str]]` returning the message object, the generated `<msg-id@host>` string, and the envelope recipient list (to+cc+bcc).
  - Use `email.message.EmailMessage`, `add_alternative`, `add_attachment`.
  - Do **not** call `.add_header("Bcc", ...)`.
- [ ] Verify tests.
- [ ] Commit.

### Task G: SMTP submission

- [ ] `tests/test_smtp_submission.py` using `aiosmtpd` to spin up an in-process SMTP server (no TLS in test by default; configure relay to skip STARTTLS in test only via injected SMTP transport, or use `smtpd_tls=False` test path):
  - Happy path: relay submits, envelope MAIL FROM = configured envelope_sender, envelope RCPT = to+cc+bcc, serialized message contains `From:` = app-provided, `Bcc:` header absent.
  - SMTP 5xx → HTTP 502; SMTP 4xx → HTTP 503; connection refused → HTTP 503; auth failure (535) → HTTP 502 with logged error class but no creds in log.
- [ ] Implement `src/mailgun_relay/smtp_client.py`:
  - `submit(message, envelope_sender, recipients, settings) -> None` using `smtplib.SMTP` with `starttls()` when configured, `login()` with creds, `send_message(msg, from_addr=envelope_sender, to_addrs=recipients)`.
  - `SMTPSubmitError(category)` raised with category in {`permanent`, `temporary`, `auth`}.
  - Map SMTP responses to category by code (`5xx` → permanent, `4xx`+OSError+timeout → temporary, `535` → auth (still permanent for relay, return 502)).
- [ ] Verify tests.
- [ ] Commit.

### Task H: Routes + end-to-end

- [ ] `tests/test_messages_endpoint.py`:
  - POST `/v3/mg.wersdoerfer.de/messages` with valid Basic auth and form `from=Jochen <jochen-homepage@wersdoerfer.de>&to=admin@wersdoerfer.de&subject=hi&text=body` → 200 with `{"id":"<...@mailgun.home.xn--wersdrfer-47a.de>","message":"Queued. Thank you."}`. Returned `id` matches the SMTP `Message-Id:` header seen by the fake SMTP.
  - Auth missing → 401 + `WWW-Authenticate: Basic realm="MG API"`.
  - Path domain mismatched → 403.
  - `from` address not in token's allowed_from_addresses → 403.
  - `o:tag=foo` field → 400 (unsupported field).
  - `v:userid=x` → 400.
  - `subject` with CRLF injection → 400.
  - `h:Bcc=evil@x.com` → 400 (dangerous header).
  - BCC in form → not in serialized MIME headers but present in envelope RCPT.
  - Attachment via `attachment=@file`, total under limit → 200; over limit → 413.
- [ ] Implement `src/mailgun_relay/routes.py`:
  - `POST /v3/{domain}/messages` handler: parse multipart form (FastAPI `Request.form()` to get repeated keys + UploadFile), authenticate, normalize/validate domain, validate from, validate subject/headers, build MIME, submit SMTP, return JSON.
  - Translate exceptions to Mailgun-shaped error JSON via `errors.py`: `{"message": "<human readable>"}` body for non-2xx; appropriate status code.
- [ ] Implement `src/mailgun_relay/errors.py`: `MailgunRelayError` base with `status_code` + safe `public_message`; exception → JSON handler attached via `add_exception_handler`.
- [ ] Verify tests.
- [ ] Commit.

### Task I: Observability + secret redaction

- [ ] `tests/test_logging.py`:
  - JSON structured log on a successful POST includes: `request_id`, `token_label`, `path_domain`, `from`, `recipient_count`, `message_id`, `result=ok`, `duration_ms`.
  - Logger never emits `Authorization` header value, never emits raw form values for `attachment`/`inline`/`text`/`html`, never emits SMTP password.
  - On SMTP error, log has `result=error` and `error_class` but no message-body / no credentials.
- [ ] Implement `src/mailgun_relay/logging_setup.py`:
  - `configure_logging(level)` installs a JSON formatter writing to stdout.
  - Middleware in `app.py` assigns a UUID request_id, captures duration, and emits one structured log line per request via `mailgun_relay.access` logger.
- [ ] Verify tests.
- [ ] Commit.

### Task J: Health + version endpoint hardening

- [ ] Test: `GET /health` returns `{"status":"ok","version":"0.1.0"}` without auth; does NOT touch SMTP.
- [ ] Verify final mailgun-relay test suite + ruff + format-check + mypy all pass.
- [ ] Update mailgun-relay `README.md`: env vars table, run command, `docs/superpowers/plans/...` reference, repro recipe for `pytest && ruff check . && ruff format --check . && mypy src`.
- [ ] Update `docs/api-compatibility.md` only if Phase 0 disagreed with the doc (verify e.g. that "Anymail emits `bcc` as plain form field" is reflected; that "Mailgun success body `id` is angle-bracketed Message-Id" is reflected).
- [ ] Commit.

### Task K: ops-library role `mailgun_relay_deploy`

Pattern modeled on `ops-library/roles/graphyard_deploy/` and `voxhelm_deploy`.

- [ ] Create `roles/mailgun_relay_deploy/{defaults,handlers,meta,tasks,templates}/` and `README.md`.
- [ ] `defaults/main.yml` with all variables `CHANGEME`-defaulted (per ops-library design principle):
  - `mailgun_relay_user: mailgun-relay`
  - `mailgun_relay_home: /opt/apps/mailgun-relay`
  - `mailgun_relay_site_path: "{{ mailgun_relay_home }}/site"`
  - `mailgun_relay_venv_path: "{{ mailgun_relay_site_path }}/.venv"`
  - `mailgun_relay_python_version: "3.12"`
  - `mailgun_relay_deploy_method: rsync`
  - `mailgun_relay_source_path: ""`
  - `mailgun_relay_git_repo`, `mailgun_relay_git_version: main`
  - `mailgun_relay_env_dir: /etc/mailgun-relay`
  - `mailgun_relay_env_path: "{{ mailgun_relay_env_dir }}/mailgun-relay.env"`
  - `mailgun_relay_secrets_path: "{{ mailgun_relay_env_dir }}/secrets.yml"`
  - `mailgun_relay_bind_host: "127.0.0.1"`
  - `mailgun_relay_bind_port: 8085` (pick a free port; verify against `host_vars/macmini.yml`)
  - `mailgun_relay_public_host: "mailgun.home.xn--wersdrfer-47a.de"`
  - `mailgun_relay_smtp_host: "smtp.home.xn--wersdrfer-47a.de"`
  - `mailgun_relay_smtp_port: 587`
  - `mailgun_relay_smtp_username: "CHANGEME"`
  - `mailgun_relay_smtp_password: "CHANGEME"`
  - `mailgun_relay_envelope_sender: "CHANGEME"`
  - `mailgun_relay_tokens: []` (asserted non-empty)
  - `mailgun_relay_max_body_bytes: 26214400`, etc.
- [ ] `tasks/main.yml`: validate vars (no CHANGEME), ensure user/group, sync source (rsync/git), uv sync, render env file (mode 0600 owner mailgun-relay), render secrets.yml (mode 0600 owner mailgun-relay), install systemd unit, enable + restart on change. Notify traefik ingress role (separate role) to reload labels.
- [ ] `templates/mailgun-relay.service.j2`: systemd unit `ExecStart=...uv run python -m mailgun_relay`, Restart=on-failure, User=mailgun-relay, EnvironmentFile=…env, NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp.
- [ ] `templates/mailgun-relay.env.j2`: all non-secret env vars (bind host/port, smtp host/port, public host, paths, log level, ENVELOPE_SENDER value).
- [ ] `templates/secrets.yml.j2`: SMTP credentials + tokens list (token sha256 hex + label + policy lists).
- [ ] `meta/main.yml`: depends on `uv_install`.
- [ ] `roles/mailgun_relay_ingress_deploy/` (separate role, modeled on `graphyard_ingress_deploy`): renders traefik dynamic config file with router/service rule `Host(mailgun.home.xn--wersdrfer-47a.de)` and backend `http://macmini.lan:{port}`. Notify `traefik` handler.
- [ ] Role `README.md` documenting all variables, example, ports, security assumptions, troubleshooting.
- [ ] Run `ansible-lint roles/mailgun_relay_deploy roles/mailgun_relay_ingress_deploy`.
- [ ] If repo has molecule tests for similar roles, add minimal scenario (out of scope if not customary).
- [ ] Commit in ops-library.

### Task L: ops-control playbook + SOPS secrets

- [ ] `playbooks/deploy-mailgun-relay.yml`:
  - Play 1 on macmini: load `secrets/prod/mailgun-relay.yml` via `community.sops.sops`; validate non-CHANGEME; include `uv_install` then `mailgun_relay_deploy` with bound vars.
  - Play 2 on macmini: include `mailgun_relay_ingress_deploy` for traefik labels.
- [ ] `secrets/prod/mailgun-relay.yml` (SOPS-encrypted):
  ```yaml
  mailgun_relay:
    smtp_username: "mailgun-relay@xn--wersdrfer-47a.de"
    smtp_password: "<generated>"
    envelope_sender: "mailgun-relay@xn--wersdrfer-47a.de"
    tokens:
      - label: homepage-staging
        token_sha256: "<sha256 of generated token>"
        mailgun_domains: ["mg.wersdoerfer.de"]
        allowed_from_domains: ["wersdoerfer.de"]
        allowed_from_addresses: ["jochen-homepage@wersdoerfer.de"]
      - label: homepage-production
        token_sha256: "..."
        mailgun_domains: ["mg.wersdoerfer.de"]
        allowed_from_domains: ["wersdoerfer.de"]
        allowed_from_addresses: ["jochen-homepage@wersdoerfer.de"]
      - label: python-podcast-staging
        token_sha256: "..."
        mailgun_domains: ["mg.python-podcast.de"]
        allowed_from_domains: ["mg.python-podcast.de"]
        allowed_from_addresses: ["noreply@mg.python-podcast.de"]
      - label: python-podcast-production
        token_sha256: "..."
        mailgun_domains: ["mg.python-podcast.de"]
        allowed_from_domains: ["mg.python-podcast.de"]
        allowed_from_addresses: ["noreply@mg.python-podcast.de"]
  ```
  *Real values generated locally; only sha256 of tokens stored.* The raw token values live in the per-app SOPS files (next task) and are never committed in cleartext.
- [ ] Add `inventories/prod/host_vars/macmini.yml` lines binding the relay vars.
- [ ] `just deploy-one mailgun-relay`. Or add Justfile target.
- [ ] Commit (ops-control is private).

### Task M: Pre-deploy ops checklist

**Manual ops steps the user must perform — script-call-outs only, no automation:**
- [ ] Create PostfixAdmin mailbox `mailgun-relay@xn--wersdrfer-47a.de` with a strong password. Document password in the relay SOPS file `smtp_password`.
- [ ] Generate four tokens (e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`). Store sha256 hexdigests in the relay SOPS file. Store the raw tokens (one per app per env) in each app's SOPS file as the new `django_mailgun_api_key` / `mailgun_api_key`.
- [ ] Verify DNS for `mailgun.home.xn--wersdrfer-47a.de` resolves to macmini (existing traefik wildcard cert covers `*.home.xn--wersdrfer-47a.de`).
- [ ] Run `just deploy-one mailgun-relay` (ops-control).
- [ ] Verify `curl -fsS https://mailgun.home.xn--wersdrfer-47a.de/health` returns `{"status":"ok","version":"0.1.0"}`.
- [ ] Verify negative tests from outside (no auth → 401; bad token → 401; bad domain → 403).
- [ ] Inspect logs to confirm no secret leakage (`journalctl -u mailgun-relay`).

### Task N: Migrate homepage staging

- [ ] In `homepage/deploy/templates/env.template.j2`, add a line `MAILGUN_API_URL={{ mailgun_api_url }}`.
- [ ] In `ops-control/secrets/staging/homepage.yml`, set `mailgun_api_url: "https://mailgun.home.xn--wersdrfer-47a.de/v3"` and replace `django_mailgun_api_key` value with the staging relay token. Leave `mailgun_sender_domain: "mg.wersdoerfer.de"` (the existing value — homepage's real Mailgun sender subdomain). Encrypt with SOPS.
- [ ] In the deploy playbook (`ops-control/playbooks/deploy-homepage.yml` or the existing path the agent identified), wire `mailgun_api_url` from secrets through to the rendered env.
- [ ] `just deploy-one homepage` (staging selector).
- [ ] On staging host, confirm `.env` contains the new `MAILGUN_API_URL` and the new token; **commercial Mailgun key is no longer present** (the only `DJANGO_MAILGUN_API_KEY` is the relay token).
- [ ] Add the rollback note to `mailgun-relay/CHANGELOG.md`: revert procedure = remove `MAILGUN_API_URL` from staging SOPS + redeploy.
- [ ] Commit changes in homepage + ops-control.

### Task O: Migrate python-podcast staging

- [ ] Same shape as Task N but in `python-podcast/deploy/templates/env.template.j2` and the python-podcast SOPS files. Use env var name `MAILGUN_API_URL` (python-podcast already reads `MAILGUN_API_KEY` and `MAILGUN_DOMAIN`; we add `MAILGUN_API_URL` and rotate `MAILGUN_API_KEY` to the relay token; leave `MAILGUN_DOMAIN=mg.python-podcast.de`).
- [ ] Deploy staging, verify env.
- [ ] Commit.

### Task P: Final acceptance — real sends

For each of homepage staging and python-podcast staging:
- [ ] SSH to staging host, `cd` to site, `uv run python manage.py shell -c "from django.core.mail import mail_admins; mail_admins('mailgun-relay acceptance', 'request-id verifier')"`.
- [ ] Check mail arrives in the first ADMINS mailbox via the home stack:
  - homepage → `jochen-homepage@wersdoerfer.de`
  - python-podcast → `jochen-pythonpodcast@wersdoerfer.de`
- [ ] On macmini, capture the relay log line for each send (token_label, from, recipient_count, request_id, message_id).
- [ ] Compare the message's SMTP `Message-Id:` header against the relay `message_id` log field — must match.
- [ ] Record both request_ids + timestamps + matching Message-Ids in `mailgun-relay/CHANGELOG.md` (or `docs/CHANGELOG.md` if that path is conventional).
- [ ] Commit acceptance evidence.

### Task Q: Homelab tile

- [ ] Edit `homelab/src/apps/core/management/commands/add_default_services.py` and add:
  ```python
  {
      "name": "Mailgun Relay",
      "description": "Self-hosted Mailgun API for Django Anymail",
      "url": "https://mailgun.home.xn--wersdrfer-47a.de/",
      "icon": "fas fa-envelope-square",
      "logo_filename": "mailgun.svg",  # only if asset exists; otherwise omit
      "order": <next-free-int>,
  },
  ```
  (If no logo asset, omit `logo_filename`.)
- [ ] Apply seed in production via the homelab deploy path the agent identified: `just deploy` (or whatever homelab's command is — re-confirm before running).
- [ ] Commit in homelab.

---

## Self-Review (against goal "Done when" list)

| Goal requirement | Task |
| --- | --- |
| Deployed at https://mailgun.home.xn--wersdrfer-47a.de behind traefik with HTTPS | K + L + M |
| Health endpoint | J + M |
| Structured logs with no token/cred/body leakage | I |
| POST /v3/{domain}/messages per docs/api-compatibility.md | C + D + E + F + G + H |
| HTTP Basic user `api` constant-time | C |
| Per-token sender-domain + from-address policy | B + D |
| MIME with attachments/CC + envelope-only BCC | F + H |
| Header-injection + dangerous-header rejection | E + H |
| Authenticated STARTTLS to smtp.home.xn--wersdrfer-47a.de:587 | G + L |
| Mailgun-shaped JSON, status codes verified against Anymail | Decision log + G + H |
| pytest covers auth/sender/from/header-injection/BCC privacy/MIME/SMTP failure | B–I |
| ruff check + ruff format --check + mypy pass | A–J |
| ops-library role + ops-control playbook + SOPS | K + L |
| mailgun-relay repo contains no ansible/vaults/host-specific config | (negative: A–J files only) |
| homepage + python-podcast keep Anymail backend + gain MAILGUN_API_URL | N + O |
| Each app has its own token | L (4 tokens) |
| Secrets in SOPS, commercial key removed from staging | N + O |
| Rollback documented in mailgun-relay release notes | N + O + M |
| Real send acceptance from both staging apps in ADMINS mailbox | P |
| Acceptance request ids + timestamps in release notes | P |
| Homelab tile | Q |
| Never an open relay | C + D + E (all three must pass before SMTP) |
| No real tokens/SMTP passwords/secrets in repo/logs/tests/docs | B + I + L (SOPS only) |
| Punycode for IDN | B (normalization) |
| .messages.mime out of scope | (not implemented; explicitly rejected) |

---

## Execution Order

A → B → C → D → E → F → G → H → I → J → (mailgun-relay shippable here)
→ K → L → M (deployed)
→ N → O (apps point at relay)
→ P (acceptance)
→ Q (tile)

I'll execute inline with checkpoints between each task using TaskUpdate to mark progress.
