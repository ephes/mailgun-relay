# Changelog

All notable changes to mailgun-relay are documented here.

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
   `{"status":"ok","version":"0.1.0"}` and check `journalctl -u mailgun-relay`
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
4. (`python-podcast` only) leave `mailgun_sender_domain: mg.python-podcast.de`.
   (`homepage`) leave `mailgun_sender_domain: wersdoerfer.de`.
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

### Acceptance evidence

The final acceptance step (real send from each staging app to the Django
`ADMINS` mailbox, plus matching relay log capture) must be performed by the
operator after step 5 above completes for both staging environments. Capture
the relay log line for each send — it identifies the token label, the
sender, the recipient count, the request id, and the SMTP `Message-Id:` — and
append the matching entries below.

```
homepage-staging:    request_id=<TBD-by-operator>  message_id=<TBD>  ts=<TBD>
python-podcast-staging: request_id=<TBD-by-operator>  message_id=<TBD>  ts=<TBD>
```

Operator: replace the `<TBD>` markers above with the values from the relay
log (`journalctl -u mailgun-relay -o cat | jq` and filter
`event=="request" and result=="ok"`).

### Non-goals (explicit, not deferred)

- `POST /v3/{domain}/messages.mime` — neither current app uses raw MIME
  submission (verified via source audit of homepage + python-podcast).
- Mailgun domains/events/webhooks/tracking/templates/suppressions/inbound/
  analytics APIs.
- Adding new sender domains to the home mail stack.
