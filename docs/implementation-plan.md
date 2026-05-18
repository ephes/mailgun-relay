# Implementation Plan

This plan starts from the current empty repository state and ends with a controlled production rollout. It is intentionally phase-gated because the service is a mail relay boundary.

## 1. Confirm Compatibility Inputs

Review current upstream docs immediately before coding:

- Anymail Mailgun docs: https://anymail.dev/en/stable/esps/mailgun/
- Mailgun Messages API docs: https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages
- FastAPI request files docs, if FastAPI is used: https://fastapi.tiangolo.com/tutorial/request-files/

Actions:

- Verify Anymail's current `MAILGUN_API_URL` behavior: base URL should end at `/v3`, without sender domain or `/messages`.
- Verify which form fields Anymail emits for ordinary Django `EmailMessage`, `EmailMultiAlternatives`, attachments, extra headers, CC, BCC, and Anymail-specific metadata.
- Verify exact `o:*` option fields Anymail emits for current app usage, including tags, tracking flags, delivery options, and any Anymail mixins.
- Verify current Anymail `MAILGUN_SENDER_DOMAIN` behavior for path-domain and `from`-domain mismatches.
- Verify how Anymail maps Mailgun HTTP errors to exceptions before finalizing SMTP failure status codes.
- Audit `homepage` and `python-podcast` for `send_mime_message`, raw MIME usage, or any current behavior that requires `.messages.mime`.

Checkpoint: Stop for review after documenting confirmed request samples and any changed upstream assumptions.

## 2. Choose and Scaffold the Stack

Suggested default stack:

- Python web service.
- FastAPI or another ASGI framework with first-class multipart form and upload support.
- `uv` or the repository's chosen Python packaging tool.
- `pytest` for tests.
- Ruff or equivalent for linting/formatting.
- MyPy or Pyright if type checking is adopted.

Rationale: Mailgun's send endpoint is form-data heavy, and FastAPI supports `Form`, `File`, and `UploadFile` with `python-multipart`. The FastAPI docs explicitly require `python-multipart` for uploaded form files.

Actions:

- Add project metadata and a small application package.
- Add a local run command.
- Add test, lint, format, and type-check commands.
- Add minimal CI only if appropriate for the repo workflow.

Future verification commands to define once tooling exists:

```bash
pytest
ruff check .
ruff format --check .
python -m mailgun_relay --help
```

Checkpoint: Review the scaffold before implementing relay behavior.

## 3. Implement Configuration Model

Actions:

- Define non-secret settings: bind address, public base URL, SMTP host, SMTP port, timeout limits, message size limits, and log level.
- Define secret-backed settings: token material and SMTP submission credentials.
- Model token policy as a list of token records with label, token hash or equivalent verifier, allowed Mailgun sender domains, allowed `from` domains, and optional exact sender allowlist.
- Use punycode for IDN domains in config examples.

Acceptance criteria:

- No secrets are committed.
- Invalid or incomplete configuration fails at startup.
- Token labels are loggable; token values are not.

Checkpoint: Security review of config shape before adding HTTP auth.

## 4. Implement API Authentication and Validation

Actions:

- Require HTTP Basic auth.
- Accept only username `api`.
- Compare password/token material using constant-time comparison.
- Normalize `{domain}` and email domains.
- Validate `{domain}`, `from`, and all sender policy constraints before SMTP submission.
- Reject header injection, malformed addresses, missing recipients, empty bodies, and unsupported fields as documented.

Acceptance criteria:

- Tests cover valid token, invalid token, wrong username, disallowed sender domain, disallowed path domain, malformed addresses, and header injection.
- Error responses are consistent with `docs/api-compatibility.md`.

Checkpoint: Review before adding SMTP submission.

## 5. Implement `POST /v3/{domain}/messages`

Actions:

- Parse multipart form fields and uploaded files.
- Support core fields: `from`, repeated `to`, `cc`, `bcc`, `subject`, `text`, `html`, selected `h:*` headers, `attachment`, and `inline` if needed.
- Build MIME with standard Python email APIs or a mature mail composition library.
- Put BCC recipients in the SMTP envelope only.
- Generate a stable message id value suitable for the success response.

Acceptance criteria:

- Text-only, HTML-only, alternative text/html, attachment, CC, BCC, and custom header tests pass.
- Generated MIME does not leak BCC headers.
- A generated `Message-Id:` value is correlated with the Mailgun-like response `id` where practical.
- Unsupported Mailgun-only features follow the documented allowlist/reject policy.

Future verification commands:

```bash
pytest tests/test_messages_endpoint.py
pytest tests/test_mime_construction.py
```

Checkpoint: Review generated MIME examples before integrating live SMTP.

## 6. Implement SMTP Submission

Actions:

- Submit via authenticated SMTP to `smtp.home.xn--wersdrfer-47a.de:587` by default, with STARTTLS required.
- Make host, port, username, password, TLS mode, and timeout configurable.
- Choose and implement the SMTP envelope sender policy. The MVP default should be a dedicated relay-controlled mailbox unless ops explicitly permits the relay SMTP login to send as each application sender.
- Verify the backend's PostfixAdmin sender/login binding and document any required allowance for the relay service account.
- Map SMTP success, temporary failure, permanent failure, auth failure, and timeout to documented HTTP responses.
- Log result metadata without message body or secrets.

Acceptance criteria:

- Tests use a fake SMTP server or mocked SMTP client.
- Tests assert envelope `MAIL FROM`, envelope recipients, BCC privacy, and bounce address behavior.
- SMTP auth failures do not expose credentials.
- Partial recipient failures have documented behavior.

Future verification commands:

```bash
pytest tests/test_smtp_submission.py
```

Checkpoint: Review before exposing any network-accessible deployment.

## 7. Add Observability and Operational Hooks

Actions:

- Add structured request logs with request id, token label, domain, sender, recipient count, generated message id, result, and duration.
- Add health endpoint or process check suitable for deployment.
- Add metrics only if there is an existing preferred stack; otherwise document future metric names.
- Add message size and rate-limit controls or reverse-proxy requirements.

Acceptance criteria:

- Logs are useful for troubleshooting but do not contain token values, SMTP passwords, message bodies, or attachment content.
- Health check does not require sending a real email.
- Rate-limit and size-limit behavior is tested.

Checkpoint: Ops review before role/playbook work.

## 8. Package for Deployment

Actions:

- Decide whether production runs from git checkout, wheel, or container.
- Add a production entry point compatible with systemd.
- Document runtime environment variables and secret file format without real values.
- Expose version or git revision in logs or a status endpoint.

Acceptance criteria:

- A clean checkout can install and run the service.
- Restart behavior and graceful shutdown are tested or documented.
- Release notes are updated for behavior changes once implementation exists.

Checkpoint: Review packaging before ops integration.

## 9. Integrate with Ops Repositories

Actions in `ops-library` later:

- Add a deployment role for installing and running `mailgun-relay`.
- Document role variables, defaults, examples, health checks, service files, and troubleshooting.
- Follow `ops-library` validation expectations.

Actions in `ops-control` later:

- Add a playbook targeting the chosen host.
- Configure public hostname `mailgun.home.xn--wersdrfer-47a.de`.
- Store token policies and dedicated SMTP submission credentials in SOPS.
- Wire TLS and reverse proxy configuration according to existing ops patterns.

Acceptance criteria:

- Local deploy path and production deploy path are documented.
- No secrets are committed outside SOPS.
- Rollback path is documented.

Checkpoint: Ops review before staging rollout.

## 10. Staging or Controlled Rollout

Actions:

- Deploy service behind HTTPS at the planned hostname or a staging hostname.
- Run health checks.
- Send controlled test messages using a temporary token and allowed sender.
- Confirm mail appears in the existing backend/relay logs and downstream recipient mailbox.
- Verify failure behavior with bad token, bad sender, and bad domain.

Future verification commands:

```bash
curl -u 'api:REDACTED' -F from='Allowed <allowed@example.test>' -F to='recipient@example.test' -F subject='relay test' -F text='test' https://mailgun.home.xn--wersdrfer-47a.de/v3/example.test/messages
```

Do not store real tokens in shell history or docs.

Checkpoint: Review test evidence before migrating applications.

## 11. Application Migration

Homepage:

- Keep `EMAIL_BACKEND = "anymail.backends.mailgun.EmailBackend"`.
- Add an environment-driven `MAILGUN_API_URL` setting, with production pointing to `https://mailgun.home.xn--wersdrfer-47a.de/v3`.
- Replace the Mailgun API key secret with a service-issued token.
- Confirm `MAILGUN_SENDER_DOMAIN` and sender policy match the relay token.

Python Podcast:

- Keep `EMAIL_BACKEND = "anymail.backends.mailgun.EmailBackend"`.
- Add the same `MAILGUN_API_URL` setting.
- Verify whether current sender domain `mg.python-podcast.de` is intentionally supported by the self-hosted mail stack before migration.
- Use a separate token policy unless there is a deliberate shared-token decision.

Checkpoint: Migrate one app at a time with rollback instructions.

## 12. Production Rollout and Follow-Up

Actions:

- Roll out to the first app.
- Monitor auth failures, validation failures, SMTP failures, latency, message volume, and mail queue.
- Roll out to the second app only after the first app is stable.
- Update docs and release notes with final behavior and operational lessons.

Acceptance criteria:

- Production sends succeed for migrated apps.
- Rollback to real Mailgun remains documented until confidence is high.
- Non-goals remain unsupported unless a new planning slice approves them.
