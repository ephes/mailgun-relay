# mailgun-relay

`mailgun-relay` is a small Mailgun send API adapter for existing Django projects that already use `django-anymail` with `anymail.backends.mailgun.EmailBackend`.

The goal is compatibility with the Mailgun send API surface Anymail needs, not a full Mailgun clone. Django projects keep their current email backend and point Anymail at this service with `MAILGUN_API_URL`, while using a scoped service-issued token as `MAILGUN_API_KEY`.

## Status

`0.1.0` — Implementation complete. The FastAPI service, ops-library role
(`mailgun_relay_deploy` + `mailgun_relay_ingress_deploy`), and ops-control
playbook (`deploy-mailgun-relay.yml`) are in place. The homepage and
python-podcast deploy playbooks accept a `mailgun_api_url` override that
flips Anymail's Mailgun backend at the relay.

See [`CHANGELOG.md`](./CHANGELOG.md) for the pre-deploy operator checklist,
per-app migration steps, rollback procedure, and acceptance evidence
template.

## Quickstart (development)

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy src
```

GitHub Actions (`.github/workflows/ci.yml`) runs the same checks on every push
and pull request. It needs no secrets.

The service starts with `uv run python -m mailgun_relay` and reads runtime
config from environment variables prefixed `MAILGUN_RELAY_` (see
`src/mailgun_relay/config.py::Settings`). Token policy and SMTP credentials
load from the YAML file at `MAILGUN_RELAY_SECRETS_PATH`.

## Intended Flow

```text
Django app using django-anymail
  -> POST https://mailgun.home.xn--wersdrfer-47a.de/v3/{domain}/messages
  -> mailgun-relay validates token, domain, and sender policy
  -> authenticated SMTP submission to smtp.home.xn--wersdrfer-47a.de:587
  -> existing self-hosted mail stack
  -> recipient mail system
```

The existing mail stack remains responsible for SMTP delivery, DKIM signing, SPF/DMARC alignment, queueing, and downstream relay behavior. This service is the HTTP compatibility boundary for trusted applications.

## Observability

The service writes one JSON object per line to stdout. Under systemd that is
journald, so `journalctl -u mailgun-relay -f` is the live view.

- `event=startup` — one record per process start, with the effective
  configuration: version, bind address, public host, SMTP host/port/STARTTLS,
  whether a custom CA bundle is in use, the SMTP concurrency cap, log level,
  the configured token *labels*, and the body/recipient caps. Raising `MAILGUN_RELAY_LOG_LEVEL`
  above `INFO` quietens the request records but never this one.
- `event=request` — one record per `POST /v3/{domain}/messages`, with
  `request_id`, `token_label`, `path_domain`, `from`, `recipient_count`,
  `message_id`, `result`, `status_code`, `error_class`, `duration_ms`.

Neither record contains token values or hashes, the `Authorization` header,
SMTP credentials, message bodies, or attachment content.

A relay nobody has asked to send anything logs nothing between restarts — that
is normal, not a fault. The `startup` record is the anchor: if it is there, the
logging pipeline works. Log records are flushed per record, so `PYTHONUNBUFFERED`
is not needed; if recent records are present but older history is gone, the
cause is journald retention on the host, not the service.

`GET /health` returns `{"status":"ok"}`, touches no SMTP, and writes no log
line. It deliberately omits the service version: the ingress router has no path
restriction, so the endpoint is reachable by unauthenticated callers.

## Boundaries

In scope:

- Mailgun-like `POST /v3/{domain}/messages` for Anymail sends.
- Basic auth with username `api` and a service-issued token as password.
- Strict token, sender domain, and `from` address validation so the service cannot become an open relay.
- MIME construction from accepted form fields, including selected `h:*` headers and attachments.
- Authenticated SMTP submission to the existing home mail backend.

Out of scope:

- `POST /v3/{domain}/messages.mime` (raw MIME submission) — verified unused by current Anymail callers.
- Mailgun domains API, events API, webhooks, tracking, templates, suppressions, inbound routing, analytics, message search, or account management.
- Deployment roles, playbooks, secrets, DNS, TLS, or Django app settings changes in this repository. Deployment lives in `ops-library` (`mailgun_relay_deploy`, `mailgun_relay_ingress_deploy`) and `ops-control` (`playbooks/deploy-mailgun-relay.yml`).
- Adding new sender domains to the live mail stack.

## Alternatives Considered

Postal is the closest open source alternative if this service grows into a
self-hosted ESP with queues, delivery logs, webhooks, suppressions, and domain
management. It is not used for the current MVP because the requirement is a
narrow Mailgun send API compatibility shim for existing django-anymail Mailgun
callers, backed by the existing SMTP stack. Revisit Postal if requirements
expand beyond simple trusted transactional sends.

## Documentation

- [Backlog](docs/backlog.md) defines phased, actionable work with acceptance criteria.
- [Implementation Plan](docs/implementation-plan.md) orders the work from empty repo to production rollout.
- [Architecture](docs/architecture.md) describes data flow, trust boundaries, validation, SMTP submission, and failure handling.
- [API Compatibility](docs/api-compatibility.md) documents the planned Mailgun/Anymail subset and unsupported features.
- [Ops Integration](docs/ops-integration.md) describes the later `ops-library` and `ops-control` integration shape.

## Upstream References

Future implementers must verify behavior against current upstream docs before coding:

- Anymail Mailgun docs: https://anymail.dev/en/stable/esps/mailgun/
- Mailgun Messages API docs: https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages
- FastAPI file upload docs, if FastAPI is used: https://fastapi.tiangolo.com/tutorial/request-files/
