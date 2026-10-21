# mailgun-relay

`mailgun-relay` is a small Mailgun send API adapter for existing Django projects that already use `django-anymail` with `anymail.backends.mailgun.EmailBackend`.

The goal is compatibility with the Mailgun send API surface Anymail needs, not a full Mailgun clone. Django projects keep their current email backend and point Anymail at this service with `MAILGUN_API_URL`, while using a scoped service-issued token as `MAILGUN_API_KEY`.

## Status

The current published security release is [`rs-v0.2.2`](https://github.com/ephes/mailgun-relay/releases/tag/rs-v0.2.2),
published on 2026-10-21 from `9fd78bf88bbe488d3d27ef81030ee89364f58b6c`.
Publication is separate from controller selection and running-process verification.

Rust **0.2.1** (`rs-v0.2.1`) was switched into production on macmini on
2026-10-17. The HTTP contract, token/domain/sender policy, environment and
secrets interfaces remain compatible with the Python service; MIME is
compared semantically, not byte for byte. The Python 0.1.0 implementation
remains available as the rollback path for at least 30 days after cutover
(until at least 2026-11-16 15:51:36 UTC).

The cutover and rollback checks passed on 2026-10-17. A review on
2026-10-19, about 40 hours after the final Rust return, found stable
resources, no restarts and no unexplained relay or probe errors. One
controlled Homepage production test traversed Django/Anymail, relay
acceptance, Postfix delivery and IMAP exactly once. This establishes the
stability and application transport path; it was not natural user traffic.

**The technical stability, application transport and DKIM criteria are
fulfilled and were accepted by the owner on 2026-10-19. S10 is complete.**
Normal, unmodified
`opendkim-testmsg` verified the same original Homepage mail successfully
on 2026-10-19 at 11:28:49 UTC. Earlier key-retrieval failures remain part
of the verification history. No new mail or relay restart was needed.
There is no mandatory seven-day wait. Normal 15-minute monitoring
continues; no review scheduler is configured. See
[`rust/PLAN.md`](rust/PLAN.md#106-soak-and-abort-criteria) for the current
S10 state and follow-up checks, and [`rust/README.md`](rust/README.md) for
Rust build and release instructions.

The `mailgun_relay_deploy` role in ops-library selects the implementation;
ops-control owns inventory, the deployment playbook and the operator runbook
`docs/MAILGUN_RELAY_RUST.md`. Existing Django projects keep their Anymail
Mailgun backend and scoped relay tokens.

See [`CHANGELOG.md`](./CHANGELOG.md) for changes and the earlier per-app
migration and rollback evidence.

## Quickstart (Python development)

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy
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
  the configured token *labels*, the body/recipient caps, and
  `fail_on_partial_refusal`. Raising `MAILGUN_RELAY_LOG_LEVEL`
  above `INFO` quietens the request records but never this one.
- `event=request` — one record per `POST /v3/{domain}/messages`, with
  `request_id`, `token_label`, `path_domain`, `from`, `recipient_count`,
  `refused_count`, `message_id`, `result`, `status_code`, `error_class`,
  `duration_ms`.
- `event=recipients_refused` — a `WARNING` emitted when the SMTP server
  accepted the message for some recipients and refused others. It carries the
  same `request_id`/`message_id` as the request record, `refused_count`, and a
  `refused` list of `{domain, code}` pairs. Local parts and the SMTP reply text
  are never logged. See `docs/api-compatibility.md` for the HTTP behaviour.

- `event=smtp_cleanup_failed` — a `WARNING` with only the exception class when
  QUIT or close fails. Accepted sends keep their outcome; closed sessions skip QUIT.

These records contain no token values or hashes, the `Authorization` header,
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
- [Rust port](rust/README.md) is the in-progress re-implementation as a small binary; [`rust/PLAN.md`](rust/PLAN.md) is its contract.

## Upstream References

Future implementers must verify behavior against current upstream docs before coding:

- Anymail Mailgun docs: https://anymail.dev/en/stable/esps/mailgun/
- Mailgun Messages API docs: https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages
- FastAPI file upload docs, if FastAPI is used: https://fastapi.tiangolo.com/tutorial/request-files/
