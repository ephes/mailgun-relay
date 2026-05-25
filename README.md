# mailgun-relay

`mailgun-relay` is planned as a small Mailgun send API adapter for existing Django projects that already use `django-anymail` with `anymail.backends.mailgun.EmailBackend`.

The goal is compatibility with the Mailgun send API surface Anymail needs, not a full Mailgun clone. Django projects should keep their current email backend and later point Anymail at this service with `MAILGUN_API_URL`, while continuing to use a scoped token as `MAILGUN_API_KEY`.

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

## Boundaries

In scope for the future service:

- Mailgun-like `POST /v3/{domain}/messages` for Anymail sends.
- Optional `POST /v3/{domain}/messages.mime` after verifying whether current applications need it.
- Basic auth with username `api` and a service-issued token as password.
- Strict token, sender domain, and `from` address validation so the service cannot become an open relay.
- MIME construction from accepted form fields, including selected `h:*` headers and attachments when required.
- Authenticated SMTP submission to the existing home mail backend.

Out of scope:

- Mailgun domains API, events API, webhooks, tracking, templates, suppressions, inbound routing, analytics, message search, or account management.
- Deployment roles, playbooks, secrets, DNS, TLS, or Django app settings changes in this repository unless explicitly requested in a later slice.
- Adding `django-cast.com` or any other new domain to the live mail stack as part of this planning slice.

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
