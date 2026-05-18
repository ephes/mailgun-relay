# Backlog

This backlog is organized as phases. The MVP should be intentionally small: enough Mailgun send API compatibility for Django Anymail to submit mail through the existing authenticated SMTP backend, without becoming a generic Mailgun clone.

## Phase 0: Planning Baseline

### Repository documentation set

Rationale: Future implementation needs a clear local source of truth before code and deployment work begin.

Acceptance criteria:

- `README.md` states purpose, status, boundaries, and high-level flow.
- `docs/architecture.md`, `docs/api-compatibility.md`, `docs/implementation-plan.md`, `docs/ops-integration.md`, and this backlog exist.
- Docs link to Anymail, Mailgun Messages API, and FastAPI upload docs for future verification.

Notes/dependencies: This is the current slice. No service code, ops changes, secrets, DNS, TLS, or Django app changes are part of this phase.

### Compatibility assumptions register

Rationale: The implementation will depend on the exact fields Anymail sends to Mailgun. Assumptions should be explicit and tested.

Acceptance criteria:

- API docs list supported endpoints, fields, response bodies, and error mapping.
- Unsupported Mailgun features are documented.
- Implementation plan includes a checkpoint to inspect Anymail-generated requests before production rollout.
- Current Anymail output is captured for ordinary `EmailMessage`, `EmailMultiAlternatives`, attachments, extra headers, CC, BCC, tags, metadata, tracking flags, and any Anymail mixins used by `homepage` or `python-podcast`.
- Captured request samples and field classifications are recorded in `docs/anymail-request-samples.md`.
- Exact `o:*` fields emitted by current app usage are classified as implemented, documented no-op, or rejected.
- `MAILGUN_SENDER_DOMAIN` behavior is verified for path-domain and `from`-domain mismatches in the current Anymail version.
- `homepage` and `python-podcast` are audited for `send_mime_message`, raw MIME usage, or other code paths that require `/messages.mime`.
- Candidate SMTP HTTP error mappings are verified against Anymail exception behavior before being treated as final.

Notes/dependencies: Verify against https://anymail.dev/en/stable/esps/mailgun/ and https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages before coding.

## Phase 1: MVP Service

### Project scaffold

Rationale: The repo needs a minimal, testable Python service structure before behavior can be implemented.

Acceptance criteria:

- Python project metadata, dependency management, formatting, linting, type checking, and test commands are defined.
- A local development entry point starts the HTTP service.
- CI or local verification commands are documented.

Notes/dependencies: FastAPI is the current recommended default because multipart forms, uploaded files, and automatic test clients fit the API shape. If another stack is chosen, document why.

### `POST /v3/{domain}/messages`

Rationale: This is the main Mailgun endpoint Anymail uses for normal sends.

Acceptance criteria:

- Endpoint accepts Mailgun-style multipart form data.
- Required fields are validated: `from`, at least one recipient across `to`/`cc`/`bcc`, and a body or equivalent MIME content.
- Supported fields include `from`, `to`, `cc`, `bcc`, `subject`, `text`, `html`, selected `h:*` headers, and attachments if required by current apps.
- Success returns JSON shaped like `{"id": "...", "message": "Queued. Thank you."}`.
- Tests cover success, missing required fields, invalid sender, invalid token, unsupported fields, and SMTP failure mapping.
- Response `id` and SMTP `Message-Id:` are correlated where practical.

Notes/dependencies: Do not implement templates, tracking, webhooks, domains API, events API, or analytics.

### Basic auth and token validation

Rationale: The service must never become an open relay.

Acceptance criteria:

- Requests require HTTP Basic auth username `api`.
- Password is compared to configured token material using constant-time comparison.
- Token records map to allowed Mailgun sender domains and allowed sender identities.
- Invalid credentials return a Mailgun-compatible unauthorized response without leaking token details.

Notes/dependencies: Token values belong in `ops-control` secrets later, not in this repo.

### Domain and sender policy

Rationale: Mailgun's `{domain}` path parameter is the primary compatibility hook, but local authorization must be stricter than path matching.

Acceptance criteria:

- `{domain}` is normalized and compared against the token's allowed sender domains.
- `from` address domain and optional configured sender identities are validated against token policy.
- IDN domains use punycode in configuration and logs where practical.
- Tests cover allowed domain, disallowed domain, allowed alias behavior, and invalid `from` address.

Notes/dependencies: Initial known hosted domains in the current mail stack include `xn--wersdrfer-47a.de`, `wersdoerfer.de`, `wersdoerfer.com`, and `opaq.de`; do not assume all are allowed for every token.

### MIME construction

Rationale: SMTP submission needs a standards-compliant message produced from Mailgun form fields.

Acceptance criteria:

- Text-only, HTML-only, multipart alternative, CC, BCC envelope behavior, reply-to/custom header behavior, and attachments are handled deliberately.
- `bcc` recipients are included in the SMTP envelope but not exposed in message headers.
- Header injection is rejected.
- Dangerous custom headers such as `Bcc`, `Received`, `Return-Path`, and `Resent-*` are rejected or explicitly forbidden.
- Header value length limits are enforced or documented for production hardening.
- Tests inspect generated MIME for representative messages.

Notes/dependencies: Prefer Python standard email APIs or a mature library over manual MIME string assembly.

### SMTP submission

Rationale: Delivery should reuse the existing authenticated mail backend and its DKIM/SPF/DMARC path.

Acceptance criteria:

- Service submits via STARTTLS to a configured SMTP host, expected initially as `smtp.home.xn--wersdrfer-47a.de:587`.
- SMTP envelope sender policy is explicit: default to a dedicated relay-controlled mailbox unless backend sender/login binding is configured to allow application sender addresses.
- The chosen envelope `MAIL FROM` and bounce routing behavior are documented and tested.
- Backend PostfixAdmin sender/login binding is verified before live submission.
- SMTP username and password are configured through environment or secret files, not committed.
- SMTP response handling is mapped to HTTP responses and logs without exposing credentials.
- Tests use a fake SMTP server or mocked client.

Notes/dependencies: The backend role documents ports 587/465 for authenticated client submission.

### MVP observability

Rationale: Operators need enough signal to distinguish auth failures, validation failures, and SMTP failures.

Acceptance criteria:

- Structured logs include request id, token label, domain, sender, recipient count, message id, result, and duration.
- Logs never include token values, SMTP passwords, full message bodies, or attachment content.
- A health endpoint or equivalent deploy-time check is available.

Notes/dependencies: Metrics can be minimal in MVP but should not require parsing message content.

## Phase 2: Production Hardening

### Rate limiting and abuse controls

Rationale: Even trusted app tokens can be misconfigured or leaked.

Acceptance criteria:

- Per-token and global request rate limits are implemented or delegated to the reverse proxy.
- Maximum recipients, message size, attachment count, and header count are enforced.
- Abuse limits are documented and tested.

Notes/dependencies: Coordinate final limits with ops reverse proxy and expected app traffic.

### Robust error model

Rationale: Anymail should receive actionable failures without depending on Mailgun-only semantics that are not implemented.

Acceptance criteria:

- Validation errors map to 400.
- Auth errors map to 401.
- Rate limits map to 429.
- SMTP temporary failures have a final documented HTTP mapping only after Phase 0 verifies Anymail exception and retry behavior.
- SMTP permanent failures have a final documented HTTP mapping only after Phase 0 verifies Anymail exception behavior.

Notes/dependencies: Verify how Anymail converts Mailgun HTTP errors into Django exceptions before finalizing.

### Security review

Rationale: This service bridges HTTPS requests to authenticated SMTP and can affect mail reputation.

Acceptance criteria:

- Threat model covers open relay risk, token leakage, sender spoofing, SMTP sender/login binding, envelope `MAIL FROM` choice, header injection, SSRF through attachments or remote content, log leakage, secret file leakage, and replay considerations.
- Tests cover auth bypass and sender/domain bypass attempts.
- Deployment docs describe secret rotation and token revocation.

Notes/dependencies: Review before exposing the service beyond local trusted networks.

### Delivery reliability

Rationale: Users need predictable behavior when SMTP is slow, temporarily unavailable, or returns partial recipient failures.

Acceptance criteria:

- Timeouts are explicit.
- Partial recipient acceptance behavior is documented and tested.
- Retry policy is deliberate: either synchronous SMTP result only, or a queue is introduced with documented semantics.

Notes/dependencies: MVP should prefer synchronous submission unless a queue becomes necessary.

### Packaging and release workflow

Rationale: Production deployment needs repeatable artifacts and version visibility.

Acceptance criteria:

- Service can be installed or run reproducibly from a git checkout or packaged artifact.
- Version/revision is exposed in logs or a status endpoint.
- Release notes or changelog updates are required for behavior changes.

Notes/dependencies: Match the deployment style expected by FastDeploy and the ops repos.

## Phase 3: Ops Integration

### `ops-library` deployment role

Rationale: Public deployment logic belongs in `ops-library`, not this repo.

Acceptance criteria:

- A role installs the service, configures a system user, service unit, environment file path, reverse proxy integration if needed, and health checks.
- Role README documents variables, examples, ports, TLS expectations, and troubleshooting.
- Role tests/lint/type checks run in `ops-library`.

Notes/dependencies: This repo should provide service runtime expectations and sample non-secret config only.

### `ops-control` playbook and secrets

Rationale: Private host selection, token material, and SMTP credentials belong in `ops-control`.

Acceptance criteria:

- Playbook configures host, domain `mailgun.home.xn--wersdrfer-47a.de`, token policies, and SMTP submission credentials.
- SOPS secrets contain token hashes or equivalent secret material and dedicated SMTP credentials.
- Deployment runbook explains validation and rollback.

Notes/dependencies: Do not commit real values to this repo.

### Monitoring and runbook

Rationale: Operators need production support procedures before relying on the adapter.

Acceptance criteria:

- Monitoring covers service availability, auth failure spikes, SMTP failure spikes, latency, and rate-limit events.
- Runbook covers checking service logs, SMTP connectivity, mail queue, token rotation, and rollback.
- Health checks are wired into deployment.

Notes/dependencies: Reuse existing ops patterns where possible.

## Phase 4: App Migration

### Homepage migration

Rationale: `homepage` currently uses Anymail Mailgun settings in production.

Acceptance criteria:

- Production settings add `MAILGUN_API_URL` pointing to the new service.
- Existing email backend remains `anymail.backends.mailgun.EmailBackend`.
- Secret values are moved or rotated to service-issued tokens.
- A staging or controlled production test send succeeds.

Notes/dependencies: App changes are out of scope for this planning slice.

### Python Podcast migration

Rationale: `python-podcast` also uses Anymail Mailgun in production and may have different sender domains.

Acceptance criteria:

- Production settings add `MAILGUN_API_URL` pointing to the new service.
- Sender domain and default sender policy are matched to token configuration.
- A controlled test send succeeds and rollback is documented.

Notes/dependencies: The current default sender uses `mg.python-podcast.de`; do not assume the current self-hosted mail stack accepts this domain without a separate ops decision.

## Future / Non-Goals

### Optional `POST /v3/{domain}/messages.mime`

Rationale: Anymail or future callers may need raw MIME submission.

Acceptance criteria:

- Need is verified against Anymail behavior and current app usage.
- Endpoint validates token/domain/sender policy by parsing MIME headers.
- Tests cover raw MIME with attachments and BCC envelope behavior.

Notes/dependencies: Keep optional until proven necessary.

### Explicit non-goals

Rationale: A narrow adapter reduces maintenance and risk.

Acceptance criteria:

- The project does not implement Mailgun domains, events, webhooks, tracking, templates, suppressions, inbound routing, analytics, message search, or billing/account APIs.
- Unsupported features fail clearly if Anymail sends fields the service does not accept.

Notes/dependencies: Revisit only with a concrete app requirement and new planning.
