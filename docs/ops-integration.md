# Ops Integration Plan

This repo defines the service contract and runtime expectations. Deployment implementation lives in the ops repositories:

- `ops-deploy`: public typed pyinfra relay and ingress implementation, `ops_deploy.services.mailgun_relay`.
- `ops-library`: retained public Ansible roles `mailgun_relay_deploy` and `mailgun_relay_ingress_deploy`, with their role documentation.
- `ops-control`: engine dispatch, private controller adapter/playbook, inventory, host configuration and SOPS secrets. The central dispatcher chooses the engine; `secrets/prod/mailgun-relay.yml` and host inventory provide the same policy and implementation pins.

## Ordinary Deployment and Python Retention

Run from the selected `ops-control` workspace:

```bash
just deploy-one mailgun_relay
# Equivalent alias: just deploy-one mailgun-relay
```

There is no application-local deploy wrapper. Use this dispatcher so the
controller's `services-metadata.yml` selects pyinfra or the retained Ansible
path. The host inventory remains the authority for `mailgun_relay_impl` and the
Rust version/archive checksum; this application repository does not choose or
upgrade the deployed implementation.

The existing macmini pyinfra adapter selects `python_deploy="preserve"`. It
retains Python source, interpreter, venv, dependencies and trust configuration
through at least 2026-11-16 15:51:36 UTC and beyond until explicit retirement,
with no automatic expiry or refresh. Changing inventory to Python and using
the same dispatcher starts the preserved rollback installation independently
of a failed Rust release. A bad shared environment/policy still needs correction
and redeployment; changing implementations alone cannot repair it.

Public pyinfra supports explicit fresh-host Python installation/update via
`rsync` or `git`; the retained macmini adapter does not select either. The
Ansible play remains available with its original source synchronization and uv
dependency behavior. The role variable reference below describes that retained
Ansible interface. The deployment and rollback steps in `rust/PLAN.md` §11
describe that original Ansible path, including its per-deploy venv build;
the pyinfra preservation contract above governs the retained installation
when that engine is selected. Operator details and deployment receipts belong in
`ops-control/docs/MAILGUN_RELAY_RUST.md`, and the typed public API is documented
in the [ops-deploy repository](https://github.com/ephes/ops-deploy).

## Existing Mail Stack Context

The current backend mail deployment runs on `macmini` and includes Postfix, Dovecot, PostgreSQL, and OpenDKIM. It exposes authenticated client submission on ports 587 and 465 and signs outbound mail.

The current edge relay accepts inbound mail for configured domains and relays to the backend at `smtp.home.xn--wersdrfer-47a.de`.

Known backend-hosted domains from current playbooks:

- `xn--wersdrfer-47a.de`
- `wersdoerfer.de`
- `wersdoerfer.com`
- `opaq.de`

The service should not assume every hosted domain is valid for every application token.

## Public Endpoint

Hostname:

```text
mailgun.home.xn--wersdrfer-47a.de
```

API base URL for Django Anymail:

```text
https://mailgun.home.xn--wersdrfer-47a.de/v3
```

Docs and configs should use the punycode domain.

## SMTP Submission Target

Target:

```text
smtp.home.xn--wersdrfer-47a.de:587
```

Behavior:

- STARTTLS required, with full certificate **and hostname verification** (it
  cannot be disabled). If the backend presents a certificate from a private CA,
  set `MAILGUN_RELAY_SMTP_CA_FILE` to the CA bundle path so verification
  succeeds; do not work around it by disabling STARTTLS.
- Authenticated SMTP submission. The service refuses to send credentials over a
  non-TLS connection, so leaving `smtp_starttls` off with credentials set fails
  closed instead of leaking them.
- Dedicated SMTP credentials for this service, not a personal mailbox password if avoidable.
- Sender permissions should be as narrow as the backend supports.
- Backend sender/login binding must be verified. If enforced, the service's SMTP envelope sender must be allowed for the relay login, or ops must add an explicit backend-side allowance.
- The default plan is to use a relay-controlled mailbox as SMTP envelope sender while preserving the validated application `From:` header.
- Ops must provision a dedicated PostfixAdmin mailbox or equivalent SMTP identity for the relay service account and document its envelope sender address and bounce destination.

The backend mail role documents client submission on port 587/465 and DKIM signing in the backend. The adapter should rely on that path rather than trying to sign mail itself.

## `ops-library` Role Shape

The shipped role is `mailgun_relay_deploy` (paired with
`mailgun_relay_ingress_deploy` for Traefik dynamic config).

Responsibilities:

- Install runtime dependencies or deploy packaged artifact.
- Create service user and directories.
- Install systemd unit.
- Render non-secret environment/config file.
- Reference secret file paths without embedding secret values in role defaults.
- Configure health checks.
- Optionally configure reverse proxy integration if that pattern belongs in existing roles.
- Document variables, examples, ports, security assumptions, and troubleshooting in the role README.

Key variables (full list with descriptions in
`ops-library/roles/mailgun_relay_deploy/README.md`):

```yaml
mailgun_relay_public_host: "mailgun.home.xn--wersdrfer-47a.de"
mailgun_relay_bind_host: "127.0.0.1"
mailgun_relay_bind_port: 8085
mailgun_relay_smtp_host: "smtp.home.xn--wersdrfer-47a.de"
mailgun_relay_smtp_port: 587
mailgun_relay_smtp_starttls: true
mailgun_relay_env_path: "/etc/mailgun-relay/mailgun-relay.env"
mailgun_relay_secrets_path: "/etc/mailgun-relay/secrets.yml"
# Optional: CA bundle for a private-CA SMTP backend. Empty = system trust store.
# mailgun_relay_smtp_ca_file: "/etc/ssl/private/home-ca.pem"
```

The secrets file must be `0640` or stricter (the role renders
`0640 root:mailgun-relay`). The service refuses to start if the file is
world-accessible or group-writable.

The loopback bind assumes a local reverse proxy (Traefik) terminates TLS and
forwards to the service. Binding to a non-loopback interface requires an
explicit ops decision with firewall and TLS implications documented.

## `ops-control` Playbook and Secrets Shape

Responsibilities (the private pyinfra adapter and retained
`playbooks/deploy-mailgun-relay.yml`):

- Select target host.
- Provide hostname and reverse proxy/TLS settings.
- Provide token policies and SMTP credentials via SOPS.
- Configure allowed sender domains per application.
- Deploy and verify the service using the ops workflow.

SOPS-backed secret shape (matches `ops-control/secrets/prod/mailgun-relay.yml`
and what both controller paths consume — top-level keys, no
outer `mailgun_relay:` wrapper):

```yaml
smtp_username: "mailgun-relay@xn--wersdrfer-47a.de"
smtp_password: "REDACTED"
envelope_sender: "mailgun-relay@xn--wersdrfer-47a.de"
tokens:
  - label: "homepage-production"
    token_sha256: "REDACTED"  # lowercase hex sha256(raw_token); 64 chars
    mailgun_domains:
      - "mg.wersdoerfer.de"
    allowed_from_domains:
      - "wersdoerfer.de"
    allowed_from_addresses:
      - "jochen-homepage@wersdoerfer.de"
```

`jochen-homepage@wersdoerfer.de` is a real, deliverable address, not a
placeholder: the home mail backend runs Postfix and Dovecot with
`recipient_delimiter = -`, so `jochen-<tag>@wersdoerfer.de` is a tagged form of
the `jochen@` mailbox and the tag records which application sent the message.
The delimiter is `-`, not the `+` most providers use.

This example is structural only. Do not commit real tokens, SMTP passwords,
private keys, or decrypted secret output. The raw token is never stored on
the relay host — only its `token_sha256` lives in SOPS; the raw value goes
into the consuming Django app's SOPS file as `django_mailgun_api_key`.

## DNS and TLS Considerations

Later ops work must decide:

- DNS record for `mailgun.home.xn--wersdrfer-47a.de`.
- Whether the service is reachable publicly, only through a private network, or through an authenticated reverse proxy path.
- TLS certificate issuance method.
- Reverse proxy routing to the local service.
- HSTS implications for the `home.xn--wersdrfer-47a.de` namespace.

No DNS or TLS changes are part of this repo slice.

## Monitoring Topics

Production monitoring should cover:

- HTTP availability and health endpoint.
- Request latency.
- Successful submissions.
- Auth failures by token label if known, without token values.
- Sender/domain validation failures.
- SMTP connection, auth, timeout, temporary failure, and permanent rejection counts.
- Rate-limit events.
- Process restarts.

Metrics should avoid message body, attachment content, or recipient address cardinality explosion. Logs may include recipient count rather than full recipient lists by default.

## Runbook Topics to Add Later

Operational docs should explain:

- How to deploy and roll back.
- How to check the service status.
- How to inspect logs safely.
- How to test SMTP connectivity from the service host.
- How to send a controlled test message without leaking tokens.
- How to rotate or revoke a token.
- How to rotate SMTP submission credentials.
- How to distinguish adapter errors from backend Postfix queue or relay errors.
- How to temporarily point a Django app back to real Mailgun.

## Deploy Readiness Checklist

Before production migration:

- Service tests, lint, and type checks pass.
- Ops role tests and docs are complete.
- SOPS secrets are reviewed and scoped.
- TLS and DNS are in place.
- Health check is wired into deployment.
- Controlled test send succeeds.
- Bad-token, bad-domain, and bad-sender tests fail as expected.
- Rollback path is documented for each migrated Django app.
