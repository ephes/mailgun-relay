# Ops Integration Plan

This repo defines the service contract and runtime expectations. Deployment implementation lives in the ops repositories:

- `ops-library`: public deployment role logic and role documentation. The `mailgun_relay_deploy` and `mailgun_relay_ingress_deploy` roles implement the deploy.
- `ops-control`: private playbooks, inventory, host-specific config, and SOPS secrets. `playbooks/deploy-mailgun-relay.yml` and `secrets/prod/mailgun-relay.yml` are the active artifacts.

## Existing Mail Stack Context

The current backend mail deployment runs on `macmini` and includes Postfix, Dovecot, PostgreSQL, and OpenDKIM. It exposes authenticated client submission on ports 587 and 465 and signs outbound mail.

The current edge relay accepts inbound mail for configured domains and relays to the backend at `smtp.home.xn--wersdrfer-47a.de`.

Known backend-hosted domains from current playbooks:

- `xn--wersdrfer-47a.de`
- `wersdoerfer.de`
- `wersdoerfer.com`
- `opaq.de`

The service should not assume every hosted domain is valid for every application token.

## Planned Public Endpoint

Planned hostname:

```text
mailgun.home.xn--wersdrfer-47a.de
```

Planned API base URL for Django Anymail:

```text
https://mailgun.home.xn--wersdrfer-47a.de/v3
```

Docs and configs should use the punycode domain.

## SMTP Submission Target

Expected target:

```text
smtp.home.xn--wersdrfer-47a.de:587
```

Expected behavior:

- STARTTLS required.
- Authenticated SMTP submission.
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

Expected variables:

```yaml
mailgun_relay_hostname: "mailgun.home.xn--wersdrfer-47a.de"
mailgun_relay_listen_host: "127.0.0.1"
mailgun_relay_listen_port: 8080
mailgun_relay_public_base_url: "https://mailgun.home.xn--wersdrfer-47a.de/v3"
mailgun_relay_smtp_host: "smtp.home.xn--wersdrfer-47a.de"
mailgun_relay_smtp_port: 587
mailgun_relay_smtp_starttls: true
mailgun_relay_config_path: "/etc/mailgun-relay/config.yml"
mailgun_relay_secret_path: "/etc/mailgun-relay/secrets.yml"
```

The loopback listen default assumes a local reverse proxy terminates TLS and forwards to the service. If the service is bound to a non-loopback interface, that must be an explicit ops decision with firewall and TLS implications documented.

The actual names should follow ops-library conventions when implemented.

## `ops-control` Playbook and Secrets Shape

Expected responsibilities:

- Select target host.
- Provide hostname and reverse proxy/TLS settings.
- Provide token policies and SMTP credentials via SOPS.
- Configure allowed sender domains per application.
- Deploy and verify the service using the ops workflow.

Possible SOPS-backed secret shape:

```yaml
mailgun_relay:
  smtp_username: "service-account@example.invalid"
  smtp_password: "REDACTED"
  tokens:
    - label: "homepage-production"
      token_hash: "REDACTED"
      mailgun_domains:
        - "xn--wersdrfer-47a.de"
      allowed_from_domains:
        - "xn--wersdrfer-47a.de"
        - "wersdoerfer.de"
      allowed_from_addresses:
        - "jochen-homepage@wersdoerfer.de"
```

This example is structural only. Do not commit real tokens, SMTP passwords, private keys, or decrypted secret output.

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
