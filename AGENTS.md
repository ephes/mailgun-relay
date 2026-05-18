# Repository Guidance

## Scope

This repository owns the `mailgun-relay` application code and local project documentation.

Deployment roles belong in `ops-library`. Inventory, playbooks, and secrets belong in `ops-control`. Do not add deployment automation, SOPS files, private credentials, or live host configuration here unless explicitly requested.

## Documentation

Service behavior, API compatibility, security rules, deployment expectations, or user-facing workflow changes require matching documentation updates in this repo.

Keep docs clear about MVP, production hardening, and non-goals. This service is a Mailgun send API adapter for Anymail, not a general Mailgun replacement.

## Security

Never commit real API tokens, SMTP passwords, private keys, SOPS secrets, or raw production secret output.

The core safety boundary is token, domain, and sender validation. Any implementation change that could allow untrusted relay behavior needs tests and documentation before it is considered complete.
