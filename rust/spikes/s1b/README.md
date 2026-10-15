# S1b spike: lettre connection API (throwaway)

Prototype for `rust/PLAN.md` slice S1b. Not production code; not merged to `main`.

- `src/main.rs`: `submit` (STARTTLS, AUTH, MAIL, one `RCPT` per recipient,
  partial refusal, `DATA`, status classification), `ehlo` (read-only probe:
  EHLO, STARTTLS, EHLO, QUIT), `addr` (lettre `Address` parsing).
- `fake/scripted_smtp.py`: scripted fake SMTP server (stdlib asyncio + ssl),
  one fault scenario per process.
- `fake/aiosmtpd_server.py`: aiosmtpd cross-check (STARTTLS required, AUTH,
  RCPT `bad@…` refused with 550).
- `fake/oracle.py`: runs the Python relay's `smtp_client.submit` against the
  same fake server.
- `fake/run_matrix.py`: runs every scenario through Rust and Python and
  prints both HTTP statuses.

```sh
cd rust/spikes/s1b && cargo build --release && cd -
uv sync
python3 rust/spikes/s1b/fake/run_matrix.py "$(mktemp -d)"
```

The result is recorded in the campaign handoff (`s1b-spike-result.md`).
