# Python test → Rust test map (sketch)

Every Python test that pins relay behaviour gets a Rust counterpart, a fixture
case or a parity-harness case (PLAN.md section 7). Each slice fills in the
rows it covers. Status: `pending (Sn)`, `done`, or `n/a` with the reason.
Baseline: 222 Python tests at `13e274f`.

Kinds: **unit** = Rust unit/integration test; **fixture** = case in
`rust/fixtures/*.json` generated from Python; **harness** = case in
`rust/parity/cases/` run against both implementations.

## Python fix before the port (S0-py)

New Python tests (Q1, Q2) land in S0-py; their Rust counterparts are harness
and fixture cases generated from the fixed Python.

| Python test (new in S0-py) | Rust counterpart | Status |
| --- | --- | --- |
| empty `text`/`html` without another body → 400; empty text + html → 200 html-only | harness + unit `pipeline::tests` | pending (S0-py, S3) |
| encoded CR/LF in To/Cc display name → 400, multi-fault with invalid Cc | harness + unit `mime::tests` | pending (S0-py, S4) |
| IDN recipients/from/Reply-To as A-labels, no SMTPUTF8; EAI local parts → 400 | fixture `address.json`, harness | pending (S0-py, S2/S4) |

## Auth, policy, addresses (S2)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_auth.py` (all 8) | fixture `auth.json` + unit `auth::tests`; harness 401 cases with realm | pending (S2) |
| `test_policy.py` (all 13) | fixtures `domain.json`, `address.json`, `policy.json`; unit `policy::tests` for the production shapes | pending (S2) |
| `test_headers.py::test_parse_address_list_*`, `::test_header_address_list_*` | fixture `address.json` | pending (S2) |
| `test_config.py::test_load_secrets_normalizes_idn_to_punycode`, `::test_token_policy_allowed_addresses_none_means_domain_only` | fixture `config_secrets.json` | pending (S1c) |
| new: corpus decisions (≥ 400 addresses, ≥ 100 domains), "Rust accepts ⇒ Python accepts" | property test over `address.json`/`domain.json` | pending (S2) |

## Configuration and startup (S1a, S1c, S1d)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_config.py::test_load_secrets_*` (minimal, IDN to punycode, empty tokens, changeme, bad sha, duplicate labels, missing domains, mode bits) | fixture `config_secrets.json` | pending (S1c) |
| `test_config.py::test_token_policy_allowed_addresses_none_means_domain_only` | fixture `config_secrets.json` | pending (S1c) |
| `test_config.py::test_settings_reads_env`, `::test_envelope_sender_*`, `test_nonblocking_submit.py::test_smtp_max_concurrency_must_be_positive` | fixture `config_env.json` (160 env sets) via `config::tests::config_env_fixture` | done (S1a) |
| `test_config.py::test_token_policy_repr_does_not_leak_sha` | unit: `Debug` of policies and credentials redacts | pending (S1c) |
| `test_logging.py` (all 4) | unit `log::tests`; process test reads stdout per line | pending (S1d) |
| `test_health.py` (both) | unit + process test; harness `/health` cases | pending (S1d, S6) |
| new: 404/405/307, `HEAD /health`, 413 on `/health` and a 404 path | unit + process test | pending (S1d) |
| new: `--version`, `--check-config` exit 0/1, unknown arguments exit 2 | process tests `binary.rs` | done (S1a) |

## Request pipeline (S3)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_body_limit.py` (declared, streamed, within limit) | unit + harness | pending (S3) |
| `test_body_limit.py::test_invalid_or_negative_content_length_rejected` | harness against real uvicorn (D-12) | pending (S6) |
| `test_body_limit.py::test_non_http_scope_passes_through` | n/a: ASGI lifespan scope has no Rust equivalent | n/a |
| `test_headers.py::test_validate_subject_*`, `::test_custom_headers_*` | fixture `headers.json` | pending (S3) |
| `test_messages_endpoint.py` 400/403/413 cases (`o:`, `v:`, `template`, `recipient-variables`, subject CRLF, `h:Bcc`, no recipients, no body, malformed from/to/Reply-To, injected CRLF, attachments too big/too many/flood, inline counting, huge text, malformed inline filename) | unit `pipeline::tests` + harness | pending (S3) |
| `test_messages_endpoint.py` policy cases (path/from domain/from address, cross-domain, parent domain, foreign token) | unit + harness | pending (S3) |
| `test_messages_endpoint.py::test_path_domain_logged_as_punycode`, `::test_log_redacts_token_and_smtp_password` | unit (captured log lines) | pending (S3) |
| new: decision-order multi-fault cases, both encodings, limits at N and N+1, `text=""` (D-1) | harness | pending (S6) |

## Message construction (S4)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_mime_build.py` structure tests (text, html, alternative, Cc/Bcc, Reply-To, attachment, Message-Id, display name, inline related/mixed, amp, container downgrade, malformed inline names) | unit `mime::tests` parsing the produced message; harness semantic comparison | pending (S4) |
| `test_mime_build.py::test_inline_explicit_content_id_is_not_double_bracketed` | n/a: form uploads never carry an explicit Content-ID | n/a |
| `test_messages_endpoint.py::test_bcc_only_envelope_not_in_headers`, `::test_cc_in_headers_and_envelope`, `::test_reply_to_*`, `::test_inline_upload_is_related_to_html_with_bracketed_content_id` | harness | pending (S6) |
| new: IDN/EAI recipients (D-2), non-ASCII subject/body/filenames, RFC conformance of the output | unit + harness | pending (S4) |

## SMTP (S5)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_smtp_submission.py` (happy path, partial refusal, all refused, DATA 4xx/5xx, auth, verifying TLS, no cleartext auth, connection refused, timeout) | unit `smtp::tests` against the scripted fake server | pending (S5) |
| `test_smtp_submission.py::test_no_auth_without_credentials_skips_login` | n/a: the secrets schema always provides credentials; covered by `test_refuses_cleartext_auth_without_tls` counterpart | n/a |
| `test_smtp_outcomes.py` (code matrix through submit and endpoint, all-refused mixtures, QUIT/close failures, already closed connection) | unit + harness (fake SMTP scripts) | pending (S5/S6) |
| `test_messages_endpoint.py::test_smtp_*`, `::test_partial_refusal_*`, `::test_full_acceptance_logs_zero_refusals`, `::test_strict_mode_full_acceptance_still_200` | harness | pending (S6) |
| `test_nonblocking_submit.py` (health responsive, cap queues, mapping from the task) | unit with a stalled fake server | pending (S5) |
| new: TLS certificate/hostname failure → 503, wrong CA file, D-3 classes | unit | pending (S5) |

## Not ported

| Python test | Reason |
| --- | --- |
| `test_messages_endpoint.py::test_mypy_without_arguments_checks_the_tests` | Python tooling check |
