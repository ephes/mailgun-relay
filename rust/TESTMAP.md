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
| encoded CR/LF in To/Cc display name → 400, multi-fault with invalid Cc | unit `mime::tests::python_mime_build_tests`, `::line_break_detection_fails_closed`; harness | done (S4a); harness pending (S6) |
| IDN recipients/from/Reply-To as A-labels, no SMTPUTF8; EAI local parts → 400 | fixture `address.json`, harness | pending (S0-py, S2/S4) |

## Auth, policy, addresses (S2)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_auth.py` (the 8 original tests) | unit `auth::tests::python_auth_tests` + fixture `auth.json` (121 headers: whitespace, padding, trailing bits, alphabet, UTF-8, `:` in the password, duplicate hashes, non-ASCII bytes, seeded mutations) via `auth::tests::auth_fixture`; harness 401 cases with realm | done (S2a); harness pending (S6) |
| `test_auth.py` new in S2a (accepted/refused spellings, non-ASCII → `AuthError`, colons and empty password, last duplicate wins) | fixture `auth.json`, unit `auth::tests::last_match_wins_and_trailing_bits_decode` | done (S2a) |
| `test_policy.py::test_normalize_domain_*` (new in S2a) and the path-domain parts of `test_policy.py` | fixture `domain.json` (1,003 inputs incl. each Latin-set character) via `domain::tests::domain_fixture` | done (S2a) |
| `test_policy.py` (the 13 original tests) | unit `policy::tests::python_policy_tests`; fixtures `domain.json`, `address.json`, `policy.json` via `policy::tests::policy_fixture` | done (S2c) |
| `test_policy.py` new in S2c (production shapes: cross-domain path vs from, address allowlist, IDN allowlist, ggs `webmaster@localhost`, `repr` quoting, lax Python forms) | fixture `policy.json` (1,430 cases), unit `policy::tests::forbidden_messages_are_python_reprs` | done (S2c) |
| `test_headers.py::test_parse_address_list_*`, `::test_header_address_list_*`, `::test_idn_domain_becomes_a_label`, `::test_ascii_address_is_unchanged` | unit `address::tests::python_header_tests` + fixture `address.json` via `address::tests::address_fixture` | done (S2b) |
| `test_headers.py` new in S2b (`test_mailbox_forms`, `test_refused_mailboxes`, `test_longest_address_is_accepted`, `test_header_address_list_refuses_empty_elements`) | fixture `address.json`, units `address::tests::display_names_follow_python`, `::exotic_forms_are_refused` | done (S2b) |
| `test_config.py::test_load_secrets_normalizes_idn_to_punycode`, `::test_token_policy_allowed_addresses_none_means_domain_only` | fixture `config_secrets.json` | done (S1c) |
| new: corpus decisions (≥ 400 addresses, ≥ 100 domains), "Rust accepts ⇒ Python accepts" | property checks in `address::tests::address_fixture` (stored Python results), `domain::tests::domain_fixture` (D-10 results never configurable), `auth::tests::auth_fixture` (equality); generator assertions and `tests/test_rust_fixtures.py::test_rust_address_decisions_never_widen_python` | done (S2a domains, auth; S2b addresses) |
| `test_config.py::test_envelope_sender_*` and the D-15 validity check | fixture `config_env.json` (senders Python accepts and Rust refuses marked `D-15`) | done (S2b) |

## Configuration and startup (S1: S1a, S1c, S1d)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_config.py::test_load_secrets_*` (minimal, IDN to punycode, empty tokens, changeme, bad sha, duplicate labels, missing domains, mode bits) | fixture `config_secrets.json` (130 documents) via `secrets::tests::config_secrets_fixture` | done (S1c) |
| `test_config.py::test_token_policy_allowed_addresses_none_means_domain_only` | fixture `config_secrets.json` (`addresses null`, `addresses empty`, absent) | done (S1c) |
| `test_config.py::test_settings_reads_env`, `::test_envelope_sender_*`, `test_nonblocking_submit.py::test_smtp_max_concurrency_must_be_positive` | fixture `config_env.json` (160 env sets) via `config::tests::config_env_fixture` | done (S1a) |
| `test_config.py::test_token_policy_repr_does_not_leak_sha` | unit `secrets::tests::debug_redacts_password_and_token_hash` | done (S1c) |
| `test_logging.py::test_each_record_is_flushed_to_stdout_immediately` | process test `binary.rs::serves_health_logs_startup_and_stops_on_sigterm` (reads the startup line from a pipe while the process runs) | done (S1d) |
| `test_logging.py::test_startup_line_records_effective_configuration`, `::test_startup_line_survives_a_raised_log_level`, `::test_startup_line_never_leaks_credentials` | same process test (fields, `impl`, sorted labels, level ERROR under `LOG_LEVEL=error`, no password or hash) and unit `log::tests` | done (S1d) |
| `test_health.py` (both) | unit `http::tests::health_and_fallbacks`, process test; harness `/health` cases | done (S1d); harness pending (S6) |
| new: 404/405/307, `HEAD /health`, 413 on `/health` and a 404 path, decoded-path routing | unit `http::tests` | done (S1d) |
| new: bind failure exit 1, SIGTERM exit 0 | process tests `binary.rs` | done (S1d) |
| new: `--version`, `--check-config` exit 0/1, unknown arguments exit 2 | process tests `binary.rs` | done (S1a, secrets S1c) |
| new: YAML 1.1 plain scalars, D-6 parser rules, D-5/D-10/D-17 config cases | unit `yaml::tests` + fixture `config_secrets.json` | done (S1c) |

## Request pipeline (S3)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_body_limit.py` (declared, streamed, within limit) | unit `pipeline::tests::body_reading` (declared length over the limit: the layer's 413 before auth and without a record; a chunked body counted while read: 413 with a record) and `http::tests::declared_length_over_the_limit_is_413_everywhere`; harness | done (S3d); harness pending (S6) |
| `test_body_limit.py::test_invalid_or_negative_content_length_rejected` | harness against real uvicorn (D-12) | pending (S6) |
| `test_body_limit.py::test_non_http_scope_passes_through` | n/a: ASGI lifespan scope has no Rust equivalent | n/a |
| `test_headers.py::test_validate_subject_*`, `::test_custom_headers_*` | unit `headers::tests::python_header_tests` + fixture `headers.json` (196 subjects, 100 header lists, 168 control-character probes; D-19 marked) via `headers::tests::headers_fixture` | done (S3a) |
| new: form parsing of both encodings (Starlette `FormParser`/`MultiPartParser` as the route calls them: content type, decoding, charsets, framing, part headers, limits, truncation at every byte) | fixture `form_decoding.json` (350 bodies, each also in four chunkings) via `form::tests::form_decoding_fixture`; units `form::tests` (production shapes, `unquote_plus`, content types, limits) | done (S3b) |
| `test_messages_endpoint.py::test_happy_path_returns_queued`, `::test_auth_*` | units `pipeline::tests::happy_path_in_both_encodings`, `::authentication_failures_are_401_with_realm` (response shape, realm, record) | done (S3c); harness pending (S6) |
| `test_messages_endpoint.py` 400 cases (`o:`, `v:`, `template`, `recipient-variables`, subject CRLF, `h:Bcc`, no recipients, no body, malformed from/to/Reply-To, injected CRLF) and the S0-py `text=""` cases (D-1) | unit `pipeline::tests::field_rules_are_400` (both encodings, plus `t:`, unknown fields, two `from`, EAI addresses, Reply-To case variants, D-19) | done (S3c); harness pending (S6) |
| `test_messages_endpoint.py` policy cases (path/from domain/from address, cross-domain, parent domain, foreign token) | unit `pipeline::tests::policy_decisions` (both encodings, 403 texts) | done (S3c); harness pending (S6) |
| `test_messages_endpoint.py` 413 cases (attachments too big/too many/flood, inline counting, huge text), malformed inline filename | units `pipeline::tests::limits_are_413` (also the aggregate of decoded texts, recipients and Starlette's field cap at N and N+1), `::inline_filenames` | done (S3d); harness pending (S6) |
| `test_messages_endpoint.py::test_smtp_*`, `::test_partial_refusal_*` (route side: status, records, `FAIL_ON_PARTIAL_REFUSAL`) | unit `pipeline::tests::submission_outcomes` with a recording submitter | done (S3c); SMTP side S5, harness S6 |
| `test_messages_endpoint.py::test_path_domain_logged_as_punycode`, `::test_log_redacts_token_and_smtp_password` | unit `pipeline::tests::records_follow_the_information_boundary` (captured log lines; also the 320-character `from` cap and the configured level) | done (S3d) |
| new: decision-order multi-fault cases (foreign path domain + `o:tag` → 400, oversized attachment before `o:tag` → 413 and after it → 400, bad auth + malformed multipart → 401, policy before subject/headers/recipients, recipient count before addresses, D-1 after the policy), both encodings | unit `pipeline::tests::decision_order` | done (S3d); harness pending (S6) |
| new: route matching (405 with `allow: POST`, 307, `%2F` and other paths 404, `$` before a final newline), production client shapes (Anymail urlencoded, the recorder's multipart in all 24 field orders), envelope order and de-duplication, a panic is a 500 with one record | units `pipeline::tests::route_matching`, `::production_shapes`, `::envelope_order_and_deduplication`, `::panics_are_500_with_a_record` | done (S3d) |

## Message construction (S4)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_mime_build.py` structure tests (text, html, alternative, Cc/Bcc, Reply-To, attachment, Message-Id, display name, inline related/mixed, amp, container downgrade, malformed inline names, empty bodies, CR/LF display names, IDN as A-labels, EAI in every field) | unit `mime::tests::python_mime_build_tests` (parses the produced message with `mail-parser`); fixture `mime.json` via `mime::tests::mime_fixture` and `fixtures/check_mime.py` (Python's parser on the Rust output); harness semantic comparison | done (S4a, S4b); harness pending (S6) |
| `test_mime_build.py` new in S4a (`test_non_ascii_message_id_header_is_rejected`, `test_ascii_message_id_headers_are_kept`), `test_messages_endpoint.py::test_non_ascii_references_is_400_before_smtp` | unit `mime::tests::exotic_headers` | done (S4a) |
| `test_mime_build.py::test_inline_explicit_content_id_is_not_double_bracketed` | n/a: form uploads never carry an explicit Content-ID | n/a |
| `test_messages_endpoint.py::test_bcc_only_envelope_not_in_headers`, `::test_cc_in_headers_and_envelope`, `::test_reply_to_*`, `::test_inline_upload_is_related_to_html_with_bracketed_content_id` | harness | pending (S6) |
| new: IDN/EAI recipients (D-2), non-ASCII subject/body/filenames, RFC conformance of the output, display-name quoting (S2 open point 4), D-21 | units `mime::tests::display_names_are_quoted_like_python`, `::exotic_headers`, `::long_values_stay_conformant`, `::long_encoded_words_and_upload_headers`, `::upload_content_types`, `::message_id_is_32_hex_digits_at_the_public_host`; fixture `mime.json` (124 cases, D-11/D-21 marked) with `check_mime.py`; harness | done (S4a, S4b); harness pending (S6) |
| new: fail closed, every input Python's `build_message` refuses the Rust port refuses; `check_mime.py` catches a bare LF, a long line and a changed header | `tests/test_rust_fixtures.py::test_rust_mime_decisions_never_widen_python`, `::test_check_mime_flags_broken_messages` | done (S4b) |

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
