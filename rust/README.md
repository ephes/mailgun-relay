# mailgun-relay (Rust port)

A re-implementation of the Python service in `../src/mailgun_relay` as one
small binary. [`PLAN.md`](PLAN.md) is the contract: what must match Python
exactly, what may differ (section 3), the slices and the switch of
production. [`TESTMAP.md`](TESTMAP.md) maps every Python test to its Rust
counterpart.

**Status: slices S1 to S7 of PLAN.md section 6 are done; the current
release is `rs-v0.2.1`**;
S3 adds subject and header validation, form parsing and
`POST /v3/{domain}/messages` with every decision of the Python route. The
binary loads and validates the configuration, answers `GET /health`, the
404/405/307 fallbacks and the 413 body-limit layer, and logs the startup
record and one record per message request. S4 builds the message
(`src/mime.rs`); S5a submits it over SMTP (`src/smtp.rs`, lettre's
connection API): STARTTLS with chain and hostname verification against the
system roots plus `SMTP_CA_FILE`, AUTH PLAIN or LOGIN, one `RCPT` per
recipient (a partly refused message is delivered to the others), and the
status mapping of PLAN.md 2.4, pinned by `fixtures/smtp_outcomes.json`
(Python's `submit` against the same scripted server). At most
`SMTP_MAX_CONCURRENCY` sessions run at once, further messages wait; a
submission whose client went away is finished, and SIGTERM waits for it.
S7 adds the release pipeline (see Release below). The parity harness (S6,
below) runs both implementations as processes against the same requests.
The role was switched to Rust 0.2.1 on macmini on 2026-10-17; the
2026-10-19 review after about 40 hours found stable operation, and one
controlled Homepage test verified the application transport path. Normal
DKIM verification of that same stored mail passed on 2026-10-19 at
11:28:49 UTC. Technical stability, transport and DKIM criteria are
fulfilled and were accepted by the owner on 2026-10-19; S10 is complete
(PLAN.md 10.6). The owner
replaced the original seven-day acceptance wait on 2026-10-18.

## Build and check

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on the
first `cargo` call. From this directory:

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo deny --locked check          # cargo-deny 0.20.2, policy in deny.toml
cargo build --release --locked     # target/release/mailgun-relay
```

CI runs the same steps in the `rust` job of `.github/workflows/ci.yml` (with a
pinned, sha256-checked cargo-deny) and reports the release binary size. The
build embeds the git commit (`MAILGUN_RELAY_GIT_COMMIT`, else
`git rev-parse HEAD`, else `unknown`).

## Release

`.github/workflows/rust-release.yml` (PLAN.md section 8) builds on
`ubuntu-22.04` (glibc 2.35) for `x86_64-unknown-linux-gnu` with the pinned
toolchain and no cargo cache, and runs `scripts/release_checks.py`:

- `version`: the tag must be `rs-v<crate version>` (semver without build
  metadata);
- `cargo fmt --check`, `clippy -D warnings`, `cargo test --locked`, then
  `cargo build --release --locked --target x86_64-unknown-linux-gnu` with
  `MAILGUN_RELAY_GIT_COMMIT` set to the full commit;
- `glibc-floor --max 2.35`: no glibc symbol version above 2.35, `NEEDED`
  only glibc and libgcc (macmini has 2.39);
- `smoke`: `--version` prints exactly `mailgun-relay <version> (<commit>)`,
  and `--check-config` with only a test environment (the variables of the
  role's env file) and a test secrets file (mode 0600) exits 0 with the
  expected summary;
- `pack`: `mailgun-relay-<version>-x86_64-unknown-linux-gnu.tar.gz` with
  exactly `mailgun-relay` (0755) and `LICENSE` (0644), root-owned, the commit
  time as mtime, gzip without a file name, so a rebuild of the same binary
  gives the same bytes; plus `<archive>.sha256`, checked with
  `sha256sum --check`.

A push of a tag `rs-v<semver>` then creates the GitHub release with both
files (`gh release create --verify-tag`; a version with a pre-release part
such as `0.3.0-rc.1` becomes a GitHub pre-release). The role downloads
`https://github.com/ephes/mailgun-relay/releases/download/rs-v<ver>/mailgun-relay-<ver>-x86_64-unknown-linux-gnu.tar.gz`
and pins its sha256 (PLAN.md 9.1). `workflow_dispatch` runs the same build
and checks and uploads archive and checksum as a workflow artifact only (no
tag check, no release):

```bash
gh workflow run rust-release.yml --ref main
gh run download <run-id> -n mailgun-relay-<ver>-x86_64-unknown-linux-gnu -D <dir>
```

To release: bump `version` in `Cargo.toml` (and `Cargo.lock`), add the
CHANGELOG entry, merge to `main`, then tag that commit:

```bash
git tag -a rs-v<ver> -m "mailgun-relay <ver> (Rust port)" <commit>
git push origin rs-v<ver>
```

The release checks are tested in the Python suite
(`tests/test_rust_release_checks.py`); locally, after a release build:

```bash
python3 -I scripts/release_checks.py smoke --binary target/release/mailgun-relay \
  --version "$(cargo metadata --format-version 1 --no-deps --locked | python3 -I scripts/release_checks.py version --metadata /dev/stdin)" \
  --commit "$(git rev-parse HEAD)"
```

## Run

```bash
mailgun-relay                  # serve (env and secrets as the Python service)
mailgun-relay --check-config   # load env + secrets, bind nothing; exit 0 or 1
mailgun-relay --version        # mailgun-relay 0.2.1 (<commit>)
```

Unknown arguments exit 2. The configuration interface is the Python one
(PLAN.md 2.7, 2.8): `MAILGUN_RELAY_*` variables with the same names, defaults
and validation, and the same secrets YAML (no world access, no group write or
execute: `0640`, `0600`, `0400` pass). The Rust port is stricter in a few
exotic cases and fails at start where Python would start (fail closed,
PLAN.md section 3):

- an unquoted all-digit or boolean `token_sha256` (D-5); merge keys, tags
  other than `!!str`, `%YAML`/`%TAG` directives, recursive aliases, nesting
  deeper than 64 levels, empty plain mapping keys, TAB characters and the
  YAML 1.1 line breaks NEL/LS/PS anywhere in the file (D-6);
- a variable set under several case variants of its name, also when one of
  them is the exact upper-case name (D-7);
- configured domains (secrets file, non-ASCII `ENVELOPE_SENDER`) outside
  ASCII and the Latin letter blocks, also after IDNA mapping (D-10);
- an `ENVELOPE_SENDER` that is not a valid bare address (D-15);
- a non-ASCII local part in `allowed_from_addresses` (D-17);
- an empty `BIND_HOST`, `SMTP_PORT` outside 0–65535, integers outside 64 bits,
  `SMTP_TIMEOUT_S` not finite or outside 0–1e9 s, `SMTP_MAX_CONCURRENCY`
  above 2^32−1, a value that is not UTF-8 (D-18);
- an `SMTP_CA_FILE` that is missing, unreadable, holds no PEM certificate
  or a certificate rustls cannot use, also with `SMTP_STARTTLS` off (D-22;
  Python reads the file per message and answers 503).

Run `--check-config` against the production files before any switch.

Logs are one JSON object per line on stdout. Every start writes
`{"ts":…,"level":"INFO","logger":"mailgun_relay.service","event":"startup",…}`
with the fields of the Python record plus `"impl":"rust"`; `ts` is UTC
(D-13). Each message request writes one `event=request` record; a partly
refused message adds a `recipients_refused` WARNING (domains and codes
only), a `QUIT` that is not answered with 221 an `smtp_cleanup_failed`
WARNING (the outcome stays). `/health` and the fallbacks log nothing.
SIGTERM and SIGINT stop the
server after in-flight requests (exit 0); a configuration or bind failure
exits 1.

## Fixtures

Python is the oracle for the contract and the policy decisions.
`fixtures/generate.py` calls the real Python code on a fixed corpus and writes
`fixtures/*.json`; the Rust tests load them with `include_str!`. After a
Python change, from the repository root:

```bash
uv run python rust/fixtures/generate.py           # rewrite the fixtures
uv run python rust/fixtures/generate.py --check   # exit 1 when stale
```

`tests/test_rust_fixtures.py` (Python suite) fails when a committed fixture
differs from a fresh render (`smtp_outcomes.json` runs Python's SMTP
client against a fake server and needs `openssl` for its throwaway CA).
The messages the Rust port builds are also read
with Python's parser (`mime.json`, PLAN.md 2.10):

```bash
dump=$(mktemp -d)
(cd rust && MIME_FIXTURE_DUMP="$dump" cargo test --locked mime_fixture)
uv run python rust/fixtures/check_mime.py "$dump"
```

## Parity harness

`parity/` (PLAN.md 7.4) starts the Python relay (`python -m mailgun_relay`,
real uvicorn) and the release binary as processes, each with its own fake
SMTP server (STARTTLS with a throwaway CA, AUTH, scripted replies), sends
every case of `parity/cases.py` to both byte for byte, and compares what the
parity contract fixes: status, contract headers and JSON, the SMTP
envelope, the message as Python's parser reads it, and the log records.
Expected differences name their entry of PLAN.md section 3; any other
difference fails. From the repository root:

```bash
(cd rust && cargo build --release --locked)
uv run python rust/parity/run_parity.py            # -v: every case; --filter TEXT
```

CI runs it in the `parity` job. The modules use the standard library only
and run with a host's `python3` (3.12+): `--targets PY_URL,RS_URL --sinks
PY_DIR,RS_DIR [--logs PY_LOG,RS_LOG]` runs the corpus against two running
instances whose SMTP goes to capture sinks (`parity/smtp_fake.py --listen
HOST:PORT --certs DIR --record-dir DIR`) and whose secrets come from
`run_parity.py --write-secrets PATH` (the shadow of PLAN.md 10.1).

## Layout

```
Cargo.toml  Cargo.lock  rust-toolchain.toml  deny.toml  build.rs
src/main.rs     argv, runtime, startup record, graceful shutdown
src/config.rs   MAILGUN_RELAY_* settings
src/secrets.rs  secrets file (mode check, schema)
src/yaml.rs     YAML 1.1 subset of PyYAML safe_load
src/address.rs  mailbox parsing and address validation
src/auth.rs     HTTP Basic authentication against the token hashes
src/policy.rs   the token/domain/sender policy
src/domain.rs   domain normalisation (path, address and configured domains)
src/http.rs     413 layer, /health, 404/405/307 fallbacks
src/log.rs      JSON line logger
src/pystr.rs    Python str.strip() semantics
src/headers.rs  subject and custom header validation
src/form.rs     urlencoded and multipart form parsing
src/pipeline.rs POST /v3/{domain}/messages: decision order, records
src/mime.rs     message construction (lettre)
src/smtp.rs     SMTP submission (lettre connection API)
tests/binary.rs process-level tests of the built binary
tests/support/fake_smtp.rs  scripted fake SMTP server (unit and process tests)
fixtures/       generator + generated JSON; check_mime.py (Python's parser on Rust messages)
scripts/release_checks.py  release gate of .github/workflows/rust-release.yml
parity/         process-level parity harness: run_parity.py, cases.py, smtp_fake.py, semantic.py
```
