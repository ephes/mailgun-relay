# mailgun-relay (Rust port)

A re-implementation of the Python service in `../src/mailgun_relay` as one
small binary. [`PLAN.md`](PLAN.md) is the contract: what must match Python
exactly, what may differ (section 3), the slices and the switch of
production. [`TESTMAP.md`](TESTMAP.md) maps every Python test to its Rust
counterpart.

**Status: slice S1 of PLAN.md section 6 is done** (merged as S1a, S1c and
S1d); S2 is in progress (S2a: authentication and path domains). The binary
loads and validates the configuration, answers `GET /health`, the
404/405/307 fallbacks and the 413 body-limit layer, and logs the startup
record. `POST /v3/{domain}/messages` does not exist yet (S3–S5); nothing
deploys this code until the role is switched (PLAN.md section 9).

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

CI runs the same steps in the `rust` job of `.github/workflows/ci.yml`. The
build embeds the git commit (`MAILGUN_RELAY_GIT_COMMIT`, else
`git rev-parse HEAD`, else `unknown`).

## Run

```bash
mailgun-relay                  # serve (env and secrets as the Python service)
mailgun-relay --check-config   # load env + secrets, bind nothing; exit 0 or 1
mailgun-relay --version        # mailgun-relay 0.2.0 (<commit>)
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
- a non-ASCII local part in `allowed_from_addresses` (D-17);
- an empty `BIND_HOST`, `SMTP_PORT` outside 0–65535, integers outside 64 bits,
  `SMTP_TIMEOUT_S` not finite or outside 0–1e9 s, `SMTP_MAX_CONCURRENCY`
  above 2^32−1, a value that is not UTF-8 (D-18).

Run `--check-config` against the production files before any switch.

Logs are one JSON object per line on stdout. Every start writes
`{"ts":…,"level":"INFO","logger":"mailgun_relay.service","event":"startup",…}`
with the fields of the Python record plus `"impl":"rust"`; `ts` is UTC
(D-13). `/health` and the fallbacks log nothing. SIGTERM and SIGINT stop the
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
differs from a fresh render.

## Layout

```
Cargo.toml  Cargo.lock  rust-toolchain.toml  deny.toml  build.rs
src/main.rs     argv, runtime, startup record, graceful shutdown
src/config.rs   MAILGUN_RELAY_* settings
src/secrets.rs  secrets file (mode check, schema)
src/yaml.rs     YAML 1.1 subset of PyYAML safe_load
src/auth.rs     HTTP Basic authentication against the token hashes
src/domain.rs   domain normalisation (path domains, configuration)
src/http.rs     413 layer, /health, 404/405/307 fallbacks
src/log.rs      JSON line logger
src/pystr.rs    Python str.strip() semantics
tests/binary.rs process-level tests of the built binary
fixtures/       generator + generated JSON
```
