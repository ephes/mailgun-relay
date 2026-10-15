# mailgun-relay (Rust port)

A re-implementation of the Python service in `../src/mailgun_relay` as one
small binary. [`PLAN.md`](PLAN.md) is the contract: what must match Python
exactly, what may differ (section 3), the slices and the switch of
production. [`TESTMAP.md`](TESTMAP.md) maps every Python test to its Rust
counterpart.

**Status: slice S1a of PLAN.md section 6** (S1 is split into S1a, S1c and
S1d by size). The binary loads and validates the `MAILGUN_RELAY_*`
environment. The secrets file (S1c), serving `/health` with the startup record
(S1d) and `POST /v3/{domain}/messages` (S2–S5) follow; nothing deploys this
code until the role is switched (PLAN.md section 9).

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
mailgun-relay --check-config   # load the environment, bind nothing; exit 0 or 1
mailgun-relay --version        # mailgun-relay 0.2.0 (<commit>)
```

Unknown arguments exit 2. The configuration interface is the Python one
(PLAN.md 2.7): `MAILGUN_RELAY_*` variables with the same names, defaults and
validation. The Rust port is stricter in a few exotic cases and fails at
start where Python would start (fail closed, PLAN.md section 3):

- a variable set under several case variants of its name, the exact
  upper-case name included (D-7);
- a non-ASCII `ENVELOPE_SENDER` whose domain is outside ASCII and the Latin
  letter blocks (D-10);
- an empty `BIND_HOST`, `SMTP_PORT` outside 0–65535, integers outside 64 bits,
  `SMTP_TIMEOUT_S` not finite or outside 0–1e9 s, `SMTP_MAX_CONCURRENCY`
  above 2^32−1, a value that is not UTF-8 (D-18).

Run `--check-config` against the production files before any switch.

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
src/main.rs     argv
src/config.rs   MAILGUN_RELAY_* settings
src/domain.rs   domain normalisation of the configuration
src/pystr.rs    Python str.strip() semantics
tests/binary.rs process-level tests of the built binary
fixtures/       generator + generated JSON
```
