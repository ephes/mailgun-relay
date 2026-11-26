# mailgun-relay (Rust port)

A re-implementation of the Python service in `../src/mailgun_relay` as one
small binary. [`PLAN.md`](PLAN.md) is the contract: what must match Python
exactly, what may differ (section 3), the slices and the switch of
production. [`TESTMAP.md`](TESTMAP.md) maps every Python test to its Rust
counterpart.

**Status: slices S1 to S7 of PLAN.md section 6 are done; the current
release is [`rs-v0.2.6`](https://github.com/ephes/mailgun-relay/releases/tag/rs-v0.2.6)**;
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
`SMTP_MAX_CONCURRENCY` requests are admitted at once, before body/MIME retention; excess requests
receive 503 immediately without attempting SMTP (retry with backoff). A
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

## TLS dependency security

The SMTP transport uses lettre's Rustls backend with native roots plus any
`SMTP_CA_FILE` certificates. It does not use `webpki-roots` or
`webpki-root-certs`. Its verifier must resolve to `rustls-webpki` 0.103.16 or
newer in the supported 0.103 line: [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html)
adds explicit rejection of compromised emSign intermediate public keys.
Affected older verifiers can accept such paths when the configured anchors
allow them. Updating the verifier complements system/custom CA remediation;
it is not evidence that the currently deployed relay accepts those paths.

The incident patch changes only this transitive package's lock version and
checksum. Release 0.2.2 was published on 2026-10-21 from
`9fd78bf88bbe488d3d27ef81030ee89364f58b6c`; selecting it through the controller
and verifying the running process are separate steps. Keep the previous Rust
release and Python fallback available through the existing rollout procedure.

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

CI bootstraps Rustup 1.29.2 using the SHA-pinned official updater over verified
OS trust before any SDK download in the Rust, parity and release jobs. The
bootstrap is restricted to disposable GitHub-hosted Linux x86_64 Ubuntu22.04/24.04
runners. Rust/parity CI pins Ubuntu24.04; release remains Ubuntu22.04. It uses
standard signed APT to upgrade only an older installed `ca-certificates` to the
exact [USN-8944-1](https://ubuntu.com/security/notices/USN-8944-1) fixed revision
(`20260816ubuntu0.22.04.1` / `20260816ubuntu0.24.04.1`). Current/newer packages
skip installation. Simulation permits only that exact CA upgrade/configuration;
the matching transaction refuses removals/new/unrelated packages, then verifies
installed state and non-target package parity. Existing sources/keys/proxies
remain; ambient `APT_CONFIG` is cleared and signature/TLS checks stay enabled.
Locks/network failures are bounded; no broad upgrade or custom root reconstruction.
Strict admission still refuses either incident root after the package refresh,
before curl/manager/SDK execution. Package/update/admission failures stop the job. It clears
ambient Rustup/compiler dispatch overrides and fixes the CA/TLS settings for
later Bash steps. It is not a local developer or production-host updater.
All three CI uv installations use 0.13.4. Supply-chain approval remains the
separate `cargo deny --locked check` CI gate; the release job does not replace it.

CI runs the same steps in the `rust` job of `.github/workflows/ci.yml` (with a
pinned, sha256-checked cargo-deny) and reports the release binary size. The
build embeds the git commit (`MAILGUN_RELAY_GIT_COMMIT`, else
`git rev-parse HEAD`, else `unknown`).

## Release

Releases are built and published locally by `scripts/local_release.py`,
driven by `local-release.json`; there is no release workflow and no CI run
(the tag-triggered `.github/workflows/rust-release.yml` was removed on
2026-11-18). The same program releases opsgate, graphyard's and nyxmon's Rust
binaries, and ops-deploy's `rust/scripts/release.py` follows the same
approach. Needs Docker with working `linux/amd64` containers (on an Apple
silicon Mac: colima with `vmType: vz` and `rosetta: true`; the build checks
that `docker run --platform linux/amd64 ubuntu:22.04 uname -m` prints
`x86_64`), `git`, `cargo` (for `cargo metadata`) and an authenticated `gh`
2.74.0 or newer (older versions report no asset digests; `publish` checks
this before it changes anything).

To release: bump `version` in `Cargo.toml` (and `Cargo.lock`), add the
CHANGELOG entry, merge to `main` and push, then from a clean checkout of that
commit:

```bash
python3 -I rust/scripts/local_release.py build     # builds, publishes nothing
python3 -I rust/scripts/local_release.py publish   # tag, GitHub release, verify
```

Remote facts (is the commit on `main`, does the tag exist) are read from
GitHub, and the tag is created there, through `gh api --hostname
github.com` on `ephes/mailgun-relay`: nothing is pushed with git, so no git
remote, URL rewrite or `GH_HOST` decides where the tag or the release goes
(`build` and `publish` also refuse a gh `api_host` override for github.com).
`main` means the branch `refs/heads/main`, resolved exactly.
`build` refuses a worktree with changes or untracked files, a commit that is
not on `main` on GitHub, a non-empty output directory and a version whose tag
`rs-v<version>` already exists (`--compare-released` builds such a version
as a dry run that `publish` refuses). Then:

1. Image phase, the only one with network: two `ubuntu:22.04` images (base
   pinned by the digest pulled at the start), one of the Docker engine's own
   platform and one `linux/amd64` (glibc 2.35, as the old runner). Each gets
   `binutils ca-certificates curl gcc git libc6-dev python3` (then
   `ca-certificates` must be at least the USN-8944-1 version
   `20260816ubuntu0.22.04.1` and the CA bundle must hold neither root of the
   2026-10-21 incident, as `scripts/ci_rustup.py` required of the hosted job;
   checked after the APT installation that brings the CA update, before the
   rustup, toolchain and dependency downloads),
   rustup 1.29.2 (sha256-checked; 1.29.2 fixes CVE-2026-111943), the source as `git archive` of the build commit (`rust/`
   and `LICENSE`), the pinned toolchain and `cargo fetch --locked`.
2. Checks job on the engine's own platform: `cargo fmt --check`,
   `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`
   (under Rosetta, emulation artefacts could fail tests that are about the
   code, not the target).
3. Release job on `linux/amd64`, running `scripts/release_checks.py`:
   - `version`: the tag `rs-v<version>` must equal the crate version (semver
     without build metadata);
   - `cargo build --release --locked --target x86_64-unknown-linux-gnu` with
     `MAILGUN_RELAY_GIT_COMMIT` set to the full commit;
   - `glibc-floor --max 2.35`: no glibc symbol version above 2.35, `NEEDED`
     only glibc and libgcc (macmini has 2.39);
   - `smoke`: `--version` prints exactly `mailgun-relay <version> (<commit>)`,
     and `--check-config` with only a test environment (the variables of the
     role's env file) and a test secrets file (mode 0600) exits 0 with the
     expected summary;
   - `pack`: `mailgun-relay-<version>-x86_64-unknown-linux-gnu.tar.gz` with
     exactly `mailgun-relay` (0755) and `LICENSE` (0644), root-owned, the
     commit time as mtime, gzip without a file name, so a rebuild of the same
     binary gives the same bytes; plus `<archive>.sha256`, checked with
     `sha256sum --check`.

   Both jobs run with `--network none`, no mounts, and memory, process and
   time limits.
4. The archive, its `.sha256`, `build.json` (commit, sha256, images, package
   and toolchain versions) and `notes.md` land in
   `rust/target/local-release/mailgun-relay-<version>/`, staged privately and
   moved there in one rename, so a concurrent build never mixes into it.

`publish` takes that directory. It checks that `gh` is 2.74.0 or newer,
copies the archive, checksum and notes into a private temporary directory,
and validates the copied archive and checksum against `build.json`. It uses
those copies for upload and verification, so replacing files in the build
directory after staging cannot change what is published. It then creates the
annotated tag `rs-v<version>`
on the build commit through the GitHub API (only when that commit is on
`main`; an existing tag must be annotated and point at that commit, it is
never moved), creates the GitHub release with exactly the archive and its
`.sha256` (`gh release create --verify-tag`; a version with a pre-release
part such as `0.3.0-rc.1` becomes a GitHub pre-release), then downloads both
again and compares them byte for byte. It succeeds only when afterwards the
same release (same release and asset ids) is published, with the expected
prerelease flag, exactly those two assets and GitHub's sha256 of each equal
to the built one. Every release read requires unique asset names and IDs.
After verifying the assets, it rereads the exact annotated
tag and requires it to still point at the build commit. A changed or missing
tag fails verification and leaves the remote objects in place; the steps
this run took (tag, release, uploads) are logged before that check, so the
operator knows what to settle by hand. A draft
(left by an interrupted `gh release create`) is
refused: check it, delete the draft by hand (the tag stays) and run `publish`
again. It never replaces an asset and can be rerun until that end state is
reached. Fetch the tag afterwards with `git fetch --tags`. The role downloads
`https://github.com/ephes/mailgun-relay/releases/download/rs-v<ver>/mailgun-relay-<ver>-x86_64-unknown-linux-gnu.tar.gz`
and pins its sha256 (PLAN.md 9.1); ops-control pins version and sha256
(`mailgun_relay_rust_version`, `mailgun_relay_rust_sha256`).

If tag creation reports an error, publication proceeds only when a fresh
read of that exact annotated tag confirms the build commit. Otherwise it
reports the original creation error.

The local release helpers run on POSIX. Each version/config/objdump command has
one 10-second deadline covering process exit and both output pipes, with a
combined 1 MiB output ceiling. Launch failure, cancellation, timeout or overflow
fails the check; overflow prints a fixed diagnostic. Cleanup kills the owned
process group, including pipe-holding descendants, then attempts to reap the
helper and close each pipe. Cleanup failures report the failed operations
alongside any original command failure.

`pack` accepts ASCII semver without build metadata and the supported
`x86_64-unknown-linux-gnu` target, before reading inputs or creating output.
It locks the output directory, stages and verifies both files, syncs them and
publishes the pair with rollback on handled failures. A durable
`.mailgun-relay-<version>-<target>.tar.gz.incomplete` marker identifies an
interrupted publication. Do not consume a marked pair, even if one file looks
complete: rerun the same `pack` command successfully to repair and clear it.
If a rollback fails, `pack` still attempts to restore both files and reports
the original publication failure and the private `.pack-*` directory holding
any remaining backups. Keep that directory until recovery is complete. A retry
uses a new staging directory and leaves the saved backups available.
Two file names cannot be atomically replaced together; the marker is the
interruption boundary. The helper does not publish a release or a tag.

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
mailgun-relay --version        # mailgun-relay <version> (<commit>)
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

In Rust, `SMTP_TIMEOUT_S` and `SMTP_SESSION_TIMEOUT_S` allow underscores only
between ASCII digits. For example, `1_000.5` is valid, while `1_.5` and
`1e_2` fail configuration validation before listener startup.

Run `--check-config` against the production files before any switch.

Logs are one JSON object per line on stdout. Every start writes
`{"ts":…,"level":"INFO","logger":"mailgun_relay.service","event":"startup",…}`
with the fields of the Python record plus `"impl":"rust"`; `ts` is UTC
(D-13). Each message request writes one `event=request` record, at ERROR for
HTTP 5xx (including internal failures) and INFO otherwise. LOG_LEVEL=WARNING
keeps these failures visible while suppressing normal traffic; a partly
refused message adds a `recipients_refused` WARNING (domains and codes
only), a `QUIT` that is not answered with 221 an `smtp_cleanup_failed`
WARNING (the outcome stays). `/health` and the fallbacks log nothing.
On shutdown, Rust reports nonzero log losses in one best-effort stderr summary
with counts for encoding failures (including oversized records), full queues,
unavailable queues and stdout write or flush failures. Filtered records are
excluded. If the drain deadline expires, the summary includes
`log drain unconfirmed (deadline expired)`. If the writer panics, it wakes
shutdown callers and the summary includes
`log drain unconfirmed (writer exited unexpectedly)`. Both diagnostics can
appear with zero observed losses. Delivery of pending records is unknown.
Shutdown waits at most 100 ms total for the summary and any final service
error on stderr.
On SIGTERM or SIGINT, the relay stops all listeners and waits for in-flight
requests, including submissions whose clients disconnected. The relay then
closes log admission before waiting up to one second for accepted records to
drain. Shutdown callers wait independently and share the writer's drain
result. A listener that exits early triggers the same drain. The relay
attempts to report the initiating listener failure after the drain and exits 1
even if stderr stalls.
Configuration and bind failures also exit 1. If the named log writer thread
cannot start, the relay reports `cannot start the log writer` on stderr and
exits 1 before creating any listeners.
A signal-triggered shutdown exits 0 even if the log drain is unconfirmed.

Both secrets loaders refuse a label equal to the SMTP password or any loaded
token digest, regardless of policy order; digest comparison trims whitespace
and ignores case. Errors name only the token position, before startup/access
or Debug output can expose the label. Ordinary labels and YAML aliases work.
This equality guard does not detect embedded secrets: keep labels nonsecret.

## Fixtures

CPython **3.14.10** is the canonical oracle for committed fixtures and policy
decisions. `fixtures/generate.py` calls the real Python code on a fixed synthetic
corpus and writes `fixtures/*.json`; the Rust tests load them with `include_str!`.
Writes from other interpreter versions fail before changing any files. After a
Python change, from the repository root:

```bash
uv run --frozen --python 3.14.10 python rust/fixtures/generate.py
uv run --frozen --python 3.14.10 python rust/fixtures/generate.py --check
uv run --frozen --python 3.15.2 python rust/fixtures/generate.py --check
```

`tests/test_rust_fixtures.py` (Python suite) fails when a committed fixture
differs from a fresh native render (`smtp_outcomes.json` runs Python's SMTP
client against a fake server and needs `openssl` for its throwaway CA).
CI runs the frozen audit, lint, types and full Python suite on 3.14.10 and 3.15.2.
The suite narrowly filters aiosmtpd 1.4.6's `ByteString` import deprecation on
3.15; the existing warnings-as-errors policy otherwise stays in place.
Consumer checks compare every field, projecting only a recorded `python_versions`
observation for the running minor version; Rust `expected` decisions stay fixed.
Unknown parser/serializer changes fail the guard instead of being normalized away.

Python 3.14.10 fixes the encoded-comma display name observation: `Doe, Jane`
remains one display name for `b@x.de`, with no parser defects. Rust continues
to refuse this exotic encoded ASCII special under D-21. For `encoded local part`,
3.14.10 serializes a defective message, while 3.15.2 raises `HeaderWriteError`
before DATA. The corpus records the latter as 502 (the permanent submission
failure classification), separately from a build-time 400. This is a fixture
observation, not a live-service finding or a runtime policy change. Ordinary
Unicode display names still serialize successfully on both interpreters.

The 3.15 consumer contract records `long header name` becoming body text with
`MissingHeaderBodySeparatorDefect` (Rust still refuses the field). The former
oversized Content-Type parser divergence is removed: both runtimes now fall back
to `application/octet-stream` for malformed or overlong leaf tokens. Native
observations remain checked explicitly; unknown drift still fails the guard.

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
The parser defect check inspects each header occurrence on each MIME part.
It reports duplicates of singleton fields by case-insensitive name and allows
repeatable fields such as Received.
The MIME tree compares Content-ID, disposition and parsed filenames on
containers and leaf parts. A `Content-Type` `name` parameter supplies a
filename even when the part has no `Content-Disposition` header.
If the captured MIME cannot be decoded, the case fails with the parser
exception class. The report still includes its observed HTTP statuses and
capture counts, and the harness runs the remaining cases.
Expected differences name their entry of PLAN.md section 3; any other
difference fails. A difference that keeps the status (D-23:
`smtp_outcome_unknown` and its JSON message after a transfer fault at the end
of DATA) pins both the Python and the Rust value and compares the rest of the
case in full. From the repository root:

```bash
(cd rust && cargo build --release --locked)
uv run python rust/parity/run_parity.py            # -v: every case; --filter TEXT
```

Before probing a locally chosen loopback port, the harness waits for post-bind
confirmation for that address from the spawned child's own output. Python uses
Uvicorn's INFO listening line on stderr, while Rust uses the structured startup
record on stdout. Local command overrides must preserve those signals. Startup
retries at most five port selections if another process takes the port.

Each HTTP exchange has a 60-second monotonic deadline covering connection,
split request writes and all response reads. Responses are limited to 64 KiB
of headers (before the separator) and 1 MiB of wire body, including chunk
framing. The harness decodes chunks in one pass and keeps the payload when
chunk extensions or trailers are present. Comparison requires a complete
final response with valid body framing. Close-delimited replies require a clean
EOF. A complete length-delimited, chunked or bodyless reply can still be observed
if the peer resets the connection after sending it. Timeouts, limit violations
and incomplete responses are harness failures. In a startup probe such a failure
unwinds the relay and sink and aborts the run without a `--report` receipt.
The harness owns relay children and SMTP sinks immediately and unwinds them
in reverse acquisition order on partial startup, probe errors or interruption.

CI runs it in the `parity` job. The modules use the standard library only
and run with a host's `python3` (3.12+): `--targets PY_URL,RS_URL --sinks
PY_DIR,RS_DIR [--logs PY_LOG,RS_LOG]` runs the corpus against two running
instances whose SMTP goes to capture sinks (`parity/smtp_fake.py --listen
HOST:PORT --certs DIR --record-dir DIR`) and whose secrets come from
`run_parity.py --write-secrets PATH` (the shadow of PLAN.md 10.1).
When `--logs` is supplied, the harness opens both files and starts following
from their initial end offsets before sending requests. An open or seek failure
stops setup with the target and log path in the diagnostic. The harness
discards records through each consumed marker and keeps later records for the
next case. Startup failures show the three most recent raw log lines.

Verification requires at least one runnable request case. A misspelled filter,
a startup-only filter, or a `--targets` subset consisting entirely of unsupported
cases exits nonzero before starting relays or reading capture files. The explicit
`--write-secrets` utility remains exempt. Reports distinguish
`selected_request_cases` (before target-mode exclusions) from `request_cases`
(requests attempted), and list skipped cases separately.

`--report FILE` serializes a complete success or failure receipt first, writes a
sibling temporary file, flushes and fsyncs it, then atomically replaces FILE
and fsyncs the parent directory. The replacement keeps the previous report's
permission bits, or the umask-derived mode for a new report.
Failures before replacement return nonzero with a publication error, preserve
the previous report and remove the temporary file during ordinary unwinding.
A directory sync failure after replacement also returns nonzero and reports
that the receipt was published with uncertain durability. The complete new
receipt stays visible. Abrupt process termination can leave a sibling temporary
file but cannot publish partial JSON to FILE.

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
scripts/release_checks.py  release gate run by scripts/local_release.py
scripts/local_release.py   local release build and publication (config: local-release.json)
parity/         process-level parity harness: run_parity.py, cases.py, smtp_fake.py, semantic.py
```

## Published security patch 0.2.2

Rust 0.2.2 retains the released 0.2.1 application source plus the reviewed
certificate-verifier fix, secure hosted bootstrap and maintained documentation.
The local package version and two version assertions also change.
[Exact-source CI](https://github.com/ephes/mailgun-relay/actions/runs/39641003007),
including cargo-deny/parity, and the [tag release build](https://github.com/ephes/mailgun-relay/actions/runs/39642666568)
passed. The Linux binary embeds `9fd78bf88bbe488d3d27ef81030ee89364f58b6c`;
the published archive `mailgun-relay-0.2.2-x86_64-unknown-linux-gnu.tar.gz`
and its `.sha256` carry archive SHA256
`6da71db3eb4f70c9a9d178e41220fd6afd36223531b4c25683a542dfc6e3bc7a`.
Python source/version, SMTP/API semantics and database/configuration remain
unchanged. Publication is not evidence of running-process protection.

## Rust acquisition deadlines

After authentication and admission, Rust returns HTTP 413 for a supported form
whose body size hint has a lower bound above `MAX_BODY_BYTES`, before polling
the body. Rust also checks each incoming data frame against the remaining
allowance before copying it into the body buffer. The byte limit is inclusive.

Rust bounds form-body acquisition to 30 seconds total after admission, including
stalled and trickling uploads and streams that are continuously ready. Empty
data frames and trailers count toward cooperative scheduling. A full 25 MiB
upload needs roughly 7 Mbit/s sustained throughput. Expiry returns HTTP 408
(`BodyTimeoutError`), drops the body and releases admission before MIME or SMTP. Overload still returns 503
before reading the body. Python rollback has no application body deadline.
Rust also uses one `MAILGUN_RELAY_SMTP_TIMEOUT_S` budget for DNS resolution and
all TCP connection attempts together. It tries each distinct socket address in
first resolver order and divides the remaining time equally among untried
addresses, so a stalled address permits fallback. Expiry returns retryable
HTTP 503. Each later SMTP socket operation has its own timeout. In addition,
`MAILGUN_RELAY_SMTP_SESSION_TIMEOUT_S` (default 120 seconds, finite and
`0 < value <= 1e9`) bounds DNS, connect, banner, EHLO, STARTTLS, AUTH and DATA
through the delivery outcome together. Expiry closes the connection, returns
HTTP 503, and releases admission. A transport failure or timeout before DATA
354 is a temporary failure (`smtp_temporary`). After DATA 354, loss of the
connection or expiry without a complete final reply leaves the outcome unknown
(`smtp_outcome_unknown`). So does any other failure without a parsable final
reply code after DATA 354, such as an unparsable reply or exhausting the
inbound wire-byte cap. A final reply with a code retains its normal status.
Verify upstream delivery before retrying an unknown outcome to avoid duplicate
mail. The relay never retries automatically.

During initial SMTP setup, the relay uses banner failure handling until the
current connection's transport accepts at least one outbound byte. Pending,
failed and zero-byte writes leave the classification at the banner stage.

QUIT has a separate total budget of `min(SMTP_TIMEOUT_S, 5 seconds)` and never
changes an already determined outcome, including accepted DATA. Rust also caps
inbound wire bytes at 16 MiB per connection, counted before TLS decryption and
including the handshake, TLS overhead, replies and cleanup. This conservative
ceiling bounds lettre's allocation even for a reply without a newline; it can
refuse unusually verbose sessions (including those with raised recipient limits).
Exhaustion follows the same phase-dependent transport classification (503
before the outcome, cleanup warning only after acceptance), without logging
reply contents. OS socket
buffers and TLS's bounded internal buffers are separate from this wire-read cap.
Python rollback now also validates and applies `SMTP_SESSION_TIMEOUT_S` (the
same default and bounds) through the SMTP outcome, including TCP attempts,
trickling replies, STARTTLS and recipient/DATA operations. A session-owned socket
shutdown interrupts blocking reads and TLS; QUIT has its own
`min(SMTP_TIMEOUT_S, 5 seconds)` total budget. Confirmed DATA acceptance survives
a later deadline check or cleanup failure once the complete final 250 reply
has been read. A timeout or truncated reply without a complete final DATA
result returns HTTP 503 and can leave delivery uncertain. Neither runtime
automatically retries it.
Python's blocking libc DNS calls (remote resolution and local EHLO hostname
lookup) cannot be interrupted by socket shutdown. Their elapsed time consumes
the budget and late results are refused before further SMTP work; admission stays
owned until resolution actually returns. Python has no Rust wire-byte ceiling.
These source changes require an explicit runtime update; no deployment is performed.

Tokio's system resolver may keep a blocking `getaddrinfo` call alive after its
waiting future expires. The deadline releases request admission but cannot
cancel that OS call; repeated resolver stalls can pressure the blocking pool.

## Secret file identity and bounds

Both runtimes open secrets once with nonblocking and no-follow flags, validate
that descriptor is a regular file with mode 0640 or stricter, and read at most
1 MiB (1,048,576 bytes). Oversize/invalid UTF-8 documents fail startup with
value-free errors. A final-component symlink is refused; operator-controlled
parent directories may contain symlinks. Path replacement after open cannot
substitute unchecked file bytes. This interface targets the supported POSIX
relay environments; it performs no real secret or host access in tests.

Each token digest must be unique after trimming and lowercase normalization,
even across labels with different scopes. Use one credential per policy identity;
rotation must use a new digest. Duplicate digests fail startup with positional, value-free diagnostics;
this check never prints a digest. This intentionally rejects
previously ambiguous configurations. Adoption requires a runtime update/restart;
these source changes do not deploy anything.

## Fail-closed secret schema and diagnostics

Startup accepts only these string keys: root `smtp`, `tokens`; SMTP `username`,
`password`; each token `label`, `token_sha256`, `mailgun_domains`,
`allowed_from_domains`, `allowed_from_addresses`. Unknown or non-string keys
fail startup with positional, value-free diagnostics. Optional sender addresses
may still be omitted, null or empty (domain-only authority); a misspelling now
fails instead of silently broadening that authority.

Both YAML loaders refuse duplicate mapping keys before schema lookup, including
root sections, SMTP passwords and policy restrictions. Anchors and ordinary
aliases remain supported. Python also refuses conflicting keys introduced by
YAML merges; Rust retains its existing merge-key refusal (PLAN D-6). Previously
ignored fields and ambiguous duplicate-key documents must be corrected before
updating/restarting either runtime.

Python parser and schema errors now use fixed messages or trusted field/index
positions, suppressing parser snippets and chained value-bearing exceptions.
Aliases cannot turn a password/hash into an error field name. Exceptions and
ordinary startup stdout/stderr are tested with invented secret markers; Rust
retains the same value-free diagnostic boundary. Adoption needs a runtime
update/restart; no deployment is part of this change.


## Bounded custom CA loading and HTTP framing

Rust opens `SMTP_CA_FILE` once with nonblocking I/O, requires that descriptor to
be a regular file, and reads at most 1 MiB (1,048,576 bytes), including growth
after inspection. It checks the opened descriptor's modification time and
length before and after the read and verifies the final length against the byte
count. Startup and `--check-config` refuse bundles with detected changes before
PEM parsing, and refuse nonregular or oversized bundles before binding or SMTP
AUTH. Publish updates by atomically replacing the path or symlink so a reader
can finish using the bundle it already opened. System roots, multi-certificate PEM bundles, chain and
hostname verification retain their existing behavior (D-22).

The binary loopback tests send raw conflicting Content-Length headers,
Content-Length plus malformed chunked framing, invalid chunk sizes and truncated
fixed/chunked bodies, including a trailing authenticated request. Transport
rejection (400 or connection close) or the application's controlled 400 body
error must cause no SMTP submission. A valid chunked send is the positive
control. Tests use synthetic credentials, certificates and message bodies.


The body lifecycle binary regressions use `Expect: 100-continue` to acknowledge
that admission is held and the body reader has started. A partial disconnect
must release the only slot, log one controlled body error, permit the next send
exactly once, and drain tracked tasks on shutdown. A stalled upload followed by
SIGTERM must finish at the existing 30-second body deadline (with a bounded
cleanup allowance), return/log 408 `BodyTimeoutError`, open no SMTP connection
and release the listener. These tests do not shorten the production deadline;
the shutdown test takes about 30 seconds.


The accepted-DATA shutdown regression waits until the SMTP peer receives QUIT
(proving the relay consumed DATA's 250), then sends SIGTERM while QUIT is still
pending. A cleanup timeout must preserve HTTP 200, the same message ID and one
success receipt, with exactly one SMTP transaction. The peer uses a synthetic
CA and withholds its QUIT reply.

Multi-listener startup is tested at the production `bind_addresses` seam using
explicit IPv4 loopback addresses, independent of DNS ordering and IPv6 support.
A later address-in-use error must release earlier listeners immediately; after
removing the conflict, both addresses must bind successfully. The binary bind
failure test separately pins exit 1, no startup-success record and safe output.
Startup requires at least one resolved listener address and logs success only
after binding every distinct address. Startup deduplicates resolver results in
one pass and binds each unique socket address in first-seen order. Synthetic
resolver results cover duplicates, order and refusal of an empty address list
before startup logging.

## Local SMTP fixture ownership and recovery

The scripted SMTP peer is local test/capture tooling. A recording sink takes a
kernel-held exclusive directory lock before opening its listener. A second
sink fails before accepting mail; shutdown or failed startup releases ownership.
Capture history is never overwritten. Each finished record is written to an
exclusive `.pending` file, flushed and synced, then linked to its exclusive
`<n>.json` name and the directory synced before removing `<n>.active`.
A failed publication preserves (or recreates) the active/pending evidence and
makes `stop` or `close` fail; subsequent sessions are refused until restart.
On restart, `sink.incomplete` lists unfinished attempts and the CLI prints their
count; numbering advances beyond them. Inspect these attempts
separately; only final JSON records are input to capture comparison. The
`--targets` parity harness waits up to 5 seconds at startup for `.active`
markers to clear and then ignores the remaining ones as retained attempts, so
they do not stall each case. After this wait the harness records existing JSON
filenames without reading their contents. Only captures first seen during the
new run are decoded. If a new active capture remains after a case's five-second
settle period, the harness reports a capture error for that case and skips the
remaining cases for the pair. Earlier case results remain in the report.

Each session admits at most 64 MiB of aggregate input (including AUTH/DATA),
4,096 commands and one retained message. The sink admits at most 16 simultaneous
sessions and retains at most 256 session records until `take()` drains them;
a recording sink drops finished records from memory. A session exceeding its
own byte or command budget receives SMTP 421 and a `limited` record, never a
truncated successful message. Connections refused for sink-wide concurrency or
retention, or after a failed publication, receive 421 without a session record.
These are fixture budgets, independent of relay production limits. `close()` is
idempotent: it closes all listeners, cancels live sessions, waits for capture
finalization and transport closure, then stops and joins the event-loop thread.
The standalone CLI follows this path on Ctrl-C and startup failure; on Ctrl-C a
capture publication failure is printed and the CLI exits nonzero.

Fixture PKI reuse validates every expected certificate and matching private key,
the intended hostname/CA relationships, and OpenSSL validity with at least one
hour remaining for the CA and all leaves. The deliberately wrong-host and
self-signed leaves remain negative TLS cases. Replacement material is generated
and checked in a private staging directory before publication under a parent
directory lock. Handled generation/publication failure preserves the preceding
material. A failed first publication retires the unconfirmed generation.
Reuse confirms the parent directory sync before returning fixture paths.
A `.NAME.previous` directory is the recovery generation if interruption
occurs between renames; the next preparation restores it when NAME is absent.
A successful replacement refreshes the complete two-day fixture generation;
it never changes relay TLS verification or the host trust store.

## Published release 0.2.6

Rust 0.2.6 carries the Rust fixes merged since 0.2.5 (CHANGELOG `rs-v0.2.6`):
`smtp_outcome_unknown` after DATA 354, the form-body deadline for ready frames,
size-hint and header-name admission, repeated header names, AMP order and
limit, log loss accounting and drain reporting. Built with the same hardened
builder images as 0.2.5 (rustc 1.99.0). The tag `rs-v0.2.6` (annotated,
created through the GitHub API) points at
`750a3dadccada6f277a9a63532e8c944f66ad65d`, which the binary embeds; the
archive `mailgun-relay-0.2.6-x86_64-unknown-linux-gnu.tar.gz` has SHA256
`db07ba20b2aac7febb49ec944a6c5e572246983763146e3f05c7e40abd78255d`, checked
after the upload by download and byte comparison, and again through the public
download URL. Publication is not evidence of running-process protection.

## Published release 0.2.5

Rust 0.2.5 carries the Rust fixes merged since 0.2.4 (CHANGELOG `rs-v0.2.5`)
and `url` 2.5.9 for RUSTSEC-2026-0592. It is the first release built with the
hardened builder images (rustup 1.29.2, `ca-certificates`
20260816ubuntu0.22.04.2, CA bundle check; rustc 1.99.0). The tag `rs-v0.2.5`
(annotated, created through the GitHub API) points at
`d1a5b2b5f8402f6207d9bb908306b8a674b48f82`, which the binary embeds; the
archive `mailgun-relay-0.2.5-x86_64-unknown-linux-gnu.tar.gz` has SHA256
`424033a94aef543cae62a9f2d64c3e75b5cacc468ca35a8671d58dafb89a9908`, checked
after the upload by download and byte comparison, and again through the public
download URL. Publication is not evidence of running-process protection.

## Published release 0.2.4

Rust 0.2.4 is the first release built and published locally by
`scripts/local_release.py` (see "Release"): lettre 0.11.24 for
RUSTSEC-2026-0560 to 0565 with the message's final CRLF handed to lettre,
and the Rust fixes merged since 0.2.3 (CHANGELOG `rs-v0.2.4`). The tag
`rs-v0.2.4` (annotated, created through the GitHub API) points at
`d394fe95d275b0d7fd2ca13b28d1c6d94482eae5`, which the binary embeds; the
archive `mailgun-relay-0.2.4-x86_64-unknown-linux-gnu.tar.gz` has SHA256
`abbb1ffaf73c06dbd06210e3d599e0f34d4e06aa8a9c70c95bcc44edd82f7d09`, checked
after the upload by download and byte comparison, and again through the public
download URL. Its builder images still used rustup 1.29.1 without the CA
bundle check that the program has since (rustup 1.29.2, CVE-2026-111943);
the toolchain was downloaded on a trusted home network. Publication is not
evidence of running-process protection.

## Published release 0.2.3

Rust 0.2.3 carries the Rust fixes and regression tests merged after 0.2.2
(see the `rs-v0.2.3` CHANGELOG section): bounded SMTP session time and
inbound wire bytes, bounded CA and secret reads, stricter secret validation,
admission before body parsing, and rustix 1.1.6 for RUSTSEC-2026-0486. Only
the crate version and two version assertions changed for the release.
[Exact-source CI](https://github.com/ephes/mailgun-relay/actions/runs/43430238377),
including cargo-deny/parity, the
[artifact-only build](https://github.com/ephes/mailgun-relay/actions/runs/43430290988)
and the [tag release build](https://github.com/ephes/mailgun-relay/actions/runs/43430804815)
passed. The Linux binary embeds `d2a4ddbccc549feeaaa0ae90dab111ee0d8e7870`; the published archive
`mailgun-relay-0.2.3-x86_64-unknown-linux-gnu.tar.gz` and its `.sha256` carry
archive SHA256 `a7a942e5d3f23e49515ae4f3da3bae98a03a55fc1c06848298a0de731da607cf`; the artifact-only and tag builds produced identical
bytes. Publication is not evidence of running-process protection.

Policy list expansion is bounded cumulatively across all tokens and all three
scope lists: at most 16,384 entries and 1,048,576 UTF-8 bytes. Each occurrence
counts, including duplicates and each alias use, before normalization/storage;
bytes charge the larger of the input and normalized spelling. Limits fail with
only the field/index position. Ordinary shared lists remain supported. Python
also checks public YAML events before construction, allowing at most 64 nested
collections (matching Rust), refusing aliases to unfinished collections, and
normalizing residual recursion/memory parse failures to value-free
`InvalidPolicyError`. These bounds apply to startup, not a deployed runtime
until it is updated and restarted.

Rust buffers form bodies under the existing admission limit, then moves form
parsing and MIME construction onto the bounded Tokio blocking pool (two worker
threads). The owned admission permit travels into each blocking job and returns
with its result. Cancellation cannot free a slot while that job is still running;
tracked requests still drain before shutdown. Authentication, content-type/body
limits and validation order are unchanged.

Rust stdout logging uses a dedicated OS writer thread and the standard library's
bounded `sync_channel` with nonblocking `try_send`: 256 queued records, each at
most 65,536 serialized bytes (at most 16 MiB queued payload, plus one writing
record and queue metadata).
The newest record is dropped on saturation; oversized records and write/flush
errors are also dropped. There is no recursive fallback or send retry. The
writer flushes each successfully written record. After a write error it
restores a newline boundary before the next record. A failed separator write
drops that record and counts as a sink failure. After requests drain, shutdown stops log
admission and waits at most one second for queued records; a stalled sink may
lose the tail when the process exits. Health, SMTP outcomes and capacity release
do not depend on stdout progress. Startup logging is best effort too, so a
missing startup record alone does not prove startup failed. Python's retained
logging path keeps its documented exception-isolation behavior.

STARTTLS authentication uses only the latest encrypted EHLO capabilities; a
pre-TLS AUTH offer never authorizes sending credentials after upgrade. Each
submission opens a fresh session. Synthetic TLS tests vary AUTH by phase and
session (PLAIN → LOGIN, then no AUTH, then PLAIN) and prove removed mechanisms
cannot leak into authentication or message submission.

After DATA 354, a disconnect or timeout without a complete final reply returns
HTTP 503 and logs `smtp_outcome_unknown`. The peer may already have stored
the message. Verify delivery before retrying. The relay performs no automatic
retry or replay on restart. A consumed final 250 remains successful if QUIT
fails. A full-binary loopback test records one DATA per explicit HTTP request,
reuses admission after a lost reply, and observes an idle restart without replay.

## Form and upload parity

Both implementations reject duplicate inline Content-IDs with HTTP 400 before
SMTP. IDs are compared exactly after the Python helper's optional explicit-ID
bracket normalization; HTTP inline IDs come from filenames. Ordinary attachments
may share filenames. Upload filenames and raw content types (including parameters,
after empty-value defaults) must each fit `MAX_HEADER_VALUE_LENGTH` Unicode code
points, inclusive; oversize metadata returns a fixed, value-free 400 before MIME
assembly. Unicode filenames within the limit remain supported. Rust checks
attachment size first and examines at most the character limit plus one
Unicode code point per metadata field.

`from` must occur exactly once. `subject`, `text`, `html` and `amp-html` may each
occur at most once, even for identical or empty values. Every `h:*` name is unique
case-insensitively, including extension headers such as `X-Tag`; duplicates return
400 at form admission. Repeated `to`, `cc`, `bcc`, `attachment` and `inline` fields
remain supported subject to existing limits and inline-ID uniqueness.

Uploaded leaf media types in both runtimes use two ASCII RFC 7230 tokens of
1–127 characters each. Parameters are stripped; malformed types and container
`multipart/*` or `message/*` types become `application/octet-stream`, preserving
the filename and bytes. The raw metadata length limit applies before stripping.

The shared `mime.json` corpus includes duplicate-ID refusal, distinct inline IDs,
same-name ordinary attachments, malformed inline types and attachment types.
Process parity covers raw repeated form fields in both encodings, including
denied header names. A single denied header records `DangerousHeaderError`.
Repeated case variants record `BadRequestError` during form admission, also
for non-ASCII and over-long names and before a sender-policy refusal. Rust
keeps exact copies of lowercase names within the 76-byte ASCII limit and a
keyed hash of any other name for this check. The harness also checks
Unicode filenames and raw media-type metadata at and above a small configured
limit, with synthetic loopback SMTP only.

## Multipart completion

Both runtimes require the multipart parser to reach the complete closing
boundary before accepting a send request. Truncation within the applicable
limits returns HTTP 400 with `{"message":"malformed form"}`, without SMTP
submission. Python closes all already-spooled uploads, including an unfinished
last upload. Complete multipart bodies with epilogues remain supported. HTTP
Content-Length completeness alone does not establish MIME completeness.
The Rust multipart parser reuses one byte searcher for the request boundary
across all parts. A boundary look-alike inside part data stays in the payload
unless followed by CRLF or the closing `--`.
Rust searches for text-field delimiters through the inclusive field byte
limit, with lookahead for the delimiter and its two-byte continuation.
Field data beyond the limit returns HTTP 413 even if the part is unfinished.
Uploads are scanned under the request body limit and checked against their
separate attachment limits. The send route currently uses the same configured
byte limit for the whole request and for each text field.

## HTTP singleton headers

`Authorization` and `Content-Type` may each occur at most once on a send
request. Both runtimes reject repeated fields with HTTP 400 and
`{"message":"duplicate singleton HTTP header"}` before authentication, body
reads or SMTP admission. Header names are compared case-insensitively; identical
repeated values are also refused. Single-header Anymail requests remain supported.
