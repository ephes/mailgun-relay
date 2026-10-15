"""Run every scenario against the scripted fake server with the Rust prototype
and the Python relay (oracle), and print both HTTP statuses side by side.

Usage: python3 rust/spikes/s1b/fake/run_matrix.py SCRATCH_DIR
(run from the repo root; needs `cargo build --release` in rust/spikes/s1b and
`uv sync` for the oracle). Throwaway certificates are created in SCRATCH_DIR.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPIKE = HERE.parent
REPO = SPIKE.parent.parent.parent
BIN = SPIKE / "target" / "release" / "s1b-spike"

OK3 = "ok1@example.com,bad@example.com,ok2@example.com"

# name, scenario, recipients, starttls, user, server cert ("good"/"wrongname"/"selfsigned")
CASES: list[tuple[str, dict, str, bool, str, str]] = [
    ("all accepted", {}, OK3.replace("bad", "ok3"), True, "relay", "good"),
    ("partial 550", {"rcpt": {"bad": 550}}, OK3, True, "relay", "good"),
    ("partial 450", {"rcpt": {"bad": 450}}, OK3, True, "relay", "good"),
    ("partial 550+452", {"rcpt": {"bad": 550, "ok2": 452}}, OK3, True, "relay", "good"),
    ("all refused 5xx", {"rcpt": {"ok1": 550, "bad": 553, "ok2": 550}}, OK3, True, "relay", "good"),
    ("all refused 5xx+4xx", {"rcpt": {"ok1": 550, "bad": 450, "ok2": 550}}, OK3, True, "relay", "good"),
    ("rcpt 421 after accepted", {"rcpt": {"bad": 421}}, OK3, True, "relay", "good"),
    ("rcpt 451 single", {"rcpt": {"ok1": 451}}, "ok1@example.com", True, "relay", "good"),
    ("mail 550", {"mail": 550}, OK3, True, "relay", "good"),
    ("mail 451", {"mail": 451}, OK3, True, "relay", "good"),
    ("mail 421", {"mail": 421}, OK3, True, "relay", "good"),
    ("data 554", {"data": 554}, OK3, True, "relay", "good"),
    ("data 451", {"data": 451}, OK3, True, "relay", "good"),
    ("data_end 552", {"data_end": 552}, OK3, True, "relay", "good"),
    ("data_end 450", {"data_end": 450}, OK3, True, "relay", "good"),
    ("data_end 421", {"data_end": 421}, OK3, True, "relay", "good"),
    ("banner 554", {"banner": 554}, OK3, True, "relay", "good"),
    ("banner 421", {"banner": 421}, OK3, True, "relay", "good"),
    ("ehlo 550 (starttls on)", {"ehlo": 550}, OK3, True, "relay", "good"),
    ("ehlo 421 (starttls on)", {"ehlo": 421}, OK3, True, "relay", "good"),
    ("ehlo 550 (starttls off, creds)", {"ehlo": 550, "offer_starttls": False}, OK3, False, "relay", "good"),
    ("ehlo after tls 550", {"ehlo_tls": 550}, OK3, True, "relay", "good"),
    ("starttls 454", {"starttls": 454}, OK3, True, "relay", "good"),
    ("starttls 554", {"starttls": 554}, OK3, True, "relay", "good"),
    ("starttls not offered", {"offer_starttls": False}, OK3, True, "relay", "good"),
    ("auth 535", {"auth": 535}, OK3, True, "relay", "good"),
    ("auth 454", {"auth": 454}, OK3, True, "relay", "good"),
    ("auth not offered", {"auth_offer": ""}, OK3, True, "relay", "good"),
    ("auth only CRAM-MD5", {"auth_offer": "CRAM-MD5"}, OK3, True, "relay", "good"),
    ("auth LOGIN only", {"auth_offer": "LOGIN"}, OK3, True, "relay", "good"),
    ("creds without tls", {"offer_starttls": False}, OK3, False, "relay", "good"),
    ("no creds, no tls", {"offer_starttls": False}, OK3, False, "-", "good"),
    ("cert wrong hostname", {}, OK3, True, "relay", "wrongname"),
    ("cert unknown CA", {}, OK3, True, "relay", "selfsigned"),
    ("disconnect at mail", {"fault": {"mail": "close"}}, OK3, True, "relay", "good"),
    ("disconnect at rcpt", {"fault": {"rcpt": "close"}}, OK3, True, "relay", "good"),
    ("disconnect at data_end", {"fault": {"data_end": "close"}}, OK3, True, "relay", "good"),
    ("garbage at mail", {"fault": {"mail": "garbage"}}, OK3, True, "relay", "good"),
    ("garbage at data_end", {"fault": {"data_end": "garbage"}}, OK3, True, "relay", "good"),
    ("timeout at data_end", {"fault": {"data_end": "hang"}}, OK3, True, "relay", "good"),
    ("quit 500 after accepted", {"quit": 500}, OK3, True, "relay", "good"),
    ("quit close after accepted", {"fault": {"quit": "close"}}, OK3, True, "relay", "good"),
]


def make_certs(d: Path) -> dict[str, tuple[str, str]]:
    def run(*args: str) -> None:
        subprocess.run(args, check=True, capture_output=True, cwd=d)

    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=s1b test CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    for name, san in (("good", "DNS:localhost,IP:127.0.0.1"), ("wrongname", "DNS:other.test")):
        run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={san.split(',')[0][4:]}")
        Path(d, f"{name}.ext").write_text(f"subjectAltName={san}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        run("openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", f"{name}.pem", "-days", "2", "-extfile", f"{name}.ext")
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "selfsigned.key", "-out", "selfsigned.pem", "-days", "2", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost")
    return {n: (str(d / f"{n}.pem"), str(d / f"{n}.key")) for n in ("good", "wrongname", "selfsigned")}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_case(scratch: Path, certs: dict, case: tuple) -> dict:
    name, scenario, rcpts, starttls, user, cert = case
    out = {}
    for impl in ("rust", "python"):
        port = free_port()
        transcript = scratch / f"transcript-{impl}.jsonl"
        transcript.write_text("")
        server = subprocess.Popen(
            [sys.executable, str(HERE / "scripted_smtp.py"), str(port), *certs[cert], json.dumps(scenario), str(transcript)],
            stdout=subprocess.PIPE, text=True,
        )
        server.stdout.readline()
        env = {**os.environ, "S1B_SMTP_PASS": "test-password"}
        timeout_s = "2" if "timeout" in name else "30"
        if impl == "rust":
            cmd = [str(BIN), "submit", "host=localhost", f"port={port}", f"starttls={str(starttls).lower()}",
                   f"ca_file={scratch / 'ca.pem'}", "from=sender@example.com", f"to={rcpts}", f"timeout_s={timeout_s}"]
            if user != "-":
                cmd.append(f"user={user}")
        else:
            cmd = ["uv", "run", "-q", "python", str(HERE / "oracle.py"), str(port), str(starttls).lower(),
                   str(scratch / "ca.pem"), user, "sender@example.com", rcpts, timeout_s]
        started = time.monotonic()
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, env=env, timeout=60)
        elapsed = time.monotonic() - started
        time.sleep(0.2)
        server.terminate()
        server.wait()
        lines = [json.loads(line) for line in transcript.read_text().splitlines() if line.strip()]
        out[impl] = {
            "result": (res.stdout.strip() or res.stderr.strip()).splitlines()[-1] if (res.stdout or res.stderr) else "",
            "data_for": lines[0]["data_for"] if lines else None,
            "commands": [entry[3:].split(" ")[0] for entry in (lines[0]["log"] if lines else []) if entry.startswith("C: ")],
            "elapsed_s": round(elapsed, 2),
        }
    return out


def main() -> None:
    scratch = Path(sys.argv[1])
    certs = make_certs(scratch)
    only = sys.argv[2] if len(sys.argv) > 2 else None
    mismatches = 0
    for case in CASES:
        if only and only not in case[0]:
            continue
        r = run_case(scratch, certs, case)
        rs = r["rust"]["result"].split(" ")[0]
        ps = r["python"]["result"].split(" ")[0]
        same = rs == ps
        mismatches += not same
        print(f"{'SAME' if same else 'DIFF'} | {case[0]:<32} | rust {rs} | python {ps}")
        print(f"     rust:   {r['rust']['result']}")
        print(f"             commands={r['rust']['commands']} data_for={r['rust']['data_for']} t={r['rust']['elapsed_s']}s")
        print(f"     python: {r['python']['result']}")
        print(f"             commands={r['python']['commands']} data_for={r['python']['data_for']}")
    print(f"mismatches: {mismatches}")


if __name__ == "__main__":
    main()
