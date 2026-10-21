"""Incident-specific verifier contract for the SMTP transport's locked graph."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_smtp_verifier_security_floor_without_bundled_root_store() -> None:
    manifest = tomllib.loads((ROOT / "rust/Cargo.toml").read_text())
    packages = tomllib.loads((ROOT / "rust/Cargo.lock").read_text())["package"]
    by_name = {package["name"]: package for package in packages}
    # RUSTSEC-2026-0382 fixes verifier behavior, independently of CA provenance.
    version = tuple(map(int, by_name["rustls-webpki"]["version"].split(".")))
    assert (0, 103, 16) <= version < (0, 104, 0)
    assert "rustls-webpki" in by_name["rustls"]["dependencies"]
    assert "rustls" in by_name["lettre"]["dependencies"]
    features = manifest["dependencies"]["lettre"]["features"]
    assert "rustls-native-certs" in features
    assert not {"webpki-roots", "webpki-root-certs"}.intersection(by_name)


def test_every_sdk_bootstrap_is_preceded_by_hosted_runner_security_gate() -> None:
    import yaml

    bootstraps = 0
    uv_pins = []
    for workflow in ("ci.yml", "rust-release.yml"):
        config = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
        for job in config["jobs"].values():
            steps = job.get("steps", [])
            admitted = False
            for step in steps:
                if "setup-uv@" in step.get("uses", ""):
                    uv_pins.append(step["with"]["version"])
                command = step.get("run", "")
                if "python3 scripts/ci_rustup.py" in command:
                    assert step.get("working-directory") == "."
                    admitted = True
                if "rustup toolchain install" in command:
                    assert admitted, f"SDK download precedes security bootstrap in {workflow}"
                    bootstraps += 1
    assert bootstraps == 3  # Rust CI, parity CI and release.
    assert uv_pins == ["0.13.4"] * 3
