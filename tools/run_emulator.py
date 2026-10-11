#!/usr/bin/env python3
"""Execute only the declared G03 ROM fixtures using a fixed, bounded QEMU profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import tempfile

from g03.evidence import load_json, parse_json, registration_digest, validate_registration, validate_result
from g03.process import run_bounded


ROOT = Path(__file__).resolve().parents[1]
MARKER = b"TESSRYN_G03_FIXTURE_PASS"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def evaluator_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted([Path(__file__), ROOT / "tools/verify_fixture.py", ROOT / "toolchain.lock.json",
                        *Path(__file__).parent.joinpath("g03").glob("*.py"), *ROOT.joinpath("evidence").glob("*schema*.json")]):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def regular_bytes(path: Path) -> bytes:
    # Check the open descriptor, not a path which could change between stat/read.
    # O_NONBLOCK also avoids hanging if an input is replaced with a FIFO.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 256 * 1024 * 1024:
            raise ValueError("input must be a regular file of at most 256 MiB")
        data = stream.read(256 * 1024 * 1024 + 1)
        if len(data) > 256 * 1024 * 1024:
            raise ValueError("input exceeded 256 MiB while reading")
        return data


def verified_artifact(manifest_path: Path, fixture: str, manifest: dict | None = None) -> bytes:
    manifest = manifest if manifest is not None else parse_json(regular_bytes(manifest_path))
    if manifest.get("schema_version") != 1 or manifest.get("artifact_type") != "test_fixture":
        raise ValueError("only version 1 test_fixture manifests are executable in G03")
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest artifacts are missing")
    seen = set()
    selected = None
    for entry in entries:
        path = PurePosixPath(entry["path"])
        if path.is_absolute() or len(path.parts) != 1 or "\\" in str(path) or str(path) in {".", ".."}:
            raise ValueError("artifact paths must be plain filenames beside the manifest")
        if str(path) in seen:
            raise ValueError("duplicate artifact path")
        seen.add(str(path))
        data = regular_bytes(manifest_path.parent / str(path))
        if sha256(data) != entry.get("sha256") or len(data) != entry.get("size_bytes"):
            raise ValueError("artifact hash or length mismatch")
        if str(path) == f"{fixture}.rom":
            selected = data
    if selected is None or len(selected) != 65536:
        raise ValueError("selected fixture must be a declared 64 KiB ROM")
    return selected


def fixture_command(fixture: str) -> list[str]:
    return ["qemu-system-x86_64", "-machine", "pc,accel=tcg", "-cpu", "qemu64", "-m", "16M",
            "-smp", "1", "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "none", "-nic", "none", "-no-reboot", "-bios", f"{fixture}.rom",
            "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9", "-global", "apic.vapic=off",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]


def run_emulator(manifest_path: Path, registration_path: Path, out: Path,
                 fixture: str = "pass", timeout_seconds: float = 5,
                 max_log_bytes: int = 65536, qemu: str = "qemu-system-x86_64") -> dict:
    """Own a new result directory; never overwrite a previous experiment.

    Host-owned artifacts are hashed, then copied to scratch. The guest receives
    only its ROM, with no writable disks, shares, network, or passthrough devices.
    """
    if fixture not in {"pass", "hang"}:
        raise ValueError("unknown fixture")
    # Validate budgets before making a result whose schema would be invalid.
    import math
    if isinstance(timeout_seconds, bool) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout must be positive and finite")
    if isinstance(max_log_bytes, bool) or not isinstance(max_log_bytes, int) or max_log_bytes <= 0:
        raise ValueError("log budget must be a positive integer")
    out.mkdir(parents=True, exist_ok=False)
    command = fixture_command(fixture)
    result = {
        "schema_version": 1, "format": "tessryn-evaluation-result",
        "evidence_kind": "implementation_result", "subject": "test_fixture", "status": "fail",
        "bindings": {"evaluator": evaluator_hash(), "artifact_manifest": "0" * 64, "registration": "0" * 64},
        "capabilities": {name: {"status": "unavailable", "reason": reason} for name, reason in {
            "kernel_boot": "Tessryn kernel is not implemented; ROM is a harness fixture",
            "gpu_execution": "No native GPU driver or qualified device artifact exists",
            "inference": "No model execution implementation exists"}.items()},
        "execution": {"command": command, "timeout_seconds": timeout_seconds,
                      "max_log_bytes": max_log_bytes, "elapsed_seconds": 0, "returncode": None,
                      "reason": "input validation did not complete", "emulator": None},
        "logs": [], "actual_sample_count": 0,
        "performance": {"status": "unavailable", "reason": "Fixture wall time is harness metadata, not Tessryn performance"},
    }
    stdout = stderr = b""
    stage = "manifest input read"
    try:
        manifest_bytes = regular_bytes(manifest_path)
        stage = "registration input read"
        registration_bytes = regular_bytes(registration_path)
        result["bindings"].update(artifact_manifest=sha256(manifest_bytes), registration=sha256(registration_bytes))
        registration = parse_json(registration_bytes)
        stage = "registration validation"
        validate_registration(registration)
        result["bindings"]["registration"] = registration_digest(registration)
        if registration["subject"] != "test_fixture":
            raise ValueError("fixture harness requires a fixture protocol registration")
        stage = "artifact integrity validation"
        rom = verified_artifact(manifest_path, fixture, parse_json(manifest_bytes))
        executable = shutil.which(qemu)
        if executable is None:
            result["status"] = "unavailable"
            result["execution"]["reason"] = "QEMU executable is missing"
        else:
            executable = str(Path(executable).resolve())
            stage = "emulator execution setup"
            with tempfile.TemporaryDirectory(prefix="tessryn-g03-") as temporary:
                scratch = Path(temporary)
                (scratch / f"{fixture}.rom").write_bytes(rom)
                version = run_bounded([executable, "--version"], scratch, min(timeout_seconds, 5), min(8192, max_log_bytes))
                expected_version = load_json(ROOT / "toolchain.lock.json")["qemu"]["version"]
                version_text = version.stdout.decode("utf-8", errors="replace")
                if version.status != "completed" or version.returncode != 0 or not re.search(
                        rf"QEMU emulator version {re.escape(expected_version)}(?:\s|$)", version_text):
                    result["status"] = version.status if version.status in {"timeout", "log_limit", "cancelled"} else "unavailable"
                    result["execution"].update(elapsed_seconds=version.elapsed_seconds, returncode=version.returncode,
                                                reason="QEMU version does not match the pinned profile or version probe failed")
                    stdout, stderr = version.stdout, version.stderr
                else:
                    result["execution"]["emulator"] = {"version": expected_version,
                                                          "binary_sha256": sha256(regular_bytes(Path(executable).resolve()))}
                    execution = run_bounded([executable, *command[1:]], scratch, timeout_seconds, max_log_bytes)
                    stdout, stderr = execution.stdout, execution.stderr
                    result["execution"].update(elapsed_seconds=execution.elapsed_seconds,
                                                returncode=execution.returncode, reason=execution.reason)
                    result["status"] = execution.status
                    if execution.status == "completed":
                        passed = fixture == "pass" and execution.returncode == 33 and MARKER in stdout
                        result["status"] = "pass" if passed else "fail"
                        result["execution"]["reason"] = ("fixture marker and debug-exit status matched" if passed else
                                                             "fixture marker or expected debug-exit status did not match")
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["status"] = "fail"
        result["execution"]["reason"] = f"{stage} rejected: {type(error).__name__}"
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / name).write_bytes(data)
        result["logs"].append({"path": name, "sha256": sha256(data), "size_bytes": len(data)})
    validate_result(result)
    temporary_result = out / "result.json.tmp"
    temporary_result.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n")
    temporary_result.replace(out / "result.json")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--registration", type=Path, default=ROOT / "evidence/fixture-registration.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixture", choices=["pass", "hang"], default="pass")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--max-log-bytes", type=int, default=65536)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    args = parser.parse_args()
    previous = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        result = run_emulator(args.manifest, args.registration, args.out, args.fixture,
                              args.timeout, args.max_log_bytes, args.qemu)
    except (OSError, ValueError) as error:
        parser.exit(2, f"harness setup rejected: {type(error).__name__}\n")
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps({"status": result["status"], "reason": result["execution"]["reason"],
                      "result": "result.json"}, sort_keys=True))
    return {"pass": 0, "fail": 1, "timeout": 124, "cancelled": 130, "unavailable": 2, "log_limit": 125}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
