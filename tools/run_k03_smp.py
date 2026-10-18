#!/usr/bin/env python3
"""Preregister and retain one fresh bounded two-CPU bootstrap capture."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k03_smp_protocol import (CASES, PROFILE, FORMAT, SCOPE, MAX_LOG_BYTES, require, digest,
    regular_bytes, read_ref, file_ref, strict_json, write_json, fresh_output, retain_private_error)
from tools.k03_smp_provenance import runtime_hashes, canonical, validate_toolchain
from tools.g03.process import run_bounded
from tools.setup_uefi import verify_installation
PASS_REASON = "source-bound original two-CPU bootstrap protocol matched"


def qemu_command():
    return ["qemu-system-x86_64", "-machine", PROFILE["machine"], "-accel", PROFILE["accelerator"],
        "-cpu", PROFILE["cpu"], "-m", "256M", "-smp", PROFILE["topology"], "-nodefaults", "-no-user-config",
        "-display", "none", "-monitor", "none", "-serial", "null", "-nic", "none", "-no-reboot",
        "-device", "VGA,romfile=", "-global", "apic.vapic=off",
        "-drive", "if=pflash,format=raw,readonly=on,file=code.fd", "-drive", "if=pflash,format=raw,file=vars.fd",
        "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-drive", "if=ide,format=raw,snapshot=on,file=boot.img", "-boot", "order=c"]


def launcher_command(qemu, scratch):
    info = scratch.lstat()
    require(scratch.is_absolute() and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        and not info.st_mode & 0o077 and not scratch.is_symlink(), "SMP temporary directory is not private")
    return ["/usr/bin/env", "TMPDIR=" + str(scratch), str(qemu), *qemu_command()[1:]]


def run(manifest_path, out, case, *, allow_qemu=False, capture_only=False, timeout=30):
    require(case in CASES and type(allow_qemu) is bool and type(capture_only) is bool
        and type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 60, "SMP case/opt-in/budget invalid")
    out = fresh_output(out); stdout, stderr = b"", b""
    result = {"format": FORMAT, "case": case, "status": "fail", "reason": "inputs incomplete", "scope": SCOPE,
        "qualification": "not_established", "capture_only": capture_only, "manifest_sha256": None,
        "registration_sha256": None, "evaluator_sha256": None, "observations": None, "logs": [],
        "execution": {"status": "unavailable", "returncode": None, "elapsed_seconds": 0,
            "command": qemu_command(), "timeout_seconds": timeout, "max_log_bytes": MAX_LOG_BYTES}}
    try:
        require(allow_qemu, "SMP capture needs explicit --allow-qemu")
        from tools.verify_k03_smp import validate_build
        from tools.k03_smp_trace import parse_transcript
        manifest_path = Path(manifest_path).absolute(); manifest_bytes = regular_bytes(manifest_path, 2 << 20)
        manifest = validate_build(manifest_path); runtime = runtime_hashes()
        require(manifest["runtime_files"] == runtime
            and all(digest(regular_bytes(ROOT / n, 16 << 20)) == sha for n, sha in manifest["source_files"].items()), "SMP build inputs differ from checkout")
        validate_toolchain(manifest); setup = verify_installation()
        require(setup == manifest["toolchain"]["setup"], "SMP setup differs from build")
        artifacts = [r for r in manifest["artifacts"] if r["case"] == case]
        disk = read_ref(manifest_path.parent, next(r for r in artifacts if r["path"].endswith("/boot.img")))
        qemu = ROOT / "build/toolchain/bin/qemu-system-x86_64"; qemu_sha = digest(regular_bytes(qemu, 256 << 20))
        require(qemu_sha == setup["verified_tools"]["qemu"]["sha256"], "SMP emulator differs")
        env_sha = digest(regular_bytes(Path("/usr/bin/env"), 16 << 20))
        firmware = {}; (out / "firmware").mkdir()
        for role, name in (("code", "code.fd"), ("vars", "vars.fd"), ("notice", "NOTICE")):
            row = setup["firmware"][role]; data = regular_bytes(ROOT / "build/uefi" / row["path"], 16 << 20)
            require(digest(data) == row["sha256"] and len(data) == row["size_bytes"], "SMP firmware origin differs")
            (out / "firmware" / name).write_bytes(data); firmware[name] = data
        registration = {"format": "tessryn-k03-smp-registration/v1", "case": case, "scope": SCOPE,
            "qualification": "not_established", "capture_origin": "local_runner_claim_unverified_offline",
            "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "manifest_sha256": digest(manifest_bytes), "selected_artifacts": artifacts,
            "evaluator_sha256": digest(canonical(runtime).encode()), "command": qemu_command(),
            "timeout_seconds": timeout, "max_log_bytes": MAX_LOG_BYTES, "emulator_sha256": qemu_sha,
            "launcher": {"executable": "/usr/bin/env", "sha256": env_sha, "temporary_scope": "private owned directory removed after child reap"},
            "firmware": [file_ref(out, out / "firmware" / n) for n in ("code.fd", "vars.fd", "NOTICE")]}
        write_json(out / "registration.json", registration)
        result.update(manifest_sha256=registration["manifest_sha256"], registration_sha256=digest(regular_bytes(out / "registration.json")), evaluator_sha256=registration["evaluator_sha256"])
        write_json(out / "result.json", result)
        with tempfile.TemporaryDirectory(prefix="tessryn-smp-", dir=Path("/tmp").resolve()) as temporary:
            scratch = Path(temporary); scratch.chmod(0o700)
            for name in ("code.fd", "vars.fd"): (scratch / name).write_bytes(firmware[name])
            (scratch / "boot.img").write_bytes(disk)
            execution = run_bounded(launcher_command(qemu, scratch), scratch, timeout, MAX_LOG_BYTES)
        stdout, stderr = execution.stdout, execution.stderr
        result["execution"].update(status=execution.status, returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
        require(runtime_hashes() == runtime and regular_bytes(manifest_path, 2 << 20) == manifest_bytes
            and digest(regular_bytes(qemu, 256 << 20)) == qemu_sha and digest(regular_bytes(Path("/usr/bin/env"), 16 << 20)) == env_sha
            and verify_installation() == setup, "SMP capture inputs changed")
        for row in artifacts: read_ref(manifest_path.parent, row)
        require(execution.status == "completed" and execution.returncode == 33, "SMP bounded capture failed")
        if capture_only: result.update(status="captured", reason="diagnostic capture; no protocol acceptance")
        else: result.update(status="pass", reason=PASS_REASON, observations=parse_transcript(case, stdout, execution.returncode, stderr, manifest["bindings"][case]))
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as error:
        retain_private_error(out, error); result.update(reason="SMP capture rejected: " + type(error).__name__, observations=None)
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / name).write_bytes(data); result["logs"].append(file_ref(out, out / name))
    write_json(out / "result.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("--manifest", type=Path, required=True); p.add_argument("--out", type=Path, required=True)
    p.add_argument("--case", choices=CASES, required=True); p.add_argument("--allow-qemu", action="store_true"); p.add_argument("--capture-only", action="store_true"); args = p.parse_args()
    try: result = run(args.manifest, args.out, args.case, allow_qemu=args.allow_qemu, capture_only=args.capture_only)
    except (OSError, ValueError, subprocess.SubprocessError) as error: p.exit(1, "SMP capture setup rejected: " + type(error).__name__ + "\n")
    print(canonical({k: result[k] for k in ("case", "status", "reason", "qualification")}))
    return 0 if result["status"] in ("pass", "captured") else 1
if __name__ == "__main__": raise SystemExit(main())
