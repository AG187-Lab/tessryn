#!/usr/bin/env python3
"""Preregister and retain a bounded fresh region-service emulator capture."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import math
import subprocess
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k03_timer_protocol import (CASES, PROFILE, FORMAT, SCOPE, MAX_LOG_BYTES, require,
    digest, regular_bytes, read_ref, file_ref, strict_json, write_json, fresh_output, retain_private_error)
from tools.k03_timer_provenance import runtime_hashes, canonical, validate_toolchain
from tools.run_k02_native import launcher_command
from tools.g03.process import run_bounded
from tools.setup_uefi import verify_installation

PASS_REASON = "bound CPL3 IRQ preemption and complete K03 timer budget protocol matched"


def qemu_command():
    return ["qemu-system-x86_64", "-machine", PROFILE["machine"], "-cpu", PROFILE["cpu"],
        "-m", "256M", "-smp", "1", "-nodefaults", "-no-user-config", "-display", "none",
        "-monitor", "none", "-serial", "null", "-nic", "none", "-no-reboot", "-device", "VGA,romfile=",
        "-global", "apic.vapic=off", "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
        "-drive", "if=pflash,format=raw,file=vars.fd", "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-drive", "if=ide,format=raw,snapshot=on,file=boot.img",
        "-boot", "order=c"]


def run(manifest_path, out, case, *, allow_qemu=False, capture_only=False, timeout=45, max_log_bytes=MAX_LOG_BYTES):
    require(case in CASES and type(allow_qemu) is bool and type(capture_only) is bool, "region scenario/opt-in invalid")
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 60
            and type(max_log_bytes) is int and 0 < max_log_bytes <= MAX_LOG_BYTES, "region execution budgets invalid")
    out = fresh_output(out)
    stdout, stderr = b"", b""
    result = {"format": FORMAT, "case": case, "status": "fail", "reason": "inputs incomplete", "scope": SCOPE,
        "qualification": "not_established", "capture_only": capture_only, "manifest_sha256": None,
        "registration_sha256": None, "evaluator_sha256": None,
        "execution": {"status": "unavailable", "returncode": None, "elapsed_seconds": 0,
                      "command": qemu_command(), "timeout_seconds": timeout, "max_log_bytes": max_log_bytes},
        "observations": None, "logs": []}
    try:
        require(allow_qemu, "region execution requires explicit --allow-qemu")
        from tools.verify_k03_timer import validate_build, bound_context, parse_transcript
        manifest_path = Path(manifest_path).absolute()
        manifest_raw = regular_bytes(manifest_path, 2 << 20)
        manifest = validate_build(manifest_path)
        current_runtime = runtime_hashes()
        require(manifest["runtime_files"] == current_runtime, "region build runtime differs from reviewed checkout")
        for name, value in manifest["source_files"].items():
            require(digest(regular_bytes(ROOT / name, 16 << 20)) == value, "region build compiler source differs from checkout")
        validate_toolchain(manifest)
        setup = verify_installation()
        require(setup == manifest["toolchain"]["setup"], "region checked setup differs from build")
        artifacts = [row for row in manifest["artifacts"] if row.get("case") == case]
        chosen = {row["kind"]: read_ref(manifest_path.parent, row) for row in artifacts}
        qemu = ROOT / "build/toolchain/bin/qemu-system-x86_64"
        qemu_hash = digest(regular_bytes(qemu, 256 << 20))
        require(qemu_hash == setup["verified_tools"]["qemu"]["sha256"], "region QEMU identity differs")
        firmware = {}
        (out / "firmware").mkdir()
        for role in ("code", "vars"):
            row = setup["firmware"][role]
            data = regular_bytes(ROOT / "build/uefi" / row["path"], 16 << 20)
            require(digest(data) == row["sha256"] and len(data) == row["size_bytes"], "region firmware differs")
            (out / "firmware" / (role + ".fd")).write_bytes(data)
            firmware[role] = data
        notice = setup["firmware"]["notice"]
        notice_bytes = regular_bytes(ROOT / "build/uefi" / notice["path"], 4 << 20)
        require(digest(notice_bytes) == notice["sha256"] and len(notice_bytes) == notice["size_bytes"], "region firmware notice differs")
        (out / "firmware/NOTICE").write_bytes(notice_bytes)
        env_hash = digest(regular_bytes(Path("/usr/bin/env"), 16 << 20))
        registration = {"format": "tessryn-k03-timer-registration/v1", "case": case, "scope": SCOPE,
            "qualification": "not_established", "capture_origin": "local_runner_claim_unverified_offline",
            "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "manifest_sha256": digest(manifest_raw), "selected_artifacts": artifacts,
            "evaluator_sha256": digest(canonical(current_runtime).encode()), "command": qemu_command(),
            "timeout_seconds": timeout, "max_log_bytes": max_log_bytes, "emulator_sha256": qemu_hash,
            "launcher": {"executable": "/usr/bin/env", "sha256": env_hash,
                         "temporary_scope": "fresh private owned directory removed after child reap"},
            "firmware": [file_ref(out, out / "firmware" / name) for name in ("code.fd", "vars.fd", "NOTICE")]}
        write_json(out / "registration.json", registration)
        result.update(manifest_sha256=registration["manifest_sha256"],
            registration_sha256=digest(regular_bytes(out / "registration.json", 2 << 20)),
            evaluator_sha256=registration["evaluator_sha256"])
        write_json(out / "result.json", result)
        with tempfile.TemporaryDirectory(prefix="tessryn-region-", dir=Path("/tmp").resolve()) as temporary:
            scratch = Path(temporary)
            for role, data in firmware.items():
                (scratch / (role + ".fd")).write_bytes(data)
            (scratch / "boot.img").write_bytes(chosen["boot_disk"])
            execution = run_bounded(launcher_command(qemu, qemu_command()[1:], scratch), scratch, timeout, max_log_bytes)
        stdout, stderr = execution.stdout, execution.stderr
        result["execution"].update(status=execution.status, returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
        require(runtime_hashes() == current_runtime and regular_bytes(manifest_path, 2 << 20) == manifest_raw
                and digest(regular_bytes(qemu, 256 << 20)) == qemu_hash
                and digest(regular_bytes(Path("/usr/bin/env"), 16 << 20)) == env_hash
                and verify_installation() == setup, "region capture inputs or trusted runtime changed")
        for row in artifacts:
            read_ref(manifest_path.parent, row)
        require(execution.status == "completed" and execution.returncode == 33, "region bounded emulator failed")
        if capture_only:
            result.update(status="captured", reason="diagnostic capture; no protocol acceptance")
        else:
            observations = parse_transcript(case, stdout, execution.returncode, stderr, bound_context(manifest_path, manifest, case))
            result.update(status="pass", reason=PASS_REASON, observations=observations)
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as error:
        retain_private_error(out, error)
        result.update(status="fail", reason="region capture rejected: " + type(error).__name__, observations=None)
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / name).write_bytes(data)
        result["logs"].append(file_ref(out, out / name))
    write_json(out / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--allow-qemu", action="store_true")
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    try:
        result = run(args.manifest, args.out, args.case, allow_qemu=args.allow_qemu,
                     capture_only=args.capture_only, timeout=args.timeout)
    except (OSError, ValueError) as error:
        parser.exit(1, "K03 timer capture setup rejected: " + type(error).__name__ + "\n")
    print(canonical({key: result[key] for key in ("case", "status", "reason", "qualification")}))
    return 0 if result["status"] in ("pass", "captured") else 1


if __name__ == "__main__":
    raise SystemExit(main())
