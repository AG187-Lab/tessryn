#!/usr/bin/env python3
"""Opt in to a bounded single-CPU QEMU original-kernel benchmark capture."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import build_native_kernel_benchmarks as build_tools

LOADED_SOURCE = Path(__file__).read_bytes()
CPU = "max,phys-bits=48,la57=off,nx=on,pcid=off,pge=off"


def qemu_command() -> list[str]:
    return ["qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", CPU,
            "-m", "256M", "-smp", "1", "-nodefaults", "-no-user-config", "-display", "none",
            "-monitor", "none", "-serial", "null", "-nic", "none", "-no-reboot",
            "-device", "VGA,romfile=", "-global", "apic.vapic=off",
            "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
            "-drive", "if=pflash,format=raw,file=vars.fd",
            "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-drive", "if=ide,format=raw,snapshot=on,file=boot.img", "-boot", "order=c"]


def _preflight_build(manifest_path: Path, raw: bytes) -> dict:
    # Current trusted evaluator supplies a bounded preflight before any packet
    # copy. Later acceptance uses the separately retained evaluator source.
    verifier_path = ROOT / "tools/verify_native_kernel_benchmarks.py"
    evaluator = {"__name__": "native_benchmark_preflight", "__file__": str(verifier_path)}
    exec(compile(build_tools.regular_bytes(verifier_path, 2 << 20), str(verifier_path), "exec"), evaluator)
    manifest = evaluator["validate_build"](manifest_path)
    if not evaluator["same_json"](manifest, evaluator["strict_json"](raw)):
        raise ValueError("build manifest changed during preflight")
    return manifest


def _copy_build(manifest_path: Path, out: Path) -> dict[Path, bytes]:
    """Copy only the manifest-declared closure, never arbitrary adjacent files."""
    raw = build_tools.regular_bytes(manifest_path, 2 << 20)
    manifest = _preflight_build(manifest_path, raw)
    refs = [manifest["profile"], *manifest["sources"], *manifest["artifacts"], *manifest["notices"]]
    for receipt in manifest["compile"]:
        refs.extend((receipt["stdout"], receipt["stderr"]))
    if len(refs) > 150 or sum(ref["size"] for ref in refs) > 128 << 20:
        raise ValueError("build closure exceeds aggregate copy budget")
    expected = {"manifest.json": raw}
    for ref in refs:
        name = ref["file"]
        relative = Path(name)
        if (not isinstance(name, str) or relative.is_absolute() or relative.as_posix() != name
                or any(part in ("", ".", "..") for part in relative.parts)):
            raise ValueError("unsafe build reference")
        data = build_tools.regular_bytes(manifest_path.parent / relative)
        if build_tools.digest(data) != ref["sha256"] or len(data) != ref["size"]:
            raise ValueError("selected build reference differs")
        if name in expected and expected[name] != data:
            raise ValueError("conflicting build references")
        expected[name] = data
    retained = {}
    for name, data in expected.items():
        target = out / "build" / name
        build_tools.write_bytes(target, data)
        target.chmod(0o444)
        retained[target] = data
    # Rechecking the original closure also detects a build edited while copied.
    build_tools.unchanged({manifest_path.parent / name: data for name, data in expected.items()})
    return retained


def launcher_command(executable: Path, arguments: list[str], scratch: Path) -> list[str]:
    info = scratch.lstat()
    if (not scratch.is_absolute() or scratch.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("emulator requires fresh private temporary storage")
    build_tools.regular_bytes(executable)
    launcher = Path("/usr/bin/env")
    build_tools.regular_bytes(launcher, 4 << 20)
    return [str(launcher), "TMPDIR=" + str(scratch), str(executable), *arguments]


def run(manifest_path: Path, out: Path, *, allow_qemu: bool = False,
        timeout: float = 60, max_log_bytes: int = 262144) -> dict:
    build_tools.budgets(timeout, max_log_bytes)
    if timeout > 60:
        raise ValueError("native emulator capture timeout exceeds 60 seconds")
    if allow_qemu is not True:
        raise ValueError("QEMU execution requires explicit --allow-qemu")
    out = build_tools.exclusive_directory(out)
    result = {"schema_version": 1, "kind": "native_kernel_benchmark_run", "status": "failed",
              "evidence_scope": build_tools.SCOPE, "native_qualification": False, "valid": False,
              "registration_sha256": None, "summary": None, "reason": "capture incomplete"}
    execution_receipt = None
    started = time.monotonic()
    try:
        if build_tools.regular_bytes(Path(__file__)) != LOADED_SOURCE:
            raise ValueError("running runner source changed since import")
        if build_tools.regular_bytes(Path(build_tools.__file__)) != build_tools.LOADED_SOURCE:
            raise ValueError("running builder helper source changed since import")
        retained = _copy_build(manifest_path, out)
        snapshot = out / "build/sources"
        for name, data in (("tools/run_native_kernel_benchmarks.py", LOADED_SOURCE),
                           ("tools/build_native_kernel_benchmarks.py", build_tools.LOADED_SOURCE)):
            if build_tools.regular_bytes(snapshot / name) != data:
                raise ValueError("running capture tools differ from built source binding")
        with build_tools.captured_runtime(snapshot) as runtime:
            verifier, kernel = runtime["verifier"], runtime["kernel"]
            manifest = verifier.validate_build(out / "build/manifest.json")
            setup = kernel.verify_installation()
            if setup != manifest["toolchain"]["setup"]:
                raise ValueError("checked toolchain differs from build binding")
            qemu = ROOT / "build/toolchain/bin/qemu-system-x86_64"
            emulator_data = build_tools.regular_bytes(qemu)
            emulator_sha256 = build_tools.digest(emulator_data)
            if emulator_sha256 != setup["verified_tools"]["qemu"]["sha256"]:
                raise ValueError("pinned emulator differs")
            firmware = {}
            for name in ("code", "vars"):
                ref = setup["firmware"][name]
                data = build_tools.regular_bytes(ROOT / "build/uefi" / ref["path"])
                if build_tools.digest(data) != ref["sha256"] or len(data) != ref["size_bytes"]:
                    raise ValueError("pinned firmware differs")
                target = out / "firmware" / (name + ".fd")
                build_tools.write_bytes(target, data)
                target.chmod(0o444)
                retained[target] = data
                firmware[name] = data
            disk = build_tools.regular_bytes(out / "build/boot.img")
            efi = build_tools.regular_bytes(out / "build/BOOTX64.EFI")
            if disk != kernel.make_disk(efi):
                raise ValueError("boot disk differs from registered EFI")
            registration = {"schema_version": 1, "kind": "native_kernel_benchmark_registration",
                            "created_at_utc": datetime.now(timezone.utc).isoformat(),
                            "evidence_scope": build_tools.SCOPE, "native_qualification": False,
                            "capture_origin": "local_runner_claim_unverified_offline",
                            "build_manifest": build_tools.reference(out / "build/manifest.json", out),
                            "files": [build_tools.reference(path, out) for path in sorted(retained)],
                            "config": build_tools.CONFIG.copy(), "command": qemu_command(),
                            "limits": {"timeout_seconds": timeout, "max_log_bytes": max_log_bytes},
                            "runtime": {"setup": setup, "emulator_sha256": emulator_sha256},
                            "profile_sha256": manifest["profile"]["sha256"]}
            build_tools.write_json(out / "registration.json", registration)
            registration_data = build_tools.regular_bytes(out / "registration.json")
            result["registration_sha256"] = build_tools.digest(registration_data)
            retained[out / "registration.json"] = registration_data
            build_tools.unchanged(retained)
            if build_tools.regular_bytes(qemu) != emulator_data:
                raise ValueError("emulator changed before launch")
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise ValueError("capture deadline exhausted before launch")
            with tempfile.TemporaryDirectory(prefix="tessryn-native-bench-", dir=Path("/tmp").resolve()) as temporary:
                scratch = Path(temporary)
                scratch.chmod(0o700)
                for filename, data in (("code.fd", firmware["code"]), ("vars.fd", firmware["vars"]), ("boot.img", disk)):
                    build_tools.write_bytes(scratch / filename, data)
                command = launcher_command(qemu, qemu_command()[1:], scratch)
                execution = runtime["process"].run_bounded(command, scratch, remaining, max_log_bytes)
            execution_receipt = build_tools.receipt(execution, out, "qemu", exact=True)
            build_tools.write_json(out / "run_receipts.json", {"schema_version": 1, "execution": execution_receipt})
            build_tools.unchanged(retained)
            if build_tools.regular_bytes(qemu) != emulator_data or kernel.verify_installation() != setup:
                raise ValueError("checked emulator, firmware, compiler or libraries changed during capture")
            if execution.status != "completed":
                raise ValueError("bounded emulator capture failed: " + execution.status)
            summary = verifier.verify_packet(out, require_result=False,
                                              expected_registration_sha256=result["registration_sha256"])
            result.update(status="observed", valid=True, summary=summary,
                          reason="captured original kernel completed fixed raw-counter protocol in pinned single-CPU QEMU")
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as error:
        reason = "capture rejected: " + (str(error) if isinstance(error, ValueError) else type(error).__name__)
        result["reason"] = build_tools.public_log(reason.encode()).decode()[:1024]
    if execution_receipt is None:
        # Failed setup still has an explicit execution receipt and empty logs.
        from types import SimpleNamespace
        execution_receipt = build_tools.receipt(SimpleNamespace(status="unavailable", reason="capture did not start",
            returncode=None, elapsed_seconds=0.0, stdout=b"", stderr=b""), out, "qemu", exact=True)
        build_tools.write_json(out / "run_receipts.json", {"schema_version": 1, "execution": execution_receipt})
    build_tools.write_json(out / "result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-qemu", action="store_true")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--max-log-bytes", type=int, default=262144)
    args = parser.parse_args()
    try:
        result = run(args.manifest, args.out, allow_qemu=args.allow_qemu,
                     timeout=args.timeout, max_log_bytes=args.max_log_bytes)
    except (OSError, ValueError) as error:
        parser.exit(2, "native benchmark run setup rejected: " + type(error).__name__ + "\n")
    print(json.dumps({"status": result["status"], "valid": result["valid"],
                      "evidence_scope": result["evidence_scope"], "reason": result["reason"]}))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
