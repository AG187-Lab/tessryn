#!/usr/bin/env python3
"""Preregister and retain a fresh bounded two-CPU contention capture."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import math
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.contention_benchmark_protocol import (SCOPE, COMPILER_SOURCES, RUNTIME_FILES, MAX_LOG_BYTES,
    require, digest, regular_bytes, read_ref, file_ref, strict_json, write_json, fresh_output,
    retain_private_error, runtime_hashes, canonical)
from tools.run_k03_smp import qemu_command, launcher_command
from tools.g03.process import run_bounded
from tools.setup_uefi import verify_installation
from tools.build_kernel import compiler_profile
LOADED_RUNTIME = runtime_hashes()


def run(manifest_path: Path, out: Path, *, allow_qemu=False, timeout=60) -> dict:
    require(type(allow_qemu) is bool and allow_qemu and type(timeout) in (int, float)
        and math.isfinite(timeout) and 0 < timeout <= 60, "contention execution requires explicit opt-in and bounded timeout")
    out = fresh_output(out)
    stdout = stderr = b""
    result = {"format": "tessryn-contention-result/v1", "status": "fail", "reason": "inputs incomplete",
        "scope": SCOPE, "hardware_qualified": False, "inference_qualified": False,
        "registration_sha256": None, "execution": {"status": "unavailable", "returncode": None, "elapsed_seconds": 0},
        "logs": [], "observations": None}
    try:
        from tools.verify_contention_benchmarks import validate_build, build_files, verify_packet
        manifest_path = Path(manifest_path).absolute()
        manifest_raw = regular_bytes(manifest_path, 2 << 20)
        manifest = validate_build(manifest_path)
        runtime = runtime_hashes()
        require(runtime == LOADED_RUNTIME and manifest["runtime_files"] == runtime
            and all(digest(regular_bytes(ROOT / name, 16 << 20)) == sha for name, sha in manifest["source_files"].items()),
            "contention build differs from trusted checkout; retained code is never imported")
        checked = compiler_profile()
        require(canonical(checked["toolchain"]) == canonical(manifest["toolchain"]), "contention checked compiler/libraries differ")
        copied = {}
        for name in build_files(manifest):
            data = regular_bytes(manifest_path.parent / name)
            target = out / "build" / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data); target.chmod(0o400); copied[target] = data
        require(regular_bytes(manifest_path, 2 << 20) == manifest_raw, "contention original manifest changed during copy")
        retained_manifest = validate_build(out / "build/manifest.json")
        require(canonical(retained_manifest) == canonical(manifest), "contention retained build differs")
        setup = verify_installation()
        require(canonical(setup) == canonical(manifest["toolchain"]["setup"]), "contention checked runtime setup differs")
        qemu = ROOT / "build/toolchain/bin/qemu-system-x86_64"
        qemu_sha = digest(regular_bytes(qemu, 256 << 20))
        require(qemu_sha == setup["verified_tools"]["qemu"]["sha256"], "contention pinned QEMU differs")
        launcher_sha = digest(regular_bytes(Path('/usr/bin/env'), 16 << 20))
        firmware = {}
        for role, name in (("code", "code.fd"), ("vars", "vars.fd"), ("notice", "NOTICE")):
            row = setup["firmware"][role]
            data = regular_bytes(ROOT / "build/uefi" / row["path"], 16 << 20)
            require(digest(data) == row["sha256"] and len(data) == row["size_bytes"], "contention firmware differs")
            target = out / "firmware" / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data); target.chmod(0o400); copied[target] = data; firmware[name] = data
        registration = {"format": "tessryn-contention-registration/v1", "scope": SCOPE,
            "hardware_qualified": False, "inference_qualified": False,
            "created_at_utc": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "capture_origin": "local_runner_claim_unverified_offline",
            "files": [file_ref(out, path) for path in sorted(copied)], "manifest_sha256": digest(manifest_raw),
            "runtime_files": runtime, "command": qemu_command(), "timeout_seconds": timeout,
            "max_log_bytes": MAX_LOG_BYTES, "emulator_sha256": qemu_sha, "launcher_sha256": launcher_sha, "setup": setup}
        write_json(out / "registration.json", registration)
        registration_raw = regular_bytes(out / "registration.json", 2 << 20)
        result["registration_sha256"] = digest(registration_raw)
        copied[out / "registration.json"] = registration_raw
        write_json(out / "result.json", result)
        with tempfile.TemporaryDirectory(prefix='tessryn-contention-', dir=Path('/tmp').resolve()) as temporary:
            scratch = Path(temporary); scratch.chmod(0o700)
            for name in ("code.fd", "vars.fd"): (scratch / name).write_bytes(firmware[name])
            (scratch / 'boot.img').write_bytes(regular_bytes(out / 'build/boot.img'))
            execution = run_bounded(launcher_command(qemu, scratch), scratch, timeout, MAX_LOG_BYTES)
        stdout, stderr = execution.stdout, execution.stderr
        result["execution"].update(status=execution.status, returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
        require(runtime_hashes() == runtime and all(regular_bytes(path) == data for path, data in copied.items())
            and regular_bytes(manifest_path, 2 << 20) == manifest_raw
            and digest(regular_bytes(qemu, 256 << 20)) == qemu_sha
            and digest(regular_bytes(Path('/usr/bin/env'), 16 << 20)) == launcher_sha
            and canonical(verify_installation()) == canonical(setup), "contention checked capture inputs changed")
        for row in manifest["artifacts"]: read_ref(manifest_path.parent, row)
        require(execution.status == 'completed' and execution.returncode == 33, "contention bounded capture failed")
        for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
            (out / name).write_bytes(data)
        result["logs"] = [file_ref(out, out / n) for n in ("stdout.log", "stderr.log")]
        write_json(out / "result.json", result)
        observations = verify_packet(out, require_result=False)
        result.update(status="pass", reason="original SMP stop and bounded contention protocol matched", observations=observations)
    except (OSError, ValueError, KeyError, TypeError, ImportError, RecursionError, subprocess.SubprocessError) as error:
        retain_private_error(out, error)
        result.update(status="fail", reason="contention capture rejected: " + type(error).__name__, observations=None)
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / name).write_bytes(data)
    result["logs"] = [file_ref(out, out / n) for n in ("stdout.log", "stderr.log")]
    write_json(out / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True); parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-qemu", action="store_true"); parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    try: result = run(args.manifest, args.out, allow_qemu=args.allow_qemu, timeout=args.timeout)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, "contention capture setup rejected: " + type(error).__name__ + "\n")
    print(canonical({key: result[key] for key in ("status", "reason", "scope", "hardware_qualified", "inference_qualified")}))
    return 0 if result["status"] == "pass" else 1

if __name__ == "__main__": raise SystemExit(main())
