#!/usr/bin/env python3
"""Run one fresh K02 UEFI single-CPU experiment with bounded pinned QEMU."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_k02_native import ARTIFACT_TYPE, CASES, PROFILE, SCOPE
from tools.build_fixture import sha256
from tools.g03.process import run_bounded
from tools.k01_media import make_disk
from tools.run_kernel import _regular_bytes, artifact_bytes
from tools.setup_uefi import verify_installation

FORMAT = "tessryn-k02-native-result/v1"
PASS_REASON = "fresh pinned emulator, exact CPL3 probe and owned trap evidence matched"
EVALUATOR_FILES = ("tools/run_k02_native.py", "tools/verify_k02_native.py", "tools/build_k02_native.py",
                   "tools/g03/process.py", "tools/setup_uefi.py", "tools/run_kernel.py", "tools/build_kernel.py", "tools/k01_media.py",
                   "tools/build_fixture.py", "tools/setup_toolchain.py", "tools/g03/evidence.py",
                   "toolchain.lock.json", "uefi-toolchain.lock.json")


def evaluator_hash() -> str:
    digest = hashlib.sha256()
    for name in EVALUATOR_FILES:
        digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes() + b"\0")
    return digest.hexdigest()


def qemu_command() -> list[str]:
    return ["qemu-system-x86_64", "-machine", PROFILE["machine"], "-cpu", PROFILE["cpu"],
            "-m", "256M", "-smp", "1", "-nodefaults", "-no-user-config", "-display", "none",
            "-monitor", "none", "-serial", "null", "-nic", "none", "-no-reboot",
            "-device", "VGA,romfile=", "-global", "apic.vapic=off",
            "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
            "-drive", "if=pflash,format=raw,file=vars.fd",
            "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-drive", "if=ide,format=raw,snapshot=on,file=boot.img", "-boot", "order=c"]


def launcher_command(executable: Path, arguments: list[str], scratch: Path) -> list[str]:
    """Use env's exec, retaining the bounded launcher's owned session/PID."""
    info = scratch.lstat()
    if not scratch.is_absolute() or scratch.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("child temporary storage must be fresh private regular directory")
    if not executable.is_absolute() or executable.is_symlink() or not executable.is_file():
        raise ValueError("child tool must have a checked absolute regular path")
    env = Path('/usr/bin/env')
    if env.is_symlink() or not env.is_file():
        raise ValueError("system env launcher must be regular")
    return [str(env), 'TMPDIR=' + str(scratch), str(executable), *arguments]


def check_transcript(case: str, stdout: bytes, returncode: int | None,
                     stderr: bytes, probe: dict) -> dict:
    # The concrete serial contract is supplied by the original privileged core;
    # acceptance remains independent of the runner's status field.
    from tools.verify_k02_native import parse_transcript
    return parse_transcript(case, stdout, returncode, stderr, probe)


def run(manifest_path: Path, out: Path, case: str, timeout: float = 30,
        max_log_bytes: int = 262144) -> dict:
    if case not in CASES or isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60 or type(max_log_bytes) is not int or not 0 < max_log_bytes <= 1_048_576:
        raise ValueError("unsupported case or execution budgets")
    out.mkdir(parents=True, exist_ok=False)
    result = {"format": FORMAT, "case": case, "status": "fail", "reason": "inputs incomplete",
              "manifest_sha256": None, "evaluator_sha256": evaluator_hash(), "scope": SCOPE,
              "execution": {"command": qemu_command(), "timeout_seconds": timeout,
                            "max_log_bytes": max_log_bytes, "returncode": None, "elapsed_seconds": 0},
              "observations": None, "logs": []}
    stdout = stderr = b""
    try:
        raw = _regular_bytes(manifest_path)
        if len(raw) > 2 << 20:
            raise ValueError("K02 manifest exceeds bound")
        manifest = json.loads(raw)
        result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        if manifest["artifact_type"] != ARTIFACT_TYPE or manifest["profile"] != PROFILE or manifest["cases"] != list(CASES) or manifest["scope"] != SCOPE:
            raise ValueError("K02 build profile differs")
        setup = verify_installation()
        if manifest["toolchain"]["setup"] != setup:
            raise ValueError("K02 build differs from checked UEFI target/sysroot")
        efi = artifact_bytes(manifest_path, manifest, "BOOTX64.EFI", case)
        disk = artifact_bytes(manifest_path, manifest, "boot.img", case)
        if disk != make_disk(efi):
            raise ValueError("K02 boot media differs from declared EFI")
        result["firmware"] = setup["firmware"]
        qemu = ROOT / "build/toolchain/bin/qemu-system-x86_64"
        result["emulator_sha256"] = sha256(qemu)
        if result["emulator_sha256"] != setup["verified_tools"]["qemu"]["sha256"]:
            raise ValueError("pinned QEMU changed")
        with tempfile.TemporaryDirectory(prefix="tessryn-k02-", dir=Path('/tmp').resolve()) as temp:
            scratch = Path(temp)
            for role in ("code", "vars"):
                row = setup["firmware"][role]
                data = _regular_bytes(ROOT / "build/uefi" / row["path"])
                if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
                    raise ValueError("firmware changed before fresh snapshot")
                (scratch / (role + ".fd")).write_bytes(data)
            (scratch / "boot.img").write_bytes(disk)
            actual = launcher_command(qemu, qemu_command()[1:], scratch)
            env_digest = sha256(Path('/usr/bin/env'))
            result['execution']['launcher'] = {'executable':'/usr/bin/env', 'sha256':env_digest,
                'command':['/usr/bin/env', 'TMPDIR=' + str(scratch), *qemu_command()],
                'tool_path_record':'absolute hash-checked QEMU executed; command displays its pinned role',
                'temporary_directory':str(scratch), 'temporary_scope':'fresh private owned directory removed after child reap'}
            execution = run_bounded(actual, scratch, timeout, max_log_bytes)
            if sha256(Path('/usr/bin/env')) != env_digest:
                raise ValueError("system launcher changed during execution")
        stdout, stderr = execution.stdout, execution.stderr
        result["execution"].update(returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
        result["status"], result["reason"] = execution.status, execution.reason
        if execution.status == "completed":
            result["observations"] = check_transcript(case, stdout, execution.returncode, stderr, manifest["probes"][case])
            result["status"], result["reason"] = "pass", PASS_REASON
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["status"], result["reason"] = "fail", f"K02 input or observed execution rejected: {type(error).__name__}"
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / name).write_bytes(data)
        result["logs"].append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    result = run(args.manifest, args.out, args.case, args.timeout)
    print(json.dumps({"status": result["status"], "case": result["case"], "reason": result["reason"], "scope": SCOPE}))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
