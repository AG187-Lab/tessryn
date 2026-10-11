#!/usr/bin/env python3
"""Boot K01 in bounded QEMU/OVMF cases and retain hash-bound raw evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path, PurePosixPath
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_kernel import CASES, inspect_pe
from tools.build_fixture import sha256
from tools.g03.process import run_bounded
from tools.g03.evidence import parse_json, _regular_bytes
from tools.setup_uefi import verify_installation
from tools.k01_media import make_disk, make_iso

COMMON = ("TESSRYN_K01_ENTRY", "TESSRYN_K01_MEMORY_MAP_VALID",
          "TESSRYN_K01_EXIT_BOOT_SERVICES_OK", "TESSRYN_K01_CPU_OWNED",
          "TESSRYN_K01_MEMORY_OWNERSHIP_OK")
CASE_MARKERS = {"normal": "TESSRYN_K01_PASS", "int3": "TESSRYN_K01_EXCEPTION vector=3",
                "invalid_opcode": "TESSRYN_K01_EXCEPTION vector=6",
                "page_fault": "TESSRYN_K01_EXCEPTION vector=14",
                "panic": "TESSRYN_K01_PANIC", "reboot": "TESSRYN_K01_REBOOT_REQUEST"}


def evaluator_hash() -> str:
    digest = hashlib.sha256()
    for name in ("tools/run_kernel.py", "tools/verify_kernel.py", "tools/build_kernel.py", "tools/build_fixture.py",
                 "tools/k01_media.py", "tools/setup_uefi.py", "tools/setup_toolchain.py",
                 "tools/g03/process.py", "tools/g03/evidence.py", "toolchain.lock.json", "uefi-toolchain.lock.json"):
        digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes() + b"\0")
    return digest.hexdigest()


def check_transcript(case: str, data: bytes, returncode: int | None, stderr: bytes = b"") -> bool:
    """Require an ordered complete handoff and the expected case result."""
    at = 0
    markers = [*COMMON, CASE_MARKERS[case]]
    if case == "int3":
        markers.extend(("TESSRYN_K01_INT3_RECOVERED fp_state=preserved", "TESSRYN_K01_PASS"))
    elif case in ("invalid_opcode", "page_fault"):
        markers.append("TESSRYN_K01_EXPECTED_FAULT")
    for marker in markers:
        match = re.search(rb"(?m)^" + re.escape(marker.encode()) + rb"(?=\s|$)[^\r\n]*", data[at:])
        if match is None:
            return False
        at += match.end()
    if returncode != (0 if case == "reboot" else 33):
        return False
    if case == "reboot" and (b"CPU Reset" not in stderr or b"Triple fault" in stderr):
        return False
    return not any(marker in data for marker in (b"TESSRYN_K01_FAIL", b"TESSRYN_K01_UNEXPECTED"))


def artifact_bytes(manifest_path: Path, manifest: dict, name: str, case: str) -> bytes:
    """Read only a checked artifact beside its manifest, with no path traversal."""
    expected = f"{case}/{name}"
    entries = manifest["artifacts"]
    if not isinstance(entries, list) or not all(isinstance(row, dict) for row in entries):
        raise ValueError("malformed artifact table")
    rows = [row for row in entries if row.get("path") == expected]
    if len(rows) != 1:
        raise ValueError("selected artifact missing or duplicate")
    row = rows[0]
    relative = PurePosixPath(row["path"])
    if relative.parts != (case, name) or row.get("case") != case:
        raise ValueError("artifact case/path mismatch")
    directory = manifest_path.parent
    path = directory / expected
    if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
        raise ValueError("artifact must be a regular file")
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("kernel media exceeds size budget")
    data = _regular_bytes(path)
    if hashlib.sha256(data).hexdigest() != row.get("sha256") or len(data) != row.get("size_bytes"):
        raise ValueError("artifact hash or length mismatch")
    if name == "BOOTX64.EFI" and inspect_pe(data) != row.get("pe_validation"):
        raise ValueError("PE validation differs from manifest")
    return data


def qemu_command(case: str, media: str) -> list[str]:
    command = ["qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "qemu64",
               "-m", "256M", "-smp", "1", "-nodefaults", "-no-user-config",
               "-display", "none", "-monitor", "none", "-serial", "null", "-nic", "none",
               "-no-reboot", "-device", "VGA,romfile=", "-global", "apic.vapic=off",
               "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
               "-drive", "if=pflash,format=raw,file=vars.fd",
               "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    mode = "readonly=on,media=cdrom" if media == "iso" else "snapshot=on,media=disk"
    command += ["-drive", f"if=ide,format=raw,{mode},file=boot.{media}",
                "-boot", "order=d" if media == "iso" else "order=c"]
    if case == "reboot":
        command.extend(["-d", "cpu_reset"])
    return command


def run(manifest_path: Path, out: Path, case: str = "normal", media: str = "img",
        timeout: float = 30, max_log_bytes: int = 262144) -> dict:
    if case not in CASES or media not in ("img", "iso") or media == "iso" and case != "normal":
        raise ValueError("unsupported boot case/media")
    if not math.isfinite(timeout) or timeout <= 0 or type(max_log_bytes) is not int or max_log_bytes <= 0:
        raise ValueError("execution budgets must be positive")
    out.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1, "format": "tessryn-k01-result", "evidence_kind": "implementation_result",
              "case": case, "media": media, "status": "fail", "reason": "input validation incomplete",
              "manifest_sha256": None, "evaluator_sha256": evaluator_hash(),
              "execution": {"command": qemu_command(case, media), "timeout_seconds": timeout,
                            "max_log_bytes": max_log_bytes, "returncode": None, "elapsed_seconds": 0},
              "capabilities": {"kernel_boot": "unproven", "native_gpu": "unavailable",
                               "physical_hardware": "unavailable", "inference": "unavailable"}, "logs": []}
    stdout = stderr = b""
    try:
        manifest_bytes = _regular_bytes(manifest_path)
        if len(manifest_bytes) > 1024 * 1024:
            raise ValueError("manifest exceeds budget")
        result["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        manifest = parse_json(manifest_bytes)
        if manifest.get("schema_version") != 1 or manifest.get("artifact_type") != "tessryn-k01-kernel":
            raise ValueError("unsupported manifest")
        setup = verify_installation()
        if manifest["toolchain"]["setup"] != setup:
            raise ValueError("build toolchain differs from pinned installed toolchain")
        efi = artifact_bytes(manifest_path, manifest, "BOOTX64.EFI", case)
        disk = artifact_bytes(manifest_path, manifest, f"boot.{media}", case)
        if disk != (make_iso(efi) if media == "iso" else make_disk(efi)):
            raise ValueError("boot media differs from declared kernel")
        prefix = ROOT / "build" / "uefi"
        firmware = {name: (prefix / row["path"]).read_bytes() for name, row in setup["firmware"].items()}
        for name, data in firmware.items():
            if hashlib.sha256(data).hexdigest() != setup["firmware"][name]["sha256"]:
                raise ValueError("firmware changed during snapshot")
        qemu = ROOT / "build" / "toolchain" / "bin" / "qemu-system-x86_64"
        if sha256(qemu) != setup["verified_tools"]["qemu"]["sha256"]:
            raise ValueError("emulator changed during snapshot")
        result["firmware"] = setup["firmware"]
        result["emulator_sha256"] = sha256(qemu)
        with tempfile.TemporaryDirectory(prefix="tessryn-k01-") as temporary:
            scratch = Path(temporary)
            (scratch / "code.fd").write_bytes(firmware["code"])
            (scratch / "vars.fd").write_bytes(firmware["vars"])
            (scratch / f"boot.{media}").write_bytes(disk)
            execution = run_bounded([str(qemu), *result["execution"]["command"][1:]], scratch, timeout, max_log_bytes)
        stdout, stderr = execution.stdout, execution.stderr
        result["execution"].update(returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
        result["status"], result["reason"] = execution.status, execution.reason
        if execution.status == "completed":
            result["status"] = "pass" if check_transcript(case, stdout, execution.returncode, stderr) else "fail"
            result["reason"] = "ordered handoff, expected case marker and emulator exit matched" if result["status"] == "pass" else "case marker or emulator exit mismatch"
        if result["status"] == "pass":
            result["capabilities"]["kernel_boot"] = "verified_qemu_ovmf_only"
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["status"], result["reason"] = "fail", f"input/setup rejected: {type(error).__name__}"
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / name).write_bytes(data)
        result["logs"].append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    (out / "result.json.tmp").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (out / "result.json.tmp").replace(out / "result.json")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, default="normal")
    parser.add_argument("--media", choices=("img", "iso"), default="img")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-log-bytes", type=int, default=262144)
    args = parser.parse_args()
    try:
        result = run(args.manifest, args.out, args.case, args.media, args.timeout, args.max_log_bytes)
    except (OSError, ValueError) as error:
        parser.exit(2, f"kernel runner setup rejected: {error}\n")
    print(json.dumps({"status": result["status"], "reason": result["reason"]}))
    return {"pass": 0, "fail": 1, "unavailable": 2, "timeout": 124, "log_limit": 125, "cancelled": 130}.get(result["status"], 1)


if __name__ == "__main__":
    raise SystemExit(main())
