#!/usr/bin/env python3
"""Verify two independent K01 builds and retained per-case emulator evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_kernel import CASES
from tools.build_fixture import sha256
from tools.k01_media import make_disk, make_iso
from tools.run_kernel import artifact_bytes, check_transcript, evaluator_hash, qemu_command
from tools.setup_uefi import verify_installation
from tools.g03.evidence import parse_json, _regular_bytes


def validate_build(path: Path) -> dict:
    manifest = parse_json(_regular_bytes(path))
    if manifest.get("schema_version") != 1 or manifest.get("artifact_type") != "tessryn-k01-kernel":
        raise ValueError("unsupported kernel manifest")
    if manifest["toolchain"]["setup"] != verify_installation():
        raise ValueError("manifest setup differs from pinned installed tools")
    expected = {f"{case}/{name}" for case in (*CASES, "deployment") for name in ("BOOTX64.EFI", "boot.img")}
    expected.update(("normal/boot.iso", "deployment/boot.iso"))
    names = [row["path"] for row in manifest["artifacts"]]
    if len(names) != len(expected) or set(names) != expected:
        raise ValueError("kernel artifact set incomplete or duplicate")
    for case in (*CASES, "deployment"):
        efi = artifact_bytes(path, manifest, "BOOTX64.EFI", case)
        if artifact_bytes(path, manifest, "boot.img", case) != make_disk(efi):
            raise ValueError("disk does not contain declared kernel")
        if case in ("normal", "deployment") and artifact_bytes(path, manifest, "boot.iso", case) != make_iso(efi):
            raise ValueError("ISO does not contain declared kernel")
    return manifest


def validate_result(path: Path, manifest_path: Path, manifest: dict) -> dict:
    result = parse_json(_regular_bytes(path))
    case, media = result["case"], result["media"]
    if result.get("schema_version") != 1 or result.get("format") != "tessryn-k01-result" or case not in CASES or media not in ("iso", "img"):
        raise ValueError("unsupported kernel result")
    if result["manifest_sha256"] != sha256(manifest_path) or result["evaluator_sha256"] != evaluator_hash():
        raise ValueError("result manifest/evaluator identity mismatch")
    if result["execution"]["command"] != qemu_command(case, media):
        raise ValueError("execution command mismatch")
    setup = manifest["toolchain"]["setup"]
    if result.get("firmware") != setup["firmware"] or result.get("emulator_sha256") != setup["verified_tools"]["qemu"]["sha256"]:
        raise ValueError("emulator or firmware mismatch")
    rows = result["logs"]
    if not isinstance(rows, list) or len(rows) != 2 or {row["path"] for row in rows} != {"stdout.log", "stderr.log"}:
        raise ValueError("raw evidence logs incomplete")
    logs = {}
    for row in rows:
        log = path.parent / row["path"]
        if log.is_symlink() or not log.is_file():
            raise ValueError("log must be a regular file")
        data = _regular_bytes(log)
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
            raise ValueError("raw log identity mismatch")
        logs[row["path"]] = data
    execution = result["execution"]
    timeout, elapsed, budget = execution["timeout_seconds"], execution["elapsed_seconds"], execution["max_log_bytes"]
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0
            or isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0
            or elapsed > timeout + 1.5 or type(budget) is not int or budget <= 0
            or sum(map(len, logs.values())) > budget):
        raise ValueError("invalid execution budget or elapsed/log metadata")
    passed = check_transcript(case, logs["stdout.log"], result["execution"]["returncode"], logs["stderr.log"])
    if result["status"] != "pass" or not passed or result["capabilities"] != {
        "kernel_boot": "verified_qemu_ovmf_only", "native_gpu": "unavailable",
        "physical_hardware": "unavailable", "inference": "unavailable"}:
        raise ValueError("case did not prove its expected behavior")
    if result.get("reason") != "ordered handoff, expected case marker and emulator exit matched":
        raise ValueError("pass reason differs from evaluator")
    return result


def verify(first: Path, second: Path, results: list[Path]) -> dict:
    a, b = validate_build(first), validate_build(second)
    if a != b:
        raise ValueError("independent kernel manifests differ")
    seen = set()
    for path in results:
        result = validate_result(path, first, a)
        key = (result["case"], result["media"])
        if key in seen:
            raise ValueError("duplicate execution result")
        seen.add(key)
    expected = {(case, "img") for case in CASES} | {("normal", "iso")}
    if seen != expected:
        raise ValueError("required boot/fault/panic/reboot/media cases incomplete")
    return {"status": "pass", "format": "tessryn-k01-verification", "manifest_sha256": sha256(first),
            "evaluator_sha256": evaluator_hash(), "cases": sorted([list(row) for row in seen]),
            "scope": "QEMU TCG q35/OVMF, original UEFI kernel; physical GPU Mart and GPU execution unqualified"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--result", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.first, args.second, args.result)
        if args.out:
            with args.out.open("x") as stream:
                stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"kernel verification rejected: {error}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
