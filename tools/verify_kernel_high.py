#!/usr/bin/env python3
"""Verify reproducible high-profile builds and all declared address regressions."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_fixture import sha256
from tools.build_kernel import HIGH_PROFILES
from tools.g03.evidence import parse_json, _regular_bytes
from tools.k01_media import make_disk
from tools.run_kernel import artifact_bytes
from tools.run_kernel_high import (MEMORY_BYTES, PASS_REASON, RESULT_SCOPE, check_high_transcript,
                                   evaluator_hash, qemu_command, read_manifest)
from tools.setup_uefi import verify_installation


def validate_build(path: Path) -> dict:
    manifest = read_manifest(path)
    if manifest["toolchain"]["setup"] != verify_installation():
        raise ValueError("high manifest setup differs from installed pinned tools")
    for name in HIGH_PROFILES:
        efi = artifact_bytes(path, manifest, "BOOTX64.EFI", name)
        offset = struct.unpack_from("<I", efi, 60)[0]
        preferred = struct.unpack_from("<Q", efi, offset + 48)[0]
        row = next(row for row in manifest["artifacts"] if row["path"] == f"{name}/BOOTX64.EFI")
        if preferred != row["preferred_image_base"]:
            raise ValueError("actual PE preferred image address differs from declaration")
        if artifact_bytes(path, manifest, "boot.img", name) != make_disk(efi):
            raise ValueError("high media does not contain declared kernel")
    return manifest


def validate_result(path: Path, manifest_path: Path, manifest: dict) -> dict:
    result = parse_json(_regular_bytes(path))
    name = result["variant"]
    if result.get("schema_version") != 1 or result.get("format") != "tessryn-k01-high-result" or name not in HIGH_PROFILES:
        raise ValueError("unsupported high result")
    if result["case"] != HIGH_PROFILES[name]["case"] or result["manifest_sha256"] != sha256(manifest_path) or result["evaluator_sha256"] != evaluator_hash():
        raise ValueError("high result identity differs")
    setup = manifest["toolchain"]["setup"]
    if result["emulator_sha256"] != setup["verified_tools"]["qemu"]["sha256"] or result["firmware"] != setup["firmware"]:
        raise ValueError("high emulator/firmware differs from build")
    execution = result["execution"]
    if execution["command"] != qemu_command(name) or execution["memory_bytes"] != MEMORY_BYTES:
        raise ValueError("high execution command or memory profile differs")
    timeout, elapsed, budget = (execution[key] for key in ("timeout_seconds", "elapsed_seconds", "max_log_bytes"))
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0
            or isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed)
            or not 0 <= elapsed <= timeout + 1.5 or type(budget) is not int or budget <= 0):
        raise ValueError("high execution budget or elapsed metadata invalid")
    rows = result["logs"]
    if not isinstance(rows, list) or len(rows) != 2 or {row["path"] for row in rows} != {"stdout.log", "stderr.log"}:
        raise ValueError("high raw logs missing or duplicate")
    logs = {}
    for row in rows:
        data = _regular_bytes(path.parent / row["path"])
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
            raise ValueError("high raw log hash or size differs")
        logs[row["path"]] = data
    if sum(map(len, logs.values())) > budget:
        raise ValueError("high raw logs exceed declared budget")
    observed = check_high_transcript(name, logs["stdout.log"], execution["returncode"], logs["stderr.log"])
    if result["status"] != "pass" or result["reason"] != PASS_REASON or result["observed_live_addresses"] != observed or result["scope"] != RESULT_SCOPE:
        raise ValueError("high result does not match actual observed address evidence")
    return result


def verify(first: Path, second: Path, results: list[Path]) -> dict:
    a, b = validate_build(first), validate_build(second)
    if _regular_bytes(first) != _regular_bytes(second) or a != b:
        raise ValueError("independent high kernel manifests differ")
    seen = {}
    for path in results:
        result = validate_result(path, first, a)
        if result["variant"] in seen:
            raise ValueError("duplicate high execution variant")
        seen[result["variant"]] = result["observed_live_addresses"]
    if set(seen) != set(HIGH_PROFILES):
        raise ValueError("required high image/handoff/control results incomplete")
    return {"status": "pass", "format": "tessryn-k01-high-verification", "manifest_sha256": sha256(first),
            "evaluator_sha256": evaluator_hash(), "observed_live_addresses": seen,
            "scope": "actual high image/stack/map/scratch in pinned QEMU OVMF; runtime/GOP high edges separately labeled fixtures; physical hardware unqualified"}


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
        parser.exit(1, f"high verification rejected: {error}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
