#!/usr/bin/env python3
"""Exercise actual high live addresses with a bounded, isolated QEMU child."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_fixture import sha256
from tools.build_kernel import HIGH_PROFILES, high_case_flags
from tools.g03.evidence import parse_json, _regular_bytes
from tools.g03.process import run_bounded
from tools.k01_media import make_disk
from tools.run_kernel import artifact_bytes, check_transcript, evaluator_hash as baseline_evaluator_hash, qemu_command as baseline_command
from tools.setup_uefi import verify_installation

FOUR_GIB = 1 << 32
MEMORY_BYTES = 8 << 30
GUARD_ADDRESS = 0x7FFFFFE00000  # Last 2 MiB of the lower canonical half is reserved.
RANGE_FIELDS = ("image_start", "image_end", "stack_start", "stack_end", "map_start", "map_end",
                "scratch", "runtime_high", "gop_start", "gop_end")
PASS_REASON = "ordered handoff, actual address admission, owned memory and expected case exit matched"
RESULT_SCOPE = "QEMU q35/TCG OVMF actual live image/handoff; physical hardware unqualified"


def evaluator_hash() -> str:
    digest = hashlib.sha256(baseline_evaluator_hash().encode())
    for name in ("tools/run_kernel_high.py", "tools/verify_kernel_high.py", "kernel/paging.rs"):
        digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes() + b"\0")
    return digest.hexdigest()


def qemu_command(name: str) -> list[str]:
    command = baseline_command(HIGH_PROFILES[name]["case"], "img")
    command[command.index("-m") + 1] = "8G"
    # Each run writes only its freshly copied disk inside the owned directory.
    command[command.index("if=ide,format=raw,snapshot=on,media=disk,file=boot.img")] = "if=ide,format=raw,media=disk,file=boot.img"
    return command


def unique_marker(data: bytes, marker: bytes) -> tuple[int, dict[str, str]]:
    matches = list(re.finditer(rb"(?m)^" + re.escape(marker) + rb"(?: [^\r\n]*)?$", data))
    if len(matches) != 1:
        raise ValueError(f"exactly one {marker.decode()} marker required")
    fields = {}
    for token in matches[0].group().split()[1:]:
        if token.count(b"=") != 1:
            raise ValueError("malformed live diagnostic field")
        key, value = token.decode("ascii").split("=", 1)
        if key in fields:
            raise ValueError("duplicate live diagnostic field")
        fields[key] = value
    return matches[0].start(), fields


def parse_address(value: str) -> int:
    if re.fullmatch(r"0x[0-9a-f]+", value) is None:
        raise ValueError("live address must be an explicit hexadecimal integer")
    return int(value, 16)


def final_admission(stdout: bytes) -> tuple[bytes, int]:
    """Bind the final successful map while allowing documented firmware retries."""
    exits = list(re.finditer(rb"(?m)^TESSRYN_K01_EXIT_BOOT_SERVICES_OK$", stdout))
    if len(exits) != 1:
        raise ValueError("exactly one successful firmware exit required")
    end = exits[0].start()
    starts = [row.start() for row in re.finditer(rb"(?m)^TESSRYN_K01_LIVE_RANGES(?: |$)", stdout[:end])]
    if not 1 <= len(starts) <= 8:
        raise ValueError("firmware map attempt count is invalid")
    for i, start in enumerate(starts):
        group = stdout[start:starts[i + 1] if i + 1 < len(starts) else end]
        live, _ = unique_marker(group, b"TESSRYN_K01_LIVE_RANGES")
        paging, _ = unique_marker(group, b"TESSRYN_K01_PAGING_READY")
        reset, _ = unique_marker(group, b"TESSRYN_K01_RESET_POINTER")
        memory, fields = unique_marker(group, b"TESSRYN_K01_MEMORY_MAP_VALID")
        if not live < paging < reset < memory or fields.get("attempt") != str(i + 1):
            raise ValueError("firmware admission attempt order differs")
        retries = list(re.finditer(rb"(?m)^TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY$", group))
        if len(retries) != (1 if i + 1 < len(starts) else 0) or retries and retries[0].start() <= memory:
            raise ValueError("firmware retry witness is incomplete")
    return stdout[:starts[0]] + stdout[starts[-1]:], len(starts)


def check_high_transcript(name: str, stdout: bytes, returncode: int | None, stderr: bytes) -> dict:
    """Require addresses actually printed by the booted kernel, not RAM size."""
    profile = HIGH_PROFILES[name]
    if not check_transcript(profile["case"], stdout, returncode, stderr):
        raise ValueError("ordered handoff or expected case result did not match")
    stdout, attempts = final_admission(stdout)
    position, fields = unique_marker(stdout, b"TESSRYN_K01_LIVE_RANGES")
    if set(fields) != set(RANGE_FIELDS) or re.fullmatch(r"[0-9]+", fields["runtime_high"]) is None:
        raise ValueError("live range diagnostic layout differs")
    observed = {key: int(value) if key == "runtime_high" else parse_address(value) for key, value in fields.items()}
    if not stdout.find(b"TESSRYN_K01_ENTRY") < position < stdout.find(b"TESSRYN_K01_EXIT_BOOT_SERVICES_OK"):
        raise ValueError("live range admission must precede firmware exit")
    ranges = []
    for prefix in ("image", "stack", "map", "gop"):
        start, end = observed[prefix + "_start"], observed[prefix + "_end"]
        if not 0 < start < end <= 1 << 47:
            raise ValueError("live range is empty, overflowing or noncanonical")
        if prefix != "gop" and (start % 4096 or end % 4096):
            raise ValueError("live allocation must be page aligned")
        if prefix != "gop":
            ranges.append((start, end))
    for i, first in enumerate(ranges):
        if any(first[0] < other[1] and other[0] < first[1] for other in ranges[:i]):
            raise ValueError("live allocations overlap")
    scratch = observed["scratch"]
    if not 0 < scratch < (1 << 47) - 4096 or scratch % 4096:
        raise ValueError("owned scratch page is invalid")
    if any(scratch < end and start < scratch + 4096 for start, end in ranges):
        raise ValueError("owned scratch overlaps a live allocation")
    if profile["low_image"]:
        if observed["image_end"] > FOUR_GIB or scratch >= FOUR_GIB:
            raise ValueError("ordinary high RAM control must keep its live image and scratch low")
    elif observed["image_start"] < FOUR_GIB:
        raise ValueError("high RAM did not place the actual live image above 4 GiB")
    if profile["high_handoff"] and any(observed[key] < FOUR_GIB for key in ("stack_start", "map_start", "scratch")):
        raise ValueError("forced high handoff did not use actual high allocations")
    owned_position, owned = unique_marker(stdout, b"TESSRYN_K01_CPU_OWNED")
    cr3, rsp = parse_address(owned["cr3"]), parse_address(owned["rsp"])
    if not observed["image_start"] <= cr3 < observed["image_end"] or cr3 % 4096:
        raise ValueError("owned CR3 does not belong to the admitted kernel image")
    if not observed["stack_start"] <= rsp < observed["stack_end"]:
        raise ValueError("owned RSP does not belong to the admitted stack")
    if not observed["image_start"] <= parse_address(owned["rip"]) < observed["image_end"]:
        raise ValueError("post-CR3 instruction did not execute from the admitted image")
    paging_position, paging = unique_marker(stdout, b"TESSRYN_K01_PAGING_READY")
    if not position < paging_position < stdout.find(b"TESSRYN_K01_EXIT_BOOT_SERVICES_OK"):
        raise ValueError("paging preparation must precede firmware exit")
    if (parse_address(paging["cr3"]) != cr3 or parse_address(paging["guard"]) != GUARD_ADDRESS
            or paging.get("free_scope") != "low-conventional"
            or any(re.fullmatch(r"[0-9]+", paging[key]) is None for key in ("tables", "leaves", "physical_bits"))
            or not 1 <= int(paging["tables"]) <= 128 or not 1 <= int(paging["leaves"]) <= 16384
            or not 32 <= int(paging["physical_bits"]) <= 52):
        raise ValueError("prepared paging identity or bounds differ")
    reset_position, reset = unique_marker(stdout, b"TESSRYN_K01_RESET_POINTER")
    if not paging_position < reset_position < stdout.find(b"TESSRYN_K01_EXIT_BOOT_SERVICES_OK") or reset.get("method") != "uefi-runtime":
        raise ValueError("runtime reset pointer must be admitted before firmware exit")
    observed.update(reset_pointer=parse_address(reset["address"]), physical_bits=int(paging["physical_bits"]),
                    paging_tables=int(paging["tables"]), paging_leaves=int(paging["leaves"]), guard=GUARD_ADDRESS,
                    exit_attempts=attempts)
    maximum = 1 << observed["physical_bits"]
    if any(observed[key] > maximum for key in ("image_end", "stack_end", "map_end", "gop_end")) or scratch + 4096 > maximum or not 0 < observed["reset_pointer"] < maximum:
        raise ValueError("admitted live range exceeds the observed CPU physical width")
    _, inventory = unique_marker(stdout, b"TESSRYN_K01_MEMORY_MAP_VALID")
    if (re.fullmatch(r"[0-9]+", inventory["descriptors"]) is None
            or not 0 <= observed["runtime_high"] <= int(inventory["descriptors"]) <= 4096):
        raise ValueError("runtime range count exceeds the observed descriptor inventory")
    scratch_position, owned_memory = unique_marker(stdout, b"TESSRYN_K01_MEMORY_OWNERSHIP_OK")
    if scratch_position <= owned_position or parse_address(owned_memory["scratch"]) != scratch:
        raise ValueError("post-CR3 owned memory readback did not use the admitted scratch")
    if any(owned_memory.get(key) != value for key, value in
           (("loader", "reserved"), ("runtime", "reserved"), ("firmware", "quarantined"))):
        raise ValueError("live memory ownership policy differs")
    if profile["high_handoff"]:
        high_position, high = unique_marker(stdout, b"TESSRYN_K01_HIGH_OWNERSHIP_OK")
        if high_position <= scratch_position or parse_address(high["scratch"]) != scratch or high.get("pattern") != "0x5445535352594e01":
            raise ValueError("high owned probe did not prove the post-CR3 readback")
    if profile["case"] in ("page_fault", "int3"):
        _, fault = unique_marker(stdout, b"TESSRYN_K01_EXCEPTION")
        if fault.get("error") != "0x0" or fault.get("cs") != "0x8":
            raise ValueError("exception frame differs from the owned supervisor context")
        if not observed["image_start"] <= parse_address(fault["rip"]) < observed["image_end"]:
            raise ValueError("exception instruction did not execute from the admitted image")
        if profile["case"] == "page_fault" and parse_address(fault["cr2"]) != GUARD_ADDRESS:
            raise ValueError("page fault must reach the explicit canonical unmapped guard")
    return observed


def read_manifest(path: Path) -> dict:
    manifest = parse_json(_regular_bytes(path))
    if manifest.get("schema_version") != 1 or manifest.get("artifact_type") != "tessryn-k01-high-kernel":
        raise ValueError("unsupported high kernel manifest")
    if manifest.get("profiles") != HIGH_PROFILES:
        raise ValueError("declared high profiles differ from evaluator")
    rows = manifest["artifacts"]
    expected = {f"{name}/{filename}" for name in HIGH_PROFILES for filename in ("BOOTX64.EFI", "boot.img")}
    if not isinstance(rows, list) or len(rows) != len(expected) or {row["path"] for row in rows} != expected:
        raise ValueError("high artifact set missing or duplicate")
    for name, profile in HIGH_PROFILES.items():
        flags, extra = high_case_flags(name)
        preferred = 0x10000000 if profile["low_image"] else 0x140000000
        for row in (row for row in rows if row["case"] == name):
            if row["rust_case_flags"] != flags or row["extra_rust_flags"] != extra or row["preferred_image_base"] != preferred:
                raise ValueError("high variant compilation profile differs")
    expected_notices = {"notices/tessryn-LICENSE", "notices/tessryn-NOTICE", "notices/rust-LICENSE-APACHE",
                        "notices/rust-LICENSE-MIT", "notices/rust-COPYRIGHT"}
    notices = manifest["notices"]
    if len(notices) != 5 or {row["path"] for row in notices} != expected_notices:
        raise ValueError("high redistribution notices incomplete or duplicate")
    for row in notices:
        data = _regular_bytes(path.parent / row["path"])
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
            raise ValueError("high redistribution notice differs")
    return manifest


def run(manifest_path: Path, out: Path, name: str, timeout: float = 30, max_log_bytes: int = 262144) -> dict:
    if name not in HIGH_PROFILES or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0 or type(max_log_bytes) is not int or max_log_bytes <= 0:
        raise ValueError("unsupported high profile or execution budget")
    out.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1, "format": "tessryn-k01-high-result", "variant": name,
              "case": HIGH_PROFILES[name]["case"], "status": "fail", "reason": "input validation incomplete",
              "manifest_sha256": None, "evaluator_sha256": evaluator_hash(), "observed_live_addresses": None,
              "execution": {"command": qemu_command(name), "memory_bytes": MEMORY_BYTES,
                            "timeout_seconds": timeout, "max_log_bytes": max_log_bytes,
                            "returncode": None, "elapsed_seconds": 0}, "logs": [],
              "scope": RESULT_SCOPE}
    stdout = stderr = b""
    try:
        result["manifest_sha256"] = sha256(manifest_path)
        manifest = read_manifest(manifest_path)
        setup = verify_installation()
        if manifest["toolchain"]["setup"] != setup:
            raise ValueError("high build toolchain differs from verified installation")
        efi = artifact_bytes(manifest_path, manifest, "BOOTX64.EFI", name)
        disk = artifact_bytes(manifest_path, manifest, "boot.img", name)
        if disk != make_disk(efi):
            raise ValueError("high media differs from selected kernel")
        qemu = ROOT / "build" / "toolchain" / "bin" / "qemu-system-x86_64"
        if sha256(qemu) != setup["verified_tools"]["qemu"]["sha256"]:
            raise ValueError("emulator changed during snapshot")
        result.update(firmware=setup["firmware"], emulator_sha256=sha256(qemu))
        with tempfile.TemporaryDirectory(prefix="tessryn-high-") as temporary:
            scratch = Path(temporary)
            for role, filename in (("code", "code.fd"), ("vars", "vars.fd")):
                row = setup["firmware"][role]
                data = _regular_bytes(ROOT / "build" / "uefi" / row["path"])
                if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
                    raise ValueError("firmware changed during snapshot")
                (scratch / filename).write_bytes(data)
            (scratch / "boot.img").write_bytes(disk)
            execution = run_bounded([str(qemu), *result["execution"]["command"][1:]], scratch, timeout, max_log_bytes)
        stdout, stderr = execution.stdout, execution.stderr
        result["execution"].update(returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
        result.update(status=execution.status, reason=execution.reason)
        if execution.status == "completed":
            result["observed_live_addresses"] = check_high_transcript(name, stdout, execution.returncode, stderr)
            result.update(status="pass", reason=PASS_REASON)
    except (OSError, ValueError, KeyError, TypeError) as error:
        detail = type(error).__name__ if isinstance(error, OSError) else str(error)
        result.update(status="fail", reason=f"high execution rejected: {detail}")
    for filename, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / filename).write_bytes(data)
        result["logs"].append({"path": filename, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--variant", choices=HIGH_PROFILES, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    try:
        result = run(args.manifest, args.out, args.variant, args.timeout)
    except (OSError, ValueError) as error:
        parser.exit(2, f"high runner rejected: {error}\n")
    print(json.dumps({"status": result["status"], "reason": result["reason"]}))
    return {"pass": 0, "timeout": 124, "log_limit": 125, "cancelled": 130}.get(result["status"], 1)


if __name__ == "__main__":
    raise SystemExit(main())
