#!/usr/bin/env python3
"""Verify independent AWS-input builds and local headless boot/reset evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_fixture import sha256
from tools.build_kernel import CASES
from tools.g03.evidence import parse_json, _regular_bytes
from tools.run_aws_boot import check_serial, evaluator_hash, qemu_command, selected_artifact
from tools.setup_uefi import verify_installation

NOTICES = {"notices/tessryn-LICENSE", "notices/tessryn-NOTICE", "notices/rust-LICENSE-APACHE",
           "notices/rust-LICENSE-MIT", "notices/rust-COPYRIGHT"}
CAPABILITIES = {"aws_native_boot": "unqualified", "aws_recovery": "unqualified",
                "native_gpu": "unavailable", "network": "unavailable", "inference": "unavailable"}


def validate_build(path: Path) -> dict:
    manifest = parse_json(_regular_bytes(path))
    if manifest["toolchain"]["setup"] != verify_installation():
        raise ValueError("AWS manifest toolchain differs from current pinned tools")
    names = [row["path"] for row in manifest["artifacts"]]
    expected = {f"{case}/{name}" for case in CASES for name in ("BOOTX64.EFI", "boot.img")}
    if len(names) != len(expected) or set(names) != expected:
        raise ValueError("AWS artifact set incomplete or duplicate")
    plans = manifest.get("snapshot_input_plans", [])
    if len(plans) != len(CASES) or {row["path"] for row in plans} != {f"{case}/snapshot-inputs.json" for case in CASES}:
        raise ValueError("AWS snapshot input set incomplete")
    for case in CASES:
        selected_artifact(path, manifest, case)
    rows = manifest.get("notices", [])
    if len(rows) != len(NOTICES) or {row["path"] for row in rows} != NOTICES:
        raise ValueError("AWS notices incomplete or duplicate")
    for row in rows:
        data = _regular_bytes(path.parent / row["path"])
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
            raise ValueError("AWS notice integrity mismatch")
    return manifest


def validate_result(path: Path, manifest_path: Path, manifest: dict) -> dict:
    result = parse_json(_regular_bytes(path))
    case = result["case"]
    if (result.get("schema_version") != 1 or result.get("format") != "tessryn-aws-headless-result"
            or case not in CASES or result.get("status") != "pass"
            or result.get("reason") != "headless serial markers and independent control matched"
            or result.get("scope") != "QEMU TCG q35/OVMF only; native AWS unqualified"
            or result.get("capabilities") != CAPABILITIES):
        raise ValueError("AWS headless result does not prove its declared local scope")
    if result["manifest_sha256"] != sha256(manifest_path) or result["evaluator_sha256"] != evaluator_hash():
        raise ValueError("AWS result manifest/evaluator identity mismatch")
    setup = manifest["toolchain"]["setup"]
    if result.get("firmware") != setup["firmware"] or result.get("emulator_sha256") != setup["verified_tools"]["qemu"]["sha256"]:
        raise ValueError("AWS result firmware/emulator identity mismatch")
    for key, name in (("kernel_sha256", "BOOTX64.EFI"), ("disk_sha256", "boot.img")):
        rows = [row for row in manifest["artifacts"] if row["path"] == f"{case}/{name}"]
        if len(rows) != 1 or rows[0]["sha256"] != result.get(key):
            raise ValueError("AWS result artifact identity mismatch")
    log_rows = result["logs"]
    if len(log_rows) != 3 or {row["path"] for row in log_rows} != {"stdout.log", "stderr.log", "qmp.jsonl"}:
        raise ValueError("AWS raw logs incomplete or duplicate")
    logs = {}
    for row in log_rows:
        data = _regular_bytes(path.parent / row["path"])
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size_bytes"]:
            raise ValueError("AWS raw log integrity mismatch")
        logs[row["path"]] = data
    execution = result["execution"]
    timeout, elapsed, limit = (execution[key] for key in ("timeout_seconds", "elapsed_seconds", "max_log_bytes"))
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 90
            or isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed)
            or not 0 <= elapsed <= timeout + 1.5 or type(limit) is not int or not 0 < limit <= 1024 * 1024
            or len(logs["stdout.log"]) + len(logs["stderr.log"]) > limit
            or execution["command"] != qemu_command(case) or execution["returncode"] != 0
            or b"Triple fault" in logs["stderr.log"] or any(marker in logs["stdout.log"] for marker in
                                                           (b"TESSRYN_K01_FAIL", b"TESSRYN_K01_UNEXPECTED"))):
        raise ValueError("AWS execution bounds, fixed command or exit evidence mismatch")
    messages = [parse_json(line) for line in logs["qmp.jsonl"].splitlines() if line.strip()]
    if not messages or len(messages) > 1024 or not isinstance(messages[0].get("QMP"), dict):
        raise ValueError("AWS live control greeting missing")
    responses = [row for row in messages if "id" in row]
    if any("error" in row or "return" not in row for row in responses):
        raise ValueError("AWS control command failed")
    controls, phases = result["controls"], result["phases"]
    expected_controls = ["query-status"] if case == "reboot" else ["query-status", "stop", "query-status", "quit"]
    if case == "normal":
        expected_controls = ["query-status", "stop", "query-status", "system_reset", "query-status",
                             "cont", "stop", "query-status", "quit"]
    if [row["execute"] for row in controls] != expected_controls:
        raise ValueError("AWS independent control sequence incomplete")
    if [row.get("id") for row in responses] != list(range(1, len(controls) + 2)):
        raise ValueError("AWS raw control response sequence mismatch")
    previous_stdout = previous_stderr = 0
    for index, control in enumerate(controls, 2):
        if set(control) != {"execute", "id", "stdout_offset", "stderr_offset", "result"} or control["id"] != index:
            raise ValueError("AWS control identity mismatch")
        stdout, stderr = control["stdout_offset"], control["stderr_offset"]
        if (type(stdout) is not int or type(stderr) is not int
                or not previous_stdout <= stdout <= len(logs["stdout.log"])
                or not previous_stderr <= stderr <= len(logs["stderr.log"])):
            raise ValueError("AWS control log offsets invalid")
        previous_stdout, previous_stderr = stdout, stderr
        if responses[index - 1]["return"] != control["result"]:
            raise ValueError("AWS control disposition differs from raw response")
        if control["execute"] == "query-status":
            state = "running" if index == 2 else "paused"
            states = ("paused", "prelaunch") if case == "normal" and index == 6 else (state,)
            if control["result"].get("status") not in states or control["result"].get("running") != (state == "running"):
                raise ValueError("AWS host pause/liveness evidence missing")
    if len(phases) != (2 if case == "normal" else 1):
        raise ValueError("AWS boot phase evidence incomplete")
    end = 0
    for index, phase in enumerate(phases):
        start, finish = phase["stdout_begin"], phase["stdout_end"]
        if (set(phase) != {"index", "stdout_begin", "stdout_end"} or phase["index"] != index
                or type(start) is not int or type(finish) is not int or not end <= start < finish <= len(logs["stdout.log"])
                or index == 0 and start != 0 or not check_serial(case, logs["stdout.log"][start:finish])):
            raise ValueError("AWS serial phase lacks ordered fresh markers")
        end = finish
    if case == "normal":
        if phases[0]["stdout_end"] != controls[3]["stdout_offset"] or phases[1]["stdout_begin"] != controls[5]["stdout_offset"]:
            raise ValueError("AWS serial phases not separated by external reset control")
        # RESET must occur after the first confirmed pause and before resume.
        pause = next(index for index, row in enumerate(messages) if row.get("id") == controls[2]["id"])
        resume = next(index for index, row in enumerate(messages) if row.get("id") == controls[5]["id"])
        if not any(row.get("event") == "RESET" and row.get("data", {}).get("guest") is False
                   and row.get("data", {}).get("reason") == "host-qmp-system-reset"
                   for row in messages[pause + 1:resume]):
            raise ValueError("AWS second boot lacks a witnessed external reset")
    if case == "reboot" and b"CPU Reset" not in logs["stderr.log"]:
        raise ValueError("AWS runtime reset diagnostics absent")
    return result


def verify(first: Path, second: Path, results: list[Path]) -> dict:
    a, b = validate_build(first), validate_build(second)
    if a != b or a.get("source", {}).get("dirty") is not False:
        raise ValueError("AWS independent manifests differ or source is dirty")
    seen = set()
    for path in results:
        case = validate_result(path, first, a)["case"]
        if case in seen:
            raise ValueError("AWS result case duplicated")
        seen.add(case)
    if seen != set(CASES):
        raise ValueError("AWS local headless cases incomplete")
    return {"status": "pass", "format": "tessryn-aws-local-verification", "cases": sorted(seen),
            "manifest_sha256": sha256(first), "evaluator_sha256": evaluator_hash(),
            "scope": "deterministic AWS input media and QEMU headless serial/reset only; native AWS boot/recovery unqualified"}


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
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        parser.exit(1, f"AWS local verification rejected: {type(error).__name__}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
