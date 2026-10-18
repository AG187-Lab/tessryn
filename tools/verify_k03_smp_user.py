#!/usr/bin/env python3
"""Independently replay source, twin binaries, host checks and all raw SMP user cases."""
from __future__ import annotations
import argparse
from datetime import datetime
import math
from pathlib import Path
import re
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from tools.k03_smp_user_protocol import (CASES, PROFILE, ARTIFACT_TYPE, FORMAT, SCOPE, MAX_LOG_BYTES,
    require, digest, regular_bytes, read_ref, strict_json, write_json)
from tools.k03_smp_user_provenance import COMPILER_SOURCES, RUNTIME_FILES, canonical, runtime_hashes, committed_sources, validate_source, validate_toolchain
from tools.build_k03_smp_user import coff_binding
from tools.k03_smp_user_trace import parse_transcript
from tools.k01_media import make_disk


def completed(row):
    return (row.get("status") == "completed" and type(row.get("returncode")) is int and row["returncode"] == 0
        and type(row.get("elapsed_seconds")) in (int, float) and math.isfinite(row["elapsed_seconds"]) and 0 <= row["elapsed_seconds"] <= 92)


def validate_notices(root, notices, setup):
    names = ("tessryn-LICENSE", "tessryn-NOTICE", "rust-LICENSE-APACHE", "rust-LICENSE-MIT", "rust-COPYRIGHT")
    require(type(notices) is list and len(notices) == 5 and {r.get("path") for r in notices if type(r) is dict} == {"notices/" + n for n in names}, "SMP user notice allowlist differs")
    for row in notices:
        require(type(row) is dict and set(row) == {"component", "path", "sha256", "size_bytes"}, "SMP user notice fields differ")
        data = read_ref(root, row, 4 << 20); component, name = row["path"].removeprefix("notices/").split("-", 1)
        require(row["component"] == component, "SMP user notice component differs")
        if component == "tessryn": require(data == regular_bytes(ROOT / name, 4 << 20), "SMP user notice differs from reviewed origin")
        else:
            origin = setup["rust_notices"][name]
            require(row["sha256"] == origin["sha256"] and row["size_bytes"] == origin["size_bytes"], "SMP user Rust notice differs from pinned origin")


def validate_build(path):
    path = Path(path); manifest = strict_json(regular_bytes(path, 2 << 20))
    keys = {"format", "artifact_type", "source", "source_files", "runtime_files", "retained_sources", "toolchain", "profile", "cases", "scope", "qualification", "compile_commands", "compile", "bindings", "artifacts", "notices"}
    require(type(manifest) is dict and set(manifest) == keys and manifest["format"] == "tessryn-k03-smp-user-build/v1"
        and manifest["artifact_type"] == ARTIFACT_TYPE and canonical(manifest["profile"]) == canonical(PROFILE)
        and manifest["cases"] == list(CASES) and manifest["scope"] == SCOPE and manifest["qualification"] == "not_established", "SMP user build fields/scope differ")
    files, runtime = manifest["source_files"], manifest["runtime_files"]
    require(type(files) is dict and set(files) == set(COMPILER_SOURCES) and type(runtime) is dict and set(runtime) == set(RUNTIME_FILES), "SMP user source closure differs")
    expected = {"sources/" + n for n in set(files) | set(runtime)}; rows = manifest["retained_sources"]
    require(type(rows) is list and len(rows) == len(expected) and {r.get("path") for r in rows if type(r) is dict} == expected, "SMP user retained source inventory differs")
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "sha256", "size_bytes"}, "SMP user retained source fields differ")
        name = row["path"].removeprefix("sources/"); data = read_ref(path.parent, row, 16 << 20)
        require(digest(data) == (files[name] if name in files else runtime[name]), "SMP user retained source differs")
    artifacts = manifest["artifacts"]; expected = {case + "/" + n for case in CASES for n in ("BOOTX64.EFI", "kernel.obj", "boot.img")}
    require(type(artifacts) is list and len(artifacts) == len(CASES) * 3 and {r.get("path") for r in artifacts if type(r) is dict} == expected, "SMP user artifact inventory differs")
    data = {}
    for row in artifacts:
        require(type(row) is dict and set(row) == {"path", "sha256", "size_bytes", "case"} and row["case"] == row["path"].split("/")[0], "SMP user artifact fields differ")
        data[row["path"]] = read_ref(path.parent, row)
    require(type(manifest["bindings"]) is dict and set(manifest["bindings"]) == set(CASES), "SMP user binding set differs")
    for case in CASES:
        efi, obj, disk = (data[case + "/" + n] for n in ("BOOTX64.EFI", "kernel.obj", "boot.img"))
        require(make_disk(efi) == disk and coff_binding(obj, efi, case) == manifest["bindings"][case], "SMP user linked descriptor/trampoline/media differ")
    receipts = manifest["compile"]
    require(type(receipts) is list and len(receipts) == len(CASES) and [r.get("role") for r in receipts if type(r) is dict] == list(CASES), "SMP user compiler receipts differ")
    for row in receipts:
        require(set(row) == {"role", "status", "returncode", "elapsed_seconds", "stdout", "stderr"} and completed(row), "SMP user compiler process did not complete")
        for stream in ("stdout", "stderr"):
            ref = row[stream]
            require(type(ref) is dict and set(ref) == {"path", "sha256", "size_bytes"} and ref["path"] == row["role"] + "/" + stream + ".log", "SMP user compiler log inventory differs")
            require(str(ROOT).encode() not in read_ref(path.parent, ref, 1 << 20), "SMP user compiler log contains local paths")
    validate_notices(path.parent, manifest["notices"], manifest["toolchain"]["setup"])
    return manifest


def verify_host(path, manifest):
    from tools.check_k03_smp_user_host import SOURCES, EXPECTED_TESTS, FORMAT as HOST_FORMAT, SCOPE as HOST_SCOPE, normalized_commands, verified_setup
    path = Path(path); result = strict_json(regular_bytes(path, 2 << 20))
    require(type(result) is dict and set(result) == {"format", "status", "scope", "source", "toolchain", "tests", "sources", "receipts"}
        and result["format"] == HOST_FORMAT and result["status"] == "pass" and result["scope"] == HOST_SCOPE
        and type(result["tests"]) is int and result["tests"] == EXPECTED_TESTS
        and canonical(result["source"]) == canonical(manifest["source"]) and result["toolchain"] == verified_setup(), "SMP user host result source/scope/toolchain differs")
    setup, uefi = result["toolchain"], manifest["toolchain"]["setup"]
    require(all(setup[k] == uefi[k] for k in ("host", "rustc", "verified_tools")) and setup["g03_lock_sha256"] == uefi["base_lock_sha256"]
        and setup["g03_record_sha256"] == uefi["base_setup_sha256"], "SMP user host and UEFI toolchains differ")
    sources = committed_sources(manifest["source"]["revision"])
    require(type(result["sources"]) is dict and set(result["sources"]) == set(SOURCES)
        and all(n in sources and result["sources"][n] == digest(sources[n][1]) for n in SOURCES), "SMP user actual host sources differ from commit")
    expected = normalized_commands(); rows = result["receipts"]
    require(type(rows) is list and len(rows) == 2 and [r.get("role") for r in rows if type(r) is dict] == list(expected), "SMP user host receipts differ")
    for row in rows:
        require(set(row) == {"role", "status", "returncode", "elapsed_seconds", "stdout", "stderr", "command"}
            and completed(row) and row["command"] == expected[row["role"]], "SMP user host process/flags differ")
        for stream in ("stdout", "stderr"):
            ref = row[stream]; require(type(ref) is dict and set(ref) == {"path", "sha256", "size_bytes"}
                and ref["path"] == row["role"] + "-" + stream + ".log", "SMP user host log inventory differs")
            data = read_ref(path.parent, ref, 1 << 20); require(str(ROOT).encode() not in data, "SMP user host log contains local paths")
            if row["role"] == "tests" and stream == "stdout":
                require(re.findall(rb"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", data) == [str(EXPECTED_TESTS).encode()], "SMP user host raw test count differs")
    return {"tests": EXPECTED_TESTS, "source_files": len(SOURCES), "receipts": 2, "result_sha256": digest(regular_bytes(path, 2 << 20))}


def verify_capture(path, manifest_path, manifest):
    from tools.run_k03_smp_user import qemu_command, PASS_REASON
    path, manifest_path = Path(path), Path(manifest_path)
    result = strict_json(regular_bytes(path, 2 << 20)); keys = {"format", "case", "status", "reason", "scope", "qualification", "capture_only", "manifest_sha256", "registration_sha256", "evaluator_sha256", "observations", "logs", "execution"}
    require(type(result) is dict and set(result) == keys and result["format"] == FORMAT and result["case"] in CASES
        and result["status"] == "pass" and result["reason"] == PASS_REASON and result["scope"] == SCOPE
        and result["qualification"] == "not_established" and result["capture_only"] is False, "SMP user capture did not pass complete acceptance")
    raw = regular_bytes(path.parent / "registration.json", 2 << 20); registration = strict_json(raw)
    require(result["registration_sha256"] == digest(raw) and type(registration) is dict and set(registration) == {"format", "case", "scope", "qualification", "capture_origin", "created_at_utc", "manifest_sha256", "selected_artifacts", "evaluator_sha256", "command", "timeout_seconds", "max_log_bytes", "emulator_sha256", "launcher", "firmware"}, "SMP user registration differs")
    case = result["case"]
    require(registration["format"] == "tessryn-k03-smp-user-registration/v1" and registration["case"] == case and registration["scope"] == SCOPE
        and registration["qualification"] == "not_established" and registration["capture_origin"] == "local_runner_claim_unverified_offline"
        and registration["manifest_sha256"] == result["manifest_sha256"] == digest(regular_bytes(manifest_path, 2 << 20))
        and registration["selected_artifacts"] == [r for r in manifest["artifacts"] if r["case"] == case]
        and registration["evaluator_sha256"] == result["evaluator_sha256"] == digest(canonical(runtime_hashes()).encode())
        and registration["command"] == qemu_command(), "SMP user registration input/command identity differs")
    created = datetime.fromisoformat(registration["created_at_utc"].replace("Z", "+00:00")); require(created.utcoffset() is not None and created.utcoffset().total_seconds() == 0, "SMP user registration time is not UTC")
    setup = manifest["toolchain"]["setup"]
    require(registration["emulator_sha256"] == setup["verified_tools"]["qemu"]["sha256"] and registration["launcher"] == {"executable": "/usr/bin/env", "sha256": digest(regular_bytes(Path("/usr/bin/env"), 16 << 20)), "temporary_scope": "private owned directory removed after child reap"}, "SMP user launch identity differs")
    firmware = registration["firmware"]
    require(type(firmware) is list and len(firmware) == 3 and [r.get("path") for r in firmware if type(r) is dict] == ["firmware/code.fd", "firmware/vars.fd", "firmware/NOTICE"], "SMP user firmware inventory differs")
    for row, role in zip(firmware, ("code", "vars", "notice")):
        require(set(row) == {"path", "sha256", "size_bytes"}, "SMP user firmware fields differ"); read_ref(path.parent, row, 16 << 20)
        require(all(row[k] == setup["firmware"][role][k] for k in ("sha256", "size_bytes")), "SMP user firmware origin differs")
    timeout = registration["timeout_seconds"]
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 60 and type(registration["max_log_bytes"]) is int and registration["max_log_bytes"] == MAX_LOG_BYTES, "SMP user execution budgets differ")
    execution = result["execution"]
    require(type(execution) is dict and set(execution) == {"status", "returncode", "elapsed_seconds", "command", "timeout_seconds", "max_log_bytes"}
        and execution["status"] == "completed" and type(execution["returncode"]) is int and execution["returncode"] == 33
        and type(execution["elapsed_seconds"]) in (int, float) and math.isfinite(execution["elapsed_seconds"]) and 0 <= execution["elapsed_seconds"] <= timeout + 2
        and execution["command"] == qemu_command() and execution["timeout_seconds"] == timeout and execution["max_log_bytes"] == MAX_LOG_BYTES, "SMP user actual process receipt differs")
    logs = result["logs"]
    require(type(logs) is list and len(logs) == 2 and [r.get("path") for r in logs if type(r) is dict] == ["stdout.log", "stderr.log"]
        and all(set(r) == {"path", "sha256", "size_bytes"} for r in logs), "SMP user raw log coverage differs")
    stdout, stderr = (read_ref(path.parent, r, MAX_LOG_BYTES) for r in logs)
    require(len(stdout) + len(stderr) <= MAX_LOG_BYTES, "SMP user raw logs exceed budget")
    observations = parse_transcript(case, stdout, 33, stderr, manifest["bindings"][case])
    require(canonical(observations) == canonical(result["observations"]), "SMP user stored observations differ from raw replay")
    return observations


def verify(first, second, host_result, results):
    first, second = Path(first).absolute(), Path(second).absolute()
    require(first.parent.resolve() != second.parent.resolve() and not first.samefile(second), "SMP user twin manifests must come from distinct build directories/inodes")
    a, b = validate_build(first), validate_build(second)
    artifact_inodes = set()
    for path, manifest in ((first, a), (second, b)):
        for row in manifest["artifacts"]:
            info = (path.parent / row["path"]).stat()
            identity = info.st_dev, info.st_ino
            require(identity not in artifact_inodes, "SMP user twin artifacts require independent file inodes")
            artifact_inodes.add(identity)
    for manifest in (a, b): validate_source(manifest); validate_toolchain(manifest)
    require(all(canonical(a[k]) == canonical(b[k]) for k in set(a) - {"compile"}), "SMP user independent twin differs")
    host = verify_host(host_result, a); observations = {}
    for path in results:
        result = strict_json(regular_bytes(path, 2 << 20)); require(type(result) is dict and result.get("case") in CASES and result["case"] not in observations, "SMP user repeated/unknown scenario")
        observations[result["case"]] = verify_capture(path, first, a)
    require(set(observations) == set(CASES), "SMP user verification needs all fresh scenarios")
    return {"format": "tessryn-k03-smp-user-verification/v1", "status": "pass", "scope": SCOPE, "qualification": "not_established",
        "source": a["source"], "provenance": validate_source(a), "twin_artifacts": len(CASES) * 3, "host_parser": host,
        "observations": observations, "capture_authentication": "unverified_offline"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("first", "second", "host-result", "out"): p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--result", type=Path, action="append", required=True); args = p.parse_args()
    try:
        require(not args.out.exists(), "SMP user verification output exists")
        value = verify(args.first, args.second, args.host_result, args.result); args.out.parent.mkdir(parents=True, exist_ok=True); write_json(args.out, value)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, AttributeError, subprocess.SubprocessError) as error:
        p.exit(1, "SMP user verification rejected: " + type(error).__name__ + "\n")
    print("All SMP user scenarios independently verified; shared-budget/physical scheduling qualification unavailable")
if __name__ == "__main__": main()
