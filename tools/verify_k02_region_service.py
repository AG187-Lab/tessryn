#!/usr/bin/env python3
"""Independently verify region twins and all three original raw captures."""

from __future__ import annotations

import argparse
from datetime import datetime
import math
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k02_region_protocol import (CASES, PROFILE, ARTIFACT_TYPE, FORMAT, SCOPE, MAX_LOG_BYTES,
    require, digest, regular_bytes, read_ref, strict_json, write_json)
from tools.k02_region_provenance import (COMPILER_SOURCES, RUNTIME_FILES, canonical, runtime_hashes,
    committed_sources, validate_source, validate_toolchain)
from tools.build_k02_region_service import service_binding
from tools.k01_media import make_disk
from tools.k02_region_trace import parse_transcript


def validate_notices(root, notices, setup):
    expected = {"notices/" + name for name in ("tessryn-LICENSE", "tessryn-NOTICE", "rust-LICENSE-APACHE", "rust-LICENSE-MIT", "rust-COPYRIGHT")}
    require(type(notices) is list and len(notices) == 5
            and {row.get("path") for row in notices if type(row) is dict} == expected, "region notice allowlist differs")
    for row in notices:
        require(type(row) is dict and set(row) == {"component", "path", "sha256", "size_bytes"}, "region notice fields differ")
        data = read_ref(root, row, 4 << 20)
        component, name = row["path"].removeprefix("notices/").split("-", 1)
        require(row["component"] == component, "region notice component differs")
        if component == "tessryn":
            require(data == regular_bytes(ROOT / name, 4 << 20), "region Tessryn notice differs from reviewed origin")
        else:
            origin = setup["rust_notices"][name]
            require(row["sha256"] == origin["sha256"] and row["size_bytes"] == origin["size_bytes"],
                    "region Rust notice differs from pinned origin")


def validate_firmware(root, firmware, setup):
    require(type(firmware) is list and len(firmware) == 3
            and all(type(row) is dict and set(row) == {"path", "sha256", "size_bytes"} for row in firmware)
            and [row["path"] for row in firmware] == ["firmware/code.fd", "firmware/vars.fd", "firmware/NOTICE"], "region firmware coverage differs")
    for role, row in zip(("code", "vars", "notice"), firmware):
        read_ref(root, row, 16 << 20)
        require(row["sha256"] == setup["firmware"][role]["sha256"] and row["size_bytes"] == setup["firmware"][role]["size_bytes"],
                "region firmware setup binding differs")


def verify_host(path, manifest):
    from tools.check_k02_region_host import SOURCES, verified_setup
    path = Path(path)
    result = strict_json(regular_bytes(path, 2 << 20))
    require(type(result) is dict and set(result) == {"format", "status", "scope", "source", "toolchain", "tests", "sources", "receipts"}
            and result["format"] == "tessryn-k02-region-host/v1" and result["status"] == "pass"
            and result["scope"] == "host policy model; native CPU/TLB execution unqualified"
            and type(result["tests"]) is int and result["tests"] == 21
            and canonical(result["source"]) == canonical(manifest["source"])
            and canonical(result["toolchain"]) == canonical(verified_setup()), "region host result scope/source/toolchain differs")
    host_setup, uefi_setup = result["toolchain"], manifest["toolchain"]["setup"]
    require(all(canonical(host_setup[key]) == canonical(uefi_setup[key]) for key in ("host", "rustc", "verified_tools"))
            and host_setup["g03_lock_sha256"] == uefi_setup["base_lock_sha256"]
            and host_setup["g03_record_sha256"] == uefi_setup["base_setup_sha256"], "region host and UEFI base toolchains differ")
    sources = committed_sources(manifest["source"]["revision"])
    require(type(result["sources"]) is dict and set(result["sources"]) == set(SOURCES)
            and all(name in sources and result["sources"][name] == digest(sources[name][1]) for name in SOURCES),
            "region host test sources differ from reviewed commit")
    common = ["rust-toolchain/bin/rustc", "--edition=2024", "-Dwarnings", "-Copt-level=1",
              "--remap-path-prefix=tessryn=tessryn", "--remap-path-prefix=region-host=region-host"]
    expected = {
        "library": [*common, "kernel-core/lib.rs", "--crate-name=tessryn_owned_memory", "--crate-type=rlib", "-o", "region-host/libtessryn_owned_memory.rlib"],
        "test-build": [*common, "tests/region_service_host.rs", "--test", "--extern", "tessryn_owned_memory=region-host/libtessryn_owned_memory.rlib", "-o", "region-host/region-tests"],
        "tests": ["region-host/region-tests", "--test-threads=1"],
    }
    receipts = result["receipts"]
    require(type(receipts) is list and len(receipts) == 3
            and [row.get("role") for row in receipts if type(row) is dict] == list(expected), "region host receipts differ")
    test_stdout = b""
    for row in receipts:
        require(set(row) == {"role", "status", "returncode", "elapsed_seconds", "stdout", "stderr", "command"}
                and row["status"] == "completed" and type(row["returncode"]) is int and row["returncode"] == 0
                and type(row["elapsed_seconds"]) in (int, float) and math.isfinite(row["elapsed_seconds"])
                and 0 <= row["elapsed_seconds"] <= 92 and row["command"] == expected[row["role"]], "region host process receipt differs")
        for stream in ("stdout", "stderr"):
            require(type(row[stream]) is dict and set(row[stream]) == {"path", "sha256", "size_bytes"}
                    and row[stream]["path"] == row["role"] + "-" + stream + ".log", "region host log coverage differs")
            data = read_ref(path.parent, row[stream], 1 << 20)
            require(str(ROOT).encode() not in data, "region successful host log contains local paths")
            if row["role"] == "tests" and stream == "stdout":
                test_stdout = data
    require(re.findall(rb"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", test_stdout) == [b"21"],
            "region host raw test count differs")
    return {"tests": 21, "source_files": len(SOURCES), "receipts": len(receipts), "result_sha256": digest(regular_bytes(path, 2 << 20))}


def validate_build(path):
    path = Path(path)
    manifest = strict_json(regular_bytes(path, 2 << 20))
    keys = {"schema_version", "artifact_type", "source", "source_files", "source_files_sha256", "runtime_files",
            "retained_sources", "toolchain", "profile", "cases", "qualification", "compile_commands", "compile",
            "bindings", "artifacts", "notices", "scope"}
    require(type(manifest) is dict and set(manifest) == keys, "region manifest fields differ")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
            and manifest["artifact_type"] == ARTIFACT_TYPE and canonical(manifest["profile"]) == canonical(PROFILE)
            and manifest["cases"] == list(CASES) and manifest["qualification"] == "not_established"
            and manifest["scope"] == SCOPE, "region manifest scope/profile differs")
    files, runtime = manifest["source_files"], manifest["runtime_files"]
    require(type(files) is dict and set(files) == set(COMPILER_SOURCES)
            and type(runtime) is dict and set(runtime) == set(RUNTIME_FILES), "region source/runtime closure differs")
    require(manifest["source_files_sha256"] == digest(canonical(files).encode()), "region compiler dependency hash differs")
    retained = manifest["retained_sources"]
    require(type(retained) is list and len(retained) == len(set(files) | set(runtime)), "region retained source count differs")
    refs = {}
    for row in retained:
        require(type(row) is dict and set(row) == {"path", "sha256", "size_bytes"}, "region retained source fields differ")
        name = row["path"]
        require(type(name) is str and name.startswith("sources/") and name not in refs, "region retained source path repeated")
        source_name = name.removeprefix("sources/")
        require(source_name in files or source_name in runtime, "region undeclared retained source")
        data = read_ref(path.parent, row, 16 << 20)
        require(digest(data) == (files[source_name] if source_name in files else runtime[source_name]), "region retained source hash differs")
        refs[name] = row
    require(set(refs) == {"sources/" + name for name in set(files) | set(runtime)}, "region retained source closure incomplete")
    expected = {"libtessryn_owned_memory.rlib"} | {case + "/" + name for case in CASES for name in ("BOOTX64.EFI", "boot.img", "kernel.obj")}
    artifacts = manifest["artifacts"]
    require(type(artifacts) is list and len(artifacts) == len(expected)
            and {row.get("path") for row in artifacts if type(row) is dict} == expected, "region artifact allowlist differs")
    by_path = {}
    kinds = {"BOOTX64.EFI": "kernel_efi", "boot.img": "boot_disk", "kernel.obj": "compiler_object"}
    for row in artifacts:
        require(type(row) is dict, "region artifact malformed")
        name = row["path"]
        if name == "libtessryn_owned_memory.rlib":
            require(set(row) == {"path", "sha256", "size_bytes", "kind", "target", "crate"}
                    and row["kind"] == "target_rlib" and row["target"] == PROFILE["target"]
                    and row["crate"] == "tessryn_owned_memory", "region core target/library differs")
        else:
            case, basename = name.split("/")
            require(set(row) == {"path", "sha256", "size_bytes", "kind", "case"}
                    and row["case"] == case and row["kind"] == kinds[basename], "region scenario artifact kind differs")
        by_path[name] = read_ref(path.parent, row)
    require(type(manifest["bindings"]) is dict and set(manifest["bindings"]) == set(CASES), "region program binding set differs")
    for case in CASES:
        efi, obj, disk = (by_path[case + "/" + name] for name in ("BOOTX64.EFI", "kernel.obj", "boot.img"))
        require(make_disk(efi) == disk and service_binding(obj, efi, case) == manifest["bindings"][case], "region linked programs/descriptor/media differ")
    validate_notices(path.parent, manifest["notices"], manifest["toolchain"]["setup"])
    receipts = manifest["compile"]
    require(type(receipts) is list and len(receipts) == 4 and [row.get("role") for row in receipts] == ["core", *CASES], "region compiler receipts incomplete")
    for row in receipts:
        require(set(row) == {"role", "status", "returncode", "elapsed_seconds", "stdout", "stderr"}
                and row["status"] == "completed" and type(row["returncode"]) is int and row["returncode"] == 0
                and type(row["elapsed_seconds"]) in (int, float) and math.isfinite(row["elapsed_seconds"])
                and 0 <= row["elapsed_seconds"] <= 92, "region compiler did not complete successfully")
        role = row["role"]
        for stream in ("stdout", "stderr"):
            expected_name = ("" if role == "core" else role + "/") + role + "-" + stream + ".log"
            require(row[stream]["path"] == expected_name, "region compiler log path differs")
            read_ref(path.parent, row[stream], 1 << 20)
    require(type(manifest["compile_commands"]) is dict and set(manifest["compile_commands"]) == {"core", *CASES}, "region compiler command set differs")
    return manifest


def bound_context(path, manifest, case):
    context = dict(manifest["bindings"][case])
    row = next(row for row in manifest["artifacts"] if row["path"] == case + "/BOOTX64.EFI")
    efi = read_ref(Path(path).parent, row)
    pe = struct.unpack_from("<I", efi, 60)[0]
    headers = struct.unpack_from("<I", efi, pe + 24 + 60)[0]
    require(0 < headers <= 4096 and headers <= len(efi), "region PE header extent unsupported")
    context["kernel_header_hex"] = efi[:headers].hex()
    context["kernel_imagebase_offset"] = pe + 48
    return context


def verify_capture(path, manifest_path, manifest):
    from tools.run_k02_region_service import qemu_command, PASS_REASON
    path, manifest_path = Path(path), Path(manifest_path)
    result = strict_json(regular_bytes(path, 2 << 20))
    expected_keys = {"format", "case", "status", "reason", "scope", "qualification", "capture_only", "manifest_sha256",
                     "registration_sha256", "evaluator_sha256", "execution", "observations", "logs"}
    require(type(result) is dict and set(result) == expected_keys and result["format"] == FORMAT
            and result["case"] in CASES and result["status"] == "pass" and result["reason"] == PASS_REASON
            and result["scope"] == SCOPE and result["qualification"] == "not_established"
            and result["capture_only"] is False, "region capture did not pass complete acceptance")
    root, case = path.parent, result["case"]
    manifest_hash = digest(regular_bytes(manifest_path, 2 << 20))
    require(result["manifest_sha256"] == manifest_hash, "region result build identity differs")
    registration_bytes = regular_bytes(root / "registration.json", 2 << 20)
    require(digest(registration_bytes) == result["registration_sha256"], "region preregistration bytes differ")
    registration = strict_json(registration_bytes)
    require(type(registration) is dict and set(registration) == {"format", "case", "scope", "qualification", "capture_origin",
        "created_at_utc", "manifest_sha256", "selected_artifacts", "evaluator_sha256", "command", "timeout_seconds",
        "max_log_bytes", "emulator_sha256", "launcher", "firmware"}, "region preregistration fields differ")
    require(registration["format"] == "tessryn-k02-region-registration/v1" and registration["case"] == case
            and registration["scope"] == SCOPE and registration["qualification"] == "not_established"
            and registration["capture_origin"] == "local_runner_claim_unverified_offline"
            and registration["manifest_sha256"] == manifest_hash, "region preregistration scope differs")
    try:
        created = datetime.fromisoformat(registration["created_at_utc"].replace("Z", "+00:00"))
        require(created.utcoffset() is not None and created.utcoffset().total_seconds() == 0, "region registration time is not UTC")
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("region registration time malformed") from error
    require(registration["selected_artifacts"] == [row for row in manifest["artifacts"] if row.get("case") == case]
            and registration["evaluator_sha256"] == result["evaluator_sha256"] == digest(canonical(runtime_hashes()).encode())
            and registration["command"] == qemu_command(), "region registered artifacts/evaluator/command differ")
    setup = manifest["toolchain"]["setup"]
    require(registration["emulator_sha256"] == setup["verified_tools"]["qemu"]["sha256"], "region registered emulator differs")
    launcher = registration["launcher"]
    require(type(launcher) is dict and set(launcher) == {"executable", "sha256", "temporary_scope"}
            and launcher["executable"] == "/usr/bin/env" and launcher["sha256"] == digest(regular_bytes(Path("/usr/bin/env"), 16 << 20))
            and launcher["temporary_scope"] == "fresh private owned directory removed after child reap", "region launcher differs from checked host")
    validate_firmware(root, registration["firmware"], setup)
    timeout, limit = registration["timeout_seconds"], registration["max_log_bytes"]
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 60
            and type(limit) is int and 0 < limit <= MAX_LOG_BYTES, "region execution budget malformed")
    execution = result["execution"]
    require(type(execution) is dict and set(execution) == {"status", "returncode", "elapsed_seconds", "command", "timeout_seconds", "max_log_bytes"}
            and execution["status"] == "completed" and type(execution["returncode"]) is int and execution["returncode"] == 33
            and type(execution["elapsed_seconds"]) in (int, float) and math.isfinite(execution["elapsed_seconds"])
            and 0 <= execution["elapsed_seconds"] <= timeout + 2 and execution["command"] == qemu_command()
            and execution["timeout_seconds"] == timeout and execution["max_log_bytes"] == limit, "region process receipt differs")
    logs = result["logs"]
    require(type(logs) is list and len(logs) == 2 and [row["path"] for row in logs] == ["stdout.log", "stderr.log"], "region raw log coverage differs")
    stdout, stderr = (read_ref(root, row, limit) for row in logs)
    require(len(stdout) + len(stderr) <= limit, "region combined raw logs exceed budget")
    observed = parse_transcript(case, stdout, 33, stderr, bound_context(manifest_path, manifest, case))
    require(canonical(observed) == canonical(result["observations"]), "region stored result differs from raw trace")
    return observed


def verify(first, second, results, host_result):
    a, b = validate_build(first), validate_build(second)
    for manifest in (a, b):
        validate_source(manifest)
        validate_toolchain(manifest)
    for key in set(a) - {"compile"}:
        require(canonical(a[key]) == canonical(b[key]), "region independent twin build differs: " + key)
    host = verify_host(host_result, a)
    observations = {}
    for path in results:
        result = strict_json(regular_bytes(path, 2 << 20))
        require(type(result) is dict, "region capture result must be an object")
        case = result.get("case")
        require(case in CASES and case not in observations, "region repeated/unknown capture scenario")
        observations[case] = verify_capture(path, first, a)
    require(set(observations) == set(CASES), "region full verification requires all three fresh scenarios")
    return {"format": "tessryn-k02-region-verification/v1", "status": "pass", "qualification": "not_established",
            "scope": SCOPE, "source": a["source"], "provenance": validate_source(a),
            "twin_artifacts": len(a["artifacts"]), "host_policy": host, "observations": observations,
            "capture_authentication": "unverified_offline"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--result", type=Path, action="append", required=True)
    parser.add_argument("--host-result", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.out.exists(), "region verification output already exists")
        result = verify(args.first, args.second, args.result, args.host_result)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.out, result)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.exit(1, "Region verification rejected: " + type(error).__name__ + "\n")
    print("All three region-service scenarios independently verified; hardware/SMP qualification unavailable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
