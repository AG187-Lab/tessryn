#!/usr/bin/env python3
"""Recompute repeated emulator runtime observations with reviewed checkout tools."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.verify_native_kernel_benchmarks import (read_regular, strict_json, same_json, require,
    object_fields, integer, digest, file_ref, portable_path, sha)

PROFILE = "planning/runtime-benchmark-profile.json"
SCOPE = "repeated_qemu_runtime_observations"
TIMER_CASES = ("preemption", "budget", "deadline", "forged_irq")
OWN_RUNTIME = ("tools/run_runtime_benchmarks.py", "tools/verify_runtime_benchmarks.py",
               "tools/verify_native_kernel_benchmarks.py", "tools/preemption_benchmark.py", PROFILE,
               "tools/build_native_kernel_benchmarks.py",
               ".github/workflows/runtime-benchmarks.yml")


def expected_profile():
    return {"format": "tessryn-runtime-benchmark-profile/v1", "scope": SCOPE, "independent_repeats": 2,
            "preemption": {"scenarios": list(TIMER_CASES), "samples": "all_accepted_actual_irq_endpoints",
                           "warmup_samples": 0, "counter": "hpet64", "period_fs": 10000000,
                           "time_domain": "qemu_emulator_virtual_time", "pool_boots": False},
            "contention": {"profile": "planning/contention-benchmark-profile.json", "cases": 6,
                           "samples_per_case": 16, "warmup_per_case": 4, "iterations": 1024,
                           "counter": "bsp_hpet64", "pool_boots": False},
            "limits": {"wall_seconds": 1800, "stage_cleanup_grace_seconds": 3.5, "stage_log_bytes": 1048576,
                       "public_bytes": 2147483648, "public_files": 2048},
            "comparison": {"identity": "exact_source_build_runtime_machine_clock_profile",
                           "statistics": "within_boot_only", "overhead_subtraction": False,
                           "performance_threshold": None, "promotion_decision": False},
            "capture_authentication": "unverified_offline", "hardware_qualified": False,
            "inference_qualified": False}


def validate_profile(value):
    require(same_json(value, expected_profile()), "unsupported runtime benchmark profile")
    return value


def runtime_paths():
    from tools.k03_timer_provenance import RUNTIME_FILES as timer
    from tools import verify_contention_benchmarks as contention
    return tuple(sorted(set(OWN_RUNTIME) | set(timer) | set(contention.RUNTIME_FILES)))


def runtime_hashes():
    return {name: digest(read_regular(ROOT, name, 16 << 20)) for name in runtime_paths()}


def stage_plan():
    stages = []
    def add(name, tool, args, timeout):
        stages.append({"id": name, "tool": tool, "arguments": args, "timeout_seconds": timeout})
    for repeat in (1, 2):
        p = f"<run>/preemption/repeat-{repeat}"
        c = f"<run>/contention/repeat-{repeat}"
        add(f"preemption-{repeat}-host", "tools/check_k03_timer_host.py", ["--out", p + "/host"], 900)
        for twin in ("a", "b"):
            add(f"preemption-{repeat}-{twin}", "tools/build_k03_timer.py", ["--out", p + "/" + twin], 900)
        for case in TIMER_CASES:
            add(f"preemption-{repeat}-{case}", "tools/run_k03_timer.py",
                ["--manifest", p + "/a/manifest.json", "--out", p + "/" + case,
                 "--case", case, "--allow-qemu", "--timeout", "45"], 180)
        add(f"preemption-{repeat}-extract", "tools/preemption_benchmark.py",
            ["--packet", p, "--out", p + "/preemption-summary.json"], 300)
        add(f"contention-{repeat}-build", "tools/build_contention_benchmarks.py", ["--out", c + "/image"], 300)
        add(f"contention-{repeat}-capture", "tools/run_contention_benchmarks.py",
            ["--manifest", c + "/image/manifest.json", "--out", c + "/packet", "--allow-qemu", "--timeout", "60"], 180)
    return stages


def final_verifier():
    return {"tool": "tools/verify_runtime_benchmarks.py", "arguments": ["<run>", "--recompute-only"], "timeout_seconds": 300}


def utc(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0, "UTC timestamp required")
        return parsed
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("invalid UTC timestamp") from error


def validate_capture_time(created, registration_created, receipt):
    require(utc(registration_created) <= utc(receipt["started_at_utc"]) <= utc(created)
            <= utc(receipt["completed_at_utc"]), "capture preregistration outside declared experiment stage")


def validate_inventory(root, expected_names):
    expected = set(expected_names)
    require(len(expected) <= 2048, "runtime file count budget exceeded")
    directories = {"."}
    for name in expected:
        path = portable_path(name)
        directories.update(parent.as_posix() for parent in path.parents)
    found, total = {}, 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in (*dirs, *files):
            path = Path(base) / name
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            require(not stat.S_ISLNK(mode), "runtime inventory contains symlink")
            if stat.S_ISDIR(mode):
                require(relative in directories, "runtime inventory contains undeclared directory")
            else:
                require(stat.S_ISREG(mode) and relative in expected, "runtime inventory contains undeclared or special file")
                size = path.stat().st_size
                total += size
                require(total <= 2 << 30, "runtime complete inventory exceeds byte budget")
                found[relative] = size
    require(set(found) == expected, "runtime complete inventory missing files")
    return found


def validate_source(source, runtime):
    from tools.k03_timer_provenance import committed_sources
    object_fields(source, {"revision", "dirty", "tree_sha256", "snapshot_algorithm"}, "source")
    require(source["dirty"] is False and source["snapshot_algorithm"] == "git-worktree-v2", "clean committed source required")
    files = committed_sources(source["revision"])
    hashed = hashlib.sha256()
    for name, (mode, data) in sorted(files.items()):
        hashed.update(name.encode() + b"\0" + mode.encode() + b"\0" + digest(data).encode() + b"\0")
    require(hashed.hexdigest() == source["tree_sha256"], "registered committed tree differs")
    require(type(runtime) is dict and set(runtime) == set(runtime_paths()), "reviewed runtime closure differs")
    for name, value in runtime.items():
        require(name in files and value == digest(files[name][1]) == digest(read_regular(ROOT, name, 16 << 20)),
                "runtime differs from committed reviewed checkout")


def reference(root, name):
    data = read_regular(root, name, 64 << 20)
    return {"file": name, "sha256": digest(data), "size": len(data)}


def preemption_files(directory):
    """Collect only references admitted by the unchanged full timer verifier."""
    root = Path(directory)
    names = {"preemption-summary.json", "host/result.json"}
    for twin in ("a", "b"):
        manifest = strict_json(read_regular(root, twin + "/manifest.json", 2 << 20))
        names.add(twin + "/manifest.json")
        refs = [*manifest["retained_sources"], *manifest["artifacts"], *manifest["notices"]]
        for receipt in manifest["compile"]:
            refs.extend((receipt["stdout"], receipt["stderr"]))
        for ref in refs:
            portable_path(ref["path"])
            names.add(twin + "/" + ref["path"])
    host = strict_json(read_regular(root, "host/result.json", 2 << 20))
    for receipt in host["receipts"]:
        names.update("host/" + receipt[stream]["path"] for stream in ("stdout", "stderr"))
    for case in TIMER_CASES:
        names.update(case + "/" + name for name in ("result.json", "registration.json", "stdout.log", "stderr.log"))
        registration = strict_json(read_regular(root, case + "/registration.json", 2 << 20))
        names.update(case + "/" + row["path"] for row in registration["firmware"])
    for name in names:
        portable_path(name)
    return sorted(names)


def compare_identities(summaries, label):
    require(type(summaries) is list and len(summaries) == 2, label + ": exactly two independent repeats required")
    identities = [row["identity"] for row in summaries]
    fields = {"source", "toolchain", "machine_profile", "clock_profile", "artifact_sha256",
              "compiler_sources_sha256", "runtime_sha256"}
    for identity in identities:
        object_fields(identity, fields, label + " identity")
    require(same_json(identities[0], identities[1]), label + ": repeat source/build/runtime/clock identity differs")
    return identities[0]


def verify_packet(directory, *, require_result=True, expected_registration_sha256=None):
    root = Path(directory)
    raw = read_regular(root, "registration.json", 2 << 20)
    registration_sha = digest(raw)
    if expected_registration_sha256 is not None:
        require(registration_sha == sha(expected_registration_sha256, "expected registration"), "registration pin differs")
    reg = strict_json(raw)
    object_fields(reg, {"format", "scope", "created_at_utc", "profile", "source", "runtime_sha256", "runtime_sources", "stages",
                       "final_verifier", "capture_authentication", "hardware_qualified", "inference_qualified"}, "registration")
    require(reg["format"] == "tessryn-runtime-benchmark-registration/v1" and reg["scope"] == SCOPE
            and reg["capture_authentication"] == "unverified_offline" and reg["hardware_qualified"] is False
            and reg["inference_qualified"] is False, "runtime registration scope differs")
    validate_profile(strict_json(file_ref(root, reg["profile"], "profile")))
    require(reg["profile"]["file"] == "profile.json", "runtime profile path differs")
    created = utc(reg["created_at_utc"])
    require(same_json(reg["stages"], stage_plan()), "runtime stage plan differs")
    require(same_json(reg["final_verifier"], final_verifier()), "final verifier plan differs")
    validate_source(reg["source"], reg["runtime_sha256"])
    require(type(reg["runtime_sources"]) is list and len(reg["runtime_sources"]) == len(runtime_paths()), "retained runtime coverage differs")
    retained = {}
    for ref in reg["runtime_sources"]:
        data = file_ref(root, ref, "retained runtime", 16 << 20)
        name = ref["file"]
        require(name.startswith("sources/") and name not in retained, "runtime source path differs")
        retained[name] = digest(data)
    require(retained == {"sources/" + name: value for name, value in reg["runtime_sha256"].items()}, "retained runtime identity differs")
    receipts = strict_json(read_regular(root, "stages.json", 4 << 20))
    object_fields(receipts, {"format", "stages"}, "stage receipts")
    require(receipts["format"] == "tessryn-runtime-benchmark-stages/v1" and type(receipts["stages"]) is list
            and len(receipts["stages"]) == len(stage_plan()), "stage receipt coverage differs")
    public = {"registration.json", "profile.json", "stages.json", "result.json"}
    public.update(retained)
    total_elapsed, last_completed, by_stage = 0, created, {}
    for plan, receipt in zip(stage_plan(), receipts["stages"]):
        object_fields(receipt, {"id", "status", "returncode", "elapsed_seconds", "stdout", "stderr",
                               "diagnostic_semantics", "started_at_utc", "completed_at_utc"}, "stage receipt")
        require(receipt["id"] == plan["id"] and receipt["status"] == "completed"
                and type(receipt["returncode"]) is int and receipt["returncode"] == 0
                and receipt["diagnostic_semantics"] == "sanitized_nonmeasurement", "stage did not complete")
        elapsed = receipt["elapsed_seconds"]
        require(type(elapsed) in (int, float) and math.isfinite(elapsed)
                and 0 <= elapsed <= plan["timeout_seconds"] + 6, "stage elapsed invalid")
        total_elapsed += elapsed
        require(last_completed <= utc(receipt["started_at_utc"]) <= utc(receipt["completed_at_utc"]), "stage chronology regressed")
        last_completed = utc(receipt["completed_at_utc"])
        by_stage[plan["id"]] = receipt
        for stream in ("stdout", "stderr"):
            ref = receipt[stream]
            require(ref["file"] == "stages/" + plan["id"] + "-" + stream + ".log", "stage log role differs")
            data = file_ref(root, ref, "stage diagnostics", 1 << 20)
            require(str(ROOT).encode() not in data, "stage diagnostics contain workspace path")
            public.add(ref["file"])
    require(total_elapsed <= 1800, "runtime stage wall budget exceeded")
    from tools.preemption_benchmark import extract_packet
    from tools import verify_contention_benchmarks as contention
    preemption, contended, capture_registrations, unpublished_images = [], [], [], set()
    for repeat in (1, 2):
        relative = f"preemption/repeat-{repeat}"
        summary = extract_packet(root / relative)
        stored = strict_json(read_regular(root, relative + "/preemption-summary.json", 8 << 20))
        require(same_json(stored, summary), "preemption extraction differs from retained full verified packet")
        preemption.append(summary)
        public.update(relative + "/" + name for name in preemption_files(root / relative))
        for case in TIMER_CASES:
            raw_registration = read_regular(root, relative + "/" + case + "/registration.json", 2 << 20)
            capture_registrations.append(digest(raw_registration))
            validate_capture_time(strict_json(raw_registration)["created_at_utc"], reg["created_at_utc"],
                                  by_stage[f"preemption-{repeat}-{case}"])
        relative = f"contention/repeat-{repeat}/packet"
        summary = contention.verify_packet(root / relative, require_result=True)
        contended.append(summary)
        raw_registration = read_regular(root, relative + "/registration.json", 2 << 20)
        capture_registrations.append(digest(raw_registration))
        validate_capture_time(strict_json(raw_registration)["created_at_utc"], reg["created_at_utc"],
                              by_stage[f"contention-{repeat}-capture"])
        public.update(relative + "/" + name for name in contention.packet_files(root / relative))
        manifest = strict_json(read_regular(root, relative + "/build/manifest.json", 2 << 20))
        for name in contention.build_files(manifest):
            image_path = f"contention/repeat-{repeat}/image/" + name
            require(read_regular(root, image_path, 64 << 20) == read_regular(root, relative + "/build/" + name, 64 << 20),
                    "original contention image differs from captured copy")
            unpublished_images.add(image_path)
    identities = {"preemption": compare_identities(preemption, "preemption"),
                  "contention": compare_identities(contended, "contention")}
    public.update(unpublished_images)
    require(len(set(capture_registrations)) == 10, "capture preregistration reused across declared fresh boots")
    require(all(same_json(identity["source"], reg["source"]) for identity in identities.values()), "lane source differs from registration")
    require(same_json(identities["preemption"]["toolchain"], identities["contention"]["toolchain"]),
            "lane checked toolchains differ")
    summary = {"format": "tessryn-runtime-benchmark-summary/v1", "scope": SCOPE,
               "capture_authentication": "unverified_offline", "hardware_qualified": False,
               "inference_qualified": False, "performance_threshold": None, "promotion_decision": False,
               "pooled_samples": False, "identities": identities, "preemption": preemption, "contention": contended}
    if require_result:
        verification = strict_json(read_regular(root, "verification-receipt.json", 2 << 20))
        object_fields(verification, {"id", "status", "returncode", "elapsed_seconds", "stdout", "stderr",
                                   "diagnostic_semantics", "started_at_utc", "completed_at_utc"}, "verification receipt")
        require(verification["id"] == "combined-verification" and verification["status"] == "completed"
                and type(verification["returncode"]) is int and verification["returncode"] == 0
                and verification["diagnostic_semantics"] == "sanitized_nonmeasurement", "final verifier did not complete")
        elapsed = verification["elapsed_seconds"]
        require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 306
                and total_elapsed + elapsed <= 1800, "final verification exceeded bounded budget")
        require(last_completed <= utc(verification["started_at_utc"]) <= utc(verification["completed_at_utc"]),
                "final verifier chronology regressed")
        require((utc(verification["completed_at_utc"]) - created).total_seconds() <= 1806,
                "registered experiment UTC window exceeds wall budget")
        for stream in ("stdout", "stderr"):
            ref = verification[stream]
            require(ref["file"] == "stages/combined-verification-" + stream + ".log", "verification log role differs")
            file_ref(root, ref, "verification diagnostics", 1 << 20)
            public.add(ref["file"])
        public.add("verification-receipt.json")
        result = strict_json(read_regular(root, "result.json", 16 << 20))
        object_fields(result, {"format", "status", "valid", "registration_sha256", "summary", "failure_stage"}, "result")
        require(result["format"] == "tessryn-runtime-benchmark-result/v1" and result["status"] == "observed"
                and result["valid"] is True and result["registration_sha256"] == registration_sha
                and result["failure_stage"] is None and same_json(result["summary"], summary), "combined result differs")
    require(len(public) <= 2048, "public file budget exceeded")
    refs = [reference(root, name) for name in sorted(public) if require_result or name != "result.json"]
    require(sum(ref["size"] for ref in refs) <= 2 << 30, "public byte budget exceeded")
    inventory = {ref["file"] for ref in refs} | unpublished_images
    validate_inventory(root, inventory)
    return {"summary": summary, "files": refs, "registration_sha256": registration_sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--expected-registration-sha256")
    parser.add_argument("--list-files", action="store_true")
    parser.add_argument("--recompute-only", action="store_true")
    args = parser.parse_args()
    try:
        require(not (args.recompute_only and args.list_files), "incompatible verification modes")
        verified = verify_packet(args.directory, require_result=not args.recompute_only,
                                 expected_registration_sha256=args.expected_registration_sha256)
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"valid": False, "reason": "runtime packet rejected", "hardware_qualified": False}))
        return 1
    if args.recompute_only:
        print(json.dumps(verified, sort_keys=True))
    elif args.list_files:
        for ref in verified["files"]:
            print((args.directory / ref["file"]).as_posix())
    else:
        print(json.dumps({"valid": True, "registration_sha256": verified["registration_sha256"],
                          "public_files": len(verified["files"]), "hardware_qualified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
