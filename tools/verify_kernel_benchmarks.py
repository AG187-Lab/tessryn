#!/usr/bin/env python3
"""Verify retained host microbenchmark packets; this does not attest execution."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

MAX_FILE_BYTES = 16 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
UNAVAILABLE = ["native_kernel_latency", "native_context_switch_and_wakeup",
               "native_SMP_or_DMA", "native_queue_runtime", "GPU_execution",
               "inference_performance", "independent_capture_authentication",
               "complete_compiler_dependency_identity",
               "thermal_and_background_load_qualification"]
BASE_CHECKS = {"ring_full_empty_wrap_fifo", "ring_matches_vecdeque_replay",
               "memory_rejects_foreign_bounds_revoked", "memory_lifecycle_drained",
               "host_zero_and_copy_exact", "benchmark_operations_exact",
               "scheduler_reference_round_robin"}
SCHEDULER_CHECK = "scheduler_policy_reservations_stops_and_denials"
SCHEDULER_PIN = "db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d"
LOGICAL_PROFILE = {
    "clock": "synthetic_logical_ns", "quantum_ns": 2,
    "tie_rule": "stop_before_arrival", "untimed": True,
    "tasks": [
        {"task": "short", "domain": 1, "arrival_ns": 0, "work_ns": 3, "deadline_ns": 0},
        {"task": "long", "domain": 2, "arrival_ns": 0, "work_ns": 8, "deadline_ns": 0},
        {"task": "burst", "domain": 1, "arrival_ns": 3, "work_ns": 2, "deadline_ns": 0},
        {"task": "expires", "domain": 2, "arrival_ns": 7, "work_ns": 5, "deadline_ns": 8},
    ],
}


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def object_fields(value, fields: set[str], label: str) -> dict:
    require(isinstance(value, dict) and set(value) == fields, f"{label}: unexpected fields")
    return value


def integer(value, minimum: int, maximum: int, label: str) -> int:
    require(type(value) is int and minimum <= value <= maximum, f"{label}: out of bounds integer")
    return value


def sha(value, label: str) -> str:
    require(isinstance(value, str) and bool(SHA.fullmatch(value)), f"{label}: invalid SHA-256")
    return value


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_regular(root: Path, name: str, limit: int = MAX_FILE_BYTES) -> bytes:
    require(isinstance(name, str) and bool(name) and "\\" not in name, "unsafe packet path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(part not in {".", ".."} for part in path.parts), "unsafe packet path")
    root = root.absolute()
    require(all(part != ".." for part in root.parts), "unsafe packet root")
    require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK"), "bounded regular reads unavailable")
    directory = None
    try:
        directory = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY)
        for component in (*root.parts[1:], *path.parts[:-1]):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "packet file exceeds regular byte limit")
            value = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "packet changed during read")
    except OSError as error:
        raise ValueError(f"packet file unavailable: {path.name}") from error
    finally:
        if directory is not None:
            os.close(directory)
    require(len(value) <= limit, "packet file exceeds byte limit")
    return value


def strict_json(value: bytes):
    def pairs(items):
        result = {}
        for key, item in items:
            require(key not in result, "duplicate JSON key")
            result[key] = item
        return result

    def constant(value):
        raise ValueError("non-finite JSON constant")

    try:
        return json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid JSON packet") from error


def file_ref(root: Path, value, label: str, *, limit: int = MAX_FILE_BYTES) -> bytes:
    ref = object_fields(value, {"file", "sha256", "size"}, label)
    sha(ref["sha256"], label)
    integer(ref["size"], 0, limit, label)
    data = read_regular(root, ref["file"], limit)
    require(len(data) == ref["size"] and digest(data) == ref["sha256"], f"{label}: file binding mismatch")
    return data


def case_specs() -> list[dict]:
    rows = [("timer_pair", "host_clock_probe", 1, 0, 1),
            ("empty_harness", "host_loop_reference", 1, 0, 1),
            ("scheduler_reference_dispatch_cycle", "bounded_round_robin_fixture", 1, 0, 2)]
    for implementation in ("bounded_ring", "vec_deque_reference"):
        rows.extend((f"queue_roundtrip_batch_{n}", implementation, n, 0, 2 * n) for n in (1, 8, 64))
    for implementation in ("bounded_ring", "vec_deque_reference"):
        rows.extend((name, implementation, 1, 0, 1)
                    for name in ("queue_full_rejection", "queue_empty_rejection"))
    rows.extend([("memory_allocate_revoke_release", "tessryn_memory_policy_metadata", 1, 0, 3),
                 ("memory_access_check", "tessryn_memory_policy_metadata", 1, 0, 1)])
    for operation in ("zero", "copy"):
        rows.extend((f"host_{operation}_{n}", "host_byte_buffer", 1, n, 1) for n in (4096, 65536))
    result = [{"case": name, "implementation": impl, "sample_unit": "timed_batch",
               "batch_size": batch, "bytes_per_operation": size,
               "operations_per_iteration": ops, "scheduler_required": False}
              for name, impl, batch, size, ops in rows]
    result += [{"case": "scheduler_policy_dispatch_stop_cycle", "implementation": "tessryn_scheduler_policy",
                "sample_unit": "timed_batch", "batch_size": 1, "bytes_per_operation": 0,
                "operations_per_iteration": 2, "scheduler_required": True},
               {"case": "scheduler_policy_dispatch_latency", "implementation": "tessryn_scheduler_policy",
                "sample_unit": "single_operation", "batch_size": 1, "bytes_per_operation": 0,
                "operations_per_iteration": 1, "scheduler_required": True}]
    return result


def validate_profile(profile: dict, config: dict, scheduler: bool) -> list[dict]:
    object_fields(profile, {"schema_version", "kind", "scope", "limits", "scheduler_source_sha256", "cases", "logical_replay"}, "profile")
    require(profile["schema_version"] == 1 and type(profile["schema_version"]) is int
            and profile["kind"] == "kernel_benchmark_profile" and profile["scope"] == "host_microbenchmark",
            "unsupported benchmark profile")
    limits = object_fields(profile["limits"], {"samples", "warmup", "iterations", "max_total_operations", "max_total_bytes"}, "limits")
    for name, upper in (("samples", 10000), ("warmup", 10000), ("iterations", 1000000),
                        ("max_total_operations", 200000000), ("max_total_bytes", 30000000000)):
        integer(limits[name], 1, upper, f"limit {name}")
    sha(profile["scheduler_source_sha256"], "scheduler source pin")
    require(profile["scheduler_source_sha256"] == SCHEDULER_PIN, "unsupported scheduler source pin")
    require(type(profile["cases"]) is list and len(profile["cases"]) == len(case_specs()), "invalid case manifest")
    for row in profile["cases"]:
        object_fields(row, {"case", "implementation", "sample_unit", "batch_size", "bytes_per_operation",
                           "operations_per_iteration", "scheduler_required"}, "case manifest row")
        for field in ("batch_size", "bytes_per_operation", "operations_per_iteration"):
            integer(row[field], 0, 1000000, "case " + field)
        require(type(row["scheduler_required"]) is bool, "case scheduler flag must be boolean")
        require(all(type(row[field]) is str for field in ("case", "implementation", "sample_unit")), "case names must be text")
    require(profile["cases"] == case_specs(), "profile must name the supported exact case manifest")
    require(strict_json(json.dumps(profile["logical_replay"]).encode()) == LOGICAL_PROFILE
            and json.dumps(profile["logical_replay"], sort_keys=True) == json.dumps(LOGICAL_PROFILE, sort_keys=True),
            "unsupported logical replay profile")
    object_fields(config, {"samples", "warmup", "iterations", "seed"}, "config")
    for name in ("samples", "warmup", "iterations"):
        integer(config[name], 0 if name == "warmup" else 1, limits[name], f"config {name}")
    integer(config["seed"], 0, (1 << 64) - 1, "seed")
    require(type(scheduler) is bool, "scheduler enabled must be boolean")
    cases = [row for row in profile["cases"] if scheduler or not row["scheduler_required"]]
    count = config["samples"] + config["warmup"]
    total_operations = total_bytes = 0
    for row in cases:
        iterations = 1 if row["sample_unit"] == "single_operation" else config["iterations"]
        total_operations += count * iterations * row["operations_per_iteration"]
        total_bytes += count * iterations * row["bytes_per_operation"]
    require(total_operations <= limits["max_total_operations"], "registered operation budget exceeded")
    require(total_bytes <= limits["max_total_bytes"], "registered byte budget exceeded")
    return cases


def expected_checksum(row: dict, config: dict) -> int | None:
    name, seed, n = row["case"], config["seed"], config["iterations"]
    mask = (1 << 64) - 1

    def cyclic(count, width):
        full, tail = divmod(count, width)
        return full * width * (width - 1) // 2 + tail * (tail - 1) // 2

    if name in {"timer_pair", "empty_harness"}:
        value = seed + n * (n - 1) // 2
    elif name.startswith("queue_roundtrip_batch_"):
        length = n * row["batch_size"]
        value = seed + length * seed + length * (length - 1) // 2
    elif name in {"queue_full_rejection", "queue_empty_rejection"}:
        value = seed + n
    elif name == "memory_allocate_revoke_release":
        value = seed + n * (n + 1) // 2
    elif name == "memory_access_check":
        value = seed + n * 1048576 + cyclic(n, 4096)
    elif name.startswith("host_zero_"):
        value = seed
    elif name.startswith("host_copy_"):
        size, shift = row["bytes_per_operation"], seed % 251

        def prefix(count):
            return cyclic(count + shift, 251) - cyclic(shift, 251)

        full, tail = divmod(n, size)
        value = seed + full * prefix(size) + prefix(tail)
    elif name in {"scheduler_reference_dispatch_cycle", "scheduler_policy_dispatch_stop_cycle"}:
        value = seed + cyclic(n, 32)
    elif name == "scheduler_policy_dispatch_latency":
        value = seed
    else:
        raise ValueError("unsupported checksum case")
    return value & mask


def quantiles(values: list[float | int]) -> dict:
    require(bool(values), "empty sample population")
    values = sorted(values)
    # Nearest rank, including endpoints; no interpolation or overhead subtraction.
    pick = lambda p: values[max(0, math.ceil(p * len(values)) - 1)]
    return {"min": values[0], "p50": pick(.50), "p95": pick(.95),
            "p99": pick(.99), "max": values[-1], "mean": sum(values) / len(values)}


def validate_logical_replay(value, scheduler: bool) -> dict | None:
    if not scheduler:
        require(value is None, "logical replay requires the pinned scheduler")
        return None
    object_fields(value, {"kind", "clock", "quantum_ns", "episodes", "outcomes"}, "logical replay")
    require(value["kind"] == "scheduler_logical_replay" and value["clock"] == "synthetic_logical_ns"
            and type(value["quantum_ns"]) is int and value["quantum_ns"] == 2, "invalid logical replay scope")
    expected_episodes = [
        ("short", 0, 0, 0, 0), ("long", 0, 2, 2, 1), ("burst", 3, 4, 1, 2),
        ("long", 4, 6, 2, 3), ("short", 2, 8, 6, 4), ("long", 8, 9, 1, 5), ("long", 11, 11, 0, 6),
    ]
    require(type(value["episodes"]) is list and len(value["episodes"]) == len(expected_episodes), "logical episode coverage mismatch")
    for episode, expected in zip(value["episodes"], expected_episodes):
        object_fields(episode, {"task", "ready_ns", "dispatch_ns", "delay_ns", "dispatch_index"}, "logical episode")
        require(type(episode["task"]) is str, "logical task must be text")
        for field in ("ready_ns", "dispatch_ns", "delay_ns", "dispatch_index"):
            integer(episode[field], 0, 1000, "logical " + field)
        require(tuple(episode[field] for field in ("task", "ready_ns", "dispatch_ns", "delay_ns", "dispatch_index")) == expected,
                "logical schedule differs from registered trace")
    expected_outcomes = [("short", "completed", 9, 3), ("long", "completed", 13, 8),
                         ("burst", "completed", 6, 2), ("expires", "deadline_expired", None, 0)]
    require(type(value["outcomes"]) is list and len(value["outcomes"]) == 4, "logical outcome coverage mismatch")
    for outcome, expected in zip(value["outcomes"], expected_outcomes):
        object_fields(outcome, {"task", "status", "completed_ns", "consumed_ns"}, "logical outcome")
        require(type(outcome["task"]) is str and type(outcome["status"]) is str, "logical outcome names must be text")
        integer(outcome["consumed_ns"], 0, 1000, "logical consumed time")
        if outcome["completed_ns"] is not None:
            integer(outcome["completed_ns"], 0, 1000, "logical completed time")
        require(tuple(outcome[field] for field in ("task", "status", "completed_ns", "consumed_ns")) == expected,
                "logical terminal outcome mismatch")
    return {"clock": "synthetic_logical_ns", "native_qualification": False,
            "ready_to_dispatch_logical_ns": quantiles([row[3] for row in expected_episodes]),
            "readiness_episodes": 7, "completed_tasks": 3, "expired_without_dispatch": 1,
            "trace": value}


def validate_raw(raw: dict, config: dict, cases: list[dict], scheduler: bool) -> dict:
    object_fields(raw, {"schema_version", "kind", "clock", "config", "samples", "checks", "logical_replay"}, "raw result")
    require(type(raw["schema_version"]) is int and raw["schema_version"] == 1
            and raw["kind"] == "kernel_benchmark_raw" and raw["clock"] == "std::time::Instant",
            "unsupported raw benchmark format")
    require(raw["config"] == config, "raw config differs from preregistration")
    object_fields(raw["config"], {"samples", "warmup", "iterations", "seed"}, "raw config")
    for name, value in raw["config"].items():
        require(type(value) is int, f"raw config {name}: integer required")
    checks = BASE_CHECKS | ({SCHEDULER_CHECK, "scheduler_logical_replay_exact"} if scheduler else set())
    require(isinstance(raw["checks"], list) and len(raw["checks"]) == len(checks)
            and all(isinstance(item, str) for item in raw["checks"])
            and set(raw["checks"]) == checks, "missing or unexpected correctness checks")
    require(isinstance(raw["samples"], list)
            and len(raw["samples"]) == len(cases) * config["samples"], "raw sample coverage differs from registration")
    indexed = {(row["case"], row["implementation"]): row for row in cases}
    collected = {key: {} for key in indexed}
    sample_fields = {"case", "implementation", "sample_unit", "sample_index", "elapsed_ns",
                     "operations", "checksum", "batch_size", "bytes_per_operation"}
    for sample in raw["samples"]:
        object_fields(sample, sample_fields, "sample")
        require(isinstance(sample["case"], str) and isinstance(sample["implementation"], str), "sample case must be text")
        key = (sample["case"], sample["implementation"])
        require(key in indexed, "unexpected sample case")
        row = indexed[key]
        index = integer(sample["sample_index"], 0, config["samples"] - 1, "sample index")
        require(index not in collected[key], "duplicate sample index")
        integer(sample["elapsed_ns"], 0, 120 * 1000000000, "elapsed_ns")
        integer(sample["operations"], 1, 200000000, "operations")
        integer(sample["checksum"], 0, (1 << 64) - 1, "checksum")
        for field in ("sample_unit", "batch_size", "bytes_per_operation"):
            require(type(sample[field]) is type(row[field]) and sample[field] == row[field], f"sample {field} mismatch")
        iterations = 1 if row["sample_unit"] == "single_operation" else config["iterations"]
        require(sample["operations"] == row["operations_per_iteration"] * iterations, "sample operation formula mismatch")
        expected = expected_checksum(row, config)
        require(expected is None or sample["checksum"] == expected, "deterministic workload checksum mismatch")
        collected[key][index] = sample
    summaries = []
    for row in cases:
        samples = collected[(row["case"], row["implementation"])]
        require(set(samples) == set(range(config["samples"])), "missing measured sample")
        samples = [samples[index] for index in range(config["samples"])]
        durations = [sample["elapsed_ns"] for sample in samples]
        zero = sum(value == 0 for value in durations)
        averages = [sample["elapsed_ns"] / sample["operations"] for sample in samples]
        summaries.append({"case": row["case"], "implementation": row["implementation"],
                          "sample_unit": row["sample_unit"], "sample_count": len(samples),
                          "operations_per_sample": samples[0]["operations"],
                          "batch_size": row["batch_size"], "bytes_per_operation": row["bytes_per_operation"],
                          "measurement_status": "resolution_limited" if zero else "observed",
                          "zero_duration_samples": zero, "elapsed_ns": quantiles(durations),
                          "ns_per_operation": None if zero else quantiles(averages),
                          "quantile_population": "individual_host_policy_calls" if row["sample_unit"] == "single_operation"
                          else "amortized_timed_batch_averages"})
    logical = validate_logical_replay(raw["logical_replay"], scheduler)
    return {"evidence_scope": "host_microbenchmark", "capture_origin": "unverified_offline",
            "native_qualification": False, "overhead_subtraction": False,
            "quantile_method": "nearest_rank", "cases": summaries, "logical_replay": logical,
            "unavailable": UNAVAILABLE}


def validate_receipt(root: Path, receipt: dict, label: str) -> bytes:
    object_fields(receipt, {"status", "reason", "returncode", "elapsed_seconds", "stdout", "stderr"}, label)
    require(receipt["status"] == "completed" and type(receipt["returncode"]) is int
            and receipt["returncode"] == 0, f"{label}: execution did not complete successfully")
    require(isinstance(receipt["reason"], str) and len(receipt["reason"]) <= 1024, "invalid process reason")
    duration = receipt["elapsed_seconds"]
    require(type(duration) in (int, float) and math.isfinite(duration) and 0 <= duration <= 122,
            "invalid bounded process duration")
    stdout = file_ref(root, receipt["stdout"], label + " stdout")
    stderr = file_ref(root, receipt["stderr"], label + " stderr")
    if label == "benchmark execution":
        require(not stderr, "benchmark execution emitted unexpected stderr")
    return stdout


def verify_run(directory: Path, *, require_result: bool = False,
               expected_registration_sha256: str | None = None) -> dict:
    root = Path(directory)
    registration_bytes = read_regular(root, "registration.json")
    registration_hash = digest(registration_bytes)
    if expected_registration_sha256 is not None:
        require(registration_hash == sha(expected_registration_sha256, "expected registration"),
                "expected registration binding mismatch")
    registration = strict_json(registration_bytes)
    object_fields(registration, {"schema_version", "kind", "evidence_scope", "config", "profile", "sources",
                                 "toolchain", "host", "executable", "created_at_utc", "build_flags",
                                 "scheduler_source_enabled", "clock", "measurement_semantics", "capture_origin",
                                 "native_qualification", "warmup_policy"}, "registration")
    require(type(registration["schema_version"]) is int and registration["schema_version"] == 1
            and registration["kind"] == "kernel_benchmark_registration"
            and registration["evidence_scope"] == "host_microbenchmark"
            and registration["native_qualification"] is False
            and registration["capture_origin"] == "local_runner_claim_unverified_offline"
            and registration["measurement_semantics"] == "raw_host_elapsed_no_subtraction"
            and registration["warmup_policy"] == "per_case_discard_before_measurement", "invalid benchmark scope")
    try:
        created = datetime.fromisoformat(registration["created_at_utc"].replace("Z", "+00:00"))
        require(created.utcoffset() is not None and created.utcoffset().total_seconds() == 0, "registration time must be UTC")
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("invalid registration time") from error
    require(registration["clock"] == {"name": "std::time::Instant", "scope": "host_monotonic", "calibration": "unqualified_timer_pair_overhead_probe"},
            "unsupported clock registration")
    flags = registration["build_flags"]
    require(isinstance(flags, list) and bool(flags) and all(isinstance(value, str) and value for value in flags), "invalid build flags")
    profile_bytes = file_ref(root, registration["profile"], "profile")
    profile = strict_json(profile_bytes)
    scheduler = registration["scheduler_source_enabled"]
    cases = validate_profile(profile, registration["config"], scheduler)
    tool = object_fields(registration["toolchain"], {"rustc_sha256", "version", "host_target", "sysroot_fingerprint", "dependency_scope"}, "toolchain")
    require(tool["dependency_scope"] == "rustc_executable_and_host_target_libraries_only", "invalid compiler dependency scope")
    for field in ("rustc_sha256", "sysroot_fingerprint"):
        sha(tool[field], field)
    require(isinstance(tool["version"], str) and tool["version"].startswith("rustc ") and len(tool["version"]) < 1024, "invalid compiler identity")
    require(isinstance(tool["host_target"], str) and bool(re.fullmatch(r"[a-zA-Z0-9_-]{3,100}", tool["host_target"])), "invalid compiler host target")
    host = object_fields(registration["host"], {"os", "architecture", "cpu_count", "processor_model"}, "host")
    integer(host["cpu_count"], 1, 4096, "cpu count")
    for field in ("os", "architecture", "processor_model"):
        require(isinstance(host[field], str) and bool(host[field]) and len(host[field]) <= 256
                and all(character.isprintable() for character in host[field]), "invalid host description")
    sources = registration["sources"]
    require(isinstance(sources, list) and 8 <= len(sources) <= 64, "source closure outside bounds")
    paths = set()
    for source in sources:
        data = file_ref(root, source, "source", limit=1048576)
        path = source["file"]
        require(path.startswith("sources/") and path not in paths, "invalid or duplicate source file")
        paths.add(path)
        if path == "sources/scheduler-core/lib.rs":
            require(scheduler and digest(data) == profile["scheduler_source_sha256"], "scheduler source pin mismatch")
    mandatory = {"sources/benchmark-harness/main.rs", "sources/benchmark-harness/ring.rs", "sources/benchmark-harness/tests.rs",
                 "sources/kernel-core/lib.rs", "sources/kernel-core/capabilities.rs", "sources/kernel-core/frames.rs",
                 "sources/kernel-core/boot_inventory.rs", "sources/interfaces/abi-v1/native.rs",
                 "sources/tools/run_kernel_benchmarks.py", "sources/tools/verify_kernel_benchmarks.py", "sources/tools/g03/process.py"}
    require(paths == mandatory | ({"sources/scheduler-core/lib.rs"} if scheduler else set()), "source closure missing or contains undeclared inputs")
    file_ref(root, registration["executable"], "benchmark executable", limit=64 * 1024 * 1024)
    raw_bytes = read_regular(root, "raw.json")
    summary = validate_raw(strict_json(raw_bytes), registration["config"], cases, scheduler)
    receipts = strict_json(read_regular(root, "run_receipts.json"))
    object_fields(receipts, {"schema_version", "compile", "execution"}, "run receipts")
    require(type(receipts["schema_version"]) is int and receipts["schema_version"] == 1
            and isinstance(receipts["compile"], list) and len(receipts["compile"]) == 2 + int(scheduler), "invalid compile receipt set")
    for index, receipt in enumerate(receipts["compile"]):
        validate_receipt(root, receipt, f"compile {index}")
    require(validate_receipt(root, receipts["execution"], "benchmark execution") == raw_bytes,
            "raw data differs from retained process stdout")
    if require_result:
        result = strict_json(read_regular(root, "result.json"))
        object_fields(result, {"schema_version", "kind", "status", "evidence_scope", "native_qualification", "valid",
                               "registration_sha256", "raw_sha256", "summary"}, "result")
        require(type(result["schema_version"]) is int and result["schema_version"] == 1
                and result["kind"] == "kernel_benchmark_run" and result["status"] == "observed"
                and result["evidence_scope"] == "host_microbenchmark" and result["native_qualification"] is False
                and result["valid"] is True and result["registration_sha256"] == registration_hash
                and result["raw_sha256"] == digest(raw_bytes)
                and json.dumps(result["summary"], sort_keys=True, allow_nan=False)
                == json.dumps(summary, sort_keys=True, allow_nan=False),
                "result summary or bindings differ from recomputed packet")
    return summary


def compare_runs(candidate: Path, baseline: Path) -> dict:
    summaries = [verify_run(path, require_result=True) for path in (candidate, baseline)]
    registrations = [strict_json(read_regular(path, "registration.json")) for path in (candidate, baseline)]
    for key in ("host", "toolchain", "config", "build_flags", "scheduler_source_enabled", "clock"):
        require(registrations[0][key] == registrations[1][key], f"comparison {key} mismatch")
    profiles = [strict_json(file_ref(path, record["profile"], "comparison profile"))
                for path, record in zip((candidate, baseline), registrations)]
    require(profiles[0] == profiles[1], "comparison registered profile mismatch")
    result = []
    for current, reference in zip(summaries[0]["cases"], summaries[1]["cases"]):
        require((current["case"], current["implementation"]) == (reference["case"], reference["implementation"]),
                "comparison population mismatch")
        ratio = None
        if current["ns_per_operation"] is not None and reference["ns_per_operation"] is not None:
            ratio = current["ns_per_operation"]["p50"] / reference["ns_per_operation"]["p50"]
        result.append({"case": current["case"], "implementation": current["implementation"],
                       "candidate_over_baseline_median": ratio})
    return {"kind": "descriptive_host_comparison", "native_qualification": False,
            "significance_or_promotion_decision": False, "cases": result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--expected-registration-sha256")
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args(argv)
    try:
        summary = verify_run(args.directory, require_result=True,
                             expected_registration_sha256=args.expected_registration_sha256)
        output = {"verification": "self_consistency_only", "summary": summary}
        if args.baseline:
            output["comparison"] = compare_runs(args.directory, args.baseline)
        print(json.dumps(output, indent=2, allow_nan=False))
        return 0
    except (ValueError, OSError) as error:
        print(f"Benchmark verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
