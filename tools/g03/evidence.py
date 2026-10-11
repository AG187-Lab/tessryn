#!/usr/bin/env python3
"""Validate G03 public evidence without importing third-party packages.

Validation checks the evidence contract, not the truth of a measurement or the
independence of its evaluator. Trusted operators must verify bound hashes and
retain preregistrations before execution outside candidate modification authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any


SUBJECTS = {"test_fixture", "tessryn_kernel", "native_service", "device_artifact"}
STATUSES = {"pass", "fail", "timeout", "cancelled", "unavailable", "log_limit"}
CAPABILITIES = {"kernel_boot", "gpu_execution", "inference"}
HASH = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON number: {value}")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite JSON number")
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes | str) -> dict[str, Any]:
    """Parse a captured snapshot, rejecting duplicate keys and nonfinite numbers."""
    value = json.loads(data, object_pairs_hook=_unique_object,
                       parse_constant=_reject_constant, parse_float=_finite_float)
    if not isinstance(value, dict):
        raise ValueError("evidence must be a JSON object")
    return value


def load_json(path: str | Path) -> dict[str, Any]:
    """Read an object using the same parser as in-memory evidence snapshots."""
    return parse_json(Path(path).read_bytes())


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _object(value: Any, name: str, keys: set[str]) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{name} must be an object")
    _require(set(value) == keys, f"{name} requires exactly: {', '.join(sorted(keys))}")
    return value


def _text(value: Any, name: str) -> None:
    _require(isinstance(value, str) and bool(value.strip()), f"{name} must be nonempty text")
    _require(not any(prefix in value for prefix in ("/Users/", "/home/", "/private/")),
             f"{name} exposes a local host path")


def _number(value: Any, name: str, minimum: float = 0, positive: bool = False) -> None:
    _require(type(value) is int or type(value) is float and math.isfinite(value),
             f"{name} must be a finite number")
    _require(value > minimum if positive else value >= minimum,
             f"{name} must be {'greater than' if positive else 'at least'} {minimum}")


def _count(value: Any, name: str, minimum: int = 0) -> None:
    _require(type(value) is int and value >= minimum, f"{name} must be an integer >= {minimum}")


def _hash(value: Any, name: str) -> None:
    _require(isinstance(value, str) and HASH.fullmatch(value) is not None,
             f"{name} must be a lowercase SHA-256 digest")


def _enum(value: Any, name: str, options: set[str]) -> None:
    _require(isinstance(value, str) and value in options, f"invalid {name}")


def _timestamp(value: Any, name: str) -> datetime:
    _require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
             f"{name} must be a UTC timestamp ending in Z")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError(f"invalid {name}") from error


def _profile(value: Any) -> None:
    profile = _object(value, "profile", {"candidate", "evaluator", "platform"})
    candidate = _object(profile["candidate"], "profile.candidate", {"source_revision", "artifact_manifest_sha256"})
    evaluator = _object(profile["evaluator"], "profile.evaluator", {"source_revision", "sha256"})
    for name, component in (("candidate", candidate), ("evaluator", evaluator)):
        revision = component["source_revision"]
        _require(isinstance(revision, str) and REVISION.fullmatch(revision) is not None,
                 f"profile.{name}.source_revision must be a full source revision")
    _hash(candidate["artifact_manifest_sha256"], "profile.candidate.artifact_manifest_sha256")
    _hash(evaluator["sha256"], "profile.evaluator.sha256")
    platform = _object(profile["platform"], "profile.platform", {
        "hardware", "firmware", "topology", "compiler", "binary_target", "model_checkpoint",
        "quantization", "state_format",
    })
    for key, value in platform.items():
        _text(value, f"profile.platform.{key}")


def _relative(value: Any, name: str) -> None:
    _text(value, name)
    path = PurePosixPath(value)
    _require(not path.is_absolute() and ".." not in path.parts and "\\" not in value,
             f"{name} must be a repository/output-relative path")


def _unavailable(value: Any, name: str) -> None:
    item = _object(value, name, {"status", "reason"})
    _require(item["status"] == "unavailable", f"{name}.status must be unavailable")
    _text(item["reason"], f"{name}.reason")


def _authority(value: Any) -> None:
    item = _object(value, "authority", {
        "evaluator", "candidate_can_modify_evaluator", "candidate_can_modify_registration",
        "candidate_can_access_held_out", "candidate_has_physical_disk_authority",
        "candidate_has_device_dma_authority", "candidate_has_promotion_authority",
    })
    _text(item["evaluator"], "authority.evaluator")
    for key, flag in item.items():
        if key != "evaluator":
            _require(flag is False, f"authority.{key} must be false")


def _numerical(value: Any) -> None:
    item = _object(value, "numerical", {
        "status", "reference", "comparisons", "teacher_forced", "greedy_agreement",
        "exact_replay_conditions",
    })
    _require(item["status"] == "declared", "numerical.status must be declared")
    ref = _object(item["reference"], "numerical.reference", {"id", "source_url", "sha256"})
    _text(ref["id"], "numerical.reference.id")
    _text(ref["source_url"], "numerical.reference.source_url")
    _require(ref["source_url"].startswith("https://"), "reference must identify an HTTPS source")
    _hash(ref["sha256"], "numerical.reference.sha256")
    _require(isinstance(item["comparisons"], list) and bool(item["comparisons"]),
             "numerical.comparisons must contain dtype/operator tolerances")
    for comparison in item["comparisons"]:
        row = _object(comparison, "numerical comparison", {"operator", "dtype", "atol", "rtol", "finite_required"})
        _text(row["operator"], "comparison.operator")
        _text(row["dtype"], "comparison.dtype")
        _number(row["atol"], "comparison.atol")
        _number(row["rtol"], "comparison.rtol")
        _require(row["finite_required"] is True, "comparison.finite_required must be true")
    forced = _object(item["teacher_forced"], "teacher_forced", {"history_sha256", "outputs"})
    _hash(forced["history_sha256"], "teacher_forced.history_sha256")
    _require(forced["outputs"] == ["logits", "probabilities"],
             "teacher_forced.outputs must register logits and probabilities")
    _require(item["greedy_agreement"] is True, "greedy agreement must be recorded")
    _text(item["exact_replay_conditions"], "numerical.exact_replay_conditions")


def _held_out(value: Any) -> None:
    item = _object(value, "held_out", {
        "status", "workload_id", "sha256", "custodian", "access_policy", "candidate_visible",
        "quality_metric", "quality_gate",
    })
    _require(item["status"] == "declared", "held_out.status must be declared")
    for key in ("workload_id", "custodian", "access_policy"):
        _text(item[key], f"held_out.{key}")
    _hash(item["sha256"], "held_out.sha256")
    _require(item["candidate_visible"] is False, "held-out content must be withheld from candidate authority")
    _text(item["quality_metric"], "held_out.quality_metric")
    gate = _object(item["quality_gate"], "held_out.quality_gate", {"direction", "threshold"})
    _enum(gate["direction"], "quality_gate.direction", {"at_least", "at_most"})
    _number(gate["threshold"], "quality_gate.threshold")


def _load(value: Any) -> None:
    item = _object(value, "load", {
        "arrival_process", "offered_requests_per_second", "concurrency", "admission_budget",
        "cache_state", "prompt_distribution", "output_distribution", "tenant_distribution",
    })
    for key in ("arrival_process", "admission_budget", "cache_state", "prompt_distribution",
                "output_distribution", "tenant_distribution"):
        _text(item[key], f"load.{key}")
    _number(item["offered_requests_per_second"], "load.offered_requests_per_second", positive=True)
    _count(item["concurrency"], "load.concurrency", 1)


def _thermal(value: Any) -> None:
    item = _object(value, "thermal", {
        "mode", "sustained_duration_seconds", "ambient_celsius", "power_mode", "frequency_policy",
    })
    _require(item["mode"] == "sustained", "thermal.mode must be sustained")
    _number(item["sustained_duration_seconds"], "thermal.sustained_duration_seconds", positive=True)
    _number(item["ambient_celsius"], "thermal.ambient_celsius", minimum=-273.15)
    _text(item["power_mode"], "thermal.power_mode")
    _text(item["frequency_policy"], "thermal.frequency_policy")


def _performance_plan(value: Any) -> None:
    item = _object(value, "performance", {
        "status", "target_sample_count", "warmup_sample_count", "duration_seconds",
        "load", "thermal", "latency_slos", "metrics",
        "methodology",
    })
    _require(item["status"] == "declared", "performance.status must be declared")
    _count(item["target_sample_count"], "performance.target_sample_count", 1)
    _count(item["warmup_sample_count"], "performance.warmup_sample_count")
    _number(item["duration_seconds"], "performance.duration_seconds", positive=True)
    _load(item["load"])
    _thermal(item["thermal"])
    slos = _object(item["latency_slos"], "latency_slos", {"ttft_ms", "inter_token_ms", "completion_ms"})
    for key, value in slos.items():
        _number(value, f"latency_slos.{key}", positive=True)
    _require(item["metrics"] == ["ttft_ms", "inter_token_ms", "completion_ms", "throughput", "goodput"],
             "performance.metrics must register user-visible latency, throughput and goodput")
    methodology = _object(item["methodology"], "methodology", {
        "independent_runs", "run_order", "quantile_estimator", "confidence_interval",
        "exclusion_policy", "stopping_rule", "warmup_policy",
    })
    _count(methodology["independent_runs"], "methodology.independent_runs", 1)
    for name in methodology.keys() - {"independent_runs"}:
        _text(methodology[name], f"methodology.{name}")


def validate_registration(data: dict[str, Any]) -> None:
    """Validate assumptions/preregistration; it does not establish independent authority."""
    required = {
        "schema_version", "format", "evidence_kind", "subject", "registration_id",
        "registration_state", "authority", "numerical", "held_out", "performance",
    }
    if isinstance(data, dict) and data.get("registration_state") == "preregistered":
        required.update({"registered_at_utc", "profile"})
    item = _object(data, "registration", required)
    _require(type(item["schema_version"]) is int and item["schema_version"] == 1, "unsupported schema_version")
    _require(item["format"] == "tessryn-evaluation-registration", "invalid registration format")
    _require(item["evidence_kind"] == "assumption", "registrations declare assumptions, not results")
    _enum(item["subject"], "subject", SUBJECTS)
    _text(item["registration_id"], "registration_id")
    _enum(item["registration_state"], "registration_state", {"fixture_protocol", "template", "preregistered"})
    _authority(item["authority"])
    if item["registration_state"] != "preregistered":
        for section in ("numerical", "held_out", "performance"):
            _unavailable(item[section], section)
        _require((item["subject"] == "test_fixture") == (item["registration_state"] == "fixture_protocol"),
                 "fixtures require fixture_protocol; future capability plans require template")
    else:
        _require(item["subject"] != "test_fixture", "fixtures cannot preregister native performance")
        _timestamp(item["registered_at_utc"], "registered_at_utc")
        _profile(item["profile"])
        _numerical(item["numerical"])
        _held_out(item["held_out"])
        _performance_plan(item["performance"])


def registration_digest(data: dict[str, Any]) -> str:
    """Hash validated canonical JSON so an embedded registration has one identity."""
    validate_registration(data)
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_result(data: dict[str, Any]) -> None:
    """Validate a bounded execution record and reject misleading fixture claims."""
    item = _object(data, "result", {
        "schema_version", "format", "evidence_kind", "subject", "status", "capabilities",
        "bindings", "execution", "logs", "actual_sample_count", "performance",
    })
    _require(type(item["schema_version"]) is int and item["schema_version"] == 1, "unsupported schema_version")
    _require(item["format"] == "tessryn-evaluation-result", "invalid result format")
    _enum(item["evidence_kind"], "result evidence_kind", {"implementation_result", "measured_performance"})
    _enum(item["subject"], "subject", SUBJECTS)
    _enum(item["status"], "status", STATUSES)
    capabilities = _object(item["capabilities"], "capabilities", CAPABILITIES)
    for name, value in capabilities.items():
        capability = _object(value, f"capabilities.{name}", {"status", "reason"})
        _enum(capability["status"], f"{name} capability", {"available", "unavailable"})
        _text(capability["reason"], f"capabilities.{name}.reason")
        if item["subject"] == "test_fixture":
            _require(capability["status"] == "unavailable", "fixture results cannot establish native capabilities")
    bindings = _object(item["bindings"], "bindings", {"evaluator", "artifact_manifest", "registration"})
    for name, value in bindings.items():
        _hash(value, f"bindings.{name}")
    execution = _object(item["execution"], "execution", {
        "command", "emulator", "timeout_seconds", "max_log_bytes", "elapsed_seconds", "returncode", "reason",
    })
    command = execution["command"]
    _require(isinstance(command, list), "execution.command must be an argv array")
    _require(bool(command) or item["status"] == "unavailable", "execution.command must identify the emulator")
    for argument in command:
        _text(argument, "execution.command argument")
        _require(re.search(r"(?:^|[=,])/", argument) is None and "../" not in argument,
                 "public commands must use relative paths and executable names")
    _number(execution["timeout_seconds"], "execution.timeout_seconds", positive=True)
    _count(execution["max_log_bytes"], "execution.max_log_bytes", 1)
    _number(execution["elapsed_seconds"], "execution.elapsed_seconds")
    if execution["emulator"] is not None:
        emulator = _object(execution["emulator"], "execution.emulator", {"version", "binary_sha256"})
        _text(emulator["version"], "execution.emulator.version")
        _hash(emulator["binary_sha256"], "execution.emulator.binary_sha256")
    _require(execution["returncode"] is None or type(execution["returncode"]) is int,
             "execution.returncode must be an integer or null")
    _text(execution["reason"], "execution.reason")
    if item["status"] == "pass":
        _require(execution["returncode"] is not None and execution["returncode"] >= 0,
                 "a passing run requires an emulator exit code")
        _require(execution["emulator"] is not None, "a passing run requires a probed emulator binary")
    _require(isinstance(item["logs"], list), "logs must be an array")
    for log in item["logs"]:
        row = _object(log, "log", {"path", "sha256", "size_bytes"})
        _relative(row["path"], "log.path")
        _hash(row["sha256"], "log.sha256")
        _count(row["size_bytes"], "log.size_bytes")
    _require(sum(log["size_bytes"] for log in item["logs"]) <= execution["max_log_bytes"],
             "combined logs exceed registered byte limit")
    _count(item["actual_sample_count"], "actual_sample_count")
    if item["evidence_kind"] == "implementation_result":
        _require(item["actual_sample_count"] == 0, "harness execution is not a performance sample")
        _unavailable(item["performance"], "performance")
        return
    _require(item["subject"] != "test_fixture", "fixture results cannot be measured performance")
    _count(item["actual_sample_count"], "actual_sample_count", 1)
    performance = _object(item["performance"], "performance measurement", {
        "status", "registration", "load", "thermal", "request_outcomes", "metrics",
        "started_at_utc", "observation_duration_seconds", "numerical_results", "held_out_results",
        "independent_run_count",
    })
    _require(performance["status"] == "measured", "performance.status must be measured")
    validate_registration(performance["registration"])
    _require(performance["registration"]["registration_state"] == "preregistered", "measurement requires preregistration")
    _require(performance["registration"]["subject"] == item["subject"], "measurement subject differs from preregistration")
    registration = performance["registration"]
    _require(bindings["registration"] == registration_digest(registration), "registration binding differs from embedded preregistration")
    _require(bindings["evaluator"] == registration["profile"]["evaluator"]["sha256"], "evaluator binding differs from preregistration")
    _require(bindings["artifact_manifest"] == registration["profile"]["candidate"]["artifact_manifest_sha256"],
             "artifact manifest binding differs from preregistration")
    start = _timestamp(performance["started_at_utc"], "performance.started_at_utc")
    _require(start > _timestamp(registration["registered_at_utc"], "registered_at_utc"),
             "preregistration must precede measurement")
    _number(performance["observation_duration_seconds"], "observation_duration_seconds", positive=True)
    _count(performance["independent_run_count"], "independent_run_count", 1)
    _load(performance["load"])
    _thermal(performance["thermal"])
    outcomes = _object(performance["request_outcomes"], "request_outcomes", {
        "accepted", "completed", "rejected", "cancelled", "failed", "slo_compliant",
    })
    for key, value in outcomes.items():
        _count(value, f"request_outcomes.{key}")
    _require(sum(outcomes[key] for key in ("completed", "rejected", "cancelled", "failed")) == item["actual_sample_count"],
             "request outcomes must account for every actual sample")
    _require(outcomes["accepted"] == outcomes["completed"] + outcomes["cancelled"] + outcomes["failed"],
             "accepted requests must account for completion, cancellation and failure")
    _require(outcomes["slo_compliant"] <= outcomes["completed"], "SLO-compliant requests must be completed")
    numerical = _object(performance["numerical_results"], "numerical_results", {
        "reference_sha256", "teacher_forced_history_sha256", "raw_results_sha256",
        "sample_count", "finite_values", "operator_tolerances_passed", "logits_tolerances_passed",
        "probabilities_tolerances_passed", "greedy_token_agreement",
    })
    for name in ("reference_sha256", "teacher_forced_history_sha256", "raw_results_sha256"):
        _hash(numerical[name], f"numerical_results.{name}")
    _require(numerical["reference_sha256"] == registration["numerical"]["reference"]["sha256"], "numerical reference differs from preregistration")
    _require(numerical["teacher_forced_history_sha256"] == registration["numerical"]["teacher_forced"]["history_sha256"],
             "teacher-forced history differs from preregistration")
    _count(numerical["sample_count"], "numerical_results.sample_count", 1)
    for name in ("finite_values", "operator_tolerances_passed", "logits_tolerances_passed", "probabilities_tolerances_passed"):
        _require(type(numerical[name]) is bool, f"numerical_results.{name} must be boolean")
    _number(numerical["greedy_token_agreement"], "greedy_token_agreement")
    _require(numerical["greedy_token_agreement"] <= 1, "greedy token agreement must be in [0,1]")
    held_out = _object(performance["held_out_results"], "held_out_results", {
        "workload_sha256", "raw_results_sha256", "sample_count", "quality_metric", "quality_value",
    })
    _hash(held_out["workload_sha256"], "held_out_results.workload_sha256")
    _hash(held_out["raw_results_sha256"], "held_out_results.raw_results_sha256")
    _require(held_out["workload_sha256"] == registration["held_out"]["sha256"], "held-out workload differs from preregistration")
    _count(held_out["sample_count"], "held_out_results.sample_count", 1)
    _text(held_out["quality_metric"], "held_out_results.quality_metric")
    _require(held_out["quality_metric"] == registration["held_out"]["quality_metric"], "held-out quality metric differs from preregistration")
    _number(held_out["quality_value"], "held_out_results.quality_value")
    metrics = _object(performance["metrics"], "metrics", {"ttft_ms", "inter_token_ms", "completion_ms", "throughput", "goodput"})
    for name in ("ttft_ms", "inter_token_ms", "completion_ms"):
        distribution = _object(metrics[name], name, {"p50", "p95", "p99", "sample_count"})
        for percentile in ("p50", "p95", "p99"):
            _number(distribution[percentile], f"{name}.{percentile}")
        _require(distribution["p50"] <= distribution["p95"] <= distribution["p99"], f"{name} percentiles must be ordered")
        _count(distribution["sample_count"], f"{name}.sample_count", 1)
        _require(distribution["sample_count"] <= outcomes["completed"], f"{name} request sample count exceeds completed requests")
    for name in ("throughput", "goodput"):
        _number(metrics[name], name)
    _require(metrics["goodput"] <= metrics["throughput"], "goodput cannot exceed throughput")
    if item["status"] == "pass":
        _require(capabilities["kernel_boot"]["status"] == "available",
                 "passing native performance evidence requires available kernel boot")
        if item["subject"] == "device_artifact":
            _require(capabilities["gpu_execution"]["status"] == "available",
                     "passing device performance evidence requires available GPU execution")
        plan = performance["registration"]["performance"]
        _require(item["actual_sample_count"] >= plan["target_sample_count"],
                 "passing measurement requires the registered sample count")
        for name in ("ttft_ms", "inter_token_ms", "completion_ms"):
            _require(metrics[name]["sample_count"] >= plan["target_sample_count"], f"{name} misses the registered sample count")
        _require(performance["observation_duration_seconds"] >= plan["duration_seconds"], "measurement misses registered observation duration")
        _require(performance["independent_run_count"] >= plan["methodology"]["independent_runs"], "measurement misses registered independent runs")
        _require(performance["load"] == plan["load"], "passing measurement must use the registered load")
        _require(performance["thermal"]["sustained_duration_seconds"] >= plan["thermal"]["sustained_duration_seconds"],
                 "passing measurement requires the registered sustained thermal duration")
        _require(all(numerical[name] for name in ("finite_values", "operator_tolerances_passed", "logits_tolerances_passed", "probabilities_tolerances_passed")),
                 "passing performance evidence requires numerical gates")
        gate = registration["held_out"]["quality_gate"]
        quality = held_out["quality_value"]
        _require(quality >= gate["threshold"] if gate["direction"] == "at_least" else quality <= gate["threshold"],
                 "passing performance evidence requires the registered held-out quality gate")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["validate"])
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        data = load_json(args.path)
        if data.get("format") == "tessryn-evaluation-registration":
            validate_registration(data)
        elif data.get("format") == "tessryn-evaluation-result":
            validate_result(data)
        else:
            raise ValueError("unknown evidence format")
    except (OSError, ValueError, TypeError) as error:
        print(f"Evidence validation failed: {error}", file=sys.stderr)
        return 1
    print(f"Validated {data['format']} (schema version 1).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
