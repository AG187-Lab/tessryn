"""Evidence-contract tests; synthetic records here are not Tessryn measurements."""

from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from tools.g03.evidence import (
    load_json, main, parse_json, registration_digest, validate_measurement_reports,
    validate_registration, validate_report, validate_result,
)


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64


def fixture_result() -> dict:
    unavailable = {"status": "unavailable", "reason": "No native capability exists in the fixture."}
    return {
        "schema_version": 1,
        "format": "tessryn-evaluation-result",
        "evidence_kind": "implementation_result",
        "subject": "test_fixture",
        "status": "pass",
        "capabilities": {key: copy.deepcopy(unavailable) for key in ("kernel_boot", "gpu_execution", "inference")},
        "bindings": {"evaluator": DIGEST, "artifact_manifest": DIGEST, "registration": DIGEST},
        "execution": {
            "command": ["qemu-system-x86_64", "-drive", "file=build/fixture.img,format=raw,readonly=on"],
            "emulator": {"version": "QEMU emulator version 10.1.0", "binary_sha256": DIGEST},
            "timeout_seconds": 2,
            "max_log_bytes": 1024,
            "elapsed_seconds": 0.1,
            "returncode": 33,
            "reason": "Expected fixture marker and emulator exit were observed.",
        },
        "logs": [{"path": "stdout.log", "sha256": DIGEST, "size_bytes": 128}],
        "actual_sample_count": 0,
        "performance": copy.deepcopy(unavailable),
    }


def synthetic_preregistration() -> dict:
    """Complete synthetic input for format tests, not an enrolled experiment."""
    registration = load_json(ROOT / "evidence/performance-template.json")
    registration.update({
        "registration_id": "synthetic-unit-test-only",
        "registration_state": "preregistered",
        "registered_at_utc": "2026-01-01T00:00:00Z",
        "profile": {
            "candidate": {"source_revision": "1" * 40, "artifact_manifest_sha256": DIGEST},
            "evaluator": {"source_revision": "2" * 40, "sha256": DIGEST},
            "platform": {key: "Synthetic format test only" for key in (
                "hardware", "firmware", "topology", "compiler", "binary_target", "model_checkpoint",
                "quantization", "state_format",
            )},
        },
        "numerical": {
            "status": "declared",
            "reference": {"id": "synthetic-reference", "source_url": "https://example.org/synthetic-reference", "sha256": DIGEST},
            "comparisons": [{"kind": kind, "operator": f"synthetic-{kind}", "dtype": "f32", "atol": 1e-6,
                             "rtol": 1e-5, "finite_required": True,
                             "tolerance_rationale": "Synthetic format-test tolerances only; no empirical claim."}
                            for kind in ("operator", "logits", "probabilities")],
            "teacher_forced": {"history_sha256": DIGEST, "outputs": ["logits", "probabilities"]},
            "greedy_agreement": True,
            "exact_replay_conditions": "Exact replay is required only with matched seed, binary, device, dtype and execution order.",
        },
        "held_out": {
            "status": "declared", "workload_id": "synthetic-test-workload", "sha256": DIGEST,
            "custodian": "independent test custodian", "access_policy": "Outside candidate training and selection authority.",
            "candidate_visible": False, "quality_metric": "synthetic_accuracy",
            "quality_gate": {"direction": "at_least", "threshold": 0.9},
        },
        "performance": {
            "status": "declared", "target_sample_count": 10, "warmup_sample_count": 2, "duration_seconds": 30,
            "load": {
                "arrival_process": "fixed schedule", "offered_requests_per_second": 1, "concurrency": 1,
                "admission_budget": "one request", "cache_state": "cold",
                "prompt_distribution": "fixed synthetic prompts", "output_distribution": "fixed synthetic outputs",
                "tenant_distribution": "one synthetic tenant",
            },
            "thermal": {"mode": "sustained", "sustained_duration_seconds": 30, "ambient_celsius": 22,
                        "power_mode": "mains", "frequency_policy": "fixed test policy"},
            "latency_slos": {"ttft_ms": 10, "inter_token_ms": 10, "completion_ms": 100},
            "metrics": ["ttft_ms", "inter_token_ms", "completion_ms", "throughput", "goodput"],
            "methodology": {
                "independent_runs": 3, "run_order": "paired randomized order", "quantile_estimator": "nearest rank",
                "confidence_interval": "preregistered bootstrap interval", "exclusion_policy": "retain all failures",
                "confidence_level": 0.95,
                "stopping_rule": "fixed sample count and duration", "warmup_policy": "exclude exactly two warmups per run",
            },
        },
    })
    return registration


def synthetic_measurement() -> dict:
    """Synthetic data solely to test future measurement-format invariants."""
    result = fixture_result()
    registration = synthetic_preregistration()
    result.update({"evidence_kind": "measured_performance", "subject": "native_service", "actual_sample_count": 10})
    result["capabilities"]["kernel_boot"] = {"status": "available", "reason": "Synthetic capability record for validator tests only."}
    result["capabilities"]["inference"] = {"status": "available", "reason": "Synthetic capability record for validator tests only."}
    result["bindings"]["registration"] = registration_digest(registration)
    result["performance"] = {
        "status": "measured", "registration": registration, "started_at_utc": "2026-01-01T00:00:01Z",
        "observation_duration_seconds": 30, "independent_run_count": 3,
        "load": copy.deepcopy(registration["performance"]["load"]),
        "thermal": copy.deepcopy(registration["performance"]["thermal"]),
        "request_outcomes": {"accepted": 10, "completed": 10, "rejected": 0, "cancelled": 0, "failed": 0, "slo_compliant": 10},
        "numerical_results": {
            "reference_sha256": DIGEST, "teacher_forced_history_sha256": DIGEST, "raw_results_sha256": DIGEST,
            "sample_count": 30, "finite_values": True, "operator_tolerances_passed": True,
            "logits_tolerances_passed": True, "probabilities_tolerances_passed": True, "greedy_token_agreement": 0.99,
        },
        "held_out_results": {
            "workload_sha256": DIGEST, "raw_results_sha256": DIGEST, "sample_count": 10,
            "quality_metric": "synthetic_accuracy", "quality_value": 0.95,
        },
        "metrics": {
            **{key: {"p50": 1, "p95": 2, "p99": 3, "sample_count": 10} for key in ("ttft_ms", "inter_token_ms", "completion_ms")},
            "throughput": 10 / 30, "goodput": 10 / 30,
        },
        "report_artifacts": {name: {"path": f"synthetic-{name}.json", "sha256": DIGEST, "size_bytes": 128}
                             for name in ("performance_trace", "statistics", "numerical", "held_out")},
    }
    return result


def synthetic_reports(result: dict) -> dict:
    """Invented unit-test payloads only; they are not retained project evidence."""
    registration = result["performance"]["registration"]
    common = {"schema_version": 1, "registration_sha256": result["bindings"]["registration"]}
    requests = [{"request_id": f"synthetic-{index}", "run_id": f"synthetic-run-{index % 3}",
                 "outcome": "completed", "slo_compliant": True,
                 **{name: 1 + index % 3 for name in ("ttft_ms", "inter_token_ms", "completion_ms")},
                 "per_token_ms": [1, 2]} for index in range(10)]
    runs = []
    for index in range(3):
        count = sum(row["run_id"] == f"synthetic-run-{index}" for row in requests)
        metrics = copy.deepcopy(result["performance"]["metrics"])
        for name in ("ttft_ms", "inter_token_ms", "completion_ms"):
            metrics[name]["sample_count"] = count
        metrics.update(throughput=count / 10, goodput=count / 10)
        runs.append({"run_id": f"synthetic-run-{index}", "observation_duration_seconds": 10, "metrics": metrics})
    return {
        "performance_trace": {**common, "format": "tessryn-performance-trace", "sample_unit": "request", "latency_unit": "ms", "requests": requests},
        "statistics": {**common, "format": "tessryn-statistical-report", "rate_unit": "requests/s", "confidence_level": 0.95,
                       "confidence_interval_method": registration["performance"]["methodology"]["confidence_interval"],
                       "intervals": {**{f"{name}.{percentile}": {"lower": 0, "upper": 4}
                                        for name in ("ttft_ms", "inter_token_ms", "completion_ms") for percentile in ("p50", "p95", "p99")},
                                     "throughput": {"lower": 0, "upper": 1}, "goodput": {"lower": 0, "upper": 1}},
                       "independent_runs": runs},
        "numerical": {**common, "format": "tessryn-numerical-report", "reference_sha256": DIGEST,
                      "teacher_forced_history_sha256": DIGEST, "greedy_sample_count": 100, "greedy_agreement_count": 99,
                      "checks": [{"kind": row["kind"], "operator": row["operator"], "dtype": row["dtype"], "sample_count": 10,
                                  "maximum_absolute_error": 1e-8, "maximum_relative_error": 1e-8,
                                  "failure_count": 0, "finite_failure_count": 0} for row in registration["numerical"]["comparisons"]]},
        "held_out": {**common, "format": "tessryn-held-out-report", "workload_sha256": DIGEST,
                     "sample_count": 10, "quality_metric": "synthetic_accuracy", "quality_value": 0.95,
                     "custody_reference": "synthetic-custody-record-only", "baseline": {"status": "unavailable", "reason": "Synthetic unit-test data has no real baseline."}},
    }


def write_synthetic_bundle(directory: Path, result: dict, reports: dict) -> Path:
    for name, report in reports.items():
        artifact = result["performance"]["report_artifacts"][name]
        contents = (json.dumps(report, sort_keys=True) + "\n").encode()
        (directory / artifact["path"]).write_bytes(contents)
        artifact.update(sha256=hashlib.sha256(contents).hexdigest(), size_bytes=len(contents))
    result["performance"]["numerical_results"]["raw_results_sha256"] = result["performance"]["report_artifacts"]["numerical"]["sha256"]
    result["performance"]["held_out_results"]["raw_results_sha256"] = result["performance"]["report_artifacts"]["held_out"]["sha256"]
    path = directory / "synthetic-result.json"
    path.write_text(json.dumps(result))
    return path


class EvidenceTests(unittest.TestCase):
    def test_public_examples_are_assumptions_with_no_claimed_measurements(self):
        for name in ("fixture-registration.json", "performance-template.json"):
            with self.subTest(name=name):
                data = load_json(ROOT / "evidence" / name)
                validate_registration(data)
                self.assertEqual(data["evidence_kind"], "assumption")
                self.assertEqual(data["performance"]["status"], "unavailable")

    def test_fixture_execution_pass_is_not_native_evidence(self):
        validate_result(fixture_result())
        for capability in ("kernel_boot", "gpu_execution", "inference"):
            result = fixture_result()
            result["capabilities"][capability]["status"] = "available"
            with self.subTest(capability=capability), self.assertRaises(ValueError):
                validate_result(result)
        result = fixture_result()
        result["evidence_kind"] = "measured_performance"
        result["actual_sample_count"] = 1
        with self.assertRaises(ValueError):
            validate_result(result)

    def test_failure_timeout_cancellation_unavailability_and_log_limit_are_retained(self):
        for status in ("fail", "timeout", "cancelled", "unavailable", "log_limit"):
            result = fixture_result()
            result["status"] = status
            result["execution"]["returncode"] = None
            result["execution"]["reason"] = "Deliberate negative test outcome."
            if status == "unavailable":
                result["execution"]["command"] = []
                result["execution"]["emulator"] = None
            with self.subTest(status=status):
                validate_result(result)

    def test_fixture_cannot_preregister_a_native_performance_workload(self):
        data = synthetic_preregistration()
        data["subject"] = "test_fixture"
        with self.assertRaises(ValueError):
            validate_registration(data)

    def test_parser_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for value in ('{"a":1,"a":2}', '{"a":{"x":1,"x":2}}', '{"a":NaN}',
                      '{"a":Infinity}', '{"a":-Infinity}', '{"a":1e9999}', '[]'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_json(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError):
                load_json(path)

    def test_deep_json_is_a_reported_validation_error(self):
        data = '{"nested":' + '[' * 2000 + '0' + ']' * 2000 + '}'
        with self.assertRaisesRegex(ValueError, "nesting"):
            parse_json(data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.json"
            path.write_text(data)
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(["validate", str(path)]), 1)
            self.assertIn("Evidence validation failed", errors.getvalue())
            self.assertNotIn("Traceback", errors.getvalue())
        with patch("tools.g03.evidence.json.loads", side_effect=RecursionError):
            with self.assertRaisesRegex(ValueError, "nesting"):
                parse_json("{}")

    def test_cli_rejects_fifo_and_oversized_numeric_evidence_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo.json"
            os.mkfifo(path)
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(["validate", str(path)]), 1)
            self.assertIn("regular file", errors.getvalue())
            path.unlink()
            result = synthetic_measurement()
            result["performance"]["metrics"]["throughput"] = 10**310
            path.write_text(json.dumps(result))
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(["validate", str(path)]), 1)
            self.assertNotIn("Traceback", errors.getvalue())

    def test_canonical_registration_binding_is_independent_of_whitespace_and_key_order(self):
        data = load_json(ROOT / "evidence/fixture-registration.json")
        expected = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        reordered = parse_json(json.dumps(dict(reversed(list(data.items()))), indent=4))
        self.assertEqual(registration_digest(data), expected)
        self.assertEqual(registration_digest(reordered), expected)

    def test_invalid_counts_tolerances_and_authority_are_rejected(self):
        for mutate in (
            lambda data: data["authority"].update(candidate_can_modify_evaluator=True),
            lambda data: data["authority"].update(evaluator="Owner at /opt/private-workspace/evaluator"),
            lambda data: data["held_out"].update(candidate_visible=True),
            lambda data: data["held_out"].update(custodian=""),
            lambda data: data["numerical"]["comparisons"][0].update(atol=-1),
            lambda data: data["numerical"]["comparisons"][0].update(rtol=float("nan")),
            lambda data: data["performance"].update(target_sample_count=True),
            lambda data: data["performance"].update(target_sample_count=0),
            lambda data: data["performance"]["thermal"].update(sustained_duration_seconds=0),
            lambda data: data["performance"]["load"].update(arrival_process=""),
            lambda data: data["performance"]["methodology"].update(exclusion_policy=""),
            lambda data: data["performance"]["methodology"].update(confidence_level=1),
            lambda data: data["numerical"]["comparisons"][0].update(tolerance_rationale=""),
            lambda data: data["numerical"]["comparisons"].pop(),
            lambda data: data["performance"]["thermal"].update(sustained_duration_seconds=31),
            lambda data: data["profile"]["candidate"].update(source_revision="main"),
            lambda data: data.update(registered_at_utc="2026-02-30T00:00:00Z"),
        ):
            data = synthetic_preregistration()
            mutate(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_registration(data)

    def test_public_results_reject_local_paths_and_combined_log_overflow(self):
        for mutate in (
            lambda data: data["execution"]["command"].append("/Users/operator/private.img"),
            lambda data: data["execution"].update(reason="Private input was C:\\Users\\operator\\candidate.img"),
            lambda data: data["execution"]["command"].append("file=/tmp/operator.img,format=raw"),
            lambda data: data["logs"][0].update(path="../private.log"),
            lambda data: data["execution"].update(emulator=None),
            lambda data: data["execution"].update(elapsed_seconds=float("inf")),
            lambda data: data["logs"].append({"path": "stderr.log", "sha256": DIGEST, "size_bytes": 1024}),
            lambda data: data.update(actual_sample_count=1),
            lambda data: data.update(subject=[]),
        ):
            data = fixture_result()
            mutate(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_result(data)

    def test_synthetic_measurement_requires_prerun_identity_numerical_and_quality_evidence(self):
        validate_result(synthetic_measurement())
        for mutate in (
            lambda data: data["bindings"].update(registration="b" * 64),
            lambda data: data["performance"].update(started_at_utc="2025-12-31T23:59:59Z"),
            lambda data: data["performance"]["numerical_results"].update(reference_sha256="b" * 64),
            lambda data: data["performance"]["numerical_results"].update(logits_tolerances_passed=False),
            lambda data: data["performance"]["held_out_results"].update(workload_sha256="b" * 64),
            lambda data: data["performance"]["held_out_results"].update(quality_value=0.5),
        ):
            data = synthetic_measurement()
            mutate(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_result(data)

    def test_measurements_reject_inconsistent_samples_outcomes_load_and_thermal_gates(self):
        for mutate in (
            lambda data: data["performance"]["request_outcomes"].update(completed=11),
            lambda data: data["performance"]["request_outcomes"].update(accepted=9),
            lambda data: data["performance"]["request_outcomes"].update(slo_compliant=11),
            lambda data: data["performance"]["metrics"]["ttft_ms"].update(sample_count=11),
            lambda data: data["performance"]["metrics"]["ttft_ms"].update(sample_count=9),
            lambda data: data["performance"]["metrics"]["ttft_ms"].update(p99=0.5),
            lambda data: data["performance"]["metrics"].update(goodput=2),
            lambda data: data["performance"]["load"].update(cache_state="warm"),
            lambda data: data["performance"]["thermal"].update(sustained_duration_seconds=20),
            lambda data: data["performance"]["thermal"].update(sustained_duration_seconds=31),
            lambda data: data["performance"]["thermal"].update(ambient_celsius=80),
            lambda data: data["performance"]["thermal"].update(power_mode="battery"),
            lambda data: data["performance"]["thermal"].update(frequency_policy="boost"),
            lambda data: data["performance"]["metrics"].update(throughput=1e6, goodput=999999),
            lambda data: data["performance"]["metrics"].update(goodput=0),
            lambda data: data["performance"]["report_artifacts"].pop("statistics"),
            lambda data: data["performance"]["report_artifacts"]["statistics"].update(path="../private.json"),
            lambda data: data["performance"]["report_artifacts"]["numerical"].update(sha256="b" * 64),
            lambda data: data["performance"]["report_artifacts"]["held_out"].update(sha256="b" * 64),
            lambda data: data["performance"].update(observation_duration_seconds=20),
            lambda data: data["performance"].update(independent_run_count=2),
        ):
            data = synthetic_measurement()
            mutate(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_result(data)

    def test_rejected_measurement_can_preserve_failed_gates_without_claiming_pass(self):
        data = synthetic_measurement()
        data["status"] = "fail"
        data["performance"]["numerical_results"]["logits_tolerances_passed"] = False
        data["performance"]["held_out_results"]["quality_value"] = 0.5
        data["performance"]["metrics"]["ttft_ms"]["sample_count"] = 9
        validate_result(data)

    def test_passing_native_measurements_require_available_capabilities(self):
        data = synthetic_measurement()
        data["capabilities"]["kernel_boot"]["status"] = "unavailable"
        with self.assertRaisesRegex(ValueError, "available kernel boot"):
            validate_result(data)
        data["status"] = "fail"
        validate_result(data)

        data = synthetic_measurement()
        data["capabilities"]["inference"]["status"] = "unavailable"
        with self.assertRaisesRegex(ValueError, "available inference"):
            validate_result(data)
        data["status"] = "fail"
        validate_result(data)

        data = synthetic_measurement()
        data["subject"] = "device_artifact"
        data["performance"]["registration"]["subject"] = "device_artifact"
        data["bindings"]["registration"] = registration_digest(data["performance"]["registration"])
        with self.assertRaisesRegex(ValueError, "available GPU execution"):
            validate_result(data)
        data["capabilities"]["gpu_execution"] = {"status": "available", "reason": "Synthetic capability record for validator tests only."}
        validate_result(data)

    def test_request_rates_allow_only_documented_rounding_tolerance(self):
        data = synthetic_measurement()
        data["performance"]["metrics"]["throughput"] += 1e-11
        validate_result(data)
        data["performance"]["metrics"]["throughput"] += 1e-5
        with self.assertRaisesRegex(ValueError, "request count"):
            validate_result(data)

    def test_synthetic_retained_reports_validate_and_bind_to_the_result(self):
        result = synthetic_measurement()
        reports = synthetic_reports(result)
        for report in reports.values():
            validate_report(report)
        with tempfile.TemporaryDirectory() as directory:
            path = write_synthetic_bundle(Path(directory), result, reports)
            validate_measurement_reports(result, Path(directory))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["validate", str(path)]), 0)

    def test_synthetic_native_result_can_identify_a_runner_without_an_emulator(self):
        result = synthetic_measurement()
        result["execution"].update(command=["native-target-runner"], returncode=0, emulator=None)
        validate_result(result)
        with tempfile.TemporaryDirectory() as directory:
            path = write_synthetic_bundle(Path(directory), result, synthetic_reports(result))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["validate", str(path)]), 0)
        result["execution"]["returncode"] = None
        with self.assertRaisesRegex(ValueError, "exit code"):
            validate_result(result)

    def test_report_payload_contracts_reject_omissions_and_invalid_statistics(self):
        mutations = (
            ("performance_trace", lambda d: d["requests"][0].pop("per_token_ms")),
            ("performance_trace", lambda d: d["requests"].append(copy.deepcopy(d["requests"][0]))),
            ("performance_trace", lambda d: d["requests"][0].update(outcome="failed", slo_compliant=True)),
            ("statistics", lambda d: d["intervals"].pop("ttft_ms.p99")),
            ("statistics", lambda d: d["intervals"]["ttft_ms.p99"].update(lower=5, upper=1)),
            ("statistics", lambda d: d["independent_runs"].append(copy.deepcopy(d["independent_runs"][0]))),
            ("numerical", lambda d: d["checks"][0].pop("maximum_absolute_error")),
            ("numerical", lambda d: d["checks"][0].update(failure_count=11)),
            ("numerical", lambda d: d["checks"].pop()),
            ("held_out", lambda d: d.pop("custody_reference")),
        )
        for name, mutate in mutations:
            report = synthetic_reports(synthetic_measurement())[name]
            mutate(report)
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_report(report)

    def test_retained_bundles_reject_changed_bytes_missing_reports_and_path_escape(self):
        for failure in ("changed", "missing", "symlink", "parent_symlink"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
                root = Path(directory)
                result = synthetic_measurement()
                write_synthetic_bundle(root, result, synthetic_reports(result))
                artifact = result["performance"]["report_artifacts"]["statistics"]
                path = root / artifact["path"]
                if failure == "changed":
                    path.write_bytes(b"changed")
                elif failure == "missing":
                    path.unlink()
                else:
                    target = Path(outside) / path.name
                    path.rename(target)
                    if failure == "symlink":
                        path.symlink_to(target)
                    else:
                        (root / "escape").symlink_to(Path(outside), target_is_directory=True)
                        artifact["path"] = f"escape/{target.name}"
                with self.assertRaises((ValueError, OSError)):
                    validate_measurement_reports(result, root)

    def test_valid_hashes_do_not_allow_report_summaries_to_disagree(self):
        mutations = (
            ("performance_trace", lambda d: d["requests"][0].update(outcome="failed", slo_compliant=False)),
            ("performance_trace", lambda d: d["requests"][0].update(ttft_ms=1000)),
            ("statistics", lambda d: d.update(confidence_interval_method="post hoc method")),
            ("statistics", lambda d: d.update(confidence_level=0.01)),
            ("statistics", lambda d: d["independent_runs"].pop()),
            ("statistics", lambda d: d["independent_runs"][0]["metrics"]["ttft_ms"].update(sample_count=1)),
            ("statistics", lambda d: d["independent_runs"][0]["metrics"].update(throughput=999)),
            ("statistics", lambda d: d["intervals"]["ttft_ms.p99"].update(lower=0, upper=1)),
            ("numerical", lambda d: d["checks"][0].update(failure_count=1)),
            ("numerical", lambda d: d.update(reference_sha256="b" * 64)),
            ("held_out", lambda d: d.update(sample_count=9)),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                result = synthetic_measurement()
                reports = synthetic_reports(result)
                mutate(reports[name])
                path = write_synthetic_bundle(Path(directory), result, reports)
                with self.assertRaises(ValueError):
                    validate_measurement_reports(result, Path(directory))
                with redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(main(["validate", str(path)]), 1)
                self.assertNotIn("Traceback", errors.getvalue())

    def test_lower_sample_gate_cannot_allow_dropped_completed_latency_samples(self):
        result = synthetic_measurement()
        result["performance"]["registration"]["performance"]["target_sample_count"] = 9
        result["bindings"]["registration"] = registration_digest(result["performance"]["registration"])
        for name in ("ttft_ms", "inter_token_ms", "completion_ms"):
            result["performance"]["metrics"][name]["sample_count"] = 9
        with tempfile.TemporaryDirectory() as directory:
            write_synthetic_bundle(Path(directory), result, synthetic_reports(result))
            with self.assertRaisesRegex(ValueError, "aggregate latency sample"):
                validate_measurement_reports(result, Path(directory))

    def test_cli_accepts_examples_and_reports_invalid_evidence(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["validate", str(ROOT / "evidence/fixture-registration.json")]), 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unknown.json"
            path.write_text('{"format":"unknown"}')
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(["validate", str(path)]), 1)
            self.assertIn("unknown evidence format", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
