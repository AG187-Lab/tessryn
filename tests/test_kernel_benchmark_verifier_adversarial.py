"""Independent adversarial checks; fixture numbers are not measurements."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_kernel_benchmarks as verifier


# Independent literal answers for seven iterations with seed eleven. These
# deliberately do not call expected_checksum while constructing valid inputs.
CHECKSUMS = {
    "timer_pair": 32,
    "empty_harness": 32,
    "scheduler_reference_dispatch_cycle": 32,
    "queue_roundtrip_batch_1": 109,
    "queue_roundtrip_batch_8": 2167,
    "queue_roundtrip_batch_64": 105067,
    "queue_full_rejection": 18,
    "queue_empty_rejection": 18,
    "memory_allocate_revoke_release": 39,
    "memory_access_check": 7340064,
    "host_zero_4096": 11,
    "host_zero_65536": 11,
    "host_copy_4096": 109,
    "host_copy_65536": 109,
    "scheduler_policy_dispatch_stop_cycle": 32,
    "scheduler_policy_dispatch_latency": 11,
}
CONFIG = {"samples": 3, "warmup": 2, "iterations": 7, "seed": 11}
CHECKS = ["ring_full_empty_wrap_fifo", "ring_matches_vecdeque_replay",
          "memory_rejects_foreign_bounds_revoked", "memory_lifecycle_drained",
          "host_zero_and_copy_exact", "benchmark_operations_exact",
          "scheduler_reference_round_robin"]


def fixture():
    profile = json.loads((ROOT / "planning/kernel-benchmark-profile.json").read_text())
    cases = [row for row in profile["cases"] if not row["scheduler_required"]]
    samples = []
    for row in cases:
        for index in range(CONFIG["samples"]):
            samples.append({"case": row["case"], "implementation": row["implementation"],
                            "sample_unit": row["sample_unit"], "sample_index": index,
                            "elapsed_ns": 100 + 10 * index,
                            "operations": CONFIG["iterations"] * row["operations_per_iteration"],
                            "checksum": CHECKSUMS[row["case"]],
                            "batch_size": row["batch_size"],
                            "bytes_per_operation": row["bytes_per_operation"]})
    raw = {"schema_version": 1, "kind": "kernel_benchmark_raw",
           "clock": "std::time::Instant", "config": copy.deepcopy(CONFIG),
           "samples": samples, "checks": list(CHECKS), "logical_replay": None}
    return profile, cases, raw


class RawVerifierAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.profile, self.cases, self.raw = fixture()

    def verify(self, raw=None):
        return verifier.validate_raw(self.raw if raw is None else raw, CONFIG, self.cases, False)

    def test_literal_workload_answers_and_scope_are_preserved(self):
        for row in self.cases:
            with self.subTest(case=row["case"], implementation=row["implementation"]):
                self.assertEqual(verifier.expected_checksum(row, CONFIG), CHECKSUMS[row["case"]])
        summary = self.verify()
        self.assertEqual(summary["capture_origin"], "unverified_offline")
        self.assertFalse(summary["native_qualification"])
        self.assertFalse(summary["overhead_subtraction"])
        self.assertIn("independent_capture_authentication", summary["unavailable"])

    def test_each_batch_population_is_explicitly_amortized(self):
        summary = self.verify()
        for case in summary["cases"]:
            self.assertEqual(case["sample_unit"], "timed_batch")
            self.assertEqual(case["quantile_population"], "amortized_timed_batch_averages")
            self.assertEqual(case["sample_count"], CONFIG["samples"])

    def test_nearest_rank_has_no_interpolation_or_subtraction(self):
        observed = verifier.quantiles([1000, 1, 100, 10])
        self.assertEqual(observed, {"min": 1, "p50": 10, "p95": 1000,
                                    "p99": 1000, "max": 1000, "mean": 277.75})
        self.assertEqual(verifier.quantiles([7]),
                         {"min": 7, "p50": 7, "p95": 7, "p99": 7, "max": 7, "mean": 7})
        with self.assertRaises(ValueError):
            verifier.quantiles([])

    def test_zero_duration_is_retained_and_suppresses_operation_average(self):
        self.raw["samples"][0]["elapsed_ns"] = 0
        summary = self.verify()
        case = next(row for row in summary["cases"] if row["case"] == "timer_pair")
        self.assertEqual(case["sample_count"], 3)
        self.assertEqual(case["zero_duration_samples"], 1)
        self.assertEqual(case["elapsed_ns"]["min"], 0)
        self.assertEqual(case["measurement_status"], "resolution_limited")
        self.assertIsNone(case["ns_per_operation"])

    def test_timer_checksum_cannot_be_fabricated(self):
        self.raw["samples"][0]["checksum"] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()

    def test_missing_duplicate_and_out_of_range_sample_indices_are_rejected(self):
        for mutate in (lambda raw: raw["samples"].pop(),
                       lambda raw: raw["samples"].__setitem__(1, copy.deepcopy(raw["samples"][0])),
                       lambda raw: raw["samples"][0].__setitem__("sample_index", 3)):
            raw = copy.deepcopy(self.raw)
            mutate(raw)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.verify(raw)

    def test_pair_identity_does_not_allow_substitution_of_an_implementation(self):
        sample = next(item for item in self.raw["samples"]
                      if item["case"] == "queue_roundtrip_batch_1"
                      and item["implementation"] == "bounded_ring")
        sample["implementation"] = "vec_deque_reference"
        with self.assertRaisesRegex(ValueError, "duplicate|missing"):
            self.verify()

    def test_single_operation_labels_cannot_be_applied_to_batches(self):
        self.raw["samples"][0]["sample_unit"] = "single_operation"
        self.raw["samples"][0]["operations"] = 1
        with self.assertRaises(ValueError):
            self.verify()

    def test_configuration_and_operation_count_changes_are_rejected(self):
        for key, value in (("seed", 12), ("iterations", 8), ("warmup", 3), ("samples", 4)):
            raw = copy.deepcopy(self.raw)
            raw["config"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(raw)
        self.raw["samples"][0]["operations"] -= 1
        with self.assertRaisesRegex(ValueError, "operation"):
            self.verify()

    def test_bool_float_negative_and_unbounded_measurement_fields_are_rejected(self):
        for field, values in {"elapsed_ns": (True, -1, 1.0, 120_000_000_001),
                              "operations": (True, 0, -1, 7.0),
                              "checksum": (True, -1, 1.0, 2**64),
                              "sample_index": (True, -1, 0.0),
                              "batch_size": (True, 1.0),
                              "bytes_per_operation": (False, 0.0)}.items():
            for value in values:
                raw = copy.deepcopy(self.raw)
                raw["samples"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.verify(raw)

    def test_unknown_fields_cases_and_correctness_tags_are_rejected(self):
        for mutate in (lambda raw: raw.__setitem__("native_qualification", True),
                       lambda raw: raw["samples"][0].__setitem__("case", "native_context_switch"),
                       lambda raw: raw["samples"][0].__setitem__("real_cpu_time", 100),
                       lambda raw: raw["checks"].append(raw["checks"][0]),
                       lambda raw: raw["checks"].pop()):
            raw = copy.deepcopy(self.raw)
            mutate(raw)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.verify(raw)

    def test_profile_does_not_accept_equal_but_wrong_numeric_types(self):
        for field, value in (("batch_size", True), ("batch_size", 1.0),
                             ("operations_per_iteration", 1.0),
                             ("bytes_per_operation", False), ("scheduler_required", 0)):
            profile = copy.deepcopy(self.profile)
            profile["cases"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verifier.validate_profile(profile, CONFIG, False)

    def test_strict_json_rejects_duplicate_keys_nonfinite_and_truncation(self):
        for data in (b'{"elapsed_ns":1,"elapsed_ns":2}', b'{"elapsed_ns":NaN}',
                     b'{"elapsed_ns":Infinity}', b'{"elapsed_ns":-Infinity}',
                     b'{"elapsed_ns":1', b'\xff'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                verifier.strict_json(data)

def write_json(path, value):
    path.write_bytes((json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode())


class RetainedPacketAdversarialTests(unittest.TestCase):
    """Unexecuted fixtures demonstrate consistency checks, never provenance."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tessryn-verifier-test-", dir="/private/tmp"
                                                     if Path("/private/tmp").is_dir() else None)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        profile, _, self.raw = fixture()

        def retain(name, data):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return {"file": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

        self.retain = retain
        profile_ref = retain("profile.json", (json.dumps(profile) + "\n").encode())
        source_names = ("benchmark-harness/main.rs", "benchmark-harness/ring.rs",
                        "benchmark-harness/tests.rs", "kernel-core/lib.rs",
                        "kernel-core/capabilities.rs", "kernel-core/frames.rs",
                        "kernel-core/boot_inventory.rs", "interfaces/abi-v1/native.rs",
                        "tools/run_kernel_benchmarks.py", "tools/verify_kernel_benchmarks.py",
                        "tools/g03/process.py")
        sources = [retain("sources/" + name, (ROOT / name).read_bytes()) for name in source_names]
        executable = retain("kernel-benchmark", b"explicitly unexecuted packet fixture\n")
        self.registration = {
            "schema_version": 1, "kind": "kernel_benchmark_registration",
            "evidence_scope": "host_microbenchmark", "config": copy.deepcopy(CONFIG),
            "profile": profile_ref, "sources": sources,
            "toolchain": {"rustc_sha256": "a" * 64, "version": "rustc 1.96.0 fixture",
                          "host_target": "x86_64-unknown-linux-gnu", "sysroot_fingerprint": "b" * 64,
                          "dependency_scope": "rustc_executable_and_host_target_libraries_only"},
            "host": {"os": "Linux", "architecture": "x86_64", "cpu_count": 2,
                     "processor_model": "synthetic test profile"},
            "executable": executable, "created_at_utc": "2026-10-13T00:00:00+00:00",
            "build_flags": ["--edition=2024", "-Copt-level=3", "-Dwarnings"],
            "scheduler_source_enabled": False,
            "clock": {"name": "std::time::Instant", "scope": "host_monotonic",
                      "calibration": "unqualified_timer_pair_overhead_probe"},
            "measurement_semantics": "raw_host_elapsed_no_subtraction",
            "capture_origin": "local_runner_claim_unverified_offline",
            "native_qualification": False, "warmup_policy": "per_case_discard_before_measurement",
        }
        write_json(self.root / "registration.json", self.registration)
        raw_bytes = (json.dumps(self.raw) + "\n").encode()
        retain("raw.json", raw_bytes)

        def receipt(label, stdout):
            return {"status": "completed", "reason": "fixture", "returncode": 0,
                    "elapsed_seconds": 1.0,
                    "stdout": retain("logs/" + label + ".stdout", stdout),
                    "stderr": retain("logs/" + label + ".stderr", b"")}

        self.receipts = {"schema_version": 1,
                         "compile": [receipt("compile-memory", b""), receipt("compile-harness", b"")],
                         "execution": receipt("measurement", raw_bytes)}
        write_json(self.root / "run_receipts.json", self.receipts)

    def verify(self):
        return verifier.verify_run(self.root)

    def test_consistent_unexecuted_packet_does_not_authenticate_execution(self):
        summary = self.verify()
        self.assertEqual(summary["capture_origin"], "unverified_offline")
        self.assertFalse(summary["native_qualification"])
        self.assertIn("independent_capture_authentication", summary["unavailable"])
        self.assertIn("complete_compiler_dependency_identity", summary["unavailable"])

    def test_compiler_fingerprint_cannot_claim_complete_dependency_identity(self):
        self.registration["toolchain"]["dependency_scope"] = "all_compiler_dependencies"
        write_json(self.root / "registration.json", self.registration)
        with self.assertRaisesRegex(ValueError, "dependency scope"):
            self.verify()

    def test_expected_registration_pin_detects_complete_registration_rebinding(self):
        pin = hashlib.sha256((self.root / "registration.json").read_bytes()).hexdigest()
        verifier.verify_run(self.root, expected_registration_sha256=pin)
        self.registration["host"]["cpu_count"] = 3
        write_json(self.root / "registration.json", self.registration)
        with self.assertRaisesRegex(ValueError, "registration"):
            verifier.verify_run(self.root, expected_registration_sha256=pin)

    def test_source_and_executable_changes_break_retained_bindings(self):
        for name in ("sources/kernel-core/lib.rs", "kernel-benchmark"):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "binding"):
                self.verify()
            path.write_bytes(original)

    def test_raw_changes_cannot_diverge_from_original_process_stdout(self):
        self.raw["samples"][0]["elapsed_ns"] += 1
        write_json(self.root / "raw.json", self.raw)
        with self.assertRaisesRegex(ValueError, "stdout"):
            self.verify()

    def test_failed_exit_and_unexpected_measurement_stderr_are_rejected(self):
        original = copy.deepcopy(self.receipts)
        for field, value in (("status", "timed_out"), ("returncode", 1), ("returncode", True)):
            self.receipts = copy.deepcopy(original)
            self.receipts["execution"][field] = value
            write_json(self.root / "run_receipts.json", self.receipts)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()
        self.receipts = copy.deepcopy(original)
        self.receipts["execution"]["stderr"] = self.retain("logs/measurement.stderr", b"unexpected failure\n")
        write_json(self.root / "run_receipts.json", self.receipts)
        with self.assertRaises(ValueError):
            self.verify()

    def test_missing_compile_and_source_closure_are_rejected(self):
        self.receipts["compile"].pop()
        write_json(self.root / "run_receipts.json", self.receipts)
        with self.assertRaises(ValueError):
            self.verify()
        self.registration["sources"].pop()
        write_json(self.root / "registration.json", self.registration)
        with self.assertRaises(ValueError):
            self.verify()

    def test_symlink_parent_traversal_and_size_bound_are_rejected(self):
        original = self.root / "raw.json"
        retained = self.root / "saved-raw.json"
        original.rename(retained)
        original.symlink_to(retained.name)
        with self.assertRaises(ValueError):
            self.verify()
        for name in ("../raw.json", "/raw.json", "a/../raw.json", "./raw.json", "raw\\json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                verifier.read_regular(self.root, name)
        self.retain("large", b"12345")
        with self.assertRaises(ValueError):
            verifier.read_regular(self.root, "large", limit=4)

    def test_deep_undeclared_json_cannot_become_a_valid_packet(self):
        (self.root / "registration.json").write_bytes(b"[" * 2000 + b"0" + b"]" * 2000)
        with self.assertRaises(ValueError):
            self.verify()

    def test_symlink_ancestor_above_packet_root_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="tessryn-verifier-ancestor-", dir=str(self.root.parent)) as temporary:
            outer = Path(temporary)
            actual = outer / "actual" / "packet"
            shutil.copytree(self.root, actual)
            (outer / "alias").symlink_to(outer / "actual")
            with self.assertRaises(ValueError):
                verifier.verify_run(outer / "alias" / "packet")


def logical_fixture():
    # A chronological one-CPU oracle: short0-2, long2-4, burst4-6,
    # long6-8, short8-9, long9-11, long11-13; expiry arrives7 and
    # reaches its deadline8 without ever being dispatched.
    episodes = [("short", 0, 0, 0, 0), ("long", 0, 2, 2, 1),
                ("burst", 3, 4, 1, 2), ("long", 4, 6, 2, 3),
                ("short", 2, 8, 6, 4), ("long", 8, 9, 1, 5),
                ("long", 11, 11, 0, 6)]
    outcomes = [("short", "completed", 9, 3), ("long", "completed", 13, 8),
                ("burst", "completed", 6, 2), ("expires", "deadline_expired", None, 0)]
    return {"kind": "scheduler_logical_replay", "clock": "synthetic_logical_ns", "quantum_ns": 2,
            "episodes": [dict(zip(("task", "ready_ns", "dispatch_ns", "delay_ns", "dispatch_index"), row))
                         for row in episodes],
            "outcomes": [dict(zip(("task", "status", "completed_ns", "consumed_ns"), row))
                         for row in outcomes]}


class LogicalReplayAdversarialTests(unittest.TestCase):
    def test_logical_delay_population_excludes_expired_undispatched_work(self):
        summary = verifier.validate_logical_replay(logical_fixture(), True)
        self.assertEqual(summary["clock"], "synthetic_logical_ns")
        self.assertFalse(summary["native_qualification"])
        self.assertEqual(summary["readiness_episodes"], 7)
        self.assertEqual(summary["completed_tasks"], 3)
        self.assertEqual(summary["expired_without_dispatch"], 1)
        self.assertEqual(summary["ready_to_dispatch_logical_ns"],
                         {"min": 0, "p50": 1, "p95": 6, "p99": 6, "max": 6, "mean": 12 / 7})
        self.assertIsNone(summary["trace"]["outcomes"][-1]["completed_ns"])

    def test_logical_trace_is_forbidden_without_actual_pinned_policy(self):
        self.assertIsNone(verifier.validate_logical_replay(None, False))
        for trace, enabled in ((logical_fixture(), False), (None, True)):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                verifier.validate_logical_replay(trace, enabled)

    def test_negative_bool_float_and_wrong_delay_fields_are_rejected(self):
        for field in ("ready_ns", "dispatch_ns", "delay_ns", "dispatch_index"):
            for value in (-1, False, 0.0, 1001):
                trace = logical_fixture()
                trace["episodes"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    verifier.validate_logical_replay(trace, True)
        trace = logical_fixture()
        trace["episodes"][4]["delay_ns"] = 0
        with self.assertRaises(ValueError):
            verifier.validate_logical_replay(trace, True)

    def test_missing_expired_outcome_and_false_completed_zero_are_rejected(self):
        for mutate in (lambda trace: trace["outcomes"].pop(),
                       lambda trace: trace["outcomes"][-1].__setitem__("completed_ns", 0),
                       lambda trace: trace["outcomes"][-1].__setitem__("completed_ns", False),
                       lambda trace: trace["outcomes"][-1].__setitem__("status", "completed"),
                       lambda trace: trace["outcomes"][-1].__setitem__("consumed_ns", 1)):
            trace = logical_fixture()
            mutate(trace)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                verifier.validate_logical_replay(trace, True)

    def test_event_order_duplicate_episode_and_clock_conflation_are_rejected(self):
        for mutate in (lambda trace: trace["episodes"].reverse(),
                       lambda trace: trace["episodes"].__setitem__(1, copy.deepcopy(trace["episodes"][0])),
                       lambda trace: trace.__setitem__("clock", "std::time::Instant"),
                       lambda trace: trace.__setitem__("elapsed_ns", 13),
                       lambda trace: trace.__setitem__("quantum_ns", True)):
            trace = logical_fixture()
            mutate(trace)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                verifier.validate_logical_replay(trace, True)

    def test_individual_host_calls_and_simulated_episodes_remain_separate(self):
        profile, _, raw = fixture()
        cases = profile["cases"]
        for row in cases:
            if not row["scheduler_required"]:
                continue
            for index in range(CONFIG["samples"]):
                raw["samples"].append({"case": row["case"], "implementation": row["implementation"],
                                       "sample_unit": row["sample_unit"], "sample_index": index,
                                       "elapsed_ns": 100 + 10 * index,
                                       "operations": 1 if row["sample_unit"] == "single_operation"
                                       else CONFIG["iterations"] * row["operations_per_iteration"],
                                       "checksum": CHECKSUMS[row["case"]],
                                       "batch_size": row["batch_size"],
                                       "bytes_per_operation": row["bytes_per_operation"]})
        raw["checks"] += ["scheduler_policy_reservations_stops_and_denials", "scheduler_logical_replay_exact"]
        raw["logical_replay"] = logical_fixture()
        summary = verifier.validate_raw(raw, CONFIG, cases, True)
        single = next(case for case in summary["cases"] if case["case"] == "scheduler_policy_dispatch_latency")
        self.assertEqual(single["quantile_population"], "individual_host_policy_calls")
        self.assertEqual(single["operations_per_sample"], 1)
        self.assertEqual(single["elapsed_ns"]["p99"], 120)
        self.assertEqual(summary["logical_replay"]["ready_to_dispatch_logical_ns"]["p99"], 6)


if __name__ == "__main__":
    unittest.main()
