"""Interval arithmetic plus adversarial reuse of the original timer oracle.

The compressed diagnostic fixtures remain parser tests, not new execution or
performance evidence. Packet plumbing tests mock the heavyweight existing full
verifier while requiring its call and preserving the real raw/context replay.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_k03_timer_trace import change, fixture, renumber
from tools import preemption_benchmark as benchmark
from tools.k03_timer_protocol import CASES, PROFILE, digest
from tools.k03_timer_trace import _Trace, parse_transcript


def analyze(case="preemption", data=None, binding=None, **kwargs):
    original, context = fixture(case)
    return benchmark._extract_capture(case, original if data is None else data,
        kwargs.get("stderr", b""), kwargs.get("returncode", 33), context if binding is None else binding)


def first_row(data, suffix):
    return next(row for kind, row in _Trace(data).rows if kind == "TESSRYN_K03_TIMER_" + suffix)


class TraceAnalysisTests(unittest.TestCase):
    def test_all_scenarios_preserve_every_irq_and_stop(self):
        for case in CASES:
            with self.subTest(case=case):
                result = analyze(case)
                observed = result["observations"]
                self.assertEqual(result["counts"]["irqs"], sum(observed["irqs"]))
                self.assertEqual(len(result["trusted_stop_samples"]), observed["dispatches"])
                self.assertEqual(result["counts"]["irqs_by_task"], observed["irqs"])
                self.assertGreaterEqual(len(result["irq_samples"]), 3)
                self.assertEqual(result["statistics"]["irq_capture_delay"]["sample_count"], sum(observed["irqs"]))

    def test_every_raw_endpoint_and_context_is_paired(self):
        result = analyze()
        for sample in result["irq_samples"]:
            stop = result["trusted_stop_samples"][sample["trusted_stop_index"]]
            self.assertEqual(sample["capture_delay_ticks"], sample["capture_raw"] - sample["target_raw"])
            self.assertEqual(sample["capture_delay_emulator_virtual_ns"], sample["capture_delay_ticks"] * 10)
            self.assertEqual(sample["target_to_stop_ticks"], sample["capture_delay_ticks"] + sample["capture_to_stop_ticks"])
            self.assertEqual(sample["context"], stop["context"])
            self.assertEqual(sample["lease_generation"], stop["lease_generation"])
            self.assertEqual(sample["task"], stop["task"])
            self.assertLess(sample["dispatch_sequence"], sample["resume_sequence"])
            self.assertLess(sample["resume_sequence"], sample["arm_sequence"])
            self.assertLess(sample["arm_sequence"], sample["trap_sequence"])
            self.assertLess(sample["trap_sequence"], sample["irq_sequence"])
            self.assertLess(sample["irq_sequence"], sample["account_sequence"])
            self.assertRegex(sample["context"]["sha256"], "^[a-f0-9]{64}$")

    def test_zero_capture_delay_is_retained(self):
        data, binding = fixture()
        clock, irq = first_row(data, "CLOCK"), first_row(data, "IRQ")
        target, generation = irq["target_raw"], irq["generation"]
        capture_ns = (target - clock["epoch_raw"]) * 10
        data = change(data, "TESSRYN_K03_TIMER_IRQ", capture_raw=target, capture_ns=capture_ns)
        account_index = next(i for i, row in enumerate(
            [row for kind, row in _Trace(data).rows if kind == "TESSRYN_K03_TIMER_ACCOUNT"])
            if row["lease_generation"] == generation)
        data = change(data, "TESSRYN_K03_TIMER_ACCOUNT", account_index, capture_raw=target, capture_ns=capture_ns)
        result = analyze(data=data, binding=binding)
        self.assertEqual(result["irq_samples"][0]["capture_delay_ticks"], 0)
        self.assertEqual(result["statistics"]["irq_capture_delay"]["ticks"]["minimum"], 0)
        self.assertEqual(result["counts"]["irqs"], sum(result["observations"]["irqs"]))

    def test_rebound_lease_task_target_root_and_context_rejected(self):
        data, _ = fixture()
        variants = [
            change(data, "TESSRYN_K03_TIMER_IRQ", generation=999),
            change(data, "TESSRYN_K03_TIMER_IRQ", task=1),
            change(data, "TESSRYN_K03_TIMER_IRQ", target_raw=123),
            change(data, "TESSRYN_K03_TIMER_RESUME", root=123),
            change(data, "TESSRYN_K03_TIMER_RESUME", generation=2),
            change(data, "TESSRYN_K03_TIMER_TRAP", fp_sha256="0" * 64),
            change(data, "TESSRYN_K03_TIMER_ACCOUNT", lease_generation=999),
        ]
        for mutated in variants:
            with self.subTest(digest=digest(mutated)):
                with self.assertRaises(ValueError):
                    analyze(data=mutated)

    def test_truncation_trailing_mixed_case_and_failed_process_rejected(self):
        data, _ = fixture()
        for mutated in (data[:-1], data[:len(data) // 2], data + data,
                        data + b"TESSRYN_K03_TIMER_FAIL reason=test\n",
                        change(data, "TESSRYN_K03_TIMER_BEGIN", case="budget")):
            with self.subTest(digest=digest(mutated)):
                with self.assertRaises(ValueError):
                    analyze(data=mutated)
        for options in ({"returncode": 0}, {"returncode": True}, {"stderr": b"warning\n"}):
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    analyze(**options)

    def test_timestamp_regression_and_bad_conversion_rejected(self):
        data, _ = fixture()
        irq = first_row(data, "IRQ")
        for fields in ({"capture_raw": irq["target_raw"] - 1}, {"capture_ns": irq["capture_ns"] + 1}):
            with self.assertRaises(ValueError):
                analyze(data=change(data, "TESSRYN_K03_TIMER_IRQ", **fields))
        with self.assertRaises(ValueError):
            analyze(data=change(data, "TESSRYN_K03_TIMER_ACCOUNT", stop_raw=0))

    def test_missing_or_duplicate_irq_and_forged_count_rejected(self):
        data, _ = fixture()
        lines = data.decode().splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith("TESSRYN_K03_TIMER_IRQ "))
        for changed in (lines[:index] + lines[index + 1:], lines[:index] + [lines[index]] + lines[index:]):
            with self.assertRaises(ValueError):
                analyze(data=renumber(("\n".join(changed) + "\n").encode()))
        with self.assertRaises(ValueError):
            analyze(data=change(data, "TESSRYN_K03_TIMER_PASS", irqs_a=999))

    def test_foreign_compiled_binding_rejected(self):
        _, binding = fixture("budget")
        with self.assertRaises(ValueError):
            analyze(binding=binding)

    def test_strict_failed_tenant_outcomes_remain_visible(self):
        for case in ("budget", "deadline"):
            result = analyze(case)
            self.assertIn(result["observations"]["policy"][0]["state"], ("failed", "exhausted", "deadline"))
            for stop in result["trusted_stop_samples"]:
                if stop["late"]:
                    self.assertEqual(stop["state"], "failed")

    def test_missed_arm_has_no_irq_sample_or_fake_context(self):
        # Transform A's final dispatch exactly as the existing adversarial timer
        # oracle does. This synthetic branch is not a native execution receipt.
        data, binding = fixture("budget")
        lines = data.decode().splitlines()
        dispatch = max(i for i, line in enumerate(lines)
                       if line.startswith("TESSRYN_K03_TIMER_DISPATCH ") and " task=0 " in line)
        account = next(i for i in range(dispatch, len(lines))
                       if lines[i].startswith("TESSRYN_K03_TIMER_ACCOUNT "))
        fields = dict(word.split("=", 1) for word in lines[account].split()[1:])
        grant = dict(word.split("=", 1) for word in lines[dispatch].split()[1:])
        lines[dispatch + 2:account] = ["TESSRYN_K03_TIMER_ARM_MISSED sequence=0 task=0 generation="
            + grant["lease_generation"] + " raw=" + fields["capture_raw"] + " now_ns=" + fields["capture_ns"]
            + " soft_ns=" + grant["soft_ns"] + " hard_ns=" + grant["hard_ns"]]
        for i in range(dispatch, len(lines)):
            line = lines[i]
            if line.startswith("TESSRYN_K03_TIMER_ACCOUNT ") and " task=0 " in line:
                line = line.replace("reason=irq outcome=yield", "reason=arm_missed outcome=fail")
                line = re.sub(r"( irqs=| spin_irqs=)([0-9]+)", lambda m: m[1] + str(int(m[2]) - 1), line)
            if line.startswith("TESSRYN_K03_TIMER_MAILBOX ") and " task=0 " in line:
                line = re.sub(r"spin_irqs=([0-9]+)", lambda m: "spin_irqs=" + str(int(m[1]) - 1), line)
            if line.startswith("TESSRYN_K03_TIMER_TERMINAL ") and " task=0 " in line:
                line = line.replace("reason=irq", "reason=arm_missed")
                line = re.sub(r"resumes=([0-9]+)", lambda m: "resumes=" + str(int(m[1]) - 1), line)
            if line.startswith("TESSRYN_K03_TIMER_PASS "):
                line = re.sub(r"(irqs_a=|spin_irqs_a=)([0-9]+)", lambda m: m[1] + str(int(m[2]) - 1), line)
                line = re.sub(r"context_switches=([0-9]+)", lambda m: "context_switches=" + str(int(m[1]) - 2), line)
            lines[i] = line
        synthetic = renumber(("\n".join(lines) + "\n").encode())
        result = analyze("budget", data=synthetic, binding=binding)
        self.assertEqual(result["counts"]["missed_arms"], 1)
        self.assertEqual(sum(not row["entered_cpl3"] for row in result["trusted_stop_samples"]), 1)
        for stop in result["trusted_stop_samples"]:
            if not stop["entered_cpl3"]:
                self.assertIsNone(stop["context"])
                self.assertFalse(any(row["trusted_stop_index"] == stop["sample_index"] for row in result["irq_samples"]))


class ArithmeticTests(unittest.TestCase):
    def test_nearest_rank_is_integer_and_keeps_zeros(self):
        self.assertEqual(benchmark.nearest_rank([0]), {"minimum": 0, "maximum": 0, "p50": 0, "p95": 0, "p99": 0})
        self.assertEqual(benchmark.nearest_rank(list(range(100)))["p95"], 94)
        self.assertEqual(benchmark.nearest_rank([9, 0, 4, 7])["p50"], 4)
        self.assertIsNone(benchmark.nearest_rank([]))
        for values in ([True], [-1], [1.0], [1 << 64], list(range(129))):
            with self.assertRaises(ValueError):
                benchmark.nearest_rank(values)

    def test_duration_zero_regression_overflow_and_bool(self):
        self.assertEqual(benchmark._duration(9, 9), (0, 0))
        for start, end in ((2, 1), (0, benchmark.U64), (True, 2), (-1, 0)):
            with self.assertRaises(ValueError):
                benchmark._duration(start, end)


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tessryn-preemption-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = {"revision": "a" * 40, "dirty": False, "tree_sha256": "b" * 64,
                       "snapshot_algorithm": "git-worktree-v2"}
        manifest = {"source": self.source, "profile": PROFILE, "toolchain": {"fixture": True},
                    "artifacts": [{"path": "preemption/BOOTX64.EFI", "sha256": "c" * 64}],
                    "source_files_sha256": "d" * 64, "runtime_files": {"tools/k03_timer_trace.py": "e" * 64}}
        self.put("a/manifest.json", manifest)
        self.put("b/manifest.json", manifest)
        self.put("host/result.json", {"fixture": True})
        observations = {}
        self.bindings = {}
        for case in CASES:
            raw, binding = fixture(case)
            self.bindings[case] = binding
            observations[case] = parse_transcript(case, raw, 33, b"", binding)
            self.put(case + "/stdout.log", raw)
            self.put(case + "/stderr.log", b"")
            self.put(case + "/registration.json", {"case": case})
            self.put(case + "/result.json", {
                "case": case, "status": "pass", "manifest_sha256": digest(self.get("a/manifest.json")),
                "registration_sha256": digest(self.get(case + "/registration.json")),
                "execution": {"returncode": 33}, "observations": observations[case],
                "logs": [{"path": name, "sha256": digest(self.get(case + "/" + name)),
                          "size_bytes": len(self.get(case + "/" + name))} for name in ("stdout.log", "stderr.log")]})
        self.verification = {"status": "pass", "qualification": "not_established", "source": self.source,
                             "observations": observations, "capture_authentication": "unverified_offline"}
        self.gate = patch.object(benchmark.timer_verifier, "verify", return_value=self.verification).start()
        self.context = patch.object(benchmark.timer_verifier, "bound_context",
                                    side_effect=lambda first, manifest, case: self.bindings[case]).start()
        self.addCleanup(patch.stopall)

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if type(value) is bytes else (json.dumps(value) + "\n").encode())

    def get(self, name):
        return (self.root / name).read_bytes()

    def mutate_result(self, scenario, **fields):
        value = json.loads(self.get(scenario + "/result.json"))
        value.update(fields)
        self.put(scenario + "/result.json", value)

    def test_full_gate_receives_both_builds_host_and_exact_four_scenarios(self):
        result = benchmark.extract_packet(self.root)
        self.gate.assert_called_once_with(self.root / "a/manifest.json", self.root / "b/manifest.json",
            [self.root / case / "result.json" for case in CASES], self.root / "host/result.json")
        self.assertEqual(result["format"], benchmark.FORMAT)
        self.assertEqual(result["qualification"], "not_established")
        self.assertEqual(result["identity"]["source"], self.source)
        self.assertEqual(result["identity"]["clock_profile"]["time_domain"], "qemu_emulator_virtual_time")
        self.assertEqual(len(result["input_refs"]), 19)
        self.assertFalse(result["analysis"]["instrumentation_subtracted"])
        self.assertEqual(result["analysis"]["warmup_discarded"], 0)
        self.assertEqual(set(result["scenarios"]), set(CASES))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_original_gate_failure_is_never_promoted(self):
        for error in (ValueError("rebound artifact"), subprocess.TimeoutExpired("probe", 1)):
            self.gate.side_effect = error
            with self.assertRaises(type(error)):
                benchmark.extract_packet(self.root)
        self.gate.side_effect = None
        for field, value in (("status", "fail"), ("qualification", "established"),
                             ("capture_authentication", "authenticated"), ("observations", {})):
            rejected = copy.deepcopy(self.verification)
            rejected[field] = value
            self.gate.return_value = rejected
            with self.assertRaises(ValueError):
                benchmark.extract_packet(self.root)

    def test_missing_case_registration_or_raw_log_rejected(self):
        for name in ("budget/result.json", "preemption/registration.json", "deadline/stdout.log"):
            saved = self.get(name)
            (self.root / name).unlink()
            with self.assertRaises(ValueError):
                benchmark.extract_packet(self.root)
            self.put(name, saved)

    def test_rebound_result_registration_log_or_observations_rejected(self):
        name = "preemption/result.json"
        saved = self.get(name)
        for fields in ({"case": "deadline"}, {"status": "fail"}, {"manifest_sha256": "0" * 64},
                       {"registration_sha256": "0" * 64}, {"logs": []}, {"observations": {}}):
            self.mutate_result("preemption", **fields)
            with self.assertRaises(ValueError):
                benchmark.extract_packet(self.root)
            self.put(name, saved)
        self.put("preemption/stdout.log", self.get("preemption/stdout.log") + b"unknown\n")
        with self.assertRaises(ValueError):
            benchmark.extract_packet(self.root)

    def test_input_rebound_during_verification_rejected(self):
        def rebound(*args):
            self.put("b/manifest.json", {"rebound": True})
            return self.verification
        self.gate.side_effect = rebound
        with self.assertRaisesRegex(ValueError, "changed during"):
            benchmark.extract_packet(self.root)

    def test_symlinked_file_or_ancestor_rejected(self):
        original = self.root / "host/result.json"
        other = self.root / "other.json"
        original.rename(other)
        original.symlink_to(other)
        with self.assertRaises(ValueError):
            benchmark.extract_packet(self.root)
        original.unlink()
        other.rename(original)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            benchmark.extract_packet(alias)

    def test_cli_input_rejection_does_not_publish_partial_summary(self):
        output = self.root / "preemption-summary.json"
        self.gate.side_effect = ValueError("failed original verification")
        with patch.object(sys, "argv", ["preemption_benchmark.py", "--packet", str(self.root), "--out", str(output)]):
            with self.assertRaises(SystemExit) as raised:
                benchmark.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertFalse(output.exists())

    def test_cli_existing_output_is_preserved(self):
        output = self.root / "preemption-summary.json"
        output.write_bytes(b"prior accepted summary\n")
        with patch.object(sys, "argv", ["preemption_benchmark.py", "--packet", str(self.root), "--out", str(output)]):
            with self.assertRaises(SystemExit) as raised:
                benchmark.main()
        self.assertEqual(raised.exception.code, 1)
        self.gate.assert_not_called()
        self.assertEqual(output.read_bytes(), b"prior accepted summary\n")


if __name__ == "__main__":
    unittest.main()
