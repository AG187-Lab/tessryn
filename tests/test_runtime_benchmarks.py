"""Adversarial combined-lane plumbing; mocks are never guest execution proof."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import run_runtime_benchmarks as runner
from tools import verify_runtime_benchmarks as verifier
from tools.g03.process import ProcessResult


class ProfileTests(unittest.TestCase):
    def test_exact_profile_and_all_negative_or_neutral_results_remain_unqualified(self):
        profile = verifier.expected_profile()
        self.assertEqual(verifier.validate_profile(copy.deepcopy(profile)), profile)
        self.assertIsNone(profile["comparison"]["performance_threshold"])
        self.assertFalse(profile["comparison"]["promotion_decision"])
        for trail, value in (
            (("independent_repeats",), True), (("independent_repeats",), 1),
            (("scope",), "hardware_performance"), (("hardware_qualified",), True),
            (("inference_qualified",), True), (("comparison", "pool_boots"), False),
            (("comparison", "performance_threshold"), 0), (("comparison", "promotion_decision"), True),
            (("preemption", "warmup_samples"), 1), (("preemption", "pool_boots"), True),
            (("contention", "samples_per_case"), 15), (("limits", "stage_cleanup_grace_seconds"), float("inf")),
        ):
            mutated = copy.deepcopy(profile)
            target = mutated
            for key in trail[:-1]:
                target = target[key]
            target[trail[-1]] = value
            with self.subTest(trail=trail, value=value):
                with self.assertRaises((ValueError, TypeError)):
                    verifier.validate_profile(mutated)

    def test_stage_plan_has_twenty_unique_exactly_scoped_stages(self):
        stages = verifier.stage_plan()
        self.assertEqual(len(stages), 20)
        self.assertEqual(len({stage["id"] for stage in stages}), 20)
        for repeat in (1, 2):
            captures = [stage for stage in stages if stage["id"].startswith(f"preemption-{repeat}-")
                        and stage["tool"] == "tools/run_k03_timer.py"]
            self.assertEqual([stage["arguments"][stage["arguments"].index("--case") + 1] for stage in captures],
                             list(verifier.TIMER_CASES))
            self.assertTrue(all("--allow-qemu" in stage["arguments"] for stage in captures))
        for stage in stages:
            expected_timeout = (900 if stage["tool"] in ("tools/check_k03_timer_host.py", "tools/build_k03_timer.py")
                else 180 if stage["tool"] in ("tools/run_k03_timer.py", "tools/run_contention_benchmarks.py") else 300)
            self.assertEqual(stage["timeout_seconds"], expected_timeout)
            self.assertTrue(stage["tool"].startswith("tools/"))
            self.assertTrue(any("<run>" in argument for argument in stage["arguments"]))

    def test_repeat_identity_rejects_each_mismatch_and_extra_fields(self):
        identity = {"source": {"revision": "a" * 40}, "toolchain": {"host": "fixture"},
                    "machine_profile": {"cpu_count": 1}, "clock_profile": {"period_fs": 10_000_000},
                    "artifact_sha256": {"BOOTX64.EFI": "b" * 64}, "compiler_sources_sha256": "c" * 64,
                    "runtime_sha256": {"tools/fixture.py": "d" * 64}}
        summaries = [{"identity": copy.deepcopy(identity)}, {"identity": copy.deepcopy(identity)}]
        self.assertEqual(verifier.compare_identities(summaries, "fixture"), identity)
        for key in identity:
            bad = copy.deepcopy(summaries)
            bad[1]["identity"][key] = {"changed": True}
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    verifier.compare_identities(bad, "fixture")
        for bad in ([], summaries[:1], summaries + summaries[:1]):
            with self.assertRaises(ValueError):
                verifier.compare_identities(bad, "fixture")
        summaries[1]["identity"]["extra"] = 1
        with self.assertRaises(ValueError):
            verifier.compare_identities(summaries, "fixture")


class CaptureChronologyTests(unittest.TestCase):
    def test_capture_registration_is_inside_top_registration_and_own_stage(self):
        top = "2026-10-18T01:00:00Z"
        receipt = {"started_at_utc": "2026-10-18T01:00:01Z", "completed_at_utc": "2026-10-18T01:00:05Z"}
        verifier.validate_capture_time("2026-10-18T01:00:02Z", top, receipt)
        for created in ("2026-10-18T00:59:59Z", "2026-10-18T01:00:00Z", "2026-10-18T01:00:06Z"):
            with self.subTest(created=created):
                with self.assertRaises(ValueError):
                    verifier.validate_capture_time(created, top, receipt)

    def test_naive_foreign_offset_and_malformed_capture_times_rejected(self):
        for timestamp in ("2026-10-18T01:00:00", "2026-10-18T01:00:00+01:00", None, True, "not a time"):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises((ValueError, TypeError, AttributeError)):
                    verifier.utc(timestamp)
        self.assertEqual(verifier.utc("2026-10-18T01:00:00Z").utcoffset().total_seconds(), 0)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tessryn-runtime-inventory-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "nested").mkdir()
        (self.root / "nested/a.bin").write_bytes(b"abc")
        (self.root / "registration.json").write_bytes(b"{}\n")
        self.names = {"nested/a.bin", "registration.json"}

    def test_exact_inventory_rejects_unpublished_failure_or_extra_directory(self):
        self.assertEqual(verifier.validate_inventory(self.root, self.names),
                         {"nested/a.bin": 3, "registration.json": 3})
        hidden = self.root / "failure-summary.json"
        hidden.write_bytes(b"failed prior attempt")
        with self.assertRaises(ValueError):
            verifier.validate_inventory(self.root, self.names)
        hidden.unlink()
        (self.root / "undeclared-empty-directory").mkdir()
        with self.assertRaises(ValueError):
            verifier.validate_inventory(self.root, self.names)

    def test_symlinks_special_files_missing_and_oversized_rejected(self):
        (self.root / "alias").symlink_to(self.root / "nested/a.bin")
        with self.assertRaises(ValueError):
            verifier.validate_inventory(self.root, self.names | {"alias"})
        (self.root / "alias").unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "fifo")
            with self.assertRaises(ValueError):
                verifier.validate_inventory(self.root, self.names | {"fifo"})
            (self.root / "fifo").unlink()
        (self.root / "nested/a.bin").unlink()
        with self.assertRaises(ValueError):
            verifier.validate_inventory(self.root, self.names)
        with (self.root / "nested/a.bin").open("wb") as sparse:
            sparse.truncate((2 << 30) + 1)
        with self.assertRaises(ValueError):
            verifier.validate_inventory(self.root, self.names)


class StageProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tessryn-runtime-process-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()

    def test_success_and_combined_output_limit(self):
        result = runner.run_stage([sys.executable, "-B", "-c", "print('bounded')"], self.directory, 3, 1024)
        self.assertEqual((result.status, result.returncode, result.stdout), ("completed", 0, b"bounded\n"))
        result = runner.run_stage([sys.executable, "-B", "-c", "print('x'*10000)"], self.directory, 3, 16)
        self.assertEqual(result.status, "log_limit")
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 16)

    def test_stage_rejects_unbounded_timeout_and_bool_log_budget(self):
        for timeout in (0, -1, True, float("nan"), float("inf")):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    runner.run_stage([sys.executable, "-B", "-c", "pass"], self.directory, timeout, 16)
        with self.assertRaises(ValueError):
            runner.run_stage([sys.executable, "-B", "-c", "pass"], self.directory, 1, True)

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_timeout_allows_inner_owner_to_reap_sigterm_ignoring_grandchild(self):
        pid_path, reaped_path = self.directory / "grandchild.pid", self.directory / "owner-reaped.json"
        grandchild = ("import os,signal,sys,time; from pathlib import Path; "
                      "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                      "Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)")
        owner = ("import json,sys; from pathlib import Path; "
                 "sys.path.insert(0,sys.argv[1]); from tools.g03.process import run_bounded; "
                 "r=run_bounded([sys.executable,'-B','-c',sys.argv[4],sys.argv[2]],Path.cwd(),30,1024); "
                 "Path(sys.argv[3]).write_text(json.dumps({'status':r.status,'returncode':r.returncode}))")
        result = runner.run_stage([sys.executable, "-B", "-c", owner, str(runner.ROOT),
            str(pid_path), str(reaped_path), grandchild], self.directory, 1, 1024)
        pid = int(pid_path.read_text()) if pid_path.exists() else None
        try:
            self.assertEqual(result.status, "timeout")
            self.assertLess(result.elapsed_seconds, 7)
            self.assertIsNotNone(pid, "nested fake child did not start")
            self.assertTrue(reaped_path.exists(), "inner owner was killed before its cleanup/reap completed")
            receipt = json.loads(reaped_path.read_text())
            self.assertEqual(receipt["status"], "cancelled")
            self.assertEqual(receipt["returncode"], -signal.SIGKILL)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            if pid is not None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


class RunnerPlumbingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tessryn-runtime-runner-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "tools/g03").mkdir(parents=True)
        (self.root / "planning").mkdir()
        (self.root / "tools/run_runtime_benchmarks.py").write_bytes(runner.LOADED_SOURCE)
        (self.root / "tools/g03/process.py").write_bytes(b"fixture runtime bytes\n")
        (self.root / verifier.PROFILE).write_text(json.dumps(verifier.expected_profile()))
        self.out = self.root / "build/run-1"
        self.source = {"revision": "a" * 40, "dirty": False, "tree_sha256": "b" * 64,
                       "snapshot_algorithm": "git-worktree-v2"}
        self.runtime = {"tools/g03/process.py": verifier.digest(b"fixture runtime bytes\n")}
        self.plan = [{"id": "fixture-stage", "tool": "tools/fixture.py", "arguments": ["<run>"], "timeout_seconds": 120}]
        def exclusive(path):
            path.mkdir(parents=True)
            return path
        patchers = [patch.object(runner, "ROOT", self.root), patch.object(runner, "source_identity", return_value=self.source),
            patch.object(runner.verify, "runtime_hashes", return_value=self.runtime),
            patch.object(runner.verify, "validate_source"), patch.object(runner.verify, "stage_plan", return_value=self.plan),
            patch.object(runner, "exclusive_directory", side_effect=exclusive)]
        self.started = [patcher.start() for patcher in patchers]
        for patcher in patchers:
            self.addCleanup(patcher.stop)

    def test_opt_in_and_dirty_source_fail_before_child_or_output(self):
        with patch.object(runner, "run_stage") as child:
            with self.assertRaises(ValueError):
                runner.run(self.out)
            self.source["dirty"] = True
            with self.assertRaises(ValueError):
                runner.run(self.out, allow_qemu=True)
        child.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_preregistration_precedes_child_and_failed_raw_diagnostics_stay_private(self):
        secret_diagnostic = b"/private/host/example compiler failed\n"
        def child(*args):
            registered = json.loads((self.out / "registration.json").read_bytes())
            self.assertEqual(registered["source"], self.source)
            self.assertEqual(registered["runtime_sha256"], self.runtime)
            self.assertTrue((self.out / "profile.json").exists())
            self.assertTrue((self.out / "sources/tools/g03/process.py").exists())
            return ProcessResult("completed", "fixture failure", 9, .01, secret_diagnostic, b"error")
        with patch.object(runner, "run_stage", side_effect=child) as call:
            result = runner.run(self.out, allow_qemu=True)
        self.assertEqual(call.call_count, 1)
        self.assertFalse(result["valid"])
        self.assertEqual(result["failure_stage"], "fixture-stage")
        self.assertIsNone(result["summary"])
        self.assertEqual((self.out / ".private/fixture-stage-stdout.log").read_bytes(), secret_diagnostic)
        public = (self.out / "stages/fixture-stage-stdout.log").read_bytes()
        self.assertNotIn(secret_diagnostic, public)
        self.assertEqual(public, b"stage failed; original diagnostics private\n")
        self.assertTrue((self.out / "failure-summary.json").exists())

    def test_full_deadline_reservation_prevents_launch(self):
        with patch.object(runner.time, "monotonic", side_effect=[0, 1799]), patch.object(runner, "run_stage") as child:
            result = runner.run(self.out, allow_qemu=True)
        child.assert_not_called()
        self.assertFalse(result["valid"])
        self.assertEqual(result["failure_stage"], "fixture-stage")

    def test_registration_mutation_prevents_second_stage(self):
        self.plan.append({"id": "fixture-stage-2", "tool": "tools/fixture.py", "arguments": ["<run>"], "timeout_seconds": 120})
        def child(*args):
            (self.out / "registration.json").write_bytes(b"{}\n")
            return ProcessResult("completed", "fixture success", 0, .01, b"done\n", b"")
        with patch.object(runner, "run_stage", side_effect=child) as call:
            result = runner.run(self.out, allow_qemu=True)
        self.assertEqual(call.call_count, 1)
        self.assertFalse(result["valid"])
        self.assertEqual(result["failure_stage"], "fixture-stage")

    def test_final_verification_is_a_bounded_registered_child_with_pin(self):
        self.plan.clear()
        def child(command, cwd, timeout, max_log_bytes):
            registered_raw = (self.out / "registration.json").read_bytes()
            registered = json.loads(registered_raw)
            self.assertEqual(registered["final_verifier"], verifier.final_verifier())
            self.assertEqual(timeout, 300)
            self.assertEqual(max_log_bytes, 1 << 20)
            self.assertIn("--recompute-only", command)
            self.assertEqual(command[command.index("--expected-registration-sha256") + 1],
                             verifier.digest(registered_raw))
            return ProcessResult("completed", "mocked recomputation only", 0, .01,
                json.dumps({"registration_sha256": verifier.digest(registered_raw),
                            "summary": {"fixture_only": True}, "files": []}).encode(), b"")
        with patch.object(runner, "run_stage", side_effect=child) as call, \
                patch.object(runner.verify, "verify_packet", side_effect=AssertionError("must not run unbounded inline")):
            result = runner.run(self.out, allow_qemu=True)
        self.assertEqual(call.call_count, 1)
        self.assertTrue(result["valid"])
        self.assertIsNone(result["failure_stage"])
        receipt = json.loads((self.out / "verification-receipt.json").read_bytes())
        self.assertEqual(receipt["id"], "combined-verification")
        self.assertEqual(receipt["status"], "completed")

    def test_final_child_failure_is_retained_and_never_promoted(self):
        self.plan.clear()
        with patch.object(runner, "run_stage", return_value=ProcessResult(
                "timeout", "mocked deadline", -signal.SIGKILL, 300, b"private final diagnostics", b"")):
            result = runner.run(self.out, allow_qemu=True)
        self.assertFalse(result["valid"])
        self.assertEqual(result["failure_stage"], "combined-verification")
        self.assertIsNone(result["summary"])
        self.assertEqual((self.out / ".private/combined-verification-stdout.log").read_bytes(), b"private final diagnostics")
        self.assertEqual((self.out / "stages/combined-verification-stdout.log").read_bytes(),
                         b"verification failed; original diagnostics private\n")
        self.assertEqual(json.loads((self.out / "verification-receipt.json").read_bytes())["status"], "timeout")

    def test_final_deadline_reservation_prevents_launch(self):
        self.plan.clear()
        with patch.object(runner.time, "monotonic", side_effect=[0, 1600]), patch.object(runner, "run_stage") as child:
            result = runner.run(self.out, allow_qemu=True)
        child.assert_not_called()
        self.assertFalse(result["valid"])
        self.assertEqual(result["failure_stage"], "combined-verification")

    def test_diagnostic_redaction_never_expands_original_byte_budget(self):
        for data in (b"/tmp/tmp", "/tmp/π🐧".encode(), b"/Users/someone/private/file", b"\xff/tmp/x"):
            with self.subTest(data=data):
                redacted = runner.sanitize(data)
                self.assertLessEqual(len(redacted), len(data))
                redacted.decode("utf-8")
                self.assertNotIn(b"/tmp/", redacted)


if __name__ == "__main__":
    unittest.main()
