"""Runner boundary fixtures; these tests produce no performance qualification."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import run_kernel_benchmarks as runner
import verify_kernel_benchmarks as verifier_api
from g03.process import ProcessResult, run_bounded


class KernelBenchmarkRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "checkout"
        self.root.mkdir()
        for relative in runner.SOURCE_FILES:
            source = self.root / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            if relative.startswith("tools/"):
                source.write_bytes((runner.ROOT / relative).read_bytes())
            else:
                source.write_text("// controlled runner fixture\n")
        self.profile = self.root / "profile.json"
        self.profile.write_bytes((runner.ROOT / "planning/kernel-benchmark-profile.json").read_bytes())
        self.sysroot = self.base / "compiler"
        (self.sysroot / "bin").mkdir(parents=True)
        libraries = self.sysroot / "lib/rustlib/fixture-host/lib"
        libraries.mkdir(parents=True)
        (libraries / "libstd-fixture.rlib").write_bytes(b"runner fixture library")
        self.compiler = self.sysroot / "bin/rustc"
        harness = (f"#!{sys.executable}\n"
                   "import json\nfrom pathlib import Path\n"
                   "assert Path('registration.json').is_file(), 'registration must precede execution'\n"
                   "registration = json.loads(Path('registration.json').read_text())\n"
                   "print(json.dumps({'schema_version': 1, 'kind': 'kernel_benchmark_raw', "
                   "'clock': 'std::time::Instant', 'config': registration['config'], "
                   "'samples': [], 'checks': ['runner_boundary_fixture']}))\n")
        self.compiler.write_text(
            f"#!{sys.executable}\n"
            "from pathlib import Path\nimport sys\n"
            f"sysroot = {str(self.sysroot)!r}\n"
            "if sys.argv[1:] == ['--print', 'sysroot']:\n"
            "    print(sysroot)\n"
            "elif sys.argv[1:] == ['-vV']:\n"
            "    print('rustc runner-fixture\\nhost: fixture-host')\n"
            "else:\n"
            "    output = Path(sys.argv[sys.argv.index('-o') + 1])\n"
            f"    output.write_text({harness!r} if output.name == 'kernel-benchmark' else 'fixture library')\n"
            "    output.chmod(0o755)\n")
        self.compiler.chmod(0o755)
        self.out = self.base / "runs" / "new-run"
        self.verifier = types.SimpleNamespace(verify_run=mock.Mock(
            return_value={"evidence_scope": "host_microbenchmark", "fixture_only": True}))
        self.process_override = None
        self.host_os = "RunnerFixtureOS"

    def run_fixture(self, **overrides) -> dict:
        options = {"rustc": str(self.compiler), "samples": 1, "warmup": 0, "iterations": 1}
        options.update(overrides)
        loader = runner.load_bound_module
        def fixture_modules(data, public_name):
            module = loader(data, public_name)
            if public_name.endswith("verify_kernel_benchmarks.py"):
                module.verify_run = self.verifier.verify_run
            elif public_name.endswith("g03/process.py") and self.process_override is not None:
                module.run_bounded = self.process_override
            return module
        with mock.patch.object(runner, "load_bound_module", side_effect=fixture_modules), \
                mock.patch.object(runner.platform, "system", return_value=self.host_os):
            return runner.run_benchmarks(self.root, self.out, self.profile, **options)

    def test_registration_precedes_execution_and_scope_is_explicit(self) -> None:
        result = self.run_fixture()
        self.assertTrue(result["valid"])
        self.assertEqual(result["evidence_scope"], "host_microbenchmark")
        self.assertFalse(result["native_qualification"])
        registration = json.loads((self.out / "registration.json").read_text())
        self.assertEqual(registration["capture_origin"], "local_runner_claim_unverified_offline")
        self.assertEqual(registration["toolchain"]["dependency_scope"],
                         "rustc_executable_and_host_target_libraries_only")
        self.assertEqual(registration["measurement_semantics"], "raw_host_elapsed_no_subtraction")
        self.assertEqual(registration["config"], {"samples": 1, "warmup": 0, "iterations": 1, "seed": 1})
        self.assertEqual(len(registration["sources"]), len(runner.SOURCE_FILES))
        self.assertEqual((self.out / "sources/kernel-core/lib.rs").read_bytes(),
                         (self.root / "kernel-core/lib.rs").read_bytes())
        receipts = json.loads((self.out / "run_receipts.json").read_text())
        self.assertEqual(len(receipts["compile"]), 2)
        self.assertEqual(receipts["execution"]["status"], "completed")
        self.verifier.verify_run.assert_called_once_with(self.out, require_result=False)
        for artifact in ("registration.json", "result.json", "run_receipts.json"):
            self.assertNotIn(str(self.base), (self.out / artifact).read_text())
        for log in (self.out / "logs").iterdir():
            self.assertNotIn(str(self.base), log.read_text())

    def test_invalid_config_is_refused_before_output_creation(self) -> None:
        for options in ({"samples": True}, {"samples": 0}, {"samples": 10001},
                        {"warmup": -1}, {"iterations": 0}, {"iterations": 1000001},
                        {"seed": -1}, {"seed": 2**64}, {"timeout_seconds": 121},
                        {"timeout_seconds": float("nan")}, {"max_log_bytes": 0}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.run_fixture(**options)
            self.assertFalse(self.out.exists())

    def test_total_workload_bounds_are_checked_before_launch(self) -> None:
        launch = self.process_override = mock.Mock()
        result = self.run_fixture(samples=10000, warmup=10000, iterations=1000000)
        self.assertFalse(result["valid"])
        self.assertIn("budget", result["reason"])
        launch.assert_not_called()

    def test_existing_output_cannot_be_reused_or_overwritten(self) -> None:
        self.out.mkdir(parents=True)
        (self.out / "result.json").write_text("existing successful evidence")
        with self.assertRaises(FileExistsError):
            self.run_fixture()
        self.assertEqual((self.out / "result.json").read_text(), "existing successful evidence")
        self.assertEqual(list(self.out.iterdir()), [self.out / "result.json"])

    def test_source_symlink_and_symlink_ancestor_are_refused(self) -> None:
        source = self.root / "kernel-core/lib.rs"
        source.unlink()
        source.symlink_to(self.root / "kernel-core/frames.rs")
        result = self.run_fixture()
        self.assertFalse(result["valid"])
        self.assertIsNone(result["registration_sha256"])
        source.unlink()
        source.write_text("// restored fixture\n")
        self.out = self.base / "ancestor-run"
        actual = self.root / "kernel-core"
        actual.rename(self.root / "real-core")
        actual.symlink_to(self.root / "real-core", target_is_directory=True)
        self.assertFalse(self.run_fixture()["valid"])

    def test_nonregular_and_oversized_sources_fail_without_hanging(self) -> None:
        source = self.root / "kernel-core/lib.rs"
        source.unlink()
        os.mkfifo(source)
        self.assertFalse(self.run_fixture()["valid"])
        source.unlink()
        source.write_bytes(b"x" * (runner.SOURCE_LIMIT + 1))
        self.out = self.base / "oversized-run"
        self.assertFalse(self.run_fixture()["valid"])

    def test_timeout_keeps_a_failed_receipt(self) -> None:
        timeout = ProcessResult("timeout", "execution exceeded deadline", None, 0.01, b"", b"")
        self.process_override = mock.Mock(return_value=timeout)
        result = self.run_fixture()
        self.assertFalse(result["valid"])
        self.assertIn("timeout", result["reason"])
        self.assertEqual(json.loads((self.out / "result.json").read_text())["status"], "failed")
        self.verifier.verify_run.assert_not_called()

    def test_real_log_budget_failure_cannot_be_observed_success(self) -> None:
        result = self.run_fixture(max_log_bytes=8)
        self.assertFalse(result["valid"])
        self.assertIn("log_limit", result["reason"])
        self.assertLessEqual((self.out / "logs/rustc-sysroot.stdout").stat().st_size, 8)
        self.verifier.verify_run.assert_not_called()

    def test_linux_style_redaction_never_expands_the_captured_byte_budget(self) -> None:
        for data in (b"/tmp/tmp", b"/tmp/x", b"/home/x", b"/opt/x", b""):
            with self.subTest(data=data):
                sanitized = runner.sanitize_log(data, {})
                self.assertLessEqual(len(sanitized), len(data))
                sanitized.decode("utf-8", errors="strict")
                self.assertNotIn(b"/tmp/", sanitized)
                self.assertNotIn(b"/home/", sanitized)
                self.assertNotIn(b"/opt/", sanitized)

    def test_unicode_and_invalid_utf8_redaction_preserve_safe_byte_boundaries(self) -> None:
        fixtures = [("λ/tmp/xλ".encode(), {}), (b"/x", {"/x": "éé"}),
                    (b"x", {"x": "🌱"}), (b"abc\xffdef", {}), (b"\xe2\x82", {})]
        for data, redactions in fixtures:
            with self.subTest(data=data):
                sanitized = runner.sanitize_log(data, redactions)
                self.assertLessEqual(len(sanitized), len(data))
                sanitized.decode("utf-8", errors="strict")
                self.assertNotIn(b"/tmp/", sanitized)
        unchanged = "é🌱 text".encode()
        self.assertEqual(runner.sanitize_log(unchanged, {}), unchanged)

    def test_measured_stdout_remains_exact_despite_path_and_unicode_content(self) -> None:
        raw = "fixture /tmp/tmp λ".encode()
        def replace_measurement(command, *args):
            captured = run_bounded(command, *args)
            if command[0].endswith("/kernel-benchmark"):
                return ProcessResult(captured.status, captured.reason, captured.returncode,
                                     captured.elapsed_seconds, raw, captured.stderr)
            return captured
        self.process_override = replace_measurement
        self.assertTrue(self.run_fixture()["valid"])
        self.assertEqual((self.out / "raw.json").read_bytes(), raw)
        self.assertEqual((self.out / "logs/measurement.stdout").read_bytes(), raw)

    def test_live_source_change_after_measurement_invalidates_raw_result(self) -> None:
        def change_after_measurement(command, *args):
            captured = run_bounded(command, *args)
            if command[0].endswith("/kernel-benchmark"):
                (self.root / "kernel-core/lib.rs").write_text("// changed live source\n")
            return captured
        self.process_override = change_after_measurement
        result = self.run_fixture()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "failed")
        self.assertIsNotNone(result["registration_sha256"])
        self.assertIsNotNone(result["raw_sha256"])
        self.assertIsNone(result["summary"])
        self.verifier.verify_run.assert_not_called()

    def test_verification_rejection_never_creates_success(self) -> None:
        self.verifier.verify_run.side_effect = ValueError("raw contract mismatch")
        result = self.run_fixture()
        self.assertFalse(result["valid"])
        self.assertIn("raw contract mismatch", result["reason"])
        self.assertEqual(json.loads((self.out / "result.json").read_text())["status"], "failed")

    def test_captured_process_source_overrides_preexisting_module_cache(self) -> None:
        helper = self.root / "tools/g03/process.py"
        with helper.open("a") as stream:
            stream.write("\ndef run_bounded(*args):\n    return ProcessResult('timeout', 'captured helper epoch', None, 0.01, b'', b'')\n")
        result = self.run_fixture()
        self.assertFalse(result["valid"])
        self.assertIn("timeout", result["reason"])
        self.assertEqual((self.out / "sources/tools/g03/process.py").read_bytes(), helper.read_bytes())

    def test_captured_verifier_source_overrides_preexisting_module_cache(self) -> None:
        verifier = self.root / "tools/verify_kernel_benchmarks.py"
        with verifier.open("a") as stream:
            stream.write("\ndef strict_json(value):\n    raise ValueError('captured verifier epoch')\n")
        result = self.run_fixture()
        self.assertFalse(result["valid"])
        self.assertIn("captured verifier epoch", result["reason"])

    def test_retained_source_change_before_measurement_is_rejected(self) -> None:
        def change_snapshot(command, *args):
            captured = run_bounded(command, *args)
            if "sources/benchmark-harness/main.rs" in command:
                (self.out / "sources/kernel-core/lib.rs").chmod(0o644)
                (self.out / "sources/kernel-core/lib.rs").write_text("// changed retained source\n")
            return captured
        self.process_override = change_snapshot
        result = self.run_fixture()
        self.assertFalse(result["valid"])
        self.assertIsNone(result["registration_sha256"])
        self.assertFalse((self.out / "raw.json").exists())

    def test_duplicate_profile_keys_fail_before_child_launch(self) -> None:
        self.profile.write_text('{"schema_version":1,"schema_version":1}')
        launch = self.process_override = mock.Mock()
        result = self.run_fixture()
        self.assertFalse(result["valid"])
        self.assertIn("duplicate JSON key", result["reason"])
        launch.assert_not_called()

    def test_human_report_preserves_unresolved_timer_samples_and_population(self) -> None:
        result = {"status": "observed", "valid": True, "registration_sha256": "a" * 64,
                  "summary": {"cases": [{"case": "timer_pair", "implementation": "host_clock_probe",
                                          "sample_unit": "timed_batch", "ns_per_operation": None}]}}
        report = runner.format_report(result)
        self.assertIn("native_qualification=false", report)
        self.assertIn("amortized batch averages", report)
        self.assertIn("unresolved", report)
        self.assertNotIn("0.000", report)

    def test_optional_cpu_model_query_failure_records_unavailable(self) -> None:
        self.host_os = "Darwin"
        def unavailable_cpu(command, *args):
            if command[0] == "/usr/sbin/sysctl":
                return ProcessResult("completed", "query unavailable", 1, 0.01, b"", b"query unavailable")
            return run_bounded(command, *args)
        self.process_override = unavailable_cpu
        result = self.run_fixture()
        self.assertTrue(result["valid"])
        registration = json.loads((self.out / "registration.json").read_text())
        self.assertEqual(registration["host"]["processor_model"], "unavailable")
        self.assertEqual((self.out / "logs/cpu-model.stderr").read_text(), "query unavailable")

    def test_optional_cpu_model_query_still_aborts_on_cleanup_or_resource_failure(self) -> None:
        self.host_os = "Darwin"
        for status in ("timeout", "cancelled", "log_limit", "fail"):
            self.out = self.base / ("cpu-" + status)
            def bounded_cpu(command, *args):
                if command[0] == "/usr/sbin/sysctl":
                    return ProcessResult(status, "bounded query failed", None, 0.01, b"", b"")
                return run_bounded(command, *args)
            self.process_override = bounded_cpu
            result = self.run_fixture()
            with self.subTest(status=status):
                self.assertFalse(result["valid"])
                self.assertIn(status, result["reason"])


if __name__ == "__main__":
    unittest.main()
