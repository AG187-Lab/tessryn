"""K03 evidence must fail closed without publishing native scheduling claims."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import check_k03_core as checker
from tools.g03.process import ProcessResult

SUMMARY = "test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"


class K03EvidenceTests(unittest.TestCase):
    def test_retained_artifact_alias_is_replaced_without_changing_its_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            result = work / "result.json"
            result.write_text('{"status":"incomplete"}')
            artifact = work / checker.ARTIFACT
            artifact.symlink_to(result.name)
            compiled = work / "compiler-output.rlib"
            compiled.write_bytes(b"compiled-library")
            checker.retain_artifact(compiled, artifact)
            checker.write_result(result, {"status": "passed"})
            self.assertFalse(artifact.is_symlink())
            self.assertEqual(artifact.read_bytes(), b"compiled-library")
            self.assertEqual(json.loads(result.read_text())["status"], "passed")

    def test_result_staging_alias_cannot_overwrite_the_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            result = work / "result.json"
            artifact = work / checker.ARTIFACT
            artifact.write_bytes(b"compiled-library")
            (work / "result.json.tmp").symlink_to(artifact.name)
            checker.write_result(result, {"status": "incomplete"})
            self.assertEqual(artifact.read_bytes(), b"compiled-library")
            self.assertEqual(json.loads(result.read_text())["status"], "incomplete")
            self.assertFalse(result.is_symlink())

    def test_result_path_cannot_replace_the_retained_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / checker.ARTIFACT
            artifact.write_bytes(b"existing-library")
            alias = Path(temporary) / "receipt.json"
            alias.symlink_to(artifact.name)
            with patch.object(checker, "verify") as verify:
                for output in (artifact, alias):
                    self.assertEqual(checker.main(["--output", str(output)]), 1)
                    self.assertEqual(artifact.read_bytes(), b"existing-library")
                verify.assert_not_called()

    def test_empty_ignored_filtered_failed_and_ambiguous_suites_are_rejected(self):
        self.assertEqual(checker.test_count(SUMMARY), 23)
        for log in ("", SUMMARY + SUMMARY, SUMMARY.replace("23 passed", "0 passed"),
                    SUMMARY.replace("0 ignored", "1 ignored"), SUMMARY.replace("0 measured", "1 measured"),
                    SUMMARY.replace("0 filtered", "1 filtered"), SUMMARY.replace("0 failed", "1 failed"),
                    SUMMARY.replace("ok.", "FAILED."), SUMMARY + SUMMARY.replace("ok.", "FAILED.")):
            with self.subTest(log=log), self.assertRaises(ValueError):
                checker.test_count(log)

    def test_timeout_cancellation_nonzero_exit_and_output_limit_are_failures(self):
        for status, code in (("timeout", None), ("cancelled", -15), ("completed", 1),
                             ("log_limit", -9), ("unavailable", None)):
            result = ProcessResult(status, "bounded failure", code, 0, b"", b"failed")
            with patch.object(checker, "run_bounded", return_value=result) as run:
                with self.assertRaises(ValueError):
                    checker.execute(["rustc"])
                self.assertEqual(run.call_args.args[2:], (60, 262144))

    def test_failure_replaces_success_removes_artifact_and_redacts_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            output = work / "result.json"
            output.write_text('{"status":"passed","source_revision":"stale"}')
            artifact = work / checker.ARTIFACT
            artifact.write_bytes(b"old-library")
            failure = ValueError("tampered /Users/private/workspace/compiler /private/tmp/build/core "
                                 "/var/folders/aa/local-workspace/core/lib.rs /var/tmp/check/core.rs "
                                 "/private/var/folders/aa/check/core.rs /private/var/tmp/check/core.rs")
            with patch.object(checker, "verify", side_effect=failure):
                self.assertEqual(checker.main(["--output", str(output)]), 1)
            result = json.loads(output.read_text())
            self.assertEqual(result["status"], "failed")
            self.assertNotIn("source_revision", result)
            self.assertFalse(artifact.exists())
            self.assertNotIn("/Users/", result["reason"])
            self.assertNotIn("/private/tmp/", result["reason"])
            self.assertNotIn("/var", result["reason"])
            self.assertNotIn("local-workspace", result["reason"])
            self.assertIn("native_multi_core_execution_and_SMP_synchronization", result["unavailable"])

    def test_failure_artifact_alias_does_not_modify_an_unrelated_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            target = work / "unrelated.txt"
            target.write_bytes(b"keep")
            artifact = work / checker.ARTIFACT
            artifact.symlink_to(target.name)
            with patch.object(checker, "verify", side_effect=ValueError("failed")):
                self.assertEqual(checker.main(["--output", str(work / "result.json")]), 1)
            self.assertEqual(target.read_bytes(), b"keep")
            self.assertFalse(artifact.is_symlink())

    def test_interrupted_run_invalidates_old_receipt_and_artifact_first(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            output = work / "result.json"
            output.write_text('{"status":"passed"}')
            artifact = work / checker.ARTIFACT
            artifact.write_bytes(b"old-library")
            with patch.object(checker, "verify", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    checker.main(["--output", str(output)])
            self.assertEqual(json.loads(output.read_text())["status"], "incomplete")
            self.assertFalse(artifact.exists())

    def test_failed_receipt_publication_discards_the_new_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            output = work / "result.json"
            artifact = work / checker.ARTIFACT
            write_result = checker.write_result

            def verify(_):
                artifact.write_bytes(b"new-library")
                return {"status": "passed", "host_tests": {"passed": 23}}

            def write(path, result):
                if result["status"] == "passed":
                    raise OSError("receipt replacement failed")
                write_result(path, result)

            with patch.object(checker, "verify", side_effect=verify), patch.object(checker, "write_result", side_effect=write):
                self.assertEqual(checker.main(["--output", str(output)]), 1)
            self.assertFalse(artifact.exists())
            self.assertEqual(json.loads(output.read_text())["status"], "failed")

    def test_artifact_directory_is_a_failure_receipt_without_running_the_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            output = work / "result.json"
            (work / checker.ARTIFACT).mkdir()
            with patch.object(checker, "verify") as verify:
                self.assertEqual(checker.main(["--output", str(output)]), 1)
                verify.assert_not_called()
            self.assertEqual(json.loads(output.read_text())["status"], "failed")

    def test_failed_result_serialization_removes_partial_staging_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            output = work / "result.json"
            output.write_text('{"status":"incomplete"}')
            with self.assertRaises(TypeError):
                checker.write_result(output, {"cannot_serialize": object()})
            self.assertEqual(json.loads(output.read_text())["status"], "incomplete")
            self.assertEqual(list(work.glob(".k03-result-*")), [])

    def test_manifest_contains_every_scheduler_module_and_exact_setup_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = set(checker.DEPENDENCIES) | {"scheduler-core/lib.rs", "scheduler-core/tests.rs",
                                                   "scheduler-core/internal/accounting.rs"}
            for name in expected:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            with patch.object(checker, "ROOT", root):
                manifest = checker.sources()
            self.assertEqual(set(manifest), expected)
            for name, value in manifest.items():
                self.assertEqual(value, hashlib.sha256(name.encode()).hexdigest())

    def test_missing_and_symlinked_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in checker.DEPENDENCIES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            with patch.object(checker, "ROOT", root), self.assertRaises(OSError):
                checker.sources()
            (root / "scheduler-core").mkdir()
            external = root / "other.rs"
            external.write_text("not a bound source")
            (root / "scheduler-core/lib.rs").symlink_to(external)
            with patch.object(checker, "ROOT", root), self.assertRaises((OSError, ValueError)):
                checker.sources()

    def test_source_reader_rejects_fifo_directory_symlink_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            regular = root / "regular"
            regular.write_bytes(b"retained")
            alias = root / "alias"
            alias.symlink_to(regular.name)
            oversized = root / "oversized"
            oversized.write_bytes(b"x" * (checker.MAX_SOURCE_BYTES + 1))
            with patch.object(checker, "ROOT", root):
                self.assertEqual(checker.read_source(regular), b"retained")
                for path in (fifo, root, alias, oversized):
                    with self.subTest(path=path.name), self.assertRaises((OSError, ValueError)):
                        checker.read_source(path)

    def test_loaded_tooling_cannot_claim_modified_on_disk_sources(self):
        for name in checker.LOADED_TOOLING:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                retained = dict(checker.LOADED_BYTES)
                retained[name] = b"changed"
                with patch.object(checker, "source_bytes", return_value=retained), \
                        patch.object(checker.setup, "verified_setup") as setup, \
                        patch.object(checker, "execute") as execute:
                    with self.assertRaises(ValueError):
                        checker.verify(Path(temporary) / "result.json")
                    setup.assert_not_called()
                    execute.assert_not_called()

    def test_temporary_import_then_tooling_source_edit_or_deletion_fails_closed(self):
        script = """
import json
from pathlib import Path
import sys
from tools import check_k03_core as checker

path = checker.ROOT / sys.argv[1]
if sys.argv[2] == "edit":
    path.write_text(path.read_text() + "\\n# changed after import\\n")
else:
    path.unlink()

def forbidden_setup():
    raise AssertionError("changed tooling reached compiler identity execution")
checker.setup.verified_setup = forbidden_setup
output = checker.ROOT / "build/k03/result.json"
output.parent.mkdir(parents=True)
output.write_text('{"status":"passed"}')
artifact = output.parent / checker.ARTIFACT
artifact.write_bytes(b"stale-library")
assert checker.main(["--output", str(output)]) == 1
receipt = json.loads(output.read_text())
assert receipt["status"] == "failed"
assert "source_revision" not in receipt
assert not artifact.exists()
if sys.argv[2] == "edit":
    assert "changed since initialization" in receipt["reason"]
"""
        for name in checker.LOADED_TOOLING:
            for mode in ("edit", "delete"):
                with self.subTest(name=name, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    for dependency in checker.DEPENDENCIES:
                        destination = root / dependency
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(checker.ROOT / dependency, destination)
                    (root / "scheduler-core").mkdir()
                    (root / "scheduler-core/lib.rs").write_text("#![no_std]\n")
                    result = checker.run_bounded([sys.executable, "-c", script, name, mode], root, 10, 262144)
                    self.assertEqual(result.status, "completed", result.reason)
                    self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))

    def copy_source_tree(self, root):
        for dependency in checker.DEPENDENCIES:
            destination = root / dependency
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(checker.ROOT / dependency, destination)
        (root / "scheduler-core").mkdir()
        (root / "scheduler-core/lib.rs").write_bytes(b"#![no_std]\n")

    def test_stale_imported_setup_and_process_are_not_the_executed_runtime(self):
        script = """
from pathlib import Path
import sys
root = Path.cwd()
setup_path = root / "tools/setup_k02_toolchain.py"
process_path = root / "tools/g03/process.py"
setup_source, process_source = setup_path.read_bytes(), process_path.read_bytes()
setup_path.write_text('from pathlib import Path\\nPREFIX = Path("/tmp/fake-compiler")\\ndef verified_setup():\\n    raise AssertionError("stale setup executed")\\n')
process_path.write_text('def run_bounded(*args):\\n    raise AssertionError("stale process executed")\\n')
from tools import setup_k02_toolchain as stale_setup
from tools.g03 import process as stale_process
setup_path.write_bytes(setup_source)
process_path.write_bytes(process_source)
from tools import check_k03_core as checker
assert checker.setup is not stale_setup
assert checker.process is not stale_process
assert checker.setup.g03.__file__ == str(root / "tools/setup_toolchain.py")
actual = checker.run_bounded([sys.executable, "-c", "raise SystemExit(7)"], root, 10, 4096)
assert actual.status == "completed" and actual.returncode == 7
assert checker.main(["--output", str(root / "build/k03/result.json")]) == 1
assert not (root / "build/k03" / checker.ARTIFACT).exists()
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_source_tree(root)
            result = checker.run_bounded([sys.executable, "-c", script], root, 10, 262144)
            self.assertEqual(result.status, "completed", result.reason)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))

    def test_cached_dependencies_from_a_different_checkout_are_not_executed(self):
        script = """
import importlib.util
from pathlib import Path
import sys
root = Path.cwd()
sys.path.insert(0, str(root / "other"))
from tools import setup_k02_toolchain as wrong_setup
from tools.g03 import process as wrong_process
wrong_setup.verified_setup = lambda: (_ for _ in ()).throw(AssertionError("wrong checkout setup executed"))
wrong_process.run_bounded = lambda *args: (_ for _ in ()).throw(AssertionError("wrong checkout process executed"))
spec = importlib.util.spec_from_file_location("intended_checker", root / "tools/check_k03_core.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
assert checker.setup.__file__ == str(root / "tools/setup_k02_toolchain.py")
assert checker.process.__file__ == str(root / "tools/g03/process.py")
assert checker.setup.g03.__file__ == str(root / "tools/setup_toolchain.py")
assert checker.setup is not wrong_setup and checker.process is not wrong_process
actual = checker.run_bounded([sys.executable, "-c", "raise SystemExit(9)"], root, 10, 4096)
assert actual.status == "completed" and actual.returncode == 9
assert checker.main(["--output", str(root / "build/k03/result.json")]) == 1
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_source_tree(root)
            self.copy_source_tree(root / "other")
            result = checker.run_bounded([sys.executable, "-c", script], root, 10, 262144)
            self.assertEqual(result.status, "completed", result.reason)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))

    def test_timestamp_valid_stale_bytecode_is_ignored(self):
        script = """
import os
from pathlib import Path
import sys
root = Path.cwd()
paths = [root / "tools/setup_k02_toolchain.py", root / "tools/g03/process.py"]
originals = [(path.read_bytes(), path.stat()) for path in paths]
poison = b'raise AssertionError("stale bytecode executed")\\n#'
for path, (original, info) in zip(paths, originals):
    path.write_bytes(poison + b"x" * (len(original) - len(poison)))
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    # Compile timestamp/size-valid pyc without executing the poison module.
    import py_compile
    py_compile.compile(str(path), doraise=True)
    path.write_bytes(original)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
from tools import check_k03_core as checker
assert checker.LOADED_TOOLING is not None
actual = checker.run_bounded([sys.executable, "-c", "raise SystemExit(11)"], root, 10, 4096)
assert actual.status == "completed" and actual.returncode == 11
assert checker.main(["--output", str(root / "build/k03/result.json")]) == 1
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_source_tree(root)
            result = checker.run_bounded([sys.executable, "-c", script], root, 10, 262144)
            self.assertEqual(result.status, "completed", result.reason)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))

    def test_runtime_initialization_failure_invalidates_stale_outputs(self):
        script = """
import json
from pathlib import Path
root = Path.cwd()
(root / "tools/g03/__init__.py").write_text('raise RuntimeError("invalid runtime source")\\n')
from tools import check_k03_core as checker
output = root / "build/k03/result.json"
output.parent.mkdir(parents=True)
output.write_text('{"status":"passed"}')
artifact = output.parent / checker.ARTIFACT
artifact.write_bytes(b"stale")
assert checker.main(["--output", str(output)]) == 1
assert json.loads(output.read_text())["status"] == "failed"
assert not artifact.exists()
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_source_tree(root)
            result = checker.run_bounded([sys.executable, "-c", script], root, 10, 262144)
            self.assertEqual(result.status, "completed", result.reason)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))

    def test_live_rust_source_aba_compiles_only_retained_original_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_source_tree(root)
            source = root / "scheduler-core/lib.rs"
            original = source.read_bytes()
            compiled = []

            def execute(command, **_):
                if "--test" in command or "--crate-type=rlib" in command:
                    source.write_bytes(b"compile-time alternate live source")
                    try:
                        snapshot = Path(command[-3])
                        self.assertNotEqual(snapshot, source)
                        self.assertEqual(snapshot.read_bytes(), original)
                        self.assertEqual(snapshot.stat().st_mode & 0o222, 0)
                        self.assertIn(f"{snapshot.parent.parent}=.", command)
                        compiled.append(snapshot.read_bytes())
                        if "--crate-type=rlib" in command:
                            Path(command[-1]).write_bytes(b"library")
                    finally:
                        source.write_bytes(original)
                    return ""
                return SUMMARY

            with patch.object(checker, "ROOT", root), patch.object(checker, "execute", side_effect=execute), \
                    patch.object(checker.setup, "verified_setup", return_value={"rustc": "pinned"}), \
                    patch.object(checker, "git_binding", return_value=("rev", "")):
                result = checker.verify(root / "build/k03/result.json")
            self.assertEqual(compiled, [original] * 3)
            self.assertEqual(result["sources"]["scheduler-core/lib.rs"], hashlib.sha256(original).hexdigest())
            self.assertEqual(result["status"], "passed")

    def verify_fixture(self, output, *, hashes=None, source_versions=None, identities=None, bindings=None):
        commands = []

        def execute(command, **_):
            commands.append(command)
            if "--crate-type=rlib" in command:
                Path(command[-1]).write_bytes(b"library")
                return ""
            if "--test" in command:
                return ""
            return SUMMARY

        versions = [{name: value.encode() for name, value in version.items()}
                    for version in source_versions or [{"scheduler-core/lib.rs": "a"}] * 2]
        with patch.object(checker, "execute", side_effect=execute), patch.object(checker, "LOADED_TOOLING", {}), \
                patch.object(checker, "source_bytes", side_effect=versions), \
                patch.object(checker.setup, "verified_setup", side_effect=identities or [{"rustc": "pinned"}] * 2), \
                patch.object(checker, "git_binding", side_effect=bindings or [("rev", " M scheduler-core/lib.rs")] * 2), \
                patch.object(checker, "digest", side_effect=hashes or ["artifact-hash"] * 2):
            result = checker.verify(output)
        return result, commands

    def test_passed_receipt_binds_policy_inputs_and_exact_repeated_builds(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            result, commands = self.verify_fixture(work / "result.json")
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["source_dirty"])
            self.assertEqual(result["source_revision"], "rev")
            self.assertEqual(result["toolchain"], {"rustc": "pinned"})
            self.assertEqual(result["sources"], {"scheduler-core/lib.rs": hashlib.sha256(b"a").hexdigest()})
            self.assertIn("host_execution", result["scope"])
            self.assertIn("hardware_monotonic_clock_and_timer_interrupts", result["unavailable"])
            self.assertEqual(result["artifacts"][checker.ARTIFACT]["target"], "x86_64-unknown-none")
            builds = [command for command in commands if "--crate-type=rlib" in command]
            self.assertEqual(len(builds), 2)
            self.assertEqual(builds[0], builds[1])
            self.assertIn("tessryn_scheduler", builds[0])
            self.assertEqual((work / checker.ARTIFACT).read_bytes(), b"library")
            self.assertEqual(list(work.glob("k03-check-*")), [])

    def test_changed_build_identity_or_nondeterministic_artifact_is_never_published(self):
        cases = (
            {"hashes": ["artifact-a", "artifact-b"]},
            {"source_versions": [{"scheduler-core/lib.rs": "a"}, {"scheduler-core/lib.rs": "b"}]},
            {"identities": [{"rustc": "pinned"}, {"rustc": "changed"}]},
            {"bindings": [("rev", ""), ("new-rev", "")]},
            {"bindings": [("rev", ""), ("rev", " M scheduler-core/lib.rs")]},
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                with self.assertRaises(ValueError):
                    self.verify_fixture(work / "result.json", **case)
                self.assertFalse((work / checker.ARTIFACT).exists())
                self.assertEqual(list(work.glob("k03-check-*")), [])

    def test_portable_logs_keep_repo_relative_context_without_host_paths(self):
        work = Path("/private/tmp/k03-check-123")
        log = checker.portable(f"{checker.ROOT}/scheduler-core/lib.rs:4 {work}/k03-tests "
                               "/home/operator/build/lib.rs /Users/operator/work/lib.rs "
                               "/var/folders/aa/local-workspace/core/lib.rs /var/tmp/check/lib.rs "
                               "/private/var/folders/aa/check/lib.rs /private/var/tmp/check/lib.rs", work)
        self.assertIn("<repo>/scheduler-core/lib.rs:4", log)
        self.assertIn("<work>/k03-tests", log)
        self.assertNotIn("/home/", log)
        self.assertNotIn("/Users/", log)
        self.assertNotIn("/var", log)
        self.assertNotIn("local-workspace", log)


if __name__ == "__main__":
    unittest.main()
