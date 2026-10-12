"""Evidence failures must not retain a successful or incomplete test claim."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import check_k02_core as checker
from tools.g03.process import ProcessResult


class K02EvidenceTests(unittest.TestCase):
    def test_retained_artifact_alias_is_replaced_without_changing_its_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            result = work / "result.json"
            result.write_text('{"status":"incomplete"}')
            artifact = work / "libtessryn_memory.rlib"
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
            artifact = work / "libtessryn_memory.rlib"
            artifact.write_bytes(b"compiled-library")
            (work / "result.json.tmp").symlink_to(artifact.name)
            checker.write_result(result, {"status": "incomplete"})
            self.assertEqual(artifact.read_bytes(), b"compiled-library")
            self.assertEqual(json.loads(result.read_text())["status"], "incomplete")
            self.assertFalse(result.is_symlink())

    def test_result_path_cannot_replace_the_retained_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "libtessryn_memory.rlib"
            artifact.write_bytes(b"existing-library")
            alias = Path(temporary) / "receipt.json"
            alias.symlink_to(artifact.name)
            with patch.object(checker, "verify") as verify:
                for output in (artifact, alias):
                    self.assertEqual(checker.main(["--output", str(output)]), 1)
                    self.assertEqual(artifact.read_bytes(), b"existing-library")
                verify.assert_not_called()

    def test_empty_ignored_filtered_failed_and_ambiguous_suites_are_rejected(self):
        valid = "test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
        self.assertEqual(checker.test_count(valid), 23)
        for log in ("", valid + valid, valid.replace("23 passed", "0 passed"),
                    valid.replace("0 ignored", "1 ignored"), valid.replace("0 filtered", "1 filtered"),
                    valid.replace("0 failed", "1 failed"), valid.replace("ok.", "FAILED.")):
            with self.subTest(log=log), self.assertRaises(ValueError):
                checker.test_count(log)

    def test_timeout_nonzero_exit_and_output_limit_are_failures(self):
        for status, code in (("timeout", None), ("completed", 1), ("log_limit", -9)):
            result = ProcessResult(status, "bounded failure", code, 0, b"", b"failed")
            with patch.object(checker, "run_bounded", return_value=result), self.assertRaises(ValueError):
                checker.execute(["rustc"])

    def test_failure_replaces_success_and_redacts_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            output.write_text('{"status":"passed","source_revision":"stale"}')
            failure = ValueError("tampered /Users/private/workspace/compiler")
            with patch.object(checker, "verify", side_effect=failure):
                self.assertEqual(checker.main(["--output", str(output)]), 1)
            result = json.loads(output.read_text())
            self.assertEqual(result["status"], "failed")
            self.assertNotIn("source_revision", result)
            self.assertNotIn("/Users/", result["reason"])
            self.assertIn("CPU_address_space_isolation", result["unavailable"])

    def test_interrupted_run_has_invalidated_old_success_first(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            output.write_text('{"status":"passed"}')
            with patch.object(checker, "verify", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                checker.main(["--output", str(output)])
            self.assertEqual(json.loads(output.read_text())["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
