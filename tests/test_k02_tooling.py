"""Evidence failures must not retain a successful or incomplete test claim."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import check_k02_core as checker
from tools.g03.process import ProcessResult


class K02EvidenceTests(unittest.TestCase):
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
