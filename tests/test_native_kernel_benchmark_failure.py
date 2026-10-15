"""Failed public diagnostics contain metadata rather than raw host messages."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import summarize_native_benchmark_failure as summary


class FailurePublicationTests(unittest.TestCase):
    def test_raw_paths_and_messages_stay_local_while_hashes_bind_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run = root / "run-1"
            run.mkdir()
            raw = b"env: /Users/operator/private/workspace/qemu: permission denied; private-token\n"
            (run / "qemu-stderr.log").write_bytes(raw)
            (run / "qemu-stdout.log").write_bytes(b"")
            (run / "result.json").write_text(json.dumps({"status": "failed", "reason": raw.decode()}))
            (run / "run_receipts.json").write_text(json.dumps({"execution": {
                "status": "completed", "returncode": 126, "reason": raw.decode(),
                "stderr": {"file": raw.decode()}, "stdout": {"file": raw.decode()}}}))
            result = summary.summarize(root)
            encoded = json.dumps(result)
            self.assertNotIn("/Users/", encoded)
            self.assertNotIn("permission denied", encoded)
            self.assertNotIn("private-token", encoded)
            self.assertFalse(result["raw_logs_uploaded"])
            self.assertEqual(result["execution"]["returncode"], 126)
            self.assertEqual(result["execution"]["stderr"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result["execution"]["stderr"]["size"], len(raw))
            self.assertEqual((run / "qemu-stderr.log").read_bytes(), raw)

    def test_missing_malformed_and_untrusted_metadata_stays_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run = root / "run-1"
            run.mkdir()
            (run / "result.json").write_bytes(b"not JSON")
            (run / "run_receipts.json").write_text(json.dumps({"execution": {
                "status": "/Users/operator/private-message", "returncode": True}}))
            result = summary.summarize(root)
            self.assertEqual(result["run_status"], "unavailable")
            self.assertEqual(result["execution"]["status"], "unavailable")
            self.assertIsNone(result["execution"]["returncode"])
            self.assertEqual(result["execution"]["stderr"]["status"], "unavailable")

    def test_symlink_and_oversized_raw_logs_are_not_read_for_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            external = root / "private.log"
            external.write_bytes(b"private bytes")
            alias = root / "alias.log"
            alias.symlink_to(external)
            oversized = root / "large.log"
            oversized.write_bytes(b"x" * ((1 << 20) + 1))
            for path in (alias, oversized, root):
                with self.subTest(kind=path.name):
                    self.assertEqual(summary.log_metadata(path)["status"], "unavailable")

    def test_deeply_nested_metadata_does_not_prevent_failure_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run = root / "run-1"
            run.mkdir()
            (run / "result.json").write_bytes(b"[" * 2000 + b"0" + b"]" * 2000)
            result = summary.summarize(root)
            self.assertEqual(result["run_status"], "unavailable")
            self.assertEqual(result["execution"]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
