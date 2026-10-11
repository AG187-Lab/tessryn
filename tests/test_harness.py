"""Independent process-harness contract tests; no kernel or QEMU is required."""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from tools.g03.process import run_bounded


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "The supported harness uses POSIX process groups")
class ProcessHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tessryn-process-test-")
        self.cwd = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def run_script(self, script: str, *, timeout: float = 2.0, limit: int = 4096):
        return run_bounded(
            [sys.executable, "-c", script],
            cwd=self.cwd,
            timeout_seconds=timeout,
            max_log_bytes=limit,
        )

    def test_completed_process_preserves_separate_binary_logs(self) -> None:
        result = self.run_script(
            "import os; os.write(1, b'out\\x00\\xff\\n'); os.write(2, b'err\\x00\\xfe\\n')"
        )
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"out\x00\xff\n")
        self.assertEqual(result.stderr, b"err\x00\xfe\n")
        self.assertGreaterEqual(result.elapsed_seconds, 0)

    def test_nonzero_exit_is_preserved_for_the_emulator_classifier(self) -> None:
        result = self.run_script("import sys; print('fixture marker'); sys.exit(19)")
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.returncode, 19)
        self.assertIn(b"fixture marker", result.stdout)

    def test_missing_executable_reports_unavailable(self) -> None:
        result = run_bounded(
            [str(self.cwd / "absent-executable")],
            cwd=self.cwd,
            timeout_seconds=1.0,
            max_log_bytes=256,
        )
        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.returncode)
        self.assertTrue(result.reason)

    def test_invalid_budgets_are_rejected_before_launch(self) -> None:
        for timeout in (0, -1, math.inf, -math.inf, math.nan):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.run_script("raise AssertionError('must not launch')", timeout=timeout)
        for limit in (0, -1, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.run_script("raise AssertionError('must not launch')", limit=limit)

    def test_hang_times_out_and_preserves_partial_output(self) -> None:
        result = self.run_script(
            "import time; print('started', flush=True); time.sleep(60)", timeout=0.25
        )
        self.assertEqual(result.status, "timeout")
        self.assertTrue(result.reason)
        self.assertIn(b"started", result.stdout)
        self.assertLess(result.elapsed_seconds, 2.0)
        self.assertIsNotNone(result.returncode)

    def test_log_budget_is_shared_between_stdout_and_stderr(self) -> None:
        result = self.run_script(
            "import os; os.write(1, b'a' * 5000); os.write(2, b'b' * 5000)", limit=6000
        )
        self.assertEqual(result.status, "log_limit")
        self.assertTrue(result.reason)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 6000)
        self.assertGreater(len(result.stdout) + len(result.stderr), 0)
        self.assertLess(result.elapsed_seconds, 2.0)

    def test_output_flood_is_stopped(self) -> None:
        result = self.run_script(
            "import os\nwhile True: os.write(1, b'x' * 8192)", limit=1024
        )
        self.assertEqual(result.status, "log_limit")
        self.assertEqual(len(result.stdout) + len(result.stderr), 1024)
        self.assertIsNotNone(result.returncode)
        self.assertLess(result.elapsed_seconds, 2.0)

    @staticmethod
    def _kill_if_alive(pid: int) -> None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_leader_exit_with_inherited_pipes_remains_bounded(self) -> None:
        # This child ignores TERM, retains its parent's pipes, and keeps making
        # observable progress. A dead process may remain as a zombie briefly;
        # unchanged heartbeat content establishes that it stopped executing.
        child_script = (
            "import os, pathlib, signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "pathlib.Path('child.pid').write_text(str(os.getpid()))\n"
            "with open('heartbeat', 'ab', buffering=0) as output:\n"
            " while True:\n"
            "  output.write(b'x'); time.sleep(0.01)\n"
        )
        leader_script = (
            "import os, pathlib, subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', {child_script!r}])\n"
            "while not pathlib.Path('child.pid').exists(): time.sleep(0.005)\n"
            "os._exit(0)\n"
        )
        try:
            result = self.run_script(leader_script, timeout=0.3)
            self.assertEqual(result.status, "timeout")
            self.assertLess(result.elapsed_seconds, 2.0)
            before = (self.cwd / "heartbeat").read_bytes()
            time.sleep(0.1)
            self.assertEqual((self.cwd / "heartbeat").read_bytes(), before)
        finally:
            pid_path = self.cwd / "child.pid"
            if pid_path.exists():
                self._kill_if_alive(int(pid_path.read_text()))

    def test_completed_leader_cannot_leave_a_running_descendant(self) -> None:
        child_script = (
            "import os, pathlib, signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "os.close(1); os.close(2)\n"
            "pathlib.Path('child.pid').write_text(str(os.getpid()))\n"
            "with open('heartbeat', 'ab', buffering=0) as output:\n"
            " while True:\n"
            "  output.write(b'x'); time.sleep(0.01)\n"
        )
        leader_script = (
            "import os, pathlib, subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', {child_script!r}])\n"
            "while not pathlib.Path('heartbeat').exists(): time.sleep(0.005)\n"
            "os._exit(0)\n"
        )
        try:
            result = self.run_script(leader_script)
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.returncode, 0)
            before = (self.cwd / "heartbeat").read_bytes()
            time.sleep(0.1)
            self.assertEqual((self.cwd / "heartbeat").read_bytes(), before)
        finally:
            pid_path = self.cwd / "child.pid"
            if pid_path.exists():
                self._kill_if_alive(int(pid_path.read_text()))

    def test_interrupt_during_pipe_setup_still_owns_and_cleans_child(self) -> None:
        script = (
            "import os, pathlib, time\n"
            "pathlib.Path('child.pid').write_text(str(os.getpid()))\n"
            "with open('heartbeat', 'ab', buffering=0) as output:\n"
            " while True:\n"
            "  output.write(b'x'); time.sleep(0.01)\n"
        )

        def interrupt_setup(*_args):
            deadline = time.monotonic() + 2
            while not (self.cwd / "heartbeat").exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            raise KeyboardInterrupt

        try:
            with patch("tools.g03.process.os.set_blocking", side_effect=interrupt_setup):
                result = self.run_script(script)
            self.assertEqual(result.status, "cancelled")
            self.assertIsNotNone(result.returncode)
            before = (self.cwd / "heartbeat").read_bytes()
            time.sleep(0.1)
            self.assertEqual((self.cwd / "heartbeat").read_bytes(), before)
        finally:
            pid_path = self.cwd / "child.pid"
            if pid_path.exists():
                self._kill_if_alive(int(pid_path.read_text()))

    def test_interrupt_cancels_child_and_produces_a_result(self) -> None:
        child_script = (
            "import os, pathlib, time\n"
            "pathlib.Path('child.pid').write_text(str(os.getpid()))\n"
            "with open('heartbeat', 'ab', buffering=0) as output:\n"
            " while True:\n"
            "  output.write(b'x'); time.sleep(0.01)\n"
        )
        wrapper_script = (
            "import json, pathlib, sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from tools.g03.process import run_bounded\n"
            f"result = run_bounded([sys.executable, '-c', {child_script!r}], "
            "cwd=pathlib.Path('.'), timeout_seconds=10, max_log_bytes=256)\n"
            "pathlib.Path('result.json').write_text(json.dumps({'status': result.status, "
            "'returncode': result.returncode, 'reason': result.reason}))\n"
        )
        wrapper = subprocess.Popen(
            [sys.executable, "-c", wrapper_script],
            cwd=self.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 3
            while not (self.cwd / "child.pid").exists() and time.monotonic() < deadline:
                if wrapper.poll() is not None:
                    break
                time.sleep(0.01)
            self.assertTrue((self.cwd / "child.pid").exists(), "Helper child did not start")
            os.kill(wrapper.pid, signal.SIGINT)
            stdout, stderr = wrapper.communicate(timeout=3)
            self.assertEqual(wrapper.returncode, 0, (stdout, stderr))
            result = json.loads((self.cwd / "result.json").read_text())
            self.assertEqual(result["status"], "cancelled")
            self.assertTrue(result["reason"])
            self.assertIsNotNone(result["returncode"])
            before = (self.cwd / "heartbeat").read_bytes()
            time.sleep(0.1)
            self.assertEqual((self.cwd / "heartbeat").read_bytes(), before)
        finally:
            if wrapper.poll() is None:
                os.killpg(wrapper.pid, signal.SIGKILL)
            wrapper.communicate(timeout=3)
            pid_path = self.cwd / "child.pid"
            if pid_path.exists():
                self._kill_if_alive(int(pid_path.read_text()))


if __name__ == "__main__":
    unittest.main()
