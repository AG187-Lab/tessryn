"""Exercise capture boundaries without using a fixture as guest evidence."""

import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import run_io01_pci as runner


def wire(rows):
    return b"".join(json.dumps(row).encode() + b"\r\n" for row in rows)


class QMPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.serial = b"TESSRYN_IO01_PCI_DONE count=1\r\n"
        self.pci = [{"bus": 0, "devices": []}]
        self.requests = wire([{"id": 1, "execute": "qmp_capabilities"}, {"id": 2, "execute": "query-status"},
                              {"id": 3, "execute": "stop"}, {"id": 4, "execute": "query-status"},
                              {"id": 5, "execute": "query-pci"}, {"id": 6, "execute": "quit"}])
        self.replies = [
            {"QMP": {"version": {}, "capabilities": []}},
            {"return": {}, "id": 1}, {"return": {"running": True, "status": "running"}, "id": 2},
            {"event": "STOP"}, {"return": {}, "id": 3},
            {"return": {"running": False, "status": "paused"}, "id": 4},
            {"return": self.pci, "id": 5}, {"return": {}, "id": 6},
            {"event": "SHUTDOWN", "data": {"guest": False, "reason": "host-qmp-quit"}},
        ]

    def test_passes_original_paused_inventory_to_trace_verifier(self):
        rtc = {"event": "RTC_CHANGE", "data": {"offset": 2, "qom-path": "/machine/unattached/device[17]/rtc"}}
        next_rtc = {"event": "RTC_CHANGE", "data": {**rtc["data"], "offset": 3}}
        replies = self.replies[:3] + [rtc, next_rtc] + self.replies[3:]
        with patch.object(runner, "verify", return_value={"case": "absent"}) as compare:
            self.assertEqual(runner.observations("absent", self.serial, b"", wire(replies), self.requests),
                             {"case": "absent"})
            compare.assert_called_once_with(self.serial, self.pci, "absent")

    def test_rejects_incomplete_or_uncontrolled_qmp(self):
        faults = [self.replies[:7],
                  self.replies[:5] + [{"return": {"running": True, "status": "running"}, "id": 4}] + self.replies[6:],
                  self.replies[:7] + [{"event": "RESET", "data": {"guest": True}}] + self.replies[7:],
                  self.replies[:7] + [{"return": {}, "id": 5}] + self.replies[8:],
                  self.replies[:3] + [{"event": "RTC_CHANGE", "data": {
                      "offset": True, "qom-path": "/machine/unattached/device[1]/rtc"}}] + self.replies[3:],
                  self.replies[:5] + [{"event": "RTC_CHANGE", "data": {
                      "offset": -1, "qom-path": "/machine/unattached/device[1]/rtc"}}] + self.replies[5:]]
        with patch.object(runner, "verify") as compare:
            for replies in faults:
                with self.subTest(replies=replies), self.assertRaises(ValueError):
                    runner.observations("absent", self.serial, b"", wire(replies), self.requests)
            compare.assert_not_called()

    def test_rejects_extra_serial_and_emulator_stderr_before_comparison(self):
        for serial, stderr in [(self.serial + b"extra\n", b""), (self.serial, b"Triple fault\n"),
                               (self.serial + self.serial, b"")]:
            with self.subTest(serial=serial, stderr=stderr), patch.object(runner, "verify") as compare:
                with self.assertRaises(ValueError):
                    runner.observations("absent", serial, stderr, wire(self.replies), self.requests)
                compare.assert_not_called()

    def test_controller_is_the_only_case_specific_device_change(self):
        present = runner.qemu_command("present")
        absent = runner.qemu_command("absent")
        target = present.index("nvme,id=io01-nvme,bus=io01-port,addr=0,serial=TESSRYN-PCI")
        self.assertEqual(present[target - 1], "-device")
        self.assertEqual(present[:target - 1] + present[target + 1:], absent)
        self.assertIn("VGA,romfile=", absent)
        self.assertNotIn("isa-debug-exit", " ".join(present))


class ChildBoundaryTests(unittest.TestCase):
    def test_timeout_reaps_a_real_child_waiting_without_qmp(self):
        fixture = [sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"]
        with tempfile.TemporaryDirectory(prefix="tessryn-io01-test-") as directory:
            with patch.object(runner, "QEMU", Path(sys.executable)), patch.object(runner, "qemu_command", return_value=fixture):
                result = runner.capture("absent", Path(directory), timeout=0.25)
        self.assertEqual(result.status, "timeout")
        self.assertIn(result.returncode, (-signal.SIGTERM, -signal.SIGKILL))
        self.assertEqual(result.qmp_recv, b"")

    def test_unavailable_executable_has_no_success_or_exit_receipt(self):
        with tempfile.TemporaryDirectory(prefix="tessryn-io01-test-") as directory:
            with patch.object(runner, "QEMU", Path(directory) / "missing"):
                result = runner.capture("absent", Path(directory))
        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.returncode)


if __name__ == "__main__":
    unittest.main()
