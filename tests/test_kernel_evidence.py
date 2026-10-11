"""Reject false-positive K01 evidence and unsafe execution arguments."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.run_kernel import COMMON, CASE_MARKERS, check_transcript, qemu_command
from tools.build_kernel import inspect_pe


class KernelEvidenceTests(unittest.TestCase):
    def transcript(self, case="normal"):
        markers = [*COMMON, CASE_MARKERS[case]]
        if case == "int3":
            markers.extend(("TESSRYN_K01_INT3_RECOVERED fp_state=preserved", "TESSRYN_K01_PASS"))
        elif case in ("invalid_opcode", "page_fault"):
            markers.append("TESSRYN_K01_EXPECTED_FAULT")
        return ("\n".join(markers) + "\n").encode()

    def test_marker_alone_or_wrong_order_does_not_prove_handoff(self):
        self.assertFalse(check_transcript("normal", b"TESSRYN_K01_PASS", 33))
        self.assertFalse(check_transcript("normal", self.transcript().replace(COMMON[1].encode(), b""), 33))
        self.assertFalse(check_transcript("normal", b"\n".join(reversed(self.transcript().splitlines())), 33))

    def test_wrong_exit_or_unexpected_failure_rejects_markers(self):
        self.assertFalse(check_transcript("normal", self.transcript(), 0))
        self.assertFalse(check_transcript("normal", self.transcript() + b"TESSRYN_K01_FAIL", 33))
        self.assertFalse(check_transcript("reboot", self.transcript("reboot"), 33))

    def test_fault_case_cannot_be_substituted(self):
        self.assertFalse(check_transcript("page_fault", self.transcript("invalid_opcode"), 33))
        self.assertTrue(check_transcript("reboot", self.transcript("reboot"), 0, b"CPU Reset (CPU 0)"))

    def test_triple_fault_cannot_prove_controlled_reset(self):
        self.assertFalse(check_transcript("reboot", self.transcript("reboot"), 0))
        self.assertFalse(check_transcript("reboot", self.transcript("reboot"), 0, b"CPU Reset (CPU 0)\nTriple fault\n"))
        self.assertIn("cpu_reset", qemu_command("reboot", "img"))

    def test_exception_vector_boundary_and_recovery_are_required(self):
        data = self.transcript("int3")
        self.assertFalse(check_transcript("int3", data.replace(b"vector=3", b"vector=30"), 33))
        self.assertFalse(check_transcript("int3", data.replace(b"TESSRYN_K01_INT3_RECOVERED", b"missing"), 33))
        self.assertFalse(check_transcript("page_fault", self.transcript("page_fault").replace(b"TESSRYN_K01_EXPECTED_FAULT", b"missing"), 33))

    def test_media_and_firmware_are_guest_only_and_no_host_disks(self):
        command = qemu_command("normal", "iso")
        self.assertIn("-nodefaults", command)
        self.assertIn("-no-user-config", command)
        self.assertIn("-no-reboot", command)
        self.assertIn("if=ide,format=raw,readonly=on,media=cdrom,file=boot.iso", command)
        self.assertNotIn("-fsdev", command)
        self.assertNotIn("-netdev", command)
        self.assertFalse(any("/dev/" in item for item in command))

    def test_invalid_pe_is_not_accepted_as_kernel(self):
        for data in (b"", b"MZ" + b"\0" * 100, b"\x7fELF" + b"\0" * 100):
            with self.assertRaises(ValueError):
                inspect_pe(data)


if __name__ == "__main__":
    unittest.main()
