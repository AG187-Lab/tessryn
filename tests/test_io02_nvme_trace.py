"""Synthetic controls for the IO02 guest record and paused QMP snapshot."""

import json
import unittest

from test_io01_pci_trace import HOST, NVME, PORT, fixture, guest
from tools.io02_nvme_trace import admit_bar0, verify_registers
from tools.run_io01_pci import observations


PRESENT = (b"TESSRYN_IO02_NVME_REGISTERS bdf=01:00.0 bar=0x81000000 "
           b"cap=0x004008200f0107ff vs=0x00010400 reads=3\n")
ABSENT = b"TESSRYN_IO02_NVME_ABSENT reads=0\n"
SNAPSHOT = bytes.fromhex("ff07010f2008400000040100")


def serial(record, *, present=True):
    functions = (HOST, PORT, NVME) if present else (HOST, PORT)
    return guest(*functions).replace(b"TESSRYN_IO01_PCI_DONE", record + b"TESSRYN_IO01_PCI_DONE")


def pci_fixture(*, present=True):
    pci = fixture(present=present)
    if present:
        endpoint = pci[0]["devices"][0]["pci_bridge"]["devices"][0]
        endpoint["regions"] = [{"bar": 0, "type": "memory", "address": 0x8100_0000, "size": 0x4000,
                                "mem_type_64": True, "prefetch": False}]
    return pci


def wire(rows):
    return b"".join(json.dumps(row).encode() + b"\r\n" for row in rows)


def exchange(*, present=True):
    ops = ["qmp_capabilities", "query-status", "stop", "query-status", "query-pci"]
    replies = [{}, {"running": True, "status": "running"}, {}, {"running": False, "status": "paused"},
               pci_fixture(present=present)]
    if present:
        ops.append("pmemsave")
        replies.append({})
    ops.append("quit")
    replies.append({})
    requests = [{"id": i, "execute": op} for i, op in enumerate(ops, 1)]
    if present:
        requests[-2]["arguments"] = {"val": 0x8100_0000, "size": 12, "filename": "nvme-registers.bin"}
    received = [{"QMP": {}}] + [{"return": value, "id": i} for i, value in enumerate(replies, 1)]
    return received, requests


class NvmeTraceTests(unittest.TestCase):
    def test_present_and_absent_use_distinct_transcripts_and_snapshots(self):
        for case, present, record, snapshot in (("present", True, PRESENT, SNAPSHOT), ("absent", False, ABSENT, None)):
            with self.subTest(case=case):
                received, sent = exchange(present=present)
                result = observations(case, serial(record, present=present), b"", wire(received), wire(sent),
                                      nvme_registers=True, nvme_snapshot=snapshot)
                self.assertEqual(result["device_count"], 3 if present else 2)
                self.assertEqual(result["nvme_registers"], {
                    "bar0": 0x8100_0000, "bar0_size": 0x4000,
                    "cap": 0x0040_0820_0F01_07FF, "vs": 0x0001_0400, "reads": 3,
                } if present else {"reads": 0})
                with self.assertRaises(ValueError):
                    observations(case, serial(record, present=present), b"", wire(received), wire(sent))

    def test_bar_admission_rejects_wrong_geometry_or_types(self):
        for fields in ({"bar": False}, {"address": 0x8100_4000}, {"size": 0x2000},
                       {"size": float(0x4000)}, {"prefetch": True}, {"mem_type_64": 1}, {"type": "io"}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                pci = pci_fixture()
                pci[0]["devices"][0]["pci_bridge"]["devices"][0]["regions"][0].update(fields)
                admit_bar0(pci)
        with self.assertRaises(ValueError):
            admit_bar0(pci_fixture(present=False))

    def test_replay_rejects_other_snapshot_commands_and_nonempty_reply(self):
        for fields in ({"val": 0x8100_0004}, {"size": 16}, {"size": 12.0}, {"filename": "different.bin"}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                received, sent = exchange()
                sent[-2]["arguments"].update(fields)
                observations("present", serial(PRESENT), b"", wire(received), wire(sent),
                             nvme_registers=True, nvme_snapshot=SNAPSHOT)
        received, sent = exchange()
        received[-2]["return"] = {"status": "unexpected"}
        with self.assertRaises(ValueError):
            observations("present", serial(PRESENT), b"", wire(received), wire(sent),
                         nvme_registers=True, nvme_snapshot=SNAPSHOT)

    def test_record_and_snapshot_must_agree_with_fixed_present_profile(self):
        for record, snapshot in (
            (PRESENT.replace(b"vs=0x00010400", b"vs=0x00010401"), SNAPSHOT),
            (PRESENT.replace(b"reads=3", b"reads=2"), SNAPSHOT),
            (PRESENT + PRESENT, SNAPSHOT),
            (ABSENT, SNAPSHOT),
            (PRESENT, SNAPSHOT[:-1]),
            (PRESENT, SNAPSHOT[:-1] + b"\x01"),
            (PRESENT, None),
        ):
            with self.subTest(record=record, snapshot=snapshot), self.assertRaises(ValueError):
                verify_registers(serial(record), pci_fixture(), "present", snapshot)

    def test_absent_control_rejects_any_snapshot_or_nonzero_read_count(self):
        for record, snapshot in ((ABSENT, SNAPSHOT), (ABSENT, b""), (PRESENT, None),
                                 (ABSENT.replace(b"reads=0", b"reads=1"), None)):
            with self.subTest(record=record, snapshot=snapshot), self.assertRaises(ValueError):
                verify_registers(serial(record, present=False), pci_fixture(present=False), "absent", snapshot)


if __name__ == "__main__":
    unittest.main()
