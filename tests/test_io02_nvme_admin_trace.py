"""Synthetic controls for the IO02 admin-queue witness and QMP captures."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_io02_nvme_trace import ABSENT, PRESENT, SNAPSHOT, exchange, serial, wire
from tools.run_io01_pci import (ADMIN_PASS_REASON, LOGS, Capture, bindings, execution, header,
                                observations, reference, verify_result)


_LIVE_IMAGE = (
    b"TESSRYN_K01_LIVE_RANGES image_start=0x120000 image_end=0x124000 "
    b"stack_start=0x124000 stack_end=0x128000 map_start=0x128000 map_end=0x129000 "
    b"scratch=0x100000 runtime_high=0 gop_start=0x80000000 gop_end=0x803e8000\n"
)
_ADMIN_PRESENT = (
    b"TESSRYN_IO02_NVME_ADMIN bdf=01:00.0 asq=0x0000000000121000 acq=0x0000000000122000 "
    b"aqa=0x00010001 cc_ready=0x00460001 csts_ready=0x00000001 "
    b"cc_final=0x00000000 csts_final=0x00000000 bme=0 doorbells=0 firmware=reset\n"
)
_ADMIN_ABSENT = b"TESSRYN_IO02_NVME_ADMIN_ABSENT writes=0\n"
_FINAL_SNAPSHOT = bytes(36)
_FINAL_NAME = "nvme-admin-final.bin"


def admin_serial(record, *, present=True, live=_LIVE_IMAGE):
    data = serial(PRESENT if present else ABSENT, present=present)
    data = data.replace(b"TESSRYN_K01_MEMORY_MAP_VALID", live + b"TESSRYN_K01_MEMORY_MAP_VALID")
    return data.replace(b"TESSRYN_IO01_PCI_DONE", record + b"TESSRYN_IO01_PCI_DONE")


def admin_exchange(*, present=True):
    received, sent = exchange(present=present)
    if present:
        sent[-1]["id"] = 8
        received[-1]["id"] = 8
        sent.insert(-1, {"id": 7, "execute": "pmemsave",
                         "arguments": {"val": 0x8100_0014, "size": 36, "filename": _FINAL_NAME}})
        received.insert(-1, {"id": 7, "return": {}})
    return received, sent


def observe(data, final_snapshot, *, present=True, received=None, sent=None):
    if received is None or sent is None:
        received, sent = admin_exchange(present=present)
    return observations("present" if present else "absent", data, b"", wire(received), wire(sent),
                        nvme_admin_queues=True, nvme_snapshot=SNAPSHOT if present else None,
                        admin_snapshot=final_snapshot)


class NvmeAdminTraceTests(unittest.TestCase):
    def test_present_requires_the_admin_mode_and_replays_both_snapshots(self):
        data = admin_serial(_ADMIN_PRESENT)
        result = observe(data, _FINAL_SNAPSHOT)
        self.assertEqual(result["nvme_registers"]["reads"], 3)
        self.assertEqual(result["nvme_admin"], {"asq": 0x121000, "acq": 0x122000, "aqa": 0x00010001,
                                               "cc_ready": 0x00460001, "csts_ready": 1,
                                               "cc_final": 0, "csts_final": 0, "bme": 0, "doorbells": 0,
                                               "firmware": "reset"})
        inactive = admin_serial(_ADMIN_PRESENT.replace(b"firmware=reset", b"firmware=inactive"))
        self.assertEqual(observe(inactive, _FINAL_SNAPSHOT)["nvme_admin"]["firmware"], "inactive")
        received, sent = admin_exchange()
        with self.assertRaises(ValueError):
            observations("present", data, b"", wire(received), wire(sent),
                         nvme_registers=True, nvme_snapshot=SNAPSHOT)

    def test_absent_control_requires_no_writes_or_second_snapshot(self):
        data = admin_serial(_ADMIN_ABSENT, present=False)
        self.assertEqual(observe(data, None, present=False)["nvme_admin"], {"writes": 0})
        for record, snapshot in ((_ADMIN_ABSENT, _FINAL_SNAPSHOT), (_ADMIN_PRESENT, None),
                                 (_ADMIN_ABSENT.replace(b"writes=0", b"writes=1"), None)):
            with self.subTest(record=record, snapshot=snapshot), self.assertRaises(ValueError):
                observe(admin_serial(record, present=False), snapshot, present=False)

    def test_witness_refuses_wrong_ready_and_final_state_or_queue_activity(self):
        for current, wrong in (
            (b"cc_ready=0x00460001", b"cc_ready=0x00460000"),
            (b"csts_ready=0x00000001", b"csts_ready=0x00000003"),
            (b"cc_final=0x00000000", b"cc_final=0x00000001"),
            (b"csts_final=0x00000000", b"csts_final=0x00000001"),
            (b"aqa=0x00010001", b"aqa=0x00000001"),
            (b"bme=0", b"bme=1"),
            (b"doorbells=0", b"doorbells=1"),
            (b"firmware=reset", b"firmware=unknown"),
            (b" firmware=reset", b""),
        ):
            with self.subTest(current=current), self.assertRaises(ValueError):
                observe(admin_serial(_ADMIN_PRESENT.replace(current, wrong)), _FINAL_SNAPSHOT)
        for record in (b"", _ADMIN_PRESENT * 2, b"TESSRYN_IO02_NVME_ADMIN_FAIL reason=timeout\n"):
            with self.subTest(record=record), self.assertRaises(ValueError):
                observe(admin_serial(record), _FINAL_SNAPSHOT)

    def test_queue_pages_must_fit_distinct_aligned_kernel_image_pages(self):
        for address in (0x11F000, 0x121001, 0x122000, 0x124000):
            with self.subTest(address=address), self.assertRaises(ValueError):
                record = _ADMIN_PRESENT.replace(b"asq=0x0000000000121000", f"asq=0x{address:016x}".encode())
                observe(admin_serial(record), _FINAL_SNAPSHOT)
        for live in (b"", _LIVE_IMAGE * 2, _LIVE_IMAGE.replace(b"image_end=0x124000", b"image_end=0x122800")):
            with self.subTest(live=live), self.assertRaises(ValueError):
                observe(admin_serial(_ADMIN_PRESENT, live=live), _FINAL_SNAPSHOT)

    def test_exact_qmp_read_is_required_and_final_state_must_be_zero(self):
        data = admin_serial(_ADMIN_PRESENT)
        for arguments in ({"val": 0x8100_0018}, {"size": 36.0}, {"filename": "different.bin"}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                received, sent = admin_exchange()
                sent[-2]["arguments"].update(arguments)
                observe(data, _FINAL_SNAPSHOT, received=received, sent=sent)
        received, sent = admin_exchange()
        received[-2]["return"] = {"unexpected": 1}
        with self.assertRaises(ValueError):
            observe(data, _FINAL_SNAPSHOT, received=received, sent=sent)
        for offset in (0, 8, 16, 20, 24, 28, 32):
            snapshot = _FINAL_SNAPSHOT[:offset] + b"\x01" + _FINAL_SNAPSHOT[offset + 1:]
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                observe(data, snapshot)
        for snapshot in (None, b"", _FINAL_SNAPSHOT + b"\0"):
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                observe(data, snapshot)

    def test_result_binds_the_final_snapshot_and_rejects_a_tampered_file(self):
        data = admin_serial(_ADMIN_PRESENT)
        received, sent = admin_exchange()
        inputs = (b"manifest", b"boot disk", "qemu hash", {})
        logs = dict(zip(LOGS, (data, b"", wire(received), wire(sent))))
        logs.update({"nvme-registers.bin": SNAPSHOT, _FINAL_NAME: _FINAL_SNAPSHOT})
        result = {**header("present", nvme_admin_queues=True), "status": "pass", "reason": ADMIN_PASS_REASON,
                  "bindings": bindings(inputs),
                  "execution": execution("present", Capture("completed", "serial, QMP and process streams completed", 0, 1)),
                  "observations": observe(data, _FINAL_SNAPSHOT),
                  "logs": [reference(name, raw) for name, raw in logs.items()]}
        with tempfile.TemporaryDirectory() as temporary, patch("tools.run_io01_pci.load_inputs", return_value=inputs):
            out = Path(temporary).resolve()
            for name, raw in logs.items():
                (out / name).write_bytes(raw)
            (out / "result.json").write_text(json.dumps(result))
            manifest = out / "unused-manifest.json"
            verified = verify_result(manifest, out, "present", nvme_admin_queues=True)
            self.assertEqual(verified["status"], "consistent")
            (out / _FINAL_NAME).write_bytes(b"\x01" + _FINAL_SNAPSHOT[1:])
            with self.assertRaisesRegex(ValueError, "raw log hashes differ"):
                verify_result(manifest, out, "present", nvme_admin_queues=True)


if __name__ == "__main__":
    unittest.main()
