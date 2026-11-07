"""Controls for the opt-in VT-d setup and replay packet."""

import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from test_io02_nvme_admin_trace import _ADMIN_PRESENT, _FINAL_SNAPSHOT, _LIVE_IMAGE, admin_exchange, admin_serial
from test_io02_nvme_trace import SNAPSHOT, wire
from tools.run_io01_pci import (DMA_PASS_REASON, LOGS, Capture, bindings, execution, header,
                                observations, qemu_command, reference, verify_result)
from tools.io02_nvme_dma_trace import vtd_snapshot_requests


_ROOT = 0x125000
_LIVE = _LIVE_IMAGE.replace(b"image_end=0x124000 stack_start=0x124000 stack_end=0x128000 "
                            b"map_start=0x128000 map_end=0x129000",
                            b"image_end=0x12c000 stack_start=0x130000 stack_end=0x134000 "
                            b"map_start=0x134000 map_end=0x135000")
_READY = (b"TESSRYN_IO02_VTD status=ready base=0xfed90000 sid=0x0100 root=0x0000000000125000 "
          b"gsts=0xc0000000 bme=0\n")
_BLOCKED = (b"TESSRYN_IO02_VTD status=blocked base=0xfed90000 sid=0x0100 root=0x0000000000000000 "
            b"gsts=0x00000000 bme=0\n")
_STATE_NAME = "vtd-state.bin"
_TABLES_NAME = "vtd-tables.bin"
_READY_STATE = struct.pack("<QQIIQ", 0x80D2_008C_2226_0206, 0xF42, 0, 0xC000_0000, _ROOT)
_BLOCKED_STATE = struct.pack("<QQIIQ", 0x80D2_008C_2226_0006, 0xF42, 0, 0, 0)
_TABLES = bytearray(20480)
for offset, entry in ((16, 0x126001), (4096, 0x127001), (4104, 0x101),
                      (8192, 0x128003), (12288 + 64, 0x129003),
                      (16384, 0x121001), (16392, 0x122002)):
    struct.pack_into("<Q", _TABLES, offset, entry)
_TABLES = bytes(_TABLES)


def dma_serial(record, *, live=_LIVE, admin=_ADMIN_PRESENT):
    return admin_serial(admin, live=live).replace(b"TESSRYN_IO01_PCI_DONE", record + b"TESSRYN_IO01_PCI_DONE")


def dma_exchange(*, case="present"):
    received, sent = admin_exchange()
    args = [{"val": 0xFED9_0008, "size": 32, "filename": _STATE_NAME}]
    if case == "present":
        args.append({"val": _ROOT, "size": 20480, "filename": _TABLES_NAME})
    sent[-1]["id"] = received[-1]["id"] = 8 + len(args)
    for request_id, arguments in enumerate(args, 8):
        sent.insert(-1, {"id": request_id, "execute": "pmemsave", "arguments": arguments})
        received.insert(-1, {"id": request_id, "return": {}})
    return received, sent


def observe(data, state=_READY_STATE, tables=_TABLES, *, case="present", received=None, sent=None):
    if received is None or sent is None:
        received, sent = dma_exchange(case=case)
    return observations(case, data, b"", wire(received), wire(sent), nvme_dma_isolation=True,
                        nvme_snapshot=SNAPSHOT, admin_snapshot=_FINAL_SNAPSHOT,
                        vtd_state=state, vtd_tables=tables)


class NvmeDmaTraceTests(unittest.TestCase):
    def test_profile_changes_only_the_iommu_capability_between_cases(self):
        present = qemu_command("present", nvme_dma_isolation=True)
        blocked = qemu_command("blocked", nvme_dma_isolation=True)
        iommu = ("intel-iommu,intremap=off,aw-bits=39,scalable-mode=off,caching-mode=off,"
                 "device-iotlb=off,dma-translation=")
        index = present.index(iommu + "on")
        self.assertTrue(present[index + 2].startswith("pcie-root-port,"))
        self.assertTrue(any(arg.startswith("nvme,id=io01-nvme,") for arg in present))
        self.assertEqual(blocked, [arg if arg != iommu + "on" else iommu + "off" for arg in present])
        self.assertNotIn(iommu + "on", qemu_command("present"))
        for case, mode in (("blocked", False), ("absent", True)):
            with self.subTest(case=case), self.assertRaises(ValueError):
                qemu_command(case, nvme_dma_isolation=mode)

    def test_ready_and_blocked_controls_replay_different_state(self):
        ready = observe(dma_serial(_READY))
        self.assertEqual(ready["nvme_bdf"], "01:00.0")
        self.assertEqual(ready["nvme_dma_isolation"], {
            "status": "ready", "base": 0xFED9_0000, "sid": 0x0100, "root": _ROOT, "gsts": 0xC000_0000,
            "cap": 0x80D2_008C_2226_0206, "ecap": 0xF42, "bme": 0, "dma_attempted": False,
            "domain": 1, "sq_iova": 0x0100_0000, "cq_iova": 0x0100_1000,
        })
        blocked = observe(dma_serial(_BLOCKED), _BLOCKED_STATE, None, case="blocked")
        self.assertEqual(blocked["nvme_bdf"], "01:00.0")
        self.assertEqual(blocked["nvme_dma_isolation"], {
            "status": "blocked", "base": 0xFED9_0000, "sid": 0x0100, "root": 0, "gsts": 0,
            "cap": 0x80D2_008C_2226_0006, "ecap": 0xF42, "bme": 0, "dma_attempted": False,
        })
        self.assertEqual([item["filename"] for item in vtd_snapshot_requests(dma_serial(_BLOCKED), "blocked")],
                         [_STATE_NAME])

    def test_invalid_serial_or_unsafe_address_cannot_request_a_table_read(self):
        for address in (0, 0x124FFF, 0x121000, 0x122000, 0x128000, 0xFED90000):
            with self.subTest(address=address), self.assertRaises(ValueError):
                data = dma_serial(_READY.replace(b"0x0000000000125000", f"0x{address:016x}".encode()))
                vtd_snapshot_requests(data, "present")
        for record, live in ((_READY * 2, _LIVE), (_READY, _LIVE * 2), (_READY, b""),
                             (_READY.replace(b"bme=0", b"bme=1"), _LIVE), (_BLOCKED, _LIVE),
                             (_READY.replace(b"sid=0x0100", b"sid=0x0200"), _LIVE)):
            with self.subTest(record=record, live=live), self.assertRaises(ValueError):
                vtd_snapshot_requests(dma_serial(record, live=live), "present")

    def test_wrong_capability_or_published_blocked_state_is_rejected(self):
        for state, table, record in ((_READY_STATE, None, _BLOCKED), (_BLOCKED_STATE, _TABLES, _BLOCKED),
                                     (_BLOCKED_STATE, None, _BLOCKED.replace(b"root=0x0000000000000000",
                                                                             b"root=0x0000000000125000")),
                                     (_BLOCKED_STATE, None, _BLOCKED.replace(b"gsts=0x00000000", b"gsts=0x40000000"))):
            with self.subTest(state=state, record=record), self.assertRaises(ValueError):
                observe(dma_serial(record), state, table, case="blocked")
        for offset in (0, 8, 16, 20, 24):
            changed = bytearray(_READY_STATE)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                observe(dma_serial(_READY), bytes(changed))

    def test_ready_rejects_extra_requester_and_wrong_leaf_permissions(self):
        for offset in (0, 16, 4096, 4104, 8192, 12352, 16384, 16392, 16400):
            changed = bytearray(_TABLES)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                observe(dma_serial(_READY), tables=bytes(changed))
        with self.assertRaises(ValueError):
            observe(dma_serial(_READY), tables=None)

    def test_exact_snapshot_requests_and_acknowledgments_are_required(self):
        for index, override in ((-2, {"val": _ROOT + 4096}), (-2, {"size": 20480.0}),
                                (-3, {"size": 12}), (-3, {"val": 0xFED9_001C})):
            with self.subTest(index=index, override=override), self.assertRaises(ValueError):
                received, sent = dma_exchange()
                sent[index]["arguments"].update(override)
                observe(dma_serial(_READY), received=received, sent=sent)
        received, sent = dma_exchange()
        received[-2]["return"] = {"unexpected": 1}
        with self.assertRaises(ValueError):
            observe(dma_serial(_READY), received=received, sent=sent)
        received, sent = dma_exchange()
        with self.assertRaises(ValueError):
            observe(dma_serial(_BLOCKED), _BLOCKED_STATE, None, case="blocked", received=received, sent=sent)

    def test_blocked_replay_refuses_an_unexpected_table_file(self):
        data = dma_serial(_BLOCKED)
        received, sent = dma_exchange(case="blocked")
        inputs = (b"manifest", b"boot disk", "qemu hash", {})
        logs = dict(zip(LOGS, (data, b"", wire(received), wire(sent))))
        logs.update({"nvme-registers.bin": SNAPSHOT, "nvme-admin-final.bin": _FINAL_SNAPSHOT,
                     _STATE_NAME: _BLOCKED_STATE})
        result = {**header("blocked", nvme_dma_isolation=True), "status": "pass", "reason": DMA_PASS_REASON,
                  "bindings": bindings(inputs),
                  "execution": execution("blocked", Capture("completed", "serial, QMP and process streams completed", 0, 1),
                                         nvme_dma_isolation=True),
                  "observations": observe(data, _BLOCKED_STATE, None, case="blocked"),
                  "logs": [reference(name, raw) for name, raw in logs.items()]}
        with tempfile.TemporaryDirectory() as temporary, patch("tools.run_io01_pci.load_inputs", return_value=inputs):
            out = Path(temporary).resolve()
            for name, raw in logs.items():
                (out / name).write_bytes(raw)
            (out / "result.json").write_text(json.dumps(result))
            manifest = out / "unused-manifest.json"
            self.assertEqual(verify_result(manifest, out, "blocked", nvme_dma_isolation=True)["status"], "consistent")
            (out / _TABLES_NAME).write_bytes(_TABLES)
            with self.assertRaises(ValueError):
                verify_result(manifest, out, "blocked", nvme_dma_isolation=True)
