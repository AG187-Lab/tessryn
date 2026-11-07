"""Verify a fixed q35 VT-d setup or capability refusal with bus mastering off."""

import re
import struct

from tools.build_io01_pci import DMA_CASES, PROFILE
from tools.io01_pci_trace import DONE_PREFIX, require_evidence
from tools.io02_nvme_admin_trace import verify_admin_queues


VTD_STATE_FILE = "vtd-state.bin"
VTD_TABLES_FILE = "vtd-tables.bin"
VTD_BASE = 0xFED9_0000
VTD_STATE_SIZE = 32
VTD_TABLES_SIZE = 5 * 4096
VTD_STATE_ARGUMENTS = {"val": VTD_BASE + 0x08, "size": VTD_STATE_SIZE, "filename": VTD_STATE_FILE}

_PAGE_SIZE = 4096
_CAP_WITHOUT_SAGAW = 0x80D2_008C_2226_0006
_CAP_SAGAW_39 = 1 << 9
_ECAP = 0xF42
_READY_GSTS = 0xC000_0000
_REQUESTER = 0x0100
_SQ_IOVA = 0x0100_0000
_CQ_IOVA = _SQ_IOVA + _PAGE_SIZE
_MARKER = b"TESSRYN_IO02_VTD"
_DONE = re.compile(re.escape(DONE_PREFIX) + rb"[0-9]{1,4}\r?\n")
_WITNESS = re.compile(
    rb"TESSRYN_IO02_VTD status=(ready|blocked) base=0xfed90000 sid=0x0100 "
    rb"root=0x([0-9a-f]{16}) gsts=0x([0-9a-f]{8}) bme=0"
)
_IMAGE = re.compile(rb"(?m)^TESSRYN_K01_LIVE_RANGES image_start=0x([0-9a-f]{1,16}) "
                    rb"image_end=0x([0-9a-f]{1,16}) ")
_QUEUE_PAGES = re.compile(rb"TESSRYN_IO02_NVME_ADMIN bdf=01:00\.0 asq=0x([0-9a-f]{16}) "
                          rb"acq=0x([0-9a-f]{16}) ")


def _witness(serial: bytes, case: str):
    require_evidence(case in DMA_CASES and serial.count(_MARKER) == 1, "expected one VT-d terminal witness")
    lines = serial.splitlines(keepends=True)
    require_evidence(len(lines) >= 3 and lines[-2].endswith(b"\n") and _DONE.fullmatch(lines[-1]) is not None,
                     "missing terminal VT-d witness")
    record = lines[-2][:-1].removesuffix(b"\r")
    match = _WITNESS.fullmatch(record)
    require_evidence(match is not None, "malformed VT-d terminal witness")
    status = match[1].decode("ascii")
    root, gsts = int(match[2], 16), int(match[3], 16)
    if case == "blocked":
        require_evidence((status, root, gsts) == ("blocked", 0, 0), "VT-d capability refusal published state")
    else:
        require_evidence(status == "ready" and gsts == _READY_GSTS, "VT-d translation did not reach ready")
        images = list(_IMAGE.finditer(serial))
        firmware_exit = serial.find(b"\nTESSRYN_K01_EXIT_BOOT_SERVICES_OK")
        queues = _QUEUE_PAGES.match(lines[-3])
        require_evidence(len(images) == 1 and images[0].start() < firmware_exit and queues is not None,
                         "missing admitted VT-d image and queue spans")
        start, end = (int(field, 16) for field in images[0].groups())
        asq, acq = (int(field, 16) for field in queues.groups())
        require_evidence(0 < start < end <= (PROFILE["memory_mib"] << 20)
                         and start % _PAGE_SIZE == end % _PAGE_SIZE == root % _PAGE_SIZE == 0
                         and start <= root <= end - VTD_TABLES_SIZE
                         and asq != acq
                         and all(start <= queue <= end - _PAGE_SIZE and queue % _PAGE_SIZE == 0
                                 and not root <= queue < root + VTD_TABLES_SIZE for queue in (asq, acq)),
                         "VT-d table pages do not fit a distinct aligned kernel image span")
    return b"".join(lines[:-2]) + lines[-1], root, gsts, status


def vtd_snapshot_requests(serial: bytes, case: str) -> tuple[dict, ...]:
    """Admit the guest-derived table address before any monitor read."""
    _, root, _, _ = _witness(serial, case)
    if case == "blocked":
        return (VTD_STATE_ARGUMENTS,)
    return VTD_STATE_ARGUMENTS, {"val": root, "size": VTD_TABLES_SIZE, "filename": VTD_TABLES_FILE}


def _verify_tables(snapshot: bytes | None, root: int, asq: int, acq: int) -> None:
    # Layout is root, context, L3, L2, L1. All other requester and leaf entries
    # must be absent. The intermediate entries permit both leaf directions.
    words = {
        (0, 2): (root + _PAGE_SIZE) | 1,  # bus 1 entry, low qword
        (1, 0): (root + 2 * _PAGE_SIZE) | 1,  # device/function 0, legacy multi-level
        (1, 1): 0x101,  # domain 1, adjusted guest address width 39
        (2, 0): (root + 3 * _PAGE_SIZE) | 3,
        (3, 8): (root + 4 * _PAGE_SIZE) | 3,
        (4, 0): asq | 1,  # 0x01000000, read only
        (4, 1): acq | 2,  # 0x01001000, write only
    }
    expected = bytearray(VTD_TABLES_SIZE)
    for (page, qword), value in words.items():
        struct.pack_into("<Q", expected, page * _PAGE_SIZE + qword * 8, value)
    require_evidence(type(snapshot) is bytes and snapshot == expected, "paused VT-d tables differ from the exact queue map")


def verify_dma_isolation(serial: bytes, pci, case: str, register_snapshot: bytes | None,
                         admin_snapshot: bytes | None, state: bytes | None, tables: bytes | None) -> dict:
    admin_serial, root, gsts, status = _witness(serial, case)
    admin = verify_admin_queues(admin_serial, pci, "present", register_snapshot, admin_snapshot)
    require_evidence(type(state) is bytes and len(state) == VTD_STATE_SIZE, "missing exact paused VT-d state")
    cap, ecap, gcmd, paused_gsts, rtaddr = struct.unpack("<QQIIQ", state)
    expected_cap = _CAP_WITHOUT_SAGAW | (_CAP_SAGAW_39 if case == "present" else 0)
    require_evidence((cap, ecap, gcmd, paused_gsts, rtaddr) == (expected_cap, _ECAP, 0, gsts, root),
                     "paused VT-d capability, status or root differs from the case")
    result = {"status": status, "base": VTD_BASE, "sid": _REQUESTER, "root": root, "gsts": gsts,
              "cap": cap, "ecap": ecap, "bme": 0, "dma_attempted": False}
    if case == "present":
        queues = admin["nvme_admin"]
        _verify_tables(tables, root, queues["asq"], queues["acq"])
        result.update({"domain": 1, "sq_iova": _SQ_IOVA, "cq_iova": _CQ_IOVA})
    else:
        require_evidence(tables is None, "blocked VT-d case retained unexpected tables")
    return {**admin, "nvme_dma_isolation": result}
