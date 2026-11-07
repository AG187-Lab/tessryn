"""Verify the bounded IO02 admin-queue witness and final QMP register state."""

import re
import struct

from tools.build_io01_pci import PROFILE
from tools.io01_pci_trace import require_evidence
from tools.io02_nvme_trace import BAR0_ADDRESS, verify_registers


ADMIN_SNAPSHOT_FILE = "nvme-admin-final.bin"
ADMIN_SNAPSHOT_SIZE = 36
ADMIN_SNAPSHOT_ARGUMENTS = {"val": BAR0_ADDRESS + 0x14, "size": ADMIN_SNAPSHOT_SIZE,
                            "filename": ADMIN_SNAPSHOT_FILE}
_MARKER = b"TESSRYN_IO02_NVME_ADMIN"
_PRESENT = re.compile(
    rb"TESSRYN_IO02_NVME_ADMIN bdf=01:00\.0 asq=0x([0-9a-f]{16}) acq=0x([0-9a-f]{16}) "
    rb"aqa=0x00010001 cc_ready=0x00460001 csts_ready=0x00000001 "
    rb"cc_final=0x00000000 csts_final=0x00000000 bme=0 doorbells=0 firmware=(reset|inactive)"
)
_ABSENT = b"TESSRYN_IO02_NVME_ADMIN_ABSENT writes=0"
_LIVE_IMAGE = re.compile(
    rb"(?m)^TESSRYN_K01_LIVE_RANGES image_start=0x([0-9a-f]{1,16}) image_end=0x([0-9a-f]{1,16}) "
    rb"stack_start=0x[0-9a-f]{1,16} stack_end=0x[0-9a-f]{1,16} "
    rb"map_start=0x[0-9a-f]{1,16} map_end=0x[0-9a-f]{1,16} "
    rb"scratch=0x[0-9a-f]{1,16} runtime_high=[0-9]+ "
    rb"gop_start=0x[0-9a-f]{1,16} gop_end=0x[0-9a-f]{1,16}\r?$"
)
_PAGE_SIZE = 4096
_FINAL_REGISTERS = struct.Struct("<I4xI4xIQQ")  # CC, CSTS, AQA, ASQ, ACQ.


def verify_admin_queues(serial: bytes, pci, case: str, register_snapshot: bytes | None,
                        final_snapshot: bytes | None) -> dict:
    require_evidence(serial.count(_MARKER) == 1, "expected one IO02 admin-queue record")
    lines = serial.splitlines(keepends=True)
    require_evidence(len(lines) >= 2 and lines[-2].endswith(b"\n"), "missing terminal IO02 admin-queue record")
    record = lines[-2][:-1].removesuffix(b"\r")
    registers = verify_registers(b"".join(lines[:-2]) + lines[-1], pci, case, register_snapshot)
    if case == "absent":
        require_evidence(record == _ABSENT and final_snapshot is None, "unexpected IO02 admin write in the absent case")
        return {**registers, "nvme_admin": {"writes": 0}}

    match = _PRESENT.fullmatch(record)
    require_evidence(match is not None, "malformed IO02 admin-queue record")
    asq, acq = (int(field, 16) for field in match.groups()[:2])
    firmware = match[3].decode("ascii")
    images = list(_LIVE_IMAGE.finditer(serial))
    firmware_exit = serial.find(b"\nTESSRYN_K01_EXIT_BOOT_SERVICES_OK")
    require_evidence(len(images) == 1 and images[0].start() < firmware_exit,
                     "missing admitted IO02 kernel image range")
    start, end = (int(field, 16) for field in images[0].groups())
    require_evidence(0 < start < end <= (PROFILE["memory_mib"] << 20)
                     and start % _PAGE_SIZE == end % _PAGE_SIZE == 0
                     and asq != acq
                     and all(start <= page <= end - _PAGE_SIZE and page % _PAGE_SIZE == 0 for page in (asq, acq)),
                     "IO02 admin-queue pages do not fit distinct aligned kernel image pages")
    require_evidence(type(final_snapshot) is bytes and len(final_snapshot) == ADMIN_SNAPSHOT_SIZE
                     and _FINAL_REGISTERS.unpack(final_snapshot) == (0, 0, 0, 0, 0),
                     "paused IO02 controller was not disabled with cleared admin queues")
    return {**registers, "nvme_admin": {"asq": asq, "acq": acq, "aqa": 0x0001_0001,
                                       "cc_ready": 0x0046_0001, "csts_ready": 1,
                                       "cc_final": 0, "csts_final": 0, "bme": 0, "doorbells": 0,
                                       "firmware": firmware}}
