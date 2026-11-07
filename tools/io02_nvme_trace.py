"""Cross-check the bounded IO02 guest register record with paused QMP."""

import re
import struct

from tools.io01_pci_trace import require_evidence, verify


BAR0_ADDRESS = 0x8100_0000
BAR0_SIZE = 0x4000
CAP = 0x0040_0820_0F01_07FF
VS = 0x0001_0400
SNAPSHOT_FILE = "nvme-registers.bin"
SNAPSHOT_SIZE = 12
SNAPSHOT_ARGUMENTS = {"val": BAR0_ADDRESS, "size": SNAPSHOT_SIZE, "filename": SNAPSHOT_FILE}
_MARKER = b"TESSRYN_IO02_NVME_"
_PRESENT = re.compile(
    rb"TESSRYN_IO02_NVME_REGISTERS bdf=01:00\.0 bar=0x81000000 "
    rb"cap=0x([0-9a-f]{16}) vs=0x([0-9a-f]{8}) reads=3"
)
_ABSENT = b"TESSRYN_IO02_NVME_ABSENT reads=0"


def _function(devices, expected):
    require_evidence(type(devices) is list and len(devices) <= 64, "invalid IO02 PCI device list")
    matches = [row for row in devices if type(row) is dict and all(
        type(row.get(key)) is type(value) and row[key] == value for key, value in expected.items()
    )]
    require_evidence(len(matches) == 1, "missing or duplicate IO02 PCI function")
    return matches[0]


def admit_bar0(pci) -> None:
    """Admit only the pinned present-case address before the host MMIO read."""
    require_evidence(type(pci) is list and len(pci) == 1 and type(pci[0]) is dict
                     and type(pci[0].get("bus")) is int and pci[0]["bus"] == 0,
                     "invalid IO02 PCI root bus")
    port = _function(pci[0].get("devices"), {"bus": 0, "slot": 2, "function": 0, "qdev_id": "io01-port"})
    bridge = port.get("pci_bridge")
    require_evidence(type(bridge) is dict, "missing IO02 root-port bridge")
    endpoint = _function(bridge.get("devices"), {"bus": 1, "slot": 0, "function": 0, "qdev_id": "io01-nvme"})
    identity, cls = endpoint.get("id"), endpoint.get("class_info")
    require_evidence(type(identity) is dict and type(identity.get("vendor")) is int and identity["vendor"] == 0x1B36
                     and type(identity.get("device")) is int and identity["device"] == 0x0010
                     and type(cls) is dict and type(cls.get("class")) is int and cls["class"] == 0x0108,
                     "unexpected IO02 endpoint identity")
    regions = endpoint.get("regions")
    require_evidence(type(regions) is list and len(regions) <= 7, "missing or oversized IO02 BAR list")
    bar0 = [row for row in regions if type(row) is dict and row.get("bar") == 0]
    expected = {"bar": 0, "type": "memory", "address": BAR0_ADDRESS, "size": BAR0_SIZE,
                "mem_type_64": True, "prefetch": False}
    require_evidence(len(bar0) == 1 and bar0[0].keys() == expected.keys() and all(
        type(bar0[0][key]) is type(value) and bar0[0][key] == value for key, value in expected.items()
    ), "IO02 BAR0 geometry differs from the fixed profile")


def verify_registers(serial: bytes, pci, case: str, snapshot: bytes | None) -> dict:
    require_evidence(serial.count(_MARKER) == 1, "expected one IO02 register record")
    lines = serial.splitlines(keepends=True)
    require_evidence(len(lines) >= 2 and lines[-2].endswith(b"\n"), "missing terminal IO02 register record")
    record = lines[-2][:-1].removesuffix(b"\r")
    inventory = verify(b"".join(lines[:-2]) + lines[-1], pci, case)
    if case == "absent":
        require_evidence(record == _ABSENT and snapshot is None, "unexpected IO02 read in the absent case")
        return {**inventory, "nvme_registers": {"reads": 0}}

    require_evidence(inventory["nvme_bdf"] == "01:00.0", "unexpected IO02 endpoint address")
    admit_bar0(pci)
    match = _PRESENT.fullmatch(record)
    require_evidence(match is not None, "malformed IO02 register record")
    cap, vs = (int(field, 16) for field in match.groups())
    require_evidence((cap, vs) == (CAP, VS), "guest IO02 registers differ from the fixed profile")
    require_evidence(type(snapshot) is bytes and len(snapshot) == SNAPSHOT_SIZE
                     and struct.unpack("<QI", snapshot) == (cap, vs),
                     "paused IO02 register snapshot differs from the guest reads")
    return {**inventory, "nvme_registers": {"bar0": BAR0_ADDRESS, "bar0_size": BAR0_SIZE,
                                            "cap": cap, "vs": vs, "reads": 3}}
