"""Compare the original kernel's bounded PCI scan with the same VM's QMP inventory."""

import re


DONE_PREFIX = b"TESSRYN_IO01_PCI_DONE count="
_BEGIN = b"TESSRYN_IO01_PCI_BEGIN segment=0 buses=0-7 mechanism=cf8-cfc"
_MAX_SERIAL = 1 << 20
_MAX_FUNCTIONS = 64
_MAX_BUS = 7
_PORT = (0, 2, 0)
_CSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
_PREAMBLE = tuple(map(re.compile, (
    rb"TESSRYN_K01_ENTRY",
    rb"TESSRYN_K01_MEMORY_MAP_VALID descriptors=[1-9][0-9]* stride=[1-9][0-9]* free_pages=[1-9][0-9]* attempt=1",
    rb"TESSRYN_K01_EXIT_BOOT_SERVICES_OK",
    rb"TESSRYN_K01_CPU_OWNED cr3=0x[0-9a-f]{1,16} rsp=0x[0-9a-f]{1,16} rip=0x[0-9a-f]{1,16} gdt=owned idt=owned tss=owned",
    rb"TESSRYN_K01_MEMORY_OWNERSHIP_OK scratch=0x[0-9a-f]{1,16} free_pages=[1-9][0-9]* loader=reserved runtime=reserved firmware=quarantined",
)))
_SUPPLEMENTAL = {
    b"TESSRYN_K01_FRAMEBUFFER", b"TESSRYN_K01_LIVE_RANGES",
    b"TESSRYN_K01_PAGING_READY", b"TESSRYN_K01_RESET_POINTER",
}
_FUNCTION = re.compile(
    rb"TESSRYN_IO01_PCI_FUNCTION bdf=([0-9a-f]{2}):([0-9a-f]{2})\.([0-7]) "
    rb"id=0x([0-9a-f]{8}) class_rev=0x([0-9a-f]{8}) header=0x([0-9a-f]{8})"
)
_DONE = re.compile(re.escape(DONE_PREFIX) + rb"(0|[1-9][0-9]?)")


class EvidenceRejected(ValueError):
    """A fixed validation message that contains no capture or host data."""


def require_evidence(condition, message):
    if not condition:
        raise EvidenceRejected(message)


def _bdf(address):
    bus, slot, function = address
    return f"{bus:02x}:{slot:02x}.{function:x}"


def _guest_inventory(serial):
    require_evidence(type(serial) is bytes and 0 < len(serial) <= _MAX_SERIAL and serial.endswith(b"\n"),
          "PCI serial is missing, oversized or truncated")
    lines = [line.removesuffix(b"\r") for line in serial[:-1].split(b"\n")]
    for i, raw in enumerate(lines):
        line = _CSI.sub(b"", raw)
        if _PREAMBLE[0].fullmatch(line):
            break
        require_evidence(b"TESSRYN_K01_" not in line and b"TESSRYN_IO01_" not in line,
              "kernel evidence precedes the original entry")
    else:
        raise EvidenceRejected("missing original kernel entry")

    required, supplemental = 1, set()
    for i in range(i + 1, len(lines)):
        line = lines[i]
        if line == _BEGIN:
            break
        if required < len(_PREAMBLE) and _PREAMBLE[required].fullmatch(line):
            required += 1
            continue
        label, _, fields = line.partition(b" ")
        if line == b"TESSRYN ORIGINAL KERNEL":
            label = line
        else:
            require_evidence(label in _SUPPLEMENTAL and bool(fields), "unexpected pre-inventory kernel record")
        require_evidence(label not in supplemental, "duplicate pre-inventory kernel record")
        supplemental.add(label)
    else:
        raise EvidenceRejected("missing PCI inventory start")
    require_evidence(required == len(_PREAMBLE), "PCI inventory precedes completed kernel handoff")

    done = _DONE.fullmatch(lines[-1])
    require_evidence(done is not None, "missing terminal PCI inventory count")
    count = int(done[1])
    require_evidence(0 < count <= _MAX_FUNCTIONS and len(lines) - i - 2 == count,
          "PCI inventory count differs from complete records")
    rows, last = {}, None
    for line in lines[i + 1:-1]:
        match = _FUNCTION.fullmatch(line)
        require_evidence(match is not None, "malformed or unknown PCI function record")
        bus, slot, function, identity, class_rev, header = (
            int(value, 16) for value in match.groups()
        )
        address = (bus, slot, function)
        vendor = identity & 0xffff
        require_evidence(bus <= _MAX_BUS and slot < 32 and vendor not in (0, 0xffff)
              and ((header >> 16) & 0x7f) <= 2, "PCI function outside the admitted header profile")
        require_evidence(last is None or last < address, "PCI function records must be unique and ordered")
        rows[address] = {
            "bdf": _bdf(address), "vendor": vendor, "device": identity >> 16,
            "class_subclass": class_rev >> 16, "prog_if": (class_rev >> 8) & 0xff,
            "revision": class_rev & 0xff, "header": header,
        }
        last = address
    return rows


def _uint(value, maximum):
    require_evidence(type(value) is int and 0 <= value <= maximum, "invalid typed QMP PCI field")
    return value


# Pinned QEMU schema: https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/qapi/pci.json
# The producer reads class/subclass, not programming interface or revision.
def _qmp_inventory(pci):
    require_evidence(type(pci) is list and len(pci) == 1 and type(pci[0]) is dict
          and pci[0].keys() == {"bus", "devices"}
          and _uint(pci[0].get("bus"), _MAX_BUS) == 0, "expected a single QMP root bus zero")
    rows, labels, bridges, visited = {}, set(), {}, set()

    def walk(devices, bus, parent=None):
        require_evidence(type(devices) is list and len(devices) <= _MAX_FUNCTIONS and bus not in visited,
              "invalid or repeated QMP PCI bus")
        visited.add(bus)
        for row in devices:
            require_evidence(type(row) is dict and _uint(row.get("bus"), _MAX_BUS) == bus,
                  "QMP device bus disagrees with bridge topology")
            address = bus, _uint(row.get("slot"), 31), _uint(row.get("function"), 7)
            require_evidence(address not in rows and len(rows) < _MAX_FUNCTIONS,
                  "duplicate or excessive QMP PCI functions")
            identity, cls = row.get("id"), row.get("class_info")
            require_evidence(type(identity) is dict and type(cls) is dict, "missing QMP PCI identity or class")
            vendor, device = _uint(identity.get("vendor"), 0xffff), _uint(identity.get("device"), 0xffff)
            require_evidence(vendor not in (0, 0xffff), "invalid QMP PCI vendor")
            class_subclass = _uint(cls.get("class"), 0xffff)
            label = row.get("qdev_id")
            require_evidence(type(label) is str and len(label) <= 128 and (not label or label.isprintable()),
                  "invalid QMP PCI device label")
            if label:
                require_evidence(label not in labels, "duplicate QMP PCI device label")
                labels.add(label)
            rows[address] = (vendor, device, class_subclass, label, parent)
            if "pci_bridge" not in row:
                continue

            bridge = row["pci_bridge"]
            require_evidence(type(bridge) is dict and bridge.keys() in ({"bus"}, {"bus", "devices"})
                  and type(bridge["bus"]) is dict and class_subclass == 0x0604, "invalid QMP PCI bridge")
            bus_info = bridge["bus"]
            require_evidence(_uint(bus_info.get("number"), _MAX_BUS) == bus,
                  "QMP bridge primary bus differs from its function")
            secondary = _uint(bus_info.get("secondary"), _MAX_BUS)
            subordinate = _uint(bus_info.get("subordinate"), 255)
            children = bridge.get("devices", [])
            require_evidence(type(children) is list and (secondary > bus and secondary <= subordinate
                  or secondary == subordinate == 0 and not children), "invalid QMP bridge child range")
            bridges[address] = secondary
            if secondary:
                walk(children, secondary, address)

    walk(pci[0].get("devices"), 0)
    require_evidence(bridges.keys() == {_PORT} and rows[_PORT][2:] == (0x0604, "io01-port", None),
          "expected one fixed QMP root port")
    return rows, bridges[_PORT]


def verify(serial: bytes, pci: object, case: str) -> dict:
    """Return typed emulator observations, never a native-device qualification.

    The runner must bind the supplied QMP return value to the emulator that
    produced the serial stream. The overlapping identity fields alone cannot
    authenticate a capture or distinguish two otherwise identical machines.
    """
    require_evidence(type(case) is str and case in ("present", "absent"), "unknown PCI inventory case")
    guest = _guest_inventory(serial)
    qmp, secondary = _qmp_inventory(pci)
    require_evidence(guest.keys() == qmp.keys(), "guest and QMP PCI function sets differ")
    for address, row in guest.items():
        require_evidence((row["vendor"], row["device"], row["class_subclass"]) == qmp[address][:3],
              "guest and QMP PCI identity or class differs")
    require_evidence(((guest[_PORT]["header"] >> 16) & 0x7f) == 1, "guest root port is not a bridge header")

    nvme = [address for address, row in qmp.items() if row[2] == 0x0108]
    labeled = [address for address, row in qmp.items() if row[3] == "io01-nvme"]
    if case == "present":
        selected = (secondary, 0, 0)
        children = [address for address, row in qmp.items() if row[4] == _PORT]
        require_evidence(secondary != 0 and nvme == labeled == children == [selected]
              and guest[selected]["prog_if"] == 2 and ((guest[selected]["header"] >> 16) & 0x7f) == 0,
              "expected exactly the modeled NVMe endpoint below the fixed root port")
    else:
        require_evidence(not nvme and not labeled and all(row[4] is None for row in qmp.values()),
              "absent fixture has an unexpected endpoint")
        selected = None
    return {"case": case, "device_count": len(guest), "functions": list(guest.values()),
            "nvme_bdf": _bdf(selected) if selected is not None else None}
