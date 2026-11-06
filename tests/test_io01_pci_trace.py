"""Synthetic host cases for the original guest/QMP inventory comparison."""

import unittest

from tools.io01_pci_trace import DONE_PREFIX, verify


PRELUDE = (
    b"\x1b[2J\x1b[01;01HTESSRYN_K01_ENTRY\n"
    b"TESSRYN ORIGINAL KERNEL\n"
    b"TESSRYN_K01_FRAMEBUFFER status=ready\n"
    b"TESSRYN_K01_MEMORY_MAP_VALID descriptors=23 stride=48 free_pages=12000 attempt=1\n"
    b"TESSRYN_K01_EXIT_BOOT_SERVICES_OK\n"
    b"TESSRYN_K01_CPU_OWNED cr3=0x123000 rsp=0x124000 rip=0x125000 gdt=owned idt=owned tss=owned\n"
    b"TESSRYN_K01_MEMORY_OWNERSHIP_OK scratch=0x100000 free_pages=12000 loader=reserved runtime=reserved firmware=quarantined\n"
    b"TESSRYN_IO01_PCI_BEGIN segment=0 buses=0-7 mechanism=cf8-cfc\n"
)
HOST = b"TESSRYN_IO01_PCI_FUNCTION bdf=00:00.0 id=0x29c08086 class_rev=0x06000000 header=0x00000000\n"
PORT = b"TESSRYN_IO01_PCI_FUNCTION bdf=00:02.0 id=0x000c1b36 class_rev=0x06040000 header=0x00010000\n"
NVME = b"TESSRYN_IO01_PCI_FUNCTION bdf=01:00.0 id=0x00101b36 class_rev=0x01080202 header=0x00000000\n"


def guest(*rows):
    return PRELUDE + b"".join(rows) + DONE_PREFIX + str(len(rows)).encode() + b"\n"


def function(bus, slot, vendor, device, cls, label="", **extras):
    return {
        "bus": bus, "slot": slot, "function": 0, "id": {"vendor": vendor, "device": device},
        "class_info": {"class": cls}, "qdev_id": label, "irq_pin": 0, "regions": [], **extras,
    }


def fixture(present=True):
    bridge = {"bus": {"number": 0, "secondary": 1, "subordinate": 1}}
    if present:
        bridge["devices"] = [function(1, 0, 0x1b36, 0x0010, 0x0108, "io01-nvme")]
    host = function(0, 0, 0x8086, 0x29c0, 0x0600)
    port = function(0, 2, 0x1b36, 0x000c, 0x0604, "io01-port", pci_bridge=bridge)
    return [{"bus": 0, "devices": [port, host]}]


class Io01PciTraceTests(unittest.TestCase):
    def test_present_correlates_ordered_guest_rows_with_unsorted_qmp_tree(self):
        result = verify(guest(HOST, PORT, NVME), fixture(), "present")
        self.assertEqual(result["device_count"], 3)
        self.assertEqual(result["nvme_bdf"], "01:00.0")
        self.assertEqual([row["bdf"] for row in result["functions"]], ["00:00.0", "00:02.0", "01:00.0"])
        self.assertEqual(result["functions"][-1], {
            "bdf": "01:00.0", "vendor": 0x1b36, "device": 0x0010, "class_subclass": 0x0108,
            "prog_if": 2, "revision": 2, "header": 0,
        })

    def test_absent_accepts_omitted_explicit_empty_and_unconfigured_bridge(self):
        for shape in ("omitted", "empty", "unconfigured"):
            with self.subTest(shape=shape):
                qmp = fixture(present=False)
                bridge = qmp[0]["devices"][0]["pci_bridge"]
                if shape == "empty":
                    bridge["devices"] = []
                if shape == "unconfigured":
                    bridge["bus"].update(secondary=0, subordinate=0)
                result = verify(guest(HOST, PORT).replace(b"\n", b"\r\n"), qmp, "absent")
                self.assertEqual(result["device_count"], 2)
                self.assertIsNone(result["nvme_bdf"])

    def test_malformed_or_unordered_guest_handoff_cannot_qualify_inventory(self):
        serial = guest(HOST, PORT, NVME)
        entry = b"TESSRYN_K01_ENTRY\n"
        exited = b"TESSRYN_K01_EXIT_BOOT_SERVICES_OK\n"
        for candidate in (
            serial.replace(entry, b""),
            serial.replace(entry, entry + entry),
            serial.replace(exited, b""),
            serial.replace(exited, exited + exited),
            serial.replace(exited, b"") + exited,
            serial.replace(b"attempt=1", b"attempt=2"),
            serial.replace(exited, b"TESSRYN_K01_FAIL reason=synthetic\n" + exited),
            serial.replace(exited, b"TESSRYN_K01_TRAP vector=14\n" + exited),
            serial.replace(b"TESSRYN_IO01_PCI_BEGIN", b"TESSRYN_IO01_PCI_FAIL"),
        ):
            with self.subTest(candidate=candidate[:36]), self.assertRaises(ValueError):
                verify(candidate, fixture(), "present")

    def test_partial_duplicate_unsorted_and_extraneous_serial_rejected(self):
        serial = guest(HOST, PORT, NVME)
        for candidate in (
            serial[:-1], serial.replace(DONE_PREFIX + b"3", DONE_PREFIX + b"2"),
            serial + DONE_PREFIX + b"3\n", serial + b"TESSRYN_K01_PANIC synthetic\n",
            serial.replace(NVME, b"TESSRYN_IO01_PCI_UNKNOWN\n"),
            serial.replace(b"0x00101b36", b"0x00101B36"),
            guest(HOST, PORT, NVME.replace(b"01:00.0", b"08:00.0")),
            guest(HOST, PORT, NVME.replace(b"01:00.0", b"01:20.0")),
            guest(HOST, PORT, NVME.replace(b"0x00101b36", b"0x0010ffff")),
            guest(HOST, PORT, NVME.replace(b"header=0x00000000", b"header=0x00030000")),
            guest(HOST, PORT, NVME, NVME), guest(PORT, HOST, NVME),
            b" " * (1 << 20) + serial,
        ):
            with self.subTest(candidate=candidate[-36:]), self.assertRaises(ValueError):
                verify(candidate, fixture(), "present")

    def test_guest_and_qmp_must_cover_identical_full_scoped_sets_and_fields(self):
        for candidate in (
            guest(PORT, NVME), guest(HOST, PORT),
            guest(HOST, PORT, NVME.replace(b"0x00101b36", b"0x00111b36")),
            guest(HOST, PORT, NVME.replace(b"0x00101b36", b"0x00101234")),
            guest(HOST, PORT, NVME.replace(b"0x01080202", b"0x01070202")),
        ):
            with self.subTest(candidate=candidate[-48:]), self.assertRaises(ValueError):
                verify(candidate, fixture(), "present")

    def test_qmp_numeric_types_unique_addresses_and_exact_bridge_location(self):
        serial = guest(HOST, PORT, NVME)
        for change in (
            lambda x: x[0].update(bus=False),
            lambda x: x[0]["devices"][1]["id"].update(vendor=True),
            lambda x: x[0]["devices"][1].pop("qdev_id"),
            lambda x: x[0]["devices"].append(x[0]["devices"][1]),
            lambda x: x[0]["devices"][0]["pci_bridge"]["bus"].update(number=2),
            lambda x: x[0]["devices"][0]["pci_bridge"]["bus"].update(subordinate=0),
            lambda x: x[0]["devices"][0]["pci_bridge"]["devices"][0].update(bus=2),
            lambda x: x[0]["devices"][0]["pci_bridge"].update(devices={}),
            lambda x: x[0]["devices"][0].update(pci_bridge=None),
        ):
            qmp = fixture()
            change(qmp)
            with self.assertRaises(ValueError):
                verify(serial, qmp, "present")
        for qmp in ({"return": fixture()}, [], fixture() + fixture()):
            with self.assertRaises(ValueError):
                verify(serial, qmp, "present")

    def test_present_requires_exact_bridge_endpoint_and_nvme_programming_interface(self):
        serial = guest(HOST, PORT, NVME)
        qmp = fixture()
        qmp[0]["devices"][0]["pci_bridge"]["devices"][0]["slot"] = 1
        with self.assertRaises(ValueError):
            verify(guest(HOST, PORT, NVME.replace(b"01:00.0", b"01:01.0")), qmp, "present")
        with self.assertRaises(ValueError):
            verify(serial.replace(b"0x01080202", b"0x01080102"), fixture(), "present")
        qmp = fixture()
        qmp[0]["devices"][0]["pci_bridge"]["devices"][0]["qdev_id"] = "wrong-endpoint"
        with self.assertRaises(ValueError):
            verify(serial, qmp, "present")
        qmp = fixture()
        qmp[0]["devices"][0]["slot"] = 3
        with self.assertRaises(ValueError):
            verify(guest(HOST, PORT.replace(b"00:02.0", b"00:03.0"), NVME), qmp, "present")

    def test_case_cannot_be_promoted_by_a_matching_but_wrong_inventory(self):
        with self.assertRaises(ValueError):
            verify(guest(HOST, PORT), fixture(present=False), "present")
        qmp = fixture()
        qmp[0]["devices"][0]["pci_bridge"]["devices"][0]["qdev_id"] = "another-nvme"
        with self.assertRaises(ValueError):
            verify(guest(HOST, PORT, NVME), qmp, "absent")
        qmp = fixture(present=False)
        qmp[0]["devices"][1]["qdev_id"] = "io01-nvme"
        with self.assertRaises(ValueError):
            verify(guest(HOST, PORT), qmp, "absent")

    def test_unexpected_child_cannot_pass_even_if_guest_also_reports_it(self):
        extra = NVME.replace(b"01:00.0", b"01:01.0").replace(b"0x01080202", b"0x02000002")
        qmp = fixture()
        qmp[0]["devices"][0]["pci_bridge"]["devices"].append(function(1, 1, 0x1b36, 0x0010, 0x0200, "extra"))
        with self.assertRaises(ValueError):
            verify(guest(HOST, PORT, NVME, extra), qmp, "present")


if __name__ == "__main__":
    unittest.main()
