"""SYNTHETIC normal serial cases, plus retained LOCAL QEMU observations.

Constructed transcripts below are test fixtures, never native AWS evidence.
The separately identified retained QEMU phase tests the actual frozen kernel's
diagnostic spelling; it likewise does not establish native execution.
"""

import hashlib
import json
from pathlib import Path
import unittest

from tools.aws_native_serial import GUARD, MAX_SERIAL_BYTES, parse_native_serial

ROOT = Path(__file__).resolve().parents[1]


def synthetic_transcript(*, attempts=1, gop=False, high_image=False, high_reset=False):
    """SYNTHETIC: explicit coherent fields, not a captured kernel execution."""
    image = 0x140000000 if high_image else 0x10000000
    reset = 0x180000000 if high_reset else 0x7F600000
    extra = len({address // (1 << 21) for address in (image, reset) if address >= 1 << 32})
    directories = len({address // (1 << 30) for address in (image, reset) if address >= 1 << 32})
    lines = ["TESSRYN_K01_ENTRY"]
    if gop:
        lines.extend(("TESSRYN ORIGINAL KERNEL",
                      "TESSRYN_K01_FRAMEBUFFER status=ready width=1280 height=800 stride=1280 base=0x80000000 format=bgrx selection=firmware-console"))
    else:
        lines.append("TESSRYN_K01_FRAMEBUFFER status=unavailable-serial-only reason=optional-gop")
    for attempt in range(1, attempts + 1):
        lines.extend((
            f"TESSRYN_K01_LIVE_RANGES image_start={image:#x} image_end={image + 0x100000:#x} stack_start=0x70000000 stack_end=0x70020000 map_start=0x71000000 map_end=0x71010000 scratch=0x100000 runtime_high={int(high_reset)} gop_start={'0x80000000' if gop else '0x0'} gop_end={'0x803e8000' if gop else '0x0'}",
            f"TESSRYN_K01_PAGING_READY cr3={image + 0x20000:#x} tables={6 + directories} leaves={2048 + extra} physical_bits=40 guard={GUARD:#x} free_scope=low-conventional",
            f"TESSRYN_K01_RESET_POINTER address={reset:#x} method=uefi-runtime",
            f"TESSRYN_K01_MEMORY_MAP_VALID descriptors=104 stride=48 free_pages=510000 attempt={attempt}",
            "TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY" if attempt < attempts else "TESSRYN_K01_EXIT_BOOT_SERVICES_OK"))
    lines.extend((f"TESSRYN_K01_CPU_OWNED cr3={image + 0x20000:#x} rsp=0x7001ff00 rip={image + 0x2000:#x} gdt=owned idt=owned tss=owned",
                  "TESSRYN_K01_MEMORY_OWNERSHIP_OK scratch=0x100000 free_pages=510000 loader=reserved runtime=reserved firmware=quarantined",
                  "TESSRYN_K01_PASS"))
    return ("\n".join(lines) + "\n").encode("ascii")


class SyntheticNormalSerialTests(unittest.TestCase):
    def reject(self, data):
        with self.assertRaises(ValueError) as caught:
            parse_native_serial(data)
        # Rejection reasons never interpolate serial text or its values.
        self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        self.assertLess(len(str(caught.exception)), 120)

    def test_low_headless_normal_returns_observations_without_qualification(self):
        data = synthetic_transcript()
        result = parse_native_serial(data)
        self.assertEqual(result["status"], "parsed")
        self.assertIn("unqualified", result["scope"])
        self.assertEqual(result["serial"], {"size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self.assertEqual(result["exit_attempts"], 1)
        final = result["admissions"][-1]
        self.assertEqual(final["live_ranges"]["scratch"], result["memory_ownership"]["scratch"])
        self.assertEqual(final["paging"]["cr3"], result["cpu_owned"]["cr3"])
        self.assertEqual(result["framebuffer"]["status"], "unavailable-serial-only")
        self.assertNotIn("qualified", result)
        json.dumps(result)  # Caller can persist the observations without custom encoding.

    def test_ready_gop_both_pixel_formats_and_console_selections(self):
        data = synthetic_transcript(gop=True)
        for pixel_format in (b"bgrx", b"rgbx"):
            for selection in (b"firmware-console", b"unique-gop"):
                with self.subTest(format=pixel_format, selection=selection):
                    result = parse_native_serial(data.replace(b"bgrx", pixel_format).replace(b"firmware-console", selection))
                    self.assertEqual(result["framebuffer"]["required_bytes"], 4096000)
        # Firmware allocation size may exceed the rendered stride*height.
        parse_native_serial(data.replace(b"gop_end=0x803e8000", b"gop_end=0x81000000"))

    def test_high_image_or_runtime_optional_and_physically_bounded(self):
        for high_image, high_reset in ((True, False), (False, True), (True, True)):
            with self.subTest(image=high_image, reset=high_reset):
                result = parse_native_serial(synthetic_transcript(high_image=high_image, high_reset=high_reset))
                self.assertEqual(result["admissions"][-1]["live_ranges"]["runtime_high"], int(high_reset))

    def test_all_eight_admissions_are_checked_with_ordered_retry_witnesses(self):
        data = synthetic_transcript(attempts=8)
        result = parse_native_serial(data)
        self.assertEqual(result["exit_attempts"], 8)
        self.assertEqual([row["memory_map"]["attempt"] for row in result["admissions"]], list(range(1, 9)))
        # Each successful retry may observe a changed free inventory or scratch.
        first, rest = data.split(b"TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY\n", 1)
        parse_native_serial(first.replace(b"free_pages=510000", b"free_pages=509999").replace(b"scratch=0x100000", b"scratch=0x101000")
                            + b"TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY\n" + rest)
        for bad in (synthetic_transcript(attempts=9), data.replace(b"attempt=2", b"attempt=3"),
                    data.replace(b"TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY\n", b"", 1),
                    data.replace(b"tables=6", b"tables=129", 1),
                    data.replace(b"stack_start=0x70000000", b"stack_start=0x6ffe0000", 1)):
            with self.subTest(bad=bad[:90]):
                self.reject(bad)

    def test_retry_cannot_change_stable_ranges_root_reset_or_cpu_width(self):
        data = synthetic_transcript(attempts=2)
        first, second = data.split(b"TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY\n", 1)
        for old, new in ((b"image_start=0x10000000 image_end=0x10100000", b"image_start=0x20000000 image_end=0x20100000"),
                         (b"cr3=0x10020000", b"cr3=0x10021000"),
                         (b"address=0x7f600000", b"address=0x7f601000"),
                         (b"physical_bits=40", b"physical_bits=39")):
            with self.subTest(field=old):
                self.reject(first + b"TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY\n" + second.replace(old, new))

    def test_raw_bounds_types_controls_and_complete_lines(self):
        data = synthetic_transcript()
        for bad in (b"", data[:-1], b"x" * (MAX_SERIAL_BYTES + 1), bytearray(data), "PRIVATE_SENTINEL",
                    data.replace(b"cr3=0x10020000", b"cr3=0x100\x0020000"),
                    data.replace(b"CPU_OWNED", b"CPU_\rOWNED"), data + b"\xff\n",
                    data + b"\x1b]PRIVATE_SENTINEL\x07\n"):
            with self.subTest(kind=type(bad).__name__):
                self.reject(bad)

    def test_firmware_ansi_crlf_and_edge_styling_preserve_raw_hash(self):
        data = synthetic_transcript()
        styled = b"\x1b[2J\x1b[01;01H\x1b[=3hBdsDxe: boot TESSRYN_BOOT_TEST\r\n" + data.replace(b"\n", b"\r\n")
        styled = styled.replace(b"TESSRYN_K01_ENTRY\r\n", b"\x1b[0mTESSRYN_K01_ENTRY\x1b[0m\r\n")
        result = parse_native_serial(styled)
        self.assertEqual(result["serial"]["sha256"], hashlib.sha256(styled).hexdigest())
        self.reject(data.replace(b"CPU_OWNED", b"CPU_\x1b[0mOWNED"))
        # Many bounded edge escapes are consumed in one scan, not repeatedly
        # searched/copied. This is synthetic styling, not native evidence.
        padding = b"\x1b[0m" * 10000
        parse_native_serial(data.replace(b"TESSRYN_K01_PASS\n", padding + b"TESSRYN_K01_PASS" + padding + b"\n"))

    def test_bare_markers_missing_prefixed_duplicate_and_reordered_boots_rejected(self):
        data = synthetic_transcript()
        lines = data.splitlines(keepends=True)
        self.reject(b"\n".join(line.split(b" ")[0] for line in data.splitlines()) + b"\n")
        for index in range(len(lines)):
            with self.subTest(missing=index):
                self.reject(b"".join(lines[:index] + lines[index + 1:]))
            with self.subTest(duplicate=index):
                self.reject(b"".join(lines[:index] + [lines[index]] + lines[index:]))
        for bad in (data + data, b"TESSRYN_K01_PASS\n" + data,
                    data.replace(b"TESSRYN_K01_PASS", b"prefix TESSRYN_K01_PASS"),
                    data.replace(b"TESSRYN_K01_PASS", b"tessryn_k01_pass"),
                    b"".join([lines[0], lines[1], lines[3], lines[2], *lines[4:]])):
            self.reject(bad)

    def test_normal_rejects_fault_panic_reboot_fixture_and_foreign_output(self):
        data = synthetic_transcript()
        for marker in (b"TESSRYN_K01_EXCEPTION vector=3", b"TESSRYN_K01_PANIC PRIVATE_SENTINEL",
                       b"TESSRYN_K01_REBOOT_REQUEST method=uefi-runtime-cold-reset", b"TESSRYN_K01_FAIL PRIVATE_SENTINEL",
                       b"TESSRYN_K01_HIGH_OWNERSHIP_OK scratch=0x100000 pattern=0x5445535352594e01",
                       b"TESSRYN_K01_PAGING_REJECT reason=table-budget", b"TESSRYN_K01_PASSIVE",
                       b"PRIVATE_SENTINEL"):
            with self.subTest(marker=marker):
                self.reject(data.replace(b"TESSRYN_K01_CPU_OWNED", marker + b"\nTESSRYN_K01_CPU_OWNED"))
        self.reject(data + b"TESSRYN_K01_PANIC PRIVATE_SENTINEL\n")
        self.reject(data + b"BdsDxe: starting a second firmware boot\n")
        self.reject(data + b"Linux PRIVATE_SENTINEL\n")
        parse_native_serial(data + b"\n\x1b[0m\r\n")  # Empty terminal styling adds no observation.

    def test_exact_fields_and_bounded_canonical_number_spelling(self):
        data = synthetic_transcript()
        for old, new in ((b"runtime_high=0", b"runtime_high=0 PRIVATE_SENTINEL=x"),
                         (b"runtime_high=0", b"runtime_high=0 runtime_high=0"),
                         (b"runtime_high=0", b"runtime_high=00"),
                         (b"runtime_high=0", b"runtime_high=-1"),
                         (b"runtime_high=0", b"runtime_high="),
                         (b"runtime_high=0", b"runtime_high=999999999999999999999999999999"),
                         (b"image_start=0x10000000", b"image_start=0X10000000"),
                         (b"image_start=0x10000000", b"image_start=0x010000000"),
                         (b"image_start=0x10000000", b"image_start=0x10000000000000000"),
                         (b"tables=6 leaves=2048", b"leaves=2048 tables=6"),
                         (b"tables=6", b"tables=6\t"), (b"tables=6", b"tables=6 ")):
            with self.subTest(field=old, mutation=new):
                self.reject(data.replace(old, new))

    def test_paging_bounds_minimums_guard_and_complete_pool_ownership(self):
        data = synthetic_transcript()
        mutations = ((b"tables=6", b"tables=5"), (b"tables=6", b"tables=129"),
                     (b"leaves=2048", b"leaves=2047"), (b"leaves=2048", b"leaves=16385"),
                     (b"physical_bits=40", b"physical_bits=31"), (b"physical_bits=40", b"physical_bits=53"),
                     (b"guard=0x7fffffe00000", b"guard=0x100000000"),
                     (b"free_scope=low-conventional", b"free_scope=all-memory"),
                     (b"cr3=0x10020000", b"cr3=0x10020001"),
                     (b"cr3=0x10020000", b"cr3=0x100ff000"),
                     (b"image_end=0x10100000", b"image_end=0x10020000"))
        for old, new in mutations:
            with self.subTest(field=old, mutation=new):
                self.reject(data.replace(old, new))
        self.reject(synthetic_transcript(high_image=True).replace(b"physical_bits=40", b"physical_bits=32"))
        self.reject(synthetic_transcript(high_image=True).replace(b"leaves=2049", b"leaves=2048"))
        self.reject(synthetic_transcript(high_image=True).replace(b"tables=7", b"tables=6"))

    def test_unknown_high_runtime_mapping_is_not_a_license_for_impossible_counts(self):
        data = synthetic_transcript()
        # No high runtime ranges: all omitted runtime pages are mapped low,
        # so the exact number of identity leaves/tables is known.
        self.reject(data.replace(b"leaves=2048", b"leaves=2049"))
        self.reject(data.replace(b"tables=6", b"tables=8").replace(b"leaves=2048", b"leaves=2049"))
        self.reject(data.replace(b"runtime_high=0", b"runtime_high=1"))
        high = data.replace(b"runtime_high=0", b"runtime_high=1").replace(b"tables=6", b"tables=7").replace(b"leaves=2048", b"leaves=2049")
        parse_native_serial(high)  # Unknown high runtime descriptor is only an observation.
        self.reject(high.replace(b"physical_bits=40", b"physical_bits=32"))
        self.reject(high.replace(b"tables=7", b"tables=9"))  # One extra leaf permits at most two extra tables.

    def test_live_allocations_exact_lengths_alignment_overlap_and_guard(self):
        data = synthetic_transcript()
        for old, new in ((b"stack_end=0x70020000", b"stack_end=0x70021000"),
                         (b"map_end=0x71010000", b"map_end=0x71011000"),
                         (b"map_start=0x71000000", b"map_start=0x71000001"),
                         (b"image_start=0x10000000", b"image_start=0x0"),
                         (b"image_end=0x10100000", b"image_end=0x10000000"),
                         (b"map_start=0x71000000 map_end=0x71010000", b"map_start=0x70000000 map_end=0x70010000"),
                         (b"image_start=0x10000000 image_end=0x10100000", b"image_start=0x7fffffd00000 image_end=0x7fffffe01000"),
                         (b"image_start=0x10000000 image_end=0x10100000", b"image_start=0x800000000000 image_end=0x800000100000")):
            with self.subTest(field=old, mutation=new):
                self.reject(data.replace(old, new))

    def test_low_scratch_readback_and_final_free_inventory_must_agree(self):
        data = synthetic_transcript()
        for address in (b"0x0", b"0xff000", b"0x100001", b"0x100000000", b"0x10000000", b"0x70000000", b"0x71000000"):
            with self.subTest(address=address):
                self.reject(data.replace(b"scratch=0x100000", b"scratch=" + address))
        self.reject(data.replace(b"MEMORY_OWNERSHIP_OK scratch=0x100000", b"MEMORY_OWNERSHIP_OK scratch=0x101000"))
        self.reject(data.replace(b"MEMORY_OWNERSHIP_OK scratch=0x100000 free_pages=510000", b"MEMORY_OWNERSHIP_OK scratch=0x100000 free_pages=509999"))
        for old, new in ((b"loader=reserved", b"loader=free"), (b"runtime=reserved", b"runtime=free"),
                         (b"firmware=quarantined", b"firmware=free")):
            self.reject(data.replace(old, new))

    def test_runtime_and_memory_inventory_constraints(self):
        data = synthetic_transcript()
        for old, new in ((b"descriptors=104", b"descriptors=0"), (b"descriptors=104", b"descriptors=2"),
                         (b"descriptors=104", b"descriptors=4097"),
                         (b"descriptors=104", b"descriptors=1400"), (b"stride=48", b"stride=32"),
                         (b"stride=48", b"stride=41"), (b"free_pages=510000", b"free_pages=0"),
                         (b"free_pages=510000", b"free_pages=1048577"), (b"runtime_high=0", b"runtime_high=105"),
                         (b"address=0x7f600000", b"address=0x0"), (b"address=0x7f600000", b"address=0x10020000"),
                         (b"address=0x7f600000", b"address=0x70010000"),
                         (b"method=uefi-runtime", b"method=emulator")):
            with self.subTest(field=old, mutation=new):
                self.reject(data.replace(old, new))
        self.reject(synthetic_transcript(high_reset=True).replace(b"runtime_high=1", b"runtime_high=0"))
        self.reject(synthetic_transcript(high_reset=True).replace(b"physical_bits=40", b"physical_bits=32"))
        self.reject(data.replace(b"free_pages=510000", b"free_pages=1048576"))

    def test_cpu_actual_root_instruction_and_stack_bind_final_admission(self):
        data = synthetic_transcript()
        for old, new in ((b"CPU_OWNED cr3=0x10020000", b"CPU_OWNED cr3=0x10021000"),
                         (b"rip=0x10002000", b"rip=0x10100000"), (b"rip=0x10002000", b"rip=0x1000"),
                         (b"rsp=0x7001ff00", b"rsp=0x70020000"), (b"rsp=0x7001ff00", b"rsp=0x7001ff01"),
                         (b"gdt=owned", b"gdt=firmware"), (b"idt=owned", b"idt=firmware"),
                         (b"tss=owned", b"tss=firmware")):
            with self.subTest(field=old, mutation=new):
                self.reject(data.replace(old, new))

    def test_gop_absence_dimensions_format_selection_and_live_span(self):
        headless = synthetic_transcript()
        self.reject(headless.replace(b"gop_end=0x0", b"gop_end=0x1000"))
        self.reject(headless.replace(b"reason=optional-gop", b"reason=PRIVATE_SENTINEL"))
        ready = synthetic_transcript(gop=True)
        for old, new in ((b"TESSRYN ORIGINAL KERNEL\n", b""), (b"width=1280", b"width=79"),
                         (b"height=800", b"height=39"), (b"stride=1280", b"stride=1279"),
                         (b"stride=1280", b"stride=100000"), (b"format=bgrx", b"format=bitmask"),
                         (b"selection=firmware-console", b"selection=arbitrary"),
                         (b"base=0x80000000", b"base=0x80000004"),
                         (b"gop_end=0x803e8000", b"gop_end=0x803e7000"),
                         (b"gop_end=0x803e8000", b"gop_end=0x1000000000000")):
            with self.subTest(field=old, mutation=new):
                self.reject(ready.replace(old, new))
        self.reject(ready.replace(b"0x80000000", b"0x10000000").replace(b"0x803e8000", b"0x103e8000"))

    def test_high_gop_requires_real_leaf_and_table_budget(self):
        data = synthetic_transcript(gop=True).replace(b"0x80000000", b"0x180000000").replace(b"0x803e8000", b"0x1803e8000")
        self.reject(data)
        result = parse_native_serial(data.replace(b"tables=6", b"tables=7").replace(b"leaves=2048", b"leaves=2050"))
        self.assertEqual(result["framebuffer"]["base"], 0x180000000)
        # A hostile declared GOP span is bounded before constructing leaf sets.
        self.reject(data.replace(b"gop_end=0x1803e8000", b"gop_end=0x3000000000"))

    def test_four_level_sparse_mapping_and_canonical_guard_edge(self):
        # SYNTHETIC image in PML4 index1 needs a second PDPT as well as a PD.
        data = synthetic_transcript(high_image=True)
        for old, new in ((b"0x140000000", b"0x8000000000"), (b"0x140100000", b"0x8000100000"),
                         (b"0x140020000", b"0x8000020000"), (b"0x140002000", b"0x8000002000"),
                         (b"physical_bits=40", b"physical_bits=48"), (b"tables=7", b"tables=8")):
            data = data.replace(old, new)
        self.assertEqual(parse_native_serial(data)["admissions"][-1]["paging"]["tables"], 8)
        self.reject(data.replace(b"tables=8", b"tables=7"))
        # A ready GOP may end exactly at GUARD, but no byte or rounded leaf
        # may consume the reserved final2MiB of the lower canonical half.
        data = synthetic_transcript(gop=True).replace(b"0x80000000", f"{GUARD - 4096000:#x}".encode())
        data = data.replace(b"0x803e8000", f"{GUARD:#x}".encode()).replace(b"physical_bits=40", b"physical_bits=48")
        data = data.replace(b"tables=6", b"tables=8").replace(b"leaves=2048", b"leaves=2050")
        self.assertEqual(parse_native_serial(data)["admissions"][-1]["live_ranges"]["gop_end"], GUARD)
        self.reject(data.replace(f"gop_end={GUARD:#x}".encode(), f"gop_end={GUARD + 4:#x}".encode()))


class RetainedLocalQemuSerialTests(unittest.TestCase):
    def test_hash_bound_single_local_qemu_phase_is_parsed_without_native_claim(self):
        directory = ROOT / "evidence/k01-aws-preparation/headless/normal"
        data = (directory / "stdout.log").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), "bed43c16a801d7471bc516565266ded27d21fdd4568f7b4a111231dec37075be")
        result = json.loads((directory / "result.json").read_bytes())
        self.assertEqual(result["scope"], "QEMU TCG q35/OVMF only; native AWS unqualified")
        self.assertEqual(result["phases"], [{"index": 0, "stdout_begin": 0, "stdout_end": 1172},
                                            {"index": 1, "stdout_begin": 1172, "stdout_end": 2344}])
        for phase in result["phases"]:
            with self.subTest(local_qemu_phase=phase["index"]):
                observations = parse_native_serial(data[phase["stdout_begin"]:phase["stdout_end"]])
                self.assertEqual(observations["status"], "parsed")
                self.assertIn("unqualified", observations["scope"])
                self.assertEqual(observations["cpu_owned"]["cr3"], 0x7DDD6000)
                self.assertEqual(observations["admissions"][-1]["memory_map"]["free_pages"], 511455)
        with self.assertRaises(ValueError):
            parse_native_serial(data)  # Two observed boots must never become one acceptance.


if __name__ == "__main__":
    unittest.main()
