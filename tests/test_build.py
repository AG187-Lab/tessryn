"""Failure checks for archive integrity, reset ROM contracts and ELF inspection."""

import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from fixtures.rom import MARKER, make_rom
from tools import build_fixture, setup_toolchain


def elf_fixture(*, dynamic=False, undefined=False, debug=True):
    """Construct a minimal original ELF fixture exercising the public ELF ABI."""
    image = bytearray(0x800)
    names = b"\0.text\0.shstrtab\0.debug_info\0.debug_line\0.symtab\0.strtab\0"
    strings = b"\0fixture_entry\0"
    image[0x100:0x100 + len(names)] = names
    image[0x180:0x180 + len(strings)] = strings
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<16sHHIQQQIHHHHHH", image, 0, ident, 2, 62, 1, 0x100000,
                     64, 0x400, 0, 64, 56, 1, 64, 7, 2)
    struct.pack_into("<IIQQQQQQ", image, 64, 3 if dynamic else 1, 5, 0x80,
                     0x100000, 0x100000, 1, 1, 0x1000)
    image[0x80] = 0xF4
    sections = [
        ("", 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (".text", 1, 6, 0x100000, 0x80, 1, 0, 0, 1, 0),
        (".shstrtab", 3, 0, 0, 0x100, len(names), 0, 0, 1, 0),
        (".debug_info", 1, 0, 0, 0x200, 1 if debug else 0, 0, 0, 1, 0),
        (".debug_line", 1, 0, 0, 0x210, 1, 0, 0, 1, 0),
        (".symtab", 2, 0, 0, 0x300, 48, 6, 1, 8, 24),
        (".strtab", 3, 0, 0, 0x180, len(strings), 0, 0, 1, 0),
    ]
    for index, section in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", image, 0x400 + 64 * index,
                         names.index(section[0].encode()) if section[0] else 0, *section[1:])
    struct.pack_into("<IBBHQQ", image, 0x318, 1, 0x12, 0, 0 if undefined else 1, 0x100000, 1)
    return bytes(image)


class FixtureTests(unittest.TestCase):
    def test_rom_contracts(self):
        image = make_rom()
        self.assertEqual(len(image), 65536)
        self.assertEqual(image[65520:65525], bytes.fromhex("ea 00 00 00 f0"))
        outputs = bytes(image[offset + 1] for offset in range(1, 1 + 4 * len(MARKER), 4))
        self.assertEqual(outputs, MARKER)
        self.assertEqual(image[1 + 4 * len(MARKER):5 + 4 * len(MARKER)], bytes.fromhex("b0 10 e6 f4"))
        self.assertEqual(make_rom(hang=True)[:4], bytes.fromhex("fa f4 eb fd"))
        self.assertNotIn(MARKER, make_rom(hang=True))

    def inspect(self, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "probe.elf"
            path.write_bytes(elf_fixture(**kwargs))
            return build_fixture.inspect_elf(path)

    def test_freestanding_elf(self):
        self.assertEqual(self.inspect()["entry_address"], 0x100000)
        self.assertFalse(self.inspect()["executed"])

    def test_reject_dynamic_loader(self):
        with self.assertRaisesRegex(ValueError, "dynamic loader"):
            self.inspect(dynamic=True)

    def test_reject_undefined_entry(self):
        with self.assertRaisesRegex(ValueError, "undefined symbols"):
            self.inspect(undefined=True)

    def test_require_debug_info(self):
        with self.assertRaisesRegex(ValueError, "DWARF"):
            self.inspect(debug=False)

    def test_reject_truncated_elf(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "probe.elf"
            path.write_bytes(elf_fixture()[:100])
            with self.assertRaisesRegex(ValueError, "table extends"):
                build_fixture.inspect_elf(path)


class ToolchainIntegrityTests(unittest.TestCase):
    def test_exact_qemu_version_with_optional_package_suffix(self):
        for line in ("QEMU emulator version 11.1.2", "QEMU emulator version 11.1.2 (distribution)"):
            self.assertTrue(setup_toolchain.qemu_version_matches(line, "11.1.2"))
        for line in ("QEMU emulator version 11.1.20", "QEMU emulator version 11.1.2-dev", "QEMU emulator version 10.0.0"):
            self.assertFalse(setup_toolchain.qemu_version_matches(line, "11.1.2"))

    def test_absolute_and_parent_archive_roots_rejected_before_cleanup(self):
        for name in ("/absolute/file", "../outside/file", "safe/../../outside"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                prefix = Path(temporary)
                archive = prefix / "tool.tar.xz"
                with tarfile.open(archive, "w:xz") as output:
                    member = tarfile.TarInfo(name)
                    member.size = 1
                    output.addfile(member, io.BytesIO(b"x"))
                with patch.object(setup_toolchain, "PREFIX", prefix), patch.object(setup_toolchain.shutil, "rmtree") as remove:
                    with self.assertRaisesRegex(ValueError, "unsafe path"):
                        setup_toolchain.extract(archive)
                    remove.assert_not_called()

    def test_wrong_cached_hash_rejected_without_fetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            (prefix / "downloads").mkdir()
            (prefix / "downloads" / "tool.tar.xz").write_bytes(b"modified")
            spec = {"url": "https://example.invalid/tool.tar.xz", "sha256": "0" * 64}
            with patch.object(setup_toolchain, "PREFIX", prefix), patch.object(setup_toolchain.urllib.request, "urlopen") as fetch:
                with self.assertRaisesRegex(ValueError, "cached archive hash mismatch"):
                    setup_toolchain.fetch(spec)
                fetch.assert_not_called()

    def test_wrong_download_hash_removes_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            spec = {"url": "https://example.invalid/tool.tar.xz", "sha256": "0" * 64}
            with patch.object(setup_toolchain, "PREFIX", prefix), patch.object(setup_toolchain.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong")):
                with self.assertRaisesRegex(ValueError, "archive hash mismatch"):
                    setup_toolchain.fetch(spec)
            self.assertEqual(list((prefix / "downloads").iterdir()), [])

    def test_staged_extract_rejects_external_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            archive = prefix / "tool.tar.xz"
            with tarfile.open(archive, "w:xz") as output:
                member = tarfile.TarInfo("tool/escape")
                member.type = tarfile.SYMTYPE
                member.linkname = "/outside"
                output.addfile(member)
            with patch.object(setup_toolchain, "PREFIX", prefix):
                with self.assertRaises(tarfile.AbsoluteLinkError):
                    setup_toolchain.extract(archive)
            self.assertEqual(list((prefix / "sources").iterdir()), [])

    def test_unused_edk2_external_link_omitted_and_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            archive = prefix / "tool.tar.xz"
            with tarfile.open(archive, "w:xz") as output:
                member = tarfile.TarInfo("tool/roms/edk2/unused")
                member.type = tarfile.SYMTYPE
                member.linkname = "/outside"
                output.addfile(member)
                readme = tarfile.TarInfo("tool/README")
                readme.size = 4
                output.addfile(readme, io.BytesIO(b"test"))
            with patch.object(setup_toolchain, "PREFIX", prefix):
                root = setup_toolchain.extract(archive)
            metadata = json.loads((root / ".tessryn-extraction.json").read_text())
            self.assertEqual(metadata["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(metadata["omitted_links"], ["tool/roms/edk2/unused"])
            self.assertFalse((root / "roms/edk2/unused").exists())


if __name__ == "__main__":
    unittest.main()
