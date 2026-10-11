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
    def test_linux_linker_source_placeholder_normalizes_to_upstream(self):
        revision = "1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e"
        linux = f"LLD 22.1.2 (/checkout/src/llvm-project/llvm {revision}) (compatible with GNU linkers)"
        upstream = f"LLD 22.1.2 (https://github.com/rust-lang/llvm-project.git {revision}) (compatible with GNU linkers)"
        self.assertEqual(build_fixture.public_linker_version(linux, revision), upstream)
        self.assertEqual(build_fixture.public_linker_version(upstream, revision), upstream)

    def test_linker_wrong_revision_and_unknown_source_paths_rejected(self):
        revision = "1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e"
        wrong = "0" * 40
        with self.assertRaisesRegex(ValueError, "revision does not match"):
            build_fixture.public_linker_version(
                f"LLD 22.1.2 (/checkout/src/llvm-project/llvm {wrong}) (compatible with GNU linkers)", revision)
        for source in ("/Users/private/llvm", "/opt/llvm", "/checkout/src/other/llvm",
                       "https://example.invalid/llvm-project"):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "unsupported source identity"):
                build_fixture.public_linker_version(
                    f"LLD 22.1.2 ({source} {revision}) (compatible with GNU linkers)", revision)

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
    def make_archive(self, prefix):
        archive = prefix / "tool.tar.xz"
        with tarfile.open(archive, "w:xz") as output:
            member = tarfile.TarInfo("tool/install.sh")
            contents = b"echo original\n"
            member.size = len(contents)
            output.addfile(member, io.BytesIO(contents))
        return archive

    def test_cached_extraction_cannot_reuse_tampered_installer(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            archive = self.make_archive(prefix)
            with patch.object(setup_toolchain, "PREFIX", prefix):
                root = setup_toolchain.extract(archive)
                (root / "install.sh").write_text("echo tampered\n")
                (root / "unexpected.py").write_text("unverified extra module\n")
                extracted = setup_toolchain.extract(archive)
            self.assertEqual((extracted / "install.sh").read_text(), "echo original\n")
            self.assertFalse((extracted / "unexpected.py").exists())

    def test_fresh_setup_products_remove_unverified_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "python-deps"
            directory.mkdir()
            (directory / "unexpected.py").write_text("unverified cached dependency")
            setup_toolchain.fresh_directory(directory)
            self.assertEqual(list(directory.iterdir()), [])

    def test_fresh_setup_product_rejects_external_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            external = prefix / "external"
            external.mkdir()
            (external / "preserved").write_text("original")
            product = prefix / "python-deps"
            product.symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "regular directory"):
                setup_toolchain.fresh_directory(product)
            self.assertEqual((external / "preserved").read_text(), "original")

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


class SetupProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prefix = self.root / "build" / "toolchain"
        self.prefix.mkdir(parents=True)
        self.lock = json.loads((build_fixture.ROOT / "toolchain.lock.json").read_text())
        (self.root / "toolchain.lock.json").write_text(json.dumps(self.lock))
        self.host = "aarch64-apple-darwin"
        self.compiler = self.prefix / "rustc"
        self.linker = self.prefix / "rust-lld"
        self.qemu = self.prefix / "qemu"
        for path in (self.compiler, self.linker, self.qemu):
            path.write_text(path.name)
        libraries = self.prefix / "lib" / "rustlib" / self.lock["rust"]["target"] / "lib"
        libraries.mkdir(parents=True)
        self.core = libraries / "libcore-original.rlib"
        self.core.write_text("original library")
        self.driver = self.prefix / "lib" / "librustc_driver.dylib"
        self.driver.write_text("original compiler driver")
        self.record = {
            "schema_version": 1, "host": self.host,
            "lock_sha256": build_fixture.sha256(self.root / "toolchain.lock.json"),
            "verified_tools": {name: {"sha256": build_fixture.sha256(path)} for name, path in (
                ("rustc", self.compiler), ("rust_lld", self.linker), ("qemu", self.qemu))},
            "rust_target_library_tree_sha256": setup_toolchain.rust_target_library_digest(self.prefix, self.lock["rust"]["target"]),
            "rust_library_tree_sha256": setup_toolchain.regular_tree_digest(self.prefix / "lib"),
            "qemu_extraction": {"archive_sha256": self.lock["qemu"]["sha256"], "omitted_links": []},
            "qemu_configure": self.lock["qemu"]["configure"], "qemu": "QEMU emulator version " + self.lock["qemu"]["version"],
            "ninja": self.lock["ninja"]["version"],
            "qemu_python_build_dependencies": self.lock["qemu_python_build_dependencies"],
            "qemu_host_dependencies": [{"name": "glib-2.0", "version": "fixture"}],
            "qemu_host_compilers": {"host": {"c": {"id": "fixture", "version": "fixture"}}},
        }
        self.record_path = self.prefix / "installed.json"
        self.write_record()
        self.root_patch = patch.object(build_fixture, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def write_record(self):
        self.record_path.write_text(json.dumps(self.record))

    def verify(self):
        return build_fixture.verified_setup(self.lock, self.compiler, self.linker, self.qemu, self.prefix, self.host)

    def test_verified_tools_and_source_record_accepted(self):
        self.assertEqual(self.verify(), self.record)

    def test_version_spoofing_override_cannot_claim_upstream_source(self):
        self.qemu.write_text("#!/bin/sh\necho 'QEMU emulator version 11.1.2'\n")
        with self.assertRaisesRegex(ValueError, "selected qemu"):
            self.verify()

    def test_modified_target_core_rejected(self):
        self.core.write_text("changed core without changing rustc")
        with self.assertRaisesRegex(ValueError, "target libraries"):
            self.verify()

    def test_modified_compiler_runtime_rejected(self):
        self.driver.write_text("changed compiler driver without changing rustc")
        with self.assertRaisesRegex(ValueError, "runtime libraries"):
            self.verify()

    def test_stale_lock_record_rejected(self):
        self.record["lock_sha256"] = "0" * 64
        self.write_record()
        with self.assertRaisesRegex(ValueError, "stale"):
            self.verify()

    def test_missing_verified_record_rejected(self):
        self.record_path.unlink()
        with self.assertRaisesRegex(ValueError, "setup record unavailable"):
            self.verify()

    def test_missing_qemu_source_record_rejected(self):
        del self.record["qemu_extraction"]
        self.write_record()
        with self.assertRaisesRegex(ValueError, "source/configuration"):
            self.verify()

    def test_malformed_record_and_binary_identity_rejected(self):
        for value in ([], {**self.record, "verified_tools": []}):
            with self.subTest(value=value):
                self.record_path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "stale|malformed"):
                    self.verify()

    def test_linked_target_library_rejected(self):
        self.core.unlink()
        self.core.symlink_to(self.driver)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            self.verify()


class SourceSnapshotTests(unittest.TestCase):
    def identity(self, root, names):
        def output(command):
            return "f" * 40 if command[1] == "rev-parse" else "dirty"
        with patch.object(build_fixture, "ROOT", root), patch.object(build_fixture, "command_output", side_effect=output), \
                patch.object(build_fixture.subprocess, "check_output", return_value="\0".join(names).encode() + b"\0"):
            return build_fixture.source_identity()

    def test_executable_mode_changes_source_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "script"
            script.write_text("same bytes")
            script.chmod(0o644)
            first = self.identity(root, ["script"])
            script.chmod(0o755)
            self.assertNotEqual(first, self.identity(root, ["script"]))

    def test_symlink_target_and_referenced_bytes_identified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("first", "second"):
                (root / name).write_text("same bytes")
            link = root / "source"
            link.symlink_to("first")
            first = self.identity(root, ["source"])
            link.unlink()
            link.symlink_to("second")
            second = self.identity(root, ["source"])
            self.assertNotEqual(first, second)
            (root / "second").write_text("changed bytes")
            self.assertNotEqual(second, self.identity(root, ["source"]))

    def test_external_source_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / "repo"
            root.mkdir()
            external = directory / "external"
            external.write_text("private")
            (root / "source").symlink_to(external)
            with self.assertRaisesRegex(ValueError, "within the repository"):
                self.identity(root, ["source"])


if __name__ == "__main__":
    unittest.main()
