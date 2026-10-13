"""Exercise UEFI archive provenance and tamper rejection without network access."""

import bz2
from contextlib import ExitStack
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import setup_uefi


def digest(contents):
    return hashlib.sha256(contents).hexdigest()


def firmware_archive(directory, *, broken_descriptor=False, duplicate=False, symbolic=False):
    descriptor = {"interface-types": ["uefi"], "mapping": {
        "device": "flash", "executable": {"filename": "@DATADIR@/code.fd"},
        "nvram-template": {"filename": "@DATADIR@/wrong.fd" if broken_descriptor else "@DATADIR@/vars.fd"}},
        "targets": [{"architecture": "x86_64"}]}
    contents = {"code": b"original firmware code" * 100, "vars": b"\xff" * 1024,
                "notice": b"original upstream notices\n", "descriptor": json.dumps(descriptor).encode()}
    specs = {}
    archive = directory / "qemu.tar.xz"
    with tarfile.open(archive, "w:xz") as output:
        for role, data in contents.items():
            compressed = bz2.compress(data) if role in ("code", "vars") else data
            filename = role + (".fd" if role in ("code", "vars") else ".txt")
            name = "qemu/pc-bios/" + filename + (".bz2" if role in ("code", "vars") else "")
            specs[role] = {"member": name, "archive_member_sha256": digest(compressed),
                           "archive_member_size_bytes": len(compressed),
                           "compression": "bz2" if role in ("code", "vars") else "none",
                           "filename": filename, "sha256": digest(data), "size_bytes": len(data)}
            member = tarfile.TarInfo(name)
            member.size = len(compressed)
            if symbolic and role == "code":
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                output.addfile(member)
            else:
                output.addfile(member, io.BytesIO(compressed))
                if duplicate and role == "code":
                    output.addfile(member, io.BytesIO(compressed))
    firmware = {"archive": {"sha256": setup_uefi.sha256(archive)}, "members": specs}
    return archive, firmware, contents


class FirmwareIntegrityTests(unittest.TestCase):
    def test_verified_archive_recovers_exact_pair_and_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive, firmware, contents = firmware_archive(directory)
            record = setup_uefi.install_firmware(archive, firmware, directory / "firmware")
            self.assertEqual(set(record), {"code", "vars", "notice", "descriptor"})
            for role, original in contents.items():
                self.assertEqual((directory / record[role]["path"]).read_bytes(), original)

    def test_tampered_archive_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive, firmware, _ = firmware_archive(directory)
            archive.write_bytes(archive.read_bytes() + b"modified")
            with self.assertRaisesRegex(ValueError, "archive hash mismatch"):
                setup_uefi.install_firmware(archive, firmware, directory / "firmware")
            self.assertFalse((directory / "firmware").exists())

    def test_compressed_and_decompressed_hashes_are_both_checked(self):
        for field in ("archive_member_sha256", "sha256"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                archive, firmware, _ = firmware_archive(directory)
                firmware["members"]["code"][field] = "0" * 64
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    setup_uefi.install_firmware(archive, firmware, directory / "firmware")

    def test_decompression_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive, firmware, _ = firmware_archive(directory)
            firmware["members"]["code"]["size_bytes"] = 2
            with self.assertRaisesRegex(ValueError, "exceeds bound"):
                setup_uefi.install_firmware(archive, firmware, directory / "firmware")

    def test_descriptor_must_identify_selected_firmware_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive, firmware, _ = firmware_archive(directory, broken_descriptor=True)
            with self.assertRaisesRegex(ValueError, "firmware pair"):
                setup_uefi.install_firmware(archive, firmware, directory / "firmware")

    def test_duplicate_or_symbolic_selected_archive_member_rejected(self):
        for option in ("duplicate", "symbolic"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                archive, firmware, _ = firmware_archive(directory, **{option: True})
                with self.assertRaisesRegex(ValueError, "member type, size or duplication"):
                    setup_uefi.install_firmware(archive, firmware, directory / "firmware")


class SetupIntegrityTests(unittest.TestCase):
    def test_supplied_archive_never_bypasses_hash_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "qemu.tar.xz"
            archive.write_bytes(b"modified source archive")
            with patch.object(setup_uefi.urllib.request, "urlopen") as network:
                with self.assertRaisesRegex(ValueError, "supplied archive hash mismatch"):
                    setup_uefi.fetch({"sha256": "0" * 64}, archive)
                network.assert_not_called()

    def test_mismatched_download_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(setup_uefi, "DOWNLOADS", directory), patch.object(
                    setup_uefi.urllib.request, "urlopen", return_value=io.BytesIO(b"corrupt")):
                with self.assertRaisesRegex(ValueError, "downloaded archive hash mismatch"):
                    setup_uefi.fetch({"url": "https://example.invalid/tool.tar.xz", "sha256": "0" * 64})
            self.assertEqual(list(directory.iterdir()), [])

    def test_rust_archive_path_escape_rejected_before_installer(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive = directory / "rust.tar.xz"
            with tarfile.open(archive, "w:xz") as output:
                member = tarfile.TarInfo("../escape/install.sh")
                member.size = 1
                output.addfile(member, io.BytesIO(b"x"))
            with patch.object(setup_uefi.subprocess, "run") as execute:
                with self.assertRaisesRegex(ValueError, "unsafe path"):
                    setup_uefi.install_target(archive, directory / "prefix", {
                        "target_library": {"sha256": setup_uefi.sha256(archive)}, "notices": {}})
                execute.assert_not_called()

    def test_failed_additive_install_preserves_base_and_previous_uefi_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            base = directory / "base"
            prefix = directory / "uefi"
            (base / "bin").mkdir(parents=True)
            (base / "lib").mkdir()
            (base / "bin" / "rustc").write_bytes(b"verified compiler")
            (base / "lib" / "runtime.so").write_bytes(b"verified runtime")
            prefix.mkdir()
            (prefix / "previous").write_bytes(b"working previous setup")
            base_digest = setup_uefi.regular_tree_digest(base / "lib")
            with ExitStack() as stack:
                stack.enter_context(patch.object(setup_uefi, "BASE_PREFIX", base))
                stack.enter_context(patch.object(setup_uefi, "PREFIX", prefix))
                stack.enter_context(patch.object(setup_uefi, "base_identity", return_value={"rust_library_tree_sha256": base_digest}))
                stack.enter_context(patch.object(setup_uefi, "fetch", return_value=directory / "verified.tar.xz"))
                stack.enter_context(patch.object(setup_uefi, "install_target", side_effect=ValueError("installer failed")))
                with self.assertRaisesRegex(ValueError, "installer failed"):
                    setup_uefi.setup()
            self.assertEqual((prefix / "previous").read_bytes(), b"working previous setup")
            self.assertEqual((base / "bin" / "rustc").read_bytes(), b"verified compiler")
            self.assertEqual(setup_uefi.regular_tree_digest(base / "lib"), base_digest)

    def test_lock_cannot_select_another_rust_or_qemu_release(self):
        base = json.loads(setup_uefi.BASE_LOCK_PATH.read_text())
        original = json.loads(setup_uefi.LOCK_PATH.read_text())
        for component, field in (("rust", "version"), ("firmware", "sha256")):
            lock = copy.deepcopy(original)
            changed = lock["rust"] if component == "rust" else lock["firmware"]["archive"]
            changed[field] = "modified"
            with self.subTest(component=component), self.assertRaises(ValueError):
                setup_uefi.validate_locks(lock, base)

    def test_lock_rejects_firmware_output_path_escape(self):
        base = json.loads(setup_uefi.BASE_LOCK_PATH.read_text())
        lock = json.loads(setup_uefi.LOCK_PATH.read_text())
        lock["firmware"]["members"]["code"]["filename"] = "../outside.fd"
        with self.assertRaisesRegex(ValueError, "unsafe firmware"):
            setup_uefi.validate_locks(lock, base)


if __name__ == "__main__":
    unittest.main()
