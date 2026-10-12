"""Offline archive, failure and provenance checks for the supplemental Rust setup."""

from copy import deepcopy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import setup_k02_toolchain as k02, setup_toolchain as g03


class K02SetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prefix = self.root / "build" / "toolchain"
        self.profile_path = self.root / "planning" / "k02-toolchain.lock.json"
        self.profile_path.parent.mkdir()
        self.lock = json.loads((k02.ROOT / "toolchain.lock.json").read_text())
        self.profile = json.loads(k02.PROFILE.read_text())
        shutil.copyfile(k02.ROOT / "toolchain.lock.json", self.root / "toolchain.lock.json")
        self.host = "aarch64-apple-darwin"
        self.version = "rustc 1.96.0 (ac68faa20 2026-05-25)"
        self.compiler = self.prefix / "bin" / "rustc"
        self.linker = self.prefix / "lib" / "rustlib" / self.host / "bin" / "rust-lld"
        self.target = self.prefix / "lib" / "rustlib" / self.lock["rust"]["target"] / "lib"
        for path in (self.compiler, self.linker, self.target / "libcore-original.rlib",
                     self.prefix / "lib" / "librustc_driver.dylib"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"original:" + path.name.encode())
        for module in (g03, k02):
            for name, value in (("ROOT", self.root), ("PREFIX", self.prefix)):
                mocked = patch.object(module, name, value)
                mocked.start()
                self.addCleanup(mocked.stop)
        for mocked in (patch.object(k02, "PROFILE", self.profile_path),
                       patch.object(g03, "host", return_value=self.host),
                       patch.object(subprocess, "check_output", side_effect=self.compiler_output),
                       patch.object(g03.urllib.request, "urlopen", side_effect=AssertionError("network forbidden"))):
            mocked.start()
            self.addCleanup(mocked.stop)
        self.manifest_dir = self.prefix / "lib" / "rustlib"
        self.write_component("rustc", [self.compiler, self.linker,
                                      self.prefix / "lib" / "librustc_driver.dylib"])
        self.write_component("rust-std-" + self.lock["rust"]["target"],
                             [self.target / "libcore-original.rlib"])
        self.base = g03.installation_identity(
            {"schema_version": 1, "host": self.host, "rustc": self.version}, self.lock)
        self.base_path = self.prefix / "installed.json"
        self.base_path.write_text(json.dumps(self.base))
        self.std = self.prefix / "lib" / "rustlib" / self.host / "lib"
        self.archive = self.make_archive()
        self.profile["rust"]["hosts"][self.host]["sha256"] = g03.sha256(self.archive)
        self.write_profile()

    def compiler_output(self, command, **kwargs):
        self.assertEqual(command[0], str(self.compiler))
        if command[1:] == ["--print", "sysroot"]:
            return str(self.prefix) + "\n"
        if command[1:] == ["--version", "--verbose"]:
            return (self.version + "\nrelease: 1.96.0\ncommit-hash: "
                    + self.lock["rust"]["revision"] + "\nhost: " + self.host + "\n")
        self.assertEqual(command[1:], ["--version"])
        return self.version + "\n"

    def write_profile(self):
        self.profile_path.write_text(json.dumps(self.profile))

    def write_component(self, name, files):
        (self.manifest_dir / ("manifest-" + name)).write_text(
            "".join("file:" + str(path) + "\n" for path in files))
        components = self.manifest_dir / "components"
        names = components.read_text().splitlines() if components.exists() else []
        if name not in names:
            names.append(name)
        components.write_text("\n".join(names) + "\n")
        (self.manifest_dir / "rust-installer-version").write_text("3\n")

    def make_archive(self, name="install.sh", contents=b"fixture installer\n"):
        spec = self.profile["rust"]["hosts"][self.host]
        archive = self.prefix / "downloads" / spec["url"].rsplit("/", 1)[1]
        archive.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive, "w:xz") as output:
            for member_name, data in (("rust-std-fixture/" + name, contents),
                                      ("rust-std-fixture/payload", b"verified host library")):
                member = tarfile.TarInfo(member_name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
        return archive

    def install(self, command):
        self.assertEqual(command[0], "sh")
        source = Path(command[1]).parent
        self.assertEqual((source / "install.sh").read_bytes(), b"fixture installer\n")
        self.assertEqual(command[2:], [f"--prefix={self.prefix}", "--disable-ldconfig"])
        for name in ("core", "std", "test"):
            (self.std / f"lib{name}-host.rlib").write_bytes((source / "payload").read_bytes())
        self.write_component("rust-std-" + self.host,
                             [self.std / f"lib{name}-host.rlib" for name in ("core", "std", "test")])

    def setup(self):
        with patch.object(g03, "run", side_effect=self.install):
            return k02.setup()

    def test_addition_binds_both_receipts_and_preserves_compiler_and_freestanding_core(self):
        result = self.setup()
        refreshed = json.loads(self.base_path.read_text())
        self.assertEqual(refreshed["verified_tools"], self.base["verified_tools"])
        self.assertEqual(refreshed["rust_target_library_tree_sha256"], self.base["rust_target_library_tree_sha256"])
        self.assertNotEqual(refreshed["rust_library_tree_sha256"], self.base["rust_library_tree_sha256"])
        self.assertEqual(result, k02.verified_setup())
        self.assertEqual(result["g03_record_sha256"], g03.sha256(self.base_path))
        self.assertEqual(result["profile_sha256"], g03.sha256(self.profile_path))
        self.assertEqual(result["host_library"]["sha256"], g03.sha256(self.archive))
        self.assertEqual(result["rust_host_library_tree_sha256"], g03.regular_tree_digest(self.std))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_repeated_setup_removes_unverified_host_library_overlay(self):
        self.setup()
        # A coherently recorded prior library overlay must not survive reinstall.
        (self.std / "unneeded.rlib").write_text("extra")
        record = g03.installation_identity(json.loads(self.base_path.read_text()), self.lock)
        self.base_path.write_text(json.dumps(record))
        self.setup()
        self.assertFalse((self.std / "unneeded.rlib").exists())

    def test_malformed_profiles_fail_before_fetch_and_remove_stale_supplemental_success(self):
        mutations = (
            lambda p: p.update(schema_version=True),
            lambda p: p.update(g03_lock_sha256="0" * 64),
            lambda p: p["rust"].update(version="1.95.0"),
            lambda p: p["rust"].update(manifest_sha256="invalid"),
            lambda p: p["rust"].update(hosts=[]),
            lambda p: p["rust"]["hosts"][self.host].update(url="https://example.invalid/std.tar.xz"),
            lambda p: p["rust"]["hosts"][self.host].update(sha256="0" * 63),
            lambda p: p["rust"]["hosts"][self.host].update(unrecognized=True),
        )
        original = deepcopy(self.profile)
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.profile = deepcopy(original)
                mutate(self.profile)
                self.write_profile()
                stale = self.prefix / "k02-installed.json"
                stale.write_text('{"status":"passed"}')
                with patch.object(g03, "fetch") as fetch, self.assertRaises(ValueError):
                    k02.setup()
                fetch.assert_not_called()
                self.assertFalse(stale.exists())
                self.assertEqual(json.loads(self.base_path.read_text()), self.base)

    def test_cached_archive_tamper_cannot_run_installer_or_change_base(self):
        self.archive.write_bytes(b"modified cached archive")
        with patch.object(g03, "run") as install, self.assertRaisesRegex(ValueError, "cached archive hash"):
            k02.setup()
        install.assert_not_called()
        self.assertEqual(json.loads(self.base_path.read_text()), self.base)

    def test_install_failure_invalidates_both_receipts_and_staging_records(self):
        (self.prefix / "k02-installed.json").write_text('{"status":"passed"}')
        with patch.object(g03, "run", side_effect=subprocess.CalledProcessError(1, "installer")):
            with self.assertRaises(subprocess.CalledProcessError):
                k02.setup()
        for name in ("installed.json", "installed.json.tmp", "k02-installed.json", "k02-installed.json.tmp"):
            self.assertFalse((self.prefix / name).exists())

    def test_installer_cannot_refresh_provenance_for_modified_compiler_or_target(self):
        for changed in (self.compiler, self.target / "libcore-original.rlib"):
            with self.subTest(changed=changed):
                def invalid_install(command):
                    self.install(command)
                    changed.write_bytes(b"modified by installer")
                with patch.object(g03, "run", side_effect=invalid_install):
                    with self.assertRaisesRegex(ValueError, "changed G03 compiler or target"):
                        k02.setup()
                self.assertFalse(self.base_path.exists())
                self.assertFalse((self.prefix / "k02-installed.json").exists())
                changed.write_bytes(b"original:" + changed.name.encode())
                self.base = g03.installation_identity(self.base, self.lock)
                self.base_path.write_text(json.dumps(self.base))

    def test_stale_base_receipt_and_libraries_fail_before_compiler_execution(self):
        for changed in (self.compiler, self.target / "libcore-original.rlib",
                        self.prefix / "lib" / "librustc_driver.dylib"):
            with self.subTest(changed=changed):
                original = changed.read_bytes()
                changed.write_bytes(b"tampered")
                with patch.object(subprocess, "check_output") as execute, patch.object(g03, "fetch") as fetch:
                    with self.assertRaisesRegex(ValueError, "does not match|stale"):
                        k02.setup()
                execute.assert_not_called()
                fetch.assert_not_called()
                changed.write_bytes(original)

    def test_verified_setup_rejects_tampered_host_library_and_stale_receipts(self):
        original = self.setup()
        path = self.prefix / "k02-installed.json"
        for field in ("profile_sha256", "g03_record_sha256", "rust_host_library_tree_sha256"):
            mutated = deepcopy(original)
            mutated[field] = "0" * 64
            path.write_text(json.dumps(mutated))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "K02 toolchain receipt"):
                k02.verified_setup()
        path.write_text(json.dumps(original))
        (self.std / "libtest-host.rlib").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "G03 installed library"):
            k02.verified_setup()

    def test_symlinked_download_cannot_write_or_delete_an_external_file(self):
        external = self.root / "unrelated"
        external.write_text("preserved")
        self.archive.unlink()
        self.archive.symlink_to(external)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            k02.setup()
        self.assertEqual(external.read_text(), "preserved")

    def test_missing_base_does_not_follow_a_sibling_download_cache(self):
        self.base_path.unlink()
        sibling = self.root / "sibling-toolchain"
        sibling.mkdir()
        (sibling / "preserved").write_text("unchanged")
        shutil.rmtree(self.prefix / "downloads")
        (self.prefix / "downloads").symlink_to(sibling, target_is_directory=True)
        with patch.object(g03, "setup") as initialize, self.assertRaisesRegex(ValueError, "symbolic links"):
            k02.setup()
        initialize.assert_not_called()
        self.assertEqual((sibling / "preserved").read_text(), "unchanged")

    def test_missing_base_calls_only_the_local_rust_setup(self):
        self.base_path.unlink()
        def initial_setup(**kwargs):
            self.assertEqual(kwargs, {"rust_only": True, "jobs": 1})
            self.assertEqual(g03.ROOT, self.root)
            self.assertEqual(g03.PREFIX, self.prefix)
            self.base_path.write_text(json.dumps(self.base))
        with patch.object(g03, "setup", side_effect=initial_setup) as initialize:
            self.setup()
        initialize.assert_called_once()

    def test_copied_setup_cannot_uninstall_original_checkout_libraries(self):
        self.setup()
        original_library = self.std / "libstd-host.rlib"
        original_bytes = original_library.read_bytes()
        copied_root = self.root / "copied-checkout"
        copied_prefix = copied_root / "build" / "toolchain"
        copied_profile = copied_root / "planning" / "k02-toolchain.lock.json"
        copied_profile.parent.mkdir(parents=True)
        shutil.copyfile(self.root / "toolchain.lock.json", copied_root / "toolchain.lock.json")
        shutil.copyfile(self.profile_path, copied_profile)
        shutil.copytree(self.prefix, copied_prefix)

        def copied_compiler_output(command, **kwargs):
            self.assertEqual(command[0], str(copied_prefix / "bin" / "rustc"))
            if command[1:] == ["--print", "sysroot"]:
                return str(copied_prefix) + "\n"
            if command[1:] == ["--version", "--verbose"]:
                return (self.version + "\nrelease: 1.96.0\ncommit-hash: "
                        + self.lock["rust"]["revision"] + "\nhost: " + self.host + "\n")
            self.assertEqual(command[1:], ["--version"])
            return self.version + "\n"

        with (patch.object(k02, "ROOT", copied_root), patch.object(g03, "ROOT", copied_root),
              patch.object(k02, "PREFIX", copied_prefix), patch.object(g03, "PREFIX", copied_prefix),
              patch.object(k02, "PROFILE", copied_profile),
              patch.object(subprocess, "check_output", side_effect=copied_compiler_output),
              patch.object(g03, "run") as install, patch.object(g03, "fetch") as fetch):
            # The byte-identical receipt and relocatable compiler alone accept
            # this copied setup; its uninstall destinations still name A.
            k02.verify_base_installation(self.lock)
            with self.assertRaisesRegex(ValueError, "outside this setup"):
                k02.setup()
            install.assert_not_called()
            fetch.assert_not_called()
        self.assertEqual(original_library.read_bytes(), original_bytes)

    def test_malformed_uninstall_directives_fail_before_any_installer(self):
        manifest = self.manifest_dir / "manifest-rustc"
        original = manifest.read_text()
        external = self.root / "unrelated-library"
        external.write_bytes(b"preserved")
        invalid = (
            f"file:{external}\n", "file:relative-library\n", f"file:{self.prefix}/../unrelated-library\n",
            f"file:{self.prefix}/./bin/rustc\n", f"unexpected:{self.compiler}\n",
            "file:\n", "malformed\n", f"file:{self.compiler}",
            f"dir:{self.compiler}\n", f"file:{self.prefix / 'lib'}\n", f"dir:{self.prefix}\n",
            f"file:{self.prefix}/bad\\path\n", f"file:{self.compiler}\r\n",
        )
        for entry in invalid:
            with self.subTest(entry=entry):
                manifest.write_text(entry)
                with (patch.object(g03, "run") as install, patch.object(g03, "setup") as initialize,
                      patch.object(g03, "fetch") as fetch, self.assertRaises(ValueError)):
                    k02.setup()
                install.assert_not_called()
                initialize.assert_not_called()
                fetch.assert_not_called()
                self.assertEqual(external.read_bytes(), b"preserved")
        manifest.write_text(original)

    def test_component_traversal_and_legacy_uninstall_metadata_are_rejected(self):
        components = self.manifest_dir / "components"
        original = components.read_text()
        for names in ("../other\n", "rustc\n../other\n", "rustc\nrustc\n", "rustc other\n", "missing\n"):
            with self.subTest(names=names):
                components.write_text(names)
                with patch.object(g03, "run") as install, self.assertRaises(ValueError):
                    k02.setup()
                install.assert_not_called()
        components.write_text(original)
        for directory in (self.manifest_dir, self.prefix / "lib" / "cargo"):
            with self.subTest(directory=directory):
                directory.mkdir(exist_ok=True)
                legacy = directory / "manifest"
                legacy.write_text(str(self.root / "unrelated-library") + "\n")
                # Missing receipts must not send these residual manifests to
                # G03's installers either (its normal reset clears lib first).
                self.base_path.unlink(missing_ok=True)
                with (patch.object(g03, "run") as install, patch.object(g03, "setup") as initialize,
                      self.assertRaisesRegex(ValueError, "legacy Rust installer")):
                    k02.setup()
                install.assert_not_called()
                initialize.assert_not_called()
                legacy.unlink()

    def test_uninstall_metadata_cannot_follow_symlinks_or_special_files(self):
        external = self.root / "unrelated-library"
        external.write_bytes(b"preserved")
        alias = self.prefix / "aliased-library"
        alias.symlink_to(external)
        manifest = self.manifest_dir / "manifest-rustc"
        original = manifest.read_text()
        manifest.write_text(f"file:{alias}\n")
        with patch.object(g03, "run") as install, self.assertRaisesRegex(ValueError, "symbolic links"):
            k02.setup()
        install.assert_not_called()
        self.assertEqual(external.read_bytes(), b"preserved")
        alias.unlink()
        manifest.unlink()
        manifest.symlink_to(external)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            k02.installer_uninstall_preflight()
        manifest.unlink()
        os.mkfifo(manifest)
        with self.assertRaisesRegex(ValueError, "regular files"):
            k02.installer_uninstall_preflight()
        manifest.unlink()
        manifest.write_text(original)


if __name__ == "__main__":
    unittest.main()
