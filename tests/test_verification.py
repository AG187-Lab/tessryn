"""Verify retained fixture evidence independently of emulator execution."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import run_emulator as emulator
import verify_fixture as verifier
from g03.process import ProcessResult
from test_emulator import synthetic_manifest


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RetainedFixtureVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tessryn-verification-test-")
        self.cwd = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.first = self.cwd / "first" / "manifest.json"
        self.second = self.cwd / "second" / "manifest.json"
        self.registration = ROOT / "evidence/fixture-registration.json"
        executable = self.cwd / "mock-qemu"
        executable.write_bytes(b"Synthetic test executor; never launched\n")
        manifest, artifacts = synthetic_manifest(executable.read_bytes())
        for path in (self.first, self.second):
            path.parent.mkdir()
            for name, contents in artifacts.items():
                (path.parent / name).write_bytes(contents)
            path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        version = json.loads((ROOT / "toolchain.lock.json").read_text())["qemu"]["version"]
        process_results = [
            ProcessResult("completed", "exit", 0, 0.01, f"QEMU emulator version {version}\n".encode(), b""),
            ProcessResult("completed", "exit", 33, 0.02, emulator.MARKER + b"\n", b""),
        ]
        self.result_path = self.cwd / "run" / "result.json"
        with patch.object(emulator.shutil, "which", return_value=str(executable)), patch.object(
                emulator, "run_bounded", side_effect=process_results):
            self.result = emulator.run_emulator(self.first, self.registration, self.result_path.parent)

    def verify(self, *, result: bool = True) -> int:
        arguments = ["verify_fixture.py", "--first", str(self.first), "--second", str(self.second),
                     "--registration", str(self.registration)]
        if result:
            arguments.extend(("--result", str(self.result_path)))
        with patch.object(sys, "argv", arguments), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return verifier.main()

    def reject(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            self.verify()
        self.assertEqual(raised.exception.code, 1)

    def save_result(self) -> None:
        self.result_path.write_text(json.dumps(self.result, sort_keys=True) + "\n")

    def test_identical_fresh_builds_and_retained_bundle_are_verified(self) -> None:
        self.assertEqual(self.verify(), 0)

    def test_build_comparison_can_run_without_a_result_bundle(self) -> None:
        self.assertEqual(self.verify(result=False), 0)

    def test_changed_second_artifact_is_rejected(self) -> None:
        (self.second.parent / "hang.rom").write_bytes(b"changed")
        self.reject()

    def test_different_source_identity_is_rejected_even_with_equal_artifact_bytes(self) -> None:
        manifest = json.loads(self.second.read_text())
        manifest["source"]["revision"] = "3" * 40
        self.second.write_text(json.dumps(manifest))
        self.reject()

    def test_matching_incomplete_manifests_are_rejected(self) -> None:
        manifest = json.loads(self.first.read_text())
        manifest.pop("components")
        for path in (self.first, self.second):
            path.write_text(json.dumps(manifest))
        with self.assertRaises(SystemExit) as raised:
            self.verify(result=False)
        self.assertEqual(raised.exception.code, 1)

    def test_semantically_equal_but_different_manifest_bytes_are_rejected(self) -> None:
        manifest = json.loads(self.second.read_text())
        self.second.write_text(json.dumps(manifest, indent=2))
        self.reject()

    def test_changed_retained_log_is_rejected(self) -> None:
        (self.result_path.parent / "stdout.log").write_bytes(b"changed after capture")
        self.reject()

    def test_wrong_input_or_evaluator_bindings_are_rejected(self) -> None:
        original = self.result["bindings"].copy()
        for name in ("artifact_manifest", "registration", "evaluator"):
            with self.subTest(name=name):
                self.result["bindings"] = original.copy()
                self.result["bindings"][name] = "f" * 64
                self.save_result()
                self.reject()

    def test_passing_bundle_requires_the_fixture_exit_code(self) -> None:
        self.result["execution"]["returncode"] = 0
        self.save_result()
        self.reject()

    def test_result_emulator_must_match_pinned_manifest_binary_and_version(self) -> None:
        original = self.result["execution"]["emulator"].copy()
        for key, replacement in (("version", "0.0.0"), ("binary_sha256", "f" * 64)):
            with self.subTest(key=key):
                self.result["execution"]["emulator"] = original.copy()
                self.result["execution"]["emulator"][key] = replacement
                self.save_result()
                self.reject()

    def test_passing_bundle_requires_the_stdout_marker(self) -> None:
        empty = b""
        (self.result_path.parent / "stdout.log").write_bytes(empty)
        for log in self.result["logs"]:
            if log["path"] == "stdout.log":
                log.update(sha256=digest(empty), size_bytes=0)
        self.save_result()
        self.reject()

    def test_symlink_retained_log_is_rejected(self) -> None:
        log = self.result_path.parent / "stdout.log"
        log.rename(self.result_path.parent / "original.log")
        log.symlink_to("original.log")
        self.reject()


if __name__ == "__main__":
    unittest.main()
