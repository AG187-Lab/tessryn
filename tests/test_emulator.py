"""Independent emulator classification/integrity tests with a simulated executor.

These tests establish the host harness contract. They do not run a kernel,
execute an emulator, or provide Tessryn boot/performance evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import run_emulator as emulator
from g03.process import ProcessResult
from fixtures.rom import make_rom
from test_build import elf_fixture


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def synthetic_manifest(qemu_binary: bytes) -> tuple[dict, dict[str, bytes]]:
    """A complete public mock record plus independently constructed original ELF.

    Archived provenance supplies realistic upstream identities only. All local
    source/binary identities here are synthetic and are never native evidence.
    """
    manifest = json.loads((ROOT / "evidence/g03-verification/manifest-a.json").read_text())
    manifest["source"].update(revision="1" * 40, dirty=False, tree_sha256="2" * 64,
                              snapshot_algorithm="git-worktree-v2")
    manifest["components"][0]["revision"] = "1" * 40
    toolchain = manifest["toolchain"]
    toolchain.update(setup_lock_sha256=digest((ROOT / "toolchain.lock.json").read_bytes()),
                     rust_target_library_tree_sha256="3" * 64, rust_library_tree_sha256="4" * 64)
    toolchain["qemu"]["sha256"] = digest(qemu_binary)
    toolchain["qemu_setup"].update(lock_sha256=toolchain["setup_lock_sha256"],
        rust_target_library_tree_sha256=toolchain["rust_target_library_tree_sha256"],
        rust_library_tree_sha256=toolchain["rust_library_tree_sha256"],
        verified_tools={name: {"sha256": toolchain[name]["sha256"]} for name in ("rustc", "rust_lld", "qemu")})
    artifacts = {"pass.rom": make_rom(), "hang.rom": make_rom(hang=True), "rust-probe.elf": elf_fixture()}
    for row in manifest["artifacts"]:
        row.update(sha256=digest(artifacts[row["path"]]), size_bytes=len(artifacts[row["path"]]))
    return manifest, artifacts


class EmulatorHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tessryn-emulator-test-")
        self.cwd = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        # Original ROM and independently constructed ELF test bytes: executor
        # mocks provide no emulator validation or kernel evidence.
        self.manifest = self.cwd / "manifest.json"
        self.registration = self.cwd / "registration.json"
        self.out = self.cwd / "result"
        self.executable = self.cwd / "mock-qemu"
        self.executable.write_bytes(b"Independent executor mock; never launched.\n")
        self.executable.chmod(0o700)
        manifest, artifacts = synthetic_manifest(self.executable.read_bytes())
        for name, data in artifacts.items():
            (self.cwd / name).write_bytes(data)
        self.manifest.write_text(json.dumps(manifest))
        self.registration.write_bytes((ROOT / "evidence/fixture-registration.json").read_bytes())
        version = json.loads((ROOT / "toolchain.lock.json").read_text())["qemu"]["version"]
        self.version_result = ProcessResult(
            "completed", "version process exited", 0, 0.01,
            f"QEMU emulator version {version}\n".encode(), b"",
        )

    def invoke(self, execution: ProcessResult | None = None, **kwargs) -> dict:
        if execution is None:
            execution = ProcessResult("completed", "process exited", 33, 0.02,
                                      emulator.MARKER + b"\n", b"diagnostic\n")
        with patch.object(emulator.shutil, "which", return_value=str(self.executable)), patch.object(
                emulator, "run_bounded", side_effect=[self.version_result, execution]) as runner:
            result = emulator.run_emulator(self.manifest, self.registration, self.out, **kwargs)
            self.calls = runner.call_args_list
        return result

    def assert_logs_match(self, result: dict) -> None:
        for log in result["logs"]:
            data = (self.out / log["path"]).read_bytes()
            self.assertEqual(log["sha256"], digest(data))
            self.assertEqual(log["size_bytes"], len(data))
        self.assertEqual(json.loads((self.out / "result.json").read_text()), result)
        self.assertFalse((self.out / "result.json.tmp").exists())

    def test_pass_is_bound_to_inputs_and_does_not_claim_kernel_capabilities(self) -> None:
        result = self.invoke()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["subject"], "test_fixture")
        self.assertEqual(result["evidence_kind"], "implementation_result")
        self.assertEqual(result["actual_sample_count"], 0)
        self.assertEqual(result["performance"]["status"], "unavailable")
        for capability in ("kernel_boot", "gpu_execution", "inference"):
            self.assertEqual(result["capabilities"][capability]["status"], "unavailable")
        self.assertEqual(result["bindings"]["artifact_manifest"], digest(self.manifest.read_bytes()))
        registration_data = json.loads(self.registration.read_text())
        canonical_registration = json.dumps(registration_data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(result["bindings"]["registration"], digest(canonical_registration))
        self.assertEqual(len(result["bindings"]["evaluator"]), 64)
        self.assertEqual(result["execution"]["emulator"]["binary_sha256"], digest(self.executable.read_bytes()))
        self.assert_logs_match(result)

    def test_fixed_profile_grants_no_disk_network_monitor_or_passthrough_arguments(self) -> None:
        result = self.invoke()
        command = result["execution"]["command"]
        self.assertEqual(command[command.index("-machine") + 1], "pc,accel=tcg")
        self.assertEqual(command[command.index("-monitor") + 1], "none")
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertEqual(command[command.index("-bios") + 1], "pass.rom")
        for forbidden in ("-drive", "-hda", "-hdb", "-fsdev", "-virtfs", "-netdev", "-qmp", "-enable-kvm"):
            self.assertNotIn(forbidden, command)
        self.assertFalse(any("vfio" in argument for argument in command))
        self.assertFalse(any(argument.startswith("/") for argument in command))
        actual_command = self.calls[-1].args[0]
        self.assertEqual(actual_command[0], str(self.executable.resolve()))
        self.assertEqual(actual_command[1:], command[1:])

    def test_pass_requires_expected_exit_and_stdout_marker(self) -> None:
        scenarios = [
            ProcessResult("completed", "exit", 0, 0.02, emulator.MARKER, b""),
            ProcessResult("completed", "exit", 33, 0.02, b"", b""),
            ProcessResult("completed", "exit", 33, 0.02, b"", emulator.MARKER),
        ]
        for number, execution in enumerate(scenarios):
            with self.subTest(number=number):
                self.out = self.cwd / f"scenario-{number}"
                result = self.invoke(execution)
                self.assertEqual(result["status"], "fail")
                self.assert_logs_match(result)

    def test_hang_fixture_cannot_be_classified_as_pass(self) -> None:
        result = self.invoke(fixture="hang")
        self.assertEqual(result["status"], "fail")

    def test_execution_failures_keep_distinct_status_and_raw_logs(self) -> None:
        for status in ("timeout", "cancelled", "log_limit", "unavailable"):
            with self.subTest(status=status):
                self.out = self.cwd / status
                execution = ProcessResult(status, f"explicit {status}", -9, 0.3, b"partial", b"failure")
                result = self.invoke(execution)
                self.assertEqual(result["status"], status)
                self.assertEqual(result["execution"]["reason"], f"explicit {status}")
                self.assertEqual(result["execution"]["elapsed_seconds"], 0.3)
                self.assert_logs_match(result)

    def test_missing_qemu_is_unavailable_after_input_integrity_checks(self) -> None:
        with patch.object(emulator.shutil, "which", return_value=None), patch.object(
                emulator, "run_bounded") as runner:
            result = emulator.run_emulator(self.manifest, self.registration, self.out)
        runner.assert_not_called()
        self.assertEqual(result["status"], "unavailable")
        self.assert_logs_match(result)

    def test_wrong_qemu_version_is_unavailable_and_does_not_execute_image(self) -> None:
        self.version_result = ProcessResult("completed", "exit", 0, 0.01,
                                           b"QEMU emulator version 0.0.0\n", b"")
        result = self.invoke()
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(len(self.calls), 1)
        self.assert_logs_match(result)

    def test_version_probe_failure_retains_bounded_failure_classification(self) -> None:
        for status in ("timeout", "cancelled", "log_limit"):
            with self.subTest(status=status):
                self.out = self.cwd / f"probe-{status}"
                self.version_result = ProcessResult(status, f"version {status}", -9, 0.3, b"partial", b"")
                result = self.invoke()
                self.assertEqual(result["status"], status)
                self.assertEqual(result["execution"]["elapsed_seconds"], 0.3)
                self.assertEqual(result["execution"]["returncode"], -9)
                self.assertEqual(len(self.calls), 1)
                self.assert_logs_match(result)

    def test_version_probe_uses_the_declared_aggregate_log_limit(self) -> None:
        self.invoke(max_log_bytes=128)
        self.assertLessEqual(self.calls[0].args[3], 128)

    def test_changed_artifact_is_rejected_before_qemu_is_considered(self) -> None:
        (self.cwd / "pass.rom").write_bytes(b"changed artifact")
        with patch.object(emulator.shutil, "which") as lookup, patch.object(emulator, "run_bounded") as runner:
            result = emulator.run_emulator(self.manifest, self.registration, self.out)
        lookup.assert_not_called()
        runner.assert_not_called()
        self.assertEqual(result["status"], "fail")
        self.assert_logs_match(result)

    def test_unselected_artifact_is_also_integrity_checked(self) -> None:
        (self.cwd / "hang.rom").write_bytes(b"changed unselected artifact")
        result = self.invoke()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(self.calls), 0)

    def test_incomplete_or_unbound_manifest_is_rejected_before_execution(self) -> None:
        original = json.loads(self.manifest.read_text())
        edits = [
            lambda data: data.pop("source"),
            lambda data: data["source"].pop("revision"),
            lambda data: data["source"].update(snapshot_algorithm="unknown"),
            lambda data: data["toolchain"].pop("rustc"),
            lambda data: data["toolchain"].update(setup_lock_sha256="4" * 64),
            lambda data: data["toolchain"]["qemu_setup"]["verified_tools"].pop("qemu"),
            lambda data: data["toolchain"]["qemu_setup"].update(verified_tools=[]),
            lambda data: data["toolchain"]["qemu_setup"].update(qemu_host_compilers={"host": {"c": 1}}),
            lambda data: data["components"].pop(),
            lambda data: data["components"][1].pop("notices"),
            lambda data: data["components"][1].update(source=1),
            lambda data: data["components"][2].update(archive_sha256="4" * 64),
            lambda data: data["artifacts"].pop(),
            lambda data: data["artifacts"][0].update(role="kernel"),
            lambda data: data["binary_validation"].update(entry_address=0),
            lambda data: data["capabilities"].update(tessryn_kernel_boot="available"),
            lambda data: data["components"][0].update(distribution_requirements="Retain /Users/private/project/LICENSE"),
            lambda data: data["components"][0].update(distribution_requirements="Retain /opt/private/project/LICENSE"),
            lambda data: data["components"][0].update(distribution_requirements=r"Retain (C:\private\project\LICENSE)"),
        ]
        for index, edit in enumerate(edits):
            with self.subTest(index=index):
                data = json.loads(json.dumps(original))
                edit(data)
                self.manifest.write_text(json.dumps(data))
                self.out = self.cwd / f"incomplete-{index}"
                result = self.invoke()
                self.assertEqual(result["status"], "fail")
                self.assertEqual(len(self.calls), 0)
                self.assert_logs_match(result)

    def test_different_emulator_binary_is_rejected_before_version_probe(self) -> None:
        self.executable.write_bytes(b"Different binary with no bound provenance\n")
        result = self.invoke()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(self.calls), 0)
        self.assert_logs_match(result)

    def test_forged_original_rom_is_rejected_even_with_matching_artifact_hash(self) -> None:
        image = bytes(65536)
        (self.cwd / "pass.rom").write_bytes(image)
        manifest = json.loads(self.manifest.read_text())
        manifest["artifacts"][0].update(sha256=digest(image), size_bytes=len(image))
        self.manifest.write_text(json.dumps(manifest))
        result = self.invoke()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(self.calls), 0)
        self.assert_logs_match(result)

    def test_deep_manifest_cli_preserves_rejected_result_and_logs(self) -> None:
        self.manifest.write_text('{"nested":' + '[' * 10000 + '0' + ']' * 10000 + '}')
        execution = subprocess.run([sys.executable, str(ROOT / "tools/run_emulator.py"),
            "--manifest", str(self.manifest), "--registration", str(self.registration), "--out", str(self.out)],
            capture_output=True, timeout=3)
        self.assertEqual(execution.returncode, 1, execution.stderr)
        result = json.loads((self.out / "result.json").read_text())
        self.assertEqual(result["status"], "fail")
        self.assert_logs_match(result)

    def test_kernel_artifact_cannot_enter_the_fixture_harness(self) -> None:
        manifest = json.loads(self.manifest.read_text())
        manifest["artifact_type"] = "kernel"
        self.manifest.write_text(json.dumps(manifest))
        result = self.invoke()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(self.calls), 0)

    def test_artifact_path_escape_is_rejected(self) -> None:
        for number, path in enumerate(("../pass.rom", "/pass.rom", "subdir/pass.rom", "subdir\\pass.rom")):
            with self.subTest(path=path):
                manifest = json.loads(self.manifest.read_text())
                manifest["artifacts"][0]["path"] = path
                self.manifest.write_text(json.dumps(manifest))
                self.out = self.cwd / f"path-{number}"
                result = self.invoke()
                self.assertEqual(result["status"], "fail")
                self.assertEqual(len(self.calls), 0)

    def test_duplicate_artifact_path_is_rejected(self) -> None:
        manifest = json.loads(self.manifest.read_text())
        manifest["artifacts"][1] = manifest["artifacts"][0].copy()
        self.manifest.write_text(json.dumps(manifest))
        result = self.invoke()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(self.calls), 0)

    def test_symlink_manifest_and_symlink_artifact_are_rejected(self) -> None:
        original = self.cwd / "original.json"
        self.manifest.rename(original)
        self.manifest.symlink_to(original.name)
        result = self.invoke()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(self.calls), 0)
        self.manifest.unlink()
        original.rename(self.manifest)
        image = self.cwd / "pass.rom"
        image.rename(self.cwd / "original.rom")
        image.symlink_to("original.rom")
        self.out = self.cwd / "symlink-image"
        result = self.invoke()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(self.calls), 0)

    def test_existing_result_directory_is_never_overwritten(self) -> None:
        self.out.mkdir()
        sentinel = self.out / "result.json"
        sentinel.write_text("previous experiment\n")
        with self.assertRaises(FileExistsError):
            self.invoke()
        self.assertEqual(sentinel.read_text(), "previous experiment\n")

    def test_evaluator_identity_changes_when_published_schema_changes(self) -> None:
        authority = self.cwd / "authority"
        (authority / "tools/g03").mkdir(parents=True)
        (authority / "evidence").mkdir()
        (authority / "fixtures").mkdir()
        for name in ("tools/run_emulator.py", "tools/verify_fixture.py", "tools/build_fixture.py", "tools/setup_toolchain.py", "fixtures/rom.py", "tools/g03/evidence.py", "toolchain.lock.json"):
            (authority / name).write_text("trusted evaluator input\n")
        schema = authority / "evidence/schema-v1.json"
        schema.write_text('{"criteria": "first"}\n')
        with patch.object(emulator, "ROOT", authority), patch.object(
                emulator, "__file__", str(authority / "tools/run_emulator.py")):
            before = emulator.evaluator_hash()
            schema.write_text('{"criteria": "changed"}\n')
            after = emulator.evaluator_hash()
        self.assertNotEqual(before, after, "Published evidence schema must be bound to evaluator identity")

    def test_relative_emulator_path_is_resolved_before_switching_to_scratch(self) -> None:
        execution = ProcessResult("completed", "exit", 33, 0.02, emulator.MARKER + b"\n", b"")
        previous = Path.cwd()
        try:
            os.chdir(self.cwd)
            with patch.object(emulator.shutil, "which", return_value="mock-qemu"), patch.object(
                    emulator, "run_bounded", side_effect=[self.version_result, execution]) as runner:
                result = emulator.run_emulator(self.manifest, self.registration, self.out, qemu="mock-qemu")
            self.assertEqual(result["status"], "pass")
            for call in runner.call_args_list:
                self.assertEqual(call.args[0][0], str(self.executable.resolve()))
                self.assertNotEqual(call.args[1], self.cwd)
        finally:
            os.chdir(previous)

    @unittest.skipUnless(os.name == "posix", "The supported harness uses POSIX signals")
    def test_cli_sigterm_cancels_simulated_emulator_and_persists_result(self) -> None:
        version = json.loads((ROOT / "toolchain.lock.json").read_text())["qemu"]["version"]
        pid_path = self.cwd / "mock.pid"
        self.executable.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, sys, time\n"
            "if '--version' in sys.argv:\n"
            f" print('QEMU emulator version {version}')\n"
            "else:\n"
            f" pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()))\n"
            " print('simulated emulator started', flush=True)\n"
            " time.sleep(60)\n"
        )
        manifest = json.loads(self.manifest.read_text())
        manifest["toolchain"]["qemu"]["sha256"] = digest(self.executable.read_bytes())
        manifest["toolchain"]["qemu_setup"]["verified_tools"]["qemu"]["sha256"] = manifest["toolchain"]["qemu"]["sha256"]
        self.manifest.write_text(json.dumps(manifest))
        wrapper = subprocess.Popen(
            [sys.executable, str(ROOT / "tools/run_emulator.py"),
             "--manifest", str(self.manifest), "--registration", str(self.registration),
             "--out", str(self.out), "--qemu", str(self.executable), "--timeout", "10"],
            cwd=self.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 3
            while not pid_path.exists() and time.monotonic() < deadline:
                if wrapper.poll() is not None:
                    break
                time.sleep(0.01)
            self.assertTrue(pid_path.exists(), "Simulated emulator did not start")
            os.kill(wrapper.pid, signal.SIGTERM)
            stdout, stderr = wrapper.communicate(timeout=3)
            self.assertEqual(wrapper.returncode, 130, (stdout, stderr))
            result = json.loads((self.out / "result.json").read_text())
            self.assertEqual(result["status"], "cancelled")
            self.assertIn(b"simulated emulator started", (self.out / "stdout.log").read_bytes())
            self.assert_logs_match(result)
        finally:
            if wrapper.poll() is None:
                os.killpg(wrapper.pid, signal.SIGKILL)
            wrapper.communicate(timeout=3)
            if pid_path.exists():
                try:
                    os.kill(int(pid_path.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
