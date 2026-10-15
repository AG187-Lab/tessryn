"""Exercise capture ownership and failure publication without expensive emulation."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import build_native_kernel_benchmarks as builder
from tools import run_native_kernel_benchmarks as runner
from tools.g03.process import run_bounded


class NativeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "build").mkdir()
        self.stack = []
        for module in (builder, runner):
            item = patch.object(module, "ROOT", self.root)
            item.start()
            self.stack.append(item)

    def tearDown(self):
        for item in reversed(self.stack):
            item.stop()
        self.temporary.cleanup()

    def output(self, name="attempt"):
        return self.root / "build" / name

    def fake_build(self):
        directory = self.output("built")
        directory.mkdir()
        refs = []
        for name, data in (("sources/tools/run_native_kernel_benchmarks.py", runner.LOADED_SOURCE),
                           ("sources/tools/build_native_kernel_benchmarks.py", builder.LOADED_SOURCE),
                           ("sources/kernel/main.rs", b"captured original source")):
            builder.write_bytes(directory / name, data)
            refs.append(builder.reference(directory / name, directory))
        builder.write_bytes(directory / "profile.json", b"{}")
        artifacts = []
        for name, role in builder.ARTIFACT_ROLES.items():
            builder.write_bytes(directory / name, b"disk" if name == "boot.img" else b"MZfixture")
            artifacts.append({**builder.reference(directory / name, directory), "role": role})
        qemu = self.root / "build/toolchain/bin/qemu-system-x86_64"
        builder.write_bytes(qemu, b"fixture executable")
        firmware = {}
        for name in ("code", "vars"):
            target = self.root / "build/uefi/firmware" / (name + ".fd")
            builder.write_bytes(target, name.encode())
            ref = builder.reference(target, self.root / "build/uefi")
            firmware[name] = {"path": ref["file"], "sha256": ref["sha256"], "size_bytes": ref["size"]}
        setup = {"firmware": firmware, "verified_tools": {"qemu": {"sha256": builder.digest(qemu.read_bytes())}}}
        manifest = {"status": "built", "profile": builder.reference(directory / "profile.json", directory),
                    "sources": refs, "artifacts": artifacts, "notices": [], "compile": [], "toolchain": {"setup": setup}}
        builder.write_json(directory / "manifest.json", manifest)
        return directory / "manifest.json", manifest, setup

    @contextmanager
    def fake_runtime(self, manifest, setup, action, verification=None):
        calls = []
        summary = {"evidence_scope": builder.SCOPE, "native_qualification": False, "clock": "tsc_ticks"}
        def verify(directory, **kwargs):
            calls.append((directory, kwargs))
            return summary if verification is None else verification(directory)
        modules = {"kernel": SimpleNamespace(verify_installation=lambda: setup, make_disk=lambda _: b"disk"),
                   "process": SimpleNamespace(run_bounded=action),
                   "verifier": SimpleNamespace(validate_build=lambda _: manifest, verify_packet=verify)}
        @contextmanager
        def runtime(_):
            yield modules
        with patch.object(runner, "_preflight_build", return_value=manifest), patch.object(builder, "captured_runtime", runtime):
            yield calls

    def completed(self, *args):
        return SimpleNamespace(status="completed", reason="exited", returncode=33,
                               elapsed_seconds=.01, stdout=b"exact guest bytes\n", stderr=b"")

    def test_budgets_reject_bool_nonfinite_and_overflow(self):
        for timeout, log in ((True, 1), (float("nan"), 1), (0, 1), (121, 1), (1, True), (1, 0), (1, (1 << 20) + 1)):
            with self.subTest(timeout=timeout, log=log), self.assertRaises(ValueError):
                builder.budgets(timeout, log)

    def test_optin_and_sixty_second_capture_bound_precede_output(self):
        with self.assertRaises(ValueError):
            runner.run(Path("missing"), self.output())
        with self.assertRaises(ValueError):
            runner.run(Path("missing"), self.output(), allow_qemu=True, timeout=61)
        self.assertFalse(self.output().exists())

    def test_output_is_exclusive(self):
        out = builder.exclusive_directory(self.output())
        builder.write_bytes(out / "sentinel", b"keep")
        with self.assertRaises(FileExistsError):
            builder.exclusive_directory(out)
        self.assertEqual((out / "sentinel").read_bytes(), b"keep")

    def test_symlink_leaf_and_ancestor_refused(self):
        target = self.root / "data"
        target.write_bytes(b"source")
        (self.root / "leaf").symlink_to(target)
        (self.root / "ancestor").symlink_to(self.root, target_is_directory=True)
        for path in (self.root / "leaf", self.root / "ancestor/data"):
            with self.subTest(path=path), self.assertRaises(OSError):
                builder.regular_bytes(path)

    def test_fifo_rejected_without_blocking_open(self):
        path = self.root / "pipe"
        os.mkfifo(path)
        started = time.monotonic()
        with self.assertRaises(ValueError):
            builder.regular_bytes(path)
        self.assertLess(time.monotonic() - started, .5)

    def test_log_redaction_keeps_byte_bound_and_utf8(self):
        for data in (b"/tmp/a", b"/tmp/a\n" * 20, b"/private/work/source.rs:10 error", "é/tmp/a".encode()):
            result = builder.public_log(data)
            self.assertLessEqual(len(result), len(data))
            result.decode("utf-8")
            self.assertNotIn(b"/private/work", result)

    def test_dependency_escape_and_symlink_rejected(self):
        snapshot = self.root / "sources"
        snapshot.mkdir()
        outside = self.root / "outside.rs"
        outside.write_bytes(b"source")
        (snapshot / "link.rs").symlink_to(outside)
        with self.assertRaises(ValueError):
            builder.dependency_paths("artifact: " + str(outside), snapshot, set())
        with self.assertRaises(OSError):
            builder.dependency_paths("artifact: link.rs", snapshot, set())

    def test_malformed_build_is_rejected_before_retention(self):
        source = self.output("malformed")
        source.mkdir()
        (source / "manifest.json").write_bytes(b'{"status":"built","status":"failed"}')
        verifier_path = Path(runner.__file__).parent / "verify_native_kernel_benchmarks.py"
        builder.write_bytes(self.root / "tools/verify_native_kernel_benchmarks.py", verifier_path.read_bytes())
        out = builder.exclusive_directory(self.output())
        with self.assertRaises(ValueError):
            runner._copy_build(source / "manifest.json", out)
        self.assertEqual(list(out.iterdir()), [])

    def test_changed_imported_runner_fails_without_launch(self):
        with patch.object(runner, "LOADED_SOURCE", b"different imported source"):
            result = runner.run(Path("missing"), self.output(), allow_qemu=True)
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["registration_sha256"])
        self.assertEqual(json.loads((self.output() / "run_receipts.json").read_text())["execution"]["status"], "unavailable")

    def test_registration_precedes_child_and_raw_bytes_are_exact(self):
        path, manifest, setup = self.fake_build()
        def child(*args):
            registration = json.loads((self.output() / "registration.json").read_text())
            self.assertEqual(registration["config"], builder.CONFIG)
            self.assertEqual(registration["evidence_scope"], "qemu_guest_microbenchmark")
            self.assertIs(registration["native_qualification"], False)
            command = registration["command"]
            self.assertEqual(command[command.index("-smp") + 1], "1")
            return self.completed()
        with self.fake_runtime(manifest, setup, child) as calls:
            result = runner.run(path, self.output(), allow_qemu=True)
        self.assertTrue(result["valid"])
        self.assertEqual(len(calls), 1)
        self.assertEqual((self.output() / "qemu-stdout.log").read_bytes(), b"exact guest bytes\n")
        self.assertEqual(result["registration_sha256"], builder.digest((self.output() / "registration.json").read_bytes()))

    def test_timeout_and_log_limit_never_publish_success(self):
        for index, program in enumerate(("import time;time.sleep(2)", "print('x'*100000)")):
            path, manifest, setup = self.fake_build()
            out = self.output("failed-" + str(index))
            def child(command, cwd, timeout, limit):
                return run_bounded([sys.executable, "-c", program], cwd, .05, 64)
            with self.fake_runtime(manifest, setup, child) as calls:
                result = runner.run(path, out, allow_qemu=True)
            self.assertFalse(result["valid"])
            self.assertEqual(result["status"], "failed")
            self.assertEqual(calls, [])
            receipt = json.loads((out / "run_receipts.json").read_text())["execution"]
            self.assertIn(receipt["status"], ("timeout", "log_limit"))
            self.assertLessEqual(receipt["stdout"]["size"] + receipt["stderr"]["size"], 64)
            # Each attempt gets a fresh build and output; existing evidence is kept.
            if index == 0:
                for file in sorted(path.parent.rglob("*"), reverse=True):
                    if file.is_file():
                        file.unlink()
                    elif file.is_dir():
                        file.rmdir()
                path.parent.rmdir()
                for file in (self.root / "build/toolchain", self.root / "build/uefi"):
                    import shutil
                    shutil.rmtree(file)

    def test_retained_source_mutation_invalidates_completed_capture(self):
        path, manifest, setup = self.fake_build()
        def child(*args):
            source = self.output() / "build/sources/kernel/main.rs"
            source.chmod(0o644)
            source.write_bytes(b"changed")
            return self.completed()
        with self.fake_runtime(manifest, setup, child) as calls:
            result = runner.run(path, self.output(), allow_qemu=True)
        self.assertFalse(result["valid"])
        self.assertEqual(calls, [])
        self.assertIn("changed", result["reason"])

    def test_current_runner_must_equal_build_source(self):
        path, manifest, setup = self.fake_build()
        source = path.parent / "sources/tools/run_native_kernel_benchmarks.py"
        source.write_bytes(b"older runner")
        for ref in manifest["sources"]:
            if ref["file"] == "sources/tools/run_native_kernel_benchmarks.py":
                ref.update(builder.reference(source, path.parent))
        path.unlink()
        builder.write_json(path, manifest)
        with self.fake_runtime(manifest, setup, self.completed) as calls:
            result = runner.run(path, self.output(), allow_qemu=True)
        self.assertFalse(result["valid"])
        self.assertIn("differ", result["reason"])
        self.assertEqual(calls, [])

    def test_self_consistent_foreign_helpers_cannot_execute_on_host(self):
        path, manifest, _ = self.fake_build()
        checkout = Path(builder.__file__).resolve().parents[1]
        runtime_sources = [name for name in builder.SOURCE_FILES if name.endswith(".py")]
        refs = {row["file"]: row for row in manifest["sources"]}
        for name in runtime_sources:
            data = (checkout / name).read_bytes()
            current, retained = self.root / name, path.parent / "sources" / name
            builder.write_bytes(current, data)
            if not retained.exists():
                builder.write_bytes(retained, data)
            refs["sources/" + name] = builder.reference(retained, path.parent)
        manifest["sources"] = list(refs.values())
        # The existing runner/builder checks already cover those entry points.
        # Every remaining helper must reject before any retained module imports.
        for index, name in enumerate(runtime_sources):
            if name in {"tools/run_native_kernel_benchmarks.py", "tools/build_native_kernel_benchmarks.py"}:
                continue
            retained = path.parent / "sources" / name
            original = retained.read_bytes()
            retained.write_bytes(b'raise AssertionError("foreign host helper executed")\n')
            refs["sources/" + name].update(builder.reference(retained, path.parent))
            path.unlink()
            builder.write_json(path, manifest)
            out = self.output("foreign-helper-" + str(index))
            with self.subTest(helper=name), patch.object(runner, "_preflight_build", return_value=manifest):
                result = runner.run(path, out, allow_qemu=True)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["valid"])
                self.assertIn("retained runtime source differs", result["reason"])
                self.assertIsNone(result["registration_sha256"])
                receipt = json.loads((out / "run_receipts.json").read_text())["execution"]
                self.assertEqual(receipt["status"], "unavailable")
            retained.write_bytes(original)
            refs["sources/" + name].update(builder.reference(retained, path.parent))

    def test_compiler_probe_subprocess_failures_publish_failed_manifest(self):
        source = self.root / "tools/build_native_kernel_benchmarks.py"
        builder.write_bytes(source, builder.LOADED_SOURCE)
        builder.write_bytes(self.root / builder.PROFILE_FILE, b"{}")
        scheduler = self.root / "build/native-inputs/scheduler-core.rs"
        builder.write_bytes(scheduler, b"scheduler fixture")
        errors = (subprocess.TimeoutExpired(["rustc", "--version"], 30),
                  subprocess.CalledProcessError(1, ["rustc", "--version"]))
        for index, error in enumerate(errors):
            @contextmanager
            def runtime(_):
                def probe():
                    raise error
                yield {"verifier": SimpleNamespace(validate_profile=lambda _: None),
                       "kernel": SimpleNamespace(compiler_profile=probe)}
            out = self.output("failed-build-" + str(index))
            with patch.object(builder, "SOURCE_FILES", ("tools/build_native_kernel_benchmarks.py", builder.PROFILE_FILE)), \
                    patch.object(builder, "SCHEDULER_SHA256", builder.digest(scheduler.read_bytes())), \
                    patch.object(builder, "captured_runtime", runtime):
                manifest = builder.build(out, scheduler)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["compile"], [])
            self.assertEqual(manifest["artifacts"], [])
            self.assertIn(type(error).__name__, manifest["reason"])
            self.assertEqual(json.loads((out / "manifest.json").read_text()), manifest)

    def test_setup_probe_subprocess_failures_publish_failed_run_receipts(self):
        path, manifest, setup = self.fake_build()
        errors = (subprocess.TimeoutExpired(["rustc", "--version"], 30),
                  subprocess.CalledProcessError(1, ["rustc", "--version"]))
        for index, error in enumerate(errors):
            launched = []
            verified = []
            @contextmanager
            def runtime(_):
                def probe():
                    raise error
                yield {"verifier": SimpleNamespace(validate_build=lambda _: manifest,
                                                    verify_packet=lambda *a, **k: verified.append(a)),
                       "kernel": SimpleNamespace(verify_installation=probe),
                       "process": SimpleNamespace(run_bounded=lambda *a: launched.append(a))}
            out = self.output("failed-probe-" + str(index))
            with patch.object(runner, "_preflight_build", return_value=manifest), \
                    patch.object(builder, "captured_runtime", runtime):
                result = runner.run(path, out, allow_qemu=True)
            self.assertEqual(result["status"], "failed")
            self.assertIs(result["valid"], False)
            self.assertIsNone(result["summary"])
            self.assertIsNone(result["registration_sha256"])
            self.assertEqual(launched, [])
            self.assertEqual(verified, [])
            self.assertIn(type(error).__name__, result["reason"])
            receipt = json.loads((out / "run_receipts.json").read_text())["execution"]
            self.assertEqual(receipt["status"], "unavailable")
            self.assertIsNone(receipt["returncode"])
            self.assertEqual(receipt["stdout"]["size"] + receipt["stderr"]["size"], 0)
            self.assertEqual(json.loads((out / "result.json").read_text()), result)

    def test_postcapture_probe_failure_keeps_raw_receipt_and_invalidates_run(self):
        path, manifest, setup = self.fake_build()
        errors = (subprocess.TimeoutExpired(["rustc", "--version"], 30),
                  subprocess.CalledProcessError(1, ["rustc", "--version"]))
        for index, error in enumerate(errors):
            probe_calls = []
            verified = []
            @contextmanager
            def runtime(_):
                def probe():
                    probe_calls.append(True)
                    if len(probe_calls) == 2:
                        raise error
                    return setup
                yield {"verifier": SimpleNamespace(validate_build=lambda _: manifest,
                                                    verify_packet=lambda *a, **k: verified.append(a)),
                       "kernel": SimpleNamespace(verify_installation=probe, make_disk=lambda _: b"disk"),
                       "process": SimpleNamespace(run_bounded=self.completed)}
            out = self.output("failed-postprobe-" + str(index))
            with patch.object(runner, "_preflight_build", return_value=manifest), \
                    patch.object(builder, "captured_runtime", runtime):
                result = runner.run(path, out, allow_qemu=True)
            self.assertEqual(len(probe_calls), 2)
            self.assertEqual(result["status"], "failed")
            self.assertIs(result["valid"], False)
            self.assertIsNone(result["summary"])
            self.assertIsNotNone(result["registration_sha256"])
            self.assertEqual(verified, [])
            self.assertIn(type(error).__name__, result["reason"])
            receipt = json.loads((out / "run_receipts.json").read_text())["execution"]
            self.assertEqual(receipt["status"], "completed")
            self.assertEqual(receipt["returncode"], 33)
            self.assertEqual((out / "qemu-stdout.log").read_bytes(), b"exact guest bytes\n")
            self.assertEqual(json.loads((out / "result.json").read_text()), result)


if __name__ == "__main__":
    unittest.main()
