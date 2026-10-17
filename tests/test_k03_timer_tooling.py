"""Synthetic wire/file checks do not supply region-service execution evidence."""

import json
import ast
import io
import hashlib
import re
from contextlib import redirect_stderr
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import k03_timer_protocol as protocol
from tools import build_k03_timer as build
from tools import run_k03_timer as runner
from tools import check_k03_timer_host as host
from tools import summarize_k03_timer_failure as failure
from tools import verify_k03_timer as verifier
from tools.k03_timer_provenance import COMPILER_SOURCES, RUNTIME_FILES
from tools import k03_timer_provenance as provenance
from tools.g03.process import ProcessResult


class K03TimerToolingTests(unittest.TestCase):
    def test_host_snapshot_closes_actual_rust_test_module_dependencies(self):
        self.assertIn("scheduler-core/tests.rs", host.SOURCES)
        pending = ["scheduler-core/lib.rs", "tests/preempt_policy_host.rs", "tests/preempt_timer_host.rs"]
        visited = set()
        pattern = re.compile(r"(?P<attrs>(?:#\[[^\]]+\]\s*)*)(?:pub\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;", re.MULTILINE)
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            path = protocol.ROOT / name
            for match in pattern.finditer(path.read_text()):
                override = re.search(r'#\[path\s*=\s*"([^"]+)"\]', match["attrs"])
                child = path.parent / (override[1] if override else match["name"] + ".rs")
                if not child.is_file() and not override:
                    child = path.parent / match["name"] / "mod.rs"
                self.assertTrue(child.is_file(), str(child))
                pending.append(child.resolve().relative_to(protocol.ROOT).as_posix())
        self.assertLessEqual(visited, set(host.SOURCES))

    def test_request_is_exact_little_endian_and_preserves_malformed_fields(self):
        raw = struct.pack("<8sHHIQIIII7Q", b"TESSRGN1", 1, 96, 0, 17, 2, 0,
                          3, 5, 2, 0, 4096, 8192, 0x100004000, 7, 0)
        decoded = protocol.decode_request(raw)
        self.assertEqual(decoded["request_id"], 17)
        self.assertEqual((decoded["capability_slot"], decoded["capability_generation"], decoded["capability_domain"]), (3, 5, 2))
        self.assertEqual((decoded["offset"], decoded["length"], decoded["virtual_address"]), (4096, 8192, 0x100004000))
        invalid = bytearray(raw)
        invalid[8:10] = (2).to_bytes(2, "little")
        self.assertEqual(protocol.decode_request(bytes(invalid))["version"], 2)
        for wrong in (raw[:-1], raw + b"\0", bytearray(raw)):
            with self.subTest(length=len(wrong)), self.assertRaises(ValueError):
                protocol.decode_request(wrong)

    def test_case_descriptor_and_published_contract_agree(self):
        contract = protocol.strict_json(protocol.regular_bytes(protocol.ROOT / protocol.CONTRACT_NAME))
        self.assertEqual(contract["cases"], list(protocol.CASES))
        self.assertEqual(contract["policy_sha256"], protocol.SCHEDULER_SHA256)
        self.assertEqual(protocol.PROFILE["clock_period_fs"], 10_000_000)
        self.assertEqual(protocol.PROFILE["irq_vector"], 32)
        self.assertFalse(protocol.PROFILE["tsc_clock"])
        for index, case in enumerate(protocol.CASES):
            raw = protocol.descriptor_bytes(case)
            self.assertEqual(len(raw), 144)
            self.assertEqual(raw[:16], b"TESSRYN-TIMER1\0\0")
            self.assertEqual(struct.unpack("<16Q", raw[16:]), (1, index, 1, 2, *protocol.ADDRESSES.values(), 96,
                250_000_000, 10_000_000, *protocol.case_limits(case), 128, 3))
            self.assertEqual(protocol.case_flags(case)[-1], 'k03_timer_case="' + case + '"')
        with self.assertRaises(ValueError):
            protocol.case_flags("native_benchmarks")

    def test_strict_json_rejects_duplicate_nonfinite_and_deep_metadata(self):
        for raw in (b'{"status":0,"status":1}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":' + b'['*80 + b'0' + b']'*80 + b'}'):
            with self.subTest(raw=raw[:32]), self.assertRaises(ValueError):
                protocol.strict_json(raw)
        self.assertEqual(protocol.strict_json(b'{"finite":1.5}'), {"finite": 1.5})

    def test_bounded_reader_rejects_file_ancestor_aliases_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "input"
            path.write_bytes(b"retained")
            self.assertEqual(protocol.regular_bytes(path, 8), b"retained")
            with self.assertRaises(ValueError):
                protocol.regular_bytes(path, 7)
            alias = root / "alias"
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                protocol.regular_bytes(alias)
            directory = root / "nested"
            directory.mkdir()
            (directory / "file").write_bytes(b"x")
            alias.unlink()
            alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                protocol.regular_bytes(alias / "file")

    def test_relative_refs_reject_traversal_and_bool_sizes(self):
        for name in ("../file", "/file", "a/../file", "a//file", "a\\file"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                protocol.portable_path(name)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "file").write_bytes(b"x")
            with self.assertRaises(ValueError):
                protocol.read_ref(root, {"path": "file", "sha256": protocol.digest(b"x"), "size_bytes": True})

    def test_coff_binding_rejects_truncated_unrelated_objects(self):
        for raw in (b"", bytes(19), bytes(4096)):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                build.timer_binding(raw, b"MZ", "preemption")

    def test_initial_compiler_probe_failure_retains_bounded_failure_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(build, "fresh_output", return_value=root), \
                    mock.patch.object(build, "source_identity", return_value={}), \
                    mock.patch.object(build, "runtime_hashes", return_value={}), \
                    mock.patch.object(build, "compiler_profile", side_effect=subprocess.TimeoutExpired("private-command", 30)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    build.build(root)
            result = json.loads((root / "build-failure.json").read_text())
            self.assertEqual(result["reason"], "TimeoutExpired")
            self.assertEqual(result["compile"], [])
            self.assertNotIn("private-command", json.dumps(result))
            self.assertIn("private-command", (root / "private-failure.json").read_text())

    def test_initial_host_probe_failure_retains_bounded_failure_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(host, "fresh_output", return_value=root), \
                    mock.patch.object(host, "source_identity", return_value={}), \
                    mock.patch.object(host, "verified_setup", side_effect=subprocess.CalledProcessError(1, "private-command")):
                result = host.check(root)
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["reason"], "CalledProcessError")
            self.assertNotIn("private-command", json.dumps(result))
            self.assertEqual(json.loads((root / "result.json").read_text()), result)

    def test_builder_cli_does_not_print_subprocess_command_or_private_paths(self):
        error = subprocess.CalledProcessError(1, ["/Users/private-workspace/compiler", "private-token"])
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["build_k03_timer.py", "--out", "build/unused"]), \
                mock.patch.object(build, "build", side_effect=error), redirect_stderr(stderr):
            with self.assertRaises(SystemExit):
                build.main()
        self.assertEqual(stderr.getvalue(), "K03 timer build rejected: CalledProcessError\n")

    def test_verifier_output_errors_are_sanitized_without_clobbering_existing_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            out = root / "verification.json"
            command = ["verify_k03_timer.py", "--first", "unused-a", "--second", "unused-b", "--result", "unused-result",
                       "--host-result", "unused-host", "--out", str(out)]
            out.write_bytes(b"existing result must survive")
            stderr = io.StringIO()
            with mock.patch.object(sys, "argv", command), mock.patch.object(verifier, "verify") as check, redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    verifier.main()
            check.assert_not_called()
            self.assertEqual(out.read_bytes(), b"existing result must survive")
            self.assertEqual(stderr.getvalue(), "K03 timer verification rejected: ValueError\n")
            out.unlink()
            stderr = io.StringIO()
            with mock.patch.object(sys, "argv", command), mock.patch.object(verifier, "verify", return_value={}), \
                    mock.patch.object(verifier, "write_json", side_effect=OSError("/Users/private-workspace token")), redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    verifier.main()
            self.assertEqual(stderr.getvalue(), "K03 timer verification rejected: OSError\n")

    def test_execution_requires_opt_in_and_diagnostics_cannot_pass_final_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(runner, "fresh_output", return_value=root), mock.patch.object(runner, "run_bounded") as process:
                result = runner.run(root / "missing-manifest", root, "preemption")
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["execution"]["status"], "unavailable")
            process.assert_not_called()
            for status, capture_only in (("captured", True), ("pass", True), ("fail", False)):
                with self.subTest(status=status, capture_only=capture_only):
                    candidate = {**result, "status": status, "capture_only": capture_only, "reason": runner.PASS_REASON}
                    protocol.write_json(root / "result.json", candidate)
                    with self.assertRaisesRegex(ValueError, "complete acceptance"):
                        verifier.verify_capture(root / "result.json", root / "missing-manifest", {})

    def test_clean_source_gate_binds_every_runtime_file_before_acceptance(self):
        sources = {name: ("100644", protocol.regular_bytes(protocol.ROOT / name) if name == "scheduler-core/lib.rs" else name.encode()) for name in set(COMPILER_SOURCES) | set(RUNTIME_FILES) | {"LICENSE", "NOTICE"}}
        hashed = hashlib.sha256()
        for name, (mode, data) in sorted(sources.items()):
            hashed.update(name.encode() + b"\0" + mode.encode() + b"\0" + protocol.digest(data).encode() + b"\0")
        files = {name: protocol.digest(sources[name][1]) for name in COMPILER_SOURCES}
        runtime = {name: protocol.digest(sources[name][1]) for name in RUNTIME_FILES}
        manifest = {"source": {"revision": "1" * 40, "dirty": False, "tree_sha256": hashed.hexdigest(), "snapshot_algorithm": "git-worktree-v2"},
                    "source_files": files, "source_files_sha256": protocol.digest(provenance.canonical(files).encode()), "runtime_files": runtime,
                    "notices": [{"path": "notices/tessryn-" + name, "sha256": protocol.digest(sources[name][1]), "size_bytes": len(sources[name][1])} for name in ("LICENSE", "NOTICE")]}
        def retained(path, limit):
            return sources[Path(path).relative_to(provenance.ROOT).as_posix()][1]
        with mock.patch.object(provenance, "committed_sources", return_value=sources), mock.patch.object(provenance, "regular_bytes", side_effect=retained):
            self.assertEqual(provenance.validate_source(manifest)["reviewed_runtime_files"], len(RUNTIME_FILES))
            for changed in RUNTIME_FILES:
                def modified(path, limit):
                    name = Path(path).relative_to(provenance.ROOT).as_posix()
                    return sources[name][1] + (b"modified" if name == changed else b"")
                with self.subTest(changed=changed), mock.patch.object(provenance, "regular_bytes", side_effect=modified):
                    with self.assertRaisesRegex(ValueError, "reviewed checkout"):
                        provenance.validate_source(manifest)
            altered = json.loads(json.dumps(manifest))
            altered["source_files"]["kernel/timer_programs.S"] = "f" * 64
            altered["source_files_sha256"] = protocol.digest(provenance.canonical(altered["source_files"]).encode())
            with self.assertRaisesRegex(ValueError, "compiler source"):
                provenance.validate_source(altered)
        altered = json.loads(json.dumps(manifest))
        altered["source"]["dirty"] = True
        with mock.patch.object(provenance, "committed_sources") as git:
            with self.assertRaisesRegex(ValueError, "clean source"):
                provenance.validate_source(altered)
            git.assert_not_called()
        with mock.patch.object(provenance, "git_bytes") as git:
            for revision in ("HEAD", "1" * 39, "1" * 40 + "\nwarning", "A" * 40):
                with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, "complete"):
                    provenance.committed_sources(revision)
            git.assert_not_called()

    def test_runner_pre_and_post_capture_subprocess_failures_keep_original_receipt(self):
        for post_capture in (False, True):
            with self.subTest(post_capture=post_capture), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                out = root / "capture"
                out.mkdir()
                manifest_path = root / "manifest.json"
                manifest_path.write_text("{}")
                qemu = root / "build/toolchain/bin/qemu-system-x86_64"
                qemu.parent.mkdir(parents=True)
                qemu.write_bytes(b"checked emulator fixture")
                setup = {"verified_tools": {"qemu": {"sha256": protocol.digest(qemu.read_bytes())}}, "firmware": {}}
                for role in ("code", "vars"):
                    path = root / "build/uefi" / (role + ".fd")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(role.encode())
                    setup["firmware"][role] = {"path": path.name, "sha256": protocol.digest(path.read_bytes()), "size_bytes": len(role)}
                notice_path = root / "build/uefi/NOTICE"
                notice_path.write_bytes(b"firmware redistribution notice fixture")
                setup["firmware"]["notice"] = {"path": "NOTICE", "sha256": protocol.digest(notice_path.read_bytes()), "size_bytes": notice_path.stat().st_size}
                manifest = {"runtime_files": {}, "source_files": {}, "toolchain": {"setup": setup},
                            "artifacts": [{"case": "preemption", "kind": "boot_disk"}]}
                error = subprocess.TimeoutExpired("private-command", 30, output=b"private-token")
                probes = [setup, error] if post_capture else [error]
                raw = ProcessResult("completed", "synthetic process receipt", 33, 1.25,
                                    b"original captured stdout\n", b"/Users/private-workspace private-token\n")
                with mock.patch.object(runner, "ROOT", root), mock.patch.object(runner, "fresh_output", return_value=out), \
                        mock.patch.object(verifier, "validate_build", return_value=manifest), \
                        mock.patch.object(runner, "runtime_hashes", return_value={}), \
                        mock.patch.object(runner, "validate_toolchain"), \
                        mock.patch.object(runner, "verify_installation", side_effect=probes), \
                        mock.patch.object(runner, "read_ref", return_value=b"disk fixture"), \
                        mock.patch.object(runner, "run_bounded", return_value=raw) as process:
                    result = runner.run(manifest_path, out, "preemption", allow_qemu=True, capture_only=True)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["reason"], "region capture rejected: TimeoutExpired")
                self.assertNotIn("private-command", json.dumps(result))
                self.assertNotIn("private-token", json.dumps(result))
                self.assertEqual(process.call_count, int(post_capture))
                self.assertEqual((out / "stdout.log").read_bytes(), raw.stdout if post_capture else b"")
                self.assertEqual((out / "stderr.log").read_bytes(), raw.stderr if post_capture else b"")
                self.assertEqual(result["execution"]["returncode"], 33 if post_capture else None)
                self.assertEqual(json.loads((out / "result.json").read_text()), result)
                self.assertEqual((out / "private-probe-stdout.log").read_bytes(), b"private-token")
                if post_capture:
                    self.assertEqual((out / "firmware/NOTICE").read_bytes(), notice_path.read_bytes())

    def test_failure_summary_does_not_publish_untrusted_status_or_raw_messages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            case = root / "preemption"
            case.mkdir()
            secret = "/Users/private-workspace token-do-not-publish"
            (case / "result.json").write_text(json.dumps({"status": secret, "reason": secret,
                "execution": {"status": "completed", "returncode": 33, "reason": secret}}))
            (case / "stderr.log").write_text(secret)
            value = failure.summarize(root)
            self.assertNotIn(secret, json.dumps(value))
            self.assertEqual(value["cases"]["preemption"]["capture_status"], "unavailable")
            self.assertEqual(value["cases"]["preemption"]["stderr"]["sha256"], protocol.digest(secret.encode()))

    def test_self_consistent_notice_replacement_cannot_replace_reviewed_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            trusted = root / "trusted"
            trusted.mkdir()
            notices, setup = [], {"rust_notices": {}}
            for component, names in (("tessryn", ("LICENSE", "NOTICE")), ("rust", ("LICENSE-APACHE", "LICENSE-MIT", "COPYRIGHT"))):
                for name in names:
                    data = ("reviewed " + component + " " + name).encode()
                    path = root / "notices" / (component + "-" + name)
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(data)
                    notices.append({"component": component, **protocol.file_ref(root, path)})
                    if component == "tessryn":
                        (trusted / name).write_bytes(data)
                    else:
                        setup["rust_notices"][name] = {"sha256": protocol.digest(data), "size_bytes": len(data)}
            with mock.patch.object(verifier, "ROOT", trusted):
                verifier.validate_notices(root, notices, setup)
                for index, original in enumerate(notices):
                    with self.subTest(path=original["path"]):
                        path = root / original["path"]
                        original_bytes = path.read_bytes()
                        path.write_bytes(b"self-consistently replaced notice")
                        altered = [{**row} for row in notices]
                        altered[index].update(protocol.file_ref(root, path))
                        with self.assertRaisesRegex(ValueError, "origin"):
                            verifier.validate_notices(root, altered, setup)
                        path.write_bytes(original_bytes)

    def test_firmware_notice_is_required_and_bound_to_pinned_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "firmware").mkdir()
            firmware, setup = [], {"firmware": {}}
            for role, name in (("code", "code.fd"), ("vars", "vars.fd"), ("notice", "NOTICE")):
                path = root / "firmware" / name
                path.write_bytes(("pinned " + role).encode())
                row = protocol.file_ref(root, path)
                firmware.append(row)
                setup["firmware"][role] = row.copy()
            verifier.validate_firmware(root, firmware, setup)
            with self.assertRaisesRegex(ValueError, "coverage"):
                verifier.validate_firmware(root, firmware[:2], setup)
            path = root / "firmware/NOTICE"
            path.write_bytes(b"self-consistently replaced firmware notice")
            firmware[-1] = protocol.file_ref(root, path)
            with self.assertRaisesRegex(ValueError, "setup binding"):
                verifier.validate_firmware(root, firmware, setup)

    def test_host_receipts_bind_all_three_suites_and_actual_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source_bytes = {name: ("100644", name.encode()) for name in host.SOURCES}
            source = {"revision": "1" * 40, "dirty": False, "tree_sha256": "2" * 64, "snapshot_algorithm": "git-worktree-v2"}
            shared = {"host": "fixture-host", "rustc": "pinned compiler", "verified_tools": {"fixture": "identity"}}
            setup = {**shared, "g03_lock_sha256": "3" * 64, "g03_record_sha256": "4" * 64}
            manifest = {"source": source, "toolchain": {"setup": {**shared, "base_lock_sha256": "3" * 64, "base_setup_sha256": "4" * 64}}}
            receipts = []
            counts = {"scheduler": 42, "adapter": 17, "driver": 31}
            for role, command in host.normalized_commands().items():
                logs = []
                for stream in ("stdout", "stderr"):
                    path = root / (role + "-" + stream + ".log")
                    data = ("test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n" % counts[role.removesuffix("-tests")]).encode() if role.endswith("-tests") and stream == "stdout" else b""
                    path.write_bytes(data)
                    logs.append(protocol.file_ref(root, path))
                receipts.append({"role": role, "status": "completed", "returncode": 0, "elapsed_seconds": .1,
                                 "command": command, "stdout": logs[0], "stderr": logs[1]})
            result = {"format": host.FORMAT, "status": "pass", "scope": host.SCOPE, "source": source, "toolchain": setup,
                      "tests": counts, "sources": {name: protocol.digest(row[1]) for name, row in source_bytes.items()}, "receipts": receipts}
            path = root / "result.json"
            def check(value):
                protocol.write_json(path, value)
                return verifier.verify_host(path, manifest)
            with mock.patch.object(verifier, "committed_sources", return_value=source_bytes), mock.patch.object(host, "verified_setup", return_value=setup):
                self.assertEqual(check(result)["tests"], counts)
                altered = json.loads(json.dumps(result)); altered["sources"]["tests/preempt_timer_host.rs"] = "f" * 64
                with self.assertRaisesRegex(ValueError, "sources"): check(altered)
                altered = json.loads(json.dumps(result)); altered["receipts"][3]["command"].remove("-Dwarnings")
                with self.assertRaisesRegex(ValueError, "process"): check(altered)
                altered = json.loads(json.dumps(result)); altered["receipts"][-1]["returncode"] = False
                with self.assertRaisesRegex(ValueError, "process"): check(altered)
                (root / "driver-tests-stdout.log").write_bytes(b"test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n")
                altered = json.loads(json.dumps(result)); altered["receipts"][-1]["stdout"] = protocol.file_ref(root, root / "driver-tests-stdout.log")
                with self.assertRaisesRegex(ValueError, "raw test count"): check(altered)

    def test_successful_explicit_ci_inventory_includes_hidden_source_records(self):
        workflow = (protocol.ROOT / ".github/workflows/k03-timer.yml").read_text()
        success = workflow.split("name: k03-timer-single-cpu-evidence", 1)[1].split("retention-days: 14", 1)[0]
        self.assertIn("include-hidden-files: true", success)
        self.assertIn("build/k03-timer/a/sources/.github/workflows/k03-timer.yml", success)
        self.assertIn("build/k03-timer/b/sources/.github/workflows/k03-timer.yml", success)
        prefix = "build/k03-timer/"
        actual = [line.strip().removeprefix(prefix) for line in success.split("path: |", 1)[1].split("if-no-files-found:", 1)[0].splitlines() if line.strip()]
        expected = {"verification.json"}
        for twin in ("a", "b"):
            names = {"manifest.json", "libtessryn_owned_memory.rlib", "libtessryn_scheduler.rlib", "core-stdout.log", "core-stderr.log", "scheduler-stdout.log", "scheduler-stderr.log"}
            names |= {case + "/" + name for case in protocol.CASES for name in ("BOOTX64.EFI", "boot.img", "kernel.obj", case + "-stdout.log", case + "-stderr.log")}
            names |= {"notices/" + name for name in ("tessryn-LICENSE", "tessryn-NOTICE", "rust-LICENSE-APACHE", "rust-LICENSE-MIT", "rust-COPYRIGHT")}
            names |= {"sources/" + name for name in set(COMPILER_SOURCES) | set(RUNTIME_FILES)}
            expected |= {twin + "/" + name for name in names}
        expected |= {case + "/" + name for case in protocol.CASES for name in ("registration.json", "result.json", "stdout.log", "stderr.log", "firmware/code.fd", "firmware/vars.fd", "firmware/NOTICE")}
        expected |= {"host/result.json"} | {"host/" + role + "-" + stream + ".log" for role in host.normalized_commands() for stream in ("stdout", "stderr")}
        self.assertEqual(len(actual), 216)
        self.assertEqual(len(actual), len(set(actual)))
        self.assertEqual(set(actual), expected)
        self.assertIn("--host-result build/k03-timer/host/result.json", workflow)

    def test_runtime_gate_covers_transitive_local_imports_and_package_initializers(self):
        pending = ["tools/" + name + ".py" for name in ("build_k03_timer", "run_k03_timer", "verify_k03_timer", "check_k03_timer_host", "summarize_k03_timer_failure")]
        visited = set()
        def module_files(module):
            parts = module.split(".")
            files = []
            for count in range(1, len(parts) + 1):
                initializer = "/".join(parts[:count]) + "/__init__.py"
                if (protocol.ROOT / initializer).is_file():
                    files.append(initializer)
            filename = "/".join(parts) + ".py"
            if (protocol.ROOT / filename).is_file():
                files.append(filename)
            return files
        while pending:
            filename = pending.pop()
            if filename in visited:
                continue
            visited.add(filename)
            tree = ast.parse((protocol.ROOT / filename).read_text())
            for node in ast.walk(tree):
                modules = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    self.assertEqual(node.level, 0, "relative import requires an explicit closure resolver")
                    if node.module:
                        modules = [node.module, *(node.module + "." + alias.name for alias in node.names)]
                for module in modules:
                    pending.extend(module_files(module))
        self.assertIn("tools/g03/__init__.py", visited)
        self.assertIn("tools/verify_k02_native.py", visited)
        self.assertLessEqual(visited, set(RUNTIME_FILES))


if __name__ == "__main__":
    unittest.main()
