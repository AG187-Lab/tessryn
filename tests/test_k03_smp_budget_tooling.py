"""Focused boundary checks for the new budget evidence tooling."""
from __future__ import annotations

import ast
from dataclasses import asdict
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import k03_smp_budget as tooling
from tools import k03_smp_budget_protocol as protocol
from tools.build_k03_smp_user import fault_entry_size


class BudgetToolingTests(unittest.TestCase):
    def test_case_contract_freezes_scheduler_caps_counts_and_uefi_flags(self):
        plan = json.loads((tooling.ROOT / "planning/k03-smp-budget.json").read_bytes())
        self.assertEqual(plan["cases"], {case: asdict(scenario) for case, scenario in protocol.SCENARIOS.items()})
        for index, case in enumerate(protocol.CASES):
            raw = protocol.descriptor_bytes(case); scenario = protocol.SCENARIOS[case]
            self.assertEqual(len(raw), 136); self.assertEqual(raw[:16], b"TESSRYN-SMPBUD1\0")
            self.assertEqual(struct.unpack("<15Q", raw[16:]), (1, index, 2, 1, 67, 3, 16, scenario.cap_ns,
                scenario.quantum_ns, scenario.timer_ns, scenario.rounds, 10_000_000, 20_000_000, 2_000_000_000, 4))
            self.assertIn('smp_user_case="rendezvous"', protocol.case_flags(case))
            self.assertIn(f'smp_budget_case="{case}"', protocol.case_flags(case))
        profile = {"linker": tooling.ROOT / "build/uefi/bin/rust-lld", "toolchain": {"rust_flags": [
            "--crate-name=tessryn_kernel", "--crate-type=bin", "-Clink-arg=/timestamp:0"]}}
        commands = tooling.expected_commands(profile)
        self.assertEqual(list(commands), ["scheduler", "preempt", "late", "fault"])
        self.assertIn("--crate-type=rlib", commands["scheduler"])
        self.assertIn("--crate-name=tessryn_scheduler", commands["scheduler"])
        self.assertNotIn("-Clink-arg=/timestamp:0", commands["scheduler"])
        for case in protocol.CASES:
            self.assertIn("tessryn_scheduler=smp-budget-build/libtessryn_scheduler.rlib", commands[case])
            self.assertEqual(tooling.expected_dependencies()["scheduler"], ["scheduler-core/lib.rs"])
            self.assertNotIn("scheduler-core/lib.rs", tooling.expected_dependencies()[case])

    def test_success_upload_matches_literal_complete_inventory(self):
        text = (tooling.ROOT / ".github/workflows/k03-smp-budget.yml").read_text()
        block = text.split("name: k03-smp-budget-evidence", 1)[1].split("if-no-files-found:", 1)[0]
        paths = [row.strip() for row in block.split("path: |", 1)[1].splitlines() if row.strip()]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(set(paths), {"build/k03-smp-budget/" + name for name in protocol.success_inventory()})
        self.assertEqual(len(paths), 165)
        self.assertIn("include-hidden-files: true", block)
        self.assertIn("if: success()", text)
        self.assertIn("path: build/k03-smp-budget/failure-summary.json", text.split("name: k03-smp-budget-failure-metadata", 1)[1])

    def test_fault_entry_binds_the_marker_rejection_and_the_actual_load_target(self):
        # Entry at page offset 64, failure UD2 at 62, peer load at 40.
        code = bytes.fromhex("66b82b00668ee84c396f0875f1f048ff07ebd5")
        self.assertEqual(fault_entry_size(code, 0, -2, -24), len(code))
        for position in (12, 15, 18):
            changed = bytearray(code)
            changed[position] ^= 1
            with self.subTest(position=position), self.assertRaises(ValueError):
                fault_entry_size(changed, 0, -2, -24)

    def test_reused_python_dependency_closure_is_explicit(self):
        pending = ["tools/k03_smp_budget.py", "tools/check_k03_smp_user_host.py"]
        seen = set()
        while pending:
            name = pending.pop()
            if name in seen: continue
            seen.add(name)
            for node in ast.walk(ast.parse((tooling.ROOT / name).read_bytes())):
                if isinstance(node, ast.Import): modules = [item.name for item in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    modules = [node.module, *(f"{node.module}.{item.name}" for item in node.names)]
                else: continue
                for module in modules:
                    path = Path(*module.split(".")); candidates = [path.with_suffix(".py"), *(base / "__init__.py" for base in path.parents)]
                    pending.extend(p.as_posix() for p in candidates if (tooling.ROOT / p).is_file())
        self.assertLessEqual(seen, set(protocol.RUNTIME_FILES))

    def test_scheduler_archive_must_have_admitted_members(self):
        for raw in (b"", b"!<arch>\n", b"!<thin>\n", b"!<arch>\n" + b"/" * 60):
            with self.subTest(raw=raw[:12]), self.assertRaises(ValueError): tooling._scheduler_archive(raw)

    def test_twin_scheduler_and_boot_artifacts_cannot_be_hardlinked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); manifests = []
            artifacts = [{"path": path, "role": role} for path, role in protocol.artifacts().items()]
            for twin in ("a", "b"):
                base = root / twin; base.mkdir(); manifest = base / "manifest.json"; manifest.write_bytes(b"{}")
                manifests.append(manifest)
                for row in artifacts:
                    path = base / row["path"]; path.parent.mkdir(exist_ok=True); path.write_bytes(b"synthetic retention")
            with mock.patch.object(tooling, "validate_build", return_value={"artifacts": artifacts}), \
                    mock.patch.object(tooling, "validate_source", side_effect=ValueError("past inode gate")):
                with self.assertRaisesRegex(ValueError, "past inode gate"): tooling.verify(*manifests, None, [])
                target = root / "b" / protocol.LIBRARY; target.unlink(); os.link(root / "a" / protocol.LIBRARY, target)
                with self.assertRaisesRegex(ValueError, "independent artifact inodes"): tooling.verify(*manifests, None, [])

    def test_no_execution_without_opt_in_and_capture_only_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp).resolve()
            with mock.patch.object(tooling, "fresh_output", return_value=out), mock.patch.object(tooling, "run_bounded") as launch:
                result = tooling.run(out / "manifest.json", out, "preempt")
            self.assertEqual(result["status"], "fail"); launch.assert_not_called()
            result.update(status="captured", capture_only=True)
            tooling.write_json(out / "result.json", result); tooling.write_json(out / "registration.json", {"timeout_seconds": 30})
            with self.assertRaisesRegex(ValueError, "complete acceptance"): tooling.verify_capture(out / "result.json", out / "manifest.json", {})

    def test_failed_raw_diagnostics_are_never_public_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); out = root / "late"; out.mkdir()
            secret = b"/Users/example/private kernel diagnostics"
            (out / "stdout.log").write_bytes(secret)
            tooling.write_json(out / "result.json", {"execution": {"status": secret.decode(), "returncode": True}})
            summary = tooling.failure_summary(root); row = summary["captures"]["late"]
            self.assertFalse(summary["raw_output_published"])
            self.assertEqual(row["status"], "unavailable"); self.assertIsNone(row["returncode"])
            self.assertEqual(row["logs"][0]["sha256"], tooling.digest(secret))
            self.assertNotIn(secret.decode(), json.dumps(summary))


if __name__ == "__main__": unittest.main()
