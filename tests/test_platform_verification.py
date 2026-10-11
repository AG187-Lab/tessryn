"""Retained numeric inventories establish collector behavior, not qualification."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"


def module(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


collector = module("collect_platform_inventory")
verifier = module("verify_platform_inventory")


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = self.root / "fixture"
        fixture.mkdir()
        self.report = collector.public_summary(collector.collect(fixture))
        self.digest = hashlib.sha256((TOOLS / "collect_platform_inventory.py").read_bytes()).hexdigest()

    def check(self, report):
        verifier.validate(report, self.digest, "synthetic_fixture")

    def test_numeric_unknown_inventory_and_historical_report(self):
        self.check(self.report)
        historical = json.loads((TOOLS.parent / "evidence/g01-verification/synthetic-public.json").read_text())
        verifier.validate(historical, historical["collector_sha256"], "synthetic_fixture")

    def test_full_and_hidden_identity_reports_are_rejected(self):
        for path in ((), ("cpu",), ("firmware",)):
            report = copy.deepcopy(self.report)
            target = report
            for key in path:
                target = target[key]
            target["private_identity"] = "PRIVATE_HOST"
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.check(report)

    def test_diagnostics_accept_only_fixed_collector_labels(self):
        self.report["diagnostics"] = [{"field": "memory", "reason": "read_limit"}]
        self.check(self.report)
        self.report["diagnostics"][0]["field"] = "private_account_alias"
        with self.assertRaises(ValueError):
            self.check(self.report)

    def test_collector_identity_and_expected_kind_are_bound(self):
        with self.assertRaises(ValueError):
            verifier.validate(self.report, "0" * 64, "synthetic_fixture")
        with self.assertRaises(ValueError):
            verifier.validate(self.report, self.digest, "linux_reference_inventory")

    def test_native_or_measured_claims_and_missing_capabilities_rejected(self):
        variants = []
        report = copy.deepcopy(self.report)
        report["tessryn_capabilities"]["gpu_execution"] = {"status": "available", "value": True}
        variants.append(report)
        report = copy.deepcopy(self.report)
        del report["tessryn_capabilities"]["inference"]
        variants.append(report)
        report = copy.deepcopy(self.report)
        report["measured_admission"] = {"status": "available", "value": 1024}
        variants.append(report)
        report = copy.deepcopy(self.report)
        report["support_status"] = "qualified"
        variants.append(report)
        for report in variants:
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.check(report)

    def test_numeric_types_ranges_and_units_rejected(self):
        for value in (True, -1, 1025, 1 << 80):
            report = copy.deepcopy(self.report)
            report["memory"] = {"status": "available", "reference_os_usable_bytes": value}
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(report)

    def test_non_utc_or_naive_collection_timestamp_rejected(self):
        for value in ("2026-10-11T00:00:00", "2026-10-11T00:00:00+01:00", "not a timestamp"):
            report = copy.deepcopy(self.report)
            report["collected_utc"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(report)

    def test_conflicting_pci_groups_and_duplicate_devices_rejected(self):
        historical = json.loads((TOOLS.parent / "evidence/g01-verification/synthetic-public.json").read_text())
        report = copy.deepcopy(historical)
        report["collector_sha256"] = self.digest
        self.check(report)
        first = report["pci"]["devices"][0]
        second = copy.deepcopy(first)
        second["bdf"] = "0000:01:00.1"
        first["iommu"]["value"]["members"].append(second["bdf"])
        second["iommu"]["value"] = {"group": 8, "members": [second["bdf"]]}
        report["pci"]["devices"].append(second)
        with self.assertRaises(ValueError):
            self.check(report)
        report["pci"]["devices"] = [first, first]
        with self.assertRaises(ValueError):
            self.check(report)

    def test_cli_malformed_deep_duplicate_and_nonregular_inputs_fail_without_echo(self):
        inputs = ["PRIVATE_BAD_JSON", '{"schema_version":1,"schema_version":1}', "[" * 2000 + "]" * 2000]
        for index, content in enumerate(inputs):
            path = self.root / f"bad-{index}.json"
            path.write_text(content)
            with self.subTest(index=index), contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(verifier.main([str(path), "--expected-kind", "synthetic_fixture"]), 1)
                self.assertNotIn("PRIVATE", stderr.getvalue())
                self.assertNotIn(str(self.root), stderr.getvalue())
        regular = self.root / "report.json"
        regular.write_text(json.dumps(self.report))
        link = self.root / "link"
        link.symlink_to(regular)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main([str(path), "--expected-kind", "synthetic_fixture"]), 1)

    def test_cli_hashes_exact_retained_bytes_and_enforces_size_bound(self):
        path = self.root / "report.json"
        path.write_text(json.dumps(self.report))
        expected_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(verifier.main([str(path), "--expected-kind", "synthetic_fixture"]), 0)
        self.assertIn(expected_hash, stdout.getvalue())
        with path.open("wb") as stream:
            stream.truncate(verifier.MAX_BYTES + 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(verifier.main([str(path), "--expected-kind", "synthetic_fixture"]), 1)


if __name__ == "__main__":
    unittest.main()
