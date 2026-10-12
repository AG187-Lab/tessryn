"""SYNTHETIC termination receipts; no native AWS execution evidence.

The full intake fixtures mock media/readback and reuse retained local QEMU
serial. The new controls are original resolved request fields, not evidence
that a guest shut down or that a provider completed resource cleanup.
"""
import copy
import importlib.machinery
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest

from tools import verify_aws_native as verifier


ROOT = Path(__file__).resolve().parents[1]
fixture_path = ROOT / "tests/test_aws_native.py"
fixtures = types.ModuleType("native_force_public_fixtures")
fixtures.__file__ = str(fixture_path)
fixtures.__package__ = ""
fixtures.__spec__ = importlib.machinery.ModuleSpec(fixtures.__name__, None, origin=str(fixture_path))
sys.modules[fixtures.__name__] = fixtures
exec(compile(fixture_path.read_bytes(), str(fixture_path), "exec", dont_inherit=True), fixtures.__dict__)


class NativeForceTerminationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tessryn-synthetic-native-force-")
        self.addCleanup(self.temp.cleanup)
        self.bundle = fixtures.SyntheticCaptureBundle(Path(self.temp.name))

    def force(self, label):
        alias = label + "_terminate"
        row = self.bundle.index["captures"][alias]
        row["request"].update(Force=True, SkipOsShutdown=True)
        row["format"] = "boto3_json"
        row["tool_version"] = "boto3/1.43.111 botocore/1.43.111 synthetic fixture"
        self.bundle.responses[alias]["ResponseMetadata"] = {"HTTPStatusCode": 200}
        self.bundle.update(alias)
        return row

    def reject_request(self):
        with self.assertRaisesRegex(ValueError, "termination identity or order differs"):
            self.bundle.verify()

    def test_existing_ids_only_receipts_for_all_three_phases_remain_valid(self):
        original = copy.deepcopy(self.bundle.index["captures"])
        result = self.bundle.verify()
        self.assertEqual(result["status"], "needs_owner_review")
        for label in ("a", "r", "b"):
            alias = label + "_terminate"
            self.assertEqual(self.bundle.index["captures"][alias], original[alias])
            self.assertEqual(set(original[alias]["request"]), {"InstanceIds"})

    def test_exact_native_sdk_flags_preserve_original_receipts_and_owner_review(self):
        rows = {label: self.force(label) for label in ("a", "b")}
        original = copy.deepcopy(rows)
        raw = {label: (self.bundle.root / row["response"]["path"]).read_bytes()
               for label, row in rows.items()}
        result = self.bundle.verify()
        self.assertEqual(result["status"], "needs_owner_review")
        self.assertEqual(result["capture_origin"], "unverified_offline")
        self.assertEqual(result["capture_kind"], "synthetic_fixture")
        self.assertEqual([x["role"] for x in result["phases"]], ["native_a", "recovery", "native_b"])
        self.assertEqual(set(self.bundle.index["captures"]["r_terminate"]["request"]), {"InstanceIds"})
        captures = verifier.CaptureSet(self.bundle.index_path, self.bundle.index)
        for label, row in rows.items():
            selected = captures.take(label + "_terminate", "TerminateInstances")
            self.assertEqual(selected.request, original[label]["request"])
            self.assertIs(selected.request["Force"], True)
            self.assertIs(selected.request["SkipOsShutdown"], True)
            self.assertEqual(row, original[label])
            self.assertEqual((self.bundle.root / row["response"]["path"]).read_bytes(), raw[label])
        encoded = json.dumps(result)
        for private in (fixtures.ACCOUNT, fixtures.AMI, fixtures.SNAPSHOT, fixtures.NONCE,
                        rows["a"]["request"]["InstanceIds"][0]):
            self.assertNotIn(private, encoded)

    def test_each_native_phase_can_independently_use_the_exact_pair(self):
        for label in ("a", "b"):
            with self.subTest(phase=label):
                row = self.force(label)
                self.assertEqual(self.bundle.verify()["evidence_consistency"], "pass")
                row["request"] = {"InstanceIds": row["request"]["InstanceIds"]}

    def test_native_flags_reject_false_integers_strings_missing_or_extra_keys(self):
        for label in ("a", "b"):
            row = self.bundle.index["captures"][label + "_terminate"]
            ordinary = copy.deepcopy(row["request"])
            bad_flags = [{"Force": True}, {"SkipOsShutdown": True},
                         {"Force": True, "SkipOsShutdown": True, "DryRun": False},
                         {"Force": True, "SkipOsShutdown": True, "PRIVATE_UNKNOWN": "PRIVATE_SENTINEL"}]
            for field in ("Force", "SkipOsShutdown"):
                for bad in (False, 0, 1, "true", None, [], {}):
                    pair = {"Force": True, "SkipOsShutdown": True}
                    pair[field] = bad
                    bad_flags.append(pair)
            for flags in bad_flags:
                with self.subTest(phase=label, flags=flags):
                    row["request"] = ordinary | flags
                    self.reject_request()
            row["request"] = ordinary

    def test_recovery_refuses_native_controls_even_when_both_are_true(self):
        row = self.bundle.index["captures"]["r_terminate"]
        ordinary = copy.deepcopy(row["request"])
        for flags in ({"Force": True, "SkipOsShutdown": True}, {"Force": True},
                      {"SkipOsShutdown": True}, {"Force": False, "SkipOsShutdown": False},
                      {"DryRun": False}):
            with self.subTest(flags=flags):
                row["request"] = ordinary | flags
                self.reject_request()
        row["request"] = ordinary
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_forced_controls_require_the_same_single_bound_instance(self):
        for label in ("a", "b"):
            row = self.force(label)
            original = row["request"]["InstanceIds"]
            other = "i-000000000000000ff"
            for ids in ([], [other], [original[0], other], original * 2, original[0], None, [True]):
                with self.subTest(phase=label, ids=ids):
                    row["request"]["InstanceIds"] = ids
                    self.reject_request()
            row["request"]["InstanceIds"] = original

    def test_forced_controls_do_not_bypass_acknowledgement_or_terminated_state(self):
        self.force("a")
        transition = self.bundle.responses["a_terminate"]["TerminatingInstances"][0]
        original = copy.deepcopy(transition)
        transition["InstanceId"] = "i-000000000000000ff"
        self.bundle.update("a_terminate")
        with self.assertRaisesRegex(ValueError, "external termination was not acknowledged"):
            self.bundle.verify()
        transition.clear()
        transition.update(original)
        transition["CurrentState"] = {"Code": 16, "Name": "running"}
        self.bundle.update("a_terminate")
        with self.assertRaisesRegex(ValueError, "external termination was not acknowledged"):
            self.bundle.verify()
        transition.clear()
        transition.update(original)
        self.bundle.update("a_terminate")
        final = self.bundle.responses["a_terminated"]["Reservations"][0]["Instances"][0]
        final["State"] = {"Code": 32, "Name": "shutting-down"}
        self.bundle.update("a_terminated")
        with self.assertRaisesRegex(ValueError, "instance termination is unconfirmed"):
            self.bundle.verify()

    def test_forced_controls_preserve_console_order_and_actual_resource_absence(self):
        row = self.force("a")
        original_start = row["started_at"]
        row["started_at"] = self.bundle.index["captures"]["a_console"]["started_at"]
        self.reject_request()
        row["started_at"] = original_start
        recycled = self.bundle.responses["a_volume_recycle_absent"]
        recycled["Volumes"] = [{"VolumeId": self.bundle.index["captures"]["a_root"]["request"]["VolumeIds"][0]}]
        self.bundle.update("a_volume_recycle_absent")
        with self.assertRaisesRegex(ValueError, "volume Recycle Bin absence is unconfirmed"):
            self.bundle.verify()


if __name__ == "__main__":
    unittest.main()
