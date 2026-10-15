"""SYNTHETIC snapshot Recycle Bin parsing; no AWS execution evidence.

Receipts and resource IDs are constructed in temporary directories. Full-intake
cases reuse the public SyntheticCaptureBundle and retained local QEMU serial;
media and snapshot readback are explicitly mocked. Only error transport,
ownership joins, cleanup ordering and sanitized review output are tested.
"""
from datetime import timedelta
import importlib.machinery
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from tools import verify_aws_native as verifier
from tools import aws_native_snapshot

ROOT = Path(__file__).resolve().parents[1]
fixture_path = ROOT / "tests/test_aws_native.py"
fixtures = types.ModuleType("snapshot_recycle_public_fixtures")
fixtures.__file__ = str(fixture_path)
fixtures.__package__ = ""
fixtures.__spec__ = importlib.machinery.ModuleSpec(fixtures.__name__, None, origin=str(fixture_path))
sys.modules[fixtures.__name__] = fixtures
exec(compile(fixture_path.read_bytes(), str(fixture_path), "exec", dont_inherit=True), fixtures.__dict__)

SNAPSHOT = fixtures.SNAPSHOT
OTHER = "snap-00000000000000099"
ACCOUNT = fixtures.ACCOUNT
BASE = fixtures.BASE
ALIAS = "snapshot_recycle_absent"
REQUEST_ID = "SYNTHETIC_SNAPSHOT_REQUEST_ID"


def error_response():
    return {"Error": {"Code": "InvalidSnapshot.NotFound",
                       "Message": f"The snapshot '{SNAPSHOT}' does not exist."},
            "ResponseMetadata": {"HTTPStatusCode": 400, "RequestId": REQUEST_ID,
                                 "RetryAttempts": 0,
                                 "HTTPHeaders": {"x-amzn-requestid": REQUEST_ID}}}


def not_found(bundle):
    row = bundle.index["captures"][ALIAS]
    row.update(format="boto3_json", exit_status=1)
    bundle.responses[ALIAS] = error_response()
    bundle.update(ALIAS)
    return row


def full_verify(bundle, evaluator=verifier):
    """Mock media/readback explicitly; only cleanup transport/order is under test."""
    bundle.write()
    def snapshot(captures, spec, disk, account, encrypted):
        ready = captures.take(spec["ready"], "DescribeSnapshots")
        row = ready.response["Snapshots"][0]
        evaluator.require(row["OwnerId"] == account and row["SnapshotId"] == SNAPSHOT
                          and row["Encrypted"] is encrypted, "synthetic owned snapshot binding differs")
        return {"snapshot_id": SNAPSHOT, "completed_at": ready.completed.isoformat()}
    with patch.object(evaluator, "selected_artifact", return_value=(b"SYNTHETIC EFI", bundle.disk)), \
         patch.object(aws_native_snapshot, "verify_snapshot", side_effect=snapshot) as mocked_readback:
        result = evaluator.verify(bundle.index_path, bundle.manifest_path)
        assert mocked_readback.call_count == 1
        return result


class SnapshotAbsenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tessryn-synthetic-snapshot-recycle-")
        self.addCleanup(self.temp.cleanup)
        self.bundle = fixtures.SyntheticCaptureBundle(Path(self.temp.name))
        self.row = not_found(self.bundle)

    def captures(self, evaluator=verifier):
        return evaluator.CaptureSet(self.bundle.index_path, self.bundle.index)

    def reject(self):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.captures().take_snapshot_recycle_absence(ALIAS, SNAPSHOT)

    def test_original_error_is_preserved_and_never_enters_the_success_cache(self):
        with self.assertRaises(ValueError):
            self.captures().take(ALIAS, "ListSnapshotsInRecycleBin")
        captures = self.captures()
        original = (self.bundle.root / self.row["response"]["path"]).read_bytes()
        result = verifier.recycle_absent(captures, ALIAS, "ListSnapshotsInRecycleBin", "Snapshots", "SnapshotIds", SNAPSHOT)
        self.assertEqual(result.response, error_response())
        self.assertNotIn("Snapshots", result.response)
        self.assertEqual(result.absence_basis, "provider_snapshot_not_found")
        self.assertEqual(result.completed, verifier.timestamp(self.row["completed_at"]))
        self.assertIn(ALIAS, captures.used)
        self.assertNotIn(ALIAS, captures.cache)
        self.assertEqual((self.bundle.root / self.row["response"]["path"]).read_bytes(), original)
        with self.assertRaises(ValueError):
            captures.take(ALIAS, "ListSnapshotsInRecycleBin")
        self.assertNotIn(ALIAS, captures.cache)

    def test_empty_list_remains_an_ordinary_success_with_distinct_basis(self):
        self.row["exit_status"] = 0
        self.bundle.responses[ALIAS] = {"Snapshots": [], "ResponseMetadata": {"HTTPStatusCode": 200}}
        self.bundle.update(ALIAS)
        captures = self.captures()
        normal = captures.take(ALIAS, "ListSnapshotsInRecycleBin")
        absence = captures.take_snapshot_recycle_absence(ALIAS, SNAPSHOT)
        self.assertIsNone(normal.absence_basis)
        self.assertEqual(absence.absence_basis, "successful_empty_list")
        self.assertIs(captures.take(ALIAS, "ListSnapshotsInRecycleBin"), normal)

    def test_sdk_only_exact_exit_empty_stderr_transport(self):
        for status in (0, 2, 254, 255, -1, True):
            with self.subTest(exit_status=status):
                self.row["exit_status"] = status
                self.reject()
        self.row["exit_status"] = 1
        self.row["format"] = "aws_cli_v2_json"
        self.reject()
        self.row["format"] = "boto3_json"
        self.row["stderr"] = self.bundle.ref(ALIAS + ".stderr", b"SYNTHETIC unexpected diagnostic")
        self.reject()

    def test_exact_single_id_request_and_typed_operation_only(self):
        for request in ({}, {"SnapshotIds": []}, {"SnapshotIds": [OTHER]},
                        {"SnapshotIds": [SNAPSHOT, OTHER]}, {"SnapshotIds": [SNAPSHOT, SNAPSHOT]},
                        {"SnapshotIds": [SNAPSHOT], "NextToken": "SYNTHETIC"},
                        {"SnapshotIds": [SNAPSHOT], "MaxResults": 5}):
            with self.subTest(request=request):
                self.row["request"] = request
                self.reject()
        self.row["request"] = {"SnapshotIds": [SNAPSHOT]}
        for operation in ("DescribeSnapshots", "ListImagesInRecycleBin", "ListVolumesInRecycleBin"):
            with self.subTest(operation=operation):
                self.row["operation"] = operation
                self.reject()

    def test_exact_error_code_and_http400_not_generic404_or_permissions(self):
        for code in ("InvalidSnapshot.NotFoundX", "InvalidSnapshot.Malformed", "UnauthorizedOperation",
                     "AuthFailure", "InvalidVolume.NotFound", "InvalidAMIID.NotFound"):
            with self.subTest(code=code):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["Error"]["Code"] = code
                self.bundle.update(ALIAS)
                self.reject()
        for status in (200, 403, 404, 500, "400", True, None):
            with self.subTest(http=status):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["ResponseMetadata"]["HTTPStatusCode"] = status
                self.bundle.update(ALIAS)
                self.reject()

    def test_message_requires_exact_sole_id_and_bounded_printable_text(self):
        for message in (f"The snapshot '{OTHER}' does not exist.", "Snapshot does not exist.",
                        f"Snapshots {SNAPSHOT} and {OTHER} do not exist.", f"{SNAPSHOT} {SNAPSHOT}",
                        f"{SNAPSHOT}-extra", f"The snapshot {SNAPSHOT}\nnot found", "x" * 4097,
                        None, 17):
            with self.subTest(message=message):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["Error"]["Message"] = message
                self.bundle.update(ALIAS)
                self.reject()

    def test_request_identity_and_error_structure_are_not_optional(self):
        for request_id in (None, "", 1, "x" * 257, "bad\nrequest", "contains a space"):
            with self.subTest(request_id=request_id):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["ResponseMetadata"]["RequestId"] = request_id
                self.bundle.update(ALIAS)
                self.reject()
        for key, value in (("Snapshots", []), ("NextToken", "SYNTHETIC"), ("Errors", [])):
            with self.subTest(extra_field=key):
                self.bundle.responses[ALIAS] = dict(error_response(), **{key: value})
                self.bundle.update(ALIAS)
                self.reject()
        self.bundle.responses[ALIAS] = error_response()
        self.bundle.responses[ALIAS]["Error"]["Extra"] = "SYNTHETIC"
        self.bundle.update(ALIAS)
        self.reject()

    def test_original_time_region_hash_and_identifier_bounds_remain_required(self):
        self.row["completed_at"] = (BASE + timedelta(hours=2, seconds=1)).isoformat()
        self.reject()
        self.row["completed_at"] = self.row["started_at"]
        self.row["region"] = "eu-central-1"
        self.reject()
        self.bundle.index["region"] = "eu-central-1"
        self.reject()
        self.row["region"] = self.bundle.index["region"] = "us-east-1"
        self.row["response"]["sha256"] = "0" * 64
        self.reject()
        self.bundle.update(ALIAS)
        for identifier in (OTHER, "snap-bad", "vol-00000000000000033"):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                self.captures().take_snapshot_recycle_absence(ALIAS, identifier)

    def test_error_never_relaxes_ordinary_snapshot_or_image_reads(self):
        for alias, operation in (("snapshot_absent", "DescribeSnapshots"),
                                 ("image_recycle_absent", "ListImagesInRecycleBin")):
            row = self.bundle.index["captures"][alias]
            row.update(format="boto3_json", exit_status=1)
            self.bundle.responses[alias] = error_response()
            self.bundle.update(alias)
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.captures().take(alias, operation)

    def test_full_synthetic_intake_keeps_owner_review_and_reports_only_basis_timestamp(self):
        result = full_verify(self.bundle)
        self.assertEqual(result["status"], "needs_owner_review")
        self.assertEqual(result["capture_origin"], "unverified_offline")
        self.assertEqual(result["snapshot_retention"], {"basis": "provider_snapshot_not_found",
                         "capture_completed_at": self.row["completed_at"]})
        encoded = json.dumps(result)
        for value in (SNAPSHOT, REQUEST_ID, "InvalidSnapshot.NotFound", ACCOUNT, fixtures.AMI):
            self.assertNotIn(value, encoded)

    def test_full_cleanup_still_requires_owned_snapshot_and_original_ordering(self):
        ready = self.bundle.responses["snapshot_ready"]["Snapshots"][0]
        ready["OwnerId"] = fixtures.OWNER
        self.bundle.update("snapshot_ready")
        with self.assertRaises(ValueError):
            full_verify(self.bundle)
        ready["OwnerId"] = ACCOUNT
        self.bundle.update("snapshot_ready")
        predecessor = self.bundle.index["captures"]["snapshot_absent"]
        original = self.row["started_at"]
        self.row["started_at"] = predecessor["started_at"]
        with self.assertRaises(ValueError):
            full_verify(self.bundle)
        self.row["started_at"] = original
        rules = self.bundle.index["captures"]["snapshot_retention_rules"]
        rules["started_at"] = self.row["started_at"]
        with self.assertRaises(ValueError):
            full_verify(self.bundle)


if __name__ == "__main__":
    unittest.main()
