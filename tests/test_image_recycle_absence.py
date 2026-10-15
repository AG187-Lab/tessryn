"""SYNTHETIC image Recycle Bin parsing; no AWS execution evidence.

Resource IDs and original SDK-shaped receipts are constructed locally. Full
intake cases explicitly mock media/readback and reuse local QEMU serial only.
The tests cover error transport, ownership/order joins and sanitized output.
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
fixtures = types.ModuleType("image_recycle_public_fixtures")
fixtures.__file__ = str(fixture_path)
fixtures.__package__ = ""
fixtures.__spec__ = importlib.machinery.ModuleSpec(fixtures.__name__, None, origin=str(fixture_path))
sys.modules[fixtures.__name__] = fixtures
exec(compile(fixture_path.read_bytes(), str(fixture_path), "exec", dont_inherit=True), fixtures.__dict__)

IMAGE = fixtures.AMI
OTHER = "ami-00000000000000099"
ALIAS = "image_recycle_absent"
REQUEST_ID = "SYNTHETIC_IMAGE_REQUEST_ID"


def error_response():
    return {"Error": {"Code": "InvalidAMIID.NotFound",
                       "Message": f"The specified Image ID {IMAGE} does not exist. "
                                  "Ensure that the Image ID is correct and try again."},
            "ResponseMetadata": {"HTTPStatusCode": 400, "RequestId": REQUEST_ID,
                                 "RetryAttempts": 0,
                                 "HTTPHeaders": {"x-amzn-requestid": REQUEST_ID}}}


def full_verify(bundle):
    """Mock media/readback explicitly; test only cleanup transport and joins."""
    bundle.write()
    def snapshot(captures, spec, disk, account, encrypted):
        ready = captures.take(spec["ready"], "DescribeSnapshots")
        row = ready.response["Snapshots"][0]
        verifier.require(row["OwnerId"] == account and row["SnapshotId"] == fixtures.SNAPSHOT
                         and row["Encrypted"] is encrypted, "synthetic owned snapshot binding differs")
        return {"snapshot_id": fixtures.SNAPSHOT, "completed_at": ready.completed.isoformat()}
    with patch.object(verifier, "selected_artifact", return_value=(b"SYNTHETIC EFI", bundle.disk)), \
         patch.object(aws_native_snapshot, "verify_snapshot", side_effect=snapshot) as readback:
        result = verifier.verify(bundle.index_path, bundle.manifest_path)
        assert readback.call_count == 1
        return result


class ImageAbsenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tessryn-synthetic-image-recycle-")
        self.addCleanup(self.temp.cleanup)
        self.bundle = fixtures.SyntheticCaptureBundle(Path(self.temp.name))
        self.row = self.bundle.index["captures"][ALIAS]
        self.row.update(format="boto3_json", exit_status=1)
        self.bundle.responses[ALIAS] = error_response()
        self.bundle.update(ALIAS)

    def captures(self):
        return verifier.CaptureSet(self.bundle.index_path, self.bundle.index)

    def reject(self):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.captures().take_image_recycle_absence(ALIAS, IMAGE)

    def test_original_error_is_preserved_and_never_enters_success_cache(self):
        captures = self.captures()
        original = (self.bundle.root / self.row["response"]["path"]).read_bytes()
        with self.assertRaises(ValueError):
            captures.take(ALIAS, "ListImagesInRecycleBin")
        result = verifier.recycle_absent(captures, ALIAS, "ListImagesInRecycleBin", "Images", "ImageIds", IMAGE)
        self.assertEqual(result.response, error_response())
        self.assertNotIn("Images", result.response)
        self.assertEqual(result.absence_basis, "provider_image_not_found")
        self.assertEqual(result.completed, verifier.timestamp(self.row["completed_at"]))
        self.assertIn(ALIAS, captures.used)
        self.assertNotIn(ALIAS, captures.cache)
        self.assertEqual((self.bundle.root / self.row["response"]["path"]).read_bytes(), original)
        with self.assertRaises(ValueError):
            captures.take(ALIAS, "ListImagesInRecycleBin")
        self.assertNotIn(ALIAS, captures.cache)

    def test_successful_empty_list_has_distinct_basis_and_normal_cache(self):
        self.row["exit_status"] = 0
        self.bundle.responses[ALIAS] = {"Images": [], "ResponseMetadata": {"HTTPStatusCode": 200}}
        self.bundle.update(ALIAS)
        captures = self.captures()
        normal = captures.take(ALIAS, "ListImagesInRecycleBin")
        absence = captures.take_image_recycle_absence(ALIAS, IMAGE)
        self.assertIsNone(normal.absence_basis)
        self.assertEqual(absence.absence_basis, "successful_empty_list")
        self.assertIs(captures.take(ALIAS, "ListImagesInRecycleBin"), normal)

    def test_sdk_only_exit_one_and_empty_stderr_are_required(self):
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

    def test_exact_single_image_request_and_operation_are_required(self):
        for request in ({}, {"ImageIds": []}, {"ImageIds": [OTHER]},
                        {"ImageIds": [IMAGE, OTHER]}, {"ImageIds": [IMAGE, IMAGE]},
                        {"ImageIds": [IMAGE], "NextToken": "SYNTHETIC"},
                        {"ImageIds": [IMAGE], "MaxResults": 5}):
            with self.subTest(request=request):
                self.row["request"] = request
                self.reject()
        self.row["request"] = {"ImageIds": [IMAGE]}
        for operation in ("DescribeImages", "ListSnapshotsInRecycleBin", "ListVolumesInRecycleBin"):
            with self.subTest(operation=operation):
                self.row["operation"] = operation
                self.reject()

    def test_exact_service_code_and_http400_never_mask_other_errors(self):
        for code in ("ResourceIdNotFound", "ResourceNotFoundException", "InvalidAMIID.NotFoundX",
                     "InvalidAMIID.Malformed", "InvalidSnapshot.NotFound", "InvalidVolume.NotFound",
                     "UnauthorizedOperation", "AuthFailure", "RequestLimitExceeded"):
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

    def test_message_requires_only_the_exact_image_and_bounded_printable_text(self):
        for message in (f"Image {OTHER} does not exist.", "Image does not exist.",
                        f"Images {IMAGE} and {OTHER} do not exist.", f"{IMAGE} {IMAGE}",
                        f"{IMAGE}-extra", f"Image {IMAGE}\nnot found", "x" * 4097, None, 17):
            with self.subTest(message=message):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["Error"]["Message"] = message
                self.bundle.update(ALIAS)
                self.reject()

    def test_request_id_and_original_error_structure_are_required(self):
        for request_id in (None, "", 1, "x" * 257, "bad\nrequest", "contains a space"):
            with self.subTest(request_id=request_id):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["ResponseMetadata"]["RequestId"] = request_id
                self.bundle.update(ALIAS)
                self.reject()
        for key, value in (("Images", []), ("NextToken", "SYNTHETIC"), ("Errors", [])):
            with self.subTest(extra=key):
                self.bundle.responses[ALIAS] = dict(error_response(), **{key: value})
                self.bundle.update(ALIAS)
                self.reject()
        self.bundle.responses[ALIAS] = error_response()
        self.bundle.responses[ALIAS]["Error"]["Extra"] = "SYNTHETIC"
        self.bundle.update(ALIAS)
        self.reject()

    def test_no_sdk_retries_and_matching_original_request_header_are_required(self):
        for attempts in (None, False, True, 1, 2, "0"):
            with self.subTest(retry_attempts=attempts):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["ResponseMetadata"]["RetryAttempts"] = attempts
                self.bundle.update(ALIAS)
                self.reject()
        for headers in (None, {}, [], {"x-amzn-requestid": "OTHER_SYNTHETIC_REQUEST"},
                        {"x-amzn-requestid": 1}, {"x-amzn-requestid": None}):
            with self.subTest(headers=headers):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["ResponseMetadata"]["HTTPHeaders"] = headers
                self.bundle.update(ALIAS)
                self.reject()
        for missing in ("RetryAttempts", "HTTPHeaders"):
            with self.subTest(missing=missing):
                self.bundle.responses[ALIAS] = error_response()
                self.bundle.responses[ALIAS]["ResponseMetadata"].pop(missing)
                self.bundle.update(ALIAS)
                self.reject()

    def test_original_region_time_hash_and_identifier_bounds_remain_required(self):
        self.row["completed_at"] = (fixtures.BASE + timedelta(hours=2, seconds=1)).isoformat()
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
        for image_id in (OTHER, "ami-bad", "snap-00000000000000033"):
            with self.subTest(image_id=image_id), self.assertRaises(ValueError):
                self.captures().take_image_recycle_absence(ALIAS, image_id)

    def test_error_does_not_relax_ordinary_image_or_snapshot_reads(self):
        for alias, operation in (("image_absent", "DescribeImages"),
                                 ("snapshot_recycle_absent", "ListSnapshotsInRecycleBin")):
            row = self.bundle.index["captures"][alias]
            row.update(format="boto3_json", exit_status=1)
            self.bundle.responses[alias] = error_response()
            self.bundle.update(alias)
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.captures().take(alias, operation)

    def test_full_synthetic_intake_keeps_owner_review_and_sanitizes_image_basis(self):
        result = full_verify(self.bundle)
        self.assertEqual(result["status"], "needs_owner_review")
        self.assertEqual(result["capture_origin"], "unverified_offline")
        self.assertEqual(result["image_retention"], {"basis": "provider_image_not_found",
                         "capture_completed_at": self.row["completed_at"]})
        encoded = json.dumps(result)
        for value in (IMAGE, REQUEST_ID, "InvalidAMIID.NotFound", fixtures.ACCOUNT, fixtures.SNAPSHOT):
            self.assertNotIn(value, encoded)

    def test_full_cleanup_still_requires_owned_image_and_original_order(self):
        image = self.bundle.responses["image"]["Images"][0]
        image["OwnerId"] = fixtures.OWNER
        self.bundle.update("image")
        with self.assertRaises(ValueError):
            full_verify(self.bundle)
        image["OwnerId"] = fixtures.ACCOUNT
        self.bundle.update("image")
        predecessor = self.bundle.index["captures"]["image_absent"]
        original = self.row["started_at"]
        self.row["started_at"] = predecessor["started_at"]
        with self.assertRaises(ValueError):
            full_verify(self.bundle)
        self.row["started_at"] = original
        deletion = self.bundle.index["captures"]["delete_snapshot"]
        deletion["started_at"] = self.row["started_at"]
        with self.assertRaises(ValueError):
            full_verify(self.bundle)


if __name__ == "__main__":
    unittest.main()
