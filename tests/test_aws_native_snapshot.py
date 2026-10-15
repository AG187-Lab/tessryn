"""Synthetic snapshot-chain fixtures; these are not captured AWS evidence."""

import base64
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import unittest

from tools import aws_native_snapshot as snapshot

ACCOUNT = "123456789012"
SNAPSHOT = "snap-0123456789abcdef0"
INDICES = [0, 2, 3, 4, 2047]
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass
class SyntheticCapture:
    operation: str
    request: dict
    response: dict
    started: datetime
    completed: datetime


class SyntheticCaptures:
    def __init__(self, records, files):
        self.records = records
        self.files = files
        self.taken = []
        self.read_sizes = []

    def take(self, alias, operation):
        record = self.records[alias]
        if record.operation != operation:
            raise ValueError("synthetic private error with resource and alias")
        self.taken.append(alias)
        return record

    def read(self, ref):
        # The production caller also restricts regular-file scope and rejects
        # replacement/concurrent writes. Here the bytes are synthetic memory.
        data = self.files[ref["path"]]
        if len(data) != ref["size_bytes"] or hashlib.sha256(data).hexdigest() != ref["sha256"]:
            raise ValueError("synthetic private filename and account error")
        self.read_sizes.append(len(data))
        return data


class AwsNativeSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.synthetic_data = {index: bytes([position + 1]) * snapshot.BLOCK_SIZE_BYTES
                              for position, index in enumerate(INDICES)}
        zero = bytes(snapshot.BLOCK_SIZE_BYTES)
        digest = hashlib.sha256()
        for index in range(snapshot.BLOCK_COUNT):
            digest.update(cls.synthetic_data.get(index, zero))
        cls.synthetic_disk = {
            "logical_size_bytes": snapshot.DISK_SIZE_BYTES,
            "block_size_bytes": snapshot.BLOCK_SIZE_BYTES,
            "sha256": digest.hexdigest(),
            "nonzero_blocks": [{"index": index, "size_bytes": snapshot.BLOCK_SIZE_BYTES,
                                "sha256": hashlib.sha256(cls.synthetic_data[index]).hexdigest()}
                               for index in INDICES],
        }

    def setUp(self):
        self.disk = copy.deepcopy(self.synthetic_disk)
        self.records = {}
        self.files = {}

        def record(alias, operation, request, response, second):
            self.records[alias] = SyntheticCapture(
                operation, request, response, EPOCH + timedelta(seconds=second),
                EPOCH + timedelta(seconds=second + 1))

        record("start", "StartSnapshot",
               {"VolumeSize": 1, "ClientToken": "synthetic-attempt-token-0001", "Encrypted": True},
               {"SnapshotId": SNAPSHOT, "BlockSize": snapshot.BLOCK_SIZE_BYTES,
                "VolumeSize": 1, "OwnerId": ACCOUNT, "Status": "pending"}, 0)
        for index in INDICES:
            checksum = base64.b64encode(bytes.fromhex(
                hashlib.sha256(self.synthetic_data[index]).hexdigest())).decode("ascii")
            record("put-" + str(index), "PutSnapshotBlock",
                   {"SnapshotId": SNAPSHOT, "BlockIndex": index,
                    "Checksum": checksum, "ChecksumAlgorithm": "SHA256",
                    "DataLength": snapshot.BLOCK_SIZE_BYTES},
                   {"Checksum": checksum, "ChecksumAlgorithm": "SHA256"}, 2)
        record("complete", "CompleteSnapshot",
               {"SnapshotId": SNAPSHOT, "ChangedBlocksCount": 5}, {"Status": "pending"}, 4)
        record("ready", "DescribeSnapshots", {"SnapshotIds": [SNAPSHOT]},
               {"Snapshots": [{"SnapshotId": SNAPSHOT, "State": "completed", "VolumeSize": 1,
                               "OwnerId": ACCOUNT, "Encrypted": True}]}, 6)
        # An empty page followed by two short pages tests full continuation.
        record("list-0", "ListSnapshotBlocks", {"SnapshotId": SNAPSHOT, "MaxResults": 100},
               {"VolumeSize": 1, "BlockSize": snapshot.BLOCK_SIZE_BYTES,
                "Blocks": [], "NextToken": "cGFnZTE=",
                "ExpiryTime": (EPOCH + timedelta(hours=1)).isoformat()}, 8)
        record("list-1", "ListSnapshotBlocks", {"SnapshotId": SNAPSHOT, "NextToken": "cGFnZTE="},
               {"VolumeSize": 1, "BlockSize": snapshot.BLOCK_SIZE_BYTES,
                "Blocks": [{"BlockIndex": index, "BlockToken": "YmxvY2s" + str(index)}
                           for index in INDICES[:2]], "NextToken": "cGFnZTI=",
                "ExpiryTime": (EPOCH + timedelta(hours=1)).timestamp()}, 10)
        record("list-2", "ListSnapshotBlocks", {"SnapshotId": SNAPSHOT, "NextToken": "cGFnZTI="},
               {"VolumeSize": 1, "BlockSize": snapshot.BLOCK_SIZE_BYTES,
                "Blocks": [{"BlockIndex": index, "BlockToken": "YmxvY2s" + str(index)}
                           for index in INDICES[2:]],
                "ExpiryTime": (EPOCH + timedelta(hours=1)).isoformat().replace("+00:00", "Z")}, 12)
        self.spec = {"start": "start", "uploads": ["put-" + str(index) for index in INDICES],
                     "complete": "complete", "ready": "ready",
                     "list_pages": ["list-0", "list-1", "list-2"], "blocks": []}
        for row in self.disk["nonzero_blocks"]:
            index = row["index"]
            checksum = base64.b64encode(bytes.fromhex(row["sha256"])).decode("ascii")
            record("get-" + str(index), "GetSnapshotBlock",
                   {"SnapshotId": SNAPSHOT, "BlockIndex": index, "BlockToken": "YmxvY2s" + str(index)},
                   {"Checksum": checksum, "ChecksumAlgorithm": "SHA256",
                    "DataLength": snapshot.BLOCK_SIZE_BYTES}, 14)
            ref = {"path": "synthetic-" + str(index) + ".bin", "sha256": row["sha256"],
                   "size_bytes": snapshot.BLOCK_SIZE_BYTES}
            self.files[ref["path"]] = self.synthetic_data[index]
            self.spec["blocks"].append({"index": index, "capture": "get-" + str(index), "data": ref})
        self.captures = SyntheticCaptures(self.records, self.files)

    def verify(self, encrypted=True):
        return snapshot.verify_snapshot(self.captures, self.spec, self.disk, ACCOUNT, encrypted)

    def reject(self, reason=None):
        with self.assertRaisesRegex(ValueError, reason or "snapshot evidence rejected"):
            self.verify()

    def test_complete_synthetic_chain_streams_zeros_and_all_blocks(self):
        result = self.verify()
        self.assertEqual(result["snapshot_id"], SNAPSHOT)
        self.assertEqual(result["owner_id"], ACCOUNT)
        self.assertEqual(result["block_indices"], INDICES)
        self.assertEqual(result["reconstructed_sha256"], self.disk["sha256"])
        self.assertEqual((result["upload_count"], result["list_page_count"], result["readback_count"]),
                         (5, 3, 5))
        self.assertEqual(self.captures.read_sizes, [snapshot.BLOCK_SIZE_BYTES] * 5)
        self.assertEqual(len(self.captures.taken), 16)
        self.assertNotIn("status", result)
        self.assertNotIn("qualified", result)
        self.assertEqual(result["completed_at"], (EPOCH + timedelta(seconds=15)).isoformat())

    def test_unencrypted_observation_and_sdk_default_request(self):
        del self.records["start"].request["Encrypted"]
        self.records["start"].response["ParentSnapshotId"] = None
        self.records["ready"].response["Snapshots"][0]["Encrypted"] = False
        self.assertIs(self.verify(encrypted=False)["encrypted"], False)

    def test_parallel_uploads_and_read_after_its_page(self):
        self.records["put-2"].started = EPOCH + timedelta(seconds=1)
        self.records["put-2"].completed = EPOCH + timedelta(seconds=4)
        self.records["get-0"].started = EPOCH + timedelta(seconds=11)
        self.records["get-0"].completed = EPOCH + timedelta(seconds=12)
        self.assertEqual(self.verify()["readback_count"], 5)

    def test_late_empty_terminal_page_must_be_consumed_after_five_blocks(self):
        self.records["list-2"].response["NextToken"] = "cGFnZTM="
        self.records["list-3"] = SyntheticCapture(
            "ListSnapshotBlocks", {"SnapshotId": SNAPSHOT, "NextToken": "cGFnZTM="},
            {"VolumeSize": 1, "BlockSize": snapshot.BLOCK_SIZE_BYTES, "Blocks": [], "NextToken": None},
            EPOCH + timedelta(seconds=16), EPOCH + timedelta(seconds=17))
        self.spec["list_pages"].append("list-3")
        self.assertEqual(self.verify()["list_page_count"], 4)
        self.assertIn("list-3", self.captures.taken)

    def test_early_stop_even_when_five_blocks_already_seen(self):
        self.records["list-2"].response["NextToken"] = "cGFnZTM="
        self.reject("listing incomplete")

    def test_new_snapshot_contract_rejects_parent_token_and_geometry(self):
        mutations = [("request", "VolumeSize", True), ("request", "VolumeSize", 2),
                     ("request", "ParentSnapshotId", SNAPSHOT), ("request", "ParentSnapshotId", None),
                     ("request", "ClientToken", "short"), ("request", "ClientToken", "unsafe token-0001"),
                     ("request", "ClientToken", self.disk["sha256"]), ("request", "Encrypted", False),
                     ("response", "BlockSize", 4096), ("response", "VolumeSize", 2),
                     ("response", "OwnerId", "000000000000"), ("response", "SnapshotId", "bad-id"),
                     ("response", "Status", "completed"), ("response", "ParentSnapshotId", SNAPSHOT)]
        for side, key, value in mutations:
            with self.subTest(side=side, key=key, value=value):
                original = copy.deepcopy(self.records["start"])
                getattr(self.records["start"], side)[key] = value
                self.reject()
                self.records["start"] = original

    def test_every_upload_must_match_exact_expected_block(self):
        mutations = [("request", "BlockIndex", 1), ("request", "BlockIndex", True),
                     ("request", "BlockIndex", 0), ("request", "SnapshotId", "snap-deadbeef"),
                     ("request", "Checksum", "wrong"), ("response", "Checksum", "wrong"),
                     ("request", "ChecksumAlgorithm", "SHA1"), ("response", "ChecksumAlgorithm", "SHA1"),
                     ("request", "DataLength", 1)]
        for side, key, value in mutations:
            with self.subTest(side=side, key=key):
                original = copy.deepcopy(self.records["put-2"])
                getattr(self.records["put-2"], side)[key] = value
                self.reject()
                self.records["put-2"] = original

    def test_complete_and_ready_snapshot_binding(self):
        mutations = [("complete", "request", "ChangedBlocksCount", 4),
                     ("complete", "request", "SnapshotId", "snap-deadbeef"),
                     ("complete", "response", "Status", "error"),
                     ("ready", "request", "SnapshotIds", ["snap-deadbeef"]),
                     ("ready", "response", "NextToken", "more")]
        for alias, side, key, value in mutations:
            with self.subTest(alias=alias, key=key):
                original = copy.deepcopy(self.records[alias])
                getattr(self.records[alias], side)[key] = value
                self.reject()
                self.records[alias] = original
        for key, value in (("State", "pending"), ("VolumeSize", 2), ("OwnerId", "000000000000"),
                           ("Encrypted", False), ("Encrypted", 1), ("SnapshotId", "snap-deadbeef")):
            with self.subTest(key=key):
                original = copy.deepcopy(self.records["ready"])
                self.records["ready"].response["Snapshots"][0][key] = value
                self.reject()
                self.records["ready"] = original

    def test_pagination_coverage_and_continuity_negatives(self):
        mutations = [("list-0", "request", "StartingBlockIndex", 1),
                     ("list-0", "request", "NextToken", "cGFnZTE="),
                     ("list-0", "request", "MaxResults", 5),
                     ("list-1", "request", "NextToken", "wrong"),
                     ("list-1", "request", "SnapshotId", "snap-deadbeef"),
                     ("list-1", "response", "NextToken", "cGFnZTE="),
                     ("list-1", "response", "NextToken", None),
                     ("list-2", "response", "BlockSize", 4096),
                     ("list-2", "response", "VolumeSize", 2),
                     ("list-2", "response", "Blocks", [])]
        for alias, side, key, value in mutations:
            with self.subTest(alias=alias, key=key):
                original = copy.deepcopy(self.records[alias])
                getattr(self.records[alias], side)[key] = value
                self.reject()
                self.records[alias] = original
        for index in (0, 1, True, 2048):
            with self.subTest(index=index):
                original = copy.deepcopy(self.records["list-2"])
                self.records["list-2"].response["Blocks"][0]["BlockIndex"] = index
                self.reject()
                self.records["list-2"] = original

    def test_get_snapshot_block_binds_tokens_indices_and_checksums(self):
        mutations = [("request", "SnapshotId", "snap-deadbeef"), ("request", "BlockIndex", 0),
                     ("request", "BlockIndex", True), ("request", "BlockToken", "other"),
                     ("response", "Checksum", "wrong"), ("response", "ChecksumAlgorithm", "SHA1"),
                     ("response", "DataLength", 4096)]
        for side, key, value in mutations:
            with self.subTest(side=side, key=key):
                original = copy.deepcopy(self.records["get-2"])
                getattr(self.records["get-2"], side)[key] = value
                self.reject()
                self.records["get-2"] = original

    def test_capture_dependencies_and_utc_times(self):
        mutations = [("put-0", "started", 0), ("complete", "started", 2),
                     ("ready", "started", 4), ("list-0", "started", 6),
                     ("list-2", "started", 10), ("get-0", "started", 10)]
        for alias, field, second in mutations:
            with self.subTest(alias=alias):
                original = copy.deepcopy(self.records[alias])
                setattr(self.records[alias], field, EPOCH + timedelta(seconds=second))
                self.reject("order differs")
                self.records[alias] = original
        self.records["start"].started = EPOCH.replace(tzinfo=None)
        self.reject("capture time")
        self.records["start"].started = EPOCH.astimezone(timezone(timedelta(hours=1)))
        self.reject("capture time")
        self.records["start"].started = EPOCH + timedelta(seconds=2)
        self.reject("capture time")

    def test_recorded_token_expiry_must_cover_read_request_start(self):
        for value in (None, False, "2026-01-01T01:00:00", "private-bad-timestamp", float("inf")):
            with self.subTest(value=value):
                self.records["list-1"].response["ExpiryTime"] = value
                self.reject("invalid block token expiration")
        self.records["list-1"].response["ExpiryTime"] = (EPOCH + timedelta(seconds=11)).isoformat()
        self.reject("already expired")
        self.records["list-1"].response["ExpiryTime"] = (EPOCH + timedelta(seconds=14)).isoformat()
        self.reject("readback block token expired")

    def test_raw_byte_corruption_and_file_failures_are_sanitized(self):
        path = self.spec["blocks"][0]["data"]["path"]
        for data in (b"", bytes(snapshot.BLOCK_SIZE_BYTES), self.synthetic_data[2]):
            with self.subTest(size=len(data)):
                self.files[path] = data
                with self.assertRaises(ValueError) as error:
                    self.verify()
                self.assertEqual(str(error.exception), "snapshot evidence rejected: unavailable readback bytes")
                self.assertIsNone(error.exception.__cause__)
                self.assertNotIn(path, str(error.exception))
                self.assertNotIn(ACCOUNT, str(error.exception))

    def test_raw_reader_success_still_requires_size_and_sha256(self):
        self.captures.read = lambda ref: b"unverified-raw-data"
        self.reject("raw readback bytes differ")

    def test_whole_logical_checksum_is_not_an_aws_checksum_claim(self):
        self.disk["sha256"] = "0" * 64
        self.reject("reconstructed logical disk checksum differs")

    def test_spec_and_expected_geometry_are_bounded_and_strict(self):
        original_spec = copy.deepcopy(self.spec)
        for value in ([], {}, {**self.spec, "unexpected": True}, {**self.spec, "uploads": []},
                      {**self.spec, "list_pages": []}, {**self.spec, "list_pages": ["page"] * 65}):
            with self.subTest(spec=value):
                self.spec = value
                self.reject()
        self.spec = original_spec
        for field, value in (("logical_size_bytes", True), ("logical_size_bytes", 2 << 30),
                             ("block_size_bytes", 4096), ("sha256", "g" * 64), ("nonzero_blocks", [])):
            with self.subTest(field=field):
                original = copy.deepcopy(self.disk)
                self.disk[field] = value
                self.reject()
                self.disk = original
        for field, value in (("index", True), ("index", 2048), ("size_bytes", 1),
                             ("sha256", hashlib.sha256(bytes(snapshot.BLOCK_SIZE_BYTES)).hexdigest())):
            with self.subTest(field=field):
                original = copy.deepcopy(self.disk)
                self.disk["nonzero_blocks"][0][field] = value
                self.reject()
                self.disk = original

    def test_readback_spec_requires_exact_unique_expected_blocks(self):
        original = copy.deepcopy(self.spec)
        self.spec["blocks"][1]["index"] = 0
        self.reject("readback block set differs")
        self.spec = copy.deepcopy(original)
        self.spec["blocks"][1]["capture"] = self.spec["blocks"][0]["capture"]
        self.reject("reused snapshot capture alias")
        self.spec = copy.deepcopy(original)
        self.spec["blocks"][0]["data"]["sha256"] = "0" * 64
        self.reject("readback file checksum differs")

    def test_operation_lookup_errors_do_not_leak_private_capture_values(self):
        self.records["start"].operation = "WrongOperation"
        with self.assertRaises(ValueError) as error:
            self.verify()
        self.assertEqual(str(error.exception), "snapshot evidence rejected: unavailable operation capture")
        self.assertIsNone(error.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
