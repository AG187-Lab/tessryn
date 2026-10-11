"""Bounded offline consistency checks for one new K01 EBS snapshot.

The caller authenticates/scopes capture files and selects the locally verified
normal disk metadata. This module makes no AWS calls. Recorded API responses
are observations under trusted owner capture, not proof of AWS execution or
platform qualification. In particular, AWS returns per-block checksums; the
whole logical disk checksum below is reconstructed locally from readback.

API contracts: docs.aws.amazon.com/ebs/latest/APIReference/API_{StartSnapshot,
PutSnapshotBlock,CompleteSnapshot,ListSnapshotBlocks,GetSnapshotBlock}.html.
The bounded K01 profile is a 1-GiB, no-parent snapshot with five nonzero blocks.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import re

DISK_SIZE_BYTES = 1 << 30
BLOCK_SIZE_BYTES = 1 << 19
BLOCK_COUNT = DISK_SIZE_BYTES // BLOCK_SIZE_BYTES
NONZERO_BLOCK_COUNT = 5
MAX_LIST_PAGES = 64
_ZERO = bytes(BLOCK_SIZE_BYTES)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_CLIENT_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{16,64}")
_SNAPSHOT_ID = re.compile(r"snap-[0-9a-f]{1,59}")
_API_TOKEN = re.compile(r"[A-Za-z0-9+/=]{1,256}")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        # Never interpolate private aliases, paths, resource IDs or API errors.
        raise ValueError("snapshot evidence rejected: " + reason)


def _integer(value, expected: int) -> bool:
    return type(value) is int and value == expected


def _checksum(sha256: str) -> str:
    return base64.b64encode(bytes.fromhex(sha256)).decode("ascii")


def _expected(expected_disk: dict) -> dict[int, str]:
    _require(type(expected_disk) is dict, "invalid disk metadata")
    _require(_integer(expected_disk.get("logical_size_bytes"), DISK_SIZE_BYTES)
             and _integer(expected_disk.get("block_size_bytes"), BLOCK_SIZE_BYTES)
             and type(expected_disk.get("sha256")) is str
             and _SHA256.fullmatch(expected_disk["sha256"]) is not None,
             "invalid disk geometry or checksum")
    rows = expected_disk.get("nonzero_blocks")
    _require(type(rows) is list and len(rows) == NONZERO_BLOCK_COUNT,
             "disk must contain exactly five nonzero blocks")
    result = {}
    previous = -1
    zero_hash = hashlib.sha256(_ZERO).hexdigest()
    for row in rows:
        _require(type(row) is dict, "invalid disk block metadata")
        index, digest = row.get("index"), row.get("sha256")
        _require(type(index) is int and previous < index < BLOCK_COUNT
                 and _integer(row.get("size_bytes"), BLOCK_SIZE_BYTES)
                 and type(digest) is str and _SHA256.fullmatch(digest) is not None
                 and digest != zero_hash, "invalid nonzero disk block")
        result[index] = digest
        previous = index
    return result


def _spec(spec: dict) -> None:
    _require(type(spec) is dict and set(spec) ==
             {"start", "uploads", "complete", "ready", "list_pages", "blocks"},
             "invalid snapshot specification")
    for key in ("uploads", "blocks"):
        _require(type(spec[key]) is list and len(spec[key]) == NONZERO_BLOCK_COUNT,
                 "invalid snapshot capture count")
    _require(type(spec["list_pages"]) is list
             and 1 <= len(spec["list_pages"]) <= MAX_LIST_PAGES,
             "invalid snapshot pagination count")
    aliases = [spec["start"], spec["complete"], spec["ready"]]
    aliases.extend(spec["uploads"])
    aliases.extend(spec["list_pages"])
    for row in spec["blocks"]:
        _require(type(row) is dict and set(row) == {"index", "capture", "data"},
                 "invalid readback specification")
        _require(type(row["index"]) is int and 0 <= row["index"] < BLOCK_COUNT,
                 "invalid readback index")
        ref = row["data"]
        _require(type(ref) is dict and set(ref) == {"path", "sha256", "size_bytes"}
                 and type(ref["path"]) is str and 0 < len(ref["path"]) <= 4096
                 and type(ref["sha256"]) is str
                 and _SHA256.fullmatch(ref["sha256"]) is not None
                 and _integer(ref["size_bytes"], BLOCK_SIZE_BYTES),
                 "invalid readback file reference")
        aliases.append(row["capture"])
    _require(all(type(alias) is str and _ALIAS.fullmatch(alias) is not None
                 for alias in aliases), "invalid capture alias")
    _require(len(set(aliases)) == len(aliases), "reused snapshot capture alias")


def _take(captures, alias: str, operation: str):
    try:
        capture = captures.take(alias, operation)
        request, response = capture.request, capture.response
        started, completed = capture.started, capture.completed
    except Exception:
        raise ValueError("snapshot evidence rejected: unavailable operation capture") from None
    _require(type(request) is dict and type(response) is dict,
             "invalid operation capture payload")
    _require(isinstance(started, datetime) and isinstance(completed, datetime)
             and started.utcoffset() == timedelta(0)
             and completed.utcoffset() == timedelta(0) and started <= completed,
             "invalid operation capture time")
    return capture


def _after(capture, predecessor) -> None:
    _require(capture.started >= predecessor.completed, "operation capture order differs")


def _expiration(value) -> datetime:
    """Accept recorded AWS JSON timestamps without echoing private input."""
    try:
        if type(value) is str and 0 < len(value) <= 64:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        elif type(value) in (int, float):
            result = datetime.fromtimestamp(value, timezone.utc)
        else:
            raise ValueError()
        if result.tzinfo is None:
            raise ValueError()
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError, TypeError):
        raise ValueError("snapshot evidence rejected: invalid block token expiration") from None


def _block_checksum(record: dict, checksum: str, length: bool = False) -> None:
    _require(record.get("ChecksumAlgorithm") == "SHA256"
             and record.get("Checksum") == checksum,
             "block checksum differs")
    if length:
        _require(_integer(record.get("DataLength"), BLOCK_SIZE_BYTES),
                 "block length differs")


def verify_snapshot(captures, spec: dict, expected_disk: dict,
                    account_id: str, encrypted: bool) -> dict:
    """Verify one bounded capture chain; return private observed metadata only.

    ``captures.take(alias, AWSOperation)`` supplies request/response dictionaries
    and aware UTC ``started``/``completed`` datetimes. ``captures.read(ref)``
    supplies exact raw bytes under the caller's regular-file/hash policy.
    Uploads may overlap each other, and reads may overlap subsequent list pages;
    each dependent operation must follow its recorded predecessor's completion.
    A supplied attempt token is required, but global/prior uniqueness cannot be
    established from this offline chain. The caller reviews that separately.
    """
    expected = _expected(expected_disk)
    _spec(spec)
    _require(type(account_id) is str and re.fullmatch(r"[0-9]{12}", account_id) is not None
             and type(encrypted) is bool, "invalid expected snapshot owner or encryption")

    start = _take(captures, spec["start"], "StartSnapshot")
    request, response = start.request, start.response
    token = request.get("ClientToken")
    _require(_integer(request.get("VolumeSize"), 1)
             and "ParentSnapshotId" not in request
             and type(token) is str and _CLIENT_TOKEN.fullmatch(token) is not None
             and token != expected_disk["sha256"], "invalid new snapshot request")
    _require("Encrypted" not in request or request["Encrypted"] is encrypted,
             "requested snapshot encryption differs")
    snapshot_id = response.get("SnapshotId")
    _require(type(snapshot_id) is str and _SNAPSHOT_ID.fullmatch(snapshot_id) is not None
             and _integer(response.get("BlockSize"), BLOCK_SIZE_BYTES)
             and _integer(response.get("VolumeSize"), 1)
             and response.get("OwnerId") == account_id and response.get("Status") == "pending"
             and response.get("ParentSnapshotId") is None, "new snapshot response differs")

    uploads = []
    uploaded = set()
    for alias in spec["uploads"]:
        capture = _take(captures, alias, "PutSnapshotBlock")
        _after(capture, start)
        index = capture.request.get("BlockIndex")
        _require(type(index) is int and index in expected and index not in uploaded
                 and capture.request.get("SnapshotId") == snapshot_id,
                 "upload snapshot or block set differs")
        checksum = _checksum(expected[index])
        _block_checksum(capture.request, checksum, length=True)
        _block_checksum(capture.response, checksum)
        uploaded.add(index)
        uploads.append(capture)
    _require(uploaded == set(expected), "upload block coverage differs")

    complete = _take(captures, spec["complete"], "CompleteSnapshot")
    for upload in uploads:
        _after(complete, upload)
    _require(complete.request.get("SnapshotId") == snapshot_id
             and _integer(complete.request.get("ChangedBlocksCount"), NONZERO_BLOCK_COUNT)
             and complete.response.get("Status") in ("pending", "completed"),
             "snapshot completion differs")

    ready = _take(captures, spec["ready"], "DescribeSnapshots")
    _after(ready, complete)
    _require(ready.request.get("SnapshotIds") == [snapshot_id]
             and "NextToken" not in ready.request, "snapshot readiness query differs")
    rows = ready.response.get("Snapshots")
    _require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict
             and ready.response.get("NextToken") is None, "snapshot readiness response differs")
    snapshot = rows[0]
    _require(snapshot.get("SnapshotId") == snapshot_id and snapshot.get("State") == "completed"
             and _integer(snapshot.get("VolumeSize"), 1) and snapshot.get("OwnerId") == account_id
             and snapshot.get("Encrypted") is encrypted, "completed snapshot identity differs")

    # No early exit after five blocks: a short or empty page can still continue.
    listed = {}
    next_token = None
    seen_tokens = set()
    previous = ready
    for position, alias in enumerate(spec["list_pages"]):
        page = _take(captures, alias, "ListSnapshotBlocks")
        _after(page, previous)
        request, response = page.request, page.response
        _require(request.get("SnapshotId") == snapshot_id, "listed snapshot differs")
        if position == 0:
            _require("NextToken" not in request
                     and ("StartingBlockIndex" not in request
                          or _integer(request["StartingBlockIndex"], 0)),
                     "snapshot listing must start at the beginning")
        else:
            _require(next_token is not None and request.get("NextToken") == next_token,
                     "snapshot pagination continuity differs")
        if "MaxResults" in request:
            _require(type(request["MaxResults"]) is int and 100 <= request["MaxResults"] <= 10000,
                     "invalid snapshot pagination limit")
        _require(_integer(response.get("BlockSize"), BLOCK_SIZE_BYTES)
                 and _integer(response.get("VolumeSize"), 1), "listed snapshot geometry differs")
        expiry = _expiration(response["ExpiryTime"]) if "ExpiryTime" in response else None
        _require(expiry is None or page.completed < expiry, "listed block token already expired")
        blocks = response.get("Blocks")
        _require(type(blocks) is list and len(blocks) <= NONZERO_BLOCK_COUNT,
                 "invalid listed block count")
        for block in blocks:
            _require(type(block) is dict, "invalid listed block")
            index, block_token = block.get("BlockIndex"), block.get("BlockToken")
            _require(type(index) is int and index in expected and index not in listed
                     and type(block_token) is str and _API_TOKEN.fullmatch(block_token) is not None,
                     "listed block set or token differs")
            listed[index] = (block_token, page, expiry)
        next_token = response.get("NextToken")
        _require(next_token is None or type(next_token) is str
                 and _API_TOKEN.fullmatch(next_token) is not None and next_token not in seen_tokens,
                 "invalid or repeated snapshot pagination token")
        if next_token is not None:
            seen_tokens.add(next_token)
        _require(next_token is not None or position == len(spec["list_pages"]) - 1,
                 "snapshot listing continued after terminal page")
        previous = page
    _require(next_token is None and set(listed) == set(expected),
             "snapshot listing incomplete or block coverage differs")

    readbacks = {}
    for row in spec["blocks"]:
        index = row["index"]
        _require(index in expected and index not in readbacks, "readback block set differs")
        capture = _take(captures, row["capture"], "GetSnapshotBlock")
        block_token, page, expiry = listed[index]
        _after(capture, page)
        # A request can start before expiry and finish afterwards. A recorded
        # request that only starts after expiry contradicts the token contract.
        _require(expiry is None or capture.started < expiry, "readback block token expired")
        _require(capture.request.get("SnapshotId") == snapshot_id
                 and _integer(capture.request.get("BlockIndex"), index)
                 and capture.request.get("BlockToken") == block_token,
                 "readback snapshot, index or token differs")
        _block_checksum(capture.response, _checksum(expected[index]), length=True)
        ref = row["data"]
        _require(ref["sha256"] == expected[index], "readback file checksum differs")
        readbacks[index] = (capture, ref)
    _require(set(readbacks) == set(expected), "readback block coverage differs")

    # Hash in index order with one raw block in memory. Zero gaps are included
    # through the actual 1-GiB logical end, including any trailing sparse holes.
    digest = hashlib.sha256()
    next_index = 0
    for index in sorted(readbacks):
        while next_index < index:
            digest.update(_ZERO)
            next_index += 1
        try:
            data = captures.read(readbacks[index][1])
        except Exception:
            raise ValueError("snapshot evidence rejected: unavailable readback bytes") from None
        _require(type(data) is bytes and len(data) == BLOCK_SIZE_BYTES
                 and hashlib.sha256(data).hexdigest() == expected[index] and data != _ZERO,
                 "raw readback bytes differ")
        digest.update(data)
        next_index += 1
    while next_index < BLOCK_COUNT:
        digest.update(_ZERO)
        next_index += 1
    logical_sha256 = digest.hexdigest()
    _require(logical_sha256 == expected_disk["sha256"], "reconstructed logical disk checksum differs")
    finished = max([previous.completed] + [capture.completed for capture, _ in readbacks.values()])
    return {"snapshot_id": snapshot_id, "volume_size_gib": 1,
            "block_size_bytes": BLOCK_SIZE_BYTES, "encrypted": snapshot["Encrypted"],
            "owner_id": snapshot["OwnerId"], "block_indices": sorted(listed),
            "logical_size_bytes": DISK_SIZE_BYTES, "reconstructed_sha256": logical_sha256,
            "upload_count": len(uploads), "list_page_count": len(spec["list_pages"]),
            "readback_count": len(readbacks), "started_at": start.started.isoformat(),
            "completed_at": finished.isoformat()}
