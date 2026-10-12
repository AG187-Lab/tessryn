#!/usr/bin/env python3
"""Check private native EC2 captures offline; AWS origin still needs owner review.

No AWS API, shell command, credential lookup or paid resource is used. Raw
captures remain private. Successful checks establish internal consistency, not
cryptographic AWS provenance or general platform qualification.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.g03.evidence import parse_json
from tools.run_aws_boot import selected_artifact, evaluator_hash as local_evaluator_hash

MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
HASH = re.compile(r"[0-9a-f]{64}")
FORMATS = {"aws_cli_v2_json", "boto3_json"}
EMPTY_RESPONSES = {"DeleteSnapshot", "DeleteVolume", "DeleteNetworkInterface", "DeregisterImage"}
MAX_RECOVERY_EPHEMERAL_MAPPINGS = 2


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def capture_json(raw: bytes) -> dict:
    try:
        return parse_json(raw)
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("malformed private capture JSON") from None


def regular_bytes(path: Path, directory_fd: int | None = None) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_CAPTURE_BYTES,
                    "capture must be a bounded regular file")
            raw = stream.read(MAX_CAPTURE_BYTES + 1)
            require(len(raw) <= MAX_CAPTURE_BYTES, "capture grew beyond byte limit")
            return raw
    except OSError:
        raise ValueError("capture file unavailable") from None


def relative_bytes(root: Path, parts: tuple[str, ...]) -> bytes:
    """Use directory descriptors so a parent symlink/replacement cannot escape."""
    try:
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return regular_bytes(Path(parts[-1]), descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise ValueError("capture directory unavailable") from None


def timestamp(value: object) -> datetime:
    require(isinstance(value, str) and len(value) <= 64, "invalid capture timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.tzinfo is not None, "capture timestamp lacks timezone")
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise ValueError("invalid capture timestamp") from error


def identifier(value: object, prefix: str) -> str:
    require(isinstance(value, str) and re.fullmatch(prefix + r"-(?:[0-9a-f]{8}|[0-9a-f]{17})", value) is not None,
            "invalid resource identifier")
    return value


def one(rows: object, reason: str) -> dict:
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), reason)
    return rows[0]


def token(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._:-]{16,64}", value) is not None,
            "invalid attempt token")
    return value


def recovery_user_data(nonce: str) -> bytes:
    """Offline, reviewable Linux witness; never executed by this verifier."""
    require(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce), "invalid recovery nonce")
    return ("#!/bin/sh\nset -eu\n"
            "kernel=$(uname -r)\narch=$(uname -m)\npid1=$(cat /proc/1/comm)\n"
            "if [ \"$arch\" != x86_64 ] || [ \"$pid1\" != systemd ]; then\n"
            f"  printf 'TESSRYN_RECOVERY_FAIL nonce={nonce}\\n' > /dev/ttyS0\n  exit 1\nfi\n"
            f"printf 'TESSRYN_RECOVERY_PASS nonce={nonce} kernel=%s arch=%s pid1=%s\\n' "
            '"$kernel" "$arch" "$pid1" > /dev/ttyS0\n').encode()


@dataclass(frozen=True)
class Capture:
    request: dict
    response: dict
    started: datetime
    completed: datetime
    format: str
    absence_basis: str | None = None


class CaptureSet:
    """Read immutable snapshots once, inside the supplied private bundle."""

    def __init__(self, index_path: Path, index: dict):
        self.root = index_path.parent.resolve()
        self.index = index
        self.started = timestamp(index["trial_started_at"])
        self.deadline = timestamp(index["trial_deadline_at"])
        require(self.started < self.deadline and self.deadline - self.started <= timedelta(hours=2),
                "invalid trial lifetime")
        self.rows = index["captures"]
        require(isinstance(self.rows, dict) and 1 <= len(self.rows) <= 128, "invalid capture set")
        require(all(isinstance(k, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", k) for k in self.rows),
                "invalid capture alias")
        self.used: set[str] = set()
        self.cache: dict[str, Capture] = {}
        self.raw_hashes: dict[str, str] = {}
        self.total_bytes = 0

    def read(self, ref: dict) -> bytes:
        require(isinstance(ref, dict) and set(ref) == {"path", "sha256", "size_bytes"}, "invalid file reference")
        name = ref["path"]
        require(isinstance(name, str) and name and "\\" not in name, "invalid relative capture path")
        path = PurePosixPath(name)
        require(not path.is_absolute() and name == str(path) and ".." not in path.parts,
                "capture path escapes bundle")
        require(isinstance(ref["sha256"], str) and HASH.fullmatch(ref["sha256"]) is not None
                and type(ref["size_bytes"]) is int and 0 <= ref["size_bytes"] <= MAX_CAPTURE_BYTES,
                "invalid capture size or hash")
        require(path.parts and path.parts[0] != ".", "invalid relative capture path")
        new_bytes = ref["size_bytes"] if name not in self.raw_hashes else 0
        require(self.total_bytes + new_bytes <= MAX_BUNDLE_BYTES, "capture bundle exceeds byte limit")
        raw = relative_bytes(self.root, path.parts)
        require(len(raw) == ref["size_bytes"] and hashlib.sha256(raw).hexdigest() == ref["sha256"],
                "capture file integrity mismatch")
        previous = self.raw_hashes.get(name)
        require(previous is None or previous == ref["sha256"], "capture file referenced with conflicting hashes")
        self.raw_hashes[name] = ref["sha256"]
        self.total_bytes += new_bytes
        return raw

    def _raw_capture(self, alias: str, operation: str) -> tuple[dict, bytes, bytes, datetime, datetime]:
        """Load the original bounded receipt without classifying service success."""
        require(isinstance(alias, str) and alias in self.rows, "capture alias missing")
        row = self.rows[alias]
        require(isinstance(row, dict) and set(row) == {
            "operation", "request", "region", "format", "tool_version", "started_at", "completed_at",
            "exit_status", "response", "stderr"}, "invalid capture envelope")
        require(row["operation"] == operation and row["region"] == self.index["region"]
                and row["format"] in FORMATS and isinstance(row["tool_version"], str)
                and 0 < len(row["tool_version"]) <= 256 and type(row["exit_status"]) is int
                and isinstance(row["request"], dict), "capture operation failed or differs")
        start, end = timestamp(row["started_at"]), timestamp(row["completed_at"])
        require(self.started <= start <= end <= self.deadline, "capture outside trial lifetime")
        raw = self.read(row["response"])
        stderr = self.read(row["stderr"])
        return row, raw, stderr, start, end

    def take(self, alias: str, operation: str) -> Capture:
        row, raw, _, start, end = self._raw_capture(alias, operation)
        require(row["exit_status"] == 0, "capture operation failed or differs")
        if alias in self.cache:
            return self.cache[alias]
        require(raw or operation in EMPTY_RESPONSES, "missing service response")
        response = capture_json(raw) if raw else {}
        require("Error" not in response and "Errors" not in response, "service response contains an error")
        require(response.get("Return", True) is True, "service operation returned false")
        metadata = response.get("ResponseMetadata", {})
        success_codes = {"StartSnapshot": {200, 201}, "PutSnapshotBlock": {200, 201},
                         "CompleteSnapshot": {200, 202}}.get(operation, {200})
        require(isinstance(metadata, dict) and type(metadata.get("HTTPStatusCode", 200)) is int
                and metadata.get("HTTPStatusCode", 200) in success_codes,
                "service response unsuccessful")
        result = Capture(row["request"], response, start, end, row["format"])
        self.used.add(alias)
        self.cache[alias] = result
        return result

    def take_volume_recycle_absence(self, alias: str, volume_id: str) -> Capture:
        """Accept only an exact-volume empty list or the specific provider absence error.

        Error receipts remain original errors and never enter the success cache.
        This checks supplied bytes, not AWS authenticity or permanent deletion.
        """
        identifier(volume_id, "vol")
        operation = "ListVolumesInRecycleBin"
        row, raw, stderr, start, end = self._raw_capture(alias, operation)
        require(row["request"] == {"VolumeIds": [volume_id]}, "volume Recycle Bin query differs")
        if row["exit_status"] == 0:
            result = self.take(alias, operation)
            require(result.response.get("Volumes") == [] and result.response.get("NextToken") is None,
                    "volume Recycle Bin absence is unconfirmed")
            return Capture(result.request, result.response, result.started, result.completed, result.format,
                           "successful_empty_list")
        if row["format"] == "aws_cli_v2_json":
            # This canonical legacy form is a future capture contract. A past
            # summary without the original bytes cannot be replayed through it.
            pattern = (rb"\n*An error occurred \(InvalidVolume\.NotFound\) when calling the "
                       rb"ListVolumesInRecycleBin operation: The volume '" + re.escape(volume_id.encode())
                       + rb"' does not exist\.?\n*")
            require(row["exit_status"] == 254 and raw == b"" and re.fullmatch(pattern, stderr) is not None,
                    "volume provider absence receipt differs")
            response = {}
        else:
            require(row["exit_status"] == 1 and stderr == b"" and raw,
                    "volume SDK absence capture failed or differs")
            response = capture_json(raw)
            require(set(response) == {"Error", "ResponseMetadata"}, "volume SDK error structure differs")
            error, metadata = response["Error"], response["ResponseMetadata"]
            require(isinstance(error, dict) and set(error) == {"Code", "Message"}
                    and error["Code"] == "InvalidVolume.NotFound" and isinstance(metadata, dict)
                    and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 400,
                    "volume SDK service error differs")
            request_id, message = metadata.get("RequestId"), error["Message"]
            require(isinstance(request_id, str)
                    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+=-]{0,255}", request_id) is not None
                    and isinstance(message, str) and re.fullmatch(r"[\x20-\x7e]{1,4096}", message) is not None
                    and re.findall(r"\bvol-[A-Za-z0-9_-]+", message) == [volume_id],
                    "volume SDK error target or request identity differs")
        self.used.add(alias)
        return Capture(row["request"], response, start, end, row["format"], "provider_volume_not_found")


    def take_snapshot_recycle_absence(self, alias: str, snapshot_id: str) -> Capture:
        """Classify one known-owned snapshot's original Recycle Bin observation.

        The caller binds ownership through the original snapshot/identity evidence.
        Only the specific SDK NotFound receipt is exceptional; it remains an error
        and never enters the success cache. This does not authenticate AWS origin.
        """
        identifier(snapshot_id, "snap")
        operation = "ListSnapshotsInRecycleBin"
        row, raw, stderr, start, end = self._raw_capture(alias, operation)
        require(self.index["region"] == "us-east-1"
                and isinstance(self.index["account_id"], str)
                and re.fullmatch(r"[0-9]{12}", self.index["account_id"]) is not None,
                "snapshot Recycle Bin context differs")
        require(row["request"] == {"SnapshotIds": [snapshot_id]}, "snapshot Recycle Bin query differs")
        if row["exit_status"] == 0:
            result = self.take(alias, operation)
            require(result.response.get("Snapshots") == [] and result.response.get("NextToken") is None,
                    "snapshot Recycle Bin absence is unconfirmed")
            return Capture(result.request, result.response, result.started, result.completed, result.format,
                           "successful_empty_list")
        require(row["format"] == "boto3_json" and row["exit_status"] == 1 and stderr == b"" and raw,
                "snapshot SDK absence capture failed or differs")
        response = capture_json(raw)
        require(set(response) == {"Error", "ResponseMetadata"}, "snapshot SDK error structure differs")
        error, metadata = response["Error"], response["ResponseMetadata"]
        require(isinstance(error, dict) and set(error) == {"Code", "Message"}
                and error["Code"] == "InvalidSnapshot.NotFound" and isinstance(metadata, dict)
                and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 400,
                "snapshot SDK service error differs")
        request_id, message = metadata.get("RequestId"), error["Message"]
        require(isinstance(request_id, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+=-]{0,255}", request_id) is not None
                and isinstance(message, str) and re.fullmatch(r"[\x20-\x7e]{1,4096}", message) is not None
                and re.findall(r"\bsnap-[A-Za-z0-9_-]+", message) == [snapshot_id],
                "snapshot SDK error target or request identity differs")
        self.used.add(alias)
        return Capture(row["request"], response, start, end, row["format"], "provider_snapshot_not_found")


def single_instance(response: dict) -> dict:
    reservation = one(response.get("Reservations"), "instance reservation count differs")
    return one(reservation.get("Instances"), "instance count differs")


def console(captures: CaptureSet, alias: str, instance_id: str, launch_time: datetime) -> tuple[bytes, Capture]:
    capture = captures.take(alias, "GetConsoleOutput")
    require(capture.request.get("InstanceId") == instance_id and capture.request.get("Latest") is True
            and capture.response.get("InstanceId") == instance_id, "console belongs to another request or instance")
    updated = timestamp(capture.response.get("Timestamp"))
    require(launch_time <= updated <= capture.completed + timedelta(seconds=120), "console buffer timestamp is stale")
    value = capture.response.get("Output")
    require(isinstance(value, str) and value, "console output missing")
    if capture.format == "boto3_json":
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("invalid SDK console encoding") from error
    else:
        raw = value.encode("utf-8")
    require(0 < len(raw) <= MAX_CAPTURE_BYTES, "console output exceeds capture bound")
    return raw, capture


def image(captures: CaptureSet, alias: str, account: str, snapshot_id: str, encrypted: bool) -> tuple[str, Capture]:
    capture = captures.take(alias, "DescribeImages")
    item = one(capture.response.get("Images"), "AMI count differs")
    ami_id = identifier(item.get("ImageId"), "ami")
    require(capture.request.get("ImageIds") == [ami_id] and not capture.response.get("NextToken"),
            "AMI query differs or is incomplete")
    require(item.get("OwnerId") == account and item.get("Public") is False and item.get("State") == "available"
            and item.get("Architecture") == "x86_64" and item.get("VirtualizationType") == "hvm"
            and item.get("BootMode") == "uefi" and item.get("RootDeviceType") == "ebs"
            and item.get("RootDeviceName") == "/dev/sda1", "AMI native metadata differs")
    mapping = one(item.get("BlockDeviceMappings"), "AMI must have exactly one root mapping")
    ebs = mapping.get("Ebs", {})
    require(mapping.get("DeviceName") == "/dev/sda1" and isinstance(ebs, dict)
            and ebs.get("SnapshotId") == snapshot_id and type(ebs.get("VolumeSize")) is int
            and ebs["VolumeSize"] == 1 and ebs.get("DeleteOnTermination") is True
            and ebs.get("Encrypted") is encrypted, "AMI root snapshot or policy differs")
    return ami_id, capture


def target_absent(captures: CaptureSet, alias: str, operation: str, collection: str,
                  filter_name: str, resource_id: str, account: str) -> Capture:
    capture = captures.take(alias, operation)
    expected = {"Filters": [{"Name": filter_name, "Values": [resource_id]}]}
    if operation == "DescribeImages":
        expected.update(Owners=[account], IncludeDeprecated=True, IncludeDisabled=True)
    if operation == "DescribeSnapshots":
        expected["OwnerIds"] = [account]
    require(capture.request == expected
            and not capture.response.get("NextToken") and capture.response.get(collection) == [],
            "resource absence query is mismatched or incomplete")
    return capture


def recycle_absent(captures: CaptureSet, alias: str, operation: str, collection: str,
                   parameter: str, resource_id: str) -> Capture:
    if operation == "ListVolumesInRecycleBin":
        require(collection == "Volumes" and parameter == "VolumeIds", "invalid volume absence contract")
        return captures.take_volume_recycle_absence(alias, resource_id)
    if operation == "ListSnapshotsInRecycleBin":
        require(collection == "Snapshots" and parameter == "SnapshotIds", "invalid snapshot absence contract")
        return captures.take_snapshot_recycle_absence(alias, resource_id)
    capture = captures.take(alias, operation)
    require(capture.request == {parameter: [resource_id]} and capture.response.get(collection) == []
            and capture.response.get("NextToken") is None,
            "resource Recycle Bin absence is unconfirmed")
    return capture


def boot(captures: CaptureSet, spec: dict, role: str, ami_id: str, snapshot_id: str,
         encrypted: bool, root_device: str = "/dev/sda1", legacy_devices: tuple[str, ...] = ()) -> dict:
    from tools.aws_native_serial import parse_native_serial
    keys = {"launch", "running", "root", "console", "terminate", "terminated", "volume_absent", "eni_absent",
            "volume_recycle_absent"}
    if role == "recovery":
        keys |= {"image_id", "nonce"}
    require(isinstance(spec, dict) and set(spec) == keys, "invalid boot capture specification")
    launch = captures.take(spec["launch"], "RunInstances")
    request = launch.request
    require(request.get("ImageId") == ami_id and request.get("InstanceType") == captures.index["instance_type"]
            and type(request.get("MinCount")) is int and request["MinCount"] == 1
            and type(request.get("MaxCount")) is int and request["MaxCount"] == 1
            and not request.get("IamInstanceProfile"), "launch image or count differs")
    require(not legacy_devices or role == "recovery", "native launch cannot suppress legacy devices")
    overrides = request.get("BlockDeviceMappings", [])
    require(isinstance(overrides, list) and len(overrides) <= 1 + len(legacy_devices),
            "launch must not add another disk")
    suppressed, root_override = set(), False
    for override in overrides:
        require(isinstance(override, dict), "invalid launch mapping")
        device = override.get("DeviceName")
        if device == root_device:
            override_ebs = override.get("Ebs")
            require(not root_override and set(override) == {"DeviceName", "Ebs"}
                    and isinstance(override_ebs, dict) and override_ebs.get("SnapshotId", snapshot_id) == snapshot_id,
                    "launch overrides the approved root snapshot")
            root_override = True
        else:
            require(role == "recovery" and set(override) == {"DeviceName", "NoDevice"}
                    and isinstance(device, str) and device in legacy_devices and device not in suppressed
                    and override["NoDevice"] == "", "launch legacy-device suppression differs")
            suppressed.add(device)
    require(suppressed == set(legacy_devices), "recovery launch must suppress every legacy device")
    client_token = token(request.get("ClientToken"))
    launched = one(launch.response.get("Instances"), "launch returned multiple instances")
    instance_id = identifier(launched.get("InstanceId"), "i")
    require(launched.get("ImageId") == ami_id and launched.get("ClientToken") == client_token
            and launch.response.get("OwnerId") == captures.index["account_id"],
            "launch response identity differs")
    observed = captures.take(spec["running"], "DescribeInstances")
    require(observed.request.get("InstanceIds") == [instance_id] and not observed.response.get("NextToken")
            and launch.completed <= observed.started, "running query identity or order differs")
    item = single_instance(observed.response)
    require(one(observed.response.get("Reservations"), "reservation missing").get("OwnerId")
            == captures.index["account_id"], "running reservation owner differs")
    require(item.get("InstanceId") == instance_id and item.get("ImageId") == ami_id
            and item.get("ClientToken") == client_token and item.get("InstanceType") == captures.index["instance_type"]
            and item.get("State") == {"Code": 16, "Name": "running"}
            and item.get("Architecture") == "x86_64" and item.get("VirtualizationType") == "hvm"
            and not item.get("PublicIpAddress") and not item.get("IamInstanceProfile"), "running instance differs")
    if role != "recovery":
        require(item.get("BootMode") == "uefi" and item.get("CurrentInstanceBootMode") == "uefi",
                "native instance did not boot in UEFI")
    launch_time = timestamp(item.get("LaunchTime"))
    require(launch.started - timedelta(seconds=120) <= launch_time <= launch.completed + timedelta(seconds=120),
            "instance launch time is outside request window")
    eni = one(item.get("NetworkInterfaces"), "instance must have one primary interface")
    eni_id = identifier(eni.get("NetworkInterfaceId"), "eni")
    attachment = eni.get("Attachment", {})
    require(isinstance(attachment, dict) and attachment.get("DeviceIndex") == 0 and not eni.get("Association")
            and launch.started - timedelta(seconds=120) <= timestamp(attachment.get("AttachTime"))
            <= launch.completed + timedelta(seconds=120), "primary interface is not fresh or private")
    mapping = one(item.get("BlockDeviceMappings"), "instance must have one root volume")
    ebs = mapping.get("Ebs", {})
    require(item.get("RootDeviceName") == root_device and mapping.get("DeviceName") == root_device and isinstance(ebs, dict)
            and ebs.get("DeleteOnTermination") is True, "root deletion policy differs")
    volume_id = identifier(ebs.get("VolumeId"), "vol")
    volume = captures.take(spec["root"], "DescribeVolumes")
    require(volume.request.get("VolumeIds") == [volume_id] and not volume.response.get("NextToken")
            and observed.completed <= volume.started,
            "root volume query differs or is incomplete")
    disk = one(volume.response.get("Volumes"), "root volume count differs")
    attached = one(disk.get("Attachments"), "root attachment count differs")
    require(disk.get("VolumeId") == volume_id and disk.get("Encrypted") is encrypted
            and disk.get("State") == "in-use" and attached.get("InstanceId") == instance_id
            and attached.get("VolumeId") == volume_id and attached.get("Device") == root_device
            and attached.get("State") == "attached", "actual root attachment differs")
    require(disk.get("SnapshotId") == snapshot_id, "actual root snapshot differs from approved image")
    if role != "recovery":
        require(root_device == "/dev/sda1" and type(disk.get("Size")) is int and disk["Size"] == 1,
                "actual native root does not contain verified snapshot")
    raw, serial_capture = console(captures, spec["console"], instance_id, launch_time)
    require(observed.completed <= serial_capture.started and volume.completed <= serial_capture.started,
            "serial observation precedes resource observation")
    if role == "recovery":
        nonce = spec["nonce"]
        expected_script = recovery_user_data(nonce)
        try:
            script = base64.b64decode(request.get("UserData", ""), validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("invalid recovery user-data encoding") from error
        require(script == expected_script, "recovery nonce is not bound to preregistered execution script")
        marker = rb"(?m)^TESSRYN_RECOVERY_PASS nonce=" + nonce.encode() + rb" kernel=([A-Za-z0-9._+-]{1,128}) arch=x86_64 pid1=systemd\r?$"
        matches = re.findall(marker, raw)
        require(len(matches) == 1 and b"TESSRYN_RECOVERY_FAIL" not in raw and b"TESSRYN_K01_PASS" not in raw,
                "known-good recovery lacks a fresh Linux execution witness")
        serial = {"status": "parsed", "sha256": hashlib.sha256(raw).hexdigest(),
                  "kernel_release_sha256": hashlib.sha256(matches[0]).hexdigest(),
                  "nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest()}
    else:
        serial = parse_native_serial(raw)
    termination = captures.take(spec["terminate"], "TerminateInstances")
    require(termination.request.get("InstanceIds") == [instance_id] and serial_capture.completed <= termination.started,
            "termination identity or order differs")
    transition = one(termination.response.get("TerminatingInstances"), "termination count differs")
    require(transition.get("InstanceId") == instance_id and transition.get("CurrentState", {}).get("Name")
            in {"shutting-down", "terminated"}, "external termination was not acknowledged")
    ended = captures.take(spec["terminated"], "DescribeInstances")
    require(ended.request.get("InstanceIds") == [instance_id] and not ended.response.get("NextToken")
            and termination.completed <= ended.started, "termination confirmation identity or order differs")
    final = single_instance(ended.response)
    require(final.get("InstanceId") == instance_id and final.get("State") == {"Code": 48, "Name": "terminated"},
            "instance termination is unconfirmed")
    volume_absent = target_absent(captures, spec["volume_absent"], "DescribeVolumes", "Volumes", "volume-id", volume_id,
                                 captures.index["account_id"])
    eni_absent = target_absent(captures, spec["eni_absent"], "DescribeNetworkInterfaces", "NetworkInterfaces",
                              "network-interface-id", eni_id, captures.index["account_id"])
    require(ended.completed <= volume_absent.started and ended.completed <= eni_absent.started,
            "resource cleanup was observed before termination")
    recycled = recycle_absent(captures, spec["volume_recycle_absent"], "ListVolumesInRecycleBin", "Volumes", "VolumeIds",
                             volume_id)
    require(volume_absent.completed <= recycled.started, "volume retention observation precedes deletion")
    return {"role": role, "instance_id": instance_id, "client_token": client_token, "volume_id": volume_id,
            "eni_id": eni_id, "started": launch.started, "ended": max(recycled.completed, eni_absent.completed),
            "observations": serial, "root_retention": {"basis": recycled.absence_basis,
                                                      "capture_completed_at": recycled.completed.isoformat()}}


def verify(index_path: Path, manifest_path: Path) -> dict:
    from tools.aws_native_snapshot import verify_snapshot
    index_raw, manifest_raw = regular_bytes(index_path), regular_bytes(manifest_path)
    index, manifest = capture_json(index_raw), capture_json(manifest_raw)
    require(index.get("schema_version") == 1 and index.get("format") == "tessryn-aws-native-capture"
            and index.get("capture_kind") in {"operator_capture", "synthetic_fixture"}, "invalid native capture index")
    require(isinstance(index.get("account_id"), str) and re.fullmatch(r"[0-9]{12}", index["account_id"])
            and isinstance(index.get("region"), str) and re.fullmatch(r"[a-z]{2}-[a-z]+-\d", index["region"])
            and isinstance(index.get("instance_type"), str) and re.fullmatch(r"[a-z][a-z0-9]*\.[a-z0-9]+", index["instance_type"])
            and type(index.get("encrypted")) is bool, "invalid exact platform identity")
    require(index.get("artifact_manifest_sha256") == hashlib.sha256(manifest_raw).hexdigest()
            and manifest.get("source", {}).get("dirty") is False
            and re.fullmatch(r"[0-9a-f]{40}", manifest.get("source", {}).get("revision", ""))
            and HASH.fullmatch(manifest.get("source", {}).get("tree_sha256", "")), "artifact/source binding differs")
    _, expected_disk = selected_artifact(manifest_path, manifest, "normal")
    captures = CaptureSet(index_path, index)
    identity = captures.take(index["identity"], "GetCallerIdentity")
    require(identity.request == {} and identity.response.get("Account") == index["account_id"], "capture account differs")
    type_capture = captures.take(index["type"], "DescribeInstanceTypes")
    declared = one(type_capture.response.get("InstanceTypes"), "type count differs")
    require(type_capture.request.get("InstanceTypes") == [index["instance_type"]]
            and declared.get("InstanceType") == index["instance_type"] and not type_capture.response.get("NextToken")
            and declared.get("BareMetal") is False
            and "uefi" in declared.get("SupportedBootModes", [])
            and "x86_64" in declared.get("ProcessorInfo", {}).get("SupportedArchitectures", []),
            "exact type does not establish x64 UEFI support")
    snapshot = verify_snapshot(captures, index["snapshot"], expected_disk, index["account_id"], index["encrypted"])
    ami_id, ami_capture = image(captures, index["image"], index["account_id"], snapshot["snapshot_id"], index["encrypted"])
    require(timestamp(snapshot["completed_at"]) <= ami_capture.started, "AMI observation precedes verified snapshot readback")
    recovery_id = identifier(index["recovery"]["image_id"], "ami")
    require(recovery_id != ami_id, "recovery image must be independent")
    recovery_image = captures.take(index["recovery_image"], "DescribeImages")
    good_image = one(recovery_image.response.get("Images"), "recovery image count differs")
    require(isinstance(index.get("recovery_image_owner"), str)
            and re.fullmatch(r"[0-9]{12}", index["recovery_image_owner"])
            and recovery_image.request.get("ImageIds") == [recovery_id] and not recovery_image.response.get("NextToken")
            and good_image.get("ImageId") == recovery_id and good_image.get("OwnerId") == index["recovery_image_owner"]
            and good_image.get("State") == "available" and good_image.get("Architecture") == "x86_64"
            and good_image.get("VirtualizationType") == "hvm" and good_image.get("RootDeviceType") == "ebs",
            "approved known-good recovery image metadata differs")
    recovery_device = good_image.get("RootDeviceName")
    require(isinstance(recovery_device, str) and re.fullmatch(r"/dev/[a-z0-9]{1,16}", recovery_device),
            "recovery image root device differs")
    mappings = good_image.get("BlockDeviceMappings")
    require(isinstance(mappings, list) and 1 <= len(mappings) <= 1 + MAX_RECOVERY_EPHEMERAL_MAPPINGS,
            "recovery image mapping count differs")
    recovery_mapping, legacy_devices, virtual_names, seen_devices = None, set(), set(), set()
    for mapping in mappings:
        require(isinstance(mapping, dict), "invalid recovery image mapping")
        device = mapping.get("DeviceName")
        require(isinstance(device, str) and re.fullmatch(r"/dev/[a-z0-9]{1,16}", device)
                and device not in seen_devices, "recovery image devices are invalid or duplicated")
        seen_devices.add(device)
        if device == recovery_device:
            require(set(mapping) == {"DeviceName", "Ebs"} and isinstance(mapping["Ebs"], dict),
                    "recovery image root mapping differs")
            recovery_mapping = mapping
        else:
            virtual = mapping.get("VirtualName")
            require(set(mapping) == {"DeviceName", "VirtualName"} and isinstance(virtual, str)
                    and re.fullmatch(r"ephemeral(?:0|[1-9][0-9]?)", virtual) and virtual not in virtual_names,
                    "recovery image legacy mapping differs")
            legacy_devices.add(device)
            virtual_names.add(virtual)
    require(recovery_mapping is not None and (not legacy_devices or declared.get("InstanceStorageSupported") is False),
            "recovery legacy mappings require an EBS-only instance type")
    recovery_snapshot = identifier(recovery_mapping["Ebs"].get("SnapshotId"), "snap")
    a = boot(captures, index["native_a"], "native_a", ami_id, snapshot["snapshot_id"], index["encrypted"])
    recovery = boot(captures, index["recovery"], "recovery", recovery_id, recovery_snapshot,
                    index["encrypted"], recovery_device, tuple(sorted(legacy_devices)))
    b = boot(captures, index["native_b"], "native_b", ami_id, snapshot["snapshot_id"], index["encrypted"])
    phases = [a, recovery, b]
    for key in ("instance_id", "client_token", "volume_id", "eni_id"):
        require(len({row[key] for row in phases}) == 3, "phase resources or launch tokens are reused")
    require(ami_capture.completed <= a["started"] and identity.completed <= a["started"]
            and type_capture.completed <= a["started"] and a["ended"] <= recovery["started"]
            and recovery_image.completed <= recovery["started"]
            and recovery["ended"] <= b["started"], "boot and independent recovery phases overlap or are unordered")
    cleanup = index["cleanup"]
    deregister = captures.take(cleanup["deregister"], "DeregisterImage")
    require(deregister.request.get("ImageId") == ami_id and b["ended"] <= deregister.started,
            "AMI cleanup identity or order differs")
    absent_image = target_absent(captures, cleanup["image_absent"], "DescribeImages", "Images", "image-id", ami_id,
                                index["account_id"])
    image_recycled = recycle_absent(captures, cleanup["image_recycle_absent"], "ListImagesInRecycleBin", "Images",
                                   "ImageIds", ami_id)
    require(absent_image.completed <= image_recycled.started, "AMI retention observation precedes removal")
    deletion = captures.take(cleanup["delete_snapshot"], "DeleteSnapshot")
    require(deletion.request.get("SnapshotId") == snapshot["snapshot_id"]
            and deregister.completed <= absent_image.started and image_recycled.completed <= deletion.started,
            "snapshot deletion precedes confirmed image removal")
    absent_snapshot = target_absent(captures, cleanup["snapshot_absent"], "DescribeSnapshots", "Snapshots", "snapshot-id",
                                   snapshot["snapshot_id"], index["account_id"])
    require(deletion.completed <= absent_snapshot.started, "snapshot absence precedes deletion")
    snapshot_recycled = recycle_absent(captures, cleanup["snapshot_recycle_absent"], "ListSnapshotsInRecycleBin", "Snapshots",
                                      "SnapshotIds", snapshot["snapshot_id"])
    require(absent_snapshot.completed <= snapshot_recycled.started, "snapshot retention observation precedes deletion")
    for kind, alias in (("EBS_VOLUME", cleanup["volume_retention_rules"]),
                        ("EBS_SNAPSHOT", cleanup["snapshot_retention_rules"]),
                        ("EC2_IMAGE", cleanup["image_retention_rules"])):
        retention = captures.take(alias, "ListRules")
        require(retention.request == {"ResourceType": kind} and retention.response.get("Rules") == []
                and retention.response.get("NextToken") is None and snapshot_recycled.completed <= retention.started,
                "retention rules require explicit owner assessment")
    require(captures.used == set(captures.rows), "unreviewed capture operations remain")
    digest = hashlib.sha256(local_evaluator_hash().encode())
    for name in ("tools/verify_aws_native.py", "tools/aws_native_serial.py", "tools/aws_native_snapshot.py",
                 "tools/g03/evidence.py"):
        digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes() + b"\0")
    return {"format": "tessryn-aws-native-evidence-review", "schema_version": 1, "status": "needs_owner_review",
            "capture_kind": index["capture_kind"], "capture_origin": "unverified_offline",
            "evidence_consistency": "pass", "native_qualification": "requires_trusted_capture_and_authorization_review",
            "scope": "one exact EC2 virtualized CPU profile; native devices/GPU/inference and physical hardware unqualified",
            "source": {key: manifest["source"][key] for key in ("revision", "tree_sha256", "dirty")},
            "artifact_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "logical_disk_sha256": expected_disk["sha256"], "capture_index_sha256": hashlib.sha256(index_raw).hexdigest(),
            "evaluator_sha256": digest.hexdigest(), "profile": {"region": index["region"], "instance_type": index["instance_type"],
            "boot_mode": "uefi", "encrypted": index["encrypted"]},
            "phases": [{"role": row["role"], "observations": row["observations"],
                        "root_retention": row["root_retention"]} for row in phases],
            "cleanup": "time_bound_resource_and_recycle_bin_absence_with_no_current_retention_rules_in_supplied_captures",
            "snapshot_retention": {"basis": snapshot_recycled.absence_basis,
                                   "capture_completed_at": snapshot_recycled.completed.isoformat()},
            "private_capture_files": len(captures.raw_hashes)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.capture, args.manifest)
        if args.out:
            with args.out.open("x") as stream:
                stream.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ImportError) as error:
        parser.exit(1, f"Native capture rejected: {type(error).__name__}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
