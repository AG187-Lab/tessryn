"""SYNTHETIC capture integration, never native AWS execution evidence.

All AWS receipts and resource IDs below are constructed in temporary directories.
The native console text is one retained LOCAL QEMU phase. Selected local media
and snapshot readback are mocked here; their independent real-format tests live
in test_aws_media and test_aws_native_snapshot.
"""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import verify_aws_native as verifier
from tools import aws_native_snapshot


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
OWNER = "210987654321"
AMI = "ami-00000000000000011"
RECOVERY_AMI = "ami-00000000000000022"
SNAPSHOT = "snap-00000000000000033"
RECOVERY_SNAPSHOT = "snap-00000000000000044"
NONCE = "0123456789abcdef0123456789abcdef"
BASE = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)


def stamp(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat()


class SyntheticCaptureBundle:
    def __init__(self, root):
        self.root = root
        self.responses = {}
        self.clock = 0
        self.manifest_path = root / "artifact-manifest.json"
        self.index_path = root / "capture-index.json"
        self.manifest = {"source": {"revision": "5ea06b998fcc854851e794aea6235b15fa34be65",
                                    "tree_sha256": "a" * 64, "dirty": False}}
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.disk = {"sha256": "b" * 64}
        self.index = {"schema_version": 1, "format": "tessryn-aws-native-capture",
                      "capture_kind": "synthetic_fixture", "account_id": ACCOUNT,
                      "region": "us-east-1", "instance_type": "t3a.small", "encrypted": True,
                      "artifact_manifest_sha256": hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
                      "trial_started_at": stamp(0), "trial_deadline_at": stamp(7200), "captures": {},
                      "identity": "identity", "type": "type", "snapshot": {"ready": "snapshot_ready"},
                      "image": "image", "recovery_image": "recovery_image", "recovery_image_owner": OWNER}
        self.add("identity", "GetCallerIdentity", {}, {"Account": ACCOUNT})
        self.add("type", "DescribeInstanceTypes", {"InstanceTypes": ["t3a.small"]},
                 {"InstanceTypes": [{"InstanceType": "t3a.small", "BareMetal": False,
                                     "SupportedBootModes": ["legacy-bios", "uefi"],
                                     "ProcessorInfo": {"SupportedArchitectures": ["x86_64"]}}]})
        self.add("snapshot_ready", "DescribeSnapshots", {"SnapshotIds": [SNAPSHOT]},
                 {"Snapshots": [{"SnapshotId": SNAPSHOT, "State": "completed", "VolumeSize": 1,
                                 "OwnerId": ACCOUNT, "Encrypted": True}]})
        image = {"ImageId": AMI, "OwnerId": ACCOUNT, "Public": False, "State": "available",
                 "Architecture": "x86_64", "VirtualizationType": "hvm", "BootMode": "uefi",
                 "RootDeviceType": "ebs", "RootDeviceName": "/dev/sda1",
                 "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": SNAPSHOT,
                                          "VolumeSize": 1, "DeleteOnTermination": True, "Encrypted": True}}]}
        self.add("image", "DescribeImages", {"ImageIds": [AMI]}, {"Images": [image]})
        self.add("recovery_image", "DescribeImages", {"ImageIds": [RECOVERY_AMI]},
                 {"Images": [{"ImageId": RECOVERY_AMI, "OwnerId": OWNER, "State": "available",
                              "Architecture": "x86_64", "VirtualizationType": "hvm", "RootDeviceType": "ebs",
                              "RootDeviceName": "/dev/sda1", "BlockDeviceMappings": [{
                                  "DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": RECOVERY_SNAPSHOT}}]}]})
        self.native_serial = (ROOT / "evidence/k01-aws-preparation/headless/normal/stdout.log").read_bytes()[:1172]
        self.index["native_a"] = self.phase("a", 101, AMI, self.native_serial)
        recovery_serial = (f"Ubuntu recovery fixture\nTESSRYN_RECOVERY_PASS nonce={NONCE} "
                           "kernel=6.14.0-1023-aws arch=x86_64 pid1=systemd\n").encode()
        self.index["recovery"] = self.phase("r", 102, RECOVERY_AMI, recovery_serial, recovery=True)
        self.index["native_b"] = self.phase("b", 103, AMI, self.native_serial)
        self.index["cleanup"] = {key: key for key in ("deregister", "image_absent", "image_recycle_absent",
                                  "delete_snapshot", "snapshot_absent", "snapshot_recycle_absent",
                                  "volume_retention_rules", "snapshot_retention_rules", "image_retention_rules")}
        self.add("deregister", "DeregisterImage", {"ImageId": AMI}, b"")
        self.add("image_absent", "DescribeImages", {"Owners": [ACCOUNT], "IncludeDeprecated": True, "IncludeDisabled": True,
                 "Filters": [{"Name": "image-id", "Values": [AMI]}]}, {"Images": []})
        self.add("image_recycle_absent", "ListImagesInRecycleBin", {"ImageIds": [AMI]}, {"Images": []})
        self.add("delete_snapshot", "DeleteSnapshot", {"SnapshotId": SNAPSHOT}, b"")
        self.add("snapshot_absent", "DescribeSnapshots", {"OwnerIds": [ACCOUNT],
                 "Filters": [{"Name": "snapshot-id", "Values": [SNAPSHOT]}]}, {"Snapshots": []})
        self.add("snapshot_recycle_absent", "ListSnapshotsInRecycleBin", {"SnapshotIds": [SNAPSHOT]}, {"Snapshots": []})
        self.add("volume_retention_rules", "ListRules", {"ResourceType": "EBS_VOLUME"}, {"Rules": []})
        self.add("snapshot_retention_rules", "ListRules", {"ResourceType": "EBS_SNAPSHOT"}, {"Rules": []})
        self.add("image_retention_rules", "ListRules", {"ResourceType": "EC2_IMAGE"}, {"Rules": []})

    def ref(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}

    def add(self, alias, operation, request, response):
        start, end = self.clock, self.clock + 1
        self.clock += 2
        self.responses[alias] = response
        raw = response if isinstance(response, bytes) else json.dumps(response).encode()
        row = {"operation": operation, "request": request, "region": self.index["region"],
               "format": "aws_cli_v2_json", "tool_version": "aws-cli/2 synthetic fixture",
               "started_at": stamp(start), "completed_at": stamp(end), "exit_status": 0,
               "response": self.ref(alias + ".json", raw), "stderr": self.ref(alias + ".stderr", b"")}
        self.index["captures"][alias] = row
        return row

    def update(self, alias):
        response = self.responses[alias]
        raw = response if isinstance(response, bytes) else json.dumps(response).encode()
        self.index["captures"][alias]["response"] = self.ref(alias + ".json", raw)

    def volume_not_found(self, alias, sdk=False):
        """Create a SYNTHETIC receipt, never reconstruct a historical AWS error."""
        row = self.index["captures"][alias]
        volume = row["request"]["VolumeIds"][0]
        message = f"The volume '{volume}' does not exist."
        if sdk:
            row["format"], row["exit_status"] = "boto3_json", 1
            self.responses[alias] = {"Error": {"Code": "InvalidVolume.NotFound", "Message": message},
                                     "ResponseMetadata": {"HTTPStatusCode": 400,
                                       "RequestId": "PRIVATE_SYNTHETIC_REQUEST_ID", "RetryAttempts": 0,
                                       "HTTPHeaders": {"x-amzn-requestid": "PRIVATE_SYNTHETIC_REQUEST_ID"}}}
            stderr = b""
        else:
            row["format"], row["exit_status"] = "aws_cli_v2_json", 254
            self.responses[alias] = b""
            stderr = ("\nAn error occurred (InvalidVolume.NotFound) when calling the "
                      f"ListVolumesInRecycleBin operation: {message}\n").encode()
        self.update(alias)
        row["stderr"] = self.ref(alias + ".stderr", stderr)

    def legacy_recovery(self):
        """Full SYNTHETIC AMI metadata plus original launch suppressions."""
        image = self.responses["recovery_image"]["Images"][0]
        image.update(Name="SYNTHETIC_CANONICAL_RECOVERY_IMAGE", BootMode="uefi",
                     Description="PRIVATE_SYNTHETIC_AMI_DESCRIPTION")
        root = image["BlockDeviceMappings"][0]
        root["Ebs"].update(VolumeSize=8, VolumeType="gp3", Encrypted=False, DeleteOnTermination=True)
        image["BlockDeviceMappings"] = [root, {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"},
                                              {"DeviceName": "/dev/sdc", "VirtualName": "ephemeral1"}]
        self.responses["type"]["InstanceTypes"][0]["InstanceStorageSupported"] = False
        self.index["captures"]["r_launch"]["request"]["BlockDeviceMappings"] = [
            {"DeviceName": "/dev/sdb", "NoDevice": ""}, {"DeviceName": "/dev/sdc", "NoDevice": ""}]
        self.update("recovery_image")
        self.update("type")

    def phase(self, label, number, image, serial, recovery=False):
        instance, volume, eni = (f"{prefix}-{number:017x}" for prefix in ("i", "vol", "eni"))
        client = f"synthetic-{label}-launch-unique-token"
        launch_time = stamp(self.clock)
        spec = {key: f"{label}_{key}" for key in ("launch", "running", "root", "console", "terminate",
                                                  "terminated", "volume_absent", "eni_absent", "volume_recycle_absent")}
        request = {"ImageId": image, "InstanceType": "t3a.small", "MinCount": 1, "MaxCount": 1,
                   "ClientToken": client}
        if recovery:
            spec.update(image_id=image, nonce=NONCE)
            script = verifier.recovery_user_data(NONCE)
            request["UserData"] = base64.b64encode(script).decode()
        self.add(spec["launch"], "RunInstances", request,
                 {"OwnerId": ACCOUNT, "Instances": [{"InstanceId": instance, "ImageId": image, "ClientToken": client}]})
        running = {"InstanceId": instance, "ImageId": image, "ClientToken": client,
                   "InstanceType": "t3a.small", "State": {"Code": 16, "Name": "running"},
                   "Architecture": "x86_64", "VirtualizationType": "hvm", "Hypervisor": "xen",
                   "BootMode": "uefi", "CurrentInstanceBootMode": "uefi", "LaunchTime": launch_time,
                   "RootDeviceName": "/dev/sda1", "RootDeviceType": "ebs",
                   "NetworkInterfaces": [{"NetworkInterfaceId": eni,
                                          "Attachment": {"DeviceIndex": 0, "AttachTime": launch_time}}],
                   "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {
                       "VolumeId": volume, "DeleteOnTermination": True}}]}
        self.add(spec["running"], "DescribeInstances", {"InstanceIds": [instance]},
                 {"Reservations": [{"OwnerId": ACCOUNT, "Instances": [running]}]})
        self.add(spec["root"], "DescribeVolumes", {"VolumeIds": [volume]},
                 {"Volumes": [{"VolumeId": volume, "Encrypted": True, "State": "in-use", "Size": 8 if recovery else 1,
                               "SnapshotId": SNAPSHOT if not recovery else RECOVERY_SNAPSHOT,
                               "Attachments": [{"InstanceId": instance, "VolumeId": volume,
                                                "Device": "/dev/sda1", "State": "attached"}]}]})
        self.add(spec["console"], "GetConsoleOutput", {"InstanceId": instance, "Latest": True},
                 {"InstanceId": instance, "Timestamp": stamp(self.clock), "Output": serial.decode()})
        self.add(spec["terminate"], "TerminateInstances", {"InstanceIds": [instance]},
                 {"TerminatingInstances": [{"InstanceId": instance,
                                            "CurrentState": {"Code": 32, "Name": "shutting-down"}}]})
        self.add(spec["terminated"], "DescribeInstances", {"InstanceIds": [instance]},
                 {"Reservations": [{"OwnerId": ACCOUNT, "Instances": [{"InstanceId": instance,
                                                    "State": {"Code": 48, "Name": "terminated"}}]}]})
        self.add(spec["volume_absent"], "DescribeVolumes", {"Filters": [
                 {"Name": "volume-id", "Values": [volume]}]}, {"Volumes": []})
        self.add(spec["eni_absent"], "DescribeNetworkInterfaces", {"Filters": [
                 {"Name": "network-interface-id", "Values": [eni]}]}, {"NetworkInterfaces": []})
        self.add(spec["volume_recycle_absent"], "ListVolumesInRecycleBin", {"VolumeIds": [volume]}, {"Volumes": []})
        return spec

    def write(self):
        self.index_path.write_text(json.dumps(self.index))

    def verify(self):
        self.write()

        def snapshot(captures, spec, disk, account, encrypted):
            ready = captures.take(spec["ready"], "DescribeSnapshots")
            return {"snapshot_id": SNAPSHOT, "completed_at": ready.completed.isoformat()}

        with patch.object(verifier, "selected_artifact", return_value=(b"SYNTHETIC EFI", self.disk)), patch.object(
                aws_native_snapshot, "verify_snapshot", side_effect=snapshot):
            return verifier.verify(self.index_path, self.manifest_path)


class SyntheticNativeIntakeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tessryn-synthetic-native-")
        self.bundle = SyntheticCaptureBundle(Path(self.directory.name))
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def tearDown(self):
        self.directory.cleanup()

    def reject(self):
        with self.assertRaises((OSError, ValueError, KeyError, TypeError)):
            self.bundle.verify()

    def test_valid_synthetic_sequence_is_only_consistent_needs_owner_review(self):
        result = self.bundle.verify()
        self.assertEqual(result["status"], "needs_owner_review")
        self.assertEqual(result["capture_kind"], "synthetic_fixture")
        self.assertEqual(result["capture_origin"], "unverified_offline")
        self.assertEqual(result["evidence_consistency"], "pass")
        encoded = json.dumps(result)
        for private in (ACCOUNT, OWNER, AMI, RECOVERY_AMI, SNAPSHOT, "i-00000000000000065", NONCE):
            self.assertNotIn(private, encoded)
        self.assertEqual([row["role"] for row in result["phases"]], ["native_a", "recovery", "native_b"])

    def test_claiming_operator_origin_does_not_bypass_owner_review(self):
        self.bundle.index["capture_kind"] = "operator_capture"
        result = self.bundle.verify()
        self.assertEqual(result["status"], "needs_owner_review")
        self.assertEqual(result["capture_origin"], "unverified_offline")

    def test_actual_root_snapshot_and_mapping_override_are_enforced(self):
        del self.bundle.responses["a_root"]["Volumes"][0]["SnapshotId"]
        self.bundle.update("a_root")
        self.reject()
        self.bundle.responses["a_root"]["Volumes"][0]["SnapshotId"] = SNAPSHOT
        self.bundle.update("a_root")
        self.bundle.index["captures"]["a_launch"]["request"]["BlockDeviceMappings"] = [
            {"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": "snap-00000000000000099"}}]
        self.reject()

    def test_root_policy_only_overrides_inherit_or_match_approved_snapshots(self):
        for label, snapshot, size in (("a", SNAPSHOT, 1), ("r", RECOVERY_SNAPSHOT, 8), ("b", SNAPSHOT, 1)):
            self.bundle.index["captures"][label + "_launch"]["request"]["BlockDeviceMappings"] = [{
                "DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": size, "VolumeType": "gp3",
                                                         "Encrypted": True, "DeleteOnTermination": True}}]
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")
        for label, snapshot in (("a", SNAPSHOT), ("r", RECOVERY_SNAPSHOT), ("b", SNAPSHOT)):
            self.bundle.index["captures"][label + "_launch"]["request"]["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"] = snapshot
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_foreign_recovery_snapshot_or_added_root_override_cannot_pass(self):
        self.bundle.index["captures"]["r_launch"]["request"]["BlockDeviceMappings"] = [{
            "DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": SNAPSHOT}}]
        self.reject()
        self.bundle.index["captures"]["r_launch"]["request"]["BlockDeviceMappings"] = []
        self.bundle.responses["r_root"]["Volumes"][0]["SnapshotId"] = SNAPSHOT
        self.bundle.update("r_root")
        self.reject()

    def test_full_recovery_ami_legacy_mappings_are_preserved_and_explicitly_suppressed(self):
        self.bundle.legacy_recovery()
        image = self.bundle.responses["recovery_image"]["Images"][0]
        image["BlockDeviceMappings"] = list(reversed(image["BlockDeviceMappings"]))
        self.bundle.update("recovery_image")
        raw_path = self.bundle.root / self.bundle.index["captures"]["recovery_image"]["response"]["path"]
        original_bytes = raw_path.read_bytes()
        original_image = copy.deepcopy(image)
        result = self.bundle.verify()
        self.assertEqual(result["status"], "needs_owner_review")
        self.assertEqual(result["capture_origin"], "unverified_offline")
        self.assertEqual(result["capture_kind"], "synthetic_fixture")
        self.assertEqual(raw_path.read_bytes(), original_bytes)
        self.assertEqual(image, original_image)
        self.assertNotIn("PRIVATE_SYNTHETIC_AMI_DESCRIPTION", json.dumps(result))

    def test_recovery_legacy_suppression_allows_one_matching_or_inherited_root_policy_override(self):
        self.bundle.legacy_recovery()
        request = self.bundle.index["captures"]["r_launch"]["request"]
        request["BlockDeviceMappings"].insert(1, {"DeviceName": "/dev/sda1", "Ebs": {
            "VolumeSize": 8, "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}})
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")
        request["BlockDeviceMappings"][1]["Ebs"]["SnapshotId"] = RECOVERY_SNAPSHOT
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_recovery_legacy_ami_rejects_extra_ebs_and_mixed_or_malformed_virtual_mappings(self):
        self.bundle.legacy_recovery()
        image = self.bundle.responses["recovery_image"]["Images"][0]
        original = copy.deepcopy(image["BlockDeviceMappings"])
        variants = [{"DeviceName": "/dev/sdb", "Ebs": {"SnapshotId": RECOVERY_SNAPSHOT}},
                    {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0", "Ebs": {}},
                    {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0", "NoDevice": ""},
                    {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0", "Unknown": True},
                    {"DeviceName": "/dev/sdb"}]
        variants += [{"DeviceName": device, "VirtualName": "ephemeral0"} for device in
                     (None, "dev/sdb", "/dev/../sdb", "/dev/sdb!")]
        variants += [{"DeviceName": "/dev/sdb", "VirtualName": name} for name in
                     (None, "ephemeral", "ephemeral-1", "ephemeral01", "ephemeral100", "swap")]
        for mapping in variants:
            with self.subTest(mapping=mapping):
                image["BlockDeviceMappings"] = copy.deepcopy(original)
                image["BlockDeviceMappings"][1] = mapping
                self.bundle.update("recovery_image")
                self.reject()
        image["BlockDeviceMappings"] = original
        self.bundle.update("recovery_image")
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_recovery_legacy_ami_requires_a_unique_root_with_the_approved_snapshot(self):
        self.bundle.legacy_recovery()
        image = self.bundle.responses["recovery_image"]["Images"][0]
        original = copy.deepcopy(image["BlockDeviceMappings"])
        for field, value in (("DeviceName", "/dev/sdz"), ("NoDevice", ""), ("VirtualName", "ephemeral2")):
            with self.subTest(root_field=field):
                image["BlockDeviceMappings"] = copy.deepcopy(original)
                image["BlockDeviceMappings"][0][field] = value
                self.bundle.update("recovery_image")
                self.reject()
        for snapshot in (None, SNAPSHOT, "invalid-snapshot"):
            with self.subTest(snapshot=snapshot):
                image["BlockDeviceMappings"] = copy.deepcopy(original)
                image["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"] = snapshot
                self.bundle.update("recovery_image")
                self.reject()
        image["BlockDeviceMappings"] = [copy.deepcopy(original[0]), copy.deepcopy(original[0]),
                                      copy.deepcopy(original[2])]
        self.bundle.update("recovery_image")
        self.reject()

    def test_recovery_legacy_ami_devices_virtual_names_and_mapping_count_are_bounded(self):
        self.bundle.legacy_recovery()
        image = self.bundle.responses["recovery_image"]["Images"][0]
        original = copy.deepcopy(image["BlockDeviceMappings"])
        image["BlockDeviceMappings"][2]["DeviceName"] = "/dev/sdb"
        self.bundle.update("recovery_image")
        self.reject()
        image["BlockDeviceMappings"] = copy.deepcopy(original)
        image["BlockDeviceMappings"][2]["VirtualName"] = "ephemeral0"
        self.bundle.update("recovery_image")
        self.reject()
        image["BlockDeviceMappings"] = original + [{"DeviceName": "/dev/sdd", "VirtualName": "ephemeral2"}]
        self.bundle.update("recovery_image")
        self.bundle.index["captures"]["r_launch"]["request"]["BlockDeviceMappings"].append(
            {"DeviceName": "/dev/sdd", "NoDevice": ""})
        self.reject()

    def test_recovery_legacy_mappings_require_observed_ebs_only_type_boolean(self):
        self.bundle.legacy_recovery()
        instance_type = self.bundle.responses["type"]["InstanceTypes"][0]
        for value in (True, "false", 0, None):
            with self.subTest(instance_storage=value):
                instance_type["InstanceStorageSupported"] = value
                self.bundle.update("type")
                self.reject()
        del instance_type["InstanceStorageSupported"]
        self.bundle.update("type")
        self.reject()
        instance_type["InstanceStorageSupported"] = False
        self.bundle.update("type")
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_recovery_launch_requires_every_exact_suppression_and_no_unknown_or_duplicate(self):
        self.bundle.legacy_recovery()
        request = self.bundle.index["captures"]["r_launch"]["request"]
        original = copy.deepcopy(request["BlockDeviceMappings"])
        variants = [[], original[:1], [original[0], original[0]],
                    [original[0], {"DeviceName": "/dev/sdz", "NoDevice": ""}],
                    [original[0], {"DeviceName": "/dev/sda1", "NoDevice": ""}]]
        variants += [[original[0], {"DeviceName": "/dev/sdc", "NoDevice": value}] for value in (None, True, "true")]
        variants += [[original[0], {**original[1], key: value}] for key, value in
                     (("VirtualName", "ephemeral1"), ("Ebs", {}), ("Unknown", True))]
        for mappings in variants:
            with self.subTest(mappings=mappings):
                request["BlockDeviceMappings"] = copy.deepcopy(mappings)
                self.reject()
        del request["BlockDeviceMappings"]
        self.reject()
        request["BlockDeviceMappings"] = original
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_recovery_legacy_suppression_cannot_change_or_duplicate_root_or_actual_volume(self):
        self.bundle.legacy_recovery()
        request = self.bundle.index["captures"]["r_launch"]["request"]
        original = copy.deepcopy(request["BlockDeviceMappings"])
        request["BlockDeviceMappings"].append({"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": SNAPSHOT}})
        self.reject()
        request["BlockDeviceMappings"] = original + [
            {"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": RECOVERY_SNAPSHOT}},
            {"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": RECOVERY_SNAPSHOT}}]
        self.reject()
        request["BlockDeviceMappings"] = original
        self.bundle.responses["r_root"]["Volumes"][0]["SnapshotId"] = SNAPSHOT
        self.bundle.update("r_root")
        self.reject()
        self.bundle.responses["r_root"]["Volumes"][0]["SnapshotId"] = RECOVERY_SNAPSHOT
        self.bundle.update("r_root")
        item = self.bundle.responses["r_running"]["Reservations"][0]["Instances"][0]
        item["BlockDeviceMappings"].append({"DeviceName": "/dev/sdb", "Ebs": {
            "VolumeId": "vol-00000000000000099", "DeleteOnTermination": True}})
        self.bundle.update("r_running")
        self.reject()

    def test_native_boots_cannot_use_recovery_virtual_mapping_or_suppression_bypass(self):
        self.bundle.legacy_recovery()
        native_image = self.bundle.responses["image"]["Images"][0]
        native_image["BlockDeviceMappings"].append({"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"})
        self.bundle.update("image")
        self.reject()
        native_image["BlockDeviceMappings"].pop()
        self.bundle.update("image")
        for label in ("a", "b"):
            with self.subTest(native=label):
                request = self.bundle.index["captures"][label + "_launch"]["request"]
                request["BlockDeviceMappings"] = [{"DeviceName": "/dev/sdb", "NoDevice": ""}]
                self.reject()
                del request["BlockDeviceMappings"]
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_replayed_launch_tokens_and_instance_id_are_rejected(self):
        old = self.bundle.index["captures"]["b_launch"]["request"]["ClientToken"]
        replay = self.bundle.index["captures"]["a_launch"]["request"]["ClientToken"]
        self.bundle.index["captures"]["b_launch"]["request"]["ClientToken"] = replay
        self.bundle.responses["b_launch"]["Instances"][0]["ClientToken"] = replay
        self.bundle.responses["b_running"]["Reservations"][0]["Instances"][0]["ClientToken"] = replay
        for name in ("b_launch", "b_running"):
            self.bundle.update(name)
        self.reject()
        self.bundle.index["captures"]["b_launch"]["request"]["ClientToken"] = old
        self.bundle.responses["b_launch"]["Instances"][0]["ClientToken"] = old
        self.bundle.responses["b_running"]["Reservations"][0]["Instances"][0]["ClientToken"] = old
        self.bundle.responses["b_launch"]["Instances"][0]["InstanceId"] = self.bundle.responses["a_launch"]["Instances"][0]["InstanceId"]
        for name in ("b_launch", "b_running"):
            self.bundle.update(name)
        self.reject()

    def test_fresh_launch_time_cannot_mask_old_primary_eni(self):
        item = self.bundle.responses["a_running"]["Reservations"][0]["Instances"][0]
        item["NetworkInterfaces"][0]["Attachment"]["AttachTime"] = stamp(-86400)
        self.bundle.update("a_running")
        self.reject()

    def test_console_instance_latest_timestamp_and_terminal_content_enforced(self):
        row = self.bundle.index["captures"]["a_console"]
        row["request"]["Latest"] = False
        self.reject()
        row["request"]["Latest"] = True
        self.bundle.responses["a_console"]["Timestamp"] = stamp(-1000)
        self.bundle.update("a_console")
        self.reject()
        self.bundle.responses["a_console"]["Timestamp"] = row["started_at"]
        self.bundle.responses["a_console"]["InstanceId"] = "i-00000000000000099"
        self.bundle.update("a_console")
        self.reject()
        self.bundle.responses["a_console"]["InstanceId"] = row["request"]["InstanceId"]
        self.bundle.responses["a_console"]["Output"] += "TESSRYN_K01_FAIL reason=synthetic\n"
        self.bundle.update("a_console")
        self.reject()

    def test_cli_decoded_and_sdk_base64_console_have_explicit_formats(self):
        for alias in ("a_console", "r_console", "b_console"):
            row = self.bundle.index["captures"][alias]
            row["format"] = "boto3_json"
            output = self.bundle.responses[alias]["Output"]
            self.bundle.responses[alias]["Output"] = base64.b64encode(output.encode()).decode()
            self.bundle.responses[alias]["ResponseMetadata"] = {"HTTPStatusCode": 200, "RequestId": "synthetic"}
            self.bundle.update(alias)
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")
        self.bundle.index["captures"]["a_console"]["format"] = "aws_cli_v2_json"
        self.reject()  # Must not guess and decode a CLI string a second time.

    def test_wrong_recovery_nonce_image_or_failure_cannot_prove_recovery(self):
        output = self.bundle.responses["r_console"]["Output"]
        self.bundle.responses["r_console"]["Output"] = output.replace(NONCE, "f" * 32)
        self.bundle.update("r_console")
        self.reject()
        self.bundle.responses["r_console"]["Output"] = output + "TESSRYN_RECOVERY_FAIL synthetic\n"
        self.bundle.update("r_console")
        self.reject()
        self.bundle.responses["r_console"]["Output"] = output
        self.bundle.update("r_console")
        self.bundle.index["recovery"]["image_id"] = AMI
        self.reject()

    def test_recovery_nonce_must_be_prebound_to_exact_launch_user_data(self):
        self.bundle.index["recovery"]["nonce"] = "f" * 32
        self.bundle.responses["r_console"]["Output"] = self.bundle.responses["r_console"]["Output"].replace(NONCE, "f" * 32)
        self.bundle.update("r_console")
        self.reject()  # Choosing an observed nonce after capture cannot bind a launch.
        self.bundle.index["recovery"]["nonce"] = NONCE
        self.bundle.responses["r_console"]["Output"] = self.bundle.responses["r_console"]["Output"].replace("f" * 32, NONCE)
        self.bundle.update("r_console")
        self.bundle.index["captures"]["r_launch"]["request"]["UserData"] = base64.b64encode(b"echo fabricated witness\n").decode()
        self.reject()

    def test_arbitrary_recovery_kernel_text_is_not_reflected_in_sanitized_result(self):
        self.bundle.responses["r_console"]["Output"] = self.bundle.responses["r_console"]["Output"].replace(
            "kernel=6.14.0-1023-aws", "kernel=PRIVATE_SENTINEL")
        self.bundle.update("r_console")
        result = self.bundle.verify()
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))

    def test_extra_manifest_source_fields_do_not_escape_sanitized_report(self):
        self.bundle.manifest["source"]["extra"] = "PRIVATE_SENTINEL"
        self.bundle.manifest_path.write_text(json.dumps(self.bundle.manifest))
        self.bundle.index["artifact_manifest_sha256"] = hashlib.sha256(self.bundle.manifest_path.read_bytes()).hexdigest()
        result = self.bundle.verify()
        self.assertEqual(set(result["source"]), {"revision", "tree_sha256", "dirty"})
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))

    def test_unconfirmed_termination_or_phase_overlap_cannot_pass(self):
        final = self.bundle.responses["a_terminated"]["Reservations"][0]["Instances"][0]
        final["State"] = {"Code": 32, "Name": "shutting-down"}
        self.bundle.update("a_terminated")
        self.reject()
        final["State"] = {"Code": 48, "Name": "terminated"}
        self.bundle.update("a_terminated")
        self.bundle.index["captures"]["r_launch"]["started_at"] = self.bundle.index["captures"]["a_launch"]["started_at"]
        self.reject()

    def test_exact_absence_filter_pagination_and_retention_enforced(self):
        captures = self.bundle.index["captures"]
        captures["a_volume_absent"]["request"]["Filters"][0]["Values"] = ["vol-00000000000000099"]
        self.reject()
        captures["a_volume_absent"]["request"]["Filters"][0]["Values"] = ["vol-00000000000000065"]
        self.bundle.responses["a_volume_absent"]["NextToken"] = "more-results"
        self.bundle.update("a_volume_absent")
        self.reject()
        del self.bundle.responses["a_volume_absent"]["NextToken"]
        self.bundle.update("a_volume_absent")
        self.bundle.responses["snapshot_retention_rules"]["Rules"] = [{"Identifier": "synthetic-retention"}]
        self.bundle.update("snapshot_retention_rules")
        self.reject()

    def test_retention_filters_cannot_hide_applicable_rules(self):
        self.bundle.index["captures"]["snapshot_retention_rules"]["request"]["ResourceTags"] = [
            {"Key": "wrong-trial", "Value": "does-not-match"}]
        self.reject()

    def recycle_queries(self):
        return (("a_volume_recycle_absent", "Volumes", "VolumeIds"),
                ("r_volume_recycle_absent", "Volumes", "VolumeIds"),
                ("b_volume_recycle_absent", "Volumes", "VolumeIds"),
                ("image_recycle_absent", "Images", "ImageIds"),
                ("snapshot_recycle_absent", "Snapshots", "SnapshotIds"))

    def test_deleted_but_recycled_resources_cannot_pass_with_empty_current_rules(self):
        # Rules may have changed after deletion; current empty ListRules cannot
        # substitute for targeted absence of each resource already in the bin.
        for alias, collection, parameter in self.recycle_queries():
            with self.subTest(capture=alias):
                resource = self.bundle.index["captures"][alias]["request"][parameter][0]
                self.bundle.responses[alias][collection] = [{parameter[:-1]: resource,
                                                          "RecycleBinExitTime": stamp(86400)}]
                self.bundle.update(alias)
                self.reject()
                self.bundle.responses[alias][collection] = []
                self.bundle.update(alias)
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_recycle_bin_queries_require_only_the_exact_resource_id(self):
        for alias, collection, parameter in self.recycle_queries():
            row = self.bundle.index["captures"][alias]
            original = copy.deepcopy(row["request"])
            resource = original[parameter][0]
            wrong = resource[:-1] + ("f" if resource[-1] != "f" else "e")
            for request in ({}, {parameter: [wrong]}, {parameter: [resource, wrong]},
                            {**original, "NextToken": "skip-an-earlier-page"}):
                with self.subTest(capture=alias, request=request):
                    row["request"] = request
                    self.reject()
            row["request"] = original
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_recycle_bin_responses_require_current_array_fields_and_complete_pagination(self):
        for alias, collection, parameter in self.recycle_queries():
            original = copy.deepcopy(self.bundle.responses[alias])
            for response in ({}, {parameter: []}, {collection: [], "NextToken": "more"}):
                with self.subTest(capture=alias, response=response):
                    self.bundle.responses[alias] = response
                    self.bundle.update(alias)
                    self.reject()
            self.bundle.responses[alias] = original
            self.bundle.update(alias)
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_legacy_index_without_recycle_bin_observations_is_incomplete(self):
        required = (("native_a", "volume_recycle_absent"), ("recovery", "volume_recycle_absent"),
                    ("native_b", "volume_recycle_absent"), ("cleanup", "image_recycle_absent"),
                    ("cleanup", "snapshot_recycle_absent"), ("cleanup", "volume_retention_rules"))
        for phase, key in required:
            with self.subTest(phase=phase, key=key):
                # Remove the receipt too, so an unused-capture check cannot hide
                # failure to require the new lifecycle observation itself.
                alias = self.bundle.index[phase].pop(key)
                row = self.bundle.index["captures"].pop(alias)
                self.reject()
                self.bundle.index[phase][key] = alias
                self.bundle.index["captures"][alias] = row
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_recycle_observations_must_follow_deletion_and_precede_next_phase(self):
        rows = self.bundle.index["captures"]
        for alias, predecessor in (("a_volume_recycle_absent", "a_volume_absent"),
                                   ("image_recycle_absent", "image_absent"),
                                   ("snapshot_recycle_absent", "snapshot_absent")):
            with self.subTest(capture=alias):
                original = rows[alias]["started_at"]
                rows[alias]["started_at"] = rows[predecessor]["started_at"]
                self.reject()
                rows[alias]["started_at"] = original
        for successor, predecessor in (("r_launch", "a_volume_recycle_absent"),
                                       ("b_launch", "r_volume_recycle_absent"),
                                       ("delete_snapshot", "image_recycle_absent"),
                                       ("volume_retention_rules", "snapshot_recycle_absent")):
            with self.subTest(successor=successor):
                original = rows[successor]["started_at"]
                rows[successor]["started_at"] = rows[predecessor]["started_at"]
                self.reject()
                rows[successor]["started_at"] = original
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_volume_retention_rules_cannot_be_present_filtered_or_paginated(self):
        alias = "volume_retention_rules"
        row = self.bundle.index["captures"][alias]
        self.bundle.responses[alias]["Rules"] = [{"Identifier": "synthetic-volume-retention"}]
        self.bundle.update(alias)
        self.reject()
        self.bundle.responses[alias]["Rules"] = []
        self.bundle.responses[alias]["NextToken"] = "unreviewed-rules"
        self.bundle.update(alias)
        self.reject()
        del self.bundle.responses[alias]["NextToken"]
        self.bundle.update(alias)
        row["request"]["ResourceTags"] = [{"Key": "nonmatching", "Value": "hides-applicable-rule"}]
        self.reject()
        row["request"] = {"ResourceType": "EC2_IMAGE"}
        self.reject()

    def test_synthetic_provider_absence_receipts_keep_originals_and_require_owner_review(self):
        for alias, sdk in (("a_volume_recycle_absent", False), ("r_volume_recycle_absent", True),
                           ("b_volume_recycle_absent", False)):
            self.bundle.volume_not_found(alias, sdk=sdk)
        result = self.bundle.verify()
        self.assertEqual(result["status"], "needs_owner_review")
        self.assertEqual(result["capture_kind"], "synthetic_fixture")
        self.assertEqual(result["capture_origin"], "unverified_offline")
        self.assertIn("time_bound", result["cleanup"])
        for phase, label in zip(result["phases"], ("a", "r", "b")):
            alias = label + "_volume_recycle_absent"
            self.assertEqual(phase["root_retention"], {"basis": "provider_volume_not_found",
                "capture_completed_at": self.bundle.index["captures"][alias]["completed_at"]})
        encoded = json.dumps(result)
        for private in ("PRIVATE_SYNTHETIC_REQUEST_ID", "InvalidVolume.NotFound", ACCOUNT,
                        "vol-00000000000000065", "vol-00000000000000066", "vol-00000000000000067"):
            self.assertNotIn(private, encoded)

    def test_successful_empty_volume_list_has_separate_sanitized_observation_basis(self):
        result = self.bundle.verify()
        self.assertEqual([row["root_retention"]["basis"] for row in result["phases"]],
                         ["successful_empty_list"] * 3)

    def test_cli_volume_not_found_requires_exact_service_exit_status(self):
        alias = "a_volume_recycle_absent"
        self.bundle.volume_not_found(alias)
        row = self.bundle.index["captures"][alias]
        for status in (0, 1, 130, 252, 253, 255, -1, True):
            with self.subTest(status=status):
                row["exit_status"] = status
                self.reject()
        row["exit_status"] = 254
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_cli_volume_not_found_full_stderr_match_rejects_other_errors_and_extra_text(self):
        alias = "a_volume_recycle_absent"
        self.bundle.volume_not_found(alias)
        row = self.bundle.index["captures"][alias]
        original = (self.bundle.root / row["stderr"]["path"]).read_bytes()
        variants = [original.replace(b"InvalidVolume.NotFound", code) for code in
                    (b"UnauthorizedOperation", b"AuthFailure", b"InvalidVolume.Malformed", b"InvalidVolume.NotFoundX")]
        variants += [original.replace(b"ListVolumesInRecycleBin", b"DescribeVolumes"),
                     original.replace(b"vol-00000000000000065", b"vol-00000000000000099"),
                     original.replace(b"does not exist", b"could not connect to endpoint"),
                     b"banner\n" + original, original + b"UnauthorizedOperation\n",
                     b"\x1b[31m" + original, original.replace(b"\n", b"\r\n"),
                     original + original]
        for stderr in variants:
            with self.subTest(stderr=stderr):
                row["stderr"] = self.bundle.ref(alias + ".stderr", stderr)
                self.reject()
        for stderr in (original.strip(b"\n"), original.replace(b"exist.", b"exist"), b"\n" + original + b"\n"):
            with self.subTest(canonical=stderr):
                row["stderr"] = self.bundle.ref(alias + ".stderr", stderr)
                self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_cli_volume_not_found_requires_untouched_empty_stdout(self):
        alias = "a_volume_recycle_absent"
        self.bundle.volume_not_found(alias)
        for stdout in (b"\n", b"{}", b'{"Volumes":[]}', b"partial request output"):
            with self.subTest(stdout=stdout):
                self.bundle.responses[alias] = stdout
                self.bundle.update(alias)
                self.reject()

    def test_sdk_volume_not_found_requires_error_status_code_and_capture_exit(self):
        alias = "a_volume_recycle_absent"
        self.bundle.volume_not_found(alias, sdk=True)
        row, response = self.bundle.index["captures"][alias], self.bundle.responses[alias]
        for status in (0, 254, 255, 130, True):
            with self.subTest(exit_status=status):
                row["exit_status"] = status
                self.reject()
        row["exit_status"] = 1
        for status in (200, 403, 404, "400", True):
            with self.subTest(http_status=status):
                response["ResponseMetadata"]["HTTPStatusCode"] = status
                self.bundle.update(alias)
                self.reject()
        response["ResponseMetadata"]["HTTPStatusCode"] = 400
        for code in ("UnauthorizedOperation", "AuthFailure", "InvalidVolume.Malformed", "InvalidVolume.NotFoundX"):
            with self.subTest(code=code):
                response["Error"]["Code"] = code
                self.bundle.update(alias)
                self.reject()
        response["Error"]["Code"] = "InvalidVolume.NotFound"
        self.bundle.update(alias)
        self.assertEqual(self.bundle.verify()["status"], "needs_owner_review")

    def test_sdk_volume_not_found_requires_one_matching_target_and_real_request_identity(self):
        alias = "a_volume_recycle_absent"
        self.bundle.volume_not_found(alias, sdk=True)
        response = self.bundle.responses[alias]
        original = response["Error"]["Message"]
        for message in ("The volume does not exist", original.replace("65", "99"),
                        original + " vol-00000000000000099", original + " vol-00000000000000065",
                        original.replace("65", "65f"), original + "\n", None):
            with self.subTest(message=message):
                response["Error"]["Message"] = message
                self.bundle.update(alias)
                self.reject()
        response["Error"]["Message"] = original
        for request_id in (None, "", " ", "invalid\nrequest", 123):
            with self.subTest(request_id=request_id):
                response["ResponseMetadata"]["RequestId"] = request_id
                self.bundle.update(alias)
                self.reject()
        del response["ResponseMetadata"]["RequestId"]
        self.bundle.update(alias)
        self.reject()

    def test_sdk_volume_not_found_cannot_mix_competing_results_or_cli_receipts(self):
        alias = "a_volume_recycle_absent"
        self.bundle.volume_not_found(alias, sdk=True)
        row, response = self.bundle.index["captures"][alias], self.bundle.responses[alias]
        for key, value in (("Volumes", []), ("NextToken", None), ("Errors", []), ("Return", True)):
            with self.subTest(extra_key=key):
                response[key] = value
                self.bundle.update(alias)
                self.reject()
                del response[key]
        self.bundle.update(alias)
        row["stderr"] = self.bundle.ref(alias + ".stderr", b"An error occurred (InvalidVolume.NotFound)\n")
        self.reject()
        row["stderr"] = self.bundle.ref(alias + ".stderr", b"")
        row["format"] = "aws_cli_v2_json"
        self.reject()
        self.bundle.volume_not_found(alias)
        row["format"], row["exit_status"] = "boto3_json", 1
        self.reject()  # Raw CLI stderr is not an SDK ClientError.response.

    def test_provider_volume_absence_errors_remain_exactly_scoped_and_time_bound(self):
        alias = "a_volume_recycle_absent"
        self.bundle.volume_not_found(alias)
        row = self.bundle.index["captures"][alias]
        original = copy.deepcopy(row)
        for field, value in (("region", "us-west-2"), ("operation", "DescribeVolumes"),
                             ("request", {}), ("request", {"VolumeIds": ["vol-00000000000000099"]}),
                             ("request", {"VolumeIds": ["vol-00000000000000065", "vol-00000000000000099"]}),
                             ("request", {"VolumeIds": ["vol-00000000000000065"], "NextToken": "skip-page"}),
                             ("started_at", stamp(-1)), ("completed_at", stamp(7201))):
            with self.subTest(field=field, value=value):
                row[field] = value
                self.reject()
                row[field] = original[field]
        row["started_at"] = self.bundle.index["captures"]["a_volume_absent"]["started_at"]
        self.reject()
        row["started_at"] = original["started_at"]
        self.bundle.index["captures"]["r_launch"]["started_at"] = row["started_at"]
        self.reject()

    def test_provider_volume_absence_still_requires_original_hashes_and_sanitized_rejection(self):
        alias = "a_volume_recycle_absent"
        self.bundle.volume_not_found(alias)
        row = self.bundle.index["captures"][alias]
        original = row["stderr"]["sha256"]
        row["stderr"]["sha256"] = "0" * 64
        self.reject()
        row["stderr"]["sha256"] = original
        row["stderr"] = self.bundle.ref(alias + ".stderr", b"PRIVATE_SENTINEL UnauthorizedOperation\n")
        with self.assertRaises(ValueError) as caught:
            self.bundle.verify()
        self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

    def test_absence_queries_cannot_filter_out_disabled_images_or_wrong_targets(self):
        request = self.bundle.index["captures"]["image_absent"]["request"]
        request["IncludeDisabled"] = False
        self.reject()
        request["IncludeDisabled"] = True
        request["ImageIds"] = ["ami-00000000000000099"]
        self.reject()

    def test_ami_snapshot_native_boot_mode_and_exact_type_metadata_enforced(self):
        image = self.bundle.responses["image"]["Images"][0]
        image["Public"] = True
        self.bundle.update("image")
        self.reject()
        image["Public"] = False
        image["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"] = "snap-00000000000000099"
        self.bundle.update("image")
        self.reject()
        image["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"] = SNAPSHOT
        self.bundle.update("image")
        self.bundle.responses["type"]["InstanceTypes"][0]["BareMetal"] = True
        self.bundle.update("type")
        self.reject()

    def test_ami_observation_must_follow_snapshot_verification(self):
        self.bundle.index["captures"]["image"]["started_at"] = stamp(0)
        self.bundle.index["captures"]["image"]["completed_at"] = stamp(1)
        self.reject()

    def test_known_good_image_and_native_running_owner_must_match(self):
        image = self.bundle.responses["recovery_image"]["Images"][0]
        image["OwnerId"] = ACCOUNT
        self.bundle.update("recovery_image")
        self.reject()
        image["OwnerId"] = OWNER
        self.bundle.update("recovery_image")
        self.bundle.responses["a_running"]["Reservations"][0]["OwnerId"] = OWNER
        self.bundle.update("a_running")
        self.reject()

    def test_raw_reference_hash_symlink_and_size_limits(self):
        ref = self.bundle.index["captures"]["a_console"]["response"]
        original = dict(ref)
        ref["sha256"] = "0" * 64
        self.reject()
        ref.update(original)
        actual = self.bundle.root / ref["path"]
        moved = self.bundle.root / "renamed-console.json"
        actual.rename(moved)
        actual.symlink_to(moved)
        self.reject()
        actual.unlink()
        moved.rename(actual)
        ref["size_bytes"] = verifier.MAX_CAPTURE_BYTES + 1
        self.reject()

    def test_duplicate_json_rejected_without_false_success(self):
        ref = self.bundle.index["captures"]["identity"]["response"]
        self.bundle.index["captures"]["identity"]["response"] = self.bundle.ref(ref["path"],
            b'{"Account":"123456789012","Account":"123456789012"}')
        self.reject()

    def test_duplicate_private_json_key_has_sanitized_rejection_reason(self):
        ref = self.bundle.index["captures"]["identity"]["response"]
        self.bundle.index["captures"]["identity"]["response"] = self.bundle.ref(ref["path"],
            b'{"PRIVATE_SENTINEL":"a","PRIVATE_SENTINEL":"b"}')
        with self.assertRaises(ValueError) as caught:
            self.bundle.verify()
        self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

    def test_failed_service_and_unconsumed_captures_cannot_pass(self):
        self.bundle.index["captures"]["a_console"]["exit_status"] = 1
        self.reject()
        self.bundle.index["captures"]["a_console"]["exit_status"] = 0
        self.bundle.responses["a_console"]["ResponseMetadata"] = {"HTTPStatusCode": 403}
        self.bundle.update("a_console")
        self.reject()
        del self.bundle.responses["a_console"]["ResponseMetadata"]
        self.bundle.update("a_console")
        self.bundle.add("unreviewed", "DescribeInstances", {}, {"Reservations": []})
        self.reject()

    def test_wrong_region_outside_lease_and_nonzero_return_rejected(self):
        row = self.bundle.index["captures"]["a_running"]
        row["region"] = "us-west-2"
        self.reject()
        row["region"] = self.bundle.index["region"]
        row["completed_at"] = stamp(7201)
        self.reject()
        row["completed_at"] = row["started_at"]
        self.bundle.responses["deregister"] = {"Return": False}
        self.bundle.update("deregister")
        self.reject()

    def test_full_synthetic_snapshot_readback_uses_real_capture_reader_and_verifier(self):
        # Reuse explicitly synthetic block data, but exercise both production
        # validators and the real bounded private-file reader in one chain.
        from tests.test_aws_native_snapshot import AwsNativeSnapshotTests, EPOCH, SNAPSHOT as fixture_snapshot
        AwsNativeSnapshotTests.setUpClass()
        fixture = AwsNativeSnapshotTests("test_complete_synthetic_chain_streams_zeros_and_all_blocks")
        fixture.setUp()
        del self.bundle.index["captures"]["snapshot_ready"]
        del self.bundle.responses["snapshot_ready"]

        def shift_response(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in ("LaunchTime", "AttachTime", "Timestamp"):
                        value[key] = (verifier.timestamp(child) + timedelta(seconds=100)).isoformat()
                    else:
                        shift_response(child)
            elif isinstance(value, list):
                for child in value:
                    shift_response(child)

        for alias, row in self.bundle.index["captures"].items():
            if alias in ("identity", "type"):
                continue
            for key in ("started_at", "completed_at"):
                row[key] = (verifier.timestamp(row[key]) + timedelta(seconds=100)).isoformat()
            shift_response(self.bundle.responses[alias])
            self.bundle.update(alias)

        def convert(value):
            if isinstance(value, dict):
                return {key: convert(child) for key, child in value.items()}
            if isinstance(value, list):
                return [convert(child) for child in value]
            return SNAPSHOT if value == fixture_snapshot else value

        aliases = {alias: "snapshot_" + alias.replace("-", "_") for alias in fixture.records}
        for alias, record in fixture.records.items():
            request, response = convert(record.request), convert(record.response)
            if "ExpiryTime" in response:
                response["ExpiryTime"] = stamp(3600)
            status = {"StartSnapshot": 201, "PutSnapshotBlock": 201, "CompleteSnapshot": 202}.get(record.operation, 200)
            response["ResponseMetadata"] = {"HTTPStatusCode": status, "RequestId": "synthetic-only"}
            row = self.bundle.add(aliases[alias], record.operation, request, response)
            row["format"] = "boto3_json"
            row["started_at"] = stamp(6 + (record.started - EPOCH).total_seconds())
            row["completed_at"] = stamp(6 + (record.completed - EPOCH).total_seconds())
        spec = copy.deepcopy(fixture.spec)
        for key in ("start", "complete", "ready"):
            spec[key] = aliases[spec[key]]
        for key in ("uploads", "list_pages"):
            spec[key] = [aliases[alias] for alias in spec[key]]
        for row in spec["blocks"]:
            row["capture"] = aliases[row["capture"]]
            row["data"] = self.bundle.ref(row["data"]["path"], fixture.files[row["data"]["path"]])
        self.bundle.index["snapshot"] = spec
        self.bundle.disk = fixture.disk
        self.bundle.write()
        with patch.object(verifier, "selected_artifact", return_value=(b"SYNTHETIC EFI", fixture.disk)):
            result = verifier.verify(self.bundle.index_path, self.bundle.manifest_path)
        self.assertEqual(result["status"], "needs_owner_review")
        self.assertEqual(result["capture_kind"], "synthetic_fixture")
        self.assertEqual(result["logical_disk_sha256"], fixture.disk["sha256"])


class CaptureTransportTests(unittest.TestCase):
    def test_exceptional_volume_absence_never_enters_or_bypasses_success_cache(self):
        for sdk in (False, True):
            with self.subTest(sdk=sdk), tempfile.TemporaryDirectory() as temporary:
                bundle = SyntheticCaptureBundle(Path(temporary))
                alias = "a_volume_recycle_absent"
                bundle.volume_not_found(alias, sdk=sdk)
                captures = verifier.CaptureSet(bundle.index_path, bundle.index)
                with self.assertRaises(ValueError):
                    captures.take(alias, "ListVolumesInRecycleBin")
                volume = bundle.index["captures"][alias]["request"]["VolumeIds"][0]
                receipt = captures.take_volume_recycle_absence(alias, volume)
                self.assertEqual(receipt.absence_basis, "provider_volume_not_found")
                self.assertEqual(receipt.response, bundle.responses[alias] if sdk else {})
                self.assertNotIn("Volumes", receipt.response)
                self.assertEqual(receipt.started, verifier.timestamp(bundle.index["captures"][alias]["started_at"]))
                self.assertEqual(receipt.completed, verifier.timestamp(bundle.index["captures"][alias]["completed_at"]))
                self.assertNotIn(alias, captures.cache)
                with self.assertRaises(ValueError):
                    captures.take(alias, "ListVolumesInRecycleBin")
                with self.assertRaises(ValueError):
                    captures.take_volume_recycle_absence(alias, "vol-00000000000000099")
                self.assertNotIn(alias, captures.cache)

    def test_successful_empty_volume_capture_stays_an_ordinary_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = SyntheticCaptureBundle(Path(temporary))
            alias = "a_volume_recycle_absent"
            captures = verifier.CaptureSet(bundle.index_path, bundle.index)
            normal = captures.take(alias, "ListVolumesInRecycleBin")
            volume = bundle.index["captures"][alias]["request"]["VolumeIds"][0]
            absence = captures.take_volume_recycle_absence(alias, volume)
            self.assertIsNone(normal.absence_basis)
            self.assertEqual(absence.absence_basis, "successful_empty_list")
            self.assertIs(captures.take(alias, "ListVolumesInRecycleBin"), normal)

    def test_volume_service_errors_do_not_relax_image_or_snapshot_capture_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = SyntheticCaptureBundle(Path(temporary))
            for alias, operation in (("image_recycle_absent", "ListImagesInRecycleBin"),
                                      ("snapshot_recycle_absent", "ListSnapshotsInRecycleBin")):
                row = bundle.index["captures"][alias]
                row["format"], row["exit_status"] = "boto3_json", 1
                bundle.responses[alias] = {"Error": {"Code": "InvalidVolume.NotFound",
                    "Message": "The volume 'vol-00000000000000065' does not exist."},
                    "ResponseMetadata": {"HTTPStatusCode": 400, "RequestId": "SYNTHETIC_REQUEST_ID"}}
                bundle.update(alias)
                captures = verifier.CaptureSet(bundle.index_path, bundle.index)
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    captures.take(alias, operation)
                with self.assertRaises(ValueError):
                    captures.take_volume_recycle_absence(alias, "vol-00000000000000065")

    def test_real_ebs_success_status_codes_are_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = SyntheticCaptureBundle(Path(temporary))
            for alias, operation, status in (("start", "StartSnapshot", 201),
                                              ("put", "PutSnapshotBlock", 201),
                                              ("complete", "CompleteSnapshot", 202)):
                bundle.add(alias, operation, {}, {"ResponseMetadata": {"HTTPStatusCode": status}})
            captures = verifier.CaptureSet(bundle.index_path, bundle.index)
            for alias, operation in (("start", "StartSnapshot"), ("put", "PutSnapshotBlock"),
                                      ("complete", "CompleteSnapshot")):
                with self.subTest(operation=operation):
                    captures.take(alias, operation)


if __name__ == "__main__":
    unittest.main()
