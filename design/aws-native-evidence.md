# Native AWS evidence intake

Status: implemented offline validation, with a separately owner-accepted
[observed CPU qualification](aws-boot-and-recovery.md#observed-cpu-qualification)
dated October 12, 2026. The parser's synthetic fixtures and consistency reports
remain distinct from the private native observations and trusted acceptance.
The native trial and cleanup are complete; this implementation grants no cloud
permissions or authorization for another trial.

`tools/verify_aws_native.py` consumes a private capture index and the clean
`build_aws_boot.py` manifest. It calls no AWS API, starts no subprocess and reads
no credentials. It verifies the normal original EFI/disk locally, then checks
the supplied cloud capture chain. Input files and raw cloud responses remain
private; the output contains artifact/capture hashes, numeric boot observations
and the declared region/type, without account/resource identifiers, network addresses,
raw logs, user-data or the recovery nonce.

```sh
python3 tools/verify_aws_native.py --manifest build/aws-ready-media-a/manifest.json \
  --capture build/private-native-trial/capture-index.json \
  --out build/private-native-trial/offline-review.json
python3 -m unittest discover -s tests -p 'test_aws_native*.py' -v
```

Both real operator captures and explicitly synthetic fixtures return
`status=needs_owner_review`, `capture_origin=unverified_offline`. A successful
command establishes consistency of supplied bytes and relations. Hashes do not
authenticate fabricated AWS JSON. Actual qualification requires trusted owner
capture, authorization/lifecycle review and a separate observed qualification
record; a fixture, parser success or this report alone cannot complete the goal.
The accepted trial retained the original controller's failed offline assembly
receipt, the separate corrected packet and its `needs_owner_review` result, and
the owner's independent terminal acceptance. The public summary reports that
disposition without publishing the private packet or converting offline parser
status into an authenticated observation.

## Private capture index

The top-level object contains these fields:

| Field | Contract |
| --- | --- |
| `format`, `schema_version` | `tessryn-aws-native-capture`, integer `1` |
| `capture_kind` | `operator_capture` or `synthetic_fixture`; neither bypasses review |
| `trial_started_at`, `trial_deadline_at` | Aware timestamps; positive lifetime at most two hours |
| `account_id`, `region`, `instance_type` | Exact private account and declared profile |
| `encrypted` | Expected observed snapshot/root encryption boolean |
| `artifact_manifest_sha256` | SHA-256 of the exact clean original-kernel manifest |
| `captures` | Unique aliases to the envelopes below; all must be consumed |
| `identity`, `type`, `image` | Aliases for `GetCallerIdentity`, `DescribeInstanceTypes`, native `DescribeImages` |
| `snapshot` | Snapshot-chain specification below |
| `native_a`, `recovery`, `native_b` | Sequential phase specifications below |
| `recovery_image`, `recovery_image_owner` | Alias and approved owner for the independent known-good image |
| `cleanup` | AMI/snapshot/retention specifications below |

Each envelope has exactly `operation`, `request`, `region`, `format`,
`tool_version`, `started_at`, `completed_at`, `exit_status`, `response`, `stderr`.
Record resolved **service request fields**, including file/blob inputs as their
actual service values; do not use a shell command or a queried summary in their
place. `format` is `aws_cli_v2_json` or `boto3_json`. Preserve full response JSON,
stderr and binary snapshot block bodies in files. Every file reference is
`{"path":"relative/file","sha256":"lowercase SHA-256","size_bytes":123}`.
Directory-descriptor reads reject path escapes, symlinks and nonregular files;
files are capped at 8 MiB and the referenced bundle at 32 MiB. Errors are
categorical and do not reflect private values.

For `GetSnapshotBlock`, preserve the response metadata/header fields in JSON
and its `BlockData` stream as the separate binary `data` reference. Do not
serialize a Python stream representation or invent a replacement body.

Successful envelopes require exit status zero and successful response metadata
when supplied. EBS creation/writes can return HTTP 201 and completion HTTP 202.
Some successful CLI deletions have empty stdout; retain those exact bytes and
later absence queries. Do not fabricate `{}` to replace an empty raw capture.

The single-volume `ListVolumesInRecycleBin` absence check has a narrowly
defined service-error alternative. A first request containing exactly one
historically bound root ID can return `InvalidVolume.NotFound`. Preserve the
untouched error rather than converting it into a successful empty list. A CLI
receipt requires its actual service-error exit status 254, empty stdout and the
complete legacy stderr line naming that operation, code and same volume. A
structured SDK receipt requires runner exit status 1 and the original
`ClientError.response`, with that code, a message bound to the same volume,
HTTP 400 and the observed request ID. Do not invent SDK metadata from CLI text.
Authorization, malformed-request, timeout, generic exit 255 and multi-ID errors
cannot establish absence.
[CLI exit codes](https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-returncodes.html),
[SDK errors](https://docs.aws.amazon.com/boto3/latest/guide/error-handling.html).

The single-snapshot `ListSnapshotsInRecycleBin` check also accepts its original
structured SDK `InvalidSnapshot.NotFound` error, with exit status 1, empty
stderr, HTTP 400, a bounded request ID and a printable message naming only the
exact owned snapshot. The original request, response hashes, region and capture
times remain required. This error stays outside the ordinary success cache and
reports `provider_snapshot_not_found`; a successful empty response reports
`successful_empty_list`.

The single-image `ListImagesInRecycleBin` check accepts only the corresponding
original SDK `InvalidAMIID.NotFound` receipt, with the same exit status, empty
stderr, HTTP status and request-ID requirements. Its request contains only the
one owned image ID, and the bounded printable message must name that exact ID
once. RetryAttempts must be the integer zero, and the original
`x-amzn-requestid` header must match `ResponseMetadata.RequestId`.
It reports `provider_image_not_found`, preserving the original error
outside the success cache. CLI image/snapshot errors and all other operations
remain success-only. These exceptions do not apply to EBS snapshot block reads.

`GetConsoleOutput` requests must bind `InstanceId` and `Latest=true`. Its response
binds `InstanceId`, `Timestamp` and `Output`. CLI JSON output is already decoded;
SDK/API output needs explicit Base64 decoding. `Timestamp` is the buffer's last
update, not a per-line execution time. Empty, stale, incomplete or contradictory
captures are inconclusive/rejected, never a native pass. The owner polls with a
bounded deadline. [Console fields](https://docs.aws.amazon.com/cli/latest/reference/ec2/get-console-output.html).

The `boto3_json` capture format preserves the service-encoded `Output`. An SDK
that automatically decodes console output must retain that original value
before its decoding handler; the tested capture producer removes that handler
from its dedicated EC2 client. Do not relabel decoded SDK text as encoded
service output or apply another Base64 transformation to repair a receipt.

## Snapshot and image chain

`snapshot` contains exactly `start`, `uploads`, `complete`, `ready`, `list_pages`,
`blocks`. The first four identify `StartSnapshot`, the five `PutSnapshotBlock`
envelopes, `CompleteSnapshot` and completed `DescribeSnapshots`. `list_pages`
contains every `ListSnapshotBlocks` page in order. Each `blocks` row is
`{"index":0,"capture":"read_0","data":file_reference}` for a
`GetSnapshotBlock` metadata envelope and its untouched binary body.

The verifier requires a new no-parent 1 GiB snapshot, a recorded attempt token,
512 KiB blocks and exact upload/checksum coverage from the locally verified
normal disk. It exhausts pagination even after all five blocks appear, binds
readback tokens and checksums, and streams all logical zero holes to reconstruct
the complete disk SHA-256. Block and page tokens are opaque strings: preserve them
exactly, including URL-safe `-` and `_`, within the bounded 1–256 character token
contract. Do not decode them or alter padding. AWS supplies per-block checksums; it does not return
the EFI/source/whole-disk digest. Token expiry, when present, must permit the
read's start; a download may finish later. [Snapshot write/read contract](https://docs.aws.amazon.com/ebs/latest/userguide/writesnapshots.html),
[listing pagination](https://docs.aws.amazon.com/ebs/latest/APIReference/API_ListSnapshotBlocks.html).

The native AMI must be owned privately by the captured account, available,
x86-64/HVM/UEFI, EBS-backed and mapped to the verified 1 GiB root snapshot at
`/dev/sda1`. The exact type must support x86-64 and UEFI and report
`BareMetal=false`; this intake covers a virtualized CPU profile. ENA metadata
and firmware/COM1 readiness remain preflight/runtime observations, not working
Tessryn network/storage driver claims.

## Boot, independent recovery and cleanup

Each phase has exactly `launch`, `running`, `root`, `console`, `terminate`,
`terminated`, `volume_absent`, `eni_absent`, `volume_recycle_absent`. These aliases select respectively
`RunInstances`, `DescribeInstances`, `DescribeVolumes`, `GetConsoleOutput`,
`TerminateInstances`, `DescribeInstances`, `DescribeVolumes`,
`DescribeNetworkInterfaces`, `ListVolumesInRecycleBin`. Recovery additionally has `image_id` and `nonce`.

All three instances/tokens/root volumes/interfaces must be distinct. Creation
is bound to the launch response, launch token and fresh primary interface
attachment time; `LaunchTime` alone is insufficient because it also changes on
a later start. Native A/B use the same approved AMI and actually boot UEFI.
Each actual root volume joins the approved image snapshot and its instance
attachment. An EBS root override can inherit the snapshot or name that
same snapshot; it cannot replace it or add another disk. Native roots remain
1 GiB. Policy overrides for encryption/type/size on the Linux recovery root
remain subject to the separately approved proposal. [Instance semantics](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Instance.html),
[launch mappings](https://docs.aws.amazon.com/cli/latest/reference/ec2/run-instances.html).

Keep the original recovery AMI mapping response intact. Its unique EBS root
must match `RootDeviceName` and the approved snapshot. Up to two legacy
`VirtualName=ephemeralN` declarations may accompany that root only when the
captured exact type reports `InstanceStorageSupported=false`; they are not
extra EBS roots. The original recovery launch must suppress every such device
with exactly `DeviceName` and `NoDevice=""`, without unknown or duplicate
suppressions or root removal. Native A/B remain restricted to one 1 GiB root.
The actual recovery instance and attached volume must still contain only the
single approved EBS root. [Block-device suppression](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_BlockDeviceMapping.html).

Normal serial parsing checks one complete original-kernel entry, every bounded
firmware admission/retry, live ranges, paging capacity/guard/physical width,
actual CR3/RIP/RSP, scratch readback and terminal PASS. High addresses are
optional on a 2 GiB guest. A/B logs may have identical bytes; freshness comes
from the distinct provider-bound instances, not a different log hash.

Use `recovery_user_data(nonce)` from the verifier to produce the exact reviewable
Linux witness script, then Base64-encode its bytes in the recorded resolved
`RunInstances.UserData`. Its fresh 32-hex nonce is bound before execution, and
the script reports `uname -r`, x86-64 and systemd PID 1 on `/dev/ttyS0`.
The verifier never executes it. Recovery uses the separately approved known-good
AMI/root snapshot. The original native kernel does not process cloud-init;
native deadline enforcement must stay outside the guest.

A native A/B `TerminateInstances` request contains exactly `InstanceIds` with
the bound single instance, or that same array plus both `Force=true` and
`SkipOsShutdown=true` as Boolean values. Recovery retains the `InstanceIds`-only
request. Retain the original request and response; accepting these native
control flags does not establish guest shutdown or completed cleanup.
[Termination controls](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TerminateInstances.html).

A termination acknowledgement may still mean `shutting-down`. The next phase
cannot launch until actual `terminated` state and root/interface absence are
captured, including root volume Recycle Bin absence. Absence queries use only the exact recorded ID filter, with complete
responses: `volume-id`, `network-interface-id`, `image-id` or `snapshot-id`.
AMI queries also use the exact owner and `IncludeDeprecated=true`,
`IncludeDisabled=true`; snapshot queries use the exact owner. Extra filters or
unresolved pagination cannot prove absence. [Termination](https://docs.aws.amazon.com/cli/latest/reference/ec2/terminate-instances.html),
[image visibility](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImages.html).

`cleanup` contains `deregister`, `image_absent`, `image_recycle_absent`, `delete_snapshot`,
`snapshot_absent`, `snapshot_recycle_absent`, `volume_retention_rules`,
`snapshot_retention_rules`, `image_retention_rules`.
Deregister after final instance cleanup, confirm ordinary and Recycle Bin image
absence before deleting the snapshot, then confirm snapshot absence. Each deleted volume and the native
AMI/snapshot also requires an exact-ID `ListVolumesInRecycleBin`,
`ListImagesInRecycleBin` or `ListSnapshotsInRecycleBin` query, an empty collection
and no continuation token, or the corresponding narrowly bound volume, image or
snapshot not-found receipt described above. Its request contains only the corresponding
`VolumeIds`, `ImageIds` or `SnapshotIds` array. Use a client model that supports
these current operations; older user-guide response examples do not replace
current CLI/SDK fields. [Volume query](https://docs.aws.amazon.com/cli/latest/reference/ec2/list-volumes-in-recycle-bin.html),
[snapshot query](https://docs.aws.amazon.com/cli/latest/reference/ec2/list-snapshots-in-recycle-bin.html),
[image query](https://docs.aws.amazon.com/cli/latest/reference/ec2/list-images-in-recycle-bin.html).

The three final `ListRules` requests must be unfiltered except exact
`ResourceType=EBS_VOLUME`, `EBS_SNAPSHOT` or `EC2_IMAGE`, exhausted and empty.
Rule absence then cannot prove that no rule retained a resource earlier;
per-resource Recycle Bin observations remain mandatory. Termination-deleted
volumes can be retained, and removing a rule does not erase already retained
resources. Existing rules or retained resources require explicit owner
assessment and budget accounting; this first intake does not infer them gone.
[Retention behavior](https://docs.aws.amazon.com/ebs/latest/userguide/recycle-bin-factors.html).
Temporary access revocation, actual capture origin, approval, deadlines and
the cost ledger remain separate owner review gates.

Each phase reports whether its root retention observation was a successful
empty list or a provider volume-not-found error. `image_retention` and
`snapshot_retention` report their absence basis and capture completion time. These remain observations
at capture time. They do not establish permanent deletion, historical charges or
global account absence. EC2 is eventually consistent, so retain the earlier
root binding, confirmed termination and ordinary volume-absence observation.
A summary of per-ID error codes without the original raw error receipts is
not a replayable native capture packet.
[Volume error meaning](https://docs.aws.amazon.com/ec2/latest/devguide/errors-overview.html),
[consistency limits](https://docs.aws.amazon.com/ec2/latest/devguide/eventual-consistency.html).
