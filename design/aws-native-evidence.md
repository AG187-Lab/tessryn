# Native AWS evidence intake

Status: implemented offline validation. There are no native EC2 observations or
new cloud permissions in this implementation. [The experiment contract](aws-boot-and-recovery.md)
still requires separate native approval, execution, independent recovery and
cleanup by the AWS operations owner.

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

`GetConsoleOutput` requests must bind `InstanceId` and `Latest=true`. Its response
binds `InstanceId`, `Timestamp` and `Output`. CLI JSON output is already decoded;
SDK/API output needs explicit Base64 decoding. `Timestamp` is the buffer's last
update, not a per-line execution time. Empty, stale, incomplete or contradictory
captures are inconclusive/rejected, never a native pass. The owner polls with a
bounded deadline. [Console fields](https://docs.aws.amazon.com/cli/latest/reference/ec2/get-console-output.html).

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
the complete disk SHA-256. AWS supplies per-block checksums; it does not return
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
attachment. A root-only launch override can inherit the snapshot or name that
same snapshot; it cannot replace it or add another disk. Native roots remain
1 GiB. Policy overrides for encryption/type/size on the Linux recovery root
remain subject to the separately approved proposal. [Instance semantics](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Instance.html),
[launch mappings](https://docs.aws.amazon.com/cli/latest/reference/ec2/run-instances.html).

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
and no continuation token. Its request contains only the corresponding
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
