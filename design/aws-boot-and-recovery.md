# AWS original-kernel CPU boot and recovery

Status: the bounded `t3a.small` original-kernel CPU boot and independent recovery
profile was accepted by the operations owner on October 12, 2026. Two fresh
native EC2 boots were separated by a fresh known-good Ubuntu recovery instance;
cleanup is complete. [The observed qualification](#observed-cpu-qualification)
records the precise scope; [ADR 0011](decisions/0011-aws-cpu-boot-experiment.md)
records its architecture and evidence contract.

The separate AWS operations session owns all account access, provisioning,
spending controls and cleanup. Its initial Linux-hosted QEMU trial and later
approved native trial remain distinct observations under the existing bounded
authorization. The native trial is closed; this workflow does not grant approval
for another trial, expand IAM permissions or launch AWS resources.

## Observed CPU qualification

On October 12, 2026 the trusted operations owner accepted the original-kernel
CPU profile on a virtualized UEFI `t3a.small` guest. Native boot A reached
the ordered firmware handoff, owned CPU tables, memory readback and terminal
PASS. Independent EC2 control then terminated that instance and provisioned a
separate known-good Ubuntu recovery instance, whose fresh launch-bound nonce
proved a usable recovery environment. After its termination, fresh native boot
B reached the same original-kernel terminal sequence. The two native instances
and the recovery instance were separately attributable; recovery was not a
rescue on the same physical machine.

The deployed normal image retained the original clean preparation identity:

| Input | Recorded identity |
| --- | --- |
| Source revision | `5ea06b998fcc854851e794aea6235b15fa34be65` |
| Source snapshot | `7c53829d4ef7d52c14ef5633b8e3d8e8c838e51b4578a12333f25eddf23399d6` |
| AWS preparation manifest SHA-256 | `5cc73ac570ea11f70c52d7497a150633030fe75f706c8b14f36f1659e4859e36` |
| Normal EFI SHA-256 | `a272b3186db19670ae320e85b60cced9f94acf84bcda894c8c033401076daba3` |
| Normal 1 GiB logical disk SHA-256 | `78478aebdf6ee303cd100bd811b5dd60fda5e282f03fca0ededda23a16127653` |

The [October 11 preparation packet](../evidence/k01-aws-preparation/README.md)
retains its original local results and unqualified-at-capture statuses. It is
historical input evidence, not the native observation packet. The owner reviewed
the private native capture chain, authorization, recovery and terminal cleanup:
all three instances and their root volumes were removed, the native AMI and
snapshot and isolated network were removed. Approved permanent encrypted,
versioned state storage and lasting development access were retained. These are
observations at closeout, not a permanent account-wide absence or final billing
claim. No private responses, identifiers, addresses, nonce, state files or local
capture paths are published here.

The original paid controller receipt retains exit status 1: its offline packet
assembly failed because an 8 MiB capture allowance conflicted with a 64 KiB
assembler limit. A separate corrected assembly and unchanged original verifier
CLI subsequently validated the supplied packet. That offline result remained
`needs_owner_review`; the owner's separate observed acceptance established this
bounded profile. The correction does not rewrite the original failure receipt.
See [the intake trust boundary](aws-native-evidence.md).

Acceptance covers normal original-kernel CPU boot and independent
termination/reprovisioning recovery for the recorded profile. Exception, panic,
runtime-reset and high-address execution remain QEMU observations. This does not
qualify bare metal, same-machine rescue, native NVMe/ENA/GPU drivers, networking,
inference, distributed operation or performance. Another type, image or trial
requires its own authorization and qualification.

## Kernel and disk contract

The `k01_aws` image uses bounded COM1 output, with the explicit assumption of an
x86 16550-compatible UART at I/O base `0x3f8`, 115200n8. AWS documents port 0 as
`ttyS0`/COM1 and serial configuration at 115200; the accepted normal boots
provide execution evidence for the recorded profile. Other profiles require
their own UART evidence. GOP is optional;
normal, expected fault and panic cases report terminal status and halt. QEMU
debug ports `0xe9`/`0xf4` are disabled, including when an emulator cfg is also
supplied. [Serial prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console-prerequisites.html),
[serial connection contract](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-to-serial-console.html).

Firmware loads the original EFI image from a fixed disk before the kernel exits
boot services. The [K01 paging contract](first-kernel.md) maps required high live
ranges with bounded four-level identity tables; it does not reclaim all high
RAM, initialize other CPUs, isolate processes or grant DMA authority. Native
NVMe, ENA, GPU and inference implementation remains unavailable.

Each `boot.img` is exactly 1 GiB logically, with a protective MBR, primary and
backup GPT at the actual disk ends, and a 64 MiB FAT32 ESP beginning at 1 MiB.
The ESP contains `EFI/BOOT/BOOTX64.EFI`; its 128,992 data clusters satisfy FAT32
classification. Host files are sparse, but all logical zero holes participate
in verification and the whole-disk SHA-256. Media tests independently recover
the EFI file, check both GPT/FAT copies and reject damaged structures, payloads,
zero holes, final symlinks, file replacement and malformed upload metadata. Failed
artifacts remain for inspection.

`snapshot-inputs.json` describes a new 1 GiB EBS snapshot and only its nonzero
512 KiB blocks. Each block has its index, length, hexadecimal SHA-256 and EBS
Base64 SHA-256 checksum; the final GPT block cannot be omitted. The upload
iterator verifies every block and the final complete disk checksum and file
stability. It must finish successfully before snapshot completion. A future
uploader must begin a new snapshot without a parent, retain AWS responses,
confirm block size/checksums, and wait for completed state. These local inputs
are not an uploaded or registered image. [EBS direct write contract](https://docs.aws.amazon.com/ebs/latest/userguide/writesnapshots.html).

The proposed AMI uses `Architecture=x86_64`, `VirtualizationType=hvm`,
`BootMode=uefi`, root device `/dev/sda1`, the verified snapshot and a 1 GiB root
volume with deletion on termination. The owner supplies region, encryption,
snapshot/AMI identifiers and required device-enablement metadata in the
approved proposal. ENA metadata, if required for launch, does not provide a
working kernel ENA driver. Registration is an experimental original-OS path;
changing boot metadata alone cannot make an image bootable. [RegisterImage](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RegisterImage.html),
[AMI boot configuration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-ami-boot-mode.html).

## Reproduce locally

Use the pinned setup in [the first-kernel guide](first-kernel.md) and a clean
checkout. Every output path must be new. These commands build local artifacts
and launch only disposable QEMU guests:

```sh
python3 tools/build_aws_boot.py --out build/aws-a
python3 tools/build_aws_boot.py --out build/aws-b
for case in normal int3 invalid_opcode page_fault panic reboot; do
  python3 tools/run_aws_boot.py --manifest build/aws-a/manifest.json --case "$case" --out "build/aws-$case"
done
python3 tools/verify_aws_boot.py --first build/aws-a/manifest.json --second build/aws-b/manifest.json \
  --result build/aws-normal/result.json --result build/aws-int3/result.json \
  --result build/aws-invalid_opcode/result.json --result build/aws-page_fault/result.json \
  --result build/aws-panic/result.json --result build/aws-reboot/result.json \
  --out build/aws-verification.json
python3 -m unittest discover -s tests -p 'test_aws_*.py' -v
```

The runner uses q35/TCG, fresh OVMF VARS, firmware NVMe loading, serial output,
no VGA, no network and no debug/exit test ports. Only the boot CPU runs kernel
code. Normal executes twice: after the first PASS, the evaluator independently
pauses the guest, witnesses QMP `system_reset`, resumes it and requires a fresh
complete second transcript. Fault/panic cases reach their expected terminal
markers; the evaluator stops and quits them. The runtime reset case uses
`-no-reboot`, CPU-reset diagnostics and no-triple-fault checks. A natural guest
exit is not substituted for the evaluator's independent control sequence.

Verification binds equal clean-build manifests, exact EFI and regenerated disk
bytes, notices, snapshot-input plans, emulator/firmware hashes, raw serial and
QMP logs, all six case results and normal's two phases. It rechecks the reset
event, control responses and phase boundaries. Passing establishes local
headless boot and external QEMU reset only. Use the separate
[nine high-address regressions](first-kernel.md#high-address-regressions) to prove
actual high image/handoff placement; synthetic high runtime/GOP fixtures do not
qualify actual firmware or devices.

## Native EC2 proposal and acceptance

Before requesting resource approval, the AWS owner records the exact artifact
and manifest hashes, proposed type/region, permitted serial route, known-good
recovery image, lifetime/cost limit and cleanup of instances, volumes, snapshots,
AMIs and temporary access. Preserve existing permissions; unresolved image or
serial/recovery prerequisites must be resolved in the proposal rather than by
launching a second uncoordinated trial.

The owner confirms `SupportedBootModes` for the exact instance type and
`CurrentInstanceBootMode=uefi` after launch. The selected `t3a.small` is a
virtualized Nitro guest; its original-kernel boot is not physical bare-metal
proof. Retain the actual raw and sanitized type/instance boot-mode observations
in the approved preflight. Generic Nitro UEFI guarantees exclude bare metal;
neither a Nitro label nor a metal label establishes the exact type's boot mode.
[Exact type boot modes](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-type-boot-mode.html),
[UEFI launch requirements](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/launch-instance-boot-mode.html).

For an approved native attempt, acceptance requires:

1. A fresh serial transcript bound to the exact instance, AMI/snapshot, source
   and artifact hashes, with ordered entry, validated map, successful `ExitBootServices`,
   owned CR3/RSP/RIP, memory readback and terminal PASS. Record expected versus
   observed addresses, firmware identity and unavailable observations.
2. An independently witnessed EC2 recovery action and its actual result:
   termination/reprovisioning with a known-good Linux image, or an explicitly
   approved and rehearsed stop/start rescue route. A reboot into the same halted
   image alone does not establish a usable recovery environment. Keep recovery
   and the rental deadline independent of the test kernel.
3. A second boot with fresh, separately attributable evidence. Capture a live
   serial stream across the witnessed action, or use a fresh disposable instance
   with isolated instance/image responses. If relying on repeated console-buffer
   queries for one reused instance, a per-attempt image nonce would be needed;
   current images do not embed that nonce. An old PASS in `GetConsoleOutput`
   cannot prove another boot. Retain its output timestamp and `Latest` setting.
4. Cleanup evidence for every approved resource and temporary access grant,
   plus a reviewed public record containing no account identifiers, network addresses,
   credentials or unrelated content.

EC2 control-plane recovery is distinct from IPMI/BMC or arbitrary ISO access.
The original kernel has no ENA driver, so guest networking and SSH are absent.
Record EC2 system/EBS/instance statuses, but do not require the guest's network
status check to pass this CPU test: AWS probes instance health using NIC ARP.
[External stop/start behavior](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Stop_Start.html),
[console output freshness fields](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetConsoleOutput.html),
[instance status checks](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-system-instance-status-check.html).

Native execution and recovery must retain separate observed statuses. A local
QEMU pass, a Linux reference inventory, an AMI ID or an EC2 running state cannot
replace the original kernel's transcript and the independent recovery result.
G01's [qualification packet](platform-qualification.md) and
[historical AWS research](../evidence/g01-research/aws-access-notes.md) keep their
dated scope; the new experiment does not qualify the product's physical nodes
or notebook, native devices, GPU execution or inference.

The [offline native evidence intake](aws-native-evidence.md) binds private
snapshot/AMI/root-volume/serial/lifecycle captures for two fresh native boots
and independent Linux recovery. It makes no cloud calls and returns consistency
requiring trusted owner review; its synthetic tests are not native observations.
