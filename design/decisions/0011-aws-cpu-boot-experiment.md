# ADR 0011: Prepare a bounded AWS original-kernel CPU experiment

Status: Accepted local architecture and evidence contract. Native AWS CPU boot
and recovery are unqualified; native AMI resource approval remains pending.

## Decision

Prepare the original K01 kernel for direct firmware loading as an x86-64 HVM
UEFI EC2 guest. Use a separate `k01_aws` image with bounded COM1 at the explicit
profile assumption `0x3f8`, 115200n8, optional GOP and terminal halt. It never
writes emulator debug ports `0xe9` or `0xf4`. UART access and actual firmware
loading require exact EC2 execution evidence.

Build a deterministic 1 GiB whole disk with GPT and a 64 MiB FAT32 EFI System
Partition containing `EFI/BOOT/BOOTX64.EFI`. Local tooling verifies the entire
logical disk, including sparse zero holes, and emits nonzero 512 KiB EBS input
blocks with SHA-256 checksums. It prepares inputs without calling AWS APIs.
The eventual AMI contract is `x86_64`, `hvm`, `uefi`, an EBS snapshot root and
explicit resource cleanup. Native storage and ENA drivers are outside this CPU
boot experiment.

Before proposing native execution, retain two equal independent clean builds,
all six local serial cases and normal boot's two fresh phases separated by
independent QMP reset. Retain separate nine-case high-address evidence and label
synthetic runtime/GOP mapping fixtures separately. [ADR 0010](0010-first-uefi-kernel.md)
defines the bounded paging and firmware handoff contract.

The separate AWS operations session owns account access, provisioning, costs,
recovery and cleanup. Its existing authorization is one `t3a.small` Linux/QEMU
trial under USD 15. That approval does not authorize a native AMI trial or IAM
expansion. Native execution requires a concrete artifact, exact UEFI-capable
type, console contract, independently controlled recovery and approved resource
proposal. Resource operations remain with that owner to avoid duplicate trials.

## Consequences

Original-kernel boot in a virtualized Nitro guest establishes that guest CPU
profile only. It is distinct from QEMU hosted on Linux and from physical
bare-metal qualification. Select an exact type using retained boot-mode metadata;
Nitro or bare-metal labels alone cannot establish UEFI support. G01 physical
stable-node/notebook gates and historical evidence remain intact.

Recovery relies on independent EC2 control: approved termination and known-good
reprovisioning, or an explicitly rehearsed stop/start rescue procedure. A guest
halt or runtime reset is not a cleanup control. Require fresh serial evidence
bound to the instance and artifact; a cached PASS is insufficient for a second
boot. Instance network health checks are not this CPU acceptance gate because
the kernel has no ENA driver. GPU, networking, storage-driver and inference
claims require later qualification.

## References

[AWS boot and recovery workflow](../aws-boot-and-recovery.md),
[AMI boot configuration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-ami-boot-mode.html),
[serial console](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-to-serial-console.html),
[EBS direct writes](https://docs.aws.amazon.com/ebs/latest/userguide/writesnapshots.html), and
[G01 qualification boundary](../platform-qualification.md).
