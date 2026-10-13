# Platform qualification

Status, October 12, 2026: physical target profiles remain unqualified. K01 has original-kernel QEMU execution and [owner-accepted AWS `t3a.small` CPU boot/recovery evidence](https://github.com/AG187-Lab/tessryn/blob/c5d82c49cefd6dbc32f122562c6bb0c1608b4816/design/aws-boot-and-recovery.md#observed-cpu-qualification), with its implementation [PR #53](https://github.com/AG187-Lab/tessryn/pull/53) awaiting merge. Qualify CPU boot, networking/storage, accelerator compute and distributed inference separately. A successful boot does not prove accelerator availability.

The [initial G01 qualification record](platform-qualification.md) prepares a short bare-metal inventory session without selecting supported hardware. Its candidate descriptions and costs are vendor facts and analytical examples; actual physical device/firmware/topology, notebook access and physical native execution remain unavailable. The later AWS CPU observation does not replace these G01 records or qualify native NVMe/ENA/GPU execution.

G01 selects exact engineering targets only after physical inventories,
boot/device-access feasibility, recovery prerequisites and artifact constraints
have evidence. That decision can leave Tessryn capability statuses
unavailable. Original-kernel boot, native device initialization, GPU compute,
inference and thermal/load qualification are subsequent implementation and
support gates, rather than prerequisites for finishing G01.

## First platforms

Start with modern x86-64 UEFI hardware on Intel or AMD CPUs, a fixed wired NIC, NVMe storage, and the selected NVIDIA family. AMD CPU support is independent of an AMD GPU/ROCm backend. Legacy 32-bit i386 is a later research target, not an initial inference promise.

A notebook can be a native model shard. Admission measures sustained execution under mains power, thermal behavior, usable memory, link latency/jitter, and availability. Initially use a headless profile with sleep disabled. GPU power restoration and multi-function PCI behavior need explicit qualification; [NVIDIA's notebook power documentation](https://download.nvidia.com/XFree86/Linux-x86_64/580.95.05/README/dynamicpowermanagement.html) describes relevant platform dependencies, not a Tessryn driver.

The first observed cloud CPU sequence uses one x86-64 Nitro `t3a.small` profile: UEFI loading, bounded serial diagnostics, kernel CPU ownership and independent termination/reprovisioning recovery. It has no native ENA, NVMe or GPU driver evidence; firmware loading the boot disk does not establish kernel storage support. Wider cloud work separately qualifies ACPI/interrupts, ENA networking and NVMe storage. AWS documents [snapshot-backed AMI registration with boot mode](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-ami-boot-mode.html) and [direct EBS snapshot writes](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-accessing-snapshot.html). This is a technically targetable image route, not official support for an arbitrary original OS. [VM Import's OS allowlist](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html) describes that import service; it must not be mistaken for every possible AMI creation route. GPU instances require separate device and firmware qualification. Google also documents [building custom OS images](https://docs.cloud.google.com/compute/docs/images/building-custom-os); its device contracts are distinct targets.

## Apple M5 and numerical formats

[Apple's November 2025 MLX evaluation](https://machinelearning.apple.com/research/exploring-llms-mlx-m5) confirms M5 GPU Neural Accelerators exposed through Metal 4 TensorOps and Metal Performance Primitives, requiring macOS 26.2 or later. These GPU units are distinct from the separate Neural Engine. Its selected BF16 and quantized model results establish macOS runtime capability, not Tessryn support.

[MLX 0.30.3, released 2026-01-13](https://github.com/ml-explore/mlx/releases/tag/v0.30.3), adds NVFP4/MXFP8 quantized operations on Metal. In its [quantized NAX kernels](https://github.com/ml-explore/mlx/blob/v0.30.3/mlx/backend/metal/kernels/fp_quantized_nax.h), packed weights/scales are dequantized into a floating compute type; the [matrix primitive](https://github.com/ml-explore/mlx/blob/v0.30.3/mlx/backend/metal/kernels/steel/gemm/nax.h#L715) uses TensorOps. Shape-dependent dispatch and small decode paths differ. These kernels establish format support and eligible accelerator use after dequantization; they do not establish NVFP4 multiply arithmetic. Record storage format, dequantization, multiply/accumulate dtype, and actual execution unit separately.

[Apple's WWDC2026 TensorOps session](https://developer.apple.com/videos/play/wwdc2026/330/) documents FP4/FP8 tensor inputs and automatic dequantization with macOS 27. Native quantized API support still does not specify the instruction-level arithmetic contract needed by an original GPU backend.

Porting MLX's API does not supply Apple's GPU command, firmware, memory, or boot interfaces. The inspected [Asahi M5 support table](https://asahilinux.org/docs/platform/feature-support/m5/) marks GPU, Thunderbolt, NVMe, and key boot peripherals TBA and installers unavailable. Native M5 remains a separate high-uncertainty effort.

[Apple's Thunderbolt RDMA note](https://developer.apple.com/documentation/technotes/tn3205-low-latency-communication-with-rdma-over-thunderbolt) documents macOS APIs with two-sided send/receive and at most ten UC queue pairs. Send completion does not guarantee uncorrupted peer reception; application integrity and acknowledgment remain necessary. This is a hardware opportunity and reference behavior, not an existing Tessryn transport or native controller driver.
