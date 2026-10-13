# Platform qualification

Status: physical target profiles remain unqualified. The [K01 emulator profile](first-kernel.md) has original-kernel CPU boot and fault evidence, and the bounded [AWS CPU profile](aws-boot-and-recovery.md#observed-cpu-qualification) has owner-accepted native `t3a.small` boot and separate Ubuntu recovery evidence. Qualify physical CPU boot, networking/storage, accelerator compute, and distributed inference separately. A successful boot does not prove accelerator availability.

The [initial G01 qualification record](platform-qualification.md) prepares a short bare-metal inventory session without selecting supported hardware. Its candidate descriptions and costs are vendor facts and analytical examples; actual device/firmware/topology, notebook access and native execution remain unavailable.

G01 selects exact engineering targets only after physical inventories,
boot/device-access feasibility, recovery prerequisites and artifact constraints
have evidence. That decision can leave Tessryn capability statuses
unavailable. Original-kernel boot, native device initialization, GPU compute,
inference and thermal/load qualification are subsequent implementation and
support gates, rather than prerequisites for finishing G01.

## First platforms

Start with modern x86-64 UEFI hardware on Intel or AMD CPUs, a fixed wired NIC, NVMe storage, and the selected NVIDIA family. AMD CPU support is independent of an AMD GPU/ROCm backend. Legacy 32-bit i386 is a later research target, not an initial inference promise.

A notebook can be a native model shard. Admission measures sustained execution under mains power, thermal behavior, usable memory, link latency/jitter, and availability. Initially use a headless profile with sleep disabled. GPU power restoration and multi-function PCI behavior need explicit qualification; [NVIDIA's notebook power documentation](https://download.nvidia.com/XFree86/Linux-x86_64/580.95.05/README/dynamicpowermanagement.html) describes relevant platform dependencies, not a Tessryn driver.

The bounded cloud CPU experiment established two fresh original-kernel boots on
UEFI x86-64 `t3a.small` Nitro guests, separated by independent recovery on a fresh
Ubuntu instance, with cleanup complete. The
[AWS workflow](aws-boot-and-recovery.md) builds fixed GPT/FAT32 media, headless
COM1 diagnostics and local firmware-NVMe tests. No ENA or native NVMe driver is
present, and an EC2 guest boot does
not qualify bare-metal CPU access, a GPU, networking or inference. The wider
cloud target still needs ACPI/interrupt, ENA and NVMe implementation evidence.

The resource owner must confirm the exact instance type's `SupportedBootModes`
and launched `CurrentInstanceBootMode`; generic Nitro guarantees exclude metal.
Retain dated regional raw and sanitized observations rather than inferring a
boot mode from Nitro or metal labels. [Exact boot modes](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-type-boot-mode.html),
[UEFI requirements](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/launch-instance-boot-mode.html).

AWS documents [snapshot-backed AMI registration with boot mode](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-ami-boot-mode.html)
and [direct EBS snapshot writes](https://docs.aws.amazon.com/ebs/latest/userguide/writesnapshots.html).
This is an experimental custom-OS route, not official support for Tessryn.
[VM Import's OS allowlist](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html)
applies to that import service. The separate authorized `t3a.small` Linux-hosted
QEMU trial, capped at USD 15, supplied emulator evidence. The later native trial
received separate approval and trusted owner acceptance for its bounded CPU
profile. Its completion authorizes no additional resources or broader support.
Historical G01 candidate and price records retain their original research scope.
Google also documents [building custom OS images](https://docs.cloud.google.com/compute/docs/images/building-custom-os);
its device contracts are distinct targets.

## Apple M5 and numerical formats

[Apple's November 2025 MLX evaluation](https://machinelearning.apple.com/research/exploring-llms-mlx-m5) confirms M5 GPU Neural Accelerators exposed through Metal 4 TensorOps and Metal Performance Primitives, requiring macOS 26.2 or later. These GPU units are distinct from the separate Neural Engine. Its selected BF16 and quantized model results establish macOS runtime capability, not Tessryn support.

[MLX 0.30.3, released 2026-01-13](https://github.com/ml-explore/mlx/releases/tag/v0.30.3), adds NVFP4/MXFP8 quantized operations on Metal. In its [quantized NAX kernels](https://github.com/ml-explore/mlx/blob/v0.30.3/mlx/backend/metal/kernels/fp_quantized_nax.h), packed weights/scales are dequantized into a floating compute type; the [matrix primitive](https://github.com/ml-explore/mlx/blob/v0.30.3/mlx/backend/metal/kernels/steel/gemm/nax.h#L715) uses TensorOps. Shape-dependent dispatch and small decode paths differ. These kernels establish format support and eligible accelerator use after dequantization; they do not establish NVFP4 multiply arithmetic. Record storage format, dequantization, multiply/accumulate dtype, and actual execution unit separately.

[Apple's WWDC2026 TensorOps session](https://developer.apple.com/videos/play/wwdc2026/330/) documents FP4/FP8 tensor inputs and automatic dequantization with macOS 27. Native quantized API support still does not specify the instruction-level arithmetic contract needed by an original GPU backend.

Porting MLX's API does not supply Apple's GPU command, firmware, memory, or boot interfaces. The inspected [Asahi M5 support table](https://asahilinux.org/docs/platform/feature-support/m5/) marks GPU, Thunderbolt, NVMe, and key boot peripherals TBA and installers unavailable. Native M5 remains a separate high-uncertainty effort.

[Apple's Thunderbolt RDMA note](https://developer.apple.com/documentation/technotes/tn3205-low-latency-communication-with-rdma-over-thunderbolt) documents macOS APIs with two-sided send/receive and at most ten UC queue pairs. Send completion does not guarantee uncorrupted peer reception; application integrity and acknowledgment remain necessary. This is a hardware opportunity and reference behavior, not an existing Tessryn transport or native controller driver.
