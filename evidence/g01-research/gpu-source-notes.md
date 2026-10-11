# GPU and notebook candidate source notes

Observed 2026-10-11. These are original summaries of public primary sources. No
physical device was available, no instance was launched, and no firmware,
proprietary compiler or driver binary was downloaded. There is no native boot,
GPU execution, performance measurement or selected supported profile in this
record. A Linux reference behavior is evidence about that reference system.

## Cloud inventory and native-access questions

**Source facts.** AWS identifies `g5.xlarge` as a Nitro v3 virtual machine with an
AMD EPYC 7R32, four vCPUs, 16 GiB host memory, one A10G and 250 GB local NVMe.
The [technical instance table](https://docs.aws.amazon.com/ec2/latest/instancetypes/ac.html)
reports 22 GiB accelerator memory; the [G5 product page](https://aws.amazon.com/ec2/instance-types/g5/)
advertises 24 GB per GPU and GPU passthrough. Keep those distinct vendor figures;
neither is measured usable Tessryn memory. G5 has no metal SKU in the table.

**Source facts.** The [G4 product page](https://aws.amazon.com/ec2/instance-types/g4/)
and technical table describe actual bare-metal SKU `g4dn.metal`: Intel Xeon
P-8259L, 96 vCPUs, 384 GiB host memory, eight T4 GPUs with 16 GiB each, two
900 GB local NVMe SSDs and network bandwidth up to 100 Gbps. It is a rental
research candidate, not a selected or available-to-this-project test system.

**Critical unknowns.** Neither record supplies our observed PCI topology, BARs,
ACPI tables, interrupt routing, IOMMU configuration, reset authority, firmware
identity or native initialization sequence. Passthrough does not resolve these
questions. AWS [UEFI requirements](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/launch-instance-boot-mode.html)
exclude bare-metal instances from the generic Nitro dual-boot-mode statement.
Obtain exact instance-type boot-mode metadata before treating `g4dn.metal` as a
UEFI candidate. [Serial-console prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console-prerequisites.html)
allow this metal SKU but require account/IAM access; this research enabled none.

The [price observation](aws-price-observation.json) retains selected official
Linux reference rows, source hash and publication date. Its 24-hour totals are
calculations, excluding ancillary charges; original-OS billing classification is
unknown. [AWS On-Demand documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-on-demand-instances.html)
describes a 60-second minimum and a default zero running G/VT vCPU quota.
`g4dn.metal` would require 96 available quota units and capacity. A priced SKU
does not prove an account can launch it. Paid native tests require a bootable
artifact and a reviewed recovery/termination plan first.

## Firmware acquisition and source provenance

**Versioned Linux reference.** NVIDIA open GPU module tag `580.95.05` resolves to
commit `2b436058a616676ec888ef3814d1db6b2220f2eb` (annotated tag object
`6f7b8c00b63934655b66c5587fc6384a9764d5d8`). The
[pinned README](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/2b436058a616676ec888ef3814d1db6b2220f2eb/README.md)
lists A10G PCI device `2237`, subsystem vendor `10DE`, subsystem device `152F`.
These are expected identities to verify, not an inventory we collected. It
requires matching `580.95.05` GSP firmware and userspace driver components for
its Linux modules and describes separate OS-agnostic and Linux interface layers.
This reference does not establish a stable GSP ABI or a native Tessryn driver.

The [pinned source COPYING](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/2b436058a616676ec888ef3814d1db6b2220f2eb/COPYING)
applies MIT per file except where otherwise noted and dual MIT/GPLv2 to combined
Linux modules. Referencing source imports no code. Any future import requires
per-file license, notices, revision and modification provenance and must respect
the project's original-kernel decision.

**Separate binary terms.** The versioned
[driver license](https://download.nvidia.com/XFree86/Linux-x86_64/580.95.05/license.txt)
provides an OSI-licensed-kernel distribution route with unmodified binaries and
the agreement supplied to recipients, in section 1.1(d). Sections 2.1–2.6 impose
NVIDIA-platform, translation, binary modification/reverse-engineering and
authentication restrictions. This is an acquisition/distribution boundary, not
permission to relicense firmware as Apache-2.0. Inspect the terms and notices of
the exact future artifact. No artifact hash or successful native firmware
startup exists here. [GSP documentation](https://download.nvidia.com/XFree86/Linux-x86_64/580.95.05/README/gsp.html)
describes versioned `gsp_*.bin` files distributed with the driver.

## Device compiler target

**Source facts.** NVIDIA's [compute-capability table](https://developer.nvidia.com/cuda/gpus)
lists T4 at 7.5 and A10 at 8.6. A10G's proposed `sm_86` target is an inference
from its Ampere family and A10 reference, requiring exact-device confirmation;
the table does not name A10G. T4's proposed device-only target is `sm_75`.

CUDA `13.1.1` is a versioned research baseline, neither installed nor selected.
Its [compiler manual](https://docs.nvidia.com/cuda/archive/13.1.1/cuda-compiler-driver-nvcc/index.html)
documents device-only cubin output, discarding host code, and exact architecture
selection. For a future original source `probe.cu`, an **unexecuted** T4 example is:

```sh
nvcc --cubin --gpu-architecture=compute_75 --gpu-code=sm_75 probe.cu -o probe.sm75.cubin
```

The [versioned toolkit EULA](https://docs.nvidia.com/cuda/archive/13.1.1/eula/index.html)
limits SDK distribution to designated portions and conditions, prohibits a
standalone SDK distribution and limits application development to NVIDIA GPU
systems. Its Linux/FreeBSD provision does not by itself establish redistribution
rights for an original OS. Do not bundle `nvcc` or transfer the source-module
license to the toolkit. Before distributing a cubin, inspect embedded vendor
headers, `libdevice`, `libcudadevrt` and other linked portions and record their
terms, versions, hashes and notices. Compiler output and firmware startup remain
separate qualification questions.

## Exact notebook research candidate

**Source facts.** Lenovo [SKU `20YQ003FUS`](https://psref.lenovo.com/Detail/ThinkPad_P15_Gen_2?M=20YQ003FUS)
identifies a ThinkPad P15 Gen 2 with i9-11950H, RTX A2000 4 GB, 32 GB DDR4,
1 TB PCIe 4.0 NVMe, built-in 2.5 GbE RJ-45 and a 170 W mains adapter. The
[family specification](https://psref.lenovo.com/Product/ThinkPad/ThinkPad_P15_Gen_2?search=true)
identifies I225-LM for vPro configurations. This withdrawn SKU is research-only:
no unit, purchase recommendation, availability guarantee or support selection.

**Critical unknowns.** Confirm exact NIC/GPU PCI revisions and subsystem IDs,
topology, UEFI/EC versions, IOMMU/ACPI tables, reset/power control, usable memory
and sustained thermal/link behavior on a physical unit. NVIDIA's versioned
[Linux RTD3 reference](https://download.nvidia.com/XFree86/Linux-x86_64/580.95.05/README/dynamicpowermanagement.html)
requires platform ACPI `_PR0`/`_PR3` support and coordinated multifunction-device
power behavior. A mains-powered headless policy is not evidence of those
prerequisites. No cloud GPU VM or metal server qualifies the native notebook gate.
