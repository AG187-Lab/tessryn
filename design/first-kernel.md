# K01 first original kernel

This bring-up implements the original Rust x86-64 kernel as an unsigned UEFI
application. Firmware loads `EFI/BOOT/BOOTX64.EFI`; the image validates its memory
handoff and calls `ExitBootServices` before entering its own CPU and memory state.
The firmware is a boot dependency, not a deployment kernel. K01 has no storage,
NIC, GPU, service or inference implementation. The separate
[AWS CPU profile](aws-boot-and-recovery.md#observed-cpu-qualification) has two
owner-accepted native `t3a.small` boots and independent recovery on a separate
Ubuntu instance, with cleanup complete. Native device drivers remain unavailable.

## Build and reproduce

Use Python 3.12 or newer on the G03 development hosts (macOS arm64 or Linux
x86-64). Install the prerequisites in [the build guide](build-and-evaluation.md),
then run from a fresh checkout:

```sh
python3 tools/setup_toolchain.py --jobs 4
python3 tools/setup_uefi.py
python3 tools/build_kernel.py --out build/kernel-a
python3 tools/build_kernel.py --out build/kernel-b
for case in normal int3 invalid_opcode page_fault panic reboot; do
  python3 tools/run_kernel.py --manifest build/kernel-a/manifest.json --case "$case" --out "build/k01-$case"
done
python3 tools/run_kernel.py --manifest build/kernel-a/manifest.json --media iso --out build/k01-iso
python3 tools/check_kernel_display.py --manifest build/kernel-a/manifest.json --out build/k01-display
python3 tools/verify_kernel.py --first build/kernel-a/manifest.json --second build/kernel-b/manifest.json \
  --result build/k01-normal/result.json --result build/k01-int3/result.json \
  --result build/k01-invalid_opcode/result.json --result build/k01-page_fault/result.json \
  --result build/k01-panic/result.json --result build/k01-reboot/result.json \
  --result build/k01-iso/result.json --out build/k01-verification.json
```

Outputs and result directories must be new. `deployment/BOOTX64.EFI` is the
physical kernel and `deployment/boot.iso` is its EFI El Torito virtual-CD image
for initial remote tests. `normal/boot.img` and `normal/boot.iso` are emulator
media with test-only I/O enabled. These deployment images contain no QEMU test port or
unqualified UART writes. `deployment/boot.img` is generated for reproducibility,
but fixed-disk installation remains unqualified.
FAT16 is specified for removable UEFI media. The AWS builder separately produces
a GPT/FAT32 fixed-disk boot input, tested locally through firmware NVMe loading;
native storage drivers and OS installation remain IO02 work. The kernel executes
from RAM after firmware loads it, and does not write a disk or install itself.

The additive [UEFI lock](../uefi-toolchain.lock.json) pins the upstream Rust
1.96.0 UEFI target library and the exact OVMF CODE/VARS bytes supplied by G03's
QEMU 11.1.2 archive. Setup verifies archive/member/output hashes, preserves
firmware and Rust notices, and uses a separate `build/uefi` sysroot so G03's
freestanding fixture toolchain remains unchanged. Third-party firmware stays
inside ignored build directories and CI artifacts contain only original kernel
media, build logs/manifests and controlled results.
Final linking disables PDB/CodeView output: its path-dependent GUID otherwise
changes the EFI bytes between independent output directories. Kernel images
retain runtime panic and exception diagnostics; a kernel debugger symbol profile
remains future work. CI publishes only the explicit artifact allowlist.
Kernel bundles include the project's license/notice and Rust's pinned license
and copyright notices for the linked core/compiler-builtins. The manifest hashes
these notices alongside the original boot artifacts.

## Boot contract

The CPU profile is one active x86-64 boot CPU, UEFI physical addressing and
unsigned image loading. It installs its own stack, GDT, IDT and CR3. Four-level
paging preserves the first 4 GiB supervisor identity mapping and adds mappings
for the live image, stack, handoff map, owned high scratch page, selected GOP
buffer and every EFI runtime-attribute range. The whole image includes the
kernel's descriptor tables and page-table pool. High ranges are rounded to
2 MiB leaves; mapped padding grants no allocator ownership.

Mapping preparation is bounded by 128 page-table pages and 16,384 distinct
2 MiB leaves, including the low mapping. Required ranges must fit the CPU's
reported physical address width and the lower canonical half. Overflow,
unsupported active five-level paging, guard overlap and exhausted table/leaf
capacity reject the handoff before `ExitBootServices`. Tables are prepared from
each validated map before exit; stale-key retries rewrite owned tables without
firmware allocations. These coarse mappings provide no process isolation or DMA
authority. Interrupts remain disabled; K02 and IO01 provide later protection and
platform support.

The final UEFI map is checked for layout, overflow, overlapping ranges and the
ownership of image/map/stack allocations. Loader, firmware runtime, ACPI and
reserved memory is retained. Conventional free-page accounting is limited to
mapped RAM below 4 GiB. The normal scratch test uses that conventional RAM;
the emulator-only high-handoff fixture instead reserves a real high loader-data
page before exit and proves its ownership by volatile write/readback. It does
not admit all high conventional RAM. The handoff reacquires the memory-map key when
`ExitBootServices` reports a stale key, without allocating in the retry path.
Firmware boot services are never used after successful exit. The physical runtime
reset pointer and runtime ranges are retained for the controlled reboot case.
The canonical address `0x7fffffe00000` begins a reserved unmapped 2 MiB guard,
used by the deliberate page-fault case. Low and high mappings cannot consume it.

Emulator diagnostics go to debug port `0xe9`, bounded COM1 output and a supported
GOP framebuffer. The physical image uses only the GOP framebuffer; missing or
unsupported graphics returns an error to firmware before handoff. A minimal
original glyph renderer preserves visible post-handoff status for IPMI KVM.
Graphics selection uses the firmware output console's GOP first. If it has no
usable linear framebuffer, the kernel accepts only one unique usable GOP
framebuffer; ambiguous graphics selection is refused before handoff. This avoids
drawing status on a discrete GPU while an IPMI console displays another adapter.
The explicit AWS profile instead uses bounded COM1 at an assumed `0x3f8`,
115200n8, with optional GOP and terminal halt. It never writes QEMU ports `0xe9`
or `0xf4`; its normal boot UART path has execution evidence for the recorded
`t3a.small` profile. Other profiles require separate qualification.

| Case | Expected observation |
| --- | --- |
| `normal` | Ordered entry/map/exit/CPU/ownership markers, then `TESSRYN_K01_PASS` |
| `int3` | Owned IDT catches vector 3, records its frame and returns with floating-point/SIMD state preserved |
| `invalid_opcode` | `ud2` reaches vector 6 diagnostics |
| `page_fault` | Read at the unmapped canonical guard reaches vector 14 with CR2 `0x7fffffe00000` |
| `panic` | Rust panic handler reports the deliberate panic and halts |
| `reboot` | Kernel requests a cold reset through retained UEFI runtime services |

The evaluator supplies `isa-debug-exit`: expected normal/fault/panic cases exit
with host code 33, failures with 35. The reset case uses QEMU `-no-reboot` and
expects host code 0 plus enabled CPU-reset diagnostics with no triple fault;
a triple-fault exit cannot pass as controlled reboot. On physical hardware the normal image displays its terminal
status and halts. The separately built fault and reboot images are evaluation
artifacts; start remote tests with the deployment ISO.

The runner owns fresh firmware VARS and disposable boot media (IDE disks use a
scratch snapshot; virtual CDs are read-only). It
exposes no host filesystem, network, physical disk or passthrough device. Results
bind source/build manifest, emulator, firmware, evaluator and raw log hashes.
Verification requires two equal independent manifests, all six cases and the
normal virtual-CD execution.
The checked-in [K01 evidence](../evidence/k01-verification/README.md) records a
clean implementation build, raw case transcripts and the visual disposition.
The physical image is booted separately with no test ports; the display capture
retains its framebuffer for explicit visual inspection. A captured image alone
does not automatically prove boot success.
These results establish the declared emulator profile, not physical support,
hostile-candidate isolation or inference performance. G03 fixtures retain their
separate schema and claims. The wider native-service ABI remains G02 work.

## High-address regressions

Increasing RAM alone does not prove high-address execution. The nine 8 GiB
QEMU runs require observed image, stack, map, scratch, CR3 and post-switch RIP
addresses. Four `image-*` variants exercise a live image above 4 GiB; four
`handoff-*` variants additionally use real high stack/map/scratch allocations
with `k01_high_handoff`. Each group covers normal, returning INT3, page fault and
runtime reset. The `ram-only` control keeps its image and scratch below 4 GiB
despite the same RAM size.

After the pinned setup, run from a clean checkout with new output paths:

```sh
python3 tools/build_kernel.py --high --out build/high-kernel-a
python3 tools/build_kernel.py --high --out build/high-kernel-b
for variant in image-normal image-int3 image-page_fault image-reboot handoff-normal handoff-int3 handoff-page_fault handoff-reboot ram-only; do
  python3 tools/run_kernel_high.py --manifest build/high-kernel-a/manifest.json --variant "$variant" --out "build/k01-high-$variant"
done
python3 tools/verify_kernel_high.py --first build/high-kernel-a/manifest.json --second build/high-kernel-b/manifest.json \
  --result build/k01-high-image-normal/result.json --result build/k01-high-image-int3/result.json \
  --result build/k01-high-image-page_fault/result.json --result build/k01-high-image-reboot/result.json \
  --result build/k01-high-handoff-normal/result.json --result build/k01-high-handoff-int3/result.json \
  --result build/k01-high-handoff-page_fault/result.json --result build/k01-high-handoff-reboot/result.json \
  --result build/k01-high-ram-only/result.json --out build/k01-high-verification.json
python3 -m unittest discover -s tests -p test_kernel_high.py -v
```

`TESSRYN_K01_LIVE_RANGES` and `TESSRYN_K01_PAGING_READY` record admitted addresses
before firmware exit. `TESSRYN_K01_CPU_OWNED` records actual CR3/RSP/RIP afterward;
the high probe marker binds successful readback to the admitted scratch page.
The evaluator checks these fields and retains runtime/GOP placement observations.
Current tested OVMF runtime ranges remain low (`runtime_high=0`), and GOP is at
`0x80000000`; passing high image/handoff cases cannot establish high firmware
runtime or high framebuffer execution.

Separately labeled pure paging fixtures test synthetic high runtime/GOP ranges,
crossings of 4 GiB/1 GiB and a sparse PML4 entry above 512 GiB, overflow, physical
width, canonical guard exclusion and table/leaf budgets. These exercise mapping
math, rather than relocating actual firmware or qualifying a device. High runs
use freshly copied disposable disks and fresh VARS, with no host shares, network
or physical devices.

## GPU Mart test path

GPU Mart advertises dedicated bare-metal servers with IPMI. Its provider FAQ
documents custom ISO loading by virtual media/FTP and BIOS changes for dedicated
servers, while VPS products lack those controls. This is a provider capability,
not a tested Tessryn platform. Use a **dedicated server** for this experiment.
Sources checked October 11, 2026:
[dedicated server offering](https://www.gpu-mart.com/gpu-dedicated-server),
[custom ISO and IPMI FAQ](https://www.databasemart.com/faq/technical-questions).

Before selecting a delivered machine, confirm x64 UEFI, authority to load an
unsigned image, IPMI KVM and virtual CD, independent power/reset, and a known-good
boot route. The exact hardware and RAM-only custom-boot route need provider or
machine evidence. Rental/access evidence is currently absent; this change does
not order a server. Reconcile the current quote with the provider because its
[hourly page](https://www.gpu-mart.com/pricing-hourly) and
[billing FAQ](https://www.databasemart.com/faq/billing-questions) describe differing
minimum billing arrangements.

For an authorized machine:

1. Record the delivered CPU/firmware, PCI IDs, recovery controls and custom-boot
   permission. Retain exact device inventory separately from kernel results.
2. Build or download the `k01-kernel-and-evidence` CI artifact; verify the ISO
   SHA-256 against `manifest.json`. Keep the deployment ISO and existing boot route.
3. Attach `deployment/boot.iso` as IPMI virtual CD, choose its UEFI boot entry and boot
   without installing or formatting storage. K01 uses RAM and leaves storage
   untouched; keep the provider's recovery path available.
4. Capture the visible handoff/terminal status and serial log if accessible.
   Record artifact hash, firmware version and expected versus actual outcome.
5. Detach virtual media, return to the known-good boot target and verify recovery.
   Stop and preserve failure evidence if boot or recovery differs from expectation.

Passing this test proves only native CPU boot for that exact delivered profile.
GPU Mart's name or NVIDIA GPU presence does not establish a working native GPU
driver. PCI/IOMMU, exact NVIDIA initialization and cubin execution remain IO01,
GPU01 and GPU02 gates.

## Primary specifications

- [UEFI system tables](https://uefi.org/specs/UEFI/2.11/04_EFI_System_Table.html)
- [UEFI boot services and memory handoff](https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html)
- [UEFI media and El Torito boot](https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html)
- [Rust UEFI target](https://doc.rust-lang.org/rustc/platform-support/unknown-uefi.html)
