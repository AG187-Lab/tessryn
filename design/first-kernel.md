# K01 first original kernel

This bring-up implements the original Rust x86-64 kernel as an unsigned UEFI
application. Firmware loads `EFI/BOOT/BOOTX64.EFI`; the image validates its memory
handoff and calls `ExitBootServices` before entering its own CPU and memory state.
The firmware is a boot dependency, not a deployment kernel. K01 has no storage,
NIC, GPU, service or inference implementation.

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
media with test-only I/O enabled. Physical images contain no QEMU test port or
unqualified UART writes. `deployment/boot.img` is generated for reproducibility,
but fixed-disk installation remains unqualified.
FAT16 is specified for removable UEFI media; fixed-disk FAT32 installation and
native storage drivers remain IO02 work. The kernel executes from RAM after
firmware loads it, and does not write a disk or install itself.

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

The current CPU profile is one x86-64 boot CPU, UEFI physical addressing, unsigned
image loading, and the kernel's live image, handoff map, stack and runtime regions
below 4 GiB. It installs its own stack, GDT, IDT and CR3 with a 4 GiB identity map.
These early mappings provide no process isolation or DMA authority. Interrupts
remain disabled. K02 and IO01 provide later isolation and platform support.

The final UEFI map is checked for layout, overflow, overlapping ranges and the
ownership of image/map/stack allocations. Loader, firmware runtime, ACPI and
reserved memory is retained. Only admitted conventional memory is used for the
scratch-page ownership test. The handoff reacquires the memory-map key when
`ExitBootServices` reports a stale key, without allocating in the retry path.
Firmware boot services are never used after successful exit. The physical runtime
reset pointer and runtime ranges are retained for the controlled reboot case.

Emulator diagnostics go to debug port `0xe9`, bounded COM1 output and a supported
GOP framebuffer. The physical image uses only the GOP framebuffer; missing or
unsupported graphics returns an error to firmware before handoff. A minimal
original glyph renderer preserves visible post-handoff status for IPMI KVM.
Graphics selection uses the firmware output console's GOP first. If it has no
usable linear framebuffer, the kernel accepts only one unique usable GOP
framebuffer; ambiguous graphics selection is refused before handoff. This avoids
drawing status on a discrete GPU while an IPMI console displays another adapter.

| Case | Expected observation |
| --- | --- |
| `normal` | Ordered entry/map/exit/CPU/ownership markers, then `TESSRYN_K01_PASS` |
| `int3` | Owned IDT catches vector 3 and records the fault frame |
| `invalid_opcode` | `ud2` reaches vector 6 diagnostics |
| `page_fault` | Read outside the owned 4 GiB map reaches vector 14 and records CR2 |
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
Verification requires two equal independent manifests and all seven boot cases.
The physical image is booted separately with no test ports; the display capture
retains its framebuffer for explicit visual inspection. A captured image alone
does not automatically prove boot success.
These results establish the declared emulator profile, not physical support,
hostile-candidate isolation or inference performance. G03 fixtures retain their
separate schema and claims. The wider native-service ABI remains G02 work.

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
