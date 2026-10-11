# ADR 0010: Start with a firmware-loaded original UEFI kernel

Status: Accepted for K01 bring-up; physical hardware qualification remains open.

## Decision

Compile original Rust `no_std` code and a small original x86 assembly boundary
into a relocatable x64 UEFI application. Use firmware only for initial image and
memory handoff. After `ExitBootServices`, the kernel owns its stack, descriptor
tables and page tables. Preserve physical UEFI runtime memory for reset; do not
introduce an existing deployment kernel or third-party bootloader.

The initial emulator profile is QEMU q35/TCG with checksum-pinned OVMF from the
existing QEMU source archive. Build deterministic disk and EFI El Torito ISO
media. The latter matches the documented IPMI virtual-media path on GPU Mart
dedicated servers. Exact physical boot/recovery remains a separate qualification.

## Consequences

This narrow bring-up validates actual Rust kernel execution and exception paths.
It does not freeze the native service ABI, qualify NVIDIA execution, provide
process isolation, support arbitrary firmware/memory layouts or implement storage.
Live kernel and runtime regions must fit the first 4 GiB identity-map profile.
Firmware runtime services retain their separate provenance and lifetime.

The upstream UEFI core archive uses a separate verified sysroot. G03's fixture
build and evaluator contracts remain intact. Original media and retained results
are reproducible; firmware binaries and compiler distributions are not committed.

## Evidence

[First kernel workflow](../first-kernel.md), [K01 issue](https://github.com/AG187-Lab/tessryn/issues/4),
[original-kernel commitment](0001-original-kernel.md), and
[language/toolchain proposal](0002-language-and-toolchain.md).
