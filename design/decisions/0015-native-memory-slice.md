# ADR 0015: First native memory protection slice

Status: accepted implementation boundary; execution acceptance is recorded
separately in [the slice report](../k02-native-slice.md).

## Context

The owned-memory core and boot inventory have host policy tests. K01 supplies a
validated final firmware handoff and supervisor paging. Those results do not
show that a CPL3 load or store is blocked by the original kernel's page tables.
GPU Mart qualification is independent of this CPU protection work.

## Decision

Integrate a bounded four-case experiment into the original UEFI kernel, with
one CPU and a declared QEMU profile. Reuse the existing `MemoryPolicy`,
`BootInventory`, capability generations and mapping leases. Copy the final
successful handoff after CPU ownership, reserve all live ranges, and scrub
admitted pages through privileged bounded writes before exposure.

Use independent image-owned page-table pools for domains A and B. Preserve
supervisor identity coverage, add exact 4 KiB user data pages with NX, and map an
image-bound read-only executable probe page through a separate trusted-code
path. B owns its writable data and stack, receives a delegated read-only page,
and receives no capability for a distinct A-owned foreign page.

Enter CPL3 using dedicated user segments and a dedicated supervisor trap stack.
Only the exact expected probe fault or controlled return can restore the saved
kernel root and stack. Verify whole-page sentinels, fence mapping leases, remove
PTEs and actually reload CR3 before acknowledging quiescence or freeing frames.
PCID, global translations, LA57, interrupt delivery and other CPUs are excluded
from this experiment's teardown assumptions.

Bind probe offsets and instruction bytes to retained compiler objects and the
linked EFI, preserve raw bounded emulator logs, and require two independent
byte-identical builds. Synthetic parser tests cannot supply execution evidence.

## Consequences

This first slice can establish authorized access, an unshared-page read fault,
a supervisor-page read fault and a read-only write fault in a declared emulated
environment. It cannot establish the full K02 acceptance matrix, a production
dispatcher, revocation/reuse safety, SMP or DMA isolation, physical hardware or
cloud protection support. Keep those gates open and retain K01 qualification
separately. No provider operations or new rentals are needed for this slice.

## October 14, 2026 implementation extension

The [ten-case matrix](../k02-native-matrix.md) extends the original four-probe
experiment within the same image-bound single-CPU boundary. Protected request
context, exact bounds/NX, recursive revocation, actual writable-frame reuse and
stale generations now have [clean execution evidence](../../evidence/k02-native-matrix/README.md).
The entry also clears unused general and legacy FP state and verifies the original
kernel state on return; active OSXSAVE remains excluded. The original four cases
and K01 boot regressions remain required alongside the extension.

This extension does not introduce a production syscall/service ABI or qualify
arbitrary service programs, physical hardware, SMP shootdowns, DMA/device
quiescence, GPU execution or inference performance. Those gates remain open.
