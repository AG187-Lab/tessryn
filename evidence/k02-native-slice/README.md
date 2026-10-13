# First native K02 memory protection slice

Recorded 2026-10-12. Four fresh original-kernel boots pass on a single-CPU QEMU
q35/TCG profile with 256 MiB RAM, 48-bit physical addresses, four-level paging
and NX enabled. PCID, global translations and LA57 are disabled. This evidence
does not complete K02 or qualify physical hardware, AWS memory isolation, SMP,
DMA, general service dispatch or GPU execution.

The tested clean source is
[`1caebb8b1693e1bc5c73c3cb8fd42da8a861bac5`](https://github.com/AG187-Lab/tessryn/commit/1caebb8b1693e1bc5c73c3cb8fd42da8a861bac5).
Both native manifests have SHA256
`4d6e423e7a9371112446a0980f6afa72fbac84e967a05198868f54776a73815d`.
All 13 generated artifacts and five notices match byte for byte between the
two independent builds. The evaluator hash is
`36447b35c2fe0ce0c88fe6c48cf5f620229267fdc274e6a5cab2f222553c2001`.

| Fresh case | Hardware trace and protected postcondition |
| --- | --- |
| [Owned page](own_page/stdout.log) | CPL3 writes word 1, reads the owned sentinel, then reaches the exact compiled INT80 return; vector 128, error 0 |
| [Foreign read](foreign_read/stdout.log) | CPL3 read of A's absent mapping faults at the exact compiled instruction/address; vector 14, error 4 |
| [Kernel read](kernel_read/stdout.log) | CPL3 read of protected policy state through its supervisor alias faults; vector 14, error 5 |
| [Read-only write](readonly_write/stdout.log) | CPL3 write to the delegated read-only page faults; vector 14, error 7 |

Every run has CS `0x33`, SS `0x2b`, a frame on the dedicated image-owned trap
stack, exit code 33 and empty stderr. The four physical backing pages are
distinct. B has no capability for the foreign page, which is separate from the
deliberately delegated read-only page. The privileged adapter observes zeroed
allocations, checks every word of the foreign/shared/owned pages after execution,
and retains leases through fencing, PTE removal and actual CR3 reloads before
trusted quiescence. All four mappings are torn down and owned allocation count
returns to zero.

[Verification](verification.json) recomputes raw log hashes, trap expectations,
compiler-object label offsets, the unique linked EFI code page, boot media,
toolchain/firmware identities and the independent build comparison. A guest
PASS line alone is insufficient. Two independent reviewers also checked the
raw traps, privilege boundary, policy leases and artifact bindings. Review
caught a shared foreign backing in the earlier bring-up fixture; the recorded
clean-source runs use a separate unshared page and reject that alias.

[The evidence index](index.json) binds the exact retained files and scope.
[Manifest A](a/manifest.json) and [manifest B](b/manifest.json) record the source,
compiler dependency hashes, target, commands, firmware and generated artifacts.
The binaries, boot disks, compiler objects, library and notices remain retained
in the ignored local build directories. They are not included in this Git
packet; its manifests and raw logs alone are not a complete offline replay
bundle. The [dedicated CI](../../.github/workflows/k02-native.yml) retains both
complete rebuild artifact sets through an exact allowlist. Each CI capture
records its own source and host/toolchain bindings.

[Host checks](host/result.json) passed 57 core, 14 mapper and 6 adapter tests,
with no failures or ignored cases. [Python tests](python-tests.log) passed all
464 tests, including 13 native-tooling format/rejection fixtures. These are
host regressions, not substitute execution evidence. The fresh K01 regressions
([normal](k01/normal/stdout.log), [INT3](k01/int3/stdout.log),
[page fault](k01/page_fault/stdout.log)) passed without changing the shared K01
tools or earlier frozen evidence.

The implementation integrates reviewed K01 PR 53 and K02 preparation already
merged into main at `dc984e34e29b561eba89ff7186bbb82276a225e8`. PR 53 remains open
pending its owner's merge approval. K02 issue 5 remains open for the full
[ten-case protocol](../../design/k02-native-preparation.md). The implementation,
limits and rerun commands are in [the design](../../design/k02-native-slice.md).
