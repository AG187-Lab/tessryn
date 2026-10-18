# Two-CPU bootstrap: clean emulator evidence

October 17, 2026. Both original-kernel scenarios passed at clean implementation
[`f3f39b8e333b5e6fcb96a829dddaa480a5858ee1`](https://github.com/AG187-Lab/tessryn/commit/f3f39b8e333b5e6fcb96a829dddaa480a5858ee1).
The [contract](../../design/k03-smp-bootstrap.md) and [ADR 0020](../../design/decisions/0020-two-cpu-bootstrap.md)
describe this kernel-only, fixed two-CPU QEMU/OVMF profile. K03 remains open for
isolated CPL3 SMP execution, scheduler budgets, contention and physical clocks.

## Observed execution

| Scenario | Original trace observation |
| --- | --- |
| [Rendezvous](rendezvous/stdout.log) | Two admitted xAPIC CPUs install distinct GDT/IDT/TSS and stacks, sharing one fixed CR3. Each contributes 4096 atomic increments, total 8192. AP progress overlaps a 20.009ms BSP observation window. Three generation-bound vector-64 IPIs have actual source/EOI acknowledgments and resumed AP progress. Vector 65 acknowledges stop generation 4; the AP heartbeat stays fixed for 20.018ms. |
| [Missing AP](missing_ap/stdout.log) | Targeted INIT deliberately receives no SIPI. The protected readiness timeout rejects after 2.010147s of guest HPET time, with no AP CPU facts or successful two-CPU completion. |

The AP's last RAM write is its terminal acknowledgment; it parks without a Rust
epilogue or IRET. All RAM remains retained through experiment exit. This grants
no authority to reclaim its stack, tables, trampoline or acknowledgment storage.
No CPL3 program, SMP scheduler, per-CPU timer, general idle/wakeup or device/DMA
quiescence is exercised by this profile. These are guest observations, with no
physical timing, parallel speedup or inference-performance qualification.

## Bindings and checks

- [Verification](verification.json) binds clean Git source, pinned tools, all
  10 compiler and 24 runtime/host inputs, matching six-artifact independent twins,
  26 actual Rust parser checks and both fresh registered captures.
- Actual interrupt RIPs must be instruction starts in the compiled eight-byte
  AP heartbeat loop. Raw frames, stack/FP storage relationships, IF/CS/root,
  actual ISR/EOI words, generations, progress and clock intervals are replayed.
- [Python test log](python-tests.log): 725 passed, including 28 focused SMP
  tooling/trace methods. [Design validation](design.log) records the 84-document
  implementation checkpoint before this packet README was added.
- [Full artifact inventory](full-artifact-audit.json): exactly 120 files,
  153,568,990 bytes. Its binary artifacts, firmware and retained source copies
  are hashed here and retained separately. The CI workflow uploads that explicit
  inventory, including hidden workflow sources, with 14-day retention.

The literal object twin check rejected an earlier diagnostic because nested
temporary source names survived in COFF debug records. Corrected compiler path
remapping produced byte-identical EFI images, objects and disks. Earlier dirty
diagnostics and unaccepted SMP v1/v2 outputs are excluded from this packet.

## Earlier-profile regressions

The original regression executions retain their actual clean source
[`febcb2ff53a512daa7ba8bac6f6156c9cbc3a6e4`](https://github.com/AG187-Lab/tessryn/commit/febcb2ff53a512daa7ba8bac6f6156c9cbc3a6e4).
The final source changes only three new SMP build helpers. The
[shared-input proof](summary.json) checks 91 declared regression compiler,
runtime and host inputs against both Git commits, retained originals and the
current checkout. Historical K01 lacks a per-file map; the complete Git delta
also leaves every non-SMP-helper blob unchanged. These results are not relabelled
as executions at the later source.

All 51 original wrapper commands passed: 97 native host checks, four original
memory probes, ten matrix boots/52 traps, seven K01 boots including ISO, three
cooperative region-service cases/21 host checks, four timer cases/90 host checks,
and the 13-case/208-sample guest benchmark plus two clock checks. The 43 portable
vectors in [commands.json](commands.json) cover the earlier kernel and
service/benchmark wrappers; timer inputs, execution and results are separately
bound in their manifests, receipts, registrations and verification report.

The budget regression additionally records one actual
[`ARM_MISSED`](regressions/timer/budget/stdout.log): a 63,000ns remaining grant
does not enter CPL3 after arming misses, and the full observed 1,472,000ns is
charged as a late failed stop. The peer completes and final reservations and
memory ownership are zero. This new emulator observation does not alter the
historical timer packet or establish physical interrupt-latency bounds.

## Retained text and reproduction

[Index](index.json) hashes 272 byte-preserved successful originals and the
derived navigation files. Fourteen historical slice/matrix result JSON files
with local launch paths remain private, unaltered, with explicit hash/size
omissions. Their public raw streams and verification reports remain present.
Binary media, copied source trees and firmware are omitted from this public
text packet. It is insufficient by itself for the full binary verifier.

Fetch the retained feature branch and check out the exact implementation commit
above to reproduce its whole Git snapshot. Install the repository's pinned
toolchain/UEFI inputs, then run the fresh-directory commands in the
[reproduction contract](../../design/k03-smp-bootstrap.md#acceptance-and-reproduction).
Use each regression's recorded source identity for its original source snapshot.
The complete text/data artifact hashes distinguish original bytes from derived
navigation. Offline replay checks consistency; it does not independently
authenticate who ran a capture. Qualified clocks and a preregistered native
complete-path performance comparison remain pending.
