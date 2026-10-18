# Two-CPU CPL3 context evidence

Clean implementation: [`ef205654aa6b4e75afb77cc8c2affc1a927f7656`](https://github.com/AG187-Lab/tessryn/commit/ef205654aa6b4e75afb77cc8c2affc1a927f7656).
Recorded October 17, 2026, under pinned QEMU/OVMF on the admitted development
host. Scope: original-kernel emulator correctness. Physical clocks, speed,
inference performance and the broader shared-budget K03 gate remain unqualified.

The complete clean `git-worktree-v2` snapshot is
`f12ab9f4b71f56b142276a9b99556c0ed11d32a63fead8ace498d7a6a8e814af`.
All compiler, runtime, host and prior-profile observations here refer to that
implementation. Diagnostic captures and earlier failed compiler attempts supply
no acceptance evidence. Later PR/main CI captures have their own source identities
and artifacts.

## Accepted observations

| Case | Original execution |
| --- | --- |
| `rendezvous` | Both CPUs execute CPL3 under distinct private roots. AP completes 65,536 warmup increments while BSP progresses, yields through its private INT128 gate, and sends a source-authenticated IPI to stop BSP. AP resumes its saved context and reaches heartbeat 90,519 before BSP's authenticated IPI. Both user stops have actual CPL3 frames and LAPIC ISR 4 → 0. |
| `peer_read` | AP faults at the bound peer-read instruction with #PF vector 14, error 4 and CR2 `0x100200000`. BSP continues after the fault for the required guest-time interval, then receives a genuine peer IPI. The fault supplies no hardware IPI acknowledgment. |
| `forged_ipi` | AP's bound INT66 produces #GP vector 13, error `0x212`, with no hardware IPI acknowledgment. BSP continues after the fault and is subsequently stopped by a genuine peer IPI. |

Across the three fresh boots, replay verifies 54 actual page-table walks,
seven raw CPL3 traps, complete 15-register and 512-byte legacy FP images,
private GDT/IDT/TSS and stack ownership, protected SWAPGS state, and 12 unchanged
payload-digest observations. The bound program deliberately reloads GS. Each
boot finishes with a terminal AP acknowledgment and stable heartbeat over at
least 20 milliseconds of the admitted HPET guest clock. All RAM remains retained;
the acknowledgment grants no reclamation or device/DMA quiescence authority.

The source-bound acceptance also passed:

- 755 Python tests, including 30 focused new tooling/trace methods.
- 26 actual Rust ACPI parser tests with two retained process receipts.
- Independent matching EFI/object/disk builds for all three cases: nine twins,
  with all 18 binary/media files independently owned.
- All 57 prior-profile commands at the same clean source: K01, native isolation
  slice/matrix, cooperative service, single-CPU timer/budgets, kernel benchmark
  and original SMP bootstrap. Benchmark regression has 13 cases/208 samples;
  its 30 retained source bindings match the implementation commit.

## Packet boundaries

This text packet has 62 files: 58 byte-preserved original logs, receipts,
manifests, notices and verification reports, plus four navigation/index files.
[summary.json](summary.json) records every original path/hash/size and the exact
observations. [index.json](index.json) indexes all other public files; it excludes
itself to avoid a self-referential hash.

[commands.json](commands.json) is explicitly derived portable navigation for
the 57 successful outer regression commands. It keeps hashes of the original
private stdout/stderr receipts; it does not replace them or claim that rewritten
commands are original byte streams. The K01/slice manifests and benchmark
manifest/registration preserve those source chains. Earlier-profile raw logs,
media and source copies remain under their original reproduction outputs.

The complete separate success artifact contains exactly **149 files / 234,288,026
bytes**: both manifests, all nine binary/media artifacts from each build,
14 actual compiler dependencies and 26 runtime inputs retained for each twin,
notices, host receipts, original captures and firmware seeds. Public text omits
those binaries, retained source copies and firmware. The explicit upload list
is in the [workflow](../../.github/workflows/k03-smp-user.yml).

[full-artifact-audit.json](full-artifact-audit.json) binds that complete inventory
to the exact implementation Git tree, source hashes, locked metadata, notices,
binary/media bytes, host receipts and independent raw replay. Audit report SHA-256:
`a15a5a28b8cdb3e5d727df7ee05354dc4185929191735fd93d68a1774ed85c33`.
The audit uses reviewed local Python and executes no archived Python. Its local
preflight records the actual macOS host; portable Linux CI audits validate Linux
metadata without claiming to execute Linux binaries on macOS. Offline capture
origin remains independently unauthenticated.

## Reproduction and remaining gates

Fetch the retained `k03-smp-user` implementation history and use a clean checkout
of the exact commit above. Install the pinned toolchain as described in
[build and evaluation](../../design/build-and-evaluation.md), then follow the
[profile commands](../../design/k03-smp-user.md#evidence-and-release-gate) with
fresh output directories. Complete acceptance needs the twin builds, actual
host execution, all three fresh captures, full verifier and regression gates.

This profile runs two isolated instances of an image-bound program template.
Shared scheduler ownership, aggregate budgets/accounting, per-CPU timers,
arbitrary admission, general idle/wakeup/migration, safe reuse, devices/DMA and
physical qualification remain future work. The existing single-CPU profiles are
the correctness references. A preregistered native complete-path performance
comparison remains pending; heartbeat intervals and emulator counters establish
no physical latency, throughput or inference gain.
