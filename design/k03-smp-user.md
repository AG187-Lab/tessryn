# Isolated CPL3 execution on two CPUs

Status: bounded clean original-kernel emulator execution accepted;
[retained evidence](../evidence/k03-smp-user/README.md).

This bounded K03 step builds on the [two-CPU bootstrap](k03-smp-bootstrap.md)
and the single-CPU protection and context-preservation references. It gives each
CPU its own protected user execution context and immutable address space before
integrating a shared scheduler. [ADR 0021](decisions/0021-two-cpu-user-contexts.md)
records the ownership boundary.

## Fixed execution and authority boundary

The separate `k03_smp_user` emulator profile retains the bootstrap's admitted
two-CPU xAPIC, HPET, INIT/SIPI and firmware contracts. Each CPU has private
GDT/IDT/TSS, supervisor and fault stacks, saved continuation, general-purpose
registers and legacy FP state. User entry and traps never use the single-CPU
region runtime's global saved context.

The two instances copy the same original image-bound program template into
distinct physical code pages. Their protected role and case inputs select the
bounded flows below; this supplies no arbitrary loader or general task ABI.
SWAPGS selects the protected continuation after checking the actual CPL3 frame.
The program deliberately reloads GS, so disabling FSGSBASE alone cannot stand in
for that boundary. Each CPU also admits its actual control/debug/descriptor
state and disables the unused fast-system-call entry paths.

Both user page-table trees and their code, data and stack backing are prepared
before AP release. The same logical user addresses select distinct physical
pages. Kernel mappings remain supervisor-only; a peer-only user address is absent
from the other root. User code is executable and read-only, while user data and
stacks are writable and non-executable. No mapping changes, page reclamation,
cross-core TLB invalidation or dynamic program loading occurs after release.
All RAM remains retained until emulator exit.

Only the BSP emits diagnostics. The AP publishes fixed observations and command
acknowledgments through explicit atomic Release/Acquire boundaries. User memory
can provide progress observations, but cannot provide CPU identity, a trusted
saved continuation, a page root, an interrupt acknowledgment or authority to
stop its peer. Aligned atomic heartbeat operations avoid racing Rust references
with untrusted writes.

## Original-kernel cases

| Case | Required execution |
| --- | --- |
| `rendezvous` | BSP enters an unbounded CPL3 loop. After observing BSP progress, AP enters a finite CPL3 warmup and yields through its private user-call gate. BSP progress before and after that interval establishes overlapping user execution. An authenticated peer IPI stops BSP user execution. BSP then coordinates resumption of AP's saved context into an unbounded CPL3 loop and interrupts that loop with another authenticated IPI. |
| `peer_read` | AP attempts the fixed peer-only address from CPL3. Its private page-fault boundary captures the expected root, faulting instruction, error code and CR2. BSP user progress must continue after that fault, followed by an authenticated interrupt of BSP user execution. |
| `forged_ipi` | AP executes a software INT for the DPL0 peer-stop vector from CPL3. Its private general-protection boundary captures the expected instruction and error code. It supplies no hardware IPI acknowledgment. BSP continues and is subsequently interrupted by the trusted AP coordinator. |

Acceptance needs actual CS/SS/RFLAGS, CR3, RIP/RSP, raw privilege-stack frames,
general registers and FP observations from both CPUs. Interrupt-driven stops
require the actual local APIC in-service bit and its clearing after EOI, the
expected CPU/root and command generation, and an interrupted CPL3 instruction
boundary. Delivery completion alone is insufficient. A protected stop of user
execution and a terminal CPU park have separate meanings; neither permits
memory reuse in this profile.

Nine raw page-table walks per CPU bind the user mappings, the missing or
read-only peer mapping, supervisor identity aliases, and UC/NX HPET/LAPIC
leaves. Intermediate links must stay in that CPU's 16-page table pool; the
additional retained bookkeeping page grants no page-table-link authority.
Replay checks every saved general register and the complete initialized
512-byte legacy FP image, including its admitted hardware MXCSR mask.

## Evidence and release gate

The original user payload, descriptor and loop/fault/yield landmarks must be
bound from the compiled COFF object into the linked EFI image. No relocation
inside a copied user payload is admitted. Independent builds must produce
identical EFI, object and boot media for every case. Fresh source-bound captures
must pass independent replay, including negative mutations of root ownership,
stack/frame geometry, trap origin, exact instruction boundaries, hardware source,
context continuity and post-fault peer progress.

Release also requires the full Python suite, actual ACPI parser host checks and
fresh regressions of K01, the native protection slice/matrix, cooperative region
service, single-CPU timer/budgets, kernel benchmark and prior SMP bootstrap.
Clean implementation `ef205654aa6b4e75afb77cc8c2affc1a927f7656` passed all
three fresh cases, nine byte-identical EFI/object/disk twins, 26 parser checks,
755 Python tests and all 57 earlier-profile regression commands. Independent
replay checked the complete 149-file artifact. The original captures contain
54 page walks, seven complete CPL3 trap/context images and continued peer progress
after both protection faults. The [62-file packet](../evidence/k03-smp-user/README.md)
retains exact source identities, commands, receipts and raw observations. Failed
or dirty diagnostics supply no acceptance evidence. Offline consistency replay
does not independently authenticate the origin of a capture.

With the pinned local toolchain installed, use fresh output directories:

```sh
python3 tools/check_k03_smp_user_host.py --out build/k03-smp-user/host
python3 tools/build_k03_smp_user.py --out build/k03-smp-user/a
python3 tools/build_k03_smp_user.py --out build/k03-smp-user/b
for case in rendezvous peer_read forged_ipi; do
  python3 tools/run_k03_smp_user.py --manifest build/k03-smp-user/a/manifest.json --case "$case" --out "build/k03-smp-user/$case" --allow-qemu
done
python3 tools/verify_k03_smp_user.py --first build/k03-smp-user/a/manifest.json --second build/k03-smp-user/b/manifest.json --host-result build/k03-smp-user/host/result.json --result build/k03-smp-user/rendezvous/result.json --result build/k03-smp-user/peer_read/result.json --result build/k03-smp-user/forged_ipi/result.json --out build/k03-smp-user/verification.json
```

## Remaining K03 and performance work

This profile establishes a per-CPU user execution boundary. Shared scheduler
mutation, aggregate budget reservations/accounting under contention, per-CPU
timers, general wakeup/migration, reusable quiescence, devices/DMA and physical
clock qualification remain open. K03's broad acceptance boxes stay unchecked.

The existing single-CPU profiles remain the simple correctness references under
the [inference performance contract](inference-performance.md). A preregistered
native comparison covering startup, synchronization, interrupts, accounting and
the complete inference path is pending. Emulator progress and trap observations
establish no physical speedup, latency, throughput or inference performance.

## Primary architecture reference

The [Intel SDM, volume 3A](https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf),
sections 3.4.4, 7.12.1.2, 7.14.2–5 and 12.8.5, supplies the segment/SWAPGS,
software-interrupt privilege, IA-32e frame/TSS and LAPIC ISR/EOI contracts.
These architecture sources are separate from source-bound project execution.
