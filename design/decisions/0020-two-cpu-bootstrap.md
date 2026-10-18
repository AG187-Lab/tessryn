# ADR 0020: Establish bounded two-CPU kernel ownership before SMP task execution

Date: 2026-10-17.
Status: accepted implementation decision; clean emulator acceptance pending.

## Context

The [single-CPU timer integration](0019-single-cpu-timer-preemption.md) stops and
accounts two resumable CPL3 programs. Its serialized service state, CPU tables,
trap stack and saved kernel continuation cannot safely be entered by a second
CPU. The unchanged scheduler policy has host concurrency/lease models, but those
models do not establish native AP startup or interrupt ownership.

[K03 issue #6](https://github.com/AG187-Lab/tessryn/issues/6) still requires isolated
multicore execution with accurate contended accounting. First establish a small
original-kernel two-CPU foundation with independently observable failure behavior.

## Decision

Add a separate opt-in `k03_smp` QEMU/OVMF profile with exactly two virtual CPUs,
fixed xAPIC/HPET addresses and checked ACPI topology. Keep the earlier single-CPU
profiles and their scheduler/runtime scope intact. Parse bounded ACPI slices with
allocation-free code; validate physical coverage before creating table views and
retain owned handoff values before ExitBootServices. Exactly two enabled legacy
APIC IDs are admitted; x2APIC, overrides and ambiguous/unsupported topology fail.

Reserve a low LoaderData trampoline page and bind its original relocation-free
template and limited patch fields to the object/EFI artifacts. The BSP performs
targeted INIT/SIPI with checked delivery and HPET-bounded readiness. The AP owns
private GDT, IDT, TSS, normal stack and fault stack, explicitly initializes its
architectural environment, and publishes actual state before readiness. Both
CPUs retain one common CR3 whose software mappings are fixed before AP release.
No single-CPU CPL3 runtime state is shared as a per-CPU context.

Require shared atomic work from both CPUs: 4096 increments each, total 8192,
plus AP heartbeat progress during a 20-millisecond BSP interval. Three ordered
IPIs require actual interrupt frames and owned LAPIC ISR/EOI transitions before
Release acknowledgments; the BSP acquires each and observes continued AP work.
A separate stop IPI publishes its final state and acknowledgment, then parks
without later AP RAM writes. Retain all RAM permanently through experiment exit.
This is a terminal bootstrap handshake, not permission to reclaim CPU resources.

Add a second fresh `missing_ap` case that deliberately withholds SIPI after
INIT. Only the bounded expected readiness timeout passes that negative case.
Never substitute an ICR delivery bit, a host thread or a synthetic trace for
actual AP entry and interrupt execution.

## Consequences and acceptance

This step makes native two-CPU kernel progress observable while avoiding an
unsupported concurrent entry into the existing CPL3 service. The common fixed
root postpones cross-core TLB invalidation; retained memory postpones safe reuse.
It supplies no SMP scheduler, shared budget enforcement, per-CPU timer,
general idle/wakeup, device/DMA quiescence or physical performance qualification.
The broader K03 acceptance remains open.

The [detailed contract](../k03-smp-bootstrap.md) requires the 26 copied-table host
checks, clean source/toolchain bindings, matching twin artifacts, both fresh
guest scenarios, independent topology/frame/clock/ownership replay and passing
historical execution regressions. Clean execution acceptance is pending; host
parser tests and dirty diagnostics do not complete that gate.

Keep the simple correctness reference under the
[inference performance contract](../inference-performance.md). A preregistered
native comparison with qualified clocks and complete startup, synchronization,
interrupt and runtime costs remains pending. Emulated work counters and
heartbeats establish no physical latency, throughput or inference improvement.

Reconsider the fixed topology/root and retained-memory design when adding
protected per-CPU CPL3 contexts, scheduler ownership, mutable mappings or
reclamation. Each needs its own failure and cross-core accounting evidence.
