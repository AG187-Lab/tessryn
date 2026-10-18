# ADR 0021: Private CPL3 contexts before shared SMP scheduling

Date: 2026-10-17

Status: accepted; bounded [clean emulator execution](../../evidence/k03-smp-user/README.md)
and earlier-profile regressions passed.

## Context

The original-kernel bootstrap starts a second CPU with private supervisor tables
and stacks. The existing resumable region service and timer integration use
single-owner global continuation, active task, trap and scheduler state. Running
those globals concurrently would violate the execution ownership boundary.

K03 still requires isolated user tasks on multiple CPUs and accurate aggregate
accounting under contention. Private user execution and interrupt ownership are
prerequisites for connecting that scheduler state safely.

## Decision

Add a separate fixed `k03_smp_user` emulator profile on the admitted two-CPU
bootstrap. Prepare two private immutable user address spaces and per-CPU
GDT/IDT/TSS, stacks and saved register/FP contexts before releasing the AP. Keep
the region-service globals outside the new execution path.

Use bounded kernel coordination and source-authenticated peer IPIs to stop
unbounded user loops. Require actual CPL3 trap frames under both private roots,
overlapping user progress, saved-context resumption, and continued peer execution
after an unauthorized read or forged software interrupt faults. Bind the copied
user payload and exact instruction landmarks to the object and linked image.

Keep all mappings immutable and all memory retained through exit. Only BSP
diagnostics access the framebuffer and serial output. Atomic observations carry
cross-CPU publication; user-controlled bytes grant no stop or accounting
authority.

## Consequences

This supplies a bounded protection and context boundary without exposing the
existing single-CPU service state to concurrent mutation. It adds no shared
scheduler, aggregate budget enforcement or per-CPU timer. A peer-stop IPI is an
enforcement mechanism for this fixed experiment, not a general scheduling policy.

Retention postpones reclamation and TLB shootdown. Dynamic admission, migration,
idle/wakeup, device quiescence and physical qualification require separate work.
K03 remains open. The single-CPU implementations remain correctness references;
a preregistered native complete-path performance comparison remains pending.

## Validation and reconsideration

Require independent matching builds, actual parser host tests, fresh original
captures for all three cases, strict binary-bound raw replay, negative verifier
tests, full Python checks and earlier-profile regressions. The retained packet
binds the clean implementation, original observations, 755 Python tests,
26 parser checks, nine twin artifacts and all 57 earlier-profile commands.
Its three fresh boots and independent 149-file artifact replay pass;
diagnostic captures remain outside acceptance.

Reconsider the fixed topology and immutable roots when adding shared scheduler
ownership, per-CPU timer-driven leases, mutable mappings or resource reuse.
