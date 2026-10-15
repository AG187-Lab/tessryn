# ADR 0016: Prepare a bounded scheduler and shared CPU-budget policy

Date: 2026-10-12.
Status: Accepted for independent policy preparation. Native integration pending.

## Decision

Implement an original allocation-free `no_std` scheduler policy in a separate
`scheduler-core/`. Use fixed domain/task/CPU tables, immutable lifetime limits,
domain-then-task round-robin and opaque generation identities. Reserve every
grant against one shared domain ledger before dispatch so simulated CPUs cannot
multiply the same remaining budget. Charge complete acknowledged execution
intervals with wide counters; task removal never resets domain consumption.

Require trusted caller identities, one synchronized node-local monotonic clock
and exclusive mutation from a future adapter. Internal task/CPU lease types
are not a new native wire ABI or memory/device authority. Keep the CPU and task
owned through expiry/failure until the exact execution context is stopped.

Overdue retained execution halts its domain before any fresh dispatch, including
when lateness is first observed through another policy operation. Stop each peer
separately, account all elapsed time and retain its grant until acknowledgment.
Every rejected operation preserves complete state, including clock and cursors.

## Alternatives and consequences

Giving each CPU the current remaining domain budget independently can admit
multiple copies of the same budget. Clamping late execution to its grant hides
enforcement failures. Releasing a lease on numerical expiry can dispatch another
task into a context that has not actually stopped. This policy rejects those
approaches and keeps actual native enforcement a separate evidence gate.

The immutable lifetime model deliberately supplies no periodic replenishment
or utilization/rate promise. It gives a small testable foundation before adding
native clocks, SMP run queues or measured serving priorities. Fixed table scans
and serialized access are reference policy choices, not performance claims or
a requirement for a globally shared production scheduling hot path.

## Evidence and acceptance

Pinned tooling executes the actual Rust policy on the host and builds repeated
identical `x86_64-unknown-none` artifacts. Adversarial tests cover aggregate CPU
time, reservations/refunds, transitions, deadlines, late stops, generation
retirement and rejection atomicity. Retained receipts identify exact source
and toolchain inputs, with native capabilities explicitly unavailable.

[K03](https://github.com/AG187-Lab/tessryn/issues/6) stays open for actual isolated
SMP execution and timing/accounting traces after
[K02](https://github.com/AG187-Lab/tessryn/issues/5). CPU policy demonstrates no
GPU/bandwidth preemption, DMA quiescence or inference performance result.

See [the preparation contract](../k03-preparation.md),
[native deadline/authority rules](../native-contract-v1.md) and
[the kernel/service boundary](0003-kernel-and-native-services.md).
