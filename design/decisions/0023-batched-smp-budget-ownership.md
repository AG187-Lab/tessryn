# ADR 0023: One scheduler owner for the first SMP budget experiment

Date: 2026-11-06

Status: accepted; bounded [clean emulator validation](../../evidence/k03-smp-budget/README.md)
passed for both timing cases and the earlier CPL3 regression.

## Context

The single-CPU runtime established timer-driven stops and strict actual-time
charging. The two-CPU profile established isolated user contexts and protected
peer interrupt stops. Running both contexts under one lifetime cap requires
proof that grant reservation, local timer delivery and stop retirement agree.

## Decision

Keep the existing serialized scheduler on the BSP. Admit only the two fixed
pinned contexts. Reserve both leases before release, and use a CPU-local xAPIC
one-shot to interrupt each context. The AP publishes trusted stop data after
restoring its supervisor continuation. Use the existing checked HPET counter as
the shared emulator clock, keeping timer expiry and accounting time separate.
Reconcile both receipts in retirement-time order before the next batch; charge
every dispatch-to-retirement interval and release only the matching lease.

Run one normal two-batch case and one deliberately late case. The latter must
halt the domain without discarding the other CPU's outstanding reservation.
Maintain the original two-CPU profile separately, retain all memory, and reject
capture or provenance mismatches. See the [profile](../k03-smp-budget.md) for
the validation boundary.

## Consequences

This bounded batch coordinator avoids shared mutable scheduling state and does
not need to rewrite late timestamps to fit a policy clock. It does wait for both
stops before admitting the next batch. Independent asynchronous dispatch,
general wakeup, migration, active cross-CPU cancellation, physical timing and
performance measurement are separate gates. Reconsider batching after a
protected ordered event queue can retire independent leases without double
charging or allowing an expired lease to become runnable again.
