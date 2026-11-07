# Local timers and a shared budget on two CPUs

Status: bounded clean original-kernel emulator execution accepted;
[retained evidence](../evidence/k03-smp-budget/README.md). This bounded K03
profile joins the [protected two-CPU contexts](k03-smp-user.md) to the unchanged
[scheduler policy](k03-preparation.md). The [single-CPU HPET timer](k03-timer-preemption.md)
and [two-CPU peer stops](k03-smp-user.md) remain separate correctness references.

## Ownership and time

Two fixed, image-bound CPL3 contexts use their existing immutable private roots,
privileged stacks, CPU tables, SWAPGS boundary and full GPR/legacy FP images. No
task migrates. The BSP alone mutates `Scheduler<1, 2, 2>`. Both protected task
identities share one lifetime domain cap. The BSP reserves both leases against
that cap before either CPU enters user mode, using a common HPET dispatch
sample. AP receives a fixed command with release/acquire publication and can
publish a local stop receipt; it cannot mutate scheduler state.

The existing shared HPET main counter supplies node-local emulator time. Each
CPU independently calibrates and arms its own xAPIC one-shot countdown. The
timer uses a dedicated DPL0 vector. A valid stop checks the actual interrupted
CPL3 frame and private root, the active local generation, the local timer
configuration, a zero current count, the hardware in-service bit, EOI and a
drained local source before rearm. Invalid stop frames, timer source state or
entry timing fail the experiment. Both legacy PICs and all 24 admitted I/O APIC routes are masked;
the profile never sends vector 67 by IPI. In the normal case the conservative
latest programmed expiry must fit inside its reservation before entry. The
deliberately late fixture still requires actual entry before the reservation's
hard deadline. The timer mode and register rules come from the
[Intel SDM, volume 3A](https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf),
sections 12.5.4 and 12.8.5. Timing observations come from the pinned emulator.

The AP arms first with a longer timer. The BSP observes fresh AP user-only
heartbeat progress before its own entry. The BSP's genuine CPL3 trap must be
captured before the AP countdown's conservative earliest expiry in the admitted
virtual clock model. Both CPUs also show independent user progress. This
brackets an overlap of the admitted user contexts rather than relying on
overlapping reservations or delayed acknowledgment alone.

Only the BSP emits diagnostics. Both CPUs return from the local trap to their
protected supervisor continuation before publishing retirement. The BSP acquires
both receipts and reconciles them by actual HPET retirement time, with a fixed
CPU order for ties. It does not advance policy time past any unconsumed receipt
or substitute a later reconciliation time. This avoids charging one CPU for the
other CPU's stop delay. Each charge includes its entire dispatch-to-retirement
interval, including attributable startup and trap work; it is not a claim of
pure CPL3 cycles or physical timing precision.

## Evidence cases

| Case | Required observation |
| --- | --- |
| `preempt` | Both CPUs start with live reservations under one cap. The second grant is clipped by the first. Both unbounded user loops are stopped by their local hardware timers; the BSP trap precedes the AP's earliest possible timer expiry after fresh AP user progress. In a second batch both saved contexts resume, advance their private heartbeats, and stop through fresh generations. Timely stops charge full observed intervals and release only their own reservations. The fixture completes after the second batch. |
| `late` | A test-only timer setup deliberately schedules both authentic stops beyond the grants. The first reconciliation charges all elapsed time, halts the domain, and leaves the peer lease and reservation owned until its separate receipt is reconciled. The BSP observes rejected further admission, charges the peer without clamping, and ends with no outstanding leases or reservations. |
| `fault` | With both grants live, the BSP's CPL3 fixture increments its private heartbeat and takes a bound non-present read fault. The kernel masks and stops its still-running timer, verifies the local interrupt request and in-service registers are clear, and records the fault without acknowledging a timer interrupt. The AP advances again after the faulting CPU has retired and then stops through its own timer IRQ. The BSP charges the failed task's full interval, retires only its lease, and leaves the peer's original grant and domain admission intact until the peer's own receipt. |

In the late case the peer may already be stopped in hardware while its receipt
awaits reconciliation. Retaining the peer lease is a policy ownership proof,
not a claim of immediate cross-CPU cancellation. Terminal park uses protected
acknowledgment and stable user progress observations. All memory stays retained.
The fault case keeps the same retained-memory rule. The faulting CPU's
countdown must agree with the HPET bracket spanning its trap capture and
retirement. Two heartbeat samples taken after that retirement must show the
peer progressing before its own timer stop. The BSP applies both receipts
after the hardware stops, in retirement order. In that ledger, the failed
task cannot be dispatched again, and the peer's reservation stays intact
until its own receipt is applied. The historical packet covers the original
two cases; the fault extension is a separate draft candidate. Broader
application recovery and arbitrary-program admission remain open.

## Validation and limits

Require clean committed source; pinned toolchain and firmware; independently
matching builds; actual ACPI parser checks; fresh runs of all three cases; and a
separate replay of the binary-bound CPL3 state, timer receipts, shared budget
transitions and terminal state. Retain artifacts with exact source and inventory
bindings. Earlier profiles keep their original evidence formats and gates.

Clean implementation `eab49c93d60132e301671e5af50cf9e098a69584` passed 774
Python tests, 26 parser checks, seven twin artifacts and two fresh boots.
An independent audit of the 148-file artifact replayed six CPL3 timer traps
and both complete ledgers, with no privacy findings. The three earlier
SMP user scenarios and nine twin artifacts also verified at that source.
Offline replay checks consistency; it does not independently attest execution.

With the pinned tools installed, use a clean implementation checkout and
fresh output directories:

```sh
python3 tools/check_k03_smp_user_host.py --out build/k03-smp-budget/host
for twin in a b; do
  python3 tools/k03_smp_budget.py build --out "build/k03-smp-budget/$twin"
done
for case in preempt late fault; do
  python3 tools/k03_smp_budget.py run --manifest build/k03-smp-budget/a/manifest.json --case "$case" --out "build/k03-smp-budget/$case" --allow-qemu
done
python3 tools/k03_smp_budget.py verify --first build/k03-smp-budget/a/manifest.json --second build/k03-smp-budget/b/manifest.json --host-result build/k03-smp-budget/host/result.json --result build/k03-smp-budget/preempt/result.json --result build/k03-smp-budget/late/result.json --result build/k03-smp-budget/fault/result.json --out build/k03-smp-budget/verification.json
```

This experiment has no general runnable queues, blocking or wakeup across
cores, deadline admission, arbitrary program loading, migration, memory reuse,
device/DMA quiescence or physical clock qualification. Both broad K03
acceptance items remain open. The [inference performance contract](inference-performance.md)
still requires a preregistered native complete-path comparison, including
startup, timer/interrupt, synchronization, accounting and inference costs.
Emulator timings and correctness observations establish no physical latency,
throughput or inference gain.
