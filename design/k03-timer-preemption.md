# Single-CPU timer preemption and strict CPU budgets

Status: single-CPU emulator execution accepted; physical clock and SMP qualification remain open.
This step integrates the existing [scheduler policy](k03-preparation.md) with the
[two resumable CPL3 programs](k02-region-service.md). It advances
[K03 issue #6](https://github.com/AG187-Lab/tessryn/issues/6) without closing its
multicore, clock qualification or contention gates.
[ADR 0019](decisions/0019-single-cpu-timer-preemption.md) records the decision.

## Protected policy adapter

`kernel/preempt_policy.rs` wraps the unchanged allocation-free
`Scheduler<2,2,1>` from `scheduler-core`. Trusted admission creates exactly one
known task in domain 1 and one in domain 2. Its protected mapping binds those
TaskIds to the existing task slots, roots and saved contexts. The adapter retains
one exact CpuLease for CPU 0 until that context has actually stopped. Task IDs,
indices, lease generations, budgets and timestamps are not authenticated by user
descriptors. A returned Grant belongs to this boot-local adapter and is never
transported as a native wire capability.

The adapter exposes trusted block/wake, failure, clock advance and read-only
accounting/task/lease queries. B starts blocked until A delegates and the trusted
bootstrap installs B's initial capability. There is no subsequent task creation,
reaping, budget reset or refill API. The scheduler's immutable lifetime caps and
domain-then-task selection remain the correctness reference. A rejected adapter
operation preserves policy tables, clock, cursors and the retained active grant.

Dispatch requests a hard quantum of 250,000,000 nanoseconds. The scheduler caps
that grant by both available task/domain budgets and the remaining deadline.
For an admitted positive grant `g` at trusted time `now`, the hardware timer has
an early target:

```text
hard_stop = now + g
soft_target = now + max(1, min(10,000,000, floor(g / 2)))
```

The checked hard-stop addition remains the policy's strict bound. The soft
target provides headroom for entry, interrupt delivery, capture, service and
attributable logging; it does not extend the grant, add grace or imply a measured
latency bound. A one-nanosecond residual grant can have equal soft/hard targets.
Actual remaining budget always caps the next grant.

The adapter publishes a dispatch only after validating the protected task mapping
and checked soft timestamp. A stop must match every retained grant field,
including task, index, CPU lease generation and both timestamps. Numerical expiry,
requesting failure or logging a terminal status does not release that ownership.

## Clock and accounting boundary

The admitted emulator profile uses an actual 64-bit HPET main counter and its
reported period. The native clock owner validates the profile, performs bounded
MMIO accesses and converts checked absolute counter differences from one boot
epoch into policy nanoseconds. Raw counter values, period, epoch and converted
timestamps must remain observable so the verifier can recompute them. A delivered
interrupt count is not elapsed time, and the earlier unqualified benchmark TSC
is not substituted for this clock.

The [Intel HPET 1.0a specification](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf),
particularly sections 2.3.4, 2.3.7–2.3.9 and 2.4.2, supplies the register,
counter/comparator and legacy-routing contract. It is a primary architecture
reference, not evidence that this driver executed or that a physical clock meets
its frequency/accuracy requirements. Pinned QEMU observations remain emulated
clock observations, not physical timing or inference measurements.

Every actual stop uses the trusted current clock sample and charges the full
interval from that grant's start, including attributable entry, interrupt,
service and logging work under the runtime's declared accounting boundary.
The runtime must locate and record that boundary consistently: sample after the
bounded attributable work before acknowledging the policy stop, record unassigned
system gaps separately, and never charge an interval twice. INT80 requests,
including ordinary errors and cooperative yields, cannot manufacture elapsed
values, reset consumed budget or offload unlimited uncharged service work.

The measured tenant interval starts at the pre-arm dispatch sample and ends at
the actual sample after capture, service work and deferred dispatch/trap logging.
The subsequent policy-stop bookkeeping, ACCOUNT/LEDGER/terminal records, reaping,
final cleanup and between-entry work belong to separately recorded kernel gaps.
Tenant intervals and those gaps partition one HPET epoch through the shutdown
sample exactly once. Reporting after that final sample is outside the window.
This is attributable runtime accounting, not a measurement of CPL3 instructions
alone or an inference-performance claim.

Charge is never clamped to the soft target, hard target, nominal quantum or
remaining budget. An actual stop after `hard_stop` retains the unchanged policy
result: full elapsed consumption, Failed state and sticky domain halt. Exact
on-time cap consumption can produce Exhausted instead. A native budget case must
report which occurred; it must not relabel a late failed stop as exact exhaustion.
A healthy peer domain remains eligible under its own budget and deadline.

Programming can miss a very short residual soft target. The driver then consumes
the attempted arm generation, masks and drains the source and returns `None`.
The runtime records `ARM_MISSED` and fails that exact reserved grant using the
actual later stop sample. It records no user resume, raw trap or IRQ for that
attempt. Admission/programming/logging cost still receives its full actual
charge; this branch cannot invent CPL3 execution or conceal a late hard stop.

A nonzero deadline expires inclusively at actual `now >= deadline`; an explicit
completion at the deadline expires. Failure/domain halt takes precedence over
deadline, completion and exhaustion as specified by the unchanged policy. A
backward counter, counter/conversion overflow, deadline overflow or impossible
lease/state relationship fails the experiment without resuming an unaccounted
context. Rejected policy calls retain active ownership and reservations.

## Interrupt and context boundary

Only CPL3 execution enables the admitted timer interrupt. Kernel dispatch,
service mutation, task capture and resume preparation remain serialized with
interrupts masked; no mutable policy or memory borrow crosses user entry.
The saved user frame restores IF while retaining IOPL 0 and excluding unsupported
tracing/task modes. No new STI-driven kernel idle path is admitted in this step.
All-blocked state is an unexpected native fixture failure: B is blocked only for
bootstrap, after which the declared programs must make bounded progress.

The timer gate is DPL0. A CPL3 software `INT 0x20` cannot stand in for a hardware
timer interrupt. Admission and capture bind task/root/generation, CPL3 selectors,
user stack, private trap frame and an exact compiled instruction range. Before
Rust or diagnostics use FP/SIMD, assembly captures the interrupted program's
complete GPR/frame and initialized legacy FP state, then installs the kernel FP
environment. Resume restores the same interrupted RIP and task-owned state;
only a declared service reply may change its defined result registers.

Timer programming, interrupt acknowledgment and pending-state handling must
prevent an earlier lease's interrupt from being reported as expiry of a new
lease. An early/pending interrupt is not evidence that a soft target elapsed.
The raw clock and actual IRQ-source observations must support the accepted event.
The first A request in `preemption` also performs one bounded IF0 negative
probe: poll the actual PIC IRR until IRQ0 is pending, then cancel it. The raw
record must show pending-before 1, pending-after 0 and no in-service IRQ. It does
not count as a delivered CPL3 interrupt. Ordinary cancellation can observe an
IRQ0 pulse after its initial capture sample; the later actual stop must then
have reached that arm's comparator target. Unknown IRQ sources or in-service
ownership fail instead of being normalized by reset.

The trusted B-ready mailbox is set only after B's source-bound second successful
request, following its actual data reads and comparisons. It prevents forged-IRQ
teardown from revoking B's page between its MAP reply and those reads. The parser
requires that actual read continuation and response before accepting A's #GP;
the mailbox supplies neither CPU budget nor a public IPC API.

A task stopped by budget, deadline or the declared protection fault cannot run
again. CPU stop precedes service/memory cleanup; retained region capabilities and
mapping leases still follow their original revoke, PTE removal, real invalidation,
quiescence and release rules. CPU accounting does not acknowledge memory or DMA
quiescence.

Legacy FP, FS/GS/TLS, debug, protection-key, CET/SGX and alternate-entry restrictions
remain those of the region-service profile. This bounded image experiment does
not admit arbitrary programs or preserve all architectural state.

## Native cases and acceptance

| Case | Required original-kernel behavior |
| --- | --- |
| `preemption` | Both tasks have two-second lifetime caps. Each executes a compiled busy loop with no INT80 inside it and observes at least three actual timer captures before continuing service work and exiting. Raw interrupted/resumed RIPs, progress and task-specific GPR/legacy-FP state agree across A-to-B-to-A execution. |
| `budget` | A has an 80-millisecond lifetime cap and spins without voluntarily yielding; B has two seconds, makes progress and waits for A's actual terminal policy state before exiting. Actual elapsed consumption, strict overrun/halt if present, retained ownership and absence of any later A resume agree. |
| `deadline` | A has an absolute deadline at the trusted admission sample plus 100 milliseconds; B makes progress and waits for A's actual terminal state. Deadline accounting and actual stop timestamps agree; late strict failures remain visibly distinct from an on-time deadline stop. |
| `forged_irq` | After B's second successful request witnesses its actual shared-page reads, A observes the protected ready mailbox and executes its bound CPL3 `INT 0x20`; the actual raw exception is #GP vector 13 with error `0x102` at that instruction. It does not increment authentic timer acceptance. A stops and B continues under its own budget. |

All cases require source-bound complete code/descriptor bindings, an admitted
actual timer/clock profile, raw exception/IRQ frames, complete policy timelines,
actual user continuation and final zero CPU reservations and memory ownership.
The independent parser must reconstruct policy accounting and match the entire
ordered execution; kernel status strings and synthetic IRQ-shaped fixtures alone
cannot establish preemption. Bound guest steps, interrupts, logs and timeout so a
lost timer or spinning task produces a retained failure rather than a hang.

Host tests execute the same unchanged scheduler policy through the adapter. They
cover hard/soft grant boundaries, full actual charging, strict lateness, deadline
precedence, block/wake and all-blocked numerical idle, rejection atomicity,
backward time, overflow and stale/foreign grant fields. Numerical idle tests
charge no tenant and show that idle/wake does not replenish consumption; they do
not claim an implemented interrupt-driven native idle loop. The original 42 core
tests retain the task-reaping/generation and no-refill invariants unchanged.

Release still requires clean source and pinned tools, exact compiler/runtime
closure, matching independent builds, all four fresh native captures, independent
raw/accounting verification and K01/K02/service/benchmark regressions. Public
successful evidence retains original portable logs and notices; failed raw host
diagnostics remain private. The [clean evidence packet](../evidence/k03-timer/README.md) records four accepted
boots, 69 actual traps, matching 14-artifact twins, 90 focused host checks,
697 Python tests and passing required regressions. Budget and deadline native
stops in that packet are strict late Failed states with full charge and sticky
domain halt; exact-cap Exhausted and inclusive DeadlineExpired have separate host
coverage. ARM_MISSED has host-model and synthetic-parser coverage, with no native
observation claimed by that packet. The later [bootstrap regression packet](../evidence/k03-smp-bootstrap/README.md#earlier-profile-regressions) records one actual ARM_MISSED no-entry stop: its full 1.472ms charge exceeds the remaining 63µs grant, A stays failed/halted and B completes. That emulator observation retains its own source identity and timing scope.

The [inference performance contract](inference-performance.md) keeps this work in
correctness preparation. Qualified physical clocks, native SMP/contended
accounting, all-core synchronization, general idle/wakeup, device/DMA isolation,
GPU preemption and registered inference/performance comparisons remain separate
gates. No production latency, throughput or inference gain is claimed.
