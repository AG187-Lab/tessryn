# ADR 0019: Integrate strict CPU budgets with single-CPU timer preemption

Date: 2026-10-16.
Status: accepted; bounded single-CPU emulator execution accepted.

## Context

The [resumable region service](0018-resumable-region-service.md) executes two
protected image programs cooperatively. [The K03 core](0016-scheduler-policy-core.md)
selects numerical tasks and accounts trusted intervals, but does not program a
timer or stop CPL3 execution. Its immutable lifetime budgets and strict late-stop
halt semantics already have separate host policy evidence. Neither that evidence
nor unqualified raw TSC benchmark samples establish native timer enforcement.

## Decision

Keep `scheduler-core` and its 42 tests unchanged. Add a small protected adapter
around `Scheduler<2,2,1>`, with one task per permanent domain and one retained
CPU lease. Initial task/domain/root admission and B's delegated-capability wake
remain privileged. No descriptor supplies task identity, time, budget or a stop
acknowledgment. The boot-local Grant never becomes a native wire capability.

Request a hard quantum of 250 milliseconds, capped by actual remaining task and
domain budgets and the absolute deadline. Arm an early soft target at
`now + max(1, min(10ms, grant/2))`. This supplies scheduling headroom inside the
existing strict grant. It adds neither tolerance to the hard stop nor a refill.
Acknowledge a stop only after the exact context is captured and full actual
elapsed time, including the declared attributable kernel work, is observed.
Never clamp accounting to a nominal interrupt period or manufacture timestamps
from interrupt counts or voluntary user requests.

Use the admitted actual 64-bit HPET counter/period and checked boot-epoch
conversion for local policy time. Keep raw clock, timer and frame observations
available to independent replay. Hardware register references and emulated
counter observations do not establish physical clock or latency qualification.

Only the admitted CPL3 context runs with timer interrupts enabled; the protected
kernel paths remain serialized with interrupts masked. The DPL0 timer gate,
actual source/pending-state observations and compiled interrupted instruction
ranges distinguish hardware preemption from a user-forged software interrupt.
Preserve complete admitted task state and prevent stale timer delivery from being
reported as another lease's expiry. Stopped CPU ownership and memory ownership
remain separate; native cleanup retains the original region lifecycle ordering.

## Consequences and acceptance

A stop after its hard bound still returns Failed and sticky domain halt, with
all elapsed consumption charged. An exact on-time cap stop can return Exhausted.
A fixture reports the observed state and overrun honestly. A shrinking residual
budget may be shorter than delivery or logging work; the early soft target is
not a proven latency guarantee. Deadlines keep inclusive expiry and existing
failure/completion precedence. A backward clock or arithmetic/lease invariant
failure prevents further unaccounted user execution. A missed soft arm returns
`None` only after masking/draining and consuming its generation. Its unentered
grant still receives full actual admission/programming cost and a failed stop;
`ARM_MISSED` produces no invented resume, trap or IRQ.

There is no native STI-driven idle loop or periodic replenishment in this step.
B is blocked only for trusted bootstrap; an unexpected all-blocked native state
fails the experiment. Host numerical idle/wakeup and unchanged core tests retain
no-charge/no-refill and generation/reaping checks. The adapter exposes no later
create, reap or reset operation that could discard consumed lifetime budget.

Require four fresh source-bound executions: noncooperative timer preemption of
both programs, A budget termination with B progress, A deadline termination with
B progress, and a bound CPL3 `INT 0x20` producing the declared #GP rather than a
forged timer. The deadline is admission time plus 100 milliseconds, using the
same checked boot-epoch clock. A protected B-ready mailbox, set only after B's
actual read-confirming second request, precedes A's forged interrupt so teardown
cannot race those reads. One preemption-only IF0 probe observes actual pending
IRQ0 and verifies cancellation drains it before another lease enters; it does
not count as a CPL3 timer interrupt. Raw hardware frames, actual user progress/context preservation,
checked clock/accounting replay, retained leases and final cleanup must agree.
Host policy tests and synthetic transcript rejection remain distinct evidence.
The [clean execution packet](../../evidence/k03-timer/README.md) records matching
twins, four accepted captures, independent accounting/context verification and
passing required regressions. Its native budget/deadline stops remain explicitly
late Failed states with full charge and sticky halt. ARM_MISSED is covered by
host models and a synthetic parser fixture, with no native observation claimed.

The [detailed contract](../k03-timer-preemption.md) records planned cases, ownership,
accounting boundaries and evidence limits. [K03 issue #6](https://github.com/AG187-Lab/tessryn/issues/6)
remains open for actual multicore execution, qualified clocks, synchronization,
contended accounting and cross-core traces. CPU timing does not establish GPU
preemption, memory-bandwidth isolation or DMA quiescence. The conservative policy
remains the reference under [the inference performance contract](../inference-performance.md);
a registered qualified comparison and inference-performance proof remain pending.
