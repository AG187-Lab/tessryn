# ADR 0022: Measure runtime preemption and bounded cross-core fixtures

- Status: accepted direction; original-kernel execution evidence pending
- Date: 2026-10-17

## Context

The first in-kernel benchmark measures serialized scheduling policy calls, memory
metadata, byte accesses and sequential ring fixtures. The kernel now also has
actual CPL3 timer preemption and a two-CPU bootstrap. Policy-call latency does not
measure either mechanism, and the active multicore task implementation needs its
own correctness work without overlapping ownership.

## Decision

Reuse complete verified timer packets to derive comparator-target to first
trusted capture and actual stop intervals. Add a separate opt-in two-CPU fixture
image for declared atomic/cache-line layouts and round-trip handoffs. Preserve
original profiles and their proof obligations. Register bounded repeated captures,
raw endpoints, work counts, geometry and distinct sample populations before
execution. Buffer contention output until the existing acknowledged terminal
AP stop. Do not subtract unsynchronized cross-CPU clocks or call emulator virtual
time physical latency.

Keep simple references, timer-cost observations and all outcomes. Independent
verification must replay the original correctness evidence before deriving
statistics, bind current reviewed source and exclude untrusted host imports.

## Consequences

The experiments become runnable before arbitrary tasks execute across cores, and
expose useful measurement seams without duplicating the scheduler or ownership
implementation. The first cross-core cases are kernel fixtures rather than a
production concurrent queue or SMP task scheduler. Extra synchronization and
measurement costs remain visible in their interval definitions.

Physical-clock/hardware comparisons and model-shaped inference qualification are
explicit pending gates. Future runtime or queue benchmarks require their own
registered endpoints and correctness evidence; these results cannot be relabeled.
See [the experiment contract](../runtime-benchmarks.md).
