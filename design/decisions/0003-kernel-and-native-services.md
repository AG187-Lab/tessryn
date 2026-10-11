# ADR 0003: Separate kernel mechanisms from model policy

Status: Accepted design direction. Implementation evidence: pending.

## Decision

The privileged core owns scheduling, address spaces, capabilities, execution budgets, interrupts, clocks, physical memory and DMA authority.

Native services own model parsing, tokenization, graph execution, batching, cluster membership, placement, storage and network protocol policy. They use bounded capabilities and asynchronous registered-buffer interfaces.

## Consequences

Model algorithms can evolve without widening privileged parsing. Persistent queues and prepared graphs can reduce repeated setup while preserving explicit lifetimes and completion fences.

CPU budgets do not imply universal GPU preemption or bandwidth isolation. Backend contracts declare enforceable bounds and faults. Per-core or per-topology ownership can be optimized after measurement; the design does not require a single globally shared scheduling hot path.

Cluster desired-state reconciliation remains outside ordinary per-token execution.

## Acceptance link

[Native ABI](../native-abi.md), K02–K05, CL02–CL05 and INF02 in [the backlog](../../planning/backlog.json).

