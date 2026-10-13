# ADR 0017: Optimize the native inference path with measured gates

Status: Accepted engineering direction on 2026-10-12. Performance mechanisms are staged proposals, and no Tessryn performance result is established.

## Decision

Use [inference-oriented kernel performance](../inference-performance.md) as the implementation and experiment contract for scheduling, owned memory, asynchronous queues and native device services. Optimize SLO-compliant inference goodput while preserving numerical quality, tenant budgets, isolation, cancellation and recovery.

Keep the kernel's enforcement boundary separate from replaceable native service policy. Reuse prepared graphs and registered buffers in steady execution, prefer measured locality, bound batching/polling and account data movement. Current conservative K02 fences and scrubbing remain the reference until an optimized path passes the complete relevant isolation matrix.

Recent research supplies hypotheses and experiment designs. It supplies no Tessryn speed estimate, imported Linux kernel dependency, qualified CPU feature or device authority. Optional user interrupts, PCID/huge pages, direct DMA and split serving need exact-profile qualification and comparison against a simpler reference.

## Consequences

K02/K03 correctness and native enforcement remain prerequisites. K04 and device/serving work add attributable queue, interrupt, copy and execution observations. Before native performance acceptance, register workload, baseline, hardware, absolute SLOs, resource limits and regression/uncertainty rules; retain raw and unfavorable results. QEMU and host-policy tests can qualify behavior, not production inference latency.

Public progress reports distinguish implemented behavior, qualification scope, preparation work and measurements. Performance-sensitive PRs link their comparison or state their pending native measurement gate. No throughput or end-to-end latency promise follows from this decision.

## Reconsideration

Revise a mechanism when the simpler baseline is faster or more robust, locality loses to balancing, interrupt delivery beats polling, or KV transfer loses to colocation on the actual workload. The measurement and authority requirements remain in force.

## References

[Architecture](../architecture.md), [benchmark gates](../benchmarks.md), [research](../research.md), [independent evaluation policy](0008-evaluation-and-recursive-improvement.md).
