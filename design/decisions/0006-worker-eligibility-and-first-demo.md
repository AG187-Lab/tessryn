# ADR 0006: Measure worker eligibility and require a real notebook shard

Status: Accepted product and admission policy. Qualification results: pending.

## Decision

Authenticated cluster membership does not automatically grant synchronous shard eligibility. Placement uses measured usable memory, operators/formats, sustained compute, thermal/power behavior, link distributions and availability.

The positive first product gate has three stable small nodes and one exact wired mains-powered notebook. All four boot Tessryn and execute resident shards of a model that exceeds every worker's realistic admitted local capacity while fitting the complete group with headroom.

## Consequences

The notebook contributes inference capacity rather than only auxiliary work. A correct refusal passes a negative admission test but does not complete the positive gate.

Partition using measured stage/link cost. Benchmark feasible pipeline, tensor and hybrid plans; report capacity enablement, single-request latency and concurrent goodput separately.

Availability and connectivity affect leases and placement. Wi-Fi is not automatically either a fast collective fabric or an excluded worker class. Abrupt departure may require explicit failure when surviving capacity cannot hold the model.

## References

[Distributed inference](../distributed-inference.md), [Kafila](https://arxiv.org/abs/2609.34045), and CL03–CL04/IO05/DEMO01 in [the backlog](../../planning/backlog.json).

