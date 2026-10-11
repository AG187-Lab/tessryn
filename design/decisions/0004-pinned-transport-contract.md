# ADR 0004: Pin Homa and qualify network adapters separately

Status: Accepted versioning and qualification policy. Exact first Homa version and NIC profile: pending G01/G02.

## Decision

Independently implement one exact Homa wire version and test interoperability. Use a common registered-buffer/completion interface for distinct native and cloud adapters.

Do not mix the original 2018 scheduling design with a later START_MSG-based draft implicitly. Separate logical transfer size, message limit and packet MTU.

Bound receiver credits and outstanding traffic; preserve parent/tenant accounting across segmentation. Compare full paths, including encryption, device copies, loss and contention, against an appropriate paced alternative.

## Consequences

Native Homa support on a qualified fabric does not establish cloud/NAT support or switch queue priority elsewhere. Cloud adapters need an explicitly permitted packet path and their own measurements.

Homa does not supply model partitioning, arithmetic collectives or GPU/NIC peer DMA. Those are separately qualified mechanisms. Avoid a serialized grant-round assumption without an actual trace.

## References

[Homa paper](https://people.csail.mit.edu/alizadeh/papers/homa-sigcomm18.pdf), [pinned draft research input](https://github.com/johnousterhout/homa-rfc/blob/df4bc0d7a1d5c30292e47f474a85c3669dce8612/draft-ousterhout-tsvwg-homa-00.md), and NET01–NET03/CLOUD02 in [the backlog](../../planning/backlog.json).

