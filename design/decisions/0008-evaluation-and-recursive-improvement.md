# ADR 0008: Require independent evidence for software improvement

Status: Accepted evaluation and authority policy. No optimization loop has been implemented.

## Decision

Evaluate original implementations and generated candidates using reproducible builds, numerical tolerances, teacher-forced probability/logit checks, held-out task quality and registered workload/performance conditions.

Candidates cannot alter trusted evaluation, enrollment, promotion/signing or recovery authority. VM experiments may share a trusted host while withholding physical disk and device-DMA authority. Bare-metal driver/kernel trials use a dedicated recoverable target and independent recovery control.

## Consequences

Generated compute kernels, runtime policies and OS code can be promoted only after their declared correctness, isolation, resource and performance gates pass. Preserve rejected results and build provenance.

Exact greedy token replay is required only for matching deterministic conditions. Quality and numerical variation require declared tolerances rather than arbitrary exactness.

Record latency sample counts, distributions, offered load, cache state and sustained thermal duration. There is no established one-prefill-chunk bound for end-to-end p99 latency.

Improved execution efficiency is software optimization. Claims of improved agent intelligence need separate held-out task evidence. Candidate experiment restrictions are not a prohibition on authorized production installation or native storage drivers.

## G03 tooling foundation

[Evidence schemas](../evaluation-evidence.md) distinguish assumptions, fixture
implementation results and future registered measurements. The
[host emulator harness](../build-and-evaluation.md) hashes candidate inputs,
withholds guest disk/network/host-share/device authority, and preserves bounded
failure logs. Trusted evaluator and registration hashes bind each result.
Its fixtures establish no native boot, GPU, inference or performance capability.
Protected enrollment, promotion/signing, recovery and hostile-candidate sandbox
qualification remain RSI01; the optimization loop remains unimplemented.

## References

[Roadmap](../roadmap.md), [numerical accuracy](https://docs.pytorch.org/docs/stable/notes/numerical_accuracy.html), and G03/DEMO01/RSI01–RSI03 in [the backlog](../../planning/backlog.json).

