# Tessryn implementation roadmap

Tessryn is an original kernel and operating system for agent execution and distributed inference. This roadmap describes implementation work, not an implemented system. No native boot, accelerator execution or performance result has been produced by the design review.

The implementation backlog is [planning/backlog.json](../planning/backlog.json). Logical issue keys become GitHub issue links when published. Milestones have no due dates until hardware qualification and the first accelerator bring-up establish a credible critical path.

## Milestone gates

| Key | Milestone | Exit evidence |
| --- | --- | --- |
| M0 | Platform qualification and contracts | Exact candidate hardware profiles, versioned interfaces, protocol choices and reproducible evaluation rules |
| M1 | Original kernel and native services | Own x86-64 kernel boot, isolated domains, scheduling, registered buffers and native service execution |
| M2 | Native devices and installation | Native PCI/DMA, storage, networking and installation on the selected stable nodes and notebook |
| M3 | Native CUDA execution and inference | Exact-target cubins execute on the original OS; the required CUDA Driver API subset and one inference architecture pass correctness gates |
| M4 | Native transport and cluster control | Qualified Homa, authenticated enrollment, three-node control quorum, profiling, admission and native client/task APIs |
| M5 | Four-device distributed inference product | Three stable nodes and one native-OS notebook execute resident shards; independent prefill/decode handoff, failure behavior, isolation and measured service results |
| M6 | Cloud and geographic operation | Named cloud profiles separately qualify boot, transport and accelerator execution; regional placement has measured end-to-end evidence |
| M7 | Bounded recursive software improvement | Candidate generation and promotion operate under independent evaluation and recovery authority |
| M8 | AArch64 and native Apple M5 | Original core and platform bring-up, independent Apple GPU execution and qualified inference/transport |
| M9 | Additional backend and compatibility programs | Individually qualified direct peer DMA, broader CUDA compatibility and an optional AMD GPU backend |

## First work and critical path

G01 qualifies hardware before a particular server, GPU or notebook SKU is advertised as supported. G03 establishes build and evaluation tooling independently. These are the two ready work items. G02 records the native interfaces and exact compatibility scope once those inputs are available.

The [G01 qualification packet](platform-qualification.md) records conditional cloud laboratory candidates, a bounded rental plan and reference inventory tooling. It does not complete hardware qualification or remove G02's platform dependency. No physical notebook or native-supported profile is available yet.

The first product path is original kernel, native physical devices, native NVIDIA execution, native model serving, measured transport, authenticated cluster control and four-participant sharding. Work on kernel interfaces, native networking and accelerator bring-up can proceed in parallel once their dependencies are satisfied.

The first notebook profile is one exact supported wired, mains-powered machine. Its own OS must initialize the platform and accelerator. An application running on an existing deployment OS can be a development reference but does not satisfy this gate. Notebook PCIe, ACPI and device power sequencing require their own evidence, even when desktop and notebook GPUs share an architecture.

## Positive product demonstration

All four participants boot Tessryn and execute resident shards of the jointly served model. Three stable nodes maintain control quorum; the notebook contributes to inference rather than serving only auxiliary work.

The chosen model's complete admitted memory demand exceeds every worker's local capacity under realistic reserves, while fitting the group with headroom. Account for weights, quantization metadata, per-layer KV or recurrent state, workspace, transfer buffers, firmware reservations and the OS. Publish physical capacity and all admission limits; arbitrary caps must not be used to imply a hardware capacity breakthrough.

Pipeline stages keep their own per-layer state during normal execution. Measure pipeline, tensor and feasible hybrid placements. Capacity enablement, single-request latency and concurrent goodput are separate outcomes.

Demonstrate prefill/decode separation with independently feasible placements. When the large model consumes the four-device pool, use a smaller checkpoint of the same supported architecture or add qualified capacity. Every destination shard must be reserved; the same memory cannot be counted twice.

## Evidence required for release

- Native boot, GPU execution and complete inference on every advertised profile.
- Four active shards, actual Homa traffic traces and complete per-node memory accounting.
- Operator tolerances, teacher-forced logit/probability checks and held-out task quality. Exact token replay is required only for matching deterministic conditions.
- Numeric service targets registered before measurement, with workload mixes, offered load, context/output limits, cache state, sample counts and sustained thermal conditions.
- Separate transport and placement comparisons on equal hardware, model precision and encryption conditions.
- Planned drain, abrupt worker loss, link degradation, cancellation and coordinator failover.
- Fencing of stale placement output and explicit client outcomes. Resume is conditional on available state and surviving or replacement capacity.
- Verified signed updates, interrupted-update behavior and recovery to a known-good image.

A correctly refused notebook placement passes a negative admission test. It does not complete the positive notebook-shard milestone. A cloud image that boots does not establish cloud accelerator support. Apple M5 and full stock CUDA ecosystem compatibility remain separate qualification programs.

## Scope and measurement discipline

The first version supports one model architecture and precision contract, one qualified NVIDIA family with exact device profiles, and selected native NIC/storage profiles. Breadth is constrained; the distributed execution path is present end to end.

CPU inference is internal bring-up tooling. The product demonstration requires native accelerator execution. Direct GPU/NIC DMA is an optional measured optimization; the first path can reuse pinned host buffers with explicit copies and ordering.

There is no universal one-prefill-chunk bound for end-to-end p99 latency. Admission uses measured complete paths. Additional hardware, transport and partition combinations enter the support matrix only after their gates pass.

## Related specifications

- [Native ABI](native-abi.md)
- [Distributed inference](distributed-inference.md)
- [Original kernel decision](decisions/0001-original-kernel.md)
- [Language and toolchain proposal](decisions/0002-language-and-toolchain.md)
- [Worker eligibility decision](decisions/0006-worker-eligibility-and-first-demo.md)
- [Evidence and improvement decision](decisions/0008-evaluation-and-recursive-improvement.md)

