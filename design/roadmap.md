# Tessryn implementation roadmap

Tessryn is an original kernel and operating system for agent execution and distributed inference. Original-kernel CPU bring-up now has emulator and bounded native AWS execution evidence. The remaining gates include complete native isolation and services, physical hardware, device drivers, accelerator execution, inference and measured performance.

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

## Current progress

Snapshot: October 12, 2026. PR merge state and check results can change; follow the linked live work before starting dependent implementation.

| Work | Observed progress | Remaining gate |
| --- | --- | --- |
| G03 | [Build and independent evaluation tooling](https://github.com/AG187-Lab/tessryn/pull/51) merged; [issue 2](https://github.com/AG187-Lab/tessryn/issues/2) closed | Fixture results establish tooling behavior, with zero performance samples |
| G01 | [Inventory and qualification tooling](https://github.com/AG187-Lab/tessryn/pull/52) merged | Exact physical stable-node/notebook records, access/artifact prerequisites and initial engineering-target decision; [issue 1](https://github.com/AG187-Lab/tessryn/issues/1) remains open |
| G02 | [Portable native interfaces and host conformance](https://github.com/AG187-Lab/tessryn/pull/54) merged | Wider contracts, compatibility/runtime decisions and G01 inputs; [issue 3](https://github.com/AG187-Lab/tessryn/issues/3) remains open |
| K01 | [Original UEFI kernel](https://github.com/AG187-Lab/tessryn/pull/53) has reproducible QEMU boot, exception, panic and reset evidence; [observed AWS CPU qualification](https://github.com/AG187-Lab/tessryn/blob/c5d82c49cefd6dbc32f122562c6bb0c1608b4816/design/aws-boot-and-recovery.md#observed-cpu-qualification) records two owner-accepted native `t3a.small` CPU boots bracketing independent fresh Ubuntu recovery, with cleanup complete | PR 53 awaits merge; this narrow CPU profile establishes no physical hardware, native drivers, GPU, inference or performance support |
| K02 | [Owned-memory core](https://github.com/AG187-Lab/tessryn/pull/55), [reserved-memory activation](https://github.com/AG187-Lab/tessryn/pull/56) and [boot inventory/protocol preparation](https://github.com/AG187-Lab/tessryn/pull/57) merged; [draft PR 58](https://github.com/AG187-Lab/tessryn/pull/58) has [four original-kernel CPL3 probe results](https://github.com/AG187-Lab/tessryn/blob/7b1b07259be350db76657d0d1183078e6f8c610f/evidence/k02-native-slice/README.md) on one emulated CPU | Full ten-case native protocol, authenticated dispatch, revocation/reuse execution, SMP and DMA; [issue 5](https://github.com/AG187-Lab/tessryn/issues/5) remains open |
| K03 | [Owner-scoped scheduling and budget host-policy preparation](https://github.com/AG187-Lab/tessryn/issues/6#issuecomment-6139885186) is active; no public implementation PR or acceptance result is attached yet | Native SMP scheduling, clocks and budget enforcement remain unqualified; [issue 6](https://github.com/AG187-Lab/tessryn/issues/6) remains open and dependent on K02 |

The next kernel milestone is landing K01 and completing K02's native acceptance matrix so scheduling and services can integrate against proven ownership boundaries. Physical qualification can progress independently. The [inference performance plan](inference-performance.md) proposes downstream experiments; published external results are research inputs, with no measured Tessryn performance claim.

## First work and critical path

G01 establishes exact physical inventories, access/artifact prerequisites and initial engineering profiles. Its tooling foundation has landed, while the qualification issue remains open. G03 is complete for its fixture profile. G02's provisional host conformance foundation has landed; wider target/interface decisions still depend on G01. Bounded K01 CPU bring-up and independent K02/K03 policy preparation do not close those platform or contract gates.

The [G01 qualification packet](platform-qualification.md) records conditional laboratory candidates, a bounded rental plan and reference inventory tooling. The later K01 AWS result qualifies only its observed CPU boot/recovery sequence; physical stable nodes and the notebook remain unqualified, and G02's platform dependency stays open. G01 can select evidence-backed engineering targets while native device execution and sustained-performance qualification remain later gates; it must not depend on those downstream implementations to complete.

The first product path is original kernel, native physical devices, native NVIDIA execution, native model serving, measured transport, authenticated cluster control and four-participant sharding. Work on kernel interfaces, native networking and accelerator bring-up can proceed in parallel once their dependencies are satisfied.

G01 must identify one exact wired, mains-powered notebook and record its PCIe,
ACPI, firmware, power and access prerequisites. Later advertised support and
the positive product demonstration require Tessryn to initialize that
platform and accelerator. An application running on an existing deployment
OS is reference evidence. Native device power sequencing and sustained
thermal behavior need their own implementation evidence, even when desktop
and notebook GPUs share an architecture.

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
- [Inference performance plan](inference-performance.md)
- [Original kernel decision](decisions/0001-original-kernel.md)
- [Language and toolchain proposal](decisions/0002-language-and-toolchain.md)
- [Worker eligibility decision](decisions/0006-worker-eligibility-and-first-demo.md)
- [Evidence and improvement decision](decisions/0008-evaluation-and-recursive-improvement.md)

