# Tessryn implementation roadmap

Tessryn is an original kernel and operating system for agent execution and distributed inference. The [K01 implementation and evidence](first-kernel.md), recorded in [PR #53](https://github.com/AG187-Lab/tessryn/pull/53), cover original-kernel CPU bring-up with emulator and bounded native AWS execution evidence. The remaining gates include complete native isolation and services, physical hardware, device drivers, accelerator execution, inference and measured performance.

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

Snapshot: October 17, 2026. PR merge state and check results can change; follow the linked live work before starting dependent implementation.

| Work | Observed progress | Remaining gate |
| --- | --- | --- |
| G03 | [Build and independent evaluation tooling](https://github.com/AG187-Lab/tessryn/pull/51) merged; [issue 2](https://github.com/AG187-Lab/tessryn/issues/2) closed | Fixture results establish tooling behavior, with zero performance samples |
| G01 | [Inventory tooling](https://github.com/AG187-Lab/tessryn/pull/52) and [hardware intake/recovery requirements](https://github.com/AG187-Lab/tessryn/pull/64) merged | No physical server is available yet; exact stable-node/notebook inventories, access/artifact prerequisites and initial target decision remain open in [issue 1](https://github.com/AG187-Lab/tessryn/issues/1) |
| G02 | [Portable native interfaces and host conformance](https://github.com/AG187-Lab/tessryn/pull/54) merged | Wider contracts, compatibility/runtime decisions and G01 inputs; [issue 3](https://github.com/AG187-Lab/tessryn/issues/3) remains open |
| K01 | [Original UEFI kernel](https://github.com/AG187-Lab/tessryn/pull/53) merged; all bounded emulator bring-up criteria complete and [issue 4](https://github.com/AG187-Lab/tessryn/issues/4) closed. [AWS CPU qualification](aws-boot-and-recovery.md#observed-cpu-qualification) records original-kernel boots around independent Linux recovery with verified cleanup | Physical hardware, native drivers, EC2 fault/reset execution, GPU, inference and performance remain separate gates; actual high firmware runtime/framebuffer execution remains unqualified |
| K02 | Ownership/activation/inventory foundations and [PR 58](https://github.com/AG187-Lab/tessryn/pull/58) merged, including the [ten-case single-CPU matrix](k02-native-matrix.md). [Clean evidence](../evidence/k02-native-matrix/README.md): ten fresh accepted boots/52 CPL3 traps, matching twin builds, 578 Python/97 Rust checks and all historical slice/K01 regressions pass. [Resumable single-CPU service](k02-region-service.md) adds reusable dispatch and two CPL3 programs: [three clean boots/68 traps](../evidence/k02-region-service/README.md), preserved contexts, final zero ownership and passing regressions | Arbitrary loading, production services, SMP and DMA/device quiescence; [issue 5](https://github.com/AG187-Lab/tessryn/issues/5) remains open |
| K03 | [Scheduler and shared CPU-budget policy core](https://github.com/AG187-Lab/tessryn/pull/61) merged: host timelines, 42 Rust policy tests and pinned freestanding compilation; [reproduction and limits](k03-preparation.md). The opt-in [single-CPU timer integration](k03-timer-preemption.md) implements HPET preemption, strict actual-time budgets/deadlines and failure containment for two CPL3 programs, with [four clean accepted boots/69 traps](../evidence/k03-timer/README.md), matching 14-artifact twins, 90 focused host checks, 697 Python tests and passing regressions | Shared SMP scheduling and aggregate budgets/accounting under contention, physical clocks, per-CPU timers and general idle/wakeup; [issue 6](https://github.com/AG187-Lab/tessryn/issues/6) remains open and dependent on K02 |
| Guest measurements | [In-kernel benchmark experiment](native-kernel-benchmarks.md): 13 fixed cases, 208 raw TSC samples, twin builds and independently verified single-CPU QEMU captures | Counter frequency and physical latency qualification; trusted runtime scheduling and multicore timing; GPU and end-to-end inference performance |

The ten-case matrix and resumable service supply a bounded single-CPU integration baseline. The timer integration advances this baseline into enforced execution. The opt-in [two-CPU bootstrap](k03-smp-bootstrap.md) now implements a bounded kernel-only foundation: ACPI topology admission, original INIT/SIPI, private AP CPU tables/stacks, 8192 shared atomic increments, heartbeat progress and three acknowledged IPIs followed by a terminal stop. Its [clean execution evidence](../evidence/k03-smp-bootstrap/README.md) records both scenarios, six identical twin artifacts, 26 parser checks, 725 Python tests and passing prior-profile regressions; all RAM stays retained. The separate [two-CPU CPL3 profile](k03-smp-user.md) now adds private immutable user roots and contexts, authenticated peer stops and fault containment. Its [clean evidence](../evidence/k03-smp-user/README.md) records three accepted boots, seven complete CPL3 traps, nine twin artifacts, 755 Python tests, 26 parser checks and all 57 earlier-profile commands. Shared scheduler/accounting ownership, aggregate budgets, per-CPU timers and reusable cross-core quiescence remain later gates. Arbitrary program admission and production service isolation need separate qualification. Physical qualification can progress independently. The [inference performance plan](inference-performance.md) proposes downstream experiments; a preregistered native comparison remains pending and published external results are research inputs, with no measured Tessryn performance claim.

## First work and critical path

G01 establishes exact physical inventories, access/artifact prerequisites and initial engineering profiles. Its tooling foundation landed in [PR #52](https://github.com/AG187-Lab/tessryn/pull/52), while the qualification issue remains open. G03's [reproducible build and evaluation tooling](build-and-evaluation.md) is complete for its fixture profile. G02's provisional host conformance foundation has landed; wider target/interface decisions still depend on G01. The bounded [K01 CPU bring-up profile](first-kernel.md), recorded under [ADR 0010](decisions/0010-first-uefi-kernel.md), and independent K02/K03 policy preparation do not close those platform or contract gates. Current readiness follows live issue state, dependencies and acceptance evidence.

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

