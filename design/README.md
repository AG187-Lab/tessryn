# Design

These documents record research, architectural decisions, implementation gates and observed progress. Intended contracts, fixture validation, original-kernel execution and qualified hardware behavior have separate evidence requirements. Update them when evidence or implementation changes a conclusion.

| Document | Purpose |
| --- | --- |
| [Overview](overview.md) | Product goals, supported roles and first demonstration |
| [Architecture](architecture.md) | Kernel boundaries, native services and execution flow |
| [Native interfaces](native-abi.md) | Memory, capabilities, queues and compatibility contracts |
| [Networking](networking.md) | Homa, collectives, transport profiles and transfer costs |
| [Distributed inference](distributed-inference.md) | Placement, sharding, handoff and failure semantics |
| [Memory and serving](memory-and-serving.md) | State ownership, batching, precision and multi-user service |
| [Native CUDA](native-cuda.md) | Accelerator execution and staged compatibility scope |
| [Platforms](platforms.md) | Hardware qualification and cloud/Apple support boundaries |
| [Initial platform qualification](platform-qualification.md) | G01 candidate records, rental gates and read-only reference inventory |
| [Benchmarks](benchmarks.md) | Workloads, baselines, numerical quality and evidence |
| [Inference performance plan](inference-performance.md) | Proposed research-backed experiments, numerical quality gates and measured goodput |
| [Runnable kernel benchmarks](kernel-benchmarks.md) | Host policy latency, memory/queue overhead, retained packets and measurement scope |
| [Build and evaluation](build-and-evaluation.md) | Pinned toolchain, artifact manifests and bounded emulator fixtures |
| [Evaluation evidence](evaluation-evidence.md) | Schemas, preregistration, holdouts and measurement rules |
| [Research](research.md) | Dated primary sources, applicability and open questions |
| [Review findings](review.md) | Adversarial findings and their resolutions |
| [Decisions](decisions/) | Architectural decision records |
| [Roadmap](roadmap.md) | Dependency-ordered milestones and deliverables |
| [Development coordination](development.md) | Ready work, GitHub workflow and planning reconciliation |
| [Provenance](provenance.md) | Original work and third-party artifact policy |
| [Name](name.md) | Naming rationale and domain evidence |

## Evidence vocabulary

- **Source fact:** supported by a linked primary document or source file.
- **Analytical example:** calculated under explicitly declared assumptions.
- **Reported result:** a paper, project or vendor's measurement, not reproduced here.
- **Decision:** the current project choice, with rationale and reconsideration conditions.
- **Open question:** requires research or an experiment before a claim is made.

As of October 12, 2026, [K01](https://github.com/AG187-Lab/tessryn/pull/53) has original-kernel QEMU boot/exception/reset evidence and owner-accepted native AWS CPU boot/recovery evidence for the bounded `t3a.small` profile. [Draft K02](https://github.com/AG187-Lab/tessryn/pull/58) adds four single-CPU CPL3 protection probes under QEMU. Physical hardware, full native isolation, device drivers, GPU execution, Thunderbolt, inference and distributed performance remain unqualified. See the [roadmap](roadmap.md) for current merge state and remaining gates; historical evidence retains its original date and scope.
