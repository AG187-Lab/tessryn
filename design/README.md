# Design

These documents capture research, architectural decisions, implementation gates and recorded evidence. Planned behavior and implemented capability are identified separately. Update them when evidence or implementation changes a conclusion.

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
| [Build and evaluation](build-and-evaluation.md) | Pinned toolchain, artifact manifests and bounded emulator fixtures |
| [First kernel](first-kernel.md) | Original UEFI kernel, boot/fault tests and GPU Mart virtual-CD workflow |
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

The first original kernel has emulator boot and fault-path evidence under the
[K01 profile](first-kernel.md). Physical native boot, GPU execution, Thunderbolt
support and distributed performance remain unqualified. Planned capabilities
must remain labeled until their acceptance evidence exists.
