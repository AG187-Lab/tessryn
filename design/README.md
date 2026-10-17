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
| [First kernel](first-kernel.md) | Original UEFI kernel, boot/fault tests and GPU Mart virtual-CD workflow |
| [Native memory isolation slice](k02-native-slice.md) | Four single-CPU CPL3 memory probes, artifact-bound traps and remaining K02 gates |
| [Native memory isolation matrix](k02-native-matrix.md) | Ten fresh single-CPU CPL3 cases, protected request dispatch and ordered revocation/reuse |
| [Resumable region service](k02-region-service.md) | Reusable bounded request dispatch, two CPL3 programs, context preservation and trusted teardown |
| [Scheduler policy preparation](k03-preparation.md) | Shared lifetime CPU caps, protected reservations, deadlines and retained stop ownership |
| [Single-CPU timer preemption](k03-timer-preemption.md) | HPET/PIC interrupts, resumable CPL3 contexts, strict actual-time budgets and evidence requirements |
| [In-kernel benchmark experiment](native-kernel-benchmarks.md) | Opt-in raw-counter guest observations, capture boundaries and hardware timing gates |
| [AWS CPU boot and recovery](aws-boot-and-recovery.md) | Headless UEFI inputs, local tests and separately approved native EC2 evidence |
| [Native AWS evidence intake](aws-native-evidence.md) | Private cloud capture consistency, fresh boots, independent recovery and cleanup review |
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

The [K01 implementation and evidence](first-kernel.md), recorded in
[PR #53](https://github.com/AG187-Lab/tessryn/pull/53), cover original-kernel
QEMU boot, exception, panic and reset paths, including actual high image/handoff
regressions. The [AWS CPU profile](aws-boot-and-recovery.md#observed-cpu-qualification)
records two owner-accepted native `t3a.small` boots and independent recovery on a
separate Ubuntu instance, with cleanup complete. Merged [K02 PR #58](https://github.com/AG187-Lab/tessryn/pull/58)
builds on K01: the historical four-probe slice and the [ten-case matrix](k02-native-matrix.md) have separate source-bound evidence under QEMU.
The [resumable region service](k02-region-service.md) adds three source-bound,
cooperative two-program executions with [clean evidence](../evidence/k02-region-service/README.md).
The [in-kernel benchmark experiment](native-kernel-benchmarks.md) separately
executes 13 fixed cases and 208 raw TSC samples with retained capture bindings.
Physical hardware, full native isolation, native device drivers, GPU execution,
Thunderbolt, inference and distributed performance remain unqualified. See the
[roadmap](roadmap.md) for observed progress and remaining gates; historical
evidence retains its original date and scope.
