# Tessryn

An original operating system for AI agents and distributed inference.

Tessryn is designed to let servers and qualified laptops form a cluster, execute models through native accelerator drivers, and serve models larger than any individual worker can hold. Its kernel, execution interfaces and distributed services are being designed together around memory ownership, asynchronous work and measured resource budgets.

**Status, October 16, 2026:** the first original x86-64 UEFI kernel is merged through [PR #53](https://github.com/AG187-Lab/tessryn/pull/53), and its bounded emulator bring-up acceptance is complete. It boots in QEMU/OVMF, exits firmware services, owns its CPU tables and memory handoff, and exercises traps, faults, panic and reset. Two original-kernel AWS CPU boots bracketing independent Linux recovery also passed, with trial cleanup verified. [First-kernel workflow](design/first-kernel.md) and [AWS CPU scope](design/aws-boot-and-recovery.md#observed-cpu-qualification).

The [K02 matrix](design/k02-native-matrix.md), merged through [PR #58](https://github.com/AG187-Lab/tessryn/pull/58), implements ten fresh single-CPU CPL3 tests for protected caller context, bounds, permissions/NX, revocation, exact-frame reuse and stale identities. [Clean execution evidence](evidence/k02-native-matrix/README.md) records all ten accepted boots, 52 hardware traps, 578 Python tests, 97 Rust checks and passing historical K02/K01 regressions. This bounded, image-bound experiment does not complete general native service isolation, SMP or DMA.

The [single-CPU region service](design/k02-region-service.md) now runs two resumable CPL3 programs that build their own requests, share read-only memory, reject invalid authority and exercise revocation and erased-page reuse. [Clean execution evidence](evidence/k02-region-service/README.md) records three accepted boots with 68 actual privilege traps, preserved task registers/legacy FP state and zero retained ownership after cleanup. That cooperative, image-bound profile keeps its original scope. Arbitrary program loading, SMP and device isolation remain open.

The opt-in [K03 timer profile](design/k03-timer-preemption.md) integrates HPET interrupts with the unchanged scheduler policy for the same two CPL3 programs. It implements protected timer stops, full actual elapsed-time charging, strict lifetime budgets and deadlines, and peer continuation after task failure. [Clean execution evidence](evidence/k03-timer/README.md) records four accepted boots, 69 actual traps and zero retained ownership, with matching twins and passing regressions. Physical clock, latency and multicore qualification remain open.

The [in-kernel benchmark experiment](design/native-kernel-benchmarks.md) executes 13 fixed cases and 208 raw TSC samples under single-CPU QEMU, with retained source, artifact and capture bindings. These observations establish guest execution and workload correctness; hardware latency, native scheduling and inference performance remain unqualified.

Reproducible builds, portable interface conformance, ownership policy and the host benchmark harness have landed. [K03 scheduler/budget policy preparation](https://github.com/AG187-Lab/tessryn/pull/61) and [hardware intake/recovery requirements](design/hardware-intake.md) are merged. Physical stable-node/notebook qualification, qualified clocks and SMP scheduling, device drivers, GPU execution, model inference and measured hardware/inference performance remain open. [Current progress and gates](design/roadmap.md).

## The first product milestone

Four small machines boot Tessryn, including a wired, mains-powered laptop. Every machine executes a resident shard of one model whose admitted memory requirement exceeds every individual worker's capacity. Three stable nodes maintain control quorum. The demonstration reports capacity, single-request latency, concurrent goodput, numerical quality and failure behavior separately.

The first accelerator qualification targets x86-64 and one exact NVIDIA hardware family. Apple M5, cloud accelerator support and additional backends have separate qualification gates. A laptop doing only auxiliary work does not complete the sharding milestone.

## Start here

- [Design index](design/README.md) and [product scope](design/overview.md)
- [Architecture](design/architecture.md), [native interfaces](design/native-abi.md) and [networking](design/networking.md)
- [Native CUDA](design/native-cuda.md), [distributed inference](design/distributed-inference.md) and [memory and serving](design/memory-and-serving.md)
- [Research](design/research.md), [review findings](design/review.md) and [decisions](design/decisions/)
- [Roadmap](design/roadmap.md), [hardware qualification](design/platforms.md) and [benchmark contract](design/benchmarks.md)
- [Inference performance plan](design/inference-performance.md): proposed experiments grounded in current research, with numerical quality and measured goodput gates
- [Development board](https://github.com/orgs/AG187-Lab/projects/1), [open implementation work](https://github.com/AG187-Lab/tessryn/issues), [milestones](https://github.com/AG187-Lab/tessryn/milestones) and [development coordination](design/development.md)
- [Build and emulator fixture workflow](design/build-and-evaluation.md) and [evaluation evidence formats](design/evaluation-evidence.md)
- [First UEFI kernel, boot media and GPU Mart test path](design/first-kernel.md)
- [Headless AWS CPU boot and independent recovery](design/aws-boot-and-recovery.md)

## Contribute

Pick an unblocked issue, agree on its acceptance criteria and open a focused pull request. Architecture changes include a decision record; performance claims include reproducible measurements. [CONTRIBUTING.md](CONTRIBUTING.md) explains the workflow.

Run the repository checks with Python 3.12 or newer (tested with 3.14.6):

```sh
python3 tools/validate_design.py
python3 -m unittest discover -s tests -v
```

The machine-readable [backlog](planning/backlog.json) records scope and dependencies. GitHub Issues is the live execution tracker; changes to either must be reconciled before merging.

## Name and license

Tessryn is pronounced **TESS-rin**. The name suggests independent devices tessellating into a coherent inference system. The project landing page is live at [tessryn.si](https://tessryn.si/). [Naming and dated domain evidence](design/name.md).

New project code and documentation are licensed under [Apache-2.0](LICENSE). Third-party components, firmware, model weights and proprietary libraries retain their own terms; see [provenance policy](design/provenance.md).
