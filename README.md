# Tessryn

An original operating system for AI agents and distributed inference.

Tessryn is designed to let servers and qualified laptops form a cluster, execute models through native accelerator drivers, and serve models larger than any individual worker can hold. Its kernel, execution interfaces and distributed services are being designed together around memory ownership, asynchronous work and measured resource budgets.

**Status:** the first original x86-64 UEFI kernel boots in QEMU/OVMF, exits firmware boot services, owns its CPU tables and memory handoff, and exercises exceptions, panic and reset. The bounded AWS `t3a.small` CPU profile has two owner-accepted native EC2 boots, separated by recovery on a fresh Ubuntu instance, with cleanup complete. Physical hardware, native device drivers, GPU execution and Tessryn performance remain unqualified. [First kernel workflow](design/first-kernel.md) and [observed AWS CPU qualification](design/aws-boot-and-recovery.md#observed-cpu-qualification).

## The first product milestone

Four small machines boot Tessryn, including a wired, mains-powered laptop. Every machine executes a resident shard of one model whose admitted memory requirement exceeds every individual worker's capacity. Three stable nodes maintain control quorum. The demonstration reports capacity, single-request latency, concurrent goodput, numerical quality and failure behavior separately.

The first accelerator qualification targets x86-64 and one exact NVIDIA hardware family. Apple M5, cloud accelerator support and additional backends have separate qualification gates. A laptop doing only auxiliary work does not complete the sharding milestone.

## Start here

- [Design index](design/README.md) and [product scope](design/overview.md)
- [Architecture](design/architecture.md), [native interfaces](design/native-abi.md) and [networking](design/networking.md)
- [Native CUDA](design/native-cuda.md), [distributed inference](design/distributed-inference.md) and [memory and serving](design/memory-and-serving.md)
- [Research](design/research.md), [review findings](design/review.md) and [decisions](design/decisions/)
- [Roadmap](design/roadmap.md), [hardware qualification](design/platforms.md) and [benchmark contract](design/benchmarks.md)
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

Tessryn is pronounced **TESS-rin**. The name suggests independent devices tessellating into a coherent inference system. `tessryn.si` appeared unregistered and unreserved when checked on October 11, 2026; it has not been purchased or reserved. [Naming evidence](design/name.md).

New project code and documentation are licensed under [Apache-2.0](LICENSE). Third-party components, firmware, model weights and proprietary libraries retain their own terms; see [provenance policy](design/provenance.md).
