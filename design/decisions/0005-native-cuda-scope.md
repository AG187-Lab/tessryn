# ADR 0005: Qualify native CUDA device execution before ecosystem compatibility

Status: Accepted scope boundary. Hardware, firmware and executable targets: pending qualification.

## Decision

The first proof initializes an exact NVIDIA device on Tessryn and launches an exact-target device-only cubin compiled on a development machine. The source-compiled native engine uses a documented CUDA Driver API subset.

Required families are discovery, contexts, allocation/copies, modules/functions, launches, streams, events and synchronization. Unsupported calls fail explicitly.

## Consequences

Executing selected NVIDIA machine code is distinct from stock host library compatibility. PTX JIT, Runtime host registration, full Graph API compatibility, stock libraries and unmodified applications are separate programs.

Native prepared graph replay can operate without full CUDA Graph API compatibility. Exact firmware, artifact metadata, ISA and platform power assumptions must be recorded. Native notebook execution requires its own platform evidence.

An AMD x86-64 CPU does not imply an AMD GPU backend. Apple GPU execution requires its own compiler/driver path.

## References

[Native ABI](../native-abi.md), [NVCC](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html), and GPU01–GPU03/CUDA01 in [the backlog](../../planning/backlog.json).

