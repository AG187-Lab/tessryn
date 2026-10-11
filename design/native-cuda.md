# Native CUDA execution

Status: proposed, unimplemented. Native means the deployed machine boots Tessryn and Tessryn owns GPU memory, submission, synchronization, interrupts, and recovery. A development machine may compile device code. A deployed Linux kernel, Linux GPU driver, or macOS accelerator service does not satisfy this target.

## Initial scope

Freeze one exact NVIDIA desktop profile and one notebook profile, their PCI identifiers, GPU architecture, firmware versions, and required power behavior. Implement PCI/BAR access, DMA isolation, GPU address spaces, firmware/GSP initialization, queues, and completion ordering before inference.

[NVIDIA's open kernel-module sources](https://github.com/NVIDIA/open-gpu-kernel-modules) contain OS-agnostic resource-management code and Linux interfaces. They require matching firmware and user-space components; UVM and DRM have additional Linux dependencies. They are implementation evidence, not a ready driver for Tessryn. [CUDA on QNX](https://developer.nvidia.com/docs/drive/drive-os/6.0.9/public/drive-os-qnx-installation/common/topics/installation/build-samples/build-run-sample-apps-qnx.html) is a non-Linux precedent on supported DRIVE systems, not generic Tessryn support.

[tinygrad's direct NVIDIA path](https://github.com/tinygrad/tinygrad/blob/7d2420e6488fed24afb5b9b45f4d983dec8c3fb8/tinygrad/runtime/support/nv/nvdev.py) demonstrates GSP/MMU/queue control outside stock libcuda. Its [host integration](https://github.com/tinygrad/tinygrad/blob/7d2420e6488fed24afb5b9b45f4d983dec8c3fb8/tinygrad/runtime/support/system.py) still uses Linux PCI mappings or VFIO. Reproducing that host contract natively remains work.

Compile exact-architecture, device-only cubins using [nvcc's documented output mode](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html#cubin-cubin). Compile host programs against Tessryn's own native ABI. Implement an explicitly versioned [Driver API](https://docs.nvidia.com/cuda/cuda-driver-api/driver-vs-runtime-api.html) subset: device discovery, contexts, allocation/copy, module/function loading, kernel launch, streams, events, and synchronization. Unsupported calls return explicit errors. See [native ABI](native-abi.md).

Runtime fatbin registration, PTX JIT, CUDA Graph compatibility, stock CUDA libraries, and stock host binaries are separate scopes. Tessryn can prepare and replay its own execution schedules without claiming CUDA Graph compatibility. Preserving a proprietary Linux libcuda binary would introduce a different host ABI project.

## Falsifiable milestones

1. Native GPU initialization, allocation, copy, and ordered completion, with invalid access and timeout tests.
2. CUDA-compiled vector addition and matrix multiplication, validated against declared numerical tolerances.
3. A resident model with source-compiled host control, concurrent clients, bounded cancellation, and fault recovery.
4. Four native machines, including the qualified wired notebook, jointly serve a resident model/state workload that exceeds every individual node's admitted capacity. All four participate in model execution.

Publish boot-to-inference evidence and dependencies for each profile. A notebook admitted only as a helper demonstrates policy behavior, but does not complete milestone four.

The portable transfer path is GPU ↔ pinned host buffers ↔ NIC, pipelined with explicit fences. [GPUDirect RDMA](https://docs.nvidia.com/cuda/gpudirect-rdma/) depends on supported GPU classes, PCIe topology, BAR mappings, registration lifetime, and memory ordering. Ordinary GeForce notebook CUDA support does not establish RDMA support. Verify exact hardware and isolation before enabling peer DMA; preserve the host-buffer path.
