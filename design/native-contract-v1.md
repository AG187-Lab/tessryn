# Native contract v1: host conformance profile

Status: **provisional host contract**, prepared 2026-10-11. This profile implements reviewable byte layouts, portable symbolic model/state records and host conformance fixtures for [G02](https://github.com/AG187-Lab/tessryn/issues/3). It supplies no native service dispatcher, isolation domain, queue runtime, transport, CUDA driver or model execution. Passing fixtures cannot close G02: [G01's remaining physical qualification and target-selection gate](https://github.com/AG187-Lab/tessryn/issues/1#issuecomment-6113620818) still applies.

The normative layout and enum definitions are [contract.json](../interfaces/abi-v1/contract.json); [compatibility.json](../interfaces/abi-v1/compatibility.json) records fixture formats and proposed external compatibility scope. [ADR 0009](decisions/0009-native-contract-profile.md) proposes this bounded profile for maintainer review while the whole-kernel language and native service ABI decision remains [Proposed](decisions/0002-language-and-toolchain.md).

## Encoding and negotiation

Every scalar uses its explicit unsigned width and little-endian encoding. Descriptors contain no process pointers, language object layouts, strings, host-sized integers or implicit padding. Native structures are layout probes; copying structure memory is not a portable encoder. Decode untrusted input by copying scalar bytes, without dereferencing the input as an aligned C or Rust object. Top-level cross-domain layout alignment is 8 bytes; the embedded Header has natural alignment 4. These requirements are independent of source-buffer alignment or device mapping alignment.

| Record | Kind | Bytes | Purpose |
| --- | --- | --- | --- |
| Header | embedded | 16 | Version, declared size, record kind, zero flags/reserved |
| CapabilityRef | embedded | 16 | Domain-local slot, generation and domain identity |
| Negotiation | 1 | 48 | Offered version range and required/supported feature masks |
| Region | 2 | 64 | Region authority, owner task, length, budget and placement epoch |
| Submission | 3 | 128 | Request/task identity, operation, region slice, completion/dependency authority, budget and deadline |
| Completion | 4 | 80 | Request/sequence, epoch, status, milestone, produced-region identity and ownership generation |

Header offsets are `major:u16@0`, `minor:u16@2`, `size:u32@4`, `kind:u16@8`, `flags:u16@10`, `reserved:u32@12`. A capability reference uses `slot:u32@0`, `generation:u32@4`, `domain:u64@8`. These byte definitions take precedence over a compiler's object layout. The fixture profile is version 1.0 and feature mask zero.

Negotiate before interpreting service records. The range endpoints must be ordered lexicographically; required features must be supported locally and advertised by the peer. Choose the highest common supported version, which is currently only 1.0. Fail if no common version or feature set exists. A future minor version is not implicitly compatible: new kinds, extension bytes and feature bits require an explicitly implemented profile and vectors.

A decoder requires an exact frame: actual size equals the declared size and the known record's size. Reject other versions, unknown kinds/enums, extra/truncated bytes, nonzero flags/reserved fields and width violations. Validation never supplies missing fields or truncates oversized integers. Reject a malformed record before it can become execution or authority. No rejected record is treated as successful work.

## Authority, ownership and admission

An all-zero capability reference means absent authority. A present reference requires a nonzero generation and domain; slot zero remains a valid slot. References are identifiers, not bearer authentication tokens or proof of authority. The receiving service must derive the caller's domain from an authenticated boundary and resolve each reference against its trusted capability table. It then checks rights, current generation, owner task, expiry, budget, permitted operation, region bounds and placement epoch. A matching numeric domain supplied by the caller does not authenticate that caller.

Delegation cannot broaden parent rights, resource ceilings, device mappings, tenant scope or expiry. Inference, enrollment, signing, ordinary storage, installation and experiment authority remain separate. Generation reuse must not permit ABA: a future runtime must retire exhausted slots or prove safe generation rollover. Host width/layout validation does not implement a capability table, revocation or tenant isolation.

Check a region slice using `offset <= capacity` and `length <= capacity - offset`, with explicit u64 overflow rejection. Region registration does not itself permit DMA. A native backend must additionally verify ownership, device authority, mapping alignment, synchronization, supported device profile and teardown ordering. Metadata referenced by copy/execute/transfer operations requires a separately versioned service format; this generic submission never invents unrestricted physical addresses or raw DMA.

Charge committed bytes, reserved growth, workspace and transfer duplication to the owning task/tenant before admission. The descriptor carries a budget identity, not an enforceable budget or permission to allocate. A deadline of zero means no deadline; other values use the owning node's monotonic nanosecond clock and cannot be compared directly between hosts. CPU, memory, device-time and bandwidth enforcement still require K02/K03 and backend evidence. GPU time budgets do not promise preemption of a kernel that hardware cannot interrupt.

Trusted expiry/deadline enforcement and the lookup joining task and budget identities to authenticated authority remain pending. The host codec validates those fields' shape and widths; it cannot prove a task/budget ID belongs to the caller or that a deadline is enforced. The separate host lifecycle reference exercises selected allocation/delegation/accounting/generation/cancellation rules with explicit caller domains. It is a single-threaded executable specification, without native task identities, expiry, clock enforcement, address spaces or protected capability storage.

A zero placement epoch denotes local work without distributed placement authority. Distributed work requires the currently committed nonzero native placement epoch; callers cannot assign an epoch by sending a descriptor. The management service's desired-state revision is a different identity. Stale submissions, completions and output must be fenced against trusted state, including after revocation or coordinator changes.

## Completion, cancellation and faults

Submission acceptance reserves responsibility for accepted work; it proves neither execution completion nor safe buffer reuse. A completion binds the request, nonzero completion sequence, placement epoch and produced region. A present region requires a positive u32 ownership generation matched against trusted outstanding work; this operation/state lifetime identity is distinct from the capability-handle generation. An absent region requires zero produced length and ownership generation. Produced bytes must fit the resolved region. Sequence allocation, replay/deduplication and trusted-origin checks belong to the runtime; a syntactically valid completion is not evidence that work occurred.

Cancellation has separate observable milestones: request received, future launches stopped, output fenced and memory reclaimed. `ok` reports the named milestone only. A cancellation receipt cannot justify region reuse, immediate device interruption or whole-task success. Reclamation follows all outstanding service/device/transfer references and required drain/reset fences. A deadline expiry or peer/device fault likewise does not prove that DMA has stopped. A failed or unknown teardown retains ownership and reports the unresolved state.

Faults distinguish malformed input, invalid authority, stale handles/epochs, bounds, capacity, admission, deadline, device/peer failures, incompatible format, partial streams and backpressure. A fault milestone requires a failure status. Losing required model state cannot be labeled continuation merely because control quorum survives. Client stream sequence and partial-response recovery need the later native model service contract.

These records define the publication boundary, not a queue implementation. K04 must separately specify ring capacity, producer/consumer atomics and ordering, wraparound, backpressure, sequence allocation, crash/restart handling and device cache/DMA fences. A proposed implementation must publish fully written descriptors before the consumer observes them, preserve bounded completion capacity, and never consume an untrusted index as memory authority. This profile does not claim that those runtime properties have been tested.

## Model, shard, operator, precision and state records

The host manifest is a strict JSON conformance record, not a packed syscall structure, model artifact, signed manifest or executable backend declaration. Its accepted schema is described by the portable records in [contract.json](../interfaces/abi-v1/contract.json) and the fixture allowlists in [compatibility.json](../interfaces/abi-v1/compatibility.json). Unknown fields and duplicate JSON keys are rejected rather than silently discarded.

The model record declares schema version 1, a nonempty model ID of at most 128 characters, artifact and tokenizer SHA-256 identities, a positive u32 layer count, architecture, precision, required operator names and shard records. Only the symbolic `conformance_fixture` architecture exists here. `copy`, `add` and `matmul` denote fixture requirements; listing them does not implement their arithmetic or qualify any numerical quality. The profile accepts `f32` and `f16` interchange names and the symbolic `contiguous_le_v1` layout, with no implicit conversion, quantization or qualified device target.

Each shard declares its index/count and a half-open layer interval. The list contains 1–1024 records ordered by index, covering `0..count-1` exactly with one consistent count; nonempty contiguous layer intervals must cover `0..layer_count` without holes, overlap or duplicated ownership. Every state record names `kv` or `recurrent`, the same precision as its model, the accepted layout, a positive u32 ownership generation and a nonzero u64 placement epoch shared by the group. These symbolic records do not specify complete tensor dimensions, strides, positional configuration, adapter identity or numerical operators. Native reusable state will require those identities and evidence before interchange is enabled.

Each shard accounts for weights, state, workspace, transfer duplication and reserved growth as nonnegative u64 byte counts. `total` must equal their overflow-checked sum. Matching the sum does not establish that those estimates fit real hardware, reserve native capacity or include every future firmware/OS overhead. Native admission must reconcile the complete footprint with measured available capacity.

Compatibility requires exact model/tokenizer/artifact identity plus the explicit accepted representation and backend profile. Different precision/layout/state representations are rejected; no conversion path is qualified. A future conversion requires its own version, resource bound, numerical test gate and recovery semantics. Hash fields bind declared identities only: the fixture does not read model files, verify signatures or authenticate artifact provenance.

## Pinned transport target

The proposed first native wire target is **Homa version 1** from `johnousterhout/homa-rfc` revision `df4bc0d7a1d5c30292e47f474a85c3669dce8612`, file `draft-ousterhout-tsvwg-homa-00.md`; its raw SHA-256 is `105df694d12a198fabd178e68000ed242db2ca34f7e1700099e645ea4fd5f0db`. The [immutable primary draft](https://github.com/johnousterhout/homa-rfc/blob/df4bc0d7a1d5c30292e47f474a85c3669dce8612/draft-ousterhout-tsvwg-homa-00.md) identifies version 1 and scheduled-message `START_MSG` packet type 25. It describes TCP-compatible common-header framing and records a planned UDP change. This pin uses that exact revision, without silently adopting a later framing change or mixing the 2018 protocol.

This selects a reviewable protocol input, not implemented interoperability or a qualified NIC/fabric. NET01 must independently implement and test it; authentication/encryption, credits, tenant accounting, loss/recovery and exact fabric support remain separate evidence requirements. Logical region length, transport message limit and packet MTU remain distinct. Homa supplies neither model sharding, arithmetic collectives nor GPU/NIC peer DMA. A cloud adapter requires its independently permitted packet path. See [ADR 0004](decisions/0004-pinned-transport-contract.md).

## Proposed CUDA source subset

The compatibility input is the archived **CUDA Driver API 13.0.0** reference. It is a documentation pin, not a claim that 13.0.0 nvcc, firmware, a driver binary or a particular GPU is qualified. The unversioned reference checked on 2026-10-11 presents 13.4; using an archive keeps this proposal reviewable across future documentation changes. [Archived reference](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/index.html), [current reference](https://docs.nvidia.com/cuda/cuda-driver-api/index.html).

| Required family | Planned source spellings |
| --- | --- |
| Initialization, version, errors | `cuInit`, `cuDriverGetVersion`, `cuGetErrorName`, `cuGetErrorString` |
| Discovery | `cuDeviceGetCount`, `cuDeviceGet`, `cuDeviceGetName`, `cuDeviceGetAttribute`, `cuDeviceTotalMem` |
| Contexts | `cuCtxCreate`, `cuCtxDestroy`, `cuCtxGetCurrent`, `cuCtxSetCurrent`, `cuCtxSynchronize` |
| Allocation and copies | `cuMemAlloc`, `cuMemFree`, `cuMemcpyHtoD`, `cuMemcpyDtoH`, `cuMemcpyDtoD`, and those three asynchronous copy variants |
| Modules/functions | `cuModuleLoadData`, `cuModuleGetFunction`, `cuModuleUnload` |
| Launch | `cuLaunchKernel` |
| Streams | `cuStreamCreate`, `cuStreamDestroy`, `cuStreamQuery`, `cuStreamSynchronize`, `cuStreamWaitEvent` |
| Events | `cuEventCreate`, `cuEventDestroy`, `cuEventRecord`, `cuEventQuery`, `cuEventSynchronize` |

These are source API spellings, not frozen declarations, header-macro mappings or exported symbol suffixes. A later source-compiled native facade must select and verify those details and allowed flags. Its boundaries translate native-owned registered regions and handles; pointers stay inside the source component and never become cross-domain authority. The initial proposal uses explicit non-default streams and exact-target device-only cubins. It rejects PTX/fatbin/JIT inputs, unsupported flags/attributes/parameter layouts and other API operations before work. [Device](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/group__CUDA__DEVICE.html), [context](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/group__CUDA__CTX.html), [memory](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/group__CUDA__MEM.html), [module](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/group__CUDA__MODULE.html), [execution](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/group__CUDA__EXEC.html), [stream](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/group__CUDA__STREAM.html), [event](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/group__CUDA__EVENT.html) and [error](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-driver-api/group__CUDA__ERROR.html) primary references.

All unlisted calls are outside this proposed subset. In particular, it excludes Runtime/fatbin registration; `cuModuleLoadDataEx` and linking/JIT calls; `cuMemHostRegister`; managed and stream-ordered allocation; primary contexts; stream capture and Graph APIs; cooperative launches; peer access; graphics/external-resource interoperability; stock libraries and unmodified host applications. [compatibility.json](../interfaces/abi-v1/compatibility.json) lists concrete excluded calls. The later facade must return explicit unsupported/invalid-input errors without side effects, never success stubs. This host profile implements no CUDA call or error-code translation. Native prepared schedule replay does not imply CUDA Graph compatibility. [ADR 0005](decisions/0005-native-cuda-scope.md), [archived nvcc device-output reference](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-compiler-driver-nvcc/index.html#cubin-cubin).

## Threat assumptions and evidence limits

Assume callers can supply malformed descriptors, wrong widths, conflicting identities, stale generations/epochs, out-of-bounds slices, unauthorized budgets and forged/replayed completions. Assume peer or device failure can occur during accepted work and teardown. Reject numeric/format errors before authority use; authenticated namespaces, capability tables, task ownership and committed epochs must supply the actual trusted state. Ordinary authorized layer execution exposes its activations/state to that worker; this design does not claim confidentiality from a worker authorized to execute those layers.

The host fixture and evaluator run under a trusted developer/operator's process and filesystem. They do not protect against hostile native candidates, host-process memory corruption, compromised privileged code, physical/DMA attacks, replay across a native authenticated channel or unauthorized resource reuse. Native capabilities, mapping isolation, cancellation enforcement, queue ordering, authentication, hardware fences and sustained performance require their own implementation and tests. Do not treat a valid byte record, declared hash, manifest total or matching C/Rust layout as evidence for those properties.

## Reproduction and remaining gates

The initial clean-source results and exact compiler/input identities are retained
in [G02 conformance evidence](../evidence/g02-conformance/README.md).

Run from the repository root:

```sh
python3 tools/check_native_abi.py --output build/g02-result.json
python3 -m unittest discover -s tests
python3 tools/validate_design.py
```

The checker must bind its result to the contract inputs, positive/negative vectors and available C/Rust layout probes, with unavailable tool profiles explicit. The C11 probe executes byte roundtrips on the host. The pinned Rust `x86_64-unknown-none` profile compiles `no_std` layout and constant byte-vector assertions; it supplies no Rust host executable or native service execution. Preserve the output and exact source/tool identities as fixture evidence. The unit tests exercise format/identity/bounds/rejection behavior; they do not invoke a native dispatcher or GPU. Do not substitute compile-only evidence for a runtime result or mark unavailable probes successful.

| Capability | Current profile | Evidence still required |
| --- | --- | --- |
| Binary descriptor encoding/layout | C host roundtrips; Rust freestanding compile-time assertions | Exact probe/tool identities and retained result |
| Model/shard/state compatibility | Symbolic fixture validation | Real model layouts, numerical/operator and artifact tests |
| Native service ABI and authority | Unavailable | K02–K05 dispatch, isolation, queue and cancellation evidence |
| Pinned Homa target | Proposed, unimplemented | NET01 exact-profile interoperability and failure tests |
| CUDA source subset | Proposed, unimplemented | G01 targets; GPU01–GPU03 firmware, execution and recovery |
| Whole-kernel/runtime/toolchain decision | Proposed | Native runtime, calling convention, debugger and target evidence |

G03's reproducible compiler fixture remains useful input; it does not settle the runtime or device compiler choice. G01 target access/qualification, native implementations and the versioned source facade remain necessary before the broader G02 acceptance can be claimed.
