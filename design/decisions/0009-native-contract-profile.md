# ADR 0009: Define a provisional portable native contract profile

- Date: 2026-10-11
- Status: Proposed for maintainer review; host fixtures implemented, native runtime and full G02 acceptance pending
- Scope: descriptor byte layouts, symbolic model/state records and explicit compatibility targets

## Context

[G02](https://github.com/AG187-Lab/tessryn/issues/3) needs versioned native interfaces, conformance vectors and bounded compatibility claims. The original [native ABI proposal](../native-abi.md) leaves byte order, layouts and negotiation open. G03 supplies reproducible tool fixtures, while G01's physical prerequisites and exact target selection remain unresolved. K01's boot work does not implement a native service runtime or freeze the whole kernel language decision.

A host contract can catch mismatched layouts, widths, identities and invalid inputs before hardware is available. That evidence must remain distinct from native authority, DMA, service dispatch, GPU execution and numerical compatibility.

## Decision

1. Define provisional ABI 1.0 as explicit-width little-endian scalars, fixed frame sizes and 8-byte layout alignment, with pointer-free references. Reject unknown versions, kinds, flags, reserved fields, lengths and enum values; negotiate only explicitly supported profiles.
2. Keep the authoritative sizes/offsets/enums and vectors under [interfaces/abi-v1](../../interfaces/abi-v1/contract.json). Execute C11 host layout/byte probes and compile pinned freestanding `no_std` Rust layout/constant-vector assertions. Compiler object memory is not a portable encoder; compile-time Rust evidence is not a Rust host or native service execution result.
3. Separate submission acceptance, execution completion, cancellation receipt, stopped launches, fenced output and safe memory reclamation. Numeric references do not grant authority; the future runtime must resolve them against authenticated namespace, ownership, generation, budgets and committed epoch state.
4. Validate symbolic model/shard/operator/precision/state records strictly, with complete overflow-checked memory totals and exact representation matching. Accept only the `conformance_fixture` architecture; f32/f16 and named fixture operators declare no supported native model or arithmetic. No conversion is qualified.
5. Pin the proposed first Homa input to version 1 in `johnousterhout/homa-rfc` revision `df4bc0d7a1d5c30292e47f474a85c3669dce8612`, using its `START_MSG` draft. Pin the proposed CUDA Driver API source subset to the archived 13.0.0 reference and explicit call allowlist. These are compatibility targets, not implemented support or selected device/compiler artifacts.
6. Keep [ADR 0002](0002-language-and-toolchain.md) Proposed. Propose this host layout/fixture profile without freezing native service calling conventions, export symbols, Rust runtime, driver/compiler targets or the entire G02 gate.

The detailed contract, threat assumptions, unsupported surface and reproduction commands are in [native contract v1](../native-contract-v1.md). [compatibility.json](../../interfaces/abi-v1/compatibility.json) records exact source links/pins and the distinction between fixtures, proposed targets and unavailable runtime capabilities.

## Alternatives considered

**Freeze the native ABI immediately:** premature while device targets, source facade signatures, queue ordering and runtime enforcement are unqualified. Retain a provisional profile with deterministic fixtures and explicit rejection behavior.

**Keep every field informal until hardware:** permits independent services to choose incompatible widths, identities and cancellation meanings. Host conformance can resolve those portable choices while preserving target gates.

**Copy language object layouts or expose process pointers:** creates host/toolchain dependencies and converts untrusted descriptors into addresses. Use fixed byte offsets, explicit-width scalars and service-resolved capabilities instead.

**Use moving Homa/CUDA documentation:** obscures which compatibility promise is under review. Pin exact immutable Homa input and archived CUDA reference; accept changes only with a new compatibility profile and tests.

## Consequences and acceptance boundary

Host checks can prove layout/serialization/rejection behavior and strict symbolic manifest conformance under a trusted development environment. They cannot prove unforgeable capabilities, tenant isolation, native queue execution, DMA fences, authentication, cancellation timing, Homa interoperability, GPU execution or model quality.

The first native runtime may revise this profile with an explicit version and migration decision. G01 remains a dependency of full G02; its merged tooling does not establish physical qualification. K02–K05, NET01, GPU01–GPU03 and INF01/INF02 must provide their corresponding authority, queue, device, compatibility and numerical evidence. A passing host result must identify its source/tool inputs and retain explicit unavailable capabilities.

Revisit when the native dispatcher/source facade is implemented, an exact hardware/compiler profile is qualified, a new protocol/reference version is proposed, a concrete model state representation is added or negative runtime evidence reveals a missing lifetime or authority field.
