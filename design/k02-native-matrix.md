# K02 original-kernel memory isolation matrix

This extends the [four-probe slice](k02-native-slice.md) with the ten cases in the
[reviewed protocol](k02-native-preparation.md). Each case boots a separate original
UEFI image, exits firmware services, installs protected CPU state and runs known,
image-bound CPL3 probes on one QEMU CPU. It is a bounded execution experiment;
it supplies no production service ABI, physical hardware, SMP, DMA or inference
qualification. K02 issue #5 remains open for those integration gates.

## What executes

| Case | Required observation |
| --- | --- |
| Caller forgery | B submits A's handle and claims caller A; protected context still supplies B and rejects the request without a PTE or charge change |
| Trusted operation forgery | Actual CPL3 requests cannot fence, acknowledge quiescence, administer allocation, complete a trusted lease or activate a reservation; a fenced mapping stays installed until trusted teardown |
| Unauthorized read | A successfully reads its retained page; B faults on the same unshared virtual address |
| Read-only sharing | B reads the delegated page, its write faults with exact permissions, and the complete backing digest stays unchanged |
| Exact bounds | An adjacent guard faults; byte-slice mapping fails alignment/bounds without rounding outward; write-only authority cannot create an x86 readable mapping |
| Kernel isolation | Actual B reads/writes fault on the supervisor kernel header, protected policy and page-table pages; each complete page stays unchanged |
| Data NX | A successful CPL3 data load proves the present page is user accessible; instruction fetch faults with NX enabled |
| Recursive revocation | A revokes B and D descendants; fresh CPL3 map requests are rejected, existing translations are removed/invalidate/quiesced, and subsequent B/D reads and writes fault before backing release |
| Writable reuse | An actually exercised writable B translation is retired before its exact frame is erased, initialized and reassigned to C; stale B reads/writes fault and C's complete payload stays unchanged |
| Stale identities | Capability and lease slots advance generations; stale release/backend-fence requests fail atomically while a current-generation request and actual B read still succeed |

Every fresh boot also challenges the privilege transition with dirty kernel
registers and legacy floating-point data. A compiled CPL3 snapshot observes zeroed
unused general registers and reset x87/MMX/SSE data, with only declared probe
inputs retained. The kernel verifies its original floating-point state after
return. Active OSXSAVE, protection keys, CET, SGX, PCID and global translations are
outside this profile; extended-state and multicore context switching need their
own implementation and evidence.

Controlled requests use a fixed, authorized NX request page. The trap derives the
caller from protected context, actual CR3 and the saved privilege frame; submitted
caller/domain and lease bits never become trusted internal identities. These
fixed probes do not accept or execute arbitrary service programs. Trusted backend
completion/stale-lease checks are labelled separately from actual CPL3 dispatch.

## Build, run and independently verify

Use the pinned tools from [the first-kernel setup](first-kernel.md). Run from a
clean committed checkout; choose fresh output directories for every attempt:

```sh
python3 tools/check_k02_native_host.py --out build/k02-matrix-host
python3 tools/build_k02_matrix.py --out build/k02-matrix-a
python3 tools/build_k02_matrix.py --out build/k02-matrix-b
for case in caller_forgery trusted_operation_forgery unauthorized_read read_only_sharing exact_bounds kernel_isolation data_nx recursive_revocation writable_reuse stale_identities; do
  python3 tools/run_k02_matrix.py --manifest build/k02-matrix-a/manifest.json \
    --case "$case" --out "build/k02-matrix-$case"
done
python3 tools/verify_k02_matrix.py \
  --first build/k02-matrix-a/manifest.json \
  --second build/k02-matrix-b/manifest.json \
  --result build/k02-matrix-caller_forgery/result.json \
  --result build/k02-matrix-trusted_operation_forgery/result.json \
  --result build/k02-matrix-unauthorized_read/result.json \
  --result build/k02-matrix-read_only_sharing/result.json \
  --result build/k02-matrix-exact_bounds/result.json \
  --result build/k02-matrix-kernel_isolation/result.json \
  --result build/k02-matrix-data_nx/result.json \
  --result build/k02-matrix-recursive_revocation/result.json \
  --result build/k02-matrix-writable_reuse/result.json \
  --result build/k02-matrix-stale_identities/result.json \
  --out build/k02-matrix-verification.json
```

The builder compiles bounded, retained source snapshots, with exact dependency,
compiler/sysroot and notice bindings. COFF symbols and the original linked EFI
bind every instruction, the immutable request recipes and per-case contract.
The two independently built manifests and all artifacts must match byte for byte.

Each runner uses fresh firmware variables and a private temporary directory,
no network, a 45-second default deadline (at most 60 seconds), a combined 1 MiB
log bound and the exact QEMU exit status. Failed/timeout observations remain
failed, with available raw output and execution receipts retained. `--capture-only`
is diagnostic capture and cannot pass matrix acceptance; a `--case` build subset
also cannot establish the complete matrix.

The separate verifier reparses original serial and hardware exception records,
checks exact caller/handle/lease generations, page permissions, fault origins,
whole-page digests and teardown order, and requires all ten fresh boot contexts.
It rejects unknown/duplicate/reordered records, stale evaluators, tampered artifacts
or raw logs, missing cases and nonzero final accounting. Full acceptance binds the
clean source revision and dependency hashes to local Git and the checked current
host toolchain. Reproduce on the corresponding pinned host to verify a foreign-host
capture; an arbitrary retained setup record is insufficient authority.

The loaded kernel-header digest predicts the UEFI loader's exact ImageBase update
from the retained EFI header and observed load address. Every other retained header
byte and the zero padding must match; equal before/after hashes alone are insufficient.

## Evidence and limits

The dedicated [K02 workflow](../.github/workflows/k02-native.yml) preserves the
four-probe regression alongside the complete matrix, host policy/mapper/adapter/
SHA-256 checks, twin artifacts and original bounded observations. Uploads use an
explicit file list and contain required redistribution notices.

A passing report establishes only the declared single-CPU emulated matrix. It does
not close physical platform selection, general native service dispatch, adversarial
arbitrary-program isolation, device quiescence, SMP translation shootdowns,
qualified scheduling/clocks, GPU execution or inference-performance gates.
Historical evidence retains its original source revision and scope.
