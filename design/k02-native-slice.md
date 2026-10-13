# K02 single-CPU enforcement experiment

Status: tooling and kernel bring-up in progress. Execution evidence is required
before any implemented enforcement claim. This four-case experiment does not
complete the ten-case K02 protocol, physical qualification, SMP or DMA isolation.

The build compiles the existing `kernel-core/lib.rs` ownership policy as a fresh
`tessryn_owned_memory` rlib for `x86_64-unknown-uefi`, then links that library into
the original UEFI kernel. A library built for `x86_64-unknown-none` is not reused
or retargeted. The checked Rust/compiler/linker, target-library tree, firmware and
QEMU identities remain in each manifest.

Each case starts a fresh pinned QEMU q35/TCG instance with one CPU, 256 MiB RAM,
48 physical address bits, four-level paging and NX. PCID, global pages and LA57
are disabled. The kernel must report the admitted CPU and actual control state.
Firmware variables and boot media are disposable, with no host networking or
device passthrough.

| Case | Required observable result |
| --- | --- |
| `own_page` | CPL3 writes/reads its owned page and returns through the declared INT80 instruction |
| `foreign_read` | CPL3 faults at the declared unmapped foreign-page read, #PF error 4 |
| `kernel_read` | CPL3 faults at the declared supervisor-page read, #PF error 5 |
| `readonly_write` | CPL3 faults at the delegated read-only page write, #PF error 7 |

The user code page starts at `0x100000000`; its owned page, stack, foreign probe
and read-only page follow at offsets `0x1000`, `0x2000`, `0x3000` and `0x4000`.
The normalized exception frame must preserve CPL3 CS/SS and the expected user
stack. The privileged handler must use a dedicated, image-owned supervisor
stack. Protected sentinels and exact probe addresses are part of acceptance.

The foreign page belongs solely to domain A. It is a different allocation from
the page A deliberately delegates read-only to B. The privileged adapter checks
all four allocations were zeroed, retains the relevant operation or mapping
leases, and checks every word of the foreign, shared and B-owned pages after the
probe. Sharing retains A's ownership charge. Teardown fences each mapping,
removes its exact PTE, actually reloads its root and the kernel root, then records
trusted quiescence before releasing authority and backing.

The adapter publishes the existing owned-memory policy only after successful
firmware exit and K01 CPU ownership. It copies the final descriptor inventory
and reserves the complete image, stacks, descriptor allocation, scratch and
runtime/device ranges. Domain roots, policy state and the trap stack are
image-owned supervisor memory. Allocator authority never comes from K01's
diagnostic free-page count. See [the decision](decisions/0015-native-memory-slice.md).

The builder retains real compiler dependency hashes and each compiler COFF
object. Exported assembler labels bind probe offsets and instruction bytes;
the entire unchanged 4096-byte code page must occur uniquely in the linked EFI.
The verifier recomputes those bindings from both artifacts and requires twin
build manifests and bytes to match. Four case results require raw stdout/stderr
hashes, the exact emulator command, matching firmware and a successful bounded
emulator exit. A PASS marker alone cannot satisfy the verifier.

```sh
python3 tools/build_k02_native.py --out build/k02-a
python3 tools/build_k02_native.py --out build/k02-b
for case in own_page foreign_read kernel_read readonly_write; do
  python3 tools/run_k02_native.py --manifest build/k02-a/manifest.json \
    --case "$case" --out "build/k02-$case"
done
python3 tools/verify_k02_native.py --first build/k02-a/manifest.json \
  --second build/k02-b/manifest.json \
  --result build/k02-own_page/result.json \
  --result build/k02-foreign_read/result.json \
  --result build/k02-kernel_read/result.json \
  --result build/k02-readonly_write/result.json --out build/k02-verification.json
```

The focused Python fixtures are explicitly synthetic format and rejection
tests. They exercise malformed artifacts, incorrect faults and contradictory
traces; they cannot establish CPU execution. Only separately retained actual
emulator runs can supply this experiment's execution evidence.

This is a dependent integration branch based on reviewed K01 PR 53 and the K02
preparation merged from PR 57 at `dc984e34e29b561eba89ff7186bbb82276a225e8`.
K01 PR 53 remains open pending the owner's merge approval. The
kernel has a fixed, protected probe context and a narrow expected-fault return,
not a general authenticated service dispatcher or scheduler. Caller forgery,
NX instruction fetch, kernel writes, recursive revocation, stale identity and
writable-frame reuse execution remain in the full
[K02 protocol](k02-native-preparation.md). K02 stays open until that matrix and
its acceptance evidence are complete. AWS and GPU rental evidence is separate.
