# Resumable region-service execution evidence

Observed October 15, 2026 with the pinned `aarch64-apple-darwin` host toolchain.
Executed clean implementation: `bf9c82528f83e25814334c696a02aff86120fa21`; git-worktree-v2 snapshot SHA-256
`3bf0016316e5aafac1527eb854de169a3370a956f17cda2ccab5be222dadf592`. The later documentation/evidence commit has a different tree identity.

[The service contract](../../design/k02-region-service.md) and
[ADR 0018](../../design/decisions/0018-resumable-region-service.md) define the
bounded original-kernel, single-CPU experiment. [The report](verification.json)
has SHA-256 `ac0a72dcb4ebdf4fed6e566180e23855795a7edaeaa7276af3ab5d4cedfdcbf9`.

## Observed acceptance

| Original guest case | Submitted requests | Actual CPL3 traps | Service records | Context switches |
| --- | --- | --- | --- | --- |
| sharing | 14 | 15 | 105 | 4 |
| revocation | 14 | 15 | 104 | 4 |
| authority | 38 | 38 | 209 | 4 |

The three fresh boots total 66 requests and 68 actual traps. Each starts two
separately bound image programs with sanitized registers/legacy FP, preserves
per-task state across replies/yields, and ends with both domains' leaves and
charged/committed/reserved pages, retained mappings and allocations all zero.
The exact compiled continuations, original raw exception frames, submitted
96-byte requests and replies, full-page digests and ordered lease retirements
agree. Sharing observes B's successful actual read and declared read-only write
fault; revocation observes a stale access fault after both translations retire;
authority observes denials, continued user execution and actual zeroed-page reuse.

Two independent complete service builds match all 10 artifacts, all 22 compiler
dependencies and 27 reviewed runtime/lock files, retaining 49 inputs per twin.
[The original host receipt](host/result.json) binds 21 pure-service policy tests,
compiler/test commands and all six original stream logs. Those host tests do not
establish CPU/TLB enforcement. [All 658 Python tests pass](python-tests.log),
without skips; [executed design validation](design.log) covers 78 documents.

Fresh same-source regressions passed: 97 original ownership/mapper/adapter/digest
host tests, ten matrix boots with 52 actual traps, four original slice boots,
and seven K01 normal/INT3/invalid-opcode/page-fault/panic/reset/ISO boots. Their
independent reports and source manifests are retained under `regressions/`.
The guest benchmark regression observes 13 cases and 208 raw-counter samples;
its retained result keeps native qualification false and all original clock and
measurement limitations. No latency, CPU-cycle or inference speedup is claimed.

An initial sandboxed K01 launcher failed before guest execution because temporary
file creation was denied. Its original failed logs remain private locally. Seven
fresh boots with approved local execution and the same clean kernel twins passed;
the failed attempt is never relabelled as a passed guest. The approved complete
unit-test log is retained here. Earlier diagnostic captures and the failed initial
unit/environment attempt are also excluded from acceptance evidence.

## Packet and claim boundary

`index.json` hashes every other retained file, including this README. Original
copied JSON, successful logs and notices are byte-preserved; `summary.json` and
`commands.json` are derived navigation records. Their repository-relative origin
paths identify ignored local outputs; they are not a claim that omitted files are
present here. One OVMF NOTICE is retained under `notices/`; its bytes match all
three original firmware notices. Original service compiler notices remain beside
their manifests. No executable, object, library, disk/ISO, firmware binary or
retained source duplication is included.

[The CI workflow](../../.github/workflows/k02-region-service.yml) retains its own
complete successful 175-file packet, including binaries, media, firmware and both
source snapshots. The local audit records all 175 paths and 241074113 bytes;
Linux CI must retain its own source/host/capture identities. This text packet
alone cannot replay full artifact verification without those original outputs
or fresh rebuilding. Full verification requires the executed source commit to
be HEAD or an ancestor and matching reviewed evaluator/lock bytes plus checked
current-host tools; a self-asserted foreign-host setup is insufficient.

Offline records do not independently authenticate capture. Qualification remains
bounded to this image-bound single-CPU emulated service. Arbitrary-program or
architectural-state isolation, a production native ABI, timer preemption,
multicore scheduling, physical hardware, DMA/devices, GPU/model execution and
inference performance remain unqualified. K02 issue #5 stays open. Parser unit
fixtures test evidence rejection and do not replace these original guest captures.

## Reproduce the executed source

Use a fresh checkout and empty output directories. Fetch the original published
implementation object before selecting its exact source; after a squash merge,
the original PR/branch history must remain available for this historical check.
The commands below create fresh evidence with its own timestamps and hashes.
Preserve all original notices with complete packets.

```sh
git fetch origin bf9c82528f83e25814334c696a02aff86120fa21
git switch --detach bf9c82528f83e25814334c696a02aff86120fa21
python3 tools/setup_toolchain.py --jobs 4
python3 tools/setup_k02_toolchain.py
python3 tools/setup_uefi.py
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
python3 tools/check_k02_native_host.py --out build/region-reg-native-host
python3 tools/check_k02_region_host.py --out build/k02-region-service/host
python3 tools/build_k02_region_service.py --out build/k02-region-service/a
python3 tools/build_k02_region_service.py --out build/k02-region-service/b
for case in sharing revocation authority; do
  python3 tools/run_k02_region_service.py --manifest build/k02-region-service/a/manifest.json --case "$case" --out "build/k02-region-service/$case" --allow-qemu
done
python3 tools/verify_k02_region_service.py --first build/k02-region-service/a/manifest.json --second build/k02-region-service/b/manifest.json \
  --host-result build/k02-region-service/host/result.json \
  --result build/k02-region-service/sharing/result.json --result build/k02-region-service/revocation/result.json \
  --result build/k02-region-service/authority/result.json --out build/k02-region-service/verification.json

python3 tools/build_k02_matrix.py --out build/region-reg-matrix-a
python3 tools/build_k02_matrix.py --out build/region-reg-matrix-b
for case in caller_forgery trusted_operation_forgery unauthorized_read read_only_sharing exact_bounds kernel_isolation data_nx recursive_revocation writable_reuse stale_identities; do
  python3 tools/run_k02_matrix.py --manifest build/region-reg-matrix-a/manifest.json --case "$case" --out "build/region-reg-matrix-$case"
done
python3 tools/verify_k02_matrix.py --first build/region-reg-matrix-a/manifest.json --second build/region-reg-matrix-b/manifest.json \
  --result build/region-reg-matrix-caller_forgery/result.json --result build/region-reg-matrix-trusted_operation_forgery/result.json \
  --result build/region-reg-matrix-unauthorized_read/result.json --result build/region-reg-matrix-read_only_sharing/result.json \
  --result build/region-reg-matrix-exact_bounds/result.json --result build/region-reg-matrix-kernel_isolation/result.json \
  --result build/region-reg-matrix-data_nx/result.json --result build/region-reg-matrix-recursive_revocation/result.json \
  --result build/region-reg-matrix-writable_reuse/result.json --result build/region-reg-matrix-stale_identities/result.json \
  --out build/region-reg-matrix-verification.json

python3 tools/build_k02_native.py --out build/region-reg-slice-a
python3 tools/build_k02_native.py --out build/region-reg-slice-b
for case in own_page foreign_read kernel_read readonly_write; do
  python3 tools/run_k02_native.py --manifest build/region-reg-slice-a/manifest.json --case "$case" --out "build/region-reg-slice-$case"
done
python3 tools/verify_k02_native.py --first build/region-reg-slice-a/manifest.json --second build/region-reg-slice-b/manifest.json \
  --result build/region-reg-slice-own_page/result.json --result build/region-reg-slice-foreign_read/result.json \
  --result build/region-reg-slice-kernel_read/result.json --result build/region-reg-slice-readonly_write/result.json \
  --out build/region-reg-slice-verification.json

python3 tools/build_kernel.py --out build/region-reg-k01-a
python3 tools/build_kernel.py --out build/region-reg-k01-b
for case in normal int3 invalid_opcode page_fault panic reboot; do
  python3 tools/run_kernel.py --manifest build/region-reg-k01-a/manifest.json --case "$case" --out "build/region-reg-k01-retry-$case"
done
python3 tools/run_kernel.py --manifest build/region-reg-k01-a/manifest.json --case normal --media iso --out build/region-reg-k01-retry-iso
python3 tools/verify_kernel.py --first build/region-reg-k01-a/manifest.json --second build/region-reg-k01-b/manifest.json \
  --result build/region-reg-k01-retry-normal/result.json --result build/region-reg-k01-retry-int3/result.json \
  --result build/region-reg-k01-retry-invalid_opcode/result.json --result build/region-reg-k01-retry-page_fault/result.json \
  --result build/region-reg-k01-retry-panic/result.json --result build/region-reg-k01-retry-reboot/result.json \
  --result build/region-reg-k01-retry-iso/result.json --out build/region-reg-k01-retry-verification.json

mkdir -p build/native-inputs
git show bf9c82528f83e25814334c696a02aff86120fa21:scheduler-core/lib.rs > build/native-inputs/scheduler-core.rs
python3 tools/build_native_kernel_benchmarks.py --out build/region-reg-benchmark-image --scheduler-source build/native-inputs/scheduler-core.rs
python3 tools/run_native_kernel_benchmarks.py --manifest build/region-reg-benchmark-image/manifest.json --out build/region-reg-benchmark-run --allow-qemu
python3 tools/verify_native_kernel_benchmarks.py build/region-reg-benchmark-run
```
