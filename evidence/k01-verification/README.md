# K01 observed kernel results

These results record clean implementation commit
`629bd101d2779351ffcafe698e12fbeaafde582f` on October 11, 2026, using a macOS arm64
development host. Both manifests report `dirty: false` and source snapshot
`44049cd9127bb5beebb58387d9734edab2f56f3d2911d2ed77e5d05a0169e99f`.
This evidence bundle follows the implementation it records.

The original kernel boots under the declared QEMU TCG q35/OVMF profile. Physical
GPU Mart boot, native GPU execution, networking, storage and inference remain
unqualified. No server was rented or modified. Emulator elapsed time is harness
metadata, not a performance measurement.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Independent builds | Two identical complete manifests and all 16 identical EFI/media artifacts | [manifest A](manifest-a.json), [manifest B](manifest-b.json), [verification](verification.json) |
| Normal disk boot | Firmware handoff, owned CPU tables, scratch memory and PASS; exit 33 | [result](normal/result.json), [stdout](normal/stdout.log), [stderr](normal/stderr.log) |
| Returning INT3 | Owned vector 3, preserved floating-point/SIMD state, recovery and PASS; exit 33 | [result](int3/result.json), [stdout](int3/stdout.log), [stderr](int3/stderr.log) |
| Invalid opcode | Expected vector 6 diagnostics; exit 33 | [result](invalid_opcode/result.json), [stdout](invalid_opcode/stdout.log), [stderr](invalid_opcode/stderr.log) |
| Page fault | Expected vector 14 with CR2; exit 33 | [result](page_fault/result.json), [stdout](page_fault/stdout.log), [stderr](page_fault/stderr.log) |
| Panic | Deliberate panic diagnostic; exit 33 | [result](panic/result.json), [stdout](panic/stdout.log), [stderr](panic/stderr.log) |
| Controlled reboot | Retained runtime reset, CPU-reset diagnostics, no triple fault; exit 0 | [result](reboot/result.json), [stdout](reboot/stdout.log), [stderr](reboot/stderr.log) |
| Virtual-CD boot | Original emulator ISO reaches PASS; exit 33 | [result](iso/result.json), [stdout](iso/stdout.log), [stderr](iso/stderr.log) |
| Deployment display | Physical image in QEMU visibly reaches owned memory and PASS | [screenshot](display/screenshot.png), [capture](display/result.json), [manual inspection](display/inspection.json) |
| Unit tests | 139 tests, zero failures | [test log](tests.log) |
| Design validation | 37 Markdown documents, 10 milestones, 49 acyclic work items before this evidence addition | [validation log](design.log) |

The deployment ISO is 33,601,536 bytes with SHA-256
`0a3205ad20c615786e641c91692981d394aa3352db6b3f1e59a0b80e09c012a9`.
The deployment EFI SHA-256 is
`122181dfc934bd5bf033ad872a75b19fc9dec08e2f107e0a582766ae7cfff792`.
The complete manifest SHA-256 is
`1d6a69ab4e7edd48b89961f4669e6af40a3a717ab590383b3ee5f1c16c3a30f6`.

The manifests bind upstream Rust 1.96.0, LLD 22.1.2, QEMU 11.1.2, firmware and
library bytes, compiler flags, source identity and redistribution notices.
Results bind the manifest, evaluator, tools, firmware, commands and raw logs.
The evaluator requires the complete ordered handoff and exact per-case markers;
the reboot case also rejects triple-fault resets. Emulator diagnostics use test
ports; the separately built deployment image uses only its GOP framebuffer.

## Reproduce and inspect

Use a separate checkout at the recorded implementation commit and the
[first-kernel workflow](../../design/first-kernel.md). Build outputs are omitted
from Git; regenerate both artifact directories and their notices before running
the verifier. The Linux CI workflow publishes the original EFI/media, notices,
manifests and its own complete raw execution/display bundle as
`k01-kernel-and-evidence`.

```sh
git clone https://github.com/AG187-Lab/tessryn.git tessryn-k01-reproduction
cd tessryn-k01-reproduction
git checkout 629bd101d2779351ffcafe698e12fbeaafde582f
python3 tools/setup_toolchain.py --jobs 4
python3 tools/setup_uefi.py
python3 tools/build_kernel.py --out build/kernel-release-a
python3 tools/build_kernel.py --out build/kernel-release-b
for case in normal int3 invalid_opcode page_fault panic reboot; do
  python3 tools/run_kernel.py --manifest build/kernel-release-a/manifest.json --case "$case" --out "build/release-$case"
done
python3 tools/run_kernel.py --manifest build/kernel-release-a/manifest.json --media iso --out build/release-iso
python3 tools/check_kernel_display.py --manifest build/kernel-release-a/manifest.json --out build/release-display
python3 tools/verify_kernel.py --first build/kernel-release-a/manifest.json --second build/kernel-release-b/manifest.json \
  --result build/release-normal/result.json --result build/release-int3/result.json \
  --result build/release-invalid_opcode/result.json --result build/release-page_fault/result.json \
  --result build/release-panic/result.json --result build/release-reboot/result.json \
  --result build/release-iso/result.json --out build/release-verification.json
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
```

The display tool reports `captured`, which requires a separate visual decision.
The primary agent inspected the full-resolution lossless PNG conversion and
recorded its visible markers in [inspection.json](display/inspection.json).
Raw display metadata, QMP exchanges, register bytes and emulator logs are retained
here. The 4 MiB framebuffer dump and 3 MiB original PPM remain in the ignored
local capture directory, and their hashes are preserved in the capture result.
The PNG has the same pixels as that PPM. They can be regenerated with the display
command above; this smaller checked-in bundle does not replace the complete raw
capture. [GPU Mart recovery instructions](../../design/first-kernel.md#gpu-mart-test-path)
describe the next experiment on an authorized dedicated machine.
