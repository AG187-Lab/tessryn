# K01 high-address boot and AWS preparation results

Observed October 11, 2026 on a macOS arm64 development host, from clean
implementation commit `5ea06b998fcc854851e794aea6235b15fa34be65`. All six build
manifests report `dirty: false` and source snapshot
`7c53829d4ef7d52c14ef5633b8e3d8e8c838e51b4578a12333f25eddf23399d6`.
This evidence addition follows the implementation it records. The earlier
[K01 results](../k01-verification/README.md) retain their original dated scope.

Native Tessryn EC2 boot and recovery remain unqualified. These results establish
original-kernel execution and independent reset under QEMU, and deterministic
inputs for a future approved AWS experiment. No AWS resources, account access
or permission changes were performed by these tools. Native GPU, networking,
storage drivers and inference remain unavailable.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Baseline | Two identical manifests and 16 EFI/media artifacts; all seven boot/trap/fault/panic/reset/ISO cases pass | [verification](baseline/verification.json), [manifest A](baseline/manifest-a.json), [manifest B](baseline/manifest-b.json) |
| High addresses | Two identical manifests and 18 EFI/media artifacts; all nine image/handoff/control variants pass | [verification and actual addresses](high/verification.json), [manifest A](high/manifest-a.json), [manifest B](high/manifest-b.json) |
| Headless AWS media | Two identical manifests and 12 EFI/disk artifacts; all six serial cases pass | [verification](headless/verification.json), [manifest A](headless/manifest-a.json), [manifest B](headless/manifest-b.json) |
| Independent reset | Two fresh complete normal transcripts, separated by acknowledged QMP pause, external reset and resume | [result and phase boundaries](headless/normal/result.json), [serial](headless/normal/stdout.log), [raw QMP](headless/normal/qmp.jsonl) |
| Deployment display | Framebuffer-only deployment ISO visibly reaches owned memory and PASS | [screenshot](display/screenshot.png), [capture metadata](display/result.json), [manual inspection](display/inspection.json) |
| Tests | 224 tests pass, including paging/media/protocol negative cases | [log](tests.log) |
| Design | 47 Markdown documents, 10 milestones and 49 acyclic work items validated before this evidence addition | [log](design.log) |

Every execution directory retains its unmodified result, serial/debug output and
emulator stderr. Headless cases also retain raw QMP exchanges. Results bind
commands, limits, firmware/emulator/evaluator hashes, inputs and raw log hashes.
Elapsed times describe bounded harness execution, not performance measurements.
Local Git attributes preserve byte-exact logs, JSON, register data and notices;
firmware CRLF and emulator whitespace are part of the retained raw evidence.

## Address and recovery observations

The high-image variants actually execute the EFI image at `0x140000000` (5 GiB).
The forced handoff variants use a real firmware-allocated high stack beginning
at `0x13ffe0000`, memory-map buffer at `0x13ffd0000` and owned scratch page at
`0x13ffcf000`, with post-handoff readback. The page-fault cases use the canonical
unmapped guard `0x7fffffe00000`; returning INT3 and firmware reset also pass at
the high placements. The RAM-only control boots the low preferred image base.

OVMF runtime descriptors and GOP are below 4 GiB in these actual runs. Synthetic
high runtime/GOP and wider paging fixtures remain separate test coverage. The
kernel's free conventional-memory accounting remains limited to low memory;
mapping live high addresses does not claim ownership of all high RAM.

The headless profile has no VGA, network or emulator debug/exit ports. Firmware
loads a 1 GiB GPT/FAT32 disk through emulated NVMe; the original kernel reports
through bounded COM1 and halts at terminal markers. Normal's second boot requires
fresh serial evidence after the witnessed external reset. This proves QEMU
control, not EC2 control-plane recovery or a usable recovery OS.

## Exact media identity

| Input | SHA-256 |
| --- | --- |
| Baseline manifest | `2d936e3659245780841919b6a17e876c06df4124aadda08ee7b53412ff4acce1` |
| High-address manifest | `18d92d677b31a63647da4ab620e658aa1a0bd9f4aedac1a4bc84d36a8c59f89f` |
| AWS preparation manifest | `5cc73ac570ea11f70c52d7497a150633030fe75f706c8b14f36f1659e4859e36` |
| AWS normal EFI | `a272b3186db19670ae320e85b60cced9f94acf84bcda894c8c033401076daba3` |
| AWS normal 1 GiB logical disk | `78478aebdf6ee303cd100bd811b5dd60fda5e282f03fca0ededda23a16127653` |

Each headless case retains its hash-bound `snapshot-inputs.json`. These are EBS
direct-upload input plans, not uploaded snapshots or registered AMIs. All logical
zero holes and the final backup GPT participate in whole-disk verification.
The complete verified block iterator must finish before any future snapshot
completion. A fresh attempt-scoped idempotency token belongs to the cloud owner.

## Reproduce and inspect

Use a separate clean checkout at the recorded implementation commit and the
pinned setup in [the first-kernel guide](../../design/first-kernel.md). Build
outputs and all firmware are omitted from this Git bundle. Regenerate the media
and notices before running the verifiers; the retained results alone cannot
replace those checks.

```sh
git clone https://github.com/AG187-Lab/tessryn.git tessryn-k01-aws-reproduction
cd tessryn-k01-aws-reproduction
git checkout 5ea06b998fcc854851e794aea6235b15fa34be65
python3 tools/setup_toolchain.py --jobs 4
python3 tools/setup_uefi.py
python3 tools/build_kernel.py --out build/aws-ready-kernel-a
python3 tools/build_kernel.py --out build/aws-ready-kernel-b
for case in normal int3 invalid_opcode page_fault panic reboot; do
  python3 tools/run_kernel.py --manifest build/aws-ready-kernel-a/manifest.json --case "$case" --out "build/aws-ready-baseline/$case"
done
python3 tools/run_kernel.py --manifest build/aws-ready-kernel-a/manifest.json --media iso --out build/aws-ready-baseline/iso
python3 tools/check_kernel_display.py --manifest build/aws-ready-kernel-a/manifest.json --out build/aws-ready-display
python3 tools/verify_kernel.py --first build/aws-ready-kernel-a/manifest.json --second build/aws-ready-kernel-b/manifest.json \
  --result build/aws-ready-baseline/normal/result.json --result build/aws-ready-baseline/int3/result.json \
  --result build/aws-ready-baseline/invalid_opcode/result.json --result build/aws-ready-baseline/page_fault/result.json \
  --result build/aws-ready-baseline/panic/result.json --result build/aws-ready-baseline/reboot/result.json \
  --result build/aws-ready-baseline/iso/result.json --out build/aws-ready-kernel-verification.json
python3 tools/build_kernel.py --high --out build/aws-ready-high-a
python3 tools/build_kernel.py --high --out build/aws-ready-high-b
for variant in image-normal image-int3 image-page_fault image-reboot handoff-normal handoff-int3 handoff-page_fault handoff-reboot ram-only; do
  python3 tools/run_kernel_high.py --manifest build/aws-ready-high-a/manifest.json --variant "$variant" --out "build/aws-ready-high-2/$variant"
done
python3 tools/verify_kernel_high.py --first build/aws-ready-high-a/manifest.json --second build/aws-ready-high-b/manifest.json \
  --result build/aws-ready-high-2/image-normal/result.json --result build/aws-ready-high-2/image-int3/result.json \
  --result build/aws-ready-high-2/image-page_fault/result.json --result build/aws-ready-high-2/image-reboot/result.json \
  --result build/aws-ready-high-2/handoff-normal/result.json --result build/aws-ready-high-2/handoff-int3/result.json \
  --result build/aws-ready-high-2/handoff-page_fault/result.json --result build/aws-ready-high-2/handoff-reboot/result.json \
  --result build/aws-ready-high-2/ram-only/result.json --out build/aws-ready-high-verification.json
python3 tools/build_aws_boot.py --out build/aws-ready-media-a
python3 tools/build_aws_boot.py --out build/aws-ready-media-b
for case in normal int3 invalid_opcode page_fault panic reboot; do
  python3 tools/run_aws_boot.py --manifest build/aws-ready-media-a/manifest.json --case "$case" --out "build/aws-ready-headless/$case"
done
python3 tools/verify_aws_boot.py --first build/aws-ready-media-a/manifest.json --second build/aws-ready-media-b/manifest.json \
  --result build/aws-ready-headless/normal/result.json --result build/aws-ready-headless/int3/result.json \
  --result build/aws-ready-headless/invalid_opcode/result.json --result build/aws-ready-headless/page_fault/result.json \
  --result build/aws-ready-headless/panic/result.json --result build/aws-ready-headless/reboot/result.json \
  --out build/aws-ready-verification.json
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
```

All output paths must be new. The original failed high-run attempt is preserved
in ignored `build/aws-ready-high`: the restricted host sandbox denied QEMU shared
memory before guest execution. The successful complete rerun used the distinct
`aws-ready-high-2` directory with local QEMU IPC permitted.

The display tool reports `captured`; the primary agent separately inspected the
full-resolution lossless PNG. The 4 MiB raw framebuffer and 3 MiB PPM remain in
ignored `build/aws-ready-display`, with hashes retained in the capture metadata.
Register bytes, QMP exchanges, logs, PNG and inspection are included here. A
[file inventory](inventory.json) binds this compact bundle's retained bytes.

The [native AWS contract](../../design/aws-boot-and-recovery.md) defines exact
boot-mode checks, fresh serial evidence, independent known-good recovery and
cleanup. The separate AWS operations session owns provisioning, permissions,
spending and cleanup; its current Ubuntu-hosted emulator approval does not
authorize a native AMI launch. Native resource approval is pending.
