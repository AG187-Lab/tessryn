# G03 observed tooling results

These are fixture/tooling results from clean implementation commit
`e5cd6ca9a6a5b89a3fc86b284cbd68f43099b68e`, recorded October 11, 2026 on a
macOS arm64 development host. Both manifests report `dirty: false` and source
snapshot `007f57296c8010336ada80605b5f4fba45ce9c0baa3391ddf035b62d4b0ec3f8`.
This evidence-only commit is subsequent to the implementation it records.

Tessryn kernel boot, native GPU execution and inference are unavailable.
Performance sample count is zero. No thermal or native device measurement was
performed. Fixture wall time in the result records is harness metadata.

| Check | Observed result | Raw evidence |
| --- | --- | --- |
| Fresh builds | Two identical complete manifests and three identical artifacts | [manifest A](manifest-a.json), [manifest B](manifest-b.json) |
| QEMU pass ROM | Marker captured; emulator exit 33; harness exit 0 | [result](pass/result.json), [stdout](pass/stdout.log), [stderr](pass/stderr.log) |
| QEMU hang ROM | Deadline 0.5 seconds; explicit timeout; harness exit 124 | [result](timeout/result.json), [stdout](timeout/stdout.log), [stderr](timeout/stderr.log) |
| Missing emulator | Explicit unavailable; harness exit 2 | [result](unavailable/result.json) |
| Changed ROM byte | Artifact integrity rejected before launch; harness exit 1 | [result](rejected/result.json) |
| Unit tests | 65 tests, zero failures | [test log](tests.log) |
| Design validation | 33 Markdown documents, 10 milestones, 49 acyclic work items | [validation log](design.log) |
| Debugger input | LLDB located fixture_entry at 0x100000 and source line 9; probe never executed | [path-redacted debugger log](debugger-redacted.log) |

The pass fixture's stderr was empty. Timeout, rejection and unavailable results
are retained. The debugger log replaces only the absolute host artifact path
with its repository-relative path and omits the final blank display line; the original debugger log remains local.
Emulator logs and result records are unmodified.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `pass.rom` | 65,536 | `7be290c0ac1d6607312077e46736e3b38fc72e4e05ffd1821f14f63667417712` |
| `hang.rom` | 65,536 | `a9ac52ad42d333fa367d082f94ab7720389c49dd2bfc94f45e8ece6dcc007c7e` |
| `rust-probe.elf` | 8,112 | `59ded6303908ea2d1c0328184b5b919bde695d3439ff57b53dd44c8d98f9c8a2` |

The manifests contain actual binary hashes and versions: upstream Rust 1.96.0,
bundled LLD 22.1.2, QEMU 11.1.2 and Python 3.14.6. They also record checksum-pinned
build dependencies, upstream licenses/notices, extraction omissions and ambient
host compiler/library versions. External QEMU binaries are not proven bit-identical
across hosts; the original fixture artifacts are the reproduced build outputs.

## Reproduce the implementation evidence

Use a separate checkout at the recorded commit and the setup prerequisites in
the [workflow](../../design/build-and-evaluation.md). The archived manifest paths
contain no committed binary artifacts; regenerate their inputs with the builder.

```sh
git clone https://github.com/AG187-Lab/tessryn.git tessryn-g03-reproduction
cd tessryn-g03-reproduction
git checkout e5cd6ca9a6a5b89a3fc86b284cbd68f43099b68e
python3 tools/setup_toolchain.py --jobs 4
python3 tools/build_fixture.py --out build/final-a
python3 tools/build_fixture.py --out build/final-b
python3 tools/run_emulator.py --manifest build/final-a/manifest.json --qemu build/toolchain/bin/qemu-system-x86_64 --out build/final-pass
set +e
python3 tools/run_emulator.py --manifest build/final-a/manifest.json --qemu build/toolchain/bin/qemu-system-x86_64 --fixture hang --timeout 0.5 --out build/final-timeout
code=$?
set -e
test "$code" -eq 124
python3 tools/verify_fixture.py --first build/final-a/manifest.json --second build/final-b/manifest.json --result build/final-pass/result.json --result build/final-timeout/result.json
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
lldb --batch -o 'target create build/final-a/rust-probe.elf' -o 'image lookup -v -a 0x100000'
```

To reproduce the unavailable case, select `--qemu missing-g03-emulator` with a new
output directory (exit 2). To reproduce rejection, copy a generated artifact
directory, flip one byte of `pass.rom` without updating its manifest, and run that
manifest with a new result directory (exit 1). Unit tests additionally exercise
bad exit/marker, malformed inputs, log overflow, version mismatch, cancellation
and descendants retaining pipes. The synthetic tests are identified in their
source and do not constitute native execution or performance evidence.

## Acceptance coverage and future qualification

G03's tool versions/hashes/source provenance/commands, bounded emulator harness,
distinct evidence formats, numerical-reference/held-out/preregistration
methodology and explicit unavailable-capability reporting are implemented.
Independent reviews found and verified fixes for cancellation ownership, input
snapshot integrity, safe archive extraction, relative tool resolution and
retained-result classification.

Native kernel/service/device artifact reproductions, actual kernel boot,
GPU/inference execution, real numerical/held-out measurements and physical thermal
performance evidence are unavailable future qualifications, not G03 tooling
blockers. Those implementations do not exist and no fixture substitutes for their
evidence. The final Rust/C ABI decision remains Proposed pending G02; hostile
candidate sandbox/promotion/recovery qualification remains RSI01. Linux CI is a
separate observed result on the PR, not claimed by these macOS records.

These records describe the original implementation at the commit above. Review
fixes and their subsequent clean reproduction are recorded separately; verify
each bundle with the evaluator revision it identifies.
