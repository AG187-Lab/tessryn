# PR #51 review against G03

These are observed tooling results from clean review-fix commit
`cf6d0eac531c000b07ba2d9988fd3d309f7633c0`, recorded October 11, 2026 on a macOS
arm64 development host. Both manifests record `dirty: false`, snapshot algorithm
`git-worktree-v2`, and source snapshot
`66a747deeba4be0a5e67602ef3e0d8bc60fc57c984f5d3069ddebd3db05d43c8`.
The evidence commit follows the implementation it records. The earlier
[implementation evidence](../g03-verification/README.md) remains identified with
its original revision and evaluator.

## Acceptance review

| Issue #2 acceptance criterion | G03 tooling disposition and evidence |
| --- | --- |
| Record toolchain versions, artifact hashes, source provenance and emulator commands | Implemented. Fresh checksum-verified setup, binary/compiler-runtime/target-library identities, complete provenance validation and two identical [manifests](manifest-a.json) ([second](manifest-b.json)). |
| Emulator harness and distinct assumptions, implementation results and measurements | Implemented. Fixed emulator profile, bounded processes/logs, structured success/failure and retained-result verification; [evidence contract](../../design/evaluation-evidence.md). |
| Numerical references, held-outs and preregistered methodology with samples and thermal/load conditions | Defined and validated. Reference/history/workload identities, justified per-kind tolerances, independent custody, registered sample/run/load/thermal conditions and confidence level; required hashed trace/statistical/numerical/held-out report formats. Synthetic format tests establish consistency, with no real measurement claim. |
| No fabricated boot, GPU or performance evidence; explicit missing capabilities | Implemented. All four actual result bundles report native capabilities unavailable and zero performance samples. The Rust probe is inspected and never executed. |

Independent review found and fixed these G03 blockers:

- Extracted installers, build objects and dependency overlays could drift from
  their pinned archives; setup now starts fresh and binds the actual installed
  binaries and libraries. Builds reject stale/spoofed overrides and recheck the
  installation before publishing. Source snapshots include file types,
  executable modes and link destinations.
- Abbreviated manifests without provenance or the compiler probe could verify.
  Verification now requires all three original artifacts, pinned components,
  complete tool/source identities, actual ELF inspection and emulator identity.
- Passing measurements could contradict registered thermal conditions, invent
  request rates, drop completed latency samples or claim unavailable inference.
  Cross-field validation rejects those contradictions.
- Measurements could omit retained traces/statistics/numerical reports. The
  format now requires four hashed report payloads and checks their bindings,
  counts, registered conditions and summaries, including held-out aggregate
  evidence without exposing private workload content.
- Future native records were forced to claim a probed emulator. They may now
  identify a target runner with `emulator: null`; passing fixtures still require
  the observed emulator identity. No native runner is implemented.
- Deep JSON on Python 3.12 and process cleanup errors could bypass structured
  failures. Bounded reads/parsing and cleanup now retain explicit errors/logs,
  close pipes and restore host signal handlers.

No remaining G03 tooling blocker was identified after these fixes and checks.
Actual kernel/service/device artifacts, Tessryn boot, native C ABI/runtime,
GPU/model execution, genuine numerical/held-out observations and physical
thermal/performance qualification are **unavailable future capabilities**, not
G03 blockers. Fixtures provide no evidence for them. The whole-kernel language
decision remains Proposed pending G02; protected hostile-candidate sandbox,
enrollment, promotion/signing and recovery qualification remain RSI01.
PR #51 and issue #2 remain open; this review does not authorize merging.

## Actual results

| Check | Observed result | Raw evidence |
| --- | --- | --- |
| Fresh source setup | Rust 1.96.0, LLD 22.1.2, QEMU 11.1.2; bound archives, binaries and installed library inventories | [Manifest](manifest-a.json) |
| Two clean builds | Byte-identical complete manifests and all three original artifacts | [A](manifest-a.json), [B](manifest-b.json) |
| QEMU pass ROM | Marker in stdout, emulator exit 33, harness exit 0 | [Result](pass/result.json), [stdout](pass/stdout.log), [stderr](pass/stderr.log) |
| QEMU hang ROM | Explicit timeout at the 0.5-second deadline, harness exit 124 | [Result](timeout/result.json), [stdout](timeout/stdout.log), [stderr](timeout/stderr.log) |
| Missing emulator | Explicit unavailable, harness exit 2 | [Result](unavailable/result.json) |
| Changed ROM byte | Integrity rejection before launch, harness exit 1 | [Result](rejected/result.json) |
| Retained verification | Identical artifacts/manifests and all four result/log bundles verified | Reproduce with the command below |
| Unit tests, Python 3.14.6 | 98 tests, zero failures | [Log](tests-py314.log) |
| Unit tests, Python 3.12.7 | 98 tests, zero failures | [Log](tests-py312.log) |
| Design validation at implementation revision | 34 Markdown documents, 10 milestones, 49 acyclic work items | [Log](design.log) |

The original artifact hashes remain unchanged from the first implementation:
`pass.rom` and `hang.rom` are 65,536 bytes; `rust-probe.elf` is 8,112 bytes.
Manifest hashes, source identities and evaluator bindings reflect the review
fixes. No fixture duration is an inference latency, and no thermal/load
measurement was performed.

## Exact reproduction

Use the prerequisites in the [workflow](../../design/build-and-evaluation.md).
Run from a separate clean checkout at the recorded implementation revision;
these directories must be new. Regenerate artifact files because binary
artifacts are not committed.

```sh
git clone https://github.com/AG187-Lab/tessryn.git tessryn-g03-review
cd tessryn-g03-review
git checkout cf6d0eac531c000b07ba2d9988fd3d309f7633c0
python3 tools/setup_toolchain.py --jobs 4
python3 tools/build_fixture.py --out build/g03-review-final-a
python3 tools/build_fixture.py --out build/g03-review-final-b
python3 tools/run_emulator.py --manifest build/g03-review-final-a/manifest.json --qemu build/toolchain/bin/qemu-system-x86_64 --out build/g03-review-final-pass
set +e
python3 tools/run_emulator.py --manifest build/g03-review-final-a/manifest.json --qemu build/toolchain/bin/qemu-system-x86_64 --fixture hang --timeout 0.5 --out build/g03-review-final-timeout
code=$?
set -e
test "$code" -eq 124
set +e
python3 tools/run_emulator.py --manifest build/g03-review-final-a/manifest.json --qemu missing-g03-emulator --out build/g03-review-final-unavailable
code=$?
set -e
test "$code" -eq 2
python3 - <<'PY'
from pathlib import Path
import shutil
shutil.copytree('build/g03-review-final-a', 'build/g03-review-final-tampered')
rom = Path('build/g03-review-final-tampered/pass.rom')
data = bytearray(rom.read_bytes())
data[0] ^= 1
rom.write_bytes(data)
PY
set +e
python3 tools/run_emulator.py --manifest build/g03-review-final-tampered/manifest.json --qemu build/toolchain/bin/qemu-system-x86_64 --out build/g03-review-final-rejected
code=$?
set -e
test "$code" -eq 1
python3 tools/verify_fixture.py --first build/g03-review-final-a/manifest.json --second build/g03-review-final-b/manifest.json --result build/g03-review-final-pass/result.json --result build/g03-review-final-timeout/result.json --result build/g03-review-final-unavailable/result.json --result build/g03-review-final-rejected/result.json
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
```

For the observed minimum-minor-version check, also run
`python3.12 -m unittest discover -s tests -v`; the local interpreter was 3.12.7.
CI pins 3.12.13 for that compatibility job and 3.14.6 for full Linux fixture
reproduction. CI results are separate evidence linked from the PR.
