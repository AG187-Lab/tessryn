# K02 clean single-CPU matrix execution evidence

Observed October 14, 2026 on the pinned `aarch64-apple-darwin` host toolchain.
Clean executed implementation: `f27b3e7fa6b76918cc6f5ac8ec88579dd69174f0`;
worktree-v2 source SHA-256:
`c54e82c5c956dbb8fef4684ac9404e6f65f10d835578545d6d0b6049a2a8d677`.

The [matrix contract](../../design/k02-native-matrix.md) defines the bounded
profile and [PR #58](https://github.com/AG187-Lab/tessryn/pull/58) carries the
implementation. This packet contains byte-preserved text metadata, original raw
guest output, host/compiler logs, required notices and independent reports.
Executable/media/object/library artifacts remain in ignored build output; the
K02 CI workflow retains complete binary packets. The text packet alone cannot
replay artifact-byte verification without those outputs or rebuilding them.

## Verified results

- 578 Python tests passed with zero failures or skips; design validation passed
  across 73 documents.
- 97 original Rust host tests passed: 57 ownership, 14 mapper, 16 adapter and
  10 SHA-256 tests.
- Two independent complete matrix builds matched exactly: all 31 binary/media
  artifacts and their manifests. Ten fresh accepted QEMU boots produced 52
  actual CPL3 hardware traps, including per-boot register/legacy-FP snapshots.
- Two independent four-probe builds matched all 13 artifacts. Four fresh boots
  passed the strict original exception/frame verifier.
- Two independent K01 baseline builds matched all 16 artifacts. Seven fresh
  normal/INT3/invalid-opcode/page-fault/panic/reset/ISO runs passed.
- All three independent verifiers passed. A separate reviewer re-ran them over
  retained original binaries/logs and reproduced each report exactly.

The [summary](k02-reviewed-summary.json) and
[33-command index](k02-reviewed-command-index.json) identify actual completed
commands, exit codes, logs and hashes. They are derived navigation records;
original compiler/runner records and logs remain the observation basis.
The [full matrix report](k02-reviewed-matrix-verification.json) has SHA-256
`2bc16aca845d7d4ec9a951a522d7712b8d6aa5eaf63141a08abbac1d950f22b9`.
It independently binds local Git, all 21 compiler dependencies, 19 reviewed runtime
files and the checked current-host toolchain. The source identities remain those
of the executed clean implementation, not the later evidence-documentation commit.

## Reproduce the recorded source

Use a fresh clean checkout and the pinned host setup in the
[first-kernel guide](../../design/first-kernel.md). After a squash merge, fetch
the original PR history and explicitly check out the executed revision:

```sh
git fetch origin refs/pull/58/head:refs/remotes/origin/pr-58-evidence
git switch --detach f27b3e7fa6b76918cc6f5ac8ec88579dd69174f0
```

Fetching the object alone is insufficient: historical full verification requires
that revision to be HEAD or an ancestor of HEAD. Its compiler/evaluator/lock bytes
must match, and the recorded macOS host needs its checked pinned toolchain.
A current main checkout can instead build fresh evidence with its own source
identity. An archive's self-asserted foreign-host setup is not accepted as proof.

The [matrix guide](../../design/k02-native-matrix.md#build-run-and-independently-verify)
gives fresh-output commands; the command index records this run's exact
`build/k02-reviewed-*` output names. Use fresh names or a fresh checkout rather
than overwriting an existing record. Include all original notices when retaining
or redistributing complete binaries. Linux CI has its own execution/source/host
identities; its report must retain those identities.

## Review findings and claim boundary

The final run follows two independently verified fixes. First, pinned QEMU leaves
FOP bytes unwritten by FXSAVE; initializing both buffers prevents stale stack bytes
from being compared, while retaining checks on implementations that populate the
field. All four formerly failing slice cases then passed. Second, the old slice
parser now requires the single exact matching raw hardware frame and rejects extra
or reordered exceptions. Previous failing/diagnostic outputs remain preserved in
ignored local build directories and are not relabelled as passing evidence.

These results establish only the declared image-bound, single-CPU emulated test
matrix. General native service dispatch, arbitrary program isolation, physical
platforms, SMP, extended CPU state, DMA/device quiescence, GPU/model execution and
performance remain unqualified. K02 issue #5 remains open for those integration
limits. Synthetic unit fixtures validate rejection behavior; they do not replace
the original QEMU captures in this packet.
