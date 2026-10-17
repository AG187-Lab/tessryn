# Single-CPU timer and CPU-budget execution evidence

Observed October 16, 2026 with the pinned `aarch64-apple-darwin` host toolchain.
Executed clean implementation: `a2ed4cc20d148d7d9337ed815cb8d517f0dbd29d`; git-worktree-v2 snapshot
SHA-256 `a33697fe6286124440bc1967db6b1abb5381e451e1fc11555dad006437cb2da3`. Later evidence/documentation commits have different tree identities.

[The contract](../../design/k03-timer-preemption.md) and
[ADR 0019](../../design/decisions/0019-single-cpu-timer-preemption.md) define this
bounded original-kernel experiment. [The independent report](verification.json)
has SHA-256 `367b3b10e9327c497584cf10d66b2dcdc66b5b438a8558e67ef400789fc0dbf5`.

## Observed original-kernel execution

| Case | INT80 requests | Actual CPL3 traps | Busy-loop timer IRQs A/B | A policy state |
| --- | --- | --- | --- | --- |
| preemption | 14 | 24 | 7/3 | completed |
| budget | 9 | 16 | 4/3 | failed |
| deadline | 9 | 15 | 3/3 | failed |
| forged_irq | 9 | 14 | 0/3 | failed |

The four fresh boots total 41 submitted requests,
69 actual traps and 27 authentic timer interrupts.
Both image-bound programs execute loops with no voluntary INT80 in those loops.
Protected roots, all 15 saved GPRs, legacy FP, original hardware frames, actual
continuation and full clock/accounting timelines agree. B completes after at
least three busy-loop timer stops in every case. Every boot ends with zero CPU
leases/reservations, mappings, allocations and charged/committed/reserved pages.

Budget A consumes 81,704,000 ns against its 80,000,000 ns lifetime cap.
Its actual late stop is **Failed with sticky domain halt**; consumption is never
clamped or reported as an exact Exhausted stop. Deadline A's admission-relative
absolute deadline is 110,346,000 ns; its actual stop sample is
111,412,000 ns. That stop also records Failed and sticky domain halt, retaining
strict late-stop precedence over DeadlineExpired. Exact-cap Exhausted and inclusive
DeadlineExpired behavior are independently exercised by the unchanged policy and
adapter host tests. These timer observations establish correctness under the
reported emulator timing, without a physical interrupt-latency guarantee.

The first A syscall in `preemption` deliberately polls actual PIC pending state
with kernel IF0: the original record shows IRQ0 pending-before 1, pending-after 0
and ISR 0 before the next lease. The forged case waits for B's actual read witness,
then records #GP vector 13/error `0x102` at the bound CPL3 `INT 0x20`. A's additional
authentic IRQ in that case occurs outside its busy loop and is not counted as
busy-loop preemption proof.

All four accepted native captures have `missed_arms=0`. The no-entry ARM_MISSED
recovery path has actual driver host-model tests and a synthetic positive full
parser fixture; no native observation of that branch is claimed. Partial pre-MAP
FP interruption is likewise a synthetic prefix/context-rejection test. Parser
fixtures derived from earlier dirty diagnostics are unit tests, separate from
these newly preregistered clean captures.

## Build and regression checks

Independent complete twins match all 14 artifacts: original memory/scheduler
libraries plus four EFI/object/media triples. Each retains all 26 compiler inputs
and 28 reviewed runtime/lock/CI inputs, 54 files per twin. The original scheduler
source remains SHA-256
`db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d`.
[The host receipt](host/result.json) binds seven actual compile/test commands and
14 original streams: 42 original scheduler, 17 adapter and 31 driver/mapper tests.
The latter includes 14 imported mapper tests and 17 new driver/UC tests; suite
counts are not a count of unique assertions across overlapping regression suites.

[All 697 Python tests pass](python-tests.log), including 19 trace rejection tests.
[Executed design validation](design.log) covers 81 documents before this packet
README was added. Same-source fresh regressions pass: 97 native host tests,
four original slice boots, ten matrix boots with 52 raw traps, seven K01 boots
including ISO, and all independent twin verifiers. The unchanged cooperative
service passes its 21 host tests, ten-artifact twins and three fresh boots with
66 requests/68 traps. The guest benchmark passes its strict `-Dwarnings` build,
two clock tests, fresh 13-case/208-sample capture and independent 55-file verifier.
Its native qualification remains false. [Derived navigation](summary.json) and
[commands](commands.json) identify original outputs and their hashes.

The benchmark regression first caught unused timer helpers in an unrelated strict
build profile. Five conditional-compilation attributes fixed that regression;
all acceptance records here were freshly produced from the corrected clean
implementation. Failed earlier-source build diagnostics stay private and are
excluded from every accepted count. Independent in-session adversarial review
also found and fixed early-pending-source and coherent fatal-RIP parser gaps.

## Packet and reproduction limits

`index.json` hashes every other retained file, including this README. Copied
successful JSON/logs/notices are byte-preserved; summary/commands/index and the
local artifact inventory are derived navigation. Fourteen original legacy
slice/matrix result JSON files contain local launch paths and remain private,
without alteration. Their full verification reports, manifests, raw guest streams
and original-result hashes remain represented. The complete private outputs are
required for full historical replay. No executable, object, library, media,
firmware binary, failed log or duplicated retained source enters this text packet.
Original Rust/Tessryn notices remain beside both manifests; one OVMF NOTICE matches
all four captures.

The [workflow](../../.github/workflows/k03-timer.yml) selects exactly 216 successful
files including hidden workflow sources. [The local inventory](local-timer-audit.json)
checks all 216 paths and 325,508,254 bytes. Four extra local host-test
executables are outside that success upload inventory. Linux CI retains its own
complete binaries/media/firmware/source packet and source identity. This text
packet alone cannot substitute for those files or reexecute a foreign compiler.
Offline records do not authenticate capture origin.

For a fresh reproduction, fetch the original implementation object, select that
exact source and use new empty output directories. The branch containing the
implementation remains published after squash merge. Preserve every original
notice with complete evidence.

```sh
git fetch origin a2ed4cc20d148d7d9337ed815cb8d517f0dbd29d
git switch --detach a2ed4cc20d148d7d9337ed815cb8d517f0dbd29d
python3 tools/setup_toolchain.py --jobs 4
python3 tools/setup_k02_toolchain.py
python3 tools/setup_uefi.py
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
python3 tools/check_k03_timer_host.py --out build/k03-timer/host
python3 tools/build_k03_timer.py --out build/k03-timer/a
python3 tools/build_k03_timer.py --out build/k03-timer/b
for timer_case in preemption budget deadline forged_irq; do
  python3 tools/run_k03_timer.py --manifest build/k03-timer/a/manifest.json --case "$timer_case" --out "build/k03-timer/$timer_case" --allow-qemu
done
python3 tools/verify_k03_timer.py --first build/k03-timer/a/manifest.json --second build/k03-timer/b/manifest.json \
  --host-result build/k03-timer/host/result.json --result build/k03-timer/preemption/result.json \
  --result build/k03-timer/budget/result.json --result build/k03-timer/deadline/result.json \
  --result build/k03-timer/forged_irq/result.json --out build/k03-timer/verification.json
```

Full verification requires the executed commit to be HEAD or an ancestor, matching
reviewed runtime/lock bytes and checked current-host tools. Fresh runs have their
own timestamps, IRQ counts, observed strict stop states and hashes; they must
independently pass rather than copy these observations. The separate regression
commands are retained in `commands.json` and the unchanged CI workflows.

This qualifies only the declared single-CPU image-bound emulated execution.
Arbitrary program admission, general idle/wakeup, physical clocks, SMP/contended
accounting, DMA/devices, GPU/model execution and inference performance remain open.
K03 issue #6 stays open. The unchanged conservative scheduler is the correctness
reference; a registered qualified native performance comparison remains pending.
