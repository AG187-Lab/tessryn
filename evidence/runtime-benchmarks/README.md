# Runtime preemption and contention observations

Status: original-kernel QEMU execution and independent packet replay passed.
This text record describes implementation `a1ef56849d6c8a163de3d16a665445cdbf64ec9a`,
which integrates the merged two-CPU user-runtime baseline
`763a1d274de2ee61b07c22527160ba8ba8216f95` from PR #68. The contention image
explicitly excludes the user-SMP execution profile; its shared hooks are opt-in.

The accepted combined registration SHA-256 is
`4cfebed76892e6e265ff260c4897f31d40b31d849522b11c3fe7b52ec0566ae5`.
The registration precedes all twenty bounded stages and ten fresh guest captures.
The final verifier has a separate bounded process receipt. Its result remains
`hardware_qualified=false`, `inference_qualified=false` and
`capture_authentication=unverified_offline`.

## Observed work

Two independent complete timer packets each retain matching builds, ninety host
checks and all four original scenarios. Every raw frame, lease, context, clock,
accounting and teardown gate passed before latency extraction. Each repeat has:

| Scenario | Actual IRQ captures | Trusted stops | Missed arms |
| --- | ---: | ---: | ---: |
| Preemption | 10 | 24 | 0 |
| Budget | 8 | 17 | 0 |
| Deadline | 6 | 15 | 0 |
| Forged interrupt | 4 | 14 | 0 |

That is 56 actual IRQ captures and 140 trusted stops across eight fresh boots.
The forged software interrupt itself supplies no IRQ sample. Strict late tenant
failures remain visible in their original budget/deadline outcomes.

Each of two fresh contention boots retains six cases, 96 measured records and
24 raw warmups excluded from statistics. The cases are adjacent HPET reads,
local atomic updates, separate 64-byte regions, distinct counters in one 64-byte
region, shared atomic updates and ownership ping-pong. All generations, final
values, payload counts and checksums match the fixed profile. The measured
counter-read reference retains eleven zero-duration observations in repeat one
and ten in repeat two; no other measured case has a zero duration. These zeros
are not removed or converted into a throughput claim.

Both repeats use identical source, machine, clock and artifact identities within
their lane. Samples from separate boots and different scenarios remain separate.
Counter differences and integer nearest-rank statistics were also recomputed by
an independent standard-library audit, which matched all 81 distinct retained
source blobs to the implementation commit.

The original default SMP profile additionally passed 26 host checks, six matching
build artifacts and fresh rendezvous/missing-AP captures. Its source-bound
verification is retained under `default-smp/`. At the implementation checkpoint,
822 Python tests, including 67 new focused tests, passed; design validation
covered 90 documents, ten milestones and 49 acyclic work items.

## Endpoints and scope

Timer samples start at the comparator target and end at the first trusted IRQ
capture after CPL3 interruption. Capture-to-actual-stop intervals separately
include deferred attributable work and logging. Neither is a pure
interrupt-entry or context-switch cost. Contention samples use BSP-only HPET
endpoints and include phase coordination; ping-pong is a round trip and its
payload-store count excludes polling loads. Raw warmups remain available.

The admitted counter period converts ticks to QEMU virtual nanoseconds. These
observations establish original-kernel execution and reproducible instrumentation;
they do not qualify a physical clock, hardware/cache latency, SMP task-scheduler
performance, GPU behavior or inference speed. No overhead subtraction, sample
pooling, promotion decision or performance threshold is applied.

## Record boundary and reproduction

This directory is a portable text subset: original registrations, results,
transcripts and derived observations. `SHA256SUMS` binds its files. Complete
firmware, media, object/library artifacts, retained source closure and process
logs remain in the original local packet. Successful CI runs retain their own
complete artifact for their exact source revision. This text
subset cannot independently satisfy the full media/toolchain verifier. Full
replay requires the matching reviewed source and checked host toolchain; offline
consistency does not authenticate who executed a capture.

Use fresh output directories with the implementation's pinned tools:

```sh
python3 tools/run_runtime_benchmarks.py --out build/runtime-benchmarks/run-new --allow-qemu
python3 tools/verify_runtime_benchmarks.py build/runtime-benchmarks/run-new
```

See [the run guide](../../design/runtime-benchmarks.md) for setup, endpoint and
hardware qualification requirements. Baseline/candidate hardware comparisons
need preregistered interleaving, workload, resource/SLO limits and uncertainty.

The first aggregate attempt at `a79e7804b5dc57c234fd78812377bdc610537665`
was rejected at final inventory verification because successful host-test stages
left four undeclared intermediate binaries each. That attempt is preserved
privately, excluded from accepted summaries and recorded in `observations.json`.
The follow-up preregisters validated removal of exactly those compiler products;
logs, results and unknown files are retained, with unknown files rejecting success.
All ten accepted captures were collected anew on the integrated implementation.
