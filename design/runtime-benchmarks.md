# Runtime preemption and cross-core benchmark experiments

Status: original-kernel QEMU execution and independent packet verification passed
on implementation `a1ef56849d6c8a163de3d16a665445cdbf64ec9a`, integrating the
merged PR #68 kernel baseline. The [accepted text evidence](../evidence/runtime-benchmarks/README.md)
records ten fresh captures. These experiments measure emulator behavior; physical
latency and inference performance remain unqualified.

## Ownership and objective

The kernel session owns isolated multicore CPL3 contexts and runtime correctness.
This experiment integrates the merged two-CPU user-runtime baseline
`763a1d274de2ee61b07c22527160ba8ba8216f95`. It uses the existing single-CPU
timer profile and separate opt-in contention hooks in the two-CPU kernel
bootstrap. Contention fixtures and user-SMP execution have mutually exclusive
configurations; the kernel session continues to own multicore task correctness.

The objective is to expose the costs that can delay decode work: a timer deadline
reaching a trusted stop, cache-line sharing, atomic updates and cross-core
handoffs. The simple references and full raw observations remain available when
later candidates change an implementation. An isolated microbenchmark improvement
is not an admitted inference request meeting its time-to-first-token or inter-token
SLO; the [inference performance contract](inference-performance.md) still governs
that comparison.

## Actual timer preemption

Each independent packet retains matching builds, host adapter tests and all four
original timer scenarios: preemption, budget, deadline and forged interrupt. The
complete existing timer verifier runs before benchmark extraction. Two packets
supply independent fresh captures; no successful scenario may replace a failed
attempt silently.

Samples come only from authenticated hardware IRQ events in the original trace.
Task, root, lease, generation and context pairing must agree with the full replay.
A pending IRQ canceled with interrupts masked, an attempted software interrupt,
a missed arm or a cooperative syscall supplies no preemption-latency sample.
The observed IRQ count is retained per scenario rather than forced to a desired
count by dropping or inventing events.

The first interval starts at the programmed HPET comparator target and ends at
the timer adapter's first trusted capture sample after the CPL3 interrupt. It
includes interrupt delivery, assembly context capture and the work preceding
that clock read. It is not a pure first-instruction interrupt-entry latency.
A second interval ends at the actual policy-stop accounting sample and includes
deferred attributable service/capture/logging work. The raw endpoints remain
visible so this broader interval cannot be presented as a context-switch cost.
The full existing budget, deadline, source, interruption/resume, memory teardown
and accounting gates remain required.

## Two-CPU contention

A separate `smp_benchmarks` image uses the admitted two-CPU topology, original
INIT/SIPI startup, private CPU stacks/tables, shared retained root and acknowledged
terminal AP stop. All memory remains retained. The existing rendezvous and missing
AP correctness profiles keep their own configuration and evidence formats.

Fixed workloads compare a local atomic reference, separate 64-byte-aligned
per-CPU counters, distinct counters sharing a 64-byte region, one shared atomic
counter, and a bounded ownership ping-pong. An adjacent clock-read reference
records timing-instrument cost without subtraction. A 64-byte layout is a
registered fixture geometry, not evidence of a physical cache-line size.

Each case has four excluded warmup rounds and 16 measured rounds. Work counts,
initial/final values, ordering and iteration limits are fixed before capture.
Only the BSP reads interval endpoints. Coordinated cases measure completion of
the entire bounded two-CPU phase, including release/acquire publication and
waiting for the peer's completion; their quantiles are distributions of batch
completion times, not individual atomic-operation tails. Ping-pong measures
round trips, not a one-way cross-core delay. No unsynchronized per-CPU timestamp
subtraction is allowed.

Every wait has a guest-time and finite-poll bound. Unexpected AP faults, clock
regression/stall, timeout, incorrect totals or missing/duplicate records reject
the attempt. The AP emits no serial output. Samples are buffered, and the BSP
publishes them only after the original AP stop is acknowledged and stable.

## Clock, statistics and evidence

The profiles use the checked QEMU q35 HPET period of 10,000,000 femtoseconds. Raw
HPET ticks remain primary; multiplication by 10 yields emulator virtual
nanoseconds. That conversion supplies neither a physical oscillator calibration
nor a latency guarantee. The single-CPU and multithreaded two-CPU QEMU profiles
are distinct populations. Neither is a cycle-accurate cache-coherence model.
QEMU's [multithreaded TCG design](https://www.qemu.org/docs/master/devel/multi-thread-tcg.html)
describes per-vCPU host threads and serialization around emulated MMIO; those
mechanisms affect these observations. Its [instruction-counting documentation](https://www.qemu.org/docs/master/devel/tcg-icount.html)
also distinguishes instruction counts from cycle-accurate execution. These
profiles do not enable instruction counting or infer physical coherence cost.

Retain raw samples, all warmups and all outcomes. Report descriptive nearest-rank
quantiles with sample counts and units; retain zeros and reject backward time.
Do not subtract measured instrument overhead, pool unrelated scenarios or use
QEMU timing thresholds to qualify a speedup. Repeated emulator runs check that
the capture and analysis path works; they supply no physical-performance
confidence interval.

Preregistration binds configuration, committed source, runtime helpers and build
inputs before capture. Every accepted packet retains original firmware/media,
raw process receipts, notices and full compiler/runtime closure. Verification
uses the reviewed checkout; retained packet Python is data and is never imported
as host code. A standalone offline replay establishes consistency, not independent
execution authentication. Successful CI artifacts use an explicit allowlist;
raw failed host messages remain private while fixed failure metadata and hashes
can be published.

## Run and next gate

The combined runner and verifier use the checksum-pinned compiler/emulator,
Python 3.12 or newer, clean committed source and a fresh output directory. Prepare
the tools in a fresh checkout with:

```sh
python3 tools/setup_toolchain.py --jobs 4
python3 tools/setup_k02_toolchain.py
python3 tools/setup_uefi.py
```

Capture and independently replay the complete experiment with:

```sh
python3 tools/run_runtime_benchmarks.py \
  --out build/runtime-benchmarks/run-1 --allow-qemu
python3 tools/verify_runtime_benchmarks.py build/runtime-benchmarks/run-1
```

The combined preregistration is written before any stage. The runner retains two
complete four-scenario timer packets and two contention packets, with independent
builds and full verification. The final verification has its own bounded child
and receipt. Nested compiler/emulator owners receive time to clean up their own
process groups before the stage owner forces termination. Stage reservations and
the total experiment deadline prevent another stage from starting without its
full declared budget. Failed attempts retain fixed failure metadata and private
diagnostics, without an accepted timing summary.

After each successful host-test stage, the runner removes only its four declared
intermediate binaries. It validates all four as bounded, owned regular files
with a single link before removing any. Test receipts, original output and
unknown files stay present; an unknown file rejects the closed success inventory.

For publication, `--list-files` prints only the independently verified successful
artifact allowlist. The verifier rejects additional files, aliases and special
files in the accepted packet. Original image directories remain declared inputs;
their contents must equal the retained build in the corresponding contention
packet. They do not silently become additional measurements.

The next hardware comparison must register the exact CPU/topology, firmware,
clock ordering/frequency, placement, power conditions, offered workload, sample
counts, baseline/candidate interleaving, SLO/regression margins and uncertainty
method before measuring candidates.
Test low load, bursts and contention with cancellation/control progress preserved.
Physical preemption/wakeup and cross-core accounting need their trusted runtime
and clock qualification; GPU/device and numerical-quality evidence remain
separate prerequisites for end-to-end inference speed claims.

[ADR 0022](decisions/0022-runtime-benchmark-experiments.md) records the scope.
