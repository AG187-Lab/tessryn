# Runnable kernel policy and overhead benchmarks

Status: host microbenchmark harness. It can run on a development host now; native kernel, wakeup/context-switch, SMP, DMA, GPU and inference performance remain unqualified. This is a separate format from G03's end-to-end inference performance records.

## Run now

Use Python 3.12 or newer and a host Rust compiler (tested with Rust 1.96.0). The harness has no package dependencies or automatic downloads. The default suite measures the existing owned-memory policy and isolated scheduler/queue references:

```sh
python3 tools/run_kernel_benchmarks.py --out build/benchmarks/base-1
python3 tools/verify_kernel_benchmarks.py build/benchmarks/base-1
```

Each run needs a **new** output directory. The runner refuses an existing path rather than overwriting success evidence. `--rustc` selects an explicit installed compiler. `--samples`, `--warmup`, `--iterations` and `--seed` control the frozen workload. Defaults are 100 measured samples per case, 20 excluded warmups, 1,000 iterations and seed 1. The complete build/run shares a 120-second deadline and bounded logs, operation count and processed bytes.

The K03 policy is separately owned and may still be in review. To measure the exact reviewed source without changing it, fetch its pinned public input or point `--scheduler-source` at a checkout's `scheduler-core` directory:

```sh
mkdir -p build/benchmark-inputs
gh api 'repos/AG187-Lab/tessryn/contents/scheduler-core/lib.rs?ref=c8b46a94ec8269c630b491e038d953cda7c66b87' \
  --header 'Accept: application/vnd.github.raw' > build/benchmark-inputs/scheduler-core.rs
python3 tools/run_kernel_benchmarks.py --out build/benchmarks/scheduler-1 \
  --scheduler-source build/benchmark-inputs/scheduler-core.rs
python3 tools/verify_kernel_benchmarks.py build/benchmarks/scheduler-1
```

The input must match SHA-256 `db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d`. This is the unchanged host policy from [K03 PR 61](https://github.com/AG187-Lab/tessryn/pull/61); its retained freestanding library is not a host executable. A different policy revision needs an explicitly reviewed adapter/profile update. The benchmark does not silently read the policy owner's changing worktree.

## What each result means

| Area | Executed work | Meaning and exclusions |
| --- | --- | --- |
| Scheduler policy latency, optional | One actual K03 dispatch per timed sample, with setup/stop outside the timer; also repeated dispatch/stop cycles | Host policy-call latency and amortized accounting cost. No native wakeup, interrupt or context switch. Numerical policy timestamps are separate from the host clock. |
| Scheduler readiness replay, optional | Four preregistered jobs with arrivals, two domains, a two-unit quantum and one expiry | Seven readiness-to-dispatch episodes and all terminal outcomes under synthetic logical time. This deterministic test is untimed; its delays are not hardware latency samples. |
| Scheduler reference | Bounded round-robin dispatch cycles over 32 numerical tasks | Fixture cost; it is neither K03 nor a production scheduling choice. |
| Memory policy | Existing `MemoryPolicy` allocate/revoke/release and authority/bounds checks | Serialized ownership metadata. The scrub callback is inert; no physical page clearing, MMU protection, map/unmap or TLB operation is timed. |
| Host bytes | Zero/copy operations over reused 4 KiB and 64 KiB buffers | Hot-buffer work plus checksum consumption. Buffer construction/allocation is outside measurement; this is not sustained system memory bandwidth. |
| Queue references | Sequential bounded ring and bounded `VecDeque` reference, batches 1/8/64, full/empty rejection | Uncontended fixture overhead. Counts include enqueue and dequeue separately. No K04 implementation, cross-core ordering, concurrent producer/consumer, interrupt or DMA evidence. |
| Clock and loop references | Repeated `Instant` pairs and empty loop/checksum work | Timer and harness overhead observations, not clock-frequency, resolution, synchronization or native-clock qualification. No overhead is subtracted from other results. |

Most cases report **quantiles of amortized batch averages** (`elapsed_ns / operations`). Those p95/p99 values are not individual-operation or request tail latencies. Only the optional single-dispatch case reports individual host policy-call samples. The output records that distinction for every row. Zero-duration samples remain retained and mark their case resolution-limited; operation averages for that case are suppressed rather than clamped, dropped or used to divide by zero.

The logical replay processes in-slice arrivals before stop acknowledgment, with stops before arrivals at equal timestamps. An early final completion releases unused reservation and charges the supplied elapsed logical time. Expired work that never dispatches appears as an outcome with `completed_ns=null`, not an invented zero-wait sample. The fixed trace checks behavior; it establishes no workload-general fairness or SLO result.

## Retained packet and verification

Before the measured child starts, `registration.json` binds workload, profile, retained source bytes, compiler executable/version, host-target-library fingerprint, build flags, host OS/architecture/CPU model and executable hash. Compilation uses the retained snapshot. Changes to these bound inputs or the executable invalidate the attempt. The registered compiler dependency scope covers its executable and host target libraries only; driver, LLVM and system linker dependencies are unbound. Matching toolchain fields does not establish complete compiler dependency identity. `raw.json` preserves exact measured stdout; structured subprocess receipts and portable logs retain failures. `result.json` contains the recomputed summary or an explicit failed result.

The verifier rejects missing/duplicate cases or sample indices, changed work/configuration, wrong units, malformed JSON, incorrect deterministic checksums, altered bindings and unsuccessful subprocess receipts. Retained inputs are bounded regular files. Failed or canceled runs never publish an observed summary; each attempt has an exclusive directory.

Offline verification establishes **packet self-consistency**, not authenticity of execution or independent preregistration. A party able to replace every file can replace a self-produced packet. Keep the registration digest independently if that distinction matters:

```sh
python3 tools/verify_kernel_benchmarks.py build/benchmarks/scheduler-1 \
  --expected-registration-sha256 <independently-retained-registration-digest>
```

Host names, serial numbers, credentials, environment variables, private prompts and tenant state are excluded. Host timing still includes unknown OS scheduling, power/thermal and background-load effects. `black_box` is a best-effort optimization barrier, not a hardware fence or proof that another compiler cannot optimize differently. The harness detects host-clock regression using checked durations. [Rust's `Instant` documentation](https://doc.rust-lang.org/std/time/struct.Instant.html) and [`black_box` contract](https://doc.rust-lang.org/std/hint/fn.black_box.html) describe these limits.

## Compare repeated runs

Run a second fresh directory with identical workload, policy selection and compiler, then compare:

```sh
python3 tools/run_kernel_benchmarks.py --out build/benchmarks/base-2
python3 tools/verify_kernel_benchmarks.py build/benchmarks/base-2 \
  --baseline build/benchmarks/base-1
```

Comparisons require matching registered host/tool/configuration/build flags/profile. They report descriptive median ratios, with no significance test, automatic regression threshold or promotion decision. Matching recorded host fields does not prove identical load/thermals or physical machine identity. Use independent, interleaved repetitions and registered tolerances before deciding an optimization is better. Preserve slow, failed and neutral runs.

## Development and ownership

Run the boundary and measurement tests with:

```sh
python3 -m unittest discover -s tests -p 'test_kernel_benchmark*.py' -v
python3 tools/validate_design.py
```

The benchmark owns `benchmark-harness/` and its runner/verifier/profile/tests. K02 owns native isolation and revocation; K03 owns scheduling policy. The queue references are harness fixtures and leave K04's production work separate. The harness changes none of those implementations, their evidence or G03's inference schema.

Next native adapters need a qualified monotonic clock, actual runnable-to-running timestamps, context-switch/interrupt accounting, CPU topology and MMU/queue enforcement before their timings enter a separate native measurement profile. They must retain the [inference performance contract](inference-performance.md), [benchmark gates](benchmarks.md) and full applicable correctness/authority/recovery requirements. Host results cannot qualify a production native optimization.
