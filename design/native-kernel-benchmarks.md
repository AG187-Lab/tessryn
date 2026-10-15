# In-kernel benchmark experiment

Status: executed inside the original kernel under single-CPU QEMU. Two independent local image builds produced identical EFI, boot-media and policy-library bytes; both fresh boots emitted all 208 samples across 13 cases and passed offline verification. Hardware latency, native scheduler enforcement and inference performance are unqualified.

This experiment executes original Rust code inside Tessryn after firmware exit and CPU ownership. It adds a separate opt-in build mode to the committed native kernel baseline; it does not execute the host benchmark binary in the guest. The [host harness merged in PR62](https://github.com/AG187-Lab/tessryn/pull/62) retains its separate format and scope.

## Build and run

Use the repository's checksum-pinned compiler, UEFI target and QEMU. Python 3.12 or newer is required. A fresh checkout can prepare those tools with:

```sh
python3 tools/setup_toolchain.py --jobs 4
python3 tools/setup_uefi.py
```

The scheduler policy remains a separately owned dependency. Fetch the exact reviewed source into ignored build inputs:

```sh
mkdir -p build/native-inputs
gh api 'repos/AG187-Lab/tessryn/contents/scheduler-core/lib.rs?ref=c8b46a94ec8269c630b491e038d953cda7c66b87' \
  --header 'Accept: application/vnd.github.raw' > build/native-inputs/scheduler-core.rs
```

The required SHA-256 is `db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d`. The builder compiles it as an external `x86_64-unknown-uefi` library. A retained library for another target cannot be substituted, and the policy source is not copied into a competing scheduler implementation.

Run the experiment with:

```sh
python3 tools/build_native_kernel_benchmarks.py --out build/native-benchmarks/image
python3 tools/run_native_kernel_benchmarks.py \
  --manifest build/native-benchmarks/image/manifest.json \
  --out build/native-benchmarks/run-1 --allow-qemu
python3 tools/verify_native_kernel_benchmarks.py build/native-benchmarks/run-1
```

Each output directory must be new. Execution requires the explicit `--allow-qemu` flag. Failed attempts remain retained. No AWS allocation or hardware rental is part of these commands.

Running a retained build also requires every executable Python helper to match
the reviewed checkout before any retained helper is imported on the host.
Self-consistent packet hashes do not grant host-code authority. Use the matching
reviewed source checkout to rerun a historical build; standalone offline packet
verification reads retained bytes without executing their Python source.

## Work and units

The first profile fixes 16 measured samples, four excluded warmups, 128 iterations and seed 1. Its 13 cases cover:

- Ordered counter reads and an empty loop as instrumentation references.
- A sequential bounded ring fixture: enqueue/dequeue batches of 1, 8 and 64, plus full/empty rejection.
- The existing memory policy's allocation/revocation/release metadata and access checks.
- Separately labelled real volatile zero/copy work over a kernel-owned 4 KiB page.
- The exact pinned K03 policy's dispatch/stop accounting and individual dispatch calls.

Memory metadata timings do not include physical erasure, mapping or TLB work. The byte cases perform actual accesses to admitted kernel-owned memory; they are small reused buffers, not sustained memory bandwidth. The ring is a fixture until K04 supplies a production queue. Scheduler calls exercise serialized policy logic; supplied logical nanoseconds remain distinct from measured counter ticks and do not demonstrate task execution, wakeup, preemption or enforcement.

Case setup/reset and serial output are outside timed regions. All sample records are buffered before emission. The existing K01 compiler profile, including optimization level 1, is recorded explicitly; this experiment does not silently change the kernel build to create an apparent improvement.

Most rows describe quantiles of amortized batch averages. Their p95/p99 values are not individual-operation tail latencies. The single-dispatch case has a distinct sample unit. Timer overhead is retained without subtraction. Zero durations remain observations; clock regression and incomplete or failed samples reject the attempt.

## Counter limits

The guest checks advertised TSC support and uses an ordered read sequence with compiler barriers. It records the counter mechanism and advertised invariant/hypervisor facts. Frequency remains unqualified. Raw TSC ticks must not be called CPU cycles or converted to nanoseconds without an independently qualified machine and clock profile. RDTSC itself is not serializing; see the [Intel software developer manual](https://cdrdv2-public.intel.com/858456/253669-088-sdm-vol-3b.pdf).

QEMU runs prove that the original kernel reaches and executes the instrumentation, produces correct workload outcomes and emits a complete transcript. They do not establish physical CPU latency. QEMU's instruction-counting documentation explicitly distinguishes its mechanism from cycle-accurate emulation; see [QEMU TCG instruction counting](https://www.qemu.org/docs/master/devel/tcg-icount.html). This experiment does not use instruction counts as a physical timing substitute.

## Retained evidence and next gate

Native observations use a separately versioned profile and packet. The build binds retained source inputs, the pinned policy, compiler flags and tool identities to the EFI image and boot media. Capture preregisters the profile and artifacts before launching fresh bounded QEMU, retains exact stdout/stderr and process outcome, and verifies the original guest transcript. Offline verification establishes packet consistency; it does not authenticate execution independently.

The original native K02 protection cases, their transcripts and the frozen AWS intake image/evaluator remain separate. This experiment starts from the last committed native baseline and does not incorporate another chat's unfinished matrix changes. New measurement media cannot be substituted into prior accepted boot/recovery evidence.

The next performance gate is a separately approved hardware profile: exact machine and CPU configuration, counter ordering and frequency qualification, virtualization/power conditions, instrumentation cost, repeated observations and uncertainty. Scheduler wakeup/context-switch and enforcement timing also require the corresponding trusted runtime. Cross-core measurements additionally require synchronization and clock evidence. End-to-end inference still requires the model, numerical-quality, cancellation, recovery, resource and latency contracts in [benchmarks](benchmarks.md) and [evaluation evidence](evaluation-evidence.md).
