# How to replay scheduled CPU arrivals

Run this deterministic host fixture to inspect how the unchanged [K03 Rust
scheduler policy](k03-preparation.md) handles short decode-like work, long
prefill-like work and small control jobs competing for one modeled CPU. The
workloads use integer virtual ticks; the job labels describe CPU work only.

## Run and verify

From the repository root, use Python 3.12 or newer and an installed host Rust
compiler. Choose a fresh output directory for each run.

```sh
python3 tools/run_scheduled_arrivals.py --out build/scheduled-arrivals/run-1
python3 tools/run_scheduled_arrivals.py --verify build/scheduled-arrivals/run-1
```

If Rust was installed through rustup, add `--rustc "$(rustup which rustc)"`
to the capture command to select an already installed compiler directly.

The run retains the fixed repository profile, registration, raw traces and
summary. Verification checks the retained packet against the reviewed sources
and replays its event and accounting rules. A separately saved registration
SHA-256 can be supplied with `--expected-registration-sha256` to check the
input pin. That pin does not fix the trace, and offline verification does not
authenticate execution or recalculate the scheduler's selection order. Rerun
the reviewed Rust adapter to reproduce those choices.

If the output directory already exists, choose a new name and use that same
name in the verification command. If verification fails, keep the rejected
packet for inspection and reproduce the run in a separate directory.

## Interpret the comparison

Each steady, burst and overload profile compares quanta of 4 and 16 virtual
ticks. Both settings receive the same scheduled offers for that profile. New
offers arrive at their scheduled ticks regardless of when earlier work finishes,
so a growing queue does not slow down the offered workload. Overload is a
finite offer window followed by a full drain. Compare settings within the same
profile to isolate the quantum change. First-wait summaries include only jobs
that dispatch; a job that never dispatches has a null wait. The peak ready count
is sampled after all stop, arrival and cancellation events at a tick and before
dispatch. Dispatch counts are useful alongside the waits because the fixture
does not charge overhead for changing tasks.

When events share a tick, the replay processes the current stop first, then
arrivals by ID, then cancellations by ID, and then dispatch. A queued job is
canceled immediately. If the job is running, it keeps its lease until its
current planned stop, and the replay charges its modeled CPU time through that
stop. Domain budgets are deliberately large enough to be nonbinding. A
cancellation that arrives too late to change an outcome remains visible as a
no-op. Read the event trace alongside the summary to account for queued,
running and late cancellations, including work that never completes.

The fixed 30-job overload replay illustrates the tradeoff:

| Observation | Quantum 4 | Quantum 16 |
| --- | ---: | ---: |
| Maximum first wait for decode-like work (virtual ticks) | 91 | 239 |
| Maximum first wait for control work (virtual ticks) | 22 | 82 |
| Dispatches | 83 | 38 |

In the burst fixture the running cancellation drains in 2 or 14 virtual ticks,
respectively. These results help choose what to measure on native hardware;
the model does not price the extra dispatches.

The replay exercises scheduling and accounting decisions under synthetic load.
Virtual ticks do not measure latency, context switch cost or throughput. No
model, GPU or network executes, and the one-CPU fixture supplies no multicore
evidence. The [inference performance contract](inference-performance.md) still
requires a preregistered native baseline and candidate comparison on a qualified
profile, with full-path costs, correctness and regression gates, before promoting
an optimization.
