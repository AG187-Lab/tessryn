# Evaluation evidence contract

Status: implemented format/validation foundation; no Tessryn performance or
numerical/model result exists. [G03 workflow](build-and-evaluation.md) executes
only original ROM fixtures and inspects a separate Rust ELF probe.

## Three kinds of evidence

| Kind | Format and purpose | Permitted claim |
| --- | --- | --- |
| `assumption` | Registration or an unfilled template | A declared hypothesis, protocol, budget or future acceptance rule |
| `implementation_result` | Bound execution result, logs and artifact manifest | Observed tooling behavior, including failure and unavailable capabilities |
| `measured_performance` | Future result bound to a frozen preregistration and raw observations | Measurements of an identified implementation under recorded conditions |

[Evidence JSON schema](../evidence/schema-v1.json) describes registrations and
results in version 1. The
[standard-library validator](../tools/g03/evidence.py) also enforces cross-field
invariants, duplicate-key rejection, finite numbers, hash identities, sample
accounting and fixture restrictions. Validate records with:

```sh
python3 tools/g03/evidence.py validate evidence/fixture-registration.json
python3 tools/g03/evidence.py validate evidence/performance-template.json
python3 tools/g03/evidence.py validate build/pass/result.json
```

The CLI accepts only regular files of at most 256 MiB, limits JSON nesting to
64 container levels, and reports parse/storage errors without a traceback.
Counts fit the nonnegative signed 64-bit range. Numbers must be representable
as finite host numeric values. These are format limits, not capability evidence.

Schema validation establishes shape and consistency, not empirical truth or an
independent evaluator. A public example is not a held-out dataset. No sample
performance values are published as measurements.

Results contain artifact-manifest, evaluator and registration SHA-256 bindings,
the exact emulator command and limits, actual return code, bounded logs with
hashes/lengths, explicit status/reason, and capability availability. Registration
hashes use UTF-8 canonical JSON (`sort_keys=True`, `separators=(',', ':')`,
`allow_nan=False`); manifest and log hashes cover the original bytes. Harness
results have zero performance samples and all native capabilities unavailable.
Never convert fixture wall-clock duration into a native performance metric.
A passing fixture requires a probed emulator; a future native record may name its
target runner with `emulator: null`, while every passing record retains a
nonnegative observed runner/emulator exit code.

## Preregister before execution

Before a future native measurement, an independent evaluator freezes and
timestamps a `preregistered` record outside candidate modification authority.
It binds candidate commit/manifest, evaluator commit/hash, hardware/firmware,
topology, compiler/target, model/checkpoint, quantization and state formats.
The measurement start must follow that registration. The public template
deliberately lacks these identities and cannot validate as preregistered.

Register numerical references and operator/dtype tolerances, teacher-forced
history, held-out workload hash/custodian/access policy, target and warmup sample
counts, duration, workload distributions, tenants, cache state, offered arrival
process/rate, concurrency, admission budgets and numeric latency SLOs. Declare
power mode, frequency policy, ambient temperature and sustained thermal duration.
Thermal conditions unsupported by an emulator must be unavailable, never inferred
from a host timing sample.

Numerical comparisons identify `kind` (`operator`, `logits`, or `probabilities`),
operator, dtype, tolerances, finite-value requirement and `tolerance_rationale`.
All three kinds are required, including explicit teacher-forced tolerances.
Each kind/operator/dtype combination is unique. A passing measurement must use
the registered ambient temperature, power mode and frequency policy; changing
them requires a new preregistration. Observed sustained thermal duration cannot
exceed observed duration, and the same rule applies to the registered plan.

Register independent run count/order, warmup rule, stopping rule, excluded sample
policy, quantile estimator, confidence level and confidence-interval method before observing a
candidate. Prefer at least three paired baseline/candidate repetitions in
randomized order and at least 10,000 measured requests per registered workload
when estimating p99. These are methodological recommendations, not measurements
or a universal guarantee of adequate statistical power. Register a larger sample
count when variability or the desired interval width requires it. Retain misses,
failures, timeouts and rejected requests; do not stop early when results look good.
Do not tune on holdouts, or edit criteria after seeing their results.

## Numerical references and held-out quality

Use identified, hashed reference implementations/outputs and trusted input data.
Prefer a justified high-precision reference per operator when possible; an
external runtime is an attributed baseline, not native execution evidence.
For each operator and dtype declare absolute/relative tolerances and finite-value
checks; compare `abs(candidate-reference) <= atol + rtol*abs(reference)` and report
sample count, maximum errors and failures. Tolerances must be justified against
the algorithm, dtype and reference rather than selected to fit a candidate.

Record fixed-history teacher-forced logits **and** probabilities, plus greedy
token agreement. Only demand exact replay under explicitly matching deterministic
conditions. [PyTorch's numerical-accuracy guidance](https://docs.pytorch.org/docs/stable/notes/numerical_accuracy.html)
explains why floating-point order and platform differences can affect results;
a greedy mismatch alone does not establish an incorrect implementation. Byte
transfer integrity still requires exact hashes.

Held-out workload content belongs to an independent custodian. Publish permitted
identity/hash and access policy; withhold private content from candidates and
public artifacts. Separate development workloads from held-out evaluation;
exclude holdouts from training, tuning and candidate selection. Report held-out
task metric, sample count, baseline and candidate quality separately from numeric
operator checks and performance. If a reference, real holdout or implementation
is absent, report `unavailable` and its reason. Future promotion requires these
gates; a structurally valid record is not promotion authority.

## Measurements and retention

Publish raw request/latency traces with units, admitted/rejected/cancelled/failed
outcomes, actual counts and observation duration. Report completed and
SLO-compliant counts separately. Include p50/p95/p99 TTFT, inter-token and
completion latency with their own sample counts, aggregate throughput and
goodput. Count queueing and transport in user-visible latency. State whether a
latency distribution excludes unsuccessful requests and retain those outcomes
separately. Independent-run variation and confidence intervals accompany the
pooled values. Emulated results must identify the emulator and never qualify
physical thermal behavior or a native device profile.

`throughput` is completed requests divided by observation seconds; `goodput` is
SLO-compliant completed requests divided by the same duration. Validation permits
rounding error of at most `max(1e-12 requests/s, 1e-9 × the larger magnitude)`.
Observation duration and sample counts aggregate the independent runs; the
retained report also records each run's duration, counts and metrics. Warmup
requests do not enter measured request traces or rates. Registered sample gates
apply to that aggregate. Any claim about individual-run adequacy must use the
individual-run results. Every measured format in v1 describes an inference
workload, so a passing result requires available inference as well as kernel
boot (and GPU execution for device artifacts). A failed record may retain
unavailable capabilities and conditions that missed registered gates.

In format v1, each latency sample is a completed **request**: inter-token latency
uses one declared summary per request. Register that summary rule in the
methodology/quantile estimator and retain the raw per-token trace. These
percentiles do not represent a pooled per-token distribution; a later format
must declare token sample units explicitly before publishing that distribution.

## Required retained reports

A measured result's `performance.report_artifacts` requires four distinct
bundle-relative files, each with its byte length and SHA-256. The numerical and
held-out summaries' `raw_results_sha256` must match their report artifacts.
Every payload binds the canonical preregistration hash. Files that escape the
bundle, symlinks, nonregular files, modified bytes and missing files fail CLI
validation. Fixture results require none of these reports and retain zero
performance samples.

| Payload `format` | Required public content |
| --- | --- |
| `tessryn-performance-trace` | `sample_unit: request`, `latency_unit: ms`, unique run/request IDs, completed/rejected/cancelled/failed outcomes, SLO outcome, TTFT/inter-token/completion summaries, and raw `per_token_ms` intervals. Failed requests may retain partial or null latencies; a completed request requires all summaries. A one-token output has an empty interval array. |
| `tessryn-statistical-report` | `rate_unit: requests/s`, confidence level and registered interval method, lower/upper intervals for all latency p50/p95/p99 and both rates, and distinct independent run IDs with duration and metrics. |
| `tessryn-numerical-report` | Reference/history hashes; per-kind/operator/dtype sample counts, maximum absolute/relative errors, tolerance failure counts and nonfinite failure counts; greedy token sample/agreement counts. Maximum errors describe finite comparisons; nonfinite cases have their own counts. |
| `tessryn-held-out-report` | Workload hash, aggregate sample count, metric/value, an independent `custody_reference`, and a separately labeled measured or unavailable baseline. A measured baseline binds its raw results hash. No private workload, prompt, expected answer or raw held-out content belongs in this public report. |

The CLI checks raw request/outcome/SLO counts, run identities and durations,
per-run rate/count consistency, interval bounds around the reported estimates,
registered statistical method, numerical comparison coverage/failure summaries,
greedy agreement, and held-out aggregate identities/counts. Numerical summary
`sample_count` is the sum of the comparison sample counts; greedy agreement has
its separate token count. Report `format` values also validate independently:

```sh
python3 tools/g03/evidence.py validate results/native/result.json
python3 tools/g03/evidence.py validate results/native/statistics.json
```

These are commands for future retained native evidence. Those files do not
exist in this repository. Unit tests create explicitly synthetic payloads only.
Validation does not recompute quantiles, confidence intervals, inference output
errors or held-out task quality. Review their raw observations and independent
custody evidence before treating the supplied summaries as measurements.

The in-memory result validator checks registered/observed identities and
sample/count consistency; CLI result validation additionally reads and verifies
the required retained report bundle. No model executor, GPU driver, metric collector or optimization
loop is supplied by G03. Maintain the [benchmark contract](benchmarks.md) and
[ADR 0008 authority policy](decisions/0008-evaluation-and-recursive-improvement.md)
when those implementations arrive.
