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

Register independent run count/order, warmup rule, stopping rule, excluded sample
policy, quantile estimator and confidence-interval method before observing a
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

In format v1, each latency sample is a completed **request**: inter-token latency
uses one declared summary per request. Register that summary rule in the
methodology/quantile estimator and retain the raw per-token trace. These
percentiles do not represent a pooled per-token distribution; a later format
must declare token sample units explicitly before publishing that distribution.

The result validator checks registered/observed identities and sample/count
consistency. It does not compute inference metrics or replace review of raw
observations. No model executor, GPU driver, metric collector or optimization
loop is supplied by G03. Maintain the [benchmark contract](benchmarks.md) and
[ADR 0008 authority policy](decisions/0008-evaluation-and-recursive-improvement.md)
when those implementations arrive.
