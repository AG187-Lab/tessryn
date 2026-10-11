# Benchmark and correctness gates

Status: measurement plan. There are no Tessryn performance results. Before testing, register the model/checkpoint, quantization, hardware/firmware, topology, admission budgets, offered arrival process, prompt/output distributions, duration, sample counts, and latency SLOs.

## Serving evidence

Measure short and long prompts, shared and unrelated prefixes, concurrent tenants, cold and warm caches, and sustained thermal operation. Report accepted, rejected, canceled, failed, and SLO-compliant requests separately. Report p50/p95/p99 time to first token, inter-token latency, completion latency, aggregate throughput, and goodput: completed requests meeting the declared SLOs per unit time. Include queueing and transport time in user-visible metrics.

Compare colocated serving with disaggregated prefill/decode; compare contiguous pipeline, tensor collectives, and hybrids on the same workload. Publish memory residency, workspace peaks, transfer bytes/copies, accelerator utilization, energy, and failure outcomes. Existing macOS/Linux runtimes are reference baselines, not native execution evidence. Keep numerical format and quality comparable when reporting speed differences.

Milestone M5 requires all four native nodes, including the exact notebook, to execute resident model shards. The declared weight/state working set must exceed every individual admitted capacity and fit aggregate capacity with headroom. If this model occupies all workers, test prefill/decode separation with a smaller checkpoint of the same architecture or additional reserved capacity; do not count the same memory twice.

## Analytical traffic example

Assume 80 attention layers, hidden dimension 8192, eight KV heads, head dimension 128, BF16, batch one, and 8192 context tokens. KV is `2 × 80 × 8 × 128 × 2 = 327,680` bytes per token; a full context is 2.5 GiB. One pipeline boundary carries 16 KiB for one decode activation, or 128 MiB for the whole prefill. This is a hypothetical architecture, not a measured model.

| Payload | Ideal 1 Gb/s | Ideal 10 Gb/s | Ideal 100 Gb/s |
| --- | ---: | ---: | ---: |
| 16 KiB activation | 0.131 ms | 0.0131 ms | 0.00131 ms |
| 128 MiB prefill activation | 1.074 s | 0.1074 s | 0.01074 s |
| 2.5 GiB full KV | 21.475 s | 2.147 s | 0.2147 s |

These serialization floors exclude startup, compute, copies, encryption, queueing, and loss. Streaming, missing-block transfer, and prefix reuse change overlap or bytes. A conventional four-rank ring with two all-reduces per layer has `80 × 2 × 6 = 960` algorithm steps per token; this is a topology sensitivity example, not a universal rejection threshold.

## Numerical and failure gates

Use per-operator dtype-specific absolute/relative tolerances, finite-value checks, fixed-history teacher-forced logits/probabilities, and held-out task quality. Record greedy token agreement. A temperature-zero mismatch alone does not prove incorrectness: [floating-point execution order can change results](https://docs.pytorch.org/docs/stable/notes/numerical_accuracy.html). Require exact replay only under declared deterministic conditions; unchanged byte encodings still require exact transfer integrity.

Test cancellation, stale coordinator epochs, rank loss, degraded links, drain, and restart. Recovery requires surviving model/state capacity; quorum alone cannot reconstruct a missing shard. Report capacity failure explicitly when recovery is unavailable.
