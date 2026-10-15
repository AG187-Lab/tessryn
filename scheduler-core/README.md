# K03 scheduler and CPU-budget policy preparation

`lib.rs` is an original, allocation-free `no_std` policy with fixed domain,
task and CPU tables. It selects numerical tasks, reserves CPU-time grants and
accounts supplied execution intervals. It performs no context switch or native
execution. [K03](https://github.com/AG187-Lab/tessryn/issues/6) remains open for
native SMP after [K02](https://github.com/AG187-Lab/tessryn/issues/5).

The internal `TaskId` and `CpuLease` types are distinct from native descriptors
and memory/device leases. Authenticated caller identities, clock readings and
stop acknowledgments must come from a future trusted adapter. All mutations
require exclusive access; the library supplies no cross-CPU lock or interrupt.

## Reproduction

Run from the repository root:

```sh
python3 tools/setup_k02_toolchain.py
python3 -m unittest discover -s tests -p 'test_k03*.py' -v
python3 tools/check_k03_core.py --output build/k03/result.json
python3 tools/validate_design.py
```

K03 reuses the existing checksum-pinned compiler/host libraries and setup
identity without changing their lock files. The checker runs the actual Rust
policy tests on the host and compiles it twice for `x86_64-unknown-none`. It
retains a source/tool-bound receipt and `libtessryn_scheduler.rlib`; failed or
interrupted verification invalidates stale success evidence and the library.
The new CI workflow repeats these checks on Linux and retains its own artifact.

## Policy contract

- Immutable lifetime limits use nanoseconds. There is no automatic budget refill
  or rate/period guarantee. Domain consumption survives task reaping.
- Dispatch reserves against both task and shared domain limits before execution.
  Concurrent grants cannot independently spend the same remaining tenant budget.
- One task owns at most one CPU; one CPU owns at most one lease. Only the exact
  trusted stop acknowledgment permits reuse or migration.
- Stop charges the full supplied interval, including lateness. Wide counters
  preserve totals across overlapping CPU intervals; an overdue retained lease
  halts new admission for its domain and requests peer stops without refunds.
- Task slots and CPU leases advance nonwrapping generations. Retired slots cannot
  resurrect old identities. Domain IDs remain registered for the policy lifetime.
- All rejected mutations leave counters, tables, clock and selection cursors
  unchanged. Successful operations refresh numerical expiry.

Domain-then-task round-robin is a bounded reference selection policy. Its table
scans and serialized mutation are not a production SMP hot-path decision or a
latency/fairness measurement. A domain with extra tasks can fill otherwise idle
CPUs when another domain has no eligible task; it still shares one lifetime cap.

See [the integration contract](../design/k03-preparation.md) and
[ADR 0016](../design/decisions/0016-scheduler-policy-core.md). Native clocks,
isolation, timer enforcement, real cross-core traces and GPU/bandwidth preemption
remain unavailable in this evidence profile.
