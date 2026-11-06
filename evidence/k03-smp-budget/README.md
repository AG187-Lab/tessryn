# Two-CPU timer and shared-budget evidence

These are November 6, 2026 observations from the original Tessryn kernel under
pinned QEMU/OVMF. The clean implementation is
`eab49c93d60132e301671e5af50cf9e098a69584`. See the
[profile, commands and remaining gates](../../design/k03-smp-budget.md).

| Case | Accepted observations |
| --- | --- |
| `preempt` | Two rounds with four genuine local timer traps in CPL3. The shared cap clips the second grant in both rounds: 800/400 ms, then 800/288.330 ms. Both contexts resume with their saved state and advance their heartbeats. Full charges total 223,177,000 ns. Both complete with zero outstanding reservations. |
| `late` | Two deliberately late local timer traps against grants of 40/20 ms. The first 67,869,000 ns charge halts the domain; redispatch is denied with the peer's 20 ms reservation still present. The peer's actual 251,042,000 ns is then charged in full, bringing the total to 318,911,000 ns and reservations to zero. |

Each round has independently checked evidence that AP user work preceded BSP
entry and the BSP trap was captured before the earliest possible AP timer
expiry in the admitted virtual clock model. Actual local timer source state,
full GPR/FP frames, private roots and terminal heartbeat stability are retained.
In the late case, both hardware receipts were acquired before reconciliation;
the pending peer reservation does not establish real-time remote cancellation.
All RAM stays retained. The times above are accounting observations, not
hardware latency or inference performance measurements.

The complete [verification](verification.json) passes two fresh boots, seven
byte-identical pairs of build artifacts (including the scheduler archive),
26 actual ACPI parser checks, and exact binding of 16 compiler and 29 runtime
inputs. All 774 Python tests pass, including 19 focused budget checks. The
[earlier CPL3 verifier](regressions/k03-smp-user/verification.json) separately
accepted all three original scenarios and nine matching twin artifacts at the
same source, using the same ACPI host receipt.

The 44-file text packet includes 41 byte-preserved originals. Its [index](index.json)
hashes the payload and summary, excluding itself and this explanatory README.
[Summary](summary.json) records hashes for all 148 files of the independently
audited complete local artifact, including the firmware images, binary media
and duplicate source bytes omitted here. The full local audit found no private
path or credential markers. Offline consistency checking does not authenticate
the original act of execution. This evidence does not qualify physical clocks,
general SMP scheduling, deadlines, blocking/wakeup, migration or memory reuse.
