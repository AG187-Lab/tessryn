# Native scheduled admission and cancellation

This opt-in experiment runs the [scheduled-arrival workload](scheduled-arrival-replay.md)
through the original kernel. It keeps the host replay as the one-worker policy
reference. The BSP coordinates offers, cancellation and accounting. The AP
runs one CPL3 job at a time and uses its own local timer. The
[two-CPU shared-budget case](k03-smp-budget.md) remains the reference for
overlapping CPL3 work.

## Workload and time

The compiled image binds the original 8 steady, 12 burst and 30 overload
offers, including all eight scheduled cancellations. A small QEMU firmware
configuration item selects a scenario and quantum. One image serves the
whole comparison. The directed correctness case is separate from the
three workload scenarios. The selector uses the x86 port interface.
[QEMU firmware configuration specification](https://www.qemu.org/docs/master/specs/fw_cfg.html)

The original offer tick maps to an absolute offset from a common HPET epoch.
Each scheduled tick represents 10 ms of QEMU virtual time. Quanta 4 and 16
request hard grants of 80 and 320 ms. The local one-shot target is one quarter
of the admitted grant, giving nominal targets of 20 and 80 ms. The finite
CPL3 payload executes 64,000 iterations per original work unit in both arms.
Work units measure instructions supplied to a job, while HPET intervals
measure the actual virtual time charged.

An initial overload diagnostic exceeded a 40 ms reservation. The kernel
charged the measured 51.267 ms and rejected that run. The registered
comparison widens the hard reservation margin for virtual interrupt
delivery. It keeps the same offers, finite work and nominal timer targets.
The worker has a 24-second guest trial bound and a 30-second launcher
timeout. Each task and domain has a 30-second lifetime cap, leaving it
nonbinding for this one-worker trial even with a live reservation.

Keep the original due time, the BSP's actual observation and the AP's
pre-entry sample. This separates admission delay from ready-queue wait and
dispatch preparation. The BSP observes due events during an active slice
while the AP continues the same generation-bound lease. Process due offers
and cancellations in scheduled order, with offers preceding cancellations at
the same tick and job IDs breaking ties. Record the actual policy time used.

## Stops and ownership

A queued cancellation changes the job's state immediately. A running
cancellation changes it to stopping while keeping its CPU reservation.
The AP retires through its authenticated local timer or the finite program's
protected completion gate. Reconciliation charges the exact dispatch-to-stop
interval, releases the reservation once, and resolves a previously requested
cancellation before treating the job as completed. A cancellation arriving
after a terminal outcome is recorded as a no-op.

The BSP consumes an earlier published retirement before advancing policy
time. The AP closes publication before sampling its protected retirement.
The BSP samples its event time before observing that phase. It can apply an
event against a running lease or wait for the closing worker's exact receipt.
The phase order resolves observations at the same raw HPET value. The
worker's task identity, slot generation, lease generation and CPU bind the
command and receipt. The finite program and its private context provide
evidence of progress and completion. Memory remains retained after the
terminal drain.

## Reproduce

Use a clean committed checkout with the pinned compiler, QEMU and firmware.
The runner registers the image, exact workload, timing rules and attempt
order before launching any guest. It runs the directed case, then two
observations per quantum in each scenario, in 4, 16, 16, 4 order. Each attempt
retains the raw trace, process receipt and exact selector.

```sh
python3 tools/k03_native_arrivals.py --out build/k03-native-arrivals/run-1 --allow-qemu
python3 tools/k03_native_arrivals.py --verify build/k03-native-arrivals/run-1
```

The result describes this image-bound CPU workload under the pinned emulator.
Physical scheduling claims require a qualified platform and clock. The
[inference performance plan](inference-performance.md) supplies the later
workload and qualification gates for choosing an inference quantum.
