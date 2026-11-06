"""Adversarial replay of protected native cancellation and completion receipts."""
from __future__ import annotations

import unittest

from tools.k03_native_arrivals_protocol import CLASSES, DIRECTED_OFFERS, WORK_ITERATIONS, load_profile
from tools.k03_native_arrivals_trace import replay_events
from tools.k03_smp_user_trace import _Trace


PREFIX = "TESSRYN_K03_WORKLOAD_"
EPOCH = 10_000_000
TICK = 1_000_000
QUANTUM_UNIT = 20_000_000
GRANT = 4 * QUANTUM_UNIT
DOMAIN_LIMIT = 30_000_000_000
RUN_LIMIT = 24_000_000_000
CODE = 0x1_0000_0000
SENTINEL = 0x534D_5055_0000_0000
OFFSETS = {
    "user_start": 0, "loop": 16, "after_inc": 20, "after_sum": 23,
    "before_dec": 25, "after_dec": 28, "complete": 30, "complete_return": 32,
}
ROOTS = {1: 0x200000, 2: 0x210000, 3: 0x220000}


def offer(row):
    due = EPOCH + row["arrival"] * TICK
    return ("OFFER", dict(id=row["id"], domain=row["domain"], arrival=row["arrival"],
                         due=due, observed=due, work=row["work"], cancel=row["cancel"] or 0,
                         **{"class": CLASSES[row["class"]]}, slot=row["id"] - 1,
                         task_gen=1, lease=0, progress=0))


def dispatch(job, lease, start):
    return ("DISPATCH", dict(id=job, domain=job, slot=job - 1, task_gen=1, cpu=1,
                            lease=lease, start=start, select_start=start, select_done=start + 2,
                            grant_ns=GRANT, hard=start + GRANT // 10))


def cancel(job, disposition, lease, reserved_ns, progress):
    return ("CANCEL", dict(id=job, domain=job, tick=1, due=EPOCH + TICK, observed=EPOCH + TICK,
                          disposition=disposition, lease=lease, reserved_ns=reserved_ns, progress=progress))


def stop(start_row, *, source, resume, rip, progress_before, progress_after, consumed, outcome):
    _, start = start_row
    job = start["id"]
    arm_before = start["start"] + 100
    timer = source == 67
    trap = arm_before + (2_001_000 if timer else 50_000)
    retired = trap + 40
    charge = (retired - start["start"]) * 10
    row = {key: start[key] for key in ("id", "domain", "slot", "task_gen", "cpu", "lease", "start", "grant_ns", "hard")}
    return ("STOP", dict(**row, arm_before=arm_before, arm_after=arm_before + 5,
                         initial=1_250_000, entry=arm_before + 10, trap=trap, eoi=trap + 10 if timer else 0,
                         retired=retired, seen=retired + 10, reconcile_start=retired + 20, reconciled=retired + 30,
                         progress_before=progress_before, progress_after=progress_after,
                         checksum=((SENTINEL + job) * progress_after) % (1 << 64),
                         rip=CODE + OFFSETS[rip], resume_rip=CODE + OFFSETS[resume], root=ROOTS[job],
                         isr_before=8 if timer else 0, isr_after=0, vector=source, drained=0,
                         outcome=outcome, charged_ns=charge, consumed_ns=consumed + charge, reserved_ns=0))


def fixture():
    first = dispatch(1, 1, EPOCH + 100)
    canceled = stop(first, source=67, resume="user_start", rip="loop", progress_before=0,
                    progress_after=2_000, consumed=0, outcome="canceled")
    second = dispatch(3, 2, EPOCH + 4 * TICK + 100)
    yielded = stop(second, source=67, resume="user_start", rip="after_dec", progress_before=0,
                   progress_after=WORK_ITERATIONS, consumed=0, outcome="yield")
    third = dispatch(3, 3, yielded[1]["reconciled"] + 100)
    completed = stop(third, source=128, resume="after_dec", rip="complete_return",
                     progress_before=WORK_ITERATIONS, progress_after=WORK_ITERATIONS,
                     consumed=yielded[1]["consumed_ns"], outcome="completed")
    totals = (canceled[1]["consumed_ns"], 0, completed[1]["consumed_ns"], 0)
    return [
        ("BEGIN", dict(scenario=3, quantum=4, epoch=EPOCH, tick_ns=10 * TICK, quantum_unit_ns=QUANTUM_UNIT,
                       unit_iterations=WORK_ITERATIONS,
                       worker_cpu=1, worker_slot=0, jobs=3, limit_ns=DOMAIN_LIMIT, run_limit_ns=RUN_LIMIT)),
        offer(DIRECTED_OFFERS[0]), offer(DIRECTED_OFFERS[1]), first,
        cancel(1, "running", 1, GRANT, 1_000), cancel(2, "queued", 0, 0, 0),
        canceled, offer(DIRECTED_OFFERS[2]), second, yielded, third, completed,
        ("TASK", dict(id=1, domain=1, state="canceled", consumed_ns=totals[0], dispatches=1, progress=2_000)),
        ("TASK", dict(id=2, domain=2, state="canceled", consumed_ns=0, dispatches=0, progress=0)),
        ("TASK", dict(id=3, domain=3, state="completed", consumed_ns=totals[2], dispatches=2, progress=WORK_ITERATIONS)),
        *(("DOMAIN", dict(id=domain, consumed_ns=value, reserved_ns=0)) for domain, value in enumerate(totals, 1)),
        ("PASS", dict(offers=3, cancels=2, completions=1, canceled=2, stops=3, end=completed[1]["reconciled"] + 2 * TICK + 10)),
    ]


class NativeArrivalLifecycleTests(unittest.TestCase):
    def replay(self, rows):
        lines = []
        for kind, fields in rows:
            line = " ".join([PREFIX + kind, *(f"{key}={value}" for key, value in fields.items())])
            lines.append(line)
        trace = _Trace(("\n".join(lines) + "\n").encode("ascii"))
        return replay_events(trace, scenario="directed", quantum=4, profile=load_profile(),
                             program={"offsets": OFFSETS}, roots=ROOTS)

    def reject(self, index, **change):
        rows = fixture()
        rows[index][1].update(change)
        with self.assertRaises(ValueError):
            self.replay(rows)

    def test_running_cancel_drains_and_queued_cancel_never_dispatches(self):
        report = self.replay(fixture())
        self.assertEqual(report["cancel_counts"], {"queued": 1, "running": 1, "terminal": 0})
        self.assertEqual(report["completed"], 1)
        first, queued, complete = report["jobs"]
        self.assertGreater(first["running_cancel_drain_ns"], 0)
        self.assertEqual((queued["consumed_ns"], queued["slices"]), (0, []))
        self.assertEqual(complete["progress"], WORK_ITERATIONS)

    def test_rejects_early_refund_or_unwitnessed_running_cancel(self):
        for change in ({"reserved_ns": 0}, {"lease": 0}, {"progress": 0}):
            with self.subTest(change=change):
                self.reject(4, **change)
        for change in ({"lease": 1}, {"reserved_ns": GRANT}):
            with self.subTest(change=change):
                self.reject(5, **change)

    def test_rejects_stale_stop_regressed_time_or_shortened_charge(self):
        for change in ({"lease": 2}, {"retired": EPOCH + TICK - 1}, {"charged_ns": 0}):
            with self.subTest(change=change):
                self.reject(6, **change)

    def test_rejects_forged_no_progress_completion_tail(self):
        for change in ({"resume_rip": CODE + OFFSETS["user_start"]}, {"progress_after": WORK_ITERATIONS - 1},
                       {"rip": CODE + OFFSETS["loop"]}, {"vector": 67}, {"drained": 1}):
            with self.subTest(change=change):
                self.reject(11, **change)

        rows = fixture()
        rows[9][1]["rip"] = CODE + OFFSETS["loop"]
        rows[11][1]["resume_rip"] = CODE + OFFSETS["loop"]
        with self.assertRaises(ValueError):
            self.replay(rows)

    def test_rejects_reordered_same_tick_cancellations(self):
        rows = fixture()
        rows[4], rows[5] = rows[5], rows[4]
        with self.assertRaises(ValueError):
            self.replay(rows)

    def test_rejects_dispatch_before_due_offer_or_nonempty_final_reservation(self):
        rows = fixture()
        rows[2], rows[3] = rows[3], rows[2]
        with self.assertRaises(ValueError):
            self.replay(rows)
        self.reject(15, reserved_ns=GRANT)
