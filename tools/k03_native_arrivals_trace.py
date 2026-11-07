"""Replay native arrivals, authentic stop receipts, and exact task/domain charges."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from tools.k02_region_protocol import digest, require
from tools.k03_native_arrivals_protocol import (
    CLASSES, DIRECTED, HARD_QUANTUM_UNIT_NS, MAX_LOG_BYTES, RUN_LIMIT_NS, SCALE_NS, SOFT_DIVISOR, TICK_NS, WORK_ITERATIONS,
    config_bytes, offers_for,
)
from tools.k03_smp_budget_trace import _boot
from tools.k03_smp_trace import _disjoint
from tools.k03_smp_user_protocol import PROFILE as USER_PROFILE
from tools.k03_smp_user_trace import ANY, _Trace, _fields
from tools.scheduled_arrival_trace import _first_wait

PREFIX = "TESSRYN_K03_WORKLOAD_"
LIMIT_NS = 30_000_000_000
WORKER_CPU = 1
TASK_CAPACITY = 30
VECTOR = 67
IRQ_BIT = 1 << (VECTOR % 32)
DIVIDER = 16
ROUNDING_NS = 20
CHECKSUM_SEED = 0x534D505500000000
MAX_U64 = (1 << 64) - 1
CODE = USER_PROFILE["user_code"]
PAGE = 4096
PHYSICAL = (1 << 48) - PAGE
STABLE_WINDOW_NS = 20_000_000

OFFER = "id domain arrival due observed work cancel class slot task_gen lease progress"
CANCEL = "id domain tick due observed disposition lease reserved_ns progress"
DISPATCH = "id domain slot task_gen cpu lease start select_start select_done grant_ns hard"
STOP = ("id domain slot task_gen cpu lease start grant_ns hard arm_before arm_after initial entry trap eoi "
        "retired seen reconcile_start reconciled progress_before progress_after checksum rip resume_rip root "
        "isr_before isr_after vector drained outcome charged_ns consumed_ns reserved_ns")


def _row(trace, marker, keys, *, words=()):
    fields = trace.take(PREFIX + marker, dict.fromkeys(keys.split(), ANY))
    require(all(type(value) is (str if key in words else int) for key, value in fields.items()),
            "native workload field type differs at " + marker)
    return fields


def _ns(start, end):
    return (end - start) * TICK_NS


@dataclass
class Job:
    offer: dict
    state: str = "future"
    admitted: int = 0
    ready: int = 0
    slot: int | None = None
    generation: int | None = None
    charged_ns: int = 0
    progress: int = 0
    resume_rip: int = 0
    terminal: int | None = None
    samples: list = field(default_factory=list)
    cancellation: dict | None = None

    @property
    def id(self):
        return self.offer["id"]

    @property
    def domain(self):
        return self.offer["domain"]

    @property
    def work(self):
        return self.offer["work"] * WORK_ITERATIONS


@dataclass
class Lease:
    job: Job
    row: dict
    events: list = field(default_factory=list)


class _Replay:
    def __init__(self, scenario, quantum, offers, epoch, program, roots):
        self.scenario = scenario
        self.quantum = quantum
        self.jobs = {offer["id"]: Job(offer) for offer in offers}
        self.epoch = epoch
        self.latest = epoch
        self.program = program
        self.roots = roots
        self.events = []
        for offer in offers:
            self.events.append((offer["arrival"], 0, offer["id"]))
            if offer["cancel"] is not None:
                self.events.append((offer["cancel"], 1, offer["id"]))
        self.events.sort()
        self.next_event = 0
        self.offers = 0
        self.domain_charges = [0] * 4
        self.domain_cursor = 0
        self.task_cursors = [0] * 4
        self.lease = None
        self.last_lease = 0
        self.stops = []
        self.peak_ready = 0
        self.in_slice_events = []

    def due(self, tick):
        return self.epoch + tick * (SCALE_NS // TICK_NS)

    def advance(self, tick):
        require(self.latest <= tick <= self.epoch + RUN_LIMIT_NS // TICK_NS,
                "native workload trusted time regressed or exceeded run limit")
        self.latest = tick

    def external(self, row, phase, tick):
        require(self.next_event < len(self.events) and self.events[self.next_event] == (tick, phase, row["id"])
                and row["due"] == self.due(tick) <= row["observed"],
                "native workload scheduled event skipped, duplicated, early, or reordered")
        self.next_event += 1
        self.advance(row["observed"])

    def offer(self, row):
        self.external(row, 0, row["arrival"])
        job = self.jobs[row["id"]]
        offer = job.offer
        require(job.state == "future" and row["domain"] == job.domain and row["work"] == offer["work"]
                and row["cancel"] == (offer["cancel"] or 0) and row["class"] == CLASSES[offer["class"]]
                and row["slot"] == self.offers and row["task_gen"] == 1,
                "native workload admitted identity or fixed work differs")
        active = self.lease
        require(row["lease"] == (0 if active is None else active.row["lease"])
                and (row["progress"] == 0 if active is None
                     else active.job.progress <= row["progress"] <= active.job.work),
                "native workload arrival misidentifies the active lease")
        if active is not None:
            active.events.append(("offer", row))
        job.state = "ready"
        job.admitted = job.ready = row["observed"]
        job.slot = row["slot"]
        job.generation = row["task_gen"]
        job.resume_rip = CODE + self.program["offsets"]["user_start"]
        self.offers += 1

    def cancel(self, row):
        self.external(row, 1, row["tick"])
        job = self.jobs[row["id"]]
        require(row["domain"] == job.domain, "native workload cancellation domain differs")
        active = self.lease
        disposition = row["disposition"]
        if job.state == "running":
            require(active is not None and active.job is job and disposition == "running"
                    and row["lease"] == active.row["lease"] and row["reserved_ns"] == active.row["grant_ns"]
                    and job.progress <= row["progress"] <= job.work, "native workload running cancellation dropped its lease")
            active.events.append(("cancel", row))
            job.state = "canceling"
        else:
            require(row["lease"] == row["reserved_ns"] == 0 and row["progress"] == job.progress,
                    "native workload idle cancellation claims a live lease or changes progress")
            if job.state == "ready":
                require(disposition == "queued", "native workload queued cancellation disposition differs")
                job.state = "canceled"
                job.terminal = row["observed"]
            else:
                require(job.state in ("completed", "canceled") and disposition == "terminal",
                        "native workload terminal cancellation changed outcome")
        job.cancellation = row

    def _selected(self):
        ready = [job for job in self.jobs.values() if job.state == "ready"
                 and job.charged_ns < LIMIT_NS and self.domain_charges[job.domain - 1] < LIMIT_NS]

        def rank(job):
            domain = job.domain - 1
            return ((domain - self.domain_cursor) % 4, (job.slot - self.task_cursors[domain]) % TASK_CAPACITY)

        return min(ready, key=rank, default=None)

    def dispatch(self, row):
        self.advance(row["start"])
        require(self.next_event == len(self.events) or self.due(self.events[self.next_event][0]) > row["start"],
                "native workload dispatched before a due external event")
        job = self.jobs.get(row["id"])
        require(job is not None and self.lease is None and self._selected() is job
                and (row["domain"], row["slot"], row["task_gen"], row["cpu"])
                == (job.domain, job.slot, job.generation, WORKER_CPU), "native workload dispatch identity or RR selection differs")
        grant = self.quantum * HARD_QUANTUM_UNIT_NS
        available = min(LIMIT_NS - job.charged_ns, LIMIT_NS - self.domain_charges[job.domain - 1])
        require(grant <= available and row["grant_ns"] == grant and row["hard"] == row["start"] + grant // TICK_NS
                and row["lease"] == self.last_lease + 1 and job.ready <= row["start"] == row["select_start"] <= row["select_done"] <= row["hard"],
                "native workload lease, reservation, or scheduler endpoints differ")
        self.last_lease = row["lease"]
        self.lease = Lease(job, row)
        self.domain_cursor = job.domain % 4
        self.task_cursors[job.domain - 1] = (job.slot + 1) % TASK_CAPACITY
        job.state = "running"

    def _check_progress(self, job, row):
        offsets = self.program["offsets"]
        rip = row["rip"] - CODE
        inverse = {offset: name for name, offset in offsets.items()}
        require(row["root"] == self.roots[job.id] and rip in inverse and row["resume_rip"] == job.resume_rip
                and row["progress_before"] == job.progress <= row["progress_after"] <= job.work,
                "native workload user root, progress, or saved instruction differs")
        label = inverse[rip]
        progress = row["progress_after"]
        require(label != "user_start" and (label != "loop" or progress < job.work)
                and (label not in ("complete", "complete_return") or progress == job.work),
                "native workload instruction and finite work phase disagree")
        adds = progress - (label == "after_inc")
        expected = ((CHECKSUM_SEED + job.id) * adds) & MAX_U64
        require(adds >= 0 and row["checksum"] == expected, "native workload CPL3 checksum differs from executed iterations")
        return label

    def _check_stop_source(self, row, rip, grant):
        require(row["arm_before"] <= row["arm_after"] <= row["entry"] <= row["trap"] <= row["retired"]
                <= row["seen"] <= row["reconcile_start"] <= row["reconciled"]
                and 0 < row["initial"] < 1 << 32 and row["drained"] in (0, 1),
                "native workload hardware stop timestamps or countdown invalid")
        target = grant // SOFT_DIVISOR
        require(row["initial"] == (target + DIVIDER - 1) // DIVIDER,
                "native workload did not arm the registered proportional timer")
        nominal = (row["initial"] + 1) * DIVIDER
        expiry_early = row["arm_before"] + (nominal - ROUNDING_NS) // TICK_NS
        expiry_late = row["arm_after"] + (nominal + ROUNDING_NS + TICK_NS - 1) // TICK_NS
        require(expiry_late < row["hard"], "native workload timer could expire beyond the hard reservation")
        if row["vector"] == VECTOR:
            require(rip != "complete_return" and row["trap"] >= expiry_early
                    and row["trap"] <= row["eoi"] <= row["retired"] and row["isr_before"] == IRQ_BIT
                    and row["isr_after"] == row["drained"] == 0 and row["progress_after"] > row["progress_before"],
                    "native workload timer source, EOI or executed progress differs")
            latency = [_ns(min(expiry_late, row["trap"]), row["trap"]), _ns(expiry_early, row["trap"])]
        else:
            require(row["vector"] == 128 and rip == "complete_return" and row["isr_before"] == row["isr_after"] == 0
                    and (max(row["trap"], expiry_early) <= row["eoi"] <= row["retired"]
                         if row["drained"] else row["eoi"] == 0),
                    "native workload completion gate or drain differs")
            latency = None
        return latency

    def stop(self, row):
        active = self.lease
        require(active is not None and all(row[key] == active.row[key] for key in
                ("id", "domain", "slot", "task_gen", "cpu", "lease", "start", "grant_ns", "hard")),
                "native workload stop does not acknowledge the exact active lease")
        job = active.job
        require(self.latest <= row["trap"], "native workload event was observed after its active lease began closing")
        self.advance(row["retired"])
        require(active.row["select_done"] <= row["arm_before"] and row["retired"] <= row["hard"],
                "native workload arm precedes selection or retirement is late")
        rip = self._check_progress(job, row)
        latency = self._check_stop_source(row, rip, row["grant_ns"])
        outcome = ("canceled" if job.state == "canceling" else
                   "completed" if row["vector"] == 128 else "yield")
        require(row["outcome"] == outcome and (row["vector"] != 128 or row["progress_after"] == job.work),
                "native workload retirement outcome or finite work differs")
        progress = job.progress
        for kind, event in active.events:
            require(progress <= event["progress"] <= row["progress_after"]
                    and active.row["start"] <= event["observed"] <= row["retired"],
                    "native workload external event or progress escapes the retained lease")
            progress = event["progress"]
            if row["entry"] <= event["observed"] < row["trap"] and event["progress"] > row["progress_before"]:
                self.in_slice_events.append({"kind": kind, "id": event["id"], "running_id": job.id,
                                             "lease": row["lease"], "observed": event["observed"]})
        charge = _ns(row["start"], row["retired"])
        job.charged_ns += charge
        self.domain_charges[job.domain - 1] += charge
        require(row["charged_ns"] == charge and row["consumed_ns"] == job.charged_ns
                and row["reserved_ns"] == 0 and job.charged_ns <= LIMIT_NS
                and self.domain_charges[job.domain - 1] <= LIMIT_NS,
                "native workload elapsed charge or grant release differs")
        job.samples.append({
            "ready": job.ready, "dispatch": active.row, "retirement": row,
            "queue_wait_ns": _ns(job.ready, row["start"]),
            "selection_ns": _ns(active.row["select_start"], active.row["select_done"]),
            "reservation_to_entry_ns": _ns(active.row["select_done"], row["entry"]),
            "timer_expiry_to_trap_ns": latency, "trap_to_retirement_ns": _ns(row["trap"], row["retired"]),
            "retirement_to_seen_ns": _ns(row["retired"], row["seen"]),
            "reconciliation_ns": _ns(row["reconcile_start"], row["reconciled"]),
        })
        self.stops.append(row)
        self.advance(row["reconciled"])
        job.progress = row["progress_after"]
        job.resume_rip = row["rip"]
        if outcome == "yield":
            job.state = "ready"
            job.ready = row["retired"]
        else:
            job.state = outcome
            job.terminal = row["retired"]
        self.lease = None

    def update_peak(self):
        self.peak_ready = max(self.peak_ready, sum(job.state == "ready" for job in self.jobs.values()))

    def finish(self, trace):
        require(self.next_event == len(self.events) and self.lease is None
                and all(job.state in ("completed", "canceled") for job in self.jobs.values()),
                "native workload terminated before all offers, cancellations, and leases drained")
        completed = canceled = 0
        rows = []
        for job in self.jobs.values():
            expected = {"id": job.id, "domain": job.domain, "state": job.state,
                        "consumed_ns": job.charged_ns, "dispatches": len(job.samples), "progress": job.progress}
            trace.take(PREFIX + "TASK", expected)
            completed += job.state == "completed"
            canceled += job.state == "canceled"
            cancel = job.cancellation
            rows.append({**job.offer, "state": job.state, "offered": self.due(job.offer["arrival"]),
                         "admitted": job.admitted, "terminal": job.terminal,
                         "offer_delay_ns": _ns(self.due(job.offer["arrival"]), job.admitted),
                         "first_wait_ns": job.samples[0]["queue_wait_ns"] if job.samples else None,
                         "consumed_ns": job.charged_ns, "progress": job.progress, "slices": job.samples,
                         "cancellation": cancel, "running_cancel_drain_ns": (
                             _ns(cancel["observed"], job.terminal) if cancel and cancel["disposition"] == "running" else None)})
        for domain, charged in enumerate(self.domain_charges, 1):
            trace.take(PREFIX + "DOMAIN", {"id": domain, "consumed_ns": charged, "reserved_ns": 0})
        cancel_count = len(self.events) - self.offers
        end = trace.take(PREFIX + "PASS", {"offers": self.offers, "cancels": cancel_count, "completions": completed,
                                          "canceled": canceled, "stops": len(self.stops), "end": ANY})["end"]
        require(type(end) is int and _ns(self.latest, end) >= STABLE_WINDOW_NS, "native workload terminal park window invalid")
        self.advance(end)
        require(trace.index == len(trace.rows), "native workload has unconsumed terminal trace rows")
        charged = sum(self.domain_charges)
        elapsed = _ns(self.epoch, end)
        require(charged <= elapsed, "native workload charged more than the single worker timeline")
        cancels = {kind: sum(row["cancellation"] is not None and row["cancellation"]["disposition"] == kind for row in rows)
                   for kind in ("queued", "running", "terminal")}
        if self.scenario == DIRECTED:
            require(cancels == {"queued": 1, "running": 1, "terminal": 0} and completed == 1
                    and any(event["kind"] == "cancel" for event in self.in_slice_events),
                    "directed native test did not prove queued cancellation, running cancellation and completion")
        classes = {}
        for task_class in CLASSES:
            group = [job for job in rows if job["class"] == task_class]
            waits = [job["first_wait_ns"] for job in group if job["first_wait_ns"] is not None]
            classes[task_class] = {"offered": len(group), "first_wait_ns": _first_wait(waits),
                                   "completed": sum(job["state"] == "completed" for job in group),
                                   "canceled": sum(job["state"] == "canceled" for job in group)}
        return {"scenario": self.scenario, "quantum": self.quantum, "epoch": self.epoch, "end": end,
                "elapsed_ns": elapsed, "charged_ns": charged, "unassigned_worker_interval_ns": elapsed - charged,
                "offers": self.offers, "cancels": cancel_count, "cancel_counts": cancels, "completed": completed,
                "canceled": canceled, "dispatches": len(self.stops), "timer_stops": sum(row["vector"] == VECTOR for row in self.stops),
                "peak_ready": self.peak_ready, "domain_charges_ns": self.domain_charges,
                "in_slice_events": self.in_slice_events, "classes": classes, "jobs": rows}


def replay_events(trace, *, scenario, quantum, profile, program, roots, clock=0):
    """Replay the serialized event stream after low-level boot validation."""
    offers = offers_for(profile, scenario)
    require(set(roots) == {offer["id"] for offer in offers}, "native workload job roots are incomplete")
    selector = config_bytes(scenario, quantum)
    begin = trace.take(PREFIX + "BEGIN", {
        "scenario": selector[0], "quantum": quantum, "epoch": ANY, "tick_ns": SCALE_NS,
        "quantum_unit_ns": HARD_QUANTUM_UNIT_NS,
        "unit_iterations": WORK_ITERATIONS, "worker_cpu": WORKER_CPU, "worker_slot": 0,
        "jobs": len(offers), "limit_ns": LIMIT_NS, "run_limit_ns": RUN_LIMIT_NS,
    })
    require(type(begin["epoch"]) is int and begin["epoch"] >= clock, "native workload epoch precedes trusted clock")
    replay = _Replay(scenario, quantum, offers, begin["epoch"], program, roots)
    actions = {
        PREFIX + "OFFER": ("OFFER", OFFER, (), replay.offer),
        PREFIX + "CANCEL": ("CANCEL", CANCEL, ("disposition",), replay.cancel),
        PREFIX + "DISPATCH": ("DISPATCH", DISPATCH, (), replay.dispatch),
        PREFIX + "STOP": ("STOP", STOP, ("outcome",), replay.stop),
    }
    while trace.index < len(trace.rows) and trace.rows[trace.index][0] in actions:
        marker, fields, words, action = actions[trace.rows[trace.index][0]]
        action(_row(trace, marker, fields, words=words))
        replay.update_peak()
    return replay.finish(trace)


def _trace_fields(line):
    if not line.startswith(PREFIX + "IRQ "):
        return _fields(line)
    parts = line.split(" ")
    vectors = [part[5:] for part in parts if part.startswith("rtes=")]
    require(len(vectors) == 1 and re.fullmatch(r"[0-9a-f]{192}", vectors[0]), "native workload IOAPIC words malformed")
    marker, fields = _fields(" ".join(part for part in parts if not part.startswith("rtes=")))
    return marker, {**fields, "rtes": vectors[0]}


class _NativeTrace(_Trace):
    def __init__(self, data):
        require(type(data) is bytes and 0 < len(data) <= MAX_LOG_BYTES and data.endswith(b"\n")
                and all(byte == 10 or 32 <= byte < 127 for byte in data), "native workload stdout is not bounded complete ASCII")
        self.rows = [_trace_fields(line) for line in data.decode("ascii").splitlines()]
        self.index = 0


def _prelude(trace, binding, offers):
    image, _, apics, clock, _, owned, madt = _boot(trace, binding["bootstrap"])
    cal = _row(trace, "CAL", "cpu divider first_before first_after first_count last_before last_after last_count")
    require(cal["cpu"] == WORKER_CPU and cal["divider"] == DIVIDER
            and clock <= cal["first_before"] <= cal["first_after"] < cal["last_before"] <= cal["last_after"]
            and 0 < cal["last_count"] < cal["first_count"] <= (1 << 32) - 1,
            "native workload local timer calibration differs")
    calibrated = (cal["first_count"] - cal["last_count"]) * DIVIDER
    require(_ns(cal["first_after"], cal["last_before"]) - ROUNDING_NS <= calibrated
            <= _ns(cal["first_before"], cal["last_after"]) + ROUNDING_NS,
            "native workload local timer rate differs from HPET")
    irq = trace.take(PREFIX + "IRQ", {"version": 0x170020, "redirections": 24, "rtes": ANY})
    require(all(int(irq["rtes"][offset:offset + 8], 16) & (1 << 16) for offset in range(0, 192, 8)),
            "native workload IOAPIC route is unmasked")
    roots = {}
    shared_code = None
    for offer in offers:
        row = _row(trace, "ROOT", "job root root_end code stack data leaves code_pte stack_pte data_pte")
        require(row["job"] == offer["id"] and row["leaves"] == 3 and row["root_end"] > row["root"]
                and row["root_end"] - row["root"] == USER_PROFILE["root_pool_pages"] * PAGE,
                "native workload private user root extent differs")
        ranges = [(row["root"], row["root_end"]), (row["stack"], row["stack"] + PAGE), (row["data"], row["data"] + PAGE)]
        require(all(lo % PAGE == 0 and image[0] <= lo < hi <= image[1] for lo, hi in ranges),
                "native workload private user space escaped owned image")
        owned.extend(ranges)
        require(shared_code is None or row["code"] == shared_code, "native workload executable backing differs between jobs")
        shared_code = row["code"]
        for kind in ("code", "stack", "data"):
            pte = row[kind + "_pte"]
            flags = 0x5 if kind == "code" else (1 << 63) | 0x7
            require(pte & PHYSICAL == row[kind] and pte & ~(PHYSICAL | 0x60) == flags,
                    "native workload user leaf authority differs")
        roots[offer["id"]] = row["root"]
    require(shared_code == image[0] + binding["program"]["efi_rva"] and shared_code % PAGE == 0
            and image[0] <= shared_code <= image[1] - PAGE,
            "native workload executable backing escaped owned image")
    owned.append((shared_code, shared_code + PAGE))
    require(all(_disjoint(left, right) for i, left in enumerate(owned) for right in owned[i + 1:]),
            "native workload private root or writable backing aliases another object")
    trace.take(PREFIX + "PAYLOAD", {"sha256": binding["program"]["sha256"]})
    return roots, cal["last_after"], apics, madt


def replay_boot(data, returncode, stderr, *, scenario, quantum, profile, binding):
    """Verify the full original boot prelude and the workload's raw event stream."""
    require(type(returncode) is int and returncode == 33 and type(stderr) is bytes and stderr == b"",
            "native workload capture did not exit cleanly")
    trace = _NativeTrace(data)
    roots, clock, apics, madt = _prelude(trace, binding, offers_for(profile, scenario))
    summary = replay_events(trace, scenario=scenario, quantum=quantum, profile=profile,
                            program=binding["program"], roots=roots, clock=clock)
    return {**summary, "online_apic_ids": apics, "madt_sha256": madt, "trace_sha256": digest(data)}
