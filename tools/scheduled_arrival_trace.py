"""Independently check a single-CPU scheduled-arrival replay's logical trace.

The preregistered job table fixes offered events and work. The trace chooses a
ready job at each dispatch; this checker intentionally does not implement the
K03 policy's selection order. It checks time, lifecycle, and work conservation
before summarizing the observed choices. Ticks are logical, not elapsed time.
"""

from dataclasses import dataclass, field
from io import BytesIO
import re


_MAX_U64 = (1 << 64) - 1
_DECIMAL = re.compile(rb"(?:0|[1-9][0-9]{0,19})")
_CLASSES = ("decode", "prefill", "control")
_OUTCOMES = ("completed", "canceled_queued", "canceled_running")
_CANCEL = ("queued", "running", "terminal")
_LAYOUTS = {
    b"arrive": (None, None),
    b"dispatch": (None, None, None, None),
    b"cancel": (None, None, (b"queued", b"running", b"terminal")),
    b"stop": (None, None, (b"yield", b"completed", b"canceled"), None),
    b"end": (None,),
}


def _integer(value, name, minimum=0):
    if type(value) is not int or not minimum <= value <= _MAX_U64:
        raise ValueError(f"invalid {name}")
    return value


def _records(data):
    for line in BytesIO(data):
        # The longest row is a dispatch with four 20-digit unsigned fields.
        if len(line) > 93 or not line.endswith(b"\n"):
            raise ValueError("invalid trace row boundary")
        kind, *parts = line[:-1].split(b"\t")
        layout = _LAYOUTS.get(kind)
        if layout is None or len(parts) != len(layout):
            raise ValueError("invalid trace row shape")
        parsed = [kind.decode("ascii")]
        for part, choices in zip(parts, layout):
            if choices is None:
                if _DECIMAL.fullmatch(part) is None:
                    raise ValueError("noncanonical trace integer")
                parsed.append(_integer(int(part), "trace integer"))
            elif part in choices:
                parsed.append(part.decode("ascii"))
            else:
                raise ValueError("invalid trace disposition")
        yield tuple(parsed)


@dataclass
class _Job:
    id: int
    domain: int
    task_class: str
    arrival: int
    work: int
    cancel: int | None
    remaining: int
    ready_tick: int | None = None
    charged: int = 0
    outcome: str | None = None
    terminal_tick: int | None = None
    cancel_disposition: str | None = None
    ready_samples: list = field(default_factory=list)

    def terminate(self, tick, outcome):
        self.ready_tick = None
        self.outcome = outcome
        self.terminal_tick = tick

    def summary(self):
        first = self.ready_samples[0] if self.ready_samples else None
        return {
            "id": self.id, "domain": self.domain, "class": self.task_class,
            "arrival": self.arrival, "work": self.work, "cancel": self.cancel,
            "outcome": self.outcome, "terminal_tick": self.terminal_tick, "charged": self.charged,
            "first_dispatch": None if first is None else first["dispatch_tick"],
            "first_wait": None if first is None else first["wait"],
            "ready_samples": self.ready_samples, "cancel_disposition": self.cancel_disposition,
            "running_cancel_drain": self.terminal_tick - self.cancel if self.cancel_disposition == "running" else None,
        }


@dataclass(frozen=True)
class _Lease:
    job: _Job
    start: int
    stop: int


def _job_table(jobs):
    if type(jobs) is not list:
        raise ValueError("invalid job table")
    table, events = {}, []
    for row in jobs:
        if type(row) is not dict:
            raise ValueError("invalid job")
        try:
            job_id = _integer(row["id"], "job ID")
            domain = _integer(row["domain"], "job domain")
            task_class = row["class"]
            arrival = _integer(row["arrival"], "job arrival")
            work = _integer(row["work"], "job work", 1)
            cancel = row["cancel"]
        except KeyError as error:
            raise ValueError("missing job field") from error
        if type(task_class) is not str or task_class not in _CLASSES or job_id in table:
            raise ValueError("invalid or duplicate job identity")
        if cancel is not None:
            _integer(cancel, "job cancellation", max(1, arrival))
            events.append((cancel, 1, job_id))
        events.append((arrival, 0, job_id))
        table[job_id] = _Job(job_id, domain, task_class, arrival, work, cancel, work)
    # External phases 0 (arrival) then 1 (cancellation), each ascending ID.
    return table, sorted(events)


def _first_wait(values):
    if not values:
        return None
    ordered = sorted(values)
    count = len(ordered)
    return {
        "count": count, "min": ordered[0], "max": ordered[-1],
        **{f"p{p}": ordered[(p * count + 99) // 100 - 1] for p in (50, 95, 99)},
    }


def _summary(table, tick, peak_ready):
    rows = [table[job_id].summary() for job_id in sorted(table)]
    classes = {}
    for task_class in _CLASSES:
        group = [job for job in rows if job["class"] == task_class]
        waits = [job["first_wait"] for job in group if job["first_wait"] is not None]
        classes[task_class] = {
            "offered": len(group), "dispatched": len(waits),
            "outcomes": {name: sum(job["outcome"] == name for job in group) for name in _OUTCOMES},
            "first_wait": _first_wait(waits),
        }
    busy = sum(job["charged"] for job in rows)
    return {
        "end_tick": tick, "busy_elapsed": busy, "idle_elapsed": tick - busy,
        "dispatches": sum(len(job["ready_samples"]) for job in rows), "peak_ready": peak_ready,
        "jobs": rows, "classes": classes,
        "cancel_counts": {name: sum(job["cancel_disposition"] == name for job in rows) for name in _CANCEL},
    }


def validate_trace(data: bytes, jobs: list[dict], quantum: int) -> dict:
    """Reject an invalid canonical TSV with ValueError, or return its summary."""
    if type(data) is not bytes:
        raise ValueError("trace must be bytes")
    _integer(quantum, "quantum", 1)
    table, external = _job_table(jobs)
    records = iter(_records(data))

    def expect(*expected):
        if next(records, None) != expected:
            raise ValueError(f"expected {expected[0]} at logical tick {expected[1]}")

    tick, index, peak_ready = 0, 0, 0
    lease, ready = None, set()
    while index < len(external) or lease is not None or ready:
        # Between dispatches, only a preregistered external event or the exact
        # planned stop can advance the clock. If ready work exists with no
        # lease, dispatch is required immediately at the current logical tick.
        next_external = external[index][0] if index < len(external) else None
        if lease is not None:
            tick = lease.stop if next_external is None else min(lease.stop, next_external)
        elif not ready:
            tick = next_external

        if lease is not None and lease.stop == tick:
            job = lease.job
            elapsed = tick - lease.start
            job.remaining -= elapsed
            job.charged += elapsed
            if job.cancel_disposition == "running":
                expect("stop", tick, job.id, "canceled", elapsed)
                job.terminate(tick, "canceled_running")
            elif job.remaining == 0:
                expect("stop", tick, job.id, "completed", elapsed)
                job.terminate(tick, "completed")
            else:
                expect("stop", tick, job.id, "yield", elapsed)
                job.ready_tick = tick
                ready.add(job.id)
            lease = None

        while index < len(external) and external[index][0] == tick:
            _, phase, job_id = external[index]
            job = table[job_id]
            if phase == 0:
                expect("arrive", tick, job_id)
                job.ready_tick = tick
                ready.add(job_id)
            else:
                if lease is not None and lease.job is job:
                    disposition = "running"
                elif job_id in ready:
                    disposition = "queued"
                    ready.remove(job_id)
                    job.terminate(tick, "canceled_queued")
                else:
                    if job.outcome is None:
                        raise ValueError("cancellation without live or terminal job")
                    disposition = "terminal"
                expect("cancel", tick, job_id, disposition)
                job.cancel_disposition = disposition
            index += 1

        peak_ready = max(peak_ready, len(ready))
        if lease is None and ready:
            record = next(records, None)
            if record is None or record[:2] != ("dispatch", tick) or record[2] not in ready:
                raise ValueError(f"expected a ready dispatch at logical tick {tick}")
            _, _, job_id, ready_tick, grant = record
            job = table[job_id]
            if ready_tick != job.ready_tick or grant != min(quantum, job.remaining):
                raise ValueError("dispatch readiness or grant differs")
            planned_stop = _integer(tick + grant, "planned stop")
            job.ready_samples.append({"ready_tick": ready_tick, "dispatch_tick": tick,
                                      "wait": tick - ready_tick, "grant": grant})
            ready.remove(job_id)
            job.ready_tick = None
            lease = _Lease(job, tick, planned_stop)

    expect("end", tick)
    if next(records, None) is not None or any(job.outcome is None for job in table.values()):
        raise ValueError("trace did not end after all work and offered events")
    return _summary(table, tick, peak_ready)
