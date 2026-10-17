"""Independent clock, IRQ, policy and continuation replay for the timer fixture.

This is an offline evidence checker, not capture authentication. Its oracle is
independent of kernel status strings: compiled continuation labels, submitted
request bytes, raw exception frames, saved contexts, and ownership transitions
must describe the complete admitted execution, in order.
"""
from __future__ import annotations

import re
import struct

from tools.k03_timer_protocol import (ADDRESSES, CASES, MAX_LOG_BYTES, PROFILE, descriptor_bytes, digest, require,
    QUANTUM_NS, SOFT_NS, MIN_IRQS, case_limits)

CODE, STACK, REQUEST, DATA = (ADDRESSES[k] for k in ("code", "stack", "request", "data"))
SEED, WRITTEN = 0x544553535245474e, 0x1122334455667788
CAP1, CAP2 = 0x100000002, 0x200000002
MAP_A1, MAP_A2, MAP_B, MAP_A3 = 0x100000001, 0x200000001, 0x100000002, 0x300000001
RESET = bytearray(512)
RESET[0:2], RESET[24:28] = b"\x7f\x03", b"\x80\x1f\0\0"
RESET_HASH = digest(RESET)
REGS = {f"r{i}" for i in range(15)}
CONTEXT = {"rip", "rsp", "cs", "ss", "rflags", "fp_sha256"} | REGS
TRAP_FIELDS = {"task", "domain", "root", "vector", "error", "frame", "trap_start", "trap_end", "cr2"} | CONTEXT
ANY = object()


def _fields(line):
    if line == "TESSRYN ORIGINAL KERNEL":
        return line, {}
    parts = line.split(" ")
    require(all(parts), "region trace has noncanonical whitespace")
    values = {}
    for part in parts[1:]:
        require(part.count("=") == 1, "region trace field malformed")
        key, value = part.split("=", 1)
        require(re.fullmatch(r"[a-z][a-z0-9_]*", key) and key not in values and value,
                "region trace field repeated or malformed")
        if key not in ("sha256", "fp_sha256", "bytes") and re.fullmatch(r"(?:0|[1-9][0-9]*|0x[0-9a-f]+)", value):
            value = int(value, 16 if value.startswith("0x") else 10)
            require(value < 1 << 64, "region trace integer exceeds u64")
        values[key] = value
    return parts[0], values


class _Trace:
    def __init__(self, data):
        require(type(data) is bytes and 0 < len(data) <= MAX_LOG_BYTES and data.endswith(b"\n"),
                "region stdout must be bounded complete bytes")
        require(all(b == 10 or 32 <= b < 127 for b in data), "region stdout is not canonical ASCII")
        self.rows = [_fields(line) for line in data.decode("ascii").splitlines()]
        self.index = 0
        sequence = 0
        for kind, fields in self.rows:
            if kind.startswith("TESSRYN_K03_TIMER_"):
                require(type(fields.get("sequence")) is int and fields["sequence"] == sequence,
                        "region service sequence is not contiguous")
                del fields["sequence"]
                sequence += 1
        self.records = sequence

    def take(self, kind, expected):
        require(self.index < len(self.rows), "region trace ended before " + kind)
        actual_kind, fields = self.rows[self.index]
        self.index += 1
        require(actual_kind == kind and set(fields) == set(expected),
                "region marker/order/fields differ at " + kind)
        for key, value in expected.items():
            require(value is ANY or fields[key] == value, "region " + kind + " field differs: " + key)
        return fields

    def service(self, kind, expected):
        return self.take("TESSRYN_K03_TIMER_" + kind, expected)


def _interval(start, end, limit=1 << 32):
    require(type(start) is int and type(end) is int and 0 < start < end <= limit,
            "region live interval invalid")
    return start, end


def _disjoint(a, b):
    return a[1] <= b[0] or b[1] <= a[0]


def _startup(trace, binding):
    trace.take("TESSRYN_K01_ENTRY", {})
    # The sole banner is intentionally not a key/value marker.
    require(trace.index < len(trace.rows) and trace.rows[trace.index] == ("TESSRYN ORIGINAL KERNEL", {}),
            "region original kernel banner missing")
    trace.index += 1
    fb = trace.take("TESSRYN_K01_FRAMEBUFFER", dict.fromkeys(
        ("status", "width", "height", "stride", "base", "format", "selection"), ANY))
    require(fb["status"] == "ready" and fb["format"] in ("rgbx", "bgrx")
            and fb["selection"] in ("firmware-console", "unique-gop")
            and all(type(fb[k]) is int for k in ("width", "height", "stride", "base"))
            and 0 < fb["width"] <= fb["stride"] <= 16384 and 0 < fb["height"] <= 16384,
            "region framebuffer profile differs")
    first_handoff = None
    for attempt in range(1, 9):
        live = trace.take("TESSRYN_K01_LIVE_RANGES", dict.fromkeys(("image_start", "image_end", "stack_start", "stack_end", "map_start", "map_end", "scratch", "runtime_high", "gop_start", "gop_end"), ANY))
        ranges = [_interval(live[k + "_start"], live[k + "_end"]) for k in ("image", "stack", "map", "gop")]
        require(all(type(v) is int for v in live.values()) and live["runtime_high"] == 0
                and all(live[k] % 4096 == 0 for k in ("image_start", "image_end", "stack_start", "stack_end", "map_start", "map_end", "scratch"))
                and live["gop_start"] == fb["base"]
                and live["gop_end"] >= fb["base"] + fb["stride"] * fb["height"] * 4
                and live["gop_end"] - live["gop_start"] <= 64 << 20
                and 0 < live["scratch"] <= (1 << 32) - 4096
                and all(_disjoint((live["scratch"], live["scratch"] + 4096), r) for r in ranges)
                and all(_disjoint(a, b) for i, a in enumerate(ranges) for b in ranges[i + 1:]),
                "region live ranges overlap or differ")
        header = bytes.fromhex(binding["kernel_header_hex"])
        base = binding["kernel_imagebase_offset"]
        pe = struct.unpack_from("<I", header, 60)[0]
        require(header[:2] == b"MZ" and pe + 84 <= len(header) and header[pe:pe + 4] == b"PE\0\0"
                and struct.unpack_from("<H", header, pe + 4)[0] == 0x8664
                and struct.unpack_from("<H", header, pe + 24)[0] == 0x20b
                and type(base) is int and base == pe + 48 and base + 36 <= len(header)
                and live["image_end"] - live["image_start"] == struct.unpack_from("<I", header, base + 32)[0],
                "region loaded image extent differs from compiled PE")
        page = trace.take("TESSRYN_K01_PAGING_READY", {"cr3": ANY, "tables": ANY, "leaves": ANY, "physical_bits": 48, "guard": 0x7fffffe00000, "free_scope": "low-conventional"})
        require(type(page["cr3"]) is int and page["cr3"] % 4096 == 0
                and live["image_start"] <= page["cr3"] < live["image_end"]
                and type(page["tables"]) is int and 0 < page["tables"] <= 32
                and type(page["leaves"]) is int and 0 < page["leaves"] <= 4096,
                "region supervisor paging bounds invalid")
        reset = trace.take("TESSRYN_K01_RESET_POINTER", {"address": ANY, "method": "uefi-runtime"})
        require(type(reset["address"]) is int and 0 < reset["address"] < 1 << 32,
                "region reset pointer invalid")
        memory = trace.take("TESSRYN_K01_MEMORY_MAP_VALID", {"descriptors": ANY, "stride": ANY, "free_pages": ANY, "attempt": attempt})
        require(all(type(v) is int for v in memory.values()) and 0 < memory["descriptors"] <= 4096
                and 40 <= memory["stride"] <= 4096 and memory["stride"] % 8 == 0
                and 5 <= memory["free_pages"] <= (256 << 20) // 4096,
                "region memory map bounds invalid")
        stable = tuple(live[k + suffix] for k in ("image", "stack", "map", "gop") for suffix in ("_start", "_end")) + (live["scratch"], page["cr3"], reset["address"])
        require(first_handoff is None or first_handoff == stable, "region allocated handoff changed across firmware retry")
        first_handoff = stable
        if trace.index < len(trace.rows) and trace.rows[trace.index][0] == "TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY":
            trace.take("TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY", {})
            continue
        trace.take("TESSRYN_K01_EXIT_BOOT_SERVICES_OK", {})
        break
    else:
        raise ValueError("region firmware retry limit exceeded")
    owned = trace.take("TESSRYN_K01_CPU_OWNED", {"cr3": page["cr3"], "rsp": ANY, "rip": ANY, "gdt": "owned", "idt": "owned", "tss": "owned"})
    require(type(owned["rsp"]) is int and live["stack_start"] <= owned["rsp"] < live["stack_end"]
            and type(owned["rip"]) is int and live["image_start"] <= owned["rip"] < live["image_end"],
            "region initial kernel context is outside owned ranges")
    profile = trace.take("TESSRYN_K02_PROFILE", {"physical_bits": 48, "cpu_count": 1, "paging_levels": 4, "nx_supported": 1, "nx_enabled": 1, "pcid_enabled": 0, "global_translations": 0, "la57_enabled": 0, "cr4": ANY, "efer_low": ANY})
    require(type(profile["cr4"]) is int and profile["cr4"] & ((1 << 7) | (1 << 8) | (1 << 12) | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 22) | (1 << 23) | (1 << 24)) == 0
            and profile["cr4"] & 0x600 == 0x600 and type(profile["efer_low"]) is int
            and profile["efer_low"] & 0xd01 == 0xd00,
            "region CPU exclusions or legacy FP controls differ")
    return live, ranges + [(live["scratch"], live["scratch"] + 4096)], page["cr3"]


def _request_bytes(counter, op, cap=0, domain=0, argument=0, length=0, va=0, rights=0, magic=b"TESSRGN1", version=1):
    return struct.pack("<8sHHIQIIII7Q", magic, version, 96, 0, counter, op, 0,
                       cap & 0xffffffff, cap >> 32, domain, argument, 0, length, va, rights, 0).hex()


TERMINAL = {"completed", "failed", "exhausted", "deadline"}
RETIRE = ("fence", "clear", "invalidate", "quiesce")


class _Policy:
    """Independent specialization of the unchanged one-task-per-domain core.

    Clock/ledger assertions use actual samples, never marker-supplied totals.
    Reservation, cursor, inclusive expiry and strict lateness remain separate.
    """
    def __init__(self, now, limits, deadlines):
        self.now, self.limits, self.deadlines = now, limits, deadlines
        self.states, self.consumed, self.reserved = ["runnable", "blocked"], [0, 0], [0, 0]
        self.halted, self.cursor, self.generation, self.active = [False, False], 0, 0, None

    def advance(self, now):
        require(type(now) is int and self.now <= now < 1 << 64, "timer policy clock regressed/overflowed")
        self.now = now
        if self.active and now > self.active[2]:
            self.halted[self.active[0]] = True
        for i in range(2):
            if self.states[i] in TERMINAL:
                continue
            expired = self.deadlines[i] != 0 and now >= self.deadlines[i]
            if self.active and i == self.active[0]:
                if self.halted[i] or expired or now >= self.active[2]:
                    self.states[i] = "stopping"
            elif self.halted[i]:
                self.states[i] = "failed"
            elif expired:
                self.states[i] = "deadline"
            elif self.consumed[i] >= self.limits[i]:
                self.states[i] = "exhausted"

    def wake(self, now):
        require(self.states[1] == "blocked", "timer bootstrap wake was replayed or late")
        self.advance(now)
        self.states[1] = "runnable"

    def dispatch(self, now):
        require(self.active is None and now >= self.now, "timer CPU lease overlaps or clock regressed")
        candidates = [(self.cursor + d) % 2 for d in range(2)]
        eligible = [i for i in candidates if self.states[i] == "runnable" and not self.halted[i]
                    and self.consumed[i] < self.limits[i]
                    and (self.deadlines[i] == 0 or now < self.deadlines[i])]
        require(eligible, "timer dispatch has no eligible task")
        i = eligible[0]
        grant = min(QUANTUM_NS, self.limits[i] - self.consumed[i])
        if self.deadlines[i]:
            grant = min(grant, self.deadlines[i] - now)
        hard, soft = now + grant, now + max(1, min(SOFT_NS, grant // 2))
        require(0 < grant and soft <= hard < 1 << 64 and self.generation < 0xffffffff,
                "timer grant timestamp/generation overflow")
        self.advance(now)
        self.generation += 1
        self.active = (i, now, hard, grant, soft)
        self.states[i], self.reserved[i], self.cursor = "running", grant, 1 - i
        return self.active

    def stop(self, now, outcome):
        i, start, hard, grant, _ = self.active
        require(now >= self.now and now >= start and self.reserved[i] == grant,
                "timer stop lost the exact active reservation")
        self.consumed[i] += now - start
        late = now > hard
        self.halted[i] |= late
        self.states[i] = ("failed" if late or self.halted[i] or outcome == "fail" else
                          "deadline" if self.deadlines[i] and now >= self.deadlines[i] else
                          "completed" if outcome == "complete" else
                          "exhausted" if self.consumed[i] >= self.limits[i] else
                          "blocked" if outcome == "block" else "runnable")
        self.active, self.reserved[i] = None, 0
        self.advance(now)

    def ledger(self, trace, i, phase):
        trace.service("LEDGER", {"phase": phase, "task": i, "domain": i + 1, "task_slot": i,
            "task_generation": 1, "state": self.states[i], "task_limit": self.limits[i],
            "task_consumed": self.consumed[i], "task_reserved": self.reserved[i],
            "domain_limit": self.limits[i], "domain_consumed": self.consumed[i],
            "domain_reserved": self.reserved[i], "halted": int(self.halted[i]),
            "deadline_ns": self.deadlines[i], "cpu_owned": int(self.active is not None and self.active[0] == i)})


class _Memory:
    def __init__(self, trace, frame):
        self.trace, self.frame = trace, frame
        self.caps, self.revoked, self.maps, self.charge = [True, False], [False, False], [0, 0], [3, 2]
        self.stopped = set()

    def cap(self, i, phase):
        self.trace.service("CAP", {"domain": i + 1, "phase": phase, "cap_slot": 2,
                                  "cap_generation": 1, "cap_domain": i + 1})

    def mapping(self, i, phases, generation=None, va=DATA, backing=None, slot=None, charged=None):
        for phase in phases:
            self.trace.service("MAP_EVENT", {"domain": i + 1, "phase": phase, "va": va,
                "frame": self.frame if backing is None else backing, "lease_slot": 4 + i if slot is None else slot,
                "lease_generation": self.maps[i] if generation is None else generation,
                "charged": self.charge[i] if charged is None else charged})

    def retire(self, i):
        require(self.maps[i] != 0, "timer retired an absent native mapping")
        self.mapping(i, RETIRE)
        self.maps[i] = 0

    def release(self, i):
        # A retained child prevents parent release even after every mapping has
        # quiesced. Any live native lease prevents either capability release.
        require(not any(self.maps) and not (i == 0 and self.caps[1]), "timer premature backing release")
        self.cap(i, "release")
        self.caps[i] = False
        if not any(self.caps):
            self.charge[0] = 2

    def reap(self):
        for i in range(2):
            if i not in self.stopped:
                continue
            if self.caps[i]:
                self.revoked[i] = True
                if i == 0 and self.caps[1]:
                    self.revoked[1] = True
            for j in range(2):
                if self.maps[j] and self.revoked[j]:
                    self.retire(j)
            if self.maps[i]:
                self.retire(i)
            if self.caps[i]:
                if any(self.maps) or i == 0 and self.caps[1]:
                    self.cap(i, "deferred")
                else:
                    self.release(i)


def _binding(binding, case):
    require(type(binding) is dict and set(binding) == {"descriptor", "programs", "kernel_header_hex", "kernel_imagebase_offset"},
            "timer compiled binding incomplete")
    descriptor = binding["descriptor"]
    require(type(descriptor) is dict and set(descriptor) == {"size_bytes", "sha256", "efi_file_offset", "efi_rva"}
            and descriptor["size_bytes"] == 144 and descriptor["sha256"] == digest(descriptor_bytes(case))
            and all(type(descriptor[k]) is int and 0 <= descriptor[k] < 1 << 32 for k in ("efi_file_offset", "efi_rva")),
            "timer compiled descriptor differs")
    require(type(binding["programs"]) is dict and set(binding["programs"]) == {"a", "b"}, "timer program set differs")
    for name, program in binding["programs"].items():
        stages = (["map", "writable_unmap", "readonly_remap", "delegate", "resumed_accounting", "unmap", "release", "final_accounting", "exit"]
                  if name == "a" else ["map", "read_confirmed", "resumed_accounting", "unmap", "stale_unmap", "exit"])
        labels = {f"region_{name}_{stage}_trap" for stage in stages} | {
            f"region_{name}_read", f"region_{name}_fail", f"timer_{name}_spin_start", f"timer_{name}_spin_end"}
        if name == "a":
            labels.add("timer_a_forged_irq")
        require(type(program) is dict and set(program) == {"size_bytes", "sha256", "efi_file_offset", "efi_rva", "offsets", "instruction_bytes"}
                and program["size_bytes"] == 4096 and type(program["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", program["sha256"])
                and all(type(program[k]) is int and 0 <= program[k] < 1 << 32 for k in ("efi_file_offset", "efi_rva"))
                and program["efi_rva"] % 4096 == 0 and type(program["offsets"]) is dict and set(program["offsets"]) == labels
                and type(program["instruction_bytes"]) is dict and set(program["instruction_bytes"]) == labels
                and all(type(v) is int and 0 <= v <= 4080 for v in program["offsets"].values())
                and len(set(program["offsets"].values())) == len(labels)
                and all(type(v) is str and re.fullmatch("[0-9a-f]{32}", v) for v in program["instruction_bytes"].values()),
                "timer program bindings malformed")
        offsets, instructions = program["offsets"], program["instruction_bytes"]
        ordered = [f"region_{name}_{s}_trap" for s in stages]
        require([offsets[x] for x in ordered] == sorted(offsets[x] for x in ordered), "timer compiled continuations reordered")
        require(offsets[f"region_{name}_map_trap"] < offsets[f"region_{name}_read"] < offsets[f"region_{name}_{stages[1]}_trap"]
                and offsets[f"region_{name}_{'delegate' if name == 'a' else 'read_confirmed'}_trap"] < offsets[f"timer_{name}_spin_start"]
                < offsets[f"timer_{name}_spin_end"] < offsets[f"region_{name}_resumed_accounting_trap"],
                "timer actual read or spin is outside its compiled continuations")
        require(instructions[f"region_{name}_read"].startswith("488b10") and instructions[f"region_{name}_fail"].startswith("0f0b")
                and instructions[f"timer_{name}_spin_start"].startswith("49ffc3")
                and instructions[f"timer_{name}_spin_end"].startswith("b807000000"), "timer actual compiled read/spin/failure differs")
        for stage in stages:
            require(instructions[f"region_{name}_{stage}_trap"].startswith("4883f8" + ("05" if stage == "stale_unmap" else "00")),
                    "timer compiled status continuation differs")
        exit_bytes = bytes.fromhex(instructions[f"region_{name}_exit_trap"])
        require(exit_bytes[:6] == b"\x48\x83\xf8\x00\x0f\x85"
                and exit_bytes[10] == 0xe8 and exit_bytes[15] == 0x0f,
                "timer exit fatal-instruction position differs from compiled continuation")
        if name == "a":
            require(offsets["region_a_delegate_trap"] < offsets["timer_a_forged_irq"] < offsets["timer_a_spin_start"]
                    and instructions["timer_a_forged_irq"].startswith("cd20"), "timer forged interrupt instruction not compiled")
    require(binding["programs"]["a"]["sha256"] != binding["programs"]["b"]["sha256"], "timer programs alias")
    require(type(binding["kernel_header_hex"]) is str and re.fullmatch("(?:[0-9a-f]{2}){64,4096}", binding["kernel_header_hex"]),
            "timer original PE binding malformed")


def parse_transcript(case, data, returncode, stderr, binding):
    """Replay the complete bounded fixture; this does not authenticate captures."""
    require(case in CASES and type(returncode) is int and returncode == 33
            and type(stderr) is bytes and stderr == b"", "timer process did not finish cleanly")
    _binding(binding, case)
    trace = _Trace(data)
    live, reserved, kernel_root = _startup(trace, binding)
    require(binding["descriptor"]["efi_rva"] + 144 <= live["image_end"] - live["image_start"], "timer descriptor exceeds loaded image")
    trace.service("BEGIN", {"case": case, "version": 1, "programs": 2, "request_bytes": 96})
    trace.service("PROFILE", {**dict.fromkeys(("fsgsbase", "pce", "syscall", "sysenter", "fs_base", "gs_base", "kernel_gs_base", "ldtr", "debug_enabled", "osxsave"), 0), "cpu_count": 1, "fp": "legacy_fxsave"})
    clock = trace.service("CLOCK", {"source": "hpet64", "base": 0xfed00000, "capability": (10_000_000 << 32) | 0x8086a201,
        "period_fs": 10_000_000, "epoch_raw": ANY, "timers": 3, "apic_before": ANY, "apic_after": ANY, "pat": ANY,
        "master_mask": 255, "slave_mask": 255, "vector": 32, "kernel_if": 0, "user_if": 1, "qualification": "emulator_only"})
    require(all(type(clock[k]) is int for k in ("epoch_raw", "apic_before", "apic_after", "pat"))
            and clock["apic_before"] & (1 << 10) == 0 and clock["apic_after"] == clock["apic_before"] & ~(1 << 11)
            and clock["pat"] >> 24 & 0xff == 0, "timer local APIC/PAT routing differs")
    epoch = clock["epoch_raw"]

    def sample(raw, ns):
        require(type(raw) is int and type(ns) is int and epoch <= raw < 1 << 64
                and ns == (raw - epoch) * 10 and 0 <= ns < 1 << 64, "timer HPET conversion/overflow differs")
        return ns

    def timed(kind, expected, raw="raw", ns="now_ns"):
        row = trace.service(kind, {**expected, raw: ANY, ns: ANY})
        sample(row[raw], row[ns])
        return row

    def gap(start, end):
        sample(*start); sample(*end)
        require(end[1] >= start[1], "timer kernel gap regressed")
        trace.service("KERNEL_GAP", {"start_raw": start[0], "end_raw": end[0], "start_ns": start[1], "end_ns": end[1], "elapsed_ns": end[1] - start[1]})

    trace.service("CAP", {"domain": 1, "phase": "provision", "cap_slot": 2, "cap_generation": 1, "cap_domain": 1})
    require(trace.index < len(trace.rows), "timer backing absent")
    frame = trace.rows[trace.index][1].get("frame")
    trace.service("BACKING", {"phase": "ready", "frame": frame,
        "sha256": digest(b"".join((SEED ^ i).to_bytes(8, "little") for i in range(512)))})
    kernel_pool = (kernel_root, kernel_root + 129 * 4096)
    require(kernel_pool[1] <= live["image_end"], "timer kernel paging pool exceeds image")
    tasks, physical, roots = [], [frame], []
    for i in range(2):
        task = trace.service("TASK", {"domain": i + 1, "root": ANY,
            "code_physical": live["image_start"] + binding["programs"]["ab"[i]]["efi_rva"], "entry": CODE,
            "stack": STACK, "stack_physical": ANY, "stack_lease_slot": 2 * i, "stack_lease_generation": 1,
            "request": REQUEST, "request_physical": ANY, "request_lease_slot": 2 * i + 1,
            "request_lease_generation": 1, "generation": 1})
        require(type(task["root"]) is int and task["root"] % 4096 == 0
                and live["image_start"] <= task["root"] and task["root"] + 17 * 4096 <= live["image_end"]
                and _disjoint((task["root"], task["root"] + 17 * 4096), kernel_pool), "timer task root not private original image pool")
        tasks.append(task)
        roots.append((task["root"], task["root"] + 17 * 4096))
        physical.extend((task["stack_physical"], task["request_physical"]))
    require(_disjoint(*roots) and len(set(physical)) == 5
            and all(type(p) is int and 0 < p <= PROFILE["memory_bytes"] - 4096 and p % 4096 == 0
                    and all(_disjoint((p, p + 4096), r) for r in reserved) for p in physical), "timer backing/root aliases or exceeds admitted memory")
    code_ranges = [(t["code_physical"], t["code_physical"] + 4096) for t in tasks]
    require(_disjoint(*code_ranges) and all(live["image_start"] <= p[0] < p[1] <= live["image_end"]
            and all(_disjoint(p, r) for r in roots + [kernel_pool]) for p in code_ranges), "timer code/root pools overlap")
    limits = list(case_limits(case)[:2])
    admit = timed("ADMIT", {"hard_quantum_ns": QUANTUM_NS, "soft_target_ns": SOFT_NS,
        "budget_a": limits[0], "budget_b": limits[1], "deadline_a": ANY, "deadline_b": 0, "b_blocked": 1})
    deadline_a = admit["now_ns"] + case_limits(case)[2] if case == "deadline" else 0
    require(deadline_a < 1 << 64 and admit["deadline_a"] == deadline_a, "timer deadline not bound to admission")
    policy = _Policy(admit["now_ns"], limits, [deadline_a, 0])
    for i in range(2): policy.ledger(trace, i, "admit")
    memory = _Memory(trace, frame)
    previous, resumes, counters, fp_hash = [None, None], [0, 0], [0, 0], [None, None]
    tokens, spin_values, spin_finished = [0, 0], [0, 0], [None, None]
    irqs, spin_irqs, traps, requests = [0, 0], [0, 0], 0, 0
    last, last_task, switches, steps = (epoch, 0), None, 0, 0
    b_ready, forged, pending_probe, missed_arms, trap_bounds = False, False, False, 0, None
    stages = []
    plans = [[("map", 2), ("writable_unmap", 5), ("readonly_remap", 2), ("delegate", 3)]
             + ([("resumed_accounting", 7), ("unmap", 5), ("release", 6), ("final_accounting", 7), ("exit", 9)] if case == "preemption" else []),
             [("map", 2), ("read_confirmed", 7), ("resumed_accounting", 7),
              ("unmap" if case == "preemption" else "stale_unmap", 5), ("exit", 9)]]

    def terminal(i, reason):
        require(i not in memory.stopped and policy.states[i] in TERMINAL, "timer duplicate or nonterminal stop")
        trace.service("TERMINAL", {"task": i, "domain": i + 1, "reason": reason, "state": policy.states[i], "resumes": resumes[i]})
        memory.stopped.add(i)

    while len(memory.stopped) != 2:
        steps += 1
        require(steps <= 128, "timer dispatch bound exceeded")
        advanced = timed("ADVANCE", {})
        require(advanced["now_ns"] >= last[1], "timer advance precedes actual stop")
        policy.advance(advanced["now_ns"])
        for i in range(2):
            if i not in memory.stopped and policy.states[i] in TERMINAL:
                terminal(i, "clock")
                policy.ledger(trace, i, "terminal")
        memory.reap()
        for i in range(2):
            trace.service("MAILBOX", {"task": i, "spin_irqs": spin_irqs[i],
                "peer_stopped": int(1 - i in memory.stopped), "b_read_confirmed": int(b_ready)})
        if len(memory.stopped) == 2: break
        require(trace.index + 1 < len(trace.rows), "timer dispatch absent")
        start_row = trace.rows[trace.index + 1][1]
        start = start_row.get("start_raw"), start_row.get("start_ns")
        sample(*start)
        require(start[1] >= advanced["now_ns"], "timer dispatch sample precedes advance")
        i, _, hard, grant, soft = policy.dispatch(start[1])
        require(i not in memory.stopped and (i == 0 or memory.caps[1]), "timer resumed stopped/unbootstrapped task")
        gap(last, start)
        trace.service("DISPATCH", {"task": i, "domain": i + 1, "cpu": 0, "lease_generation": policy.generation,
            "task_slot": i, "task_generation": 1, "start_raw": start[0], "start_ns": start[1],
            "grant_ns": grant, "hard_ns": hard, "soft_ns": soft})
        policy.ledger(trace, i, "dispatch")
        pending_target = None
        next_kind = trace.rows[trace.index][0] if trace.index < len(trace.rows) else ""
        if next_kind == "TESSRYN_K03_TIMER_ARM_MISSED":
            missed = timed("ARM_MISSED", {"task": i, "generation": policy.generation, "soft_ns": soft, "hard_ns": hard})
            capture = missed["raw"], missed["now_ns"]
            require(capture[1] >= soft, "timer missed arm reported before soft target")
            reason, outcome = "arm_missed", "fail"
            missed_arms += 1
        else:
            initial = {k: 0 for k in REGS}
            initial.update(r2=CASES.index(case), r3=CAP1, rip=CODE, rsp=STACK + 4080,
                           cs=0x33, ss=0x2b, rflags=0x202, fp_sha256=RESET_HASH)
            trace.service("RESUME", {"task": i, "domain": i + 1, "generation": 1, "root": tasks[i]["root"],
                "first": int(resumes[i] == 0), "resumes": resumes[i], **(initial if previous[i] is None else previous[i])})
            resumes[i] += 1
            if last_task is not None and last_task != i: switches += 1
            last_task = i
            target_raw = epoch + (soft + 9) // 10
            arm = timed("ARM", {"task": i, "generation": policy.generation, "soft_ns": soft,
                "target_raw": target_raw, "readback_raw": target_raw, "vector": 32}, "armed_raw", "armed_ns")
            require(start[1] <= arm["armed_ns"] < soft and target_raw < 1 << 64, "timer arm was late or target overflowed")
            require(trace.index + 1 < len(trace.rows), "timer raw exception absent")
            raw = trace.take("TESSRYN_K01_EXCEPTION", dict.fromkeys(("vector", "error", "rip", "cs", "rflags", "rsp", "cr2"), ANY))
            tr = trace.service("TRAP", {**dict.fromkeys(TRAP_FIELDS, ANY), **raw,
                "task": i, "domain": i + 1, "root": tasks[i]["root"], "ss": 0x2b})
            require(all(type(tr[k]) is int for k in (REGS | {"rip", "rsp", "cs", "rflags", "frame", "trap_start", "trap_end", "vector", "error", "cr2"}))
                    and tr["cs"] == 0x33 and CODE <= tr["rip"] < CODE + 4096 and STACK <= tr["rsp"] < STACK + 4096
                    and tr["rflags"] & 0x202 == 0x202 and tr["rflags"] & ~0x10ad7 == 0 and tr["cr2"] == 0,
                    "timer actual CPL3 frame/profile differs")
            bounds = tr["trap_start"], tr["trap_end"], tr["frame"]
            require(bounds[0] % 16 == 0 and bounds[1] - bounds[0] == 32768 and bounds[2] == bounds[1] - 176
                    and live["image_start"] <= bounds[0] < bounds[1] <= live["image_end"]
                    and all(_disjoint(bounds[:2], r) for r in roots + code_ranges + [kernel_pool])
                    and (trap_bounds is None or bounds == trap_bounds), "timer raw frame escaped private trap stack")
            trap_bounds = bounds
            fp = tr["fp_sha256"]
            require(type(fp) is str and re.fullmatch("[0-9a-f]{64}", fp)
                    and (fp_hash[i] is None or fp == fp_hash[i]), "timer initialized task FP state changed")
            if counters[i]:
                require(tr["r2"] == CASES.index(case) and tr["r3"] == CAP1
                        and tr["r10"] == (0xaaaaaaaa55555555 if i == 0 else 0xbbbbbbbb66666666)
                        and tr["r11"] == (0x4141414141414141 if i == 0 else 0x4242424242424242), "timer initialized user sentinels changed")
            program = binding["programs"]["ab"[i]]
            spin = CODE + program["offsets"][f"timer_{'ab'[i]}_spin_start"] <= tr["rip"] < CODE + program["offsets"][f"timer_{'ab'[i]}_spin_end"]
            vector = tr["vector"]
            traps += 1
            if vector == 32:
                # An arbitrary authentic interrupt can land in initial setup or
                # helpers. Known UD2/padding paths cannot later continue to the
                # declared successful request/forged-interrupt sequence.
                offset = tr["rip"] - CODE
                exit_ud2 = program["offsets"][f"region_{'ab'[i]}_exit_trap"] + 15
                require(offset < program["offsets"][f"region_{'ab'[i]}_fail"]
                        and not exit_ud2 <= offset < exit_ud2 + 2,
                        "timer IRQ landed on a compiled fatal instruction or padding")
                require(tr["error"] == 0, "timer hardware IRQ error differs")
                irq = timed("IRQ", {"task": i, "generation": policy.generation, "target_raw": target_raw,
                    "isr_before": 1, "isr_after": 0, "irr_after": 0, "eoi": 0x60}, "capture_raw", "capture_ns")
                capture = irq["capture_raw"], irq["capture_ns"]
                require(capture[0] >= target_raw, "timer hardware IRQ preceded armed target")
                irqs[i] += 1
                reason, outcome = "irq", "yield"
                if spin:
                    require(counters[i] == (4 if i == 0 else 2) and not (case == "forged_irq" and i == 0),
                            "timer spin IRQ outside the actual executed program stage")
                    values = [counters[i], tokens[i], CASES.index(case), CAP1, tr["r4"], 0,
                              memory.charge[i], memory.charge[i], REQUEST, 96,
                              0xaaaaaaaa55555555 if i == 0 else 0xbbbbbbbb66666666,
                              0x4141414141414141 if i == 0 else 0x4242424242424242,
                              CAP1 if i == 0 else 0, 2 if i == 0 else 0, REQUEST]
                    require(all(tr[f"r{j}"] == v for j, v in enumerate(values))
                            and tr["r4"] >= spin_values[i], "timer spin heartbeat/context regressed")
                    spin_values[i] = tr["r4"]
                    spin_irqs[i] += 1
            else:
                probe = vector == 128 and case == "preemption" and i == 0 and tr["r0"] == 1 and not pending_probe
                cancel = timed("CANCEL", {"task": i, "generation": policy.generation, "pending_probe": int(probe),
                    "pending_before": ANY, "isr_before": 0, "pending_after": 0, "isr_after": 0}, "capture_raw", "capture_ns")
                require(cancel["pending_before"] in (0, 1), "timer cancellation hid an unknown IRQ source")
                capture = cancel["capture_raw"], cancel["capture_ns"]
                if cancel["pending_before"] == 1:
                    pending_target = target_raw
                if probe:
                    require(cancel["pending_before"] == 1 and capture[0] >= target_raw, "timer pending IRQ probe did not observe/drain the armed source")
                    pending_probe = True
                if vector == 13:
                    require(case == "forged_irq" and i == 0 and counters[0] == 4 and b_ready and not forged
                            and tr["error"] == 0x102 and tr["rip"] == CODE + program["offsets"]["timer_a_forged_irq"]
                            and tr["rflags"] == 0x10246 and tr["rsp"] == STACK + 4080,
                            "timer forged IRQ lacks actual bound #GP/read witness")
                    values = [4, MAP_A2, 3, CAP1, 0, 0, memory.charge[0], memory.charge[0], REQUEST, 96,
                              0xaaaaaaaa55555555, 0x4141414141414141, CAP1, 2, REQUEST]
                    require(all(tr[f"r{j}"] == v for j, v in enumerate(values)), "timer forged instruction user context differs")
                    reason, outcome, forged = "forged_irq", "fail", True
                else:
                    require(vector == 128 and tr["error"] == 0 and counters[i] < len(plans[i]), "timer unknown/replayed syscall or exception")
                    stage, opcode = plans[i][counters[i]]
                    counters[i] += 1
                    counter = counters[i]
                    require(tr["rip"] == CODE + program["offsets"][f"region_{'ab'[i]}_{stage}_trap"]
                            and tr["rsp"] == STACK + 4080 and tr["rflags"] == (0x202 | (4 if CASES.index(case).bit_count() % 2 == 0 else 0) if stage == "stale_unmap" else 0x246),
                            "timer syscall skipped its compiled user continuation")
                    if stage == "resumed_accounting":
                        require(spin_irqs[i] >= MIN_IRQS and spin_values[i] > 0
                                and (i == 1 and (case == "preemption" or 0 in memory.stopped)
                                     or i == 0 and 1 in memory.stopped), "timer user left busy loop before observed IRQ/peer-stop condition")
                        require(tr["r4"] >= spin_values[i], "timer post-spin user heartbeat regressed")
                        spin_finished[i] = tr["r4"]
                    heartbeat = spin_finished[i] if spin_finished[i] is not None else 0
                    rd, rc = (SEED, WRITTEN) if stage == "writable_unmap" else (WRITTEN, WRITTEN) if stage == "read_confirmed" else (MAP_A2, 0) if stage == "delegate" else (CAP1, 2) if i == 0 and stage == "resumed_accounting" else (0, 0)
                    values = [counter, tokens[i], CASES.index(case), CAP1, heartbeat, 0,
                              0 if counter == 1 else memory.charge[i], 0 if counter == 1 else memory.charge[i],
                              REQUEST, 96, 0xaaaaaaaa55555555 if i == 0 else 0xbbbbbbbb66666666,
                              0x4141414141414141 if i == 0 else 0x4242424242424242, rd, rc, REQUEST]
                    require(all(tr[f"r{j}"] == v for j, v in enumerate(values)), "timer actual request/read/preserved user registers differ at " + stage)
                    require(fp not in (RESET_HASH, "0" * 64) and fp != fp_hash[1 - i], "timer initialized task FP aliases reset/peer")
                    fp_hash[i] = fp
                    kwargs = {}
                    if opcode in (2, 3, 6): kwargs.update(cap=CAP1, domain=i + 1)
                    if opcode == 2: kwargs.update(length=4096, va=DATA, rights=7 if i == 0 and stage == "map" else 5)
                    if opcode == 3: kwargs.update(argument=2, length=4096, rights=5)
                    if opcode == 5: kwargs["argument"] = tokens[i]
                    trace.service("REQUEST", {"task": i, "caller": i + 1, "pointer": REQUEST, "length": 96,
                        "valid": 1, "request_id": counter, "bytes": _request_bytes(counter, opcode, **kwargs)})
                    value, cap_domain, status = 0, 0, 5 if stage == "stale_unmap" else 0
                    if stage in ("map", "readonly_remap"):
                        require(memory.caps[i] and not memory.revoked[i] and not memory.maps[i], "timer mapped absent/revoked authority")
                        memory.maps[i] = 2 if stage == "readonly_remap" else 1
                        memory.mapping(i, ("install",))
                        value = MAP_B if i else MAP_A2 if stage == "readonly_remap" else MAP_A1
                    elif stage in ("writable_unmap", "unmap"):
                        memory.retire(i)
                    elif stage == "stale_unmap":
                        require(memory.maps[i] == 0 and memory.revoked[i], "timer stale unmap without actual owner revocation")
                    elif stage == "delegate":
                        require(not memory.caps[1] and memory.maps[0] == 2, "timer duplicate delegation or writable sharing")
                        memory.cap(1, "delegate")
                        memory.caps[1] = True
                        value, cap_domain = CAP1, 2
                    elif stage == "release":
                        memory.release(i)
                    memory.reap()
                    control = "exit" if opcode == 9 else "continue"
                    trace.service("RESPONSE", {"task": i, "caller": i + 1, "request_id": counter, "opcode": opcode,
                        "status": status, "value": value, "cap_domain": cap_domain, "charged": memory.charge[i],
                        "committed": memory.charge[i], "reserved": 0, "control": control})
                    if stage == "delegate":
                        wake = timed("WAKE", {"task": 1})
                        require(wake["now_ns"] >= capture[1], "timer bootstrap wake preceded capture")
                        policy.wake(wake["now_ns"])
                    if i == 1 and stage == "read_confirmed": b_ready = True
                    previous[i] = {k: tr[k] for k in CONTEXT}
                    previous[i].update(r14=status, r12=value, r13=cap_domain, r7=memory.charge[i], r6=memory.charge[i], r5=0)
                    if stage in ("map", "readonly_remap"): tokens[i] = value
                    stages.append(f"{'ab'[i]}:{stage}")
                    requests += 1
                    reason, outcome = ("exit", "complete") if opcode == 9 else ("syscall", "yield")
            require(capture[1] >= arm["armed_ns"], "timer capture preceded actual arm")
            if vector != 128: previous[i] = {k: tr[k] for k in CONTEXT}
        require(trace.index < len(trace.rows), "timer actual stop account absent")
        account = trace.rows[trace.index][1]
        stop = account.get("stop_raw"), account.get("stop_ns")
        sample(*stop)
        require(stop[1] >= capture[1] and stop[1] >= policy.now, "timer stop precedes capture/service clock")
        # cancel samples before disabling/reading IRR. Pending may therefore
        # arise after capture, but cannot precede this arm at the later stop.
        require(pending_target is None or stop[0] >= pending_target, "timer cancellation pending IRQ precedes current arm target")
        policy.stop(stop[1], outcome)
        trace.service("ACCOUNT", {"task": i, "domain": i + 1, "lease_generation": policy.generation,
            "reason": reason, "outcome": outcome, "start_raw": start[0], "capture_raw": capture[0], "stop_raw": stop[0],
            "start_ns": start[1], "capture_ns": capture[1], "stop_ns": stop[1], "elapsed_ns": stop[1] - start[1],
            "grant_ns": grant, "hard_ns": hard, "late": int(stop[1] > hard), "state": policy.states[i],
            "irqs": irqs[i], "spin_irqs": spin_irqs[i]})
        last = stop
        policy.ledger(trace, i, "stop")
        if policy.states[i] in TERMINAL: terminal(i, reason)
        memory.reap()

    require(counters[1] == len(plans[1]) and policy.states[1] == "completed" and spin_irqs[1] >= MIN_IRQS
            and spin_values[1] > 0 and b_ready, "timer peer did not actually read, preempt, progress and complete")
    if case == "preemption":
        require(counters[0] == len(plans[0]) and policy.states[0] == "completed"
                and spin_irqs[0] >= MIN_IRQS and spin_values[0] > 0 and pending_probe,
                "timer preemption/pending-source experiment incomplete")
    elif case == "budget":
        require(counters[0] == 4 and spin_irqs[0] > 0 and spin_values[0] > 0 and policy.consumed[0] >= limits[0]
                and (policy.states[0] == "exhausted" or policy.states[0] == "failed" and policy.halted[0]), "timer lifetime budget was not actually enforced")
    elif case == "deadline":
        require(counters[0] == 4 and spin_irqs[0] > 0 and spin_values[0] > 0 and policy.now >= deadline_a
                and (policy.states[0] == "deadline" or policy.states[0] == "failed" and policy.halted[0]), "timer inclusive deadline was not actually enforced")
    else:
        require(counters[0] == 4 and forged and policy.states[0] == "failed", "timer forged IRQ experiment incomplete")
    require(policy.active is None and policy.reserved == [0, 0], "timer retained active CPU ownership")
    memory.reap()
    require(memory.caps == [False, False] and memory.maps == [0, 0] and memory.charge == [2, 2], "timer premature final ownership release")
    for i, task in enumerate(tasks):
        for j, (va, name) in enumerate(((STACK, "stack"), (REQUEST, "request"))):
            memory.mapping(i, RETIRE, 1, va, task[name + "_physical"], task[name + "_lease_slot"], 2 - j)
        trace.service("FINAL", {"domain": i + 1, "leaves": 0, "charged": 0, "committed": 0, "reserved": 0})
    for i in range(2): policy.ledger(trace, i, "final")
    require(trace.index < len(trace.rows), "timer shutdown gap absent")
    end_gap = trace.rows[trace.index][1]
    end = end_gap.get("end_raw"), end_gap.get("end_ns")
    gap(last, end)
    tenant = sum(policy.consumed)
    require(end[1] >= policy.now and end[1] >= tenant, "timer tenant/system conservation failed")
    trace.service("CLOCK_END", {"raw": end[0], "now_ns": end[1], "tenant_ns": tenant,
        "kernel_ns": end[1] - tenant, "pending_after": 0, "isr_after": 0, "generation": 0})
    trace.service("PASS", {"case": case, "allocated_pages": 0, "mappings": 0, "cpu_leases": 0,
        "context_switches": switches, "requests": requests, "irqs_a": irqs[0], "irqs_b": irqs[1],
        "spin_irqs_a": spin_irqs[0], "spin_irqs_b": spin_irqs[1], "qualification": "emulator_only"})
    require(trace.index == len(trace.rows), "timer trace has trailing/unknown evidence")
    return {"case": case, "requests": requests, "traps": traps, "dispatches": policy.generation,
        "context_switches": switches, "task_resumes": resumes, "irqs": irqs, "spin_irqs": spin_irqs,
        "pending_irq_probe": pending_probe, "missed_arms": missed_arms, "b_read_confirmed": b_ready,
        "stages": stages, "task_fp_sha256": fp_hash, "service_records": trace.records,
        "policy": [{"domain": i + 1, "state": policy.states[i], "limit_ns": limits[i],
                    "consumed_ns": policy.consumed[i], "reserved_ns": 0, "halted": policy.halted[i],
                    "deadline_ns": policy.deadlines[i]} for i in range(2)],
        "clock": {"epoch_raw": epoch, "period_fs": 10_000_000, "end_raw": end[0], "end_ns": end[1],
                  "tenant_ns": tenant, "kernel_ns": end[1] - tenant},
        "final_allocated_pages": 0, "final_mappings": 0, "final_cpu_leases": 0}
