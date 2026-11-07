"""Independently replay original timer, trap, reservation and stop observations."""
from __future__ import annotations

import re
import struct

from tools.k02_region_protocol import digest, require
from tools.k03_smp_budget_protocol import (AP_TIMER_MULTIPLIER, DESCRIPTOR_SIZE, DIVIDE_CONFIG, DIVIDER,
    DOMAIN, PROFILE, SCENARIOS, VECTOR, descriptor_bytes)
from tools.k03_smp_trace import _disjoint, _startup, parse_madt
from tools.k03_smp_user_protocol import MAX_LOG_BYTES
from tools.k03_smp_user_trace import ANY, _Trace, _binding as context_binding, _fields, _walk

TICK_NS = PROFILE["period_fs"] // 1_000_000
ROUNDING_NS = 20
IRQ_BIT = 1 << (VECTOR % 32)
U32_MAX = (1 << 32) - 1


def _row(line):
    # IOAPIC low redirection words are one byte string, even when all digits.
    if not line.startswith("TESSRYN_K03_SMP_BUDGET_IRQS "):
        return _fields(line)
    parts = line.split(" ")
    raw = [part[5:] for part in parts if part.startswith("rtes=")]
    require(len(raw) == 1 and re.fullmatch(r"[0-9a-f]{192}", raw[0]), "SMP budget raw IOAPIC redirections malformed")
    marker, fields = _fields(" ".join(part for part in parts if not part.startswith("rtes=")))
    return marker, {**fields, "rtes": raw[0]}


class _BudgetTrace(_Trace):
    def __init__(self, data):
        require(type(data) is bytes and 0 < len(data) <= MAX_LOG_BYTES and data.endswith(b"\n")
            and all(byte == 10 or 32 <= byte < 127 for byte in data), "SMP budget stdout is not bounded complete ASCII")
        self.rows = [_row(line) for line in data.decode("ascii").splitlines()]; self.index = 0


def _any(*names):
    return dict.fromkeys(names, ANY)


def _integers(row, *excluded):
    require(all(type(value) is int for key, value in row.items() if key not in excluded), "SMP budget record has a non-integer field")
    return row


def _budget(trace, kind, fields):
    return trace.take("TESSRYN_K03_SMP_BUDGET_" + kind, fields)


def _boot(trace, base):
    live, reserved, root = _startup(trace, base)
    image = live["image_start"], live["image_end"]
    require(max(live[key] for key in ("image_end", "stack_end", "map_end")) <= PROFILE["memory_bytes"]
        and live["scratch"] <= PROFILE["memory_bytes"] - 4096, "SMP budget startup ranges exceed admitted RAM")
    begin = trace.take("TESSRYN_K03_SMP_BEGIN", {"case": "rendezvous", "cpus": 2, **_any("bsp", "ap", "trampoline"),
        "lapic": PROFILE["lapic"], "cr3": root})
    apics = [begin["bsp"], begin["ap"]]; low = begin["trampoline"]
    require(all(type(apic) is int and 0 <= apic < 255 for apic in apics) and apics[0] != apics[1]
        and type(low) is int and 0 < low <= (1 << 20) - 4096 and low % 4096 == 0
        and all(_disjoint((low, low + 4096), row) for row in reserved), "SMP budget bootstrap identities/trampoline differ")
    raw = trace.take("TESSRYN_K03_SMP_TOPOLOGY", {"madt": ANY})["madt"]
    require(type(raw) is str and re.fullmatch(r"(?:[0-9a-f]{2}){44,512}", raw), "SMP budget malformed raw MADT")
    madt = bytes.fromhex(raw)
    require(parse_madt(madt) == sorted(apics), "SMP budget CPU identities differ from MADT")
    clock = _integers(trace.take("TESSRYN_K03_SMP_CLOCK", {"period_fs": PROFILE["period_fs"], "start": ANY}))["start"]
    owned = [(root, root + 129 * 4096)]
    require(owned[0][1] <= image[1], "SMP budget common root object escaped image")
    stacks = []
    for cpu, apic in enumerate(apics):
        row = _integers(trace.take("TESSRYN_K03_SMP_CPU", {"cpu": cpu, "apic": apic, "cr3": root,
            **_any("rsp", "rip", "gdt", "idt", "tss", "stack_start", "stack_end")}))
        stack = row["stack_start"], row["stack_end"]; stacks.append(stack)
        require(stack[0] <= row["rsp"] < stack[1] and any(image[0] + lo <= row["rip"] < image[0] + hi for lo, hi in base["executable_ranges"]),
            "SMP budget initial kernel CPU context escaped its stack or executable image")
        if cpu == 0:
            require(stack == (live["stack_start"], live["stack_end"]), "SMP budget BSP stack differs from handoff")
        else:
            require(stack[1] - stack[0] == 65536 and stack[0] % 4096 == 0 and image[0] <= stack[0] < stack[1] <= image[1],
                "SMP budget AP kernel stack escaped image"); owned.append(stack)
        for key, size in (("gdt", 40), ("idt", 4096), ("tss", 104)):
            require(row[key] % 8 == 0 and image[0] <= row[key] <= image[1] - size, "SMP budget inherited descriptor range differs")
            owned.append((row[key], row[key] + size))
    return image, root, apics, clock, stacks, owned, digest(madt)


def _spaces(trace, apics, image, owned, program):
    spaces = []
    for cpu, apic in enumerate(apics):
        row = _integers(trace.service("SPACE", {"cpu": cpu, "apic": apic,
            **_any("root", "root_end", "code_phys", "stack_phys", "data_phys", "peer_phys", "gdt", "idt", "tss",
                   "trap_start", "trap_end", "fault_start", "fault_end", "context"),
            "code": PROFILE["user_code"], "stack": PROFILE["user_stack"], "data": PROFILE["user_data"], "peer": PROFILE["peer"],
            "leaves": 4 if cpu == 0 else 3, "marker": PROFILE["marker_seed"] + cpu}))
        pool = PROFILE["root_pool_pages"] * 4096
        require(row["root_end"] == row["root"] + pool and (row["peer_phys"] == 0) == (cpu == 1),
            "SMP budget private root extent/peer mapping differs")
        ranges = [("root", pool, 4096), ("code_phys", 4096, 4096), ("stack_phys", 4096, 4096), ("data_phys", 4096, 4096),
            ("gdt", 56, 8), ("idt", 4096, 8), ("tss", 104, 8), ("context", PROFILE["context_bytes"], 16)]
        if cpu == 0: ranges.append(("peer_phys", 4096, 4096))
        for kind in ("trap", "fault"):
            require(row[kind + "_end"] == row[kind + "_start"] + 65536, "SMP budget private stack extent differs")
            ranges.append((kind + "_start", 65536, 4096))
        for key, size, alignment in ranges:
            require(row[key] % alignment == 0 and image[0] <= row[key] <= image[1] - size, "SMP budget private space escaped image ownership")
            owned.append((row[key], row[key] + size))
        state = _integers(trace.service("STATE", {"cpu": cpu, "cr0": 0x80010033, "cr4": ANY, "efer": 0xd00, "gsbase": row["context"],
            "user_gsbase": 0, "gdt": row["gdt"], "idt": row["idt"], "tss": row["tss"], "tr": 24, "ldtr": 0, "dr7": 0x400}))
        require(state["cr4"] & 0x620 == 0x620 and state["cr4"] & ~0x678 == 0, "SMP budget privileged control-state admission differs")
        seen = {}
        for kind, va in (("code", row["code"]), ("stack", row["stack"]), ("data", row["data"]), ("peer", row["peer"]),
                ("code_alias", row["code_phys"]), ("stack_alias", row["stack_phys"]), ("data_alias", row["data_phys"]),
                ("hpet", PROFILE["hpet"]), ("lapic", PROFILE["lapic"])):
            _walk(trace.service("WALK", {"cpu": cpu, "kind": kind, "va": va, **_any("t0", "t1", "t2", "t3", "e0", "e1", "e2", "e3")}), row, seen)
        trace.service("PAYLOAD", {"cpu": cpu, "phase": "before", "sha256": program["sha256"]}); spaces.append(row)
    require(all(_disjoint(left, right) for index, left in enumerate(owned) for right in owned[index + 1:]),
        "SMP budget private roots, backing, stacks, descriptors or contexts alias")
    return spaces


def _calibration(trace, cpu, clock, epoch):
    row = _integers(_budget(trace, "CAL", {"cpu": cpu, "divider": DIVIDER, "divide_cfg": DIVIDE_CONFIG, "initial": U32_MAX,
        **_any("first_before", "first_after", "first_count", "last_before", "last_after", "last_count"), "stopped_count": 0, "irr": 0, "isr": 0}))
    lo = (row["last_before"] - row["first_after"]) * TICK_NS
    hi = (row["last_after"] - row["first_before"]) * TICK_NS
    span = (row["first_count"] - row["last_count"]) * DIVIDER
    require(clock <= row["first_before"] <= row["first_after"] < row["last_before"] <= row["last_after"] <= epoch
        and 0 < row["last_count"] < row["first_count"] <= U32_MAX and lo >= 5_000_000
        and lo - ROUNDING_NS <= span <= hi + ROUNDING_NS, "SMP budget independent LAPIC/HPET calibration differs")
    return {"minimum_ns": lo, "maximum_ns": hi, "count_interval_ns": span}


def _context(binding, case):
    if case != "fault":
        return context_binding(binding, "rendezvous")
    from tools.build_k03_smp_user import fault_entry_size

    require(type(binding) is dict and type(binding.get("program")) is dict,
        "SMP budget fault context binding incomplete")
    program = binding["program"]
    offsets, instructions = program.get("offsets"), program.get("instruction_bytes")
    require(type(offsets) is dict and type(instructions) is dict and "fault_start" in offsets and "fault_start" in instructions,
        "SMP budget compiled fault entry missing")
    inherited = {**program, "offsets": {name: value for name, value in offsets.items() if name != "fault_start"},
        "instruction_bytes": {name: value for name, value in instructions.items() if name != "fault_start"}}
    base, _ = context_binding({**binding, "program": inherited}, "rendezvous")
    start, encoded = offsets["fault_start"], instructions["fault_start"]
    require(type(start) is int and start == offsets["loop_end"] + 2
        and type(encoded) is str and re.fullmatch(r"(?:[0-9a-f]{2}){1,32}", encoded)
        and instructions["loop_end"] == ("0f0b" + encoded)[:32], "SMP budget fault entry span differs")
    code = bytes.fromhex(encoded)
    require(start + len(code) <= program["size_bytes"]
        and fault_entry_size(code, 0, offsets["loop_end"] - start, offsets["peer_fault"] - start) == len(code),
        "SMP budget fault entry instructions differ")
    return base, program


def _stop_trap(trace, cpu, lease, root, space, stack, program, heartbeat, *, fault):
    sentinel, marker = PROFILE["register_sentinel"] + cpu, PROFILE["marker_seed"] + cpu
    frame = space["trap_end"] - PROFILE["trap_frame_bytes"]
    fp = frame - PROFILE["fp_bytes"]
    fault_address = PROFILE["peer"] + 4096
    row = _integers(trace.service("TRAP", {"cpu": cpu, "stage": "fault" if fault else "timer",
        "vector": 14 if fault else VECTOR, "error": 4 if fault else 0,
        "rip": PROFILE["user_code"] + program["offsets"]["peer_fault"] if fault else ANY,
        "cs": 0x33, "rflags": ANY, "rsp": PROFILE["user_stack"] + 4096 - 16, "ss": 0x2b,
        "cr2": fault_address if fault else ANY,
        "frame": frame, "fp": fp, "root": space["root"], "apic": space["apic"], "r12": sentinel, "r13": marker,
        "xmm0lo": sentinel, "xmm0hi": marker, "isr_before": 0 if fault else IRQ_BIT, "isr_after": 0, "generation": lease,
        "marker": marker, "heartbeat": heartbeat, "kernel_rsp": ANY, "kernel_cr3": root, "gpr": ANY, "fp_image": ANY}),
        "stage", "gpr", "fp_image")
    require((fault or row["rip"] - PROFILE["user_code"] - program["offsets"]["loop_start"] in (0, 4, 6))
        and row["rflags"] & 0x202 == 0x202 and row["rflags"] & ~0x10ad7 == 0 and space["trap_start"] <= fp
        and row["kernel_rsp"] % 16 == 0 and stack[0] <= row["kernel_rsp"] <= stack[1] - 576,
        "SMP budget actual CPL3 stop/frame/continuation escaped its CPU")
    require(type(row["gpr"]) is str and re.fullmatch(r"[0-9a-f]{240}", row["gpr"])
        and type(row["fp_image"]) is str and re.fullmatch(r"[0-9a-f]{1024}", row["fp_image"]), "SMP budget full GPR or legacy FP image missing")
    rsi = fault_address if fault else PROFILE["peer"]
    expected = [0, 0, marker, sentinel, 0, 0, 0, 0, PROFILE["user_data"], rsi, 0, 0, 0, PROFILE["warmup_iterations"], 0x2b]
    require(struct.unpack("<15Q", bytes.fromhex(row["gpr"])) == tuple(expected), "SMP budget full GPR context differs")
    raw = bytes.fromhex(row["fp_image"]); mask, = struct.unpack_from("<I", raw, 28)
    require(0 < mask <= 0xffff and mask & 0x1f80 == 0x1f80, "SMP budget invalid hardware MXCSR mask")
    fp_expected = bytearray(512); struct.pack_into("<H", fp_expected, 0, 0x037f)
    struct.pack_into("<II", fp_expected, 24, 0x1f80, mask); struct.pack_into("<QQ", fp_expected, 160, sentinel, marker)
    require(raw == fp_expected, "SMP budget full legacy FP context differs")
    return row["rip"]


def _expiry(timer):
    # Pinned QEMU 11.1.2 counts N+1 divided virtual-clock ticks to one-shot
    # expiry. HPET floors that same virtual clock to 10 ns.
    delta = (timer["initial"] + 1) * DIVIDER
    return (timer["arm_before"] + delta // TICK_NS,
            timer["arm_after"] + (delta + TICK_NS - 1) // TICK_NS)


def _timer(trace, case, number, cpu, start, epoch, hard, resume, before):
    target = SCENARIOS[case].timer_ns * (AP_TIMER_MULTIPLIER if cpu == 1 else 1)
    initial = (target + DIVIDER - 1) // DIVIDER
    fault = case == "fault" and cpu == 0
    timer = _integers(_budget(trace, "TIMER", {"round": number, "cpu": cpu, "lease": number,
        **_any("arm_before", "arm_after", "entry", "capture", "retired", "peer_heartbeat", "heartbeat_after"),
        "initial": initial, "current": ANY if fault else 0, "irr_before": 0, "isr_before": 0 if fault else IRQ_BIT,
        "irr_after": 0, "isr_after": 0,
        "lvt_before": VECTOR, "lvt_after": 0x10000 | VECTOR, "retire_count": 0,
        "resume_rip": resume, "heartbeat_before": before}))
    early, late = _expiry(timer)
    require(start <= timer["arm_before"] <= timer["arm_after"] <= timer["entry"] <= timer["capture"] <= timer["retired"]
        and (timer["entry"] - epoch) * TICK_NS < hard and timer["entry"] < early
        and timer["heartbeat_after"] > before
        and (timer["retired"] - start) * TICK_NS <= PROFILE["timeout_ns"],
        "SMP budget timer entry, real one-shot expiry, or retirement bracket differs")
    if fault:
        require(timer["capture"] < early and 0 < timer["current"] <= initial
            and timer["heartbeat_after"] == before + 1, "SMP budget fault did not drain a live countdown after one user heartbeat")
        # The LAPIC count read falls between the trap clock sample and retirement.
        elapsed = (initial - timer["current"]) * DIVIDER
        lower = (timer["capture"] - timer["arm_after"]) * TICK_NS
        upper = (timer["retired"] - timer["arm_before"]) * TICK_NS
        require(lower - ROUNDING_NS <= elapsed <= upper + ROUNDING_NS,
            "SMP budget fault countdown contradicts its HPET bracket")
    else:
        require(timer["capture"] >= early, "SMP budget timer did not reach expiry")
    if case != "late":
        require((late - epoch) * TICK_NS + ROUNDING_NS < hard, "SMP budget normal timer has no margin before its hard policy bound")
    return timer


def parse_transcript(case, data, returncode, stderr, binding):
    require(case in SCENARIOS and type(returncode) is int and returncode == 33 and type(stderr) is bytes and stderr == b"", "SMP budget process did not finish cleanly")
    require(type(binding) is dict and set(binding) == {"context", "budget"}, "SMP budget compiled binding incomplete")
    base, program = _context(binding["context"], case)
    descriptor = binding["budget"]
    require(type(descriptor) is dict and set(descriptor) == {"size_bytes", "sha256", "efi_file_offset", "efi_rva"}
        and type(descriptor["size_bytes"]) is int and descriptor["size_bytes"] == DESCRIPTOR_SIZE and descriptor["sha256"] == digest(descriptor_bytes(case))
        and all(type(descriptor[key]) is int and 0 <= descriptor[key] < (1 << 32) for key in ("efi_file_offset", "efi_rva"))
        and descriptor["efi_rva"] + DESCRIPTOR_SIZE <= base["image_size"], "SMP budget descriptor differs from case")
    trace = _BudgetTrace(data); image, root, apics, clock, stacks, owned, madt_sha = _boot(trace, base)
    epoch = _integers(_budget(trace, "BEGIN", {"case": case, "cpus": 2, "domain": DOMAIN, "vector": VECTOR, "epoch": ANY}), "case")["epoch"]
    require(clock <= epoch, "SMP budget clock epoch precedes HPET activation")
    irqs = _budget(trace, "IRQS", {"version": 0x170020, "redirections": 24, "rtes": ANY}); rtes = irqs["rtes"]
    require(all(int(rtes[i:i + 8], 16) & 0x10000 for i in range(0, len(rtes), 8)), "SMP budget external IOAPIC routes were not all masked")
    spaces = _spaces(trace, apics, image, owned, program)
    calibration = [_calibration(trace, cpu, clock, epoch) for cpu in (0, 1)]
    scenario = SCENARIOS[case]; cap = scenario.cap_ns
    fault = case == "fault"
    consumed = reserved = 0; task_time = [0, 0]; previous_retired = epoch; previous_heartbeat = [0, 0]
    resume = [PROFILE["user_code"] + program["offsets"][entry] for entry in ("fault_start" if fault else "bsp_start", "bsp_start")]
    clipped = 0; overlap_ticks = []; reconciliations = []; denied = False; fault_peer = None
    for number in range(1, scenario.rounds + 1):
        grants = []; temporary = 0
        for cpu in (0, 1):
            grant = min(scenario.quantum_ns, cap - task_time[cpu], cap - consumed - temporary)
            require(grant > 0, "SMP budget admitted a CPU without shared grant capacity")
            if cpu == 1 and grant < scenario.quantum_ns and grant == cap - consumed - temporary:
                clipped += 1
            grants.append(grant); temporary += grant
        require(reserved == 0 and consumed + temporary <= cap, "SMP budget dispatched past its aggregate reservation cap")
        reserved = temporary
        batch = _integers(_budget(trace, "BATCH", {"round": number, "start": ANY, "ap_ready_heartbeat": ANY, "reserved": reserved,
            "consumed": consumed, "available": cap - consumed - reserved}))
        start = batch["start"]
        require(previous_retired <= start and batch["ap_ready_heartbeat"] > previous_heartbeat[1],
            "SMP budget reservation chronology or fresh AP user-progress witness differs")
        hard = [(start - epoch) * TICK_NS + grant for grant in grants]
        for cpu in (0, 1):
            _budget(trace, "GRANT", {"round": number, "cpu": cpu, "task": cpu, "task_generation": 1,
                "lease": number, "grant_ns": grants[cpu], "hard_ns": hard[cpu]})
        timers = []
        for cpu in (0, 1):
            timer = _timer(trace, case, number, cpu, start, epoch, hard[cpu], resume[cpu], previous_heartbeat[cpu])
            resume[cpu] = _stop_trap(trace, cpu, number, root, spaces[cpu], stacks[cpu], program,
                timer["heartbeat_after"], fault=fault and cpu == 0)
            timers.append(timer)
        bsp, ap = timers; earliest_ap, _ = _expiry(ap)
        require(ap["entry"] <= bsp["arm_before"] and bsp["capture"] + ROUNDING_NS // TICK_NS < earliest_ap
            and batch["ap_ready_heartbeat"] <= bsp["peer_heartbeat"], "SMP budget actual overlapping CPL3 execution is not established")
        require(all(previous_heartbeat[cpu ^ 1] < timer["peer_heartbeat"] <= timers[cpu ^ 1]["heartbeat_after"]
            for cpu, timer in enumerate(timers)), "SMP budget peer progress does not belong to both active CPL3 loops")
        if fault:
            fault_peer = _integers(_budget(trace, "FAULT_PEER", {"round": number,
                **_any("baseline_sample", "baseline_heartbeat", "sample", "heartbeat")}))
            require(bsp["retired"] <= fault_peer["baseline_sample"] <= fault_peer["sample"] < ap["capture"]
                and fault_peer["sample"] + ROUNDING_NS // TICK_NS < earliest_ap
                and bsp["peer_heartbeat"] <= fault_peer["baseline_heartbeat"] < fault_peer["heartbeat"] <= ap["heartbeat_after"],
                "SMP budget peer did not progress after BSP fault retirement and before its own timer")
        overlap_ticks.append(earliest_ap - bsp["capture"])
        previous_heartbeat = [timer["heartbeat_after"] for timer in timers]
        active = {0, 1}; order = sorted(active, key=lambda cpu: (timers[cpu]["retired"], cpu))
        for index, cpu in enumerate(order):
            retired = timers[cpu]["retired"]; elapsed = (retired - start) * TICK_NS
            late = (retired - epoch) * TICK_NS > hard[cpu]
            require(late == (case == "late"), "SMP budget did not produce the exact normal/late stop case")
            task_time[cpu] += elapsed; consumed += elapsed; reserved -= grants[cpu]; active.remove(cpu)
            available = max(0, cap - consumed - reserved); peer = cpu ^ 1
            halted = int(case == "late")
            state = "failed" if halted or (fault and cpu == 0) else "completed" if number == scenario.rounds else "runnable"
            peer_lease, peer_reserved = (number, grants[peer]) if peer in active else (0, 0)
            accounting = {"consumed": consumed, "reserved": reserved, "available": available,
                "halted": halted, "peer_lease": peer_lease, "peer_reserved": peer_reserved}
            _budget(trace, "ACCOUNT", {"round": number, "cpu": cpu, "lease": number, "retired": retired, "elapsed_ns": elapsed,
                "state": state, **accounting})
            reconciliations.append({"round": number, "cpu": cpu, "charged_ns": elapsed, "state": state, **accounting})
            if case in ("late", "fault") and index == 0:
                _budget(trace, "DENY", {"round": number, "cpu": cpu, "reason": "no-runnable-task", **accounting}); denied = True
        previous_retired = max(timer["retired"] for timer in timers)
    require(clipped == scenario.rounds and reserved == 0 and sum(task_time) == consumed
        and (consumed > cap if case == "late" else consumed < cap), "SMP budget required shared clipping/full charging absent")
    stop = _integers(_budget(trace, "STOP", {"ap_ack": 1, **_any("start", "end"), "cpu0": previous_heartbeat[0],
        "stable0": previous_heartbeat[0], "cpu1": previous_heartbeat[1], "stable1": previous_heartbeat[1]}))
    require(previous_retired <= stop["start"] and (stop["end"] - stop["start"]) * TICK_NS >= PROFILE["window_ns"],
        "SMP budget terminal AP ownership or stable observation window differs")
    for cpu in (0, 1): trace.service("PAYLOAD", {"cpu": cpu, "phase": "after", "sha256": program["sha256"]})
    irq_count = 1 if fault else 2 * scenario.rounds
    _budget(trace, "PASS", {"cpus": 2, "rounds": scenario.rounds, "irqs": irq_count,
        "consumed": consumed, "reserved": 0, "halted": int(case == "late"), "retained": "all"})
    require(trace.index == len(trace.rows), "SMP budget trailing or unknown evidence")
    return {"case": case, "cpus_online": 2, "enabled_apic_ids": apics, "madt_sha256": madt_sha,
        "private_roots": [space["root"] for space in spaces], "program_sha256": program["sha256"], "calibration": calibration,
        "rounds": scenario.rounds, "irq_count": irq_count, "shared_grant_clips": clipped,
        "overlap_expiry_margin_ticks": overlap_ticks, "cap_ns": cap, "consumed_ns": consumed, "task_consumed_ns": task_time,
        "reserved_ns": 0, "halted": case == "late", "denied_redispatch": denied, "reconciliation": reconciliations,
        "terminal_heartbeats": previous_heartbeat, "stop_window_ns": (stop["end"] - stop["start"]) * TICK_NS,
        "retained": "all", "capture_authentication": "unverified_offline",
        **({"fault_peer_progress": fault_peer} if fault else {})}
