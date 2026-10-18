"""Replay bounded two-CPU bootstrap evidence; offline capture remains unauthenticated."""
from __future__ import annotations
import re
import struct
from tools.k03_smp_protocol import CASES, PROFILE, MAX_LOG_BYTES, descriptor_bytes, digest, require
ANY = object()


def _fields(line):
    if line == "TESSRYN ORIGINAL KERNEL":
        return line, {}
    parts = line.split(" ")
    require(all(parts), "SMP trace has noncanonical whitespace")
    values = {}
    for part in parts[1:]:
        require(part.count("=") == 1, "SMP trace field malformed")
        key, value = part.split("=", 1)
        require(re.fullmatch(r"[a-z][a-z0-9_]*", key) and key not in values and value,
                "SMP trace field repeated or malformed")
        if key not in ("sha256", "fp_sha256", "bytes", "madt") and re.fullmatch(r"(?:0|[1-9][0-9]*|0x[0-9a-f]+)", value):
            value = int(value, 16 if value.startswith("0x") else 10)
            require(value < 1 << 64, "SMP trace integer exceeds u64")
        values[key] = value
    return parts[0], values


class _Trace:
    def __init__(self, data):
        require(type(data) is bytes and 0 < len(data) <= MAX_LOG_BYTES and data.endswith(b"\n"),
                "SMP stdout must be bounded complete bytes")
        require(all(b == 10 or 32 <= b < 127 for b in data), "SMP stdout is not canonical ASCII")
        self.rows = [_fields(line) for line in data.decode("ascii").splitlines()]
        self.index = 0

    def take(self, kind, expected):
        require(self.index < len(self.rows), "SMP trace ended before " + kind)
        actual_kind, fields = self.rows[self.index]
        self.index += 1
        require(actual_kind == kind and set(fields) == set(expected),
                "SMP marker/order/fields differ at " + kind)
        for key, value in expected.items():
            require(value is ANY or fields[key] == value, "SMP " + kind + " field differs: " + key)
        return fields

    def service(self, kind, expected):
        return self.take("TESSRYN_K03_SMP_" + kind, expected)


def _interval(start, end, limit=1 << 32):
    require(type(start) is int and type(end) is int and 0 < start < end <= limit,
            "SMP live interval invalid")
    return start, end


def _disjoint(a, b):
    return a[1] <= b[0] or b[1] <= a[0]


def _startup(trace, binding):
    trace.take("TESSRYN_K01_ENTRY", {})
    # The sole banner is intentionally not a key/value marker.
    require(trace.index < len(trace.rows) and trace.rows[trace.index] == ("TESSRYN ORIGINAL KERNEL", {}),
            "SMP original kernel banner missing")
    trace.index += 1
    fb = trace.take("TESSRYN_K01_FRAMEBUFFER", dict.fromkeys(
        ("status", "width", "height", "stride", "base", "format", "selection"), ANY))
    require(fb["status"] == "ready" and fb["format"] in ("rgbx", "bgrx")
            and fb["selection"] in ("firmware-console", "unique-gop")
            and all(type(fb[k]) is int for k in ("width", "height", "stride", "base"))
            and 0 < fb["width"] <= fb["stride"] <= 16384 and 0 < fb["height"] <= 16384,
            "SMP framebuffer profile differs")
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
                "SMP live ranges overlap or differ")
        require(live["image_end"] - live["image_start"] == binding["image_size"],
                "SMP loaded image extent differs from compiled PE")
        page = trace.take("TESSRYN_K01_PAGING_READY", {"cr3": ANY, "tables": ANY, "leaves": ANY, "physical_bits": 48, "guard": 0x7fffffe00000, "free_scope": "low-conventional"})
        require(type(page["cr3"]) is int and page["cr3"] % 4096 == 0
                and live["image_start"] <= page["cr3"] < live["image_end"]
                and type(page["tables"]) is int and 0 < page["tables"] <= 32
                and type(page["leaves"]) is int and 0 < page["leaves"] <= 4096,
                "SMP supervisor paging bounds invalid")
        reset = trace.take("TESSRYN_K01_RESET_POINTER", {"address": ANY, "method": "uefi-runtime"})
        require(type(reset["address"]) is int and 0 < reset["address"] < 1 << 32,
                "SMP reset pointer invalid")
        memory = trace.take("TESSRYN_K01_MEMORY_MAP_VALID", {"descriptors": ANY, "stride": ANY, "free_pages": ANY, "attempt": attempt})
        require(all(type(v) is int for v in memory.values()) and 0 < memory["descriptors"] <= 4096
                and 40 <= memory["stride"] <= 4096 and memory["stride"] % 8 == 0
                and 5 <= memory["free_pages"] <= (256 << 20) // 4096,
                "SMP memory map bounds invalid")
        stable = tuple(live[k + suffix] for k in ("image", "stack", "map", "gop") for suffix in ("_start", "_end")) + (live["scratch"], page["cr3"], reset["address"])
        require(first_handoff is None or first_handoff == stable, "SMP allocated handoff changed across firmware retry")
        first_handoff = stable
        if trace.index < len(trace.rows) and trace.rows[trace.index][0] == "TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY":
            trace.take("TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY", {})
            continue
        trace.take("TESSRYN_K01_EXIT_BOOT_SERVICES_OK", {})
        break
    else:
        raise ValueError("SMP firmware retry limit exceeded")
    owned = trace.take("TESSRYN_K01_CPU_OWNED", {"cr3": page["cr3"], "rsp": ANY, "rip": ANY, "gdt": "owned", "idt": "owned", "tss": "owned"})
    require(type(owned["rsp"]) is int and live["stack_start"] <= owned["rsp"] < live["stack_end"]
            and type(owned["rip"]) is int and live["image_start"] <= owned["rip"] < live["image_end"],
            "SMP initial kernel context is outside owned ranges")
    return live, ranges + [(live["scratch"], live["scratch"] + 4096)], page["cr3"]


def parse_madt(data):
    """Independent bounded table replay; checksum consistency is not authenticity."""
    require(type(data) is bytes and 44 <= len(data) <= 512 and data[:4] == b"APIC"
        and struct.unpack_from("<I", data, 4)[0] == len(data) and data[8] != 0 and sum(data) % 256 == 0,
        "SMP MADT header/checksum/length differs")
    require(struct.unpack_from("<I", data, 36)[0] == PROFILE["lapic"] and struct.unpack_from("<I", data, 40)[0] & ~1 == 0,
        "SMP MADT LAPIC address/flags differ")
    ids, seen, offset = [], set(), 44
    while offset < len(data):
        require(offset + 2 <= len(data), "SMP MADT entry truncated")
        kind, length = data[offset:offset + 2]
        require(2 <= length <= len(data) - offset, "SMP MADT entry length invalid")
        row = data[offset:offset + length]
        if kind in (0, 9):
            require(length == (8 if kind == 0 else 16), "SMP processor structure size differs")
            if kind == 0: ident, flags = row[3], struct.unpack_from("<I", row, 4)[0]
            else:
                require(row[2:4] == b"\0\0", "SMP x2APIC reserved bytes differ")
                ident, flags = struct.unpack_from("<II", row, 4)
            require(flags & ~3 == 0 and flags & 3 != 3 and ident not in seen, "SMP processor duplicate/reserved flags")
            seen.add(ident)
            if flags & 1:
                require(kind == 0 and ident != 255, "SMP active x2APIC/broadcast ID unsupported")
                ids.append(ident)
        elif kind == 5: raise ValueError("SMP LAPIC override unsupported")
        offset += length
    require(len(ids) == 2, "SMP MADT needs exactly two enabled CPUs")
    return sorted(ids)


def _binding(binding, case):
    require(type(binding) is dict and set(binding) == {"descriptor", "trampoline", "heartbeat", "image_size", "executable_ranges"}, "SMP binary binding incomplete")
    require(type(binding["image_size"]) is int and 0 < binding["image_size"] <= PROFILE["memory_bytes"] and binding["image_size"] % 4096 == 0,
        "SMP image extent differs")
    for name, length in (("descriptor", 96), ("trampoline", 4096), ("heartbeat", 8)):
        row = binding[name]
        require(type(row) is dict and set(row) == {"size_bytes", "sha256", "efi_file_offset", "efi_rva"}
            and type(row["size_bytes"]) is int and row["size_bytes"] == length
            and type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"])
            and all(type(row[k]) is int and 0 <= row[k] < 1 << 32 for k in ("efi_file_offset", "efi_rva"))
            and row["efi_rva"] + length <= binding["image_size"], "SMP descriptor/trampoline binding malformed")
    require(binding["descriptor"]["sha256"] == digest(descriptor_bytes(case)), "SMP compiled descriptor differs from case")
    require(binding["heartbeat"]["sha256"] == digest(bytes.fromhex("f048ff07f390ebf8")), "SMP compiled heartbeat instructions differ")
    ranges = binding["executable_ranges"]
    require(type(ranges) is list and 0 < len(ranges) <= 16 and all(type(r) is list and len(r) == 2
        and all(type(n) is int for n in r) and 0 <= r[0] < r[1] <= binding["image_size"] for r in ranges), "SMP executable image ranges malformed")


def parse_transcript(case, data, returncode, stderr, binding):
    require(case in CASES and type(returncode) is int and returncode == 33 and type(stderr) is bytes and stderr == b"", "SMP process did not finish cleanly")
    _binding(binding, case); trace = _Trace(data)
    live, reserved, root = _startup(trace, binding)
    require(all(live[k] <= PROFILE["memory_bytes"] for k in ("image_end", "stack_end", "map_end"))
        and live["scratch"] <= PROFILE["memory_bytes"] - 4096, "SMP RAM-owned ranges exceed admitted RAM")
    begin = trace.service("BEGIN", {"case": case, "cpus": 2, "bsp": ANY, "ap": ANY, "lapic": PROFILE["lapic"], "trampoline": ANY, "cr3": root})
    require(all(type(begin[k]) is int for k in ("bsp", "ap", "trampoline")) and 0 <= begin["bsp"] < 255 and 0 <= begin["ap"] < 255 and begin["bsp"] != begin["ap"], "SMP CPU identities invalid")
    low = begin["trampoline"]
    require(0 < low <= (1 << 20) - 4096 and low % 4096 == 0 and all(_disjoint((low, low + 4096), r) for r in reserved), "SMP low trampoline aliases live memory")
    topology = trace.service("TOPOLOGY", {"madt": ANY})["madt"]
    require(type(topology) is str and re.fullmatch("(?:[0-9a-f]{2}){44,512}", topology), "SMP raw MADT malformed")
    madt = bytes.fromhex(topology); ids = parse_madt(madt)
    require(ids == sorted((begin["bsp"], begin["ap"])), "SMP actual CPU IDs differ from raw MADT")
    clock = trace.service("CLOCK", {"period_fs": PROFILE["period_fs"], "start": ANY})
    require(type(clock["start"]) is int, "SMP HPET epoch invalid")

    def elapsed(start, end, minimum=0):
        require(type(start) is int and type(end) is int and clock["start"] <= start <= end < 1 << 64
            and minimum <= (end - start) * 10 < 1 << 64, "SMP raw HPET interval regressed/overflowed/too short")
        return (end - start) * 10

    def executable(rip):
        return type(rip) is int and any(live["image_start"] + a <= rip < live["image_start"] + b for a, b in binding["executable_ranges"])

    cpus = []
    for index in range(1 if case == "missing_ap" else 2):
        cpu = trace.service("CPU", {"cpu": index, "apic": begin["bsp" if index == 0 else "ap"], "rsp": ANY, "rip": ANY,
            "gdt": ANY, "idt": ANY, "tss": ANY, "cr3": root, "stack_start": ANY, "stack_end": ANY})
        require(all(type(v) is int for v in cpu.values()) and executable(cpu["rip"]) and cpu["stack_start"] <= cpu["rsp"] < cpu["stack_end"], "SMP actual CPU context is outside owned code/stack")
        if index == 0:
            require((cpu["stack_start"], cpu["stack_end"]) == (live["stack_start"], live["stack_end"]), "SMP BSP stack changed")
        else:
            require(cpu["stack_start"] % 4096 == 0 and cpu["stack_end"] - cpu["stack_start"] == 65536
                and live["image_start"] <= cpu["stack_start"] < cpu["stack_end"] <= live["image_end"], "SMP AP stack is not image-owned")
        for name, length in (("gdt", 40), ("idt", 4096), ("tss", 104)):
            require(cpu[name] % 8 == 0 and live["image_start"] <= cpu[name] and cpu[name] + length <= live["image_end"], "SMP CPU descriptor range invalid")
        cpus.append(cpu)
    ranges = [(cpu[name], cpu[name] + size) for cpu in cpus for name, size in (("gdt", 40), ("idt", 4096), ("tss", 104))]
    if len(cpus) == 2: ranges.append((cpus[1]["stack_start"], cpus[1]["stack_end"]))
    pool = (root, root + 129 * 4096)
    require(pool[1] <= live["image_end"] and all(_disjoint(r, pool) for r in ranges)
        and all(_disjoint(a, b) for i, a in enumerate(ranges) for b in ranges[i + 1:]), "SMP CPU descriptor/stack/paging ranges alias")
    if case == "missing_ap":
        rejection = trace.service("EXPECTED_REJECTION", {"reason": "ap-start-timeout", "start": ANY, "end": ANY, "timeout_ns": PROFILE["timeout_ns"]})
        duration = elapsed(rejection["start"], rejection["end"], PROFILE["timeout_ns"] + 10_000_000)
        require(trace.index == len(trace.rows), "SMP missing AP trace claims later progress")
        return {"case": case, "cpus_online": 1, "enabled_apic_ids": ids, "madt_sha256": digest(madt),
            "expected_rejection": "ap-start-timeout", "elapsed_ns": duration, "ipi_acknowledgments": 0, "capture_authentication": "unverified_offline"}
    work = trace.service("WORK", {"bsp": 4096, "ap": 4096, "total": 8192, "bsp_heartbeats": ANY, "ap_heartbeats": ANY, "ap_before": ANY, "start": ANY, "end": ANY})
    require(all(type(v) is int for v in work.values()) and work["bsp_heartbeats"] > 0 and work["ap_heartbeats"] > work["ap_before"] >= 0, "SMP two-CPU progress absent")
    work_ns = elapsed(work["start"], work["end"], 20_000_000); heartbeat = work["ap_heartbeats"]

    def raw_ipi(row):
        ap = cpus[1]
        require(all(type(row[k]) is int for k in ("rip", "cs", "rflags", "rsp", "frame", "cr3"))
            and row["rip"] - live["image_start"] - binding["heartbeat"]["efi_rva"] in (0, 4, 6)
            and row["cs"] == 8 and row["rflags"] & 0x202 == 0x202 and row["rflags"] & ~0x10ad7 == 0 and row["cr3"] == root
            and ap["stack_start"] <= row["rsp"] < ap["stack_end"] and row["rsp"] % 8 == 0
            and ap["stack_start"] <= row["frame"] and row["frame"] + 168 <= ap["stack_end"] and row["frame"] % 8 == 0
            and row["frame"] + 168 == row["rsp"] & ~15 and (row["frame"] & ~15) - 512 >= ap["stack_start"],
            "SMP actual IPI frame escaped the admitted AP context")

    raw = dict.fromkeys(("rip", "cs", "rflags", "rsp", "frame", "cr3"), ANY)
    for generation in (1, 2, 3):
        row = trace.service("IPI", {"generation": generation, "vector": 64, "before": 1, "after": 0, "ack": generation,
            "heartbeat_before": ANY, "heartbeat_after": ANY, **raw})
        require(type(row["heartbeat_before"]) is int and type(row["heartbeat_after"]) is int
            and row["heartbeat_after"] > row["heartbeat_before"] >= heartbeat, "SMP stale IPI acknowledgment/no continued AP progress")
        raw_ipi(row); heartbeat = row["heartbeat_after"]
    stop = trace.service("STOP", {"generation": 4, "vector": 65, "before": 2, "after": 0, "ack": 4,
        "heartbeat": ANY, "stable": ANY, "start": ANY, "end": ANY, **raw})
    require(type(stop["heartbeat"]) is int and stop["heartbeat"] >= heartbeat and stop["stable"] == stop["heartbeat"], "SMP AP progressed after terminal acknowledgment")
    raw_ipi(stop); require(type(stop["start"]) is int and stop["start"] >= work["end"] + 300_000, "SMP stop omits three mandatory one-millisecond IPI waits")
    stop_ns = elapsed(stop["start"], stop["end"], 20_000_000)
    trace.service("PASS", {"cpus": 2, "ipis": 3, "retained": "all"})
    require(trace.index == len(trace.rows), "SMP trailing/unknown evidence")
    return {"case": case, "cpus_online": 2, "enabled_apic_ids": ids, "madt_sha256": digest(madt), "increments": [4096, 4096],
        "total": 8192, "work_window_ns": work_ns, "ipi_acknowledgments": 3, "stop_generation": 4,
        "stop_window_ns": stop_ns, "final_heartbeat": stop["heartbeat"], "retained": "all", "capture_authentication": "unverified_offline"}
