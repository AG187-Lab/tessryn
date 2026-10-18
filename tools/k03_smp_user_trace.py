"""Replay source-bound isolated CPL3 observations; offline capture is unauthenticated."""
from __future__ import annotations
import re
import struct
from tools.k03_smp_user_protocol import CASES, PROFILE, MAX_LOG_BYTES, DESCRIPTOR_SIZE, descriptor_bytes, digest, require
from tools.k03_smp_protocol import descriptor_bytes as bootstrap_descriptor
from tools.k03_smp_trace import _startup, parse_madt, _interval, _disjoint, ANY as BOOTSTRAP_ANY
ANY = object()
LABELS = {"bsp_start", "loop_start", "loop_end", "warmup_start", "warmup_end", "yield", "after_yield", "peer_fault", "forged_fault"}


def _fields(line):
    if line == "TESSRYN ORIGINAL KERNEL": return line, {}
    parts = line.split(" "); require(all(parts), "SMP user trace whitespace is not canonical")
    values = {}
    for part in parts[1:]:
        require(part.count("=") == 1, "SMP user trace field malformed")
        key, value = part.split("=", 1)
        require(re.fullmatch(r"[a-z][a-z0-9_]*", key) and key not in values and value, "SMP user field repeated/malformed")
        if not key.endswith("sha256") and key not in ("bytes", "madt", "gpr", "fp_image") and re.fullmatch(r"(?:0|[1-9][0-9]*|0x[0-9a-f]+)", value):
            value = int(value, 16 if value.startswith("0x") else 10)
            require(value < 1 << 64, "SMP user integer exceeds u64")
        values[key] = value
    return parts[0], values


class _Trace:
    def __init__(self, data):
        require(type(data) is bytes and 0 < len(data) <= MAX_LOG_BYTES and data.endswith(b"\n")
            and all(byte == 10 or 32 <= byte < 127 for byte in data), "SMP user stdout is not bounded complete ASCII")
        self.rows = [_fields(line) for line in data.decode("ascii").splitlines()]; self.index = 0

    def take(self, kind, expected):
        require(self.index < len(self.rows), "SMP user trace ended before " + kind)
        actual, fields = self.rows[self.index]; self.index += 1
        require(actual == kind and set(fields) == set(expected), "SMP user marker/order/fields differ at " + kind)
        for key, value in expected.items():
            require(value is ANY or value is BOOTSTRAP_ANY or fields[key] == value, "SMP user field differs: " + kind + "/" + key)
        return fields

    def service(self, kind, expected): return self.take("TESSRYN_K03_SMP_USER_" + kind, expected)


def _binding(binding, case):
    require(type(binding) is dict and set(binding) == {"bootstrap", "descriptor", "program"}, "SMP user binding incomplete")
    base = binding["bootstrap"]
    require(type(base) is dict and set(base) == {"descriptor", "trampoline", "image_size", "executable_ranges"}
        and type(base["image_size"]) is int and 0 < base["image_size"] <= PROFILE["memory_bytes"] and base["image_size"] % 4096 == 0,
        "SMP user inherited image bounds differ")
    program = binding["program"]
    for row, size, extra in ((base["descriptor"], 96, set()), (base["trampoline"], 4096, set()),
            (binding["descriptor"], DESCRIPTOR_SIZE, set()), (program, 4096, {"offsets", "instruction_bytes"})):
        require(type(row) is dict and set(row) == {"size_bytes", "sha256", "efi_file_offset", "efi_rva"} | extra
            and type(row["size_bytes"]) is int and row["size_bytes"] == size
            and type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"])
            and all(type(row[key]) is int and 0 <= row[key] < 1 << 32 for key in ("efi_file_offset", "efi_rva"))
            and row["efi_rva"] + size <= base["image_size"], "SMP user binary span malformed")
    require(base["descriptor"]["sha256"] == digest(bootstrap_descriptor("rendezvous"))
        and binding["descriptor"]["sha256"] == digest(descriptor_bytes(case)), "SMP user case descriptor differs")
    require(program["efi_rva"] % 4096 == 0 and type(program["offsets"]) is dict and set(program["offsets"]) == LABELS
        and type(program["instruction_bytes"]) is dict and set(program["instruction_bytes"]) == LABELS,
        "SMP user program labels incomplete")
    offsets, instructions = program["offsets"], program["instruction_bytes"]
    require(all(type(offset) is int and 0 <= offset <= 4096 - 16 for offset in offsets.values())
        and all(type(data) is str and re.fullmatch("[0-9a-f]{32}", data) for data in instructions.values()), "SMP user instruction spans malformed")
    require(offsets["bsp_start"] == 0 and offsets["warmup_end"] == offsets["yield"]
        and all(instructions[name].startswith("66b82b00668ee8") for name in ("bsp_start", "warmup_start")),
        "SMP user bound entry does not exercise GS selector reload")
    require(offsets["loop_end"] == offsets["loop_start"] + 8 and instructions["loop_start"].startswith("f048ff07f390ebf8")
        and offsets["after_yield"] == offsets["yield"] + 2 and instructions["yield"].startswith("cd80")
        and instructions["peer_fault"].startswith("488b06") and instructions["forged_fault"].startswith("cd42") and offsets["warmup_start"] < offsets["warmup_end"],
        "SMP user bound loop/yield/fault instructions differ")
    ranges = base["executable_ranges"]
    require(type(ranges) is list and 0 < len(ranges) <= 16 and all(type(row) is list and len(row) == 2
        and all(type(n) is int for n in row) and 0 <= row[0] < row[1] <= base["image_size"] for row in ranges), "SMP user executable image bounds malformed")
    return base, program


def _raw_state(capture, cpu, case):
    require(type(capture["gpr"]) is str and re.fullmatch("[0-9a-f]{240}", capture["gpr"])
        and type(capture["fp_image"]) is str and re.fullmatch("[0-9a-f]{1024}", capture["fp_image"]),
        "SMP user raw GPR/FP image incomplete")
    expected = [0] * 15
    expected[2] = PROFILE["marker_seed"] + cpu; expected[3] = PROFILE["register_sentinel"] + cpu
    expected[8] = PROFILE["user_data"]; expected[9] = PROFILE["peer"]
    expected[13] = 0 if cpu == 1 and case == "rendezvous" else PROFILE["warmup_iterations"]
    expected[14] = 0x2b if cpu == 0 or case == "rendezvous" else 0
    require(struct.unpack("<15Q", bytes.fromhex(capture["gpr"])) == tuple(expected), "SMP user full GPR context crossed CPU/task ownership")
    raw = bytes.fromhex(capture["fp_image"]); mask = struct.unpack_from("<I", raw, 28)[0]
    require(mask != 0 and mask & ~0xffff == 0 and 0x1f80 & ~mask == 0, "SMP user hardware MXCSR mask invalid")
    expected_fp = bytearray(512); expected_fp[:2] = bytes.fromhex("7f03")
    struct.pack_into("<II", expected_fp, 24, 0x1f80, mask)
    struct.pack_into("<QQ", expected_fp, 160, PROFILE["register_sentinel"] + cpu, PROFILE["marker_seed"] + cpu)
    require(raw == expected_fp, "SMP user full FP image crossed CPU/task ownership")


def _walk(walk, space, seen):
    """Replay four real entries, never dereference a printed physical address."""
    require(all(type(value) is int for key, value in walk.items() if key != "kind"), "SMP user raw walk contains a non-u64")
    tables = [walk["t" + str(level)] for level in range(4)]
    entries = [walk["e" + str(level)] for level in range(4)]
    require(tables[0] == space["root"], "SMP user walk does not begin at its actual private CR3")
    address, kind = walk["va"], walk["kind"]
    absent = kind == "peer" and space["cpu"] == 1
    address_mask, ad = 0x0000fffffffff000, 0x60
    user, writable, executable = True, True, True
    active = []
    for level, (table, entry) in enumerate(zip(tables, entries)):
        require(table % 4096 == 0 and space["root"] <= table < space["root"] + 16 * 4096 and table not in active,
            "SMP user walk escaped/cycled its retained hardware table array")
        active.append(table)
        key = table, (address >> (39 - level * 9)) & 511
        require(key not in seen or seen[key] == entry, "SMP user raw walks contradict the same table slot")
        seen[key] = entry
        if entry & 1 == 0:
            require(absent and entry == 0 and level == 2 and all(value == 0 for value in tables[level + 1:] + entries[level + 1:]),
                "SMP user missing/uninitialized/forged walk termination")
            return
        user &= bool(entry & 4); writable &= bool(entry & 2); executable &= not bool(entry >> 63)
        huge = level == 2 and bool(entry & 0x80)
        if huge or level == 3:
            require(not absent and all(value == 0 for value in tables[level + 1:] + entries[level + 1:]),
                "SMP user peer missing assertion/terminal walk storage differs")
            if kind in ("code", "stack", "data", "peer"):
                physical = space[kind + "_phys"]
                flags = 5 | (2 if kind in ("stack", "data") else 0) | ((1 << 63) if kind != "code" else 0)
                require(level == 3 and not huge and entry & ~ad == physical | flags
                    and user and writable == (kind in ("stack", "data")) and executable == (kind == "code"),
                    "SMP user effective private 4KiB permissions/backing differ")
            else:
                mmio = kind in ("hpet", "lapic")
                physical = address & ~((2 << 20) - 1)
                flags = 0x83 | (((1 << 63) | 0x18) if mmio else 0)
                require(level == 2 and huge and entry & ~ad == physical | flags and not user and writable
                    and executable == (not mmio), "SMP user supervisor identity alias or UC/NX MMIO mapping differs")
            return
        require(level < 3 and entry & ~(address_mask | 0x27) == 0 and entry & 3 == 3
            and tables[level + 1] == entry & address_mask and tables[level + 1] != space["root"],
            "SMP user private page-table child link/flags differ")
    raise ValueError("SMP user raw walk has no terminal leaf")


def parse_transcript(case, data, returncode, stderr, binding):
    require(case in CASES and type(returncode) is int and returncode == 33 and type(stderr) is bytes and stderr == b"",
        "SMP user process did not finish cleanly")
    base, program = _binding(binding, case); trace = _Trace(data)
    live, reserved, bootstrap_root = _startup(trace, base)
    image = (live["image_start"], live["image_end"])
    require(all(live[key] <= PROFILE["memory_bytes"] for key in ("image_end", "stack_end", "map_end"))
        and live["scratch"] <= PROFILE["memory_bytes"] - 4096, "SMP user RAM-owned handoff exceeds admitted RAM")
    begin = trace.take("TESSRYN_K03_SMP_BEGIN", {"case": "rendezvous", "cpus": 2, "bsp": ANY, "ap": ANY,
        "lapic": PROFILE["lapic"], "trampoline": ANY, "cr3": bootstrap_root})
    require(all(type(begin[key]) is int for key in ("bsp", "ap", "trampoline")) and 0 <= begin["bsp"] < 255
        and 0 <= begin["ap"] < 255 and begin["bsp"] != begin["ap"], "SMP user CPU identities invalid")
    low = begin["trampoline"]
    require(0 < low <= (1 << 20) - 4096 and low % 4096 == 0 and all(_disjoint((low, low + 4096), row) for row in reserved),
        "SMP user trampoline aliases original live memory")
    madt_hex = trace.take("TESSRYN_K03_SMP_TOPOLOGY", {"madt": ANY})["madt"]
    require(type(madt_hex) is str and re.fullmatch("(?:[0-9a-f]{2}){44,512}", madt_hex), "SMP user raw MADT malformed")
    madt = bytes.fromhex(madt_hex); ids = parse_madt(madt)
    require(ids == sorted((begin["bsp"], begin["ap"])), "SMP user actual CPU IDs differ from MADT")
    clock = trace.take("TESSRYN_K03_SMP_CLOCK", {"period_fs": PROFILE["period_fs"], "start": ANY})
    require(type(clock["start"]) is int, "SMP user HPET epoch invalid")

    def elapsed(start, end, minimum=0):
        require(type(start) is int and type(end) is int and clock["start"] <= start <= end < 1 << 64
            and minimum <= (end - start) * 10 < 1 << 64, "SMP user HPET interval regressed/overflowed/too short")
        return (end - start) * 10

    def executable(rip):
        return type(rip) is int and any(image[0] + a <= rip < image[0] + b for a, b in base["executable_ranges"])

    bootstrap_cpus = []
    bootstrap_ranges = [(bootstrap_root, bootstrap_root + 129 * 4096)]
    for cpu in (0, 1):
        row = trace.take("TESSRYN_K03_SMP_CPU", {"cpu": cpu, "apic": begin["bsp" if cpu == 0 else "ap"],
            "rsp": ANY, "rip": ANY, "gdt": ANY, "idt": ANY, "tss": ANY, "cr3": bootstrap_root, "stack_start": ANY, "stack_end": ANY})
        require(all(type(value) is int for value in row.values()) and executable(row["rip"])
            and row["stack_start"] <= row["rsp"] < row["stack_end"], "SMP user inherited CPU context escaped owned stack/code")
        if cpu == 0:
            require((row["stack_start"], row["stack_end"]) == (live["stack_start"], live["stack_end"]), "SMP user BSP stack changed")
        else:
            require(row["stack_start"] % 4096 == 0 and row["stack_end"] - row["stack_start"] == 65536
                and image[0] <= row["stack_start"] < row["stack_end"] <= image[1], "SMP user AP startup stack is not image-owned")
            bootstrap_ranges.append((row["stack_start"], row["stack_end"]))
        for name, length in (("gdt", 40), ("idt", 4096), ("tss", 104)):
            require(row[name] % 8 == 0 and image[0] <= row[name] and row[name] + length <= image[1], "SMP user inherited descriptor range invalid")
            bootstrap_ranges.append((row[name], row[name] + length))
        bootstrap_cpus.append(row)
    require(all(_disjoint(a, b) for index, a in enumerate(bootstrap_ranges) for b in bootstrap_ranges[index + 1:]),
        "SMP user inherited CPU descriptor/stack/paging ranges alias")
    trace.service("BEGIN", {"case": case, "cpus": 2, "vector": 66})
    spaces = []
    owned = list(bootstrap_ranges)
    for cpu in (0, 1):
        row = trace.service("SPACE", {"cpu": cpu, "apic": begin["bsp" if cpu == 0 else "ap"], "root": ANY, "root_end": ANY,
            "code_phys": ANY, "stack_phys": ANY, "data_phys": ANY, "peer_phys": ANY,
            "code": PROFILE["user_code"], "stack": PROFILE["user_stack"], "data": PROFILE["user_data"], "peer": PROFILE["peer"],
            "leaves": 4 if cpu == 0 else 3, "gdt": ANY, "idt": ANY, "tss": ANY,
            "trap_start": ANY, "trap_end": ANY, "fault_start": ANY, "fault_end": ANY,
            "context": ANY, "marker": PROFILE["marker_seed"] + cpu})
        require(all(type(value) is int for value in row.values()), "SMP user private-space fact is not a u64")
        require(row["root_end"] == row["root"] + PROFILE["root_pool_pages"] * 4096, "SMP user complete private root object extent differs")
        for name, length, alignment in (("root", PROFILE["root_pool_pages"] * 4096, 4096), ("code_phys", 4096, 4096),
                ("stack_phys", 4096, 4096), ("data_phys", 4096, 4096), ("gdt", 56, 8), ("idt", 4096, 8),
                ("tss", 104, 8), ("context", PROFILE["context_bytes"], 16)):
            require(row[name] % alignment == 0 and image[0] <= row[name] and row[name] + length <= image[1],
                "SMP user private range escaped image ownership/alignment: " + name)
            owned.append((row[name], row[name] + length))
        for name in ("trap", "fault"):
            start, end = row[name + "_start"], row[name + "_end"]
            require(start % 4096 == 0 and end - start == 65536 and image[0] <= start < end <= image[1],
                "SMP user private trap/fault stack extent invalid")
            owned.append((start, end))
        if cpu == 0:
            require(row["peer_phys"] % 4096 == 0 and image[0] <= row["peer_phys"] and row["peer_phys"] + 4096 <= image[1],
                "SMP user BSP peer page is not privately image-owned")
            owned.append((row["peer_phys"], row["peer_phys"] + 4096))
        else: require(row["peer_phys"] == 0, "SMP user AP claims a peer backing page")
        state = trace.service("STATE", {"cpu": cpu, "cr0": ANY, "cr4": ANY, "efer": ANY, "gsbase": row["context"], "user_gsbase": 0,
            "gdt": row["gdt"], "idt": row["idt"], "tss": row["tss"], "tr": 24, "ldtr": 0, "dr7": 0x400})
        require(all(type(value) is int for value in state.values()) and state["cr0"] == 0x80010033
            and state["cr4"] & 0x620 == 0x620 and state["cr4"] & ~0x678 == 0 and state["efer"] == 0xd00,
            "SMP user privileged control/FP/GS/syscall admission differs")
        seen_walks = {}
        for kind, address in (("code", row["code"]), ("stack", row["stack"]), ("data", row["data"]), ("peer", row["peer"]),
                ("code_alias", row["code_phys"]), ("stack_alias", row["stack_phys"]), ("data_alias", row["data_phys"]),
                ("hpet", PROFILE["hpet"]), ("lapic", PROFILE["lapic"])):
            walk = trace.service("WALK", {"cpu": cpu, "kind": kind, "va": address,
                **dict.fromkeys(tuple("t" + str(level) for level in range(4)) + tuple("e" + str(level) for level in range(4)), ANY)})
            _walk(walk, row, seen_walks)
        trace.service("PAYLOAD", {"cpu": cpu, "phase": "before", "sha256": program["sha256"]})
        spaces.append(row)
    require(all(_disjoint(a, b) for index, a in enumerate(owned) for b in owned[index + 1:]),
        "SMP user private CPU descriptors/stacks/roots/context/backing alias")
    overlap = trace.service("OVERLAP", dict.fromkeys(("bsp_before", "bsp_after", "ap_before", "ap_after", "start", "end"), ANY))
    require(all(type(value) is int for value in overlap.values()) and overlap["bsp_after"] > overlap["bsp_before"] > 0
        and overlap["ap_before"] == 0 and overlap["ap_after"] == (PROFILE["warmup_iterations"] if case == "rendezvous" else 0),
        "SMP user concurrent BSP/AP observations absent")
    overlap_ns = elapsed(overlap["start"], overlap["end"])
    require(overlap_ns > 0, "SMP user overlap interval is empty")

    def trap(cpu, stage):
        row = spaces[cpu]
        vector, error = (66, 0) if stage == "ipi" else ((128, 0) if stage == "warmup" else ((14, 4) if case == "peer_read" else (13, 0x212)))
        capture = trace.service("TRAP", {"cpu": cpu, "stage": stage, "vector": vector, "error": error, "rip": ANY, "cs": 0x33,
            "rflags": ANY, "rsp": PROFILE["user_stack"] + 4096 - 16, "ss": 0x2b, "cr2": ANY, "frame": row["trap_end"] - 176,
            "fp": row["trap_end"] - 176 - 512, "root": row["root"], "apic": row["apic"],
            "r12": PROFILE["register_sentinel"] + cpu, "r13": PROFILE["marker_seed"] + cpu,
            "xmm0lo": PROFILE["register_sentinel"] + cpu, "xmm0hi": PROFILE["marker_seed"] + cpu,
            "isr_before": 4 if stage == "ipi" else 0, "isr_after": 0, "generation": 1 if stage == "ipi" else 0,
            "marker": PROFILE["marker_seed"] + cpu, "heartbeat": ANY, "kernel_rsp": ANY, "kernel_cr3": bootstrap_root, "gpr": ANY, "fp_image": ANY})
        require(all(type(value) is int for key, value in capture.items() if key not in ("stage", "gpr", "fp_image"))
            and capture["rflags"] & 0x202 == 0x202 and capture["rflags"] & ~0x10ad7 == 0,
            "SMP user raw CPL3 flags/frame values invalid")
        _raw_state(capture, cpu, case)
        stack = bootstrap_cpus[cpu]
        require(capture["kernel_rsp"] % 16 == 0 and stack["stack_start"] <= capture["kernel_rsp"]
            and capture["kernel_rsp"] + 576 <= stack["stack_end"], "SMP user protected kernel continuation escaped its CPU stack")
        require(row["trap_start"] <= capture["fp"] and capture["fp"] + 512 == capture["frame"] and capture["frame"] + 176 == row["trap_end"],
            "SMP user raw frame/FP storage escaped actual TSS trap stack")
        if stage == "ipi":
            require(capture["rip"] - PROFILE["user_code"] - program["offsets"]["loop_start"] in (0, 4, 6)
                and (capture["heartbeat"] > PROFILE["warmup_iterations"] if cpu == 1 else capture["heartbeat"] >= overlap["bsp_after"]),
                "SMP user hardware IPI did not interrupt the bound progressing user loop")
        elif stage == "warmup":
            require(capture["rip"] == PROFILE["user_code"] + program["offsets"]["after_yield"]
                and capture["heartbeat"] == PROFILE["warmup_iterations"], "SMP user finite warmup/yield continuation differs")
        else:
            require(capture["rip"] == PROFILE["user_code"] + program["offsets"]["peer_fault" if case == "peer_read" else "forged_fault"]
                and capture["heartbeat"] == 0, "SMP user protection fault did not occur at bound original instruction")
            if case == "peer_read": require(capture["cr2"] == PROFILE["peer"], "SMP user peer fault CR2 differs")
        return capture

    first_trap = trap(1, "warmup" if case == "rendezvous" else "fault")
    bsp_trap = trap(0, "ipi")
    ap_trap = None; post_fault_ns = None
    if case == "rendezvous": ap_trap = trap(1, "ipi")
    else:
        progress = trace.service("FAULT_PROGRESS", dict.fromkeys(("before", "after", "start", "end"), ANY))
        require(all(type(value) is int for value in progress.values()) and progress["after"] > progress["before"] >= overlap["bsp_after"]
            and progress["start"] >= overlap["end"], "SMP user BSP progress does not follow actual AP fault")
        post_fault_ns = elapsed(progress["start"], progress["end"], PROFILE["window_ns"])
        require(bsp_trap["heartbeat"] >= progress["after"], "SMP user BSP IPI predates post-fault progress")
    stop = trace.service("STOP", {"cpu": 1, "generation": 1, "heartbeat": ANY, "stable": ANY, "start": ANY, "end": ANY})
    require(all(type(value) is int for value in stop.values()) and stop["heartbeat"] == stop["stable"]
        and stop["heartbeat"] == (ap_trap["heartbeat"] if ap_trap is not None else 0)
        and stop["start"] >= overlap["end"], "SMP user AP progressed after terminal acknowledgment")
    stop_ns = elapsed(stop["start"], stop["end"], PROFILE["window_ns"])
    if case == "rendezvous": require((stop["start"] - overlap["end"]) * 10 >= PROFILE["window_ns"], "SMP user resumed AP observation interval too short")
    if case != "rendezvous": require(stop["start"] >= progress["end"], "SMP user terminal observation predates fault progress")
    for cpu in (0, 1): trace.service("PAYLOAD", {"cpu": cpu, "phase": "after", "sha256": program["sha256"]})
    trace.service("PASS", {"cpus": 2, "ipis": 2 if case == "rendezvous" else 1, "faults": 0 if case == "rendezvous" else 1, "retained": "all"})
    require(trace.index == len(trace.rows), "SMP user trailing/unknown evidence")
    return {"case": case, "cpus_online": 2, "enabled_apic_ids": ids, "madt_sha256": digest(madt),
        "private_roots": [row["root"] for row in spaces], "program_sha256": program["sha256"], "payload_checks": 4,
        "user_traps": 3 if case == "rendezvous" else 2, "ipi_acknowledgments": 2 if case == "rendezvous" else 1,
        "protection_fault": None if case == "rendezvous" else ("page-fault" if case == "peer_read" else "general-protection"),
        "bsp_heartbeat": bsp_trap["heartbeat"], "ap_heartbeat": stop["heartbeat"], "overlap_window_ns": overlap_ns,
        "post_fault_window_ns": post_fault_ns, "stop_window_ns": stop_ns, "retained": "all", "capture_authentication": "unverified_offline"}
