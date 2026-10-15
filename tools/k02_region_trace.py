"""Strict acceptance of the original, image-bound, single-CPU region fixture.

This is an offline evidence checker, not capture authentication. Its oracle is
independent of kernel status strings: compiled continuation labels, submitted
request bytes, raw exception frames, saved contexts, and ownership transitions
must describe the complete admitted execution, in order.
"""
from __future__ import annotations

import re
import struct

from tools.k02_region_protocol import ADDRESSES, CASES, MAX_LOG_BYTES, PROFILE, descriptor_bytes, digest, require

CODE, STACK, REQUEST, DATA = (ADDRESSES[k] for k in ("code", "stack", "request", "data"))
SEED, WRITTEN = 0x544553535245474e, 0x1122334455667788
CAP1, CAP2 = 0x100000002, 0x200000002
MAP_A1, MAP_A2, MAP_B, MAP_A3 = 0x100000001, 0x200000001, 0x100000002, 0x300000001
RESET = bytearray(512)
RESET[0:2], RESET[24:28] = b"\x7f\x03", b"\x80\x1f\0\0"
RESET_HASH = digest(RESET)
REGS = {f"r{i}" for i in range(15)}
CONTEXT = {"rip", "rsp", "cs", "ss", "rflags", "fp_sha256"} | REGS
TRAP_FIELDS = {"task", "domain", "root", "vector", "error", "frame", "trap_start", "trap_end", "cr2", "rdi", "rsi", "request_counter"} | CONTEXT
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
            if kind.startswith("TESSRYN_K02_SERVICE_"):
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
        return self.take("TESSRYN_K02_SERVICE_" + kind, expected)


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


# This fixed fixture program is intentionally not a general scheduler script.
# Every entry names a compiled post-INT80 continuation; no log-supplied stage is trusted.
def _plan(case):
    a = [("map", 2), ("writable_unmap", 5), ("readonly_remap", 2), ("delegate", 3), ("first_yield", 8)]
    b = [("map", 2), ("read_confirmed", 7), ("first_yield", 8)]
    if case == "authority":
        middle_a = [("cross_page", 7), ("unmapped_buffer", 7), ("overflow_buffer", 7), ("short_buffer", 7), ("bad_magic", 7), ("bad_version", 7), ("bad_operation", 99), ("private_stack", 4), ("private_request", 2), ("stale_mapping", 5), ("foreign", 2), ("stale", 2), ("collision", 2), ("busy_release", 6), ("authority_yield", 8)]
        middle_b = [("foreign_mapping", 5), ("foreign", 2), ("write_authority", 2), ("unmap", 5), ("busy_release", 6), ("exit", 9)]
        final_a = [("authority_unmap", 5), ("release", 6), ("allocate", 1), ("old_cap", 6), ("remap", 2), ("reunmap", 5), ("rerelease", 6), ("final_accounting", 7), ("exit", 9)]
    else:
        middle_a = [("accounting", 7)] if case == "sharing" else [("revoke", 4)]
        middle_a += [("second_yield", 8)]
        middle_b = [("write_fault" if case == "sharing" else "stale_fault", 0)]
        final_a = [("unmap" if case == "sharing" else "revoked_mapping", 5), ("release", 6), ("final_accounting", 7), ("exit", 9)]
    return [(0, *s) for s in a] + [(1, *s) for s in b] + [(0, *s) for s in middle_a] + [(1, *s) for s in middle_b] + [(0, *s) for s in final_a]


def parse_transcript(case, data, returncode, stderr, binding):
    """Return deterministic observations only after the entire fixture passes."""
    require(case in CASES and type(returncode) is int and returncode == 33 and stderr == b"",
            "region process did not finish cleanly")
    require(type(binding) is dict and set(binding) == {"descriptor", "programs", "kernel_header_hex", "kernel_imagebase_offset"},
            "region compiled binding incomplete")
    require(type(data) is bytes and type(stderr) is bytes, "region raw streams must be bytes")
    descriptor = binding["descriptor"]
    require(type(descriptor) is dict and set(descriptor) == {"size_bytes", "sha256", "efi_file_offset", "efi_rva"}
            and descriptor["size_bytes"] == 88 and descriptor["sha256"] == digest(descriptor_bytes(case))
            and all(type(descriptor[k]) is int and 0 <= descriptor[k] < 1 << 32 for k in ("efi_file_offset", "efi_rva")),
            "region descriptor binding differs from scenario")
    require(type(binding["programs"]) is dict and set(binding["programs"]) == {"a", "b"},
            "region program binding set differs")
    for name, program in binding["programs"].items():
        require(type(program) is dict and set(program) == {"size_bytes", "sha256", "efi_file_offset", "efi_rva", "offsets", "instruction_bytes"}
                and program["size_bytes"] == 4096 and type(program["sha256"]) is str
                and re.fullmatch("[0-9a-f]{64}", program["sha256"])
                and all(type(program[k]) is int and 0 <= program[k] < 1 << 32 for k in ("efi_file_offset", "efi_rva"))
                and program["efi_rva"] % 4096 == 0 and type(program["offsets"]) is dict
                and type(program["instruction_bytes"]) is dict and set(program["offsets"]) == set(program["instruction_bytes"])
                and all(type(v) is int and 0 <= v < 4096 for v in program["offsets"].values())
                and all(type(v) is str and re.fullmatch("[0-9a-f]{32}", v) for v in program["instruction_bytes"].values()),
                "region program binding malformed")
        for label in (f"region_{name}_read", f"region_{name}_fail") + (("region_a_scrub_read",) if name == "a" else ()):
            require(label in program["offsets"], "region actual read/failure label absent")
        offsets = program["offsets"]
        for before, read, after in ((f"region_{name}_map_trap", f"region_{name}_read", "region_a_writable_unmap_trap" if name == "a" else "region_b_read_confirmed_trap"),) + ((('region_a_remap_trap', 'region_a_scrub_read', 'region_a_reunmap_trap'),) if name == "a" else ()):
            require(all(label in offsets for label in (before, read, after)) and offsets[before] < offsets[read] < offsets[after],
                    "region read is not between accepted compiled continuations")
    require(binding["programs"]["a"]["sha256"] != binding["programs"]["b"]["sha256"], "region programs alias")
    require(type(binding["kernel_header_hex"]) is str and re.fullmatch("(?:[0-9a-f]{2}){64,4096}", binding["kernel_header_hex"]),
            "region original PE header binding malformed")
    trace = _Trace(data)
    live, reserved, kernel_root = _startup(trace, binding)
    require(binding["descriptor"]["efi_rva"] + 88 <= live["image_end"] - live["image_start"],
            "region descriptor exceeds loaded original image")
    trace.service("BEGIN", {"case": case, "version": 1, "programs": 2, "request_bytes": 96})
    trace.service("PROFILE", {**dict.fromkeys(("fsgsbase", "pce", "syscall", "sysenter", "fs_base", "gs_base", "kernel_gs_base", "ldtr", "debug_enabled", "osxsave"), 0), "cpu_count": 1, "fp": "legacy_fxsave"})

    def cap(phase, domain, generation=1):
        trace.service("CAP", {"domain": domain, "phase": phase, "cap_slot": 2, "cap_generation": generation, "cap_domain": domain})

    def payload(phase, frame, changed=False):
        raw = b"".join((WRITTEN if changed and i == 1 else SEED ^ i).to_bytes(8, "little") for i in range(512))
        trace.service("BACKING", {"phase": phase, "frame": frame, "sha256": digest(bytes(4096) if phase == "reused" else raw)})

    cap("provision", 1)
    # A physical backing is discovered once; every later mapping/digest binds it.
    require(trace.index < len(trace.rows), "region backing absent")
    frame = trace.rows[trace.index][1].get("frame")
    payload("ready", frame)
    # paging::Tables owns128 hardware pages plus one page of metadata/padding.
    kernel_pool = (kernel_root, kernel_root + 129 * 4096)
    require(kernel_pool[1] <= live["image_end"], "region kernel paging pool exceeds original image")
    tasks, physical, roots = [], [frame], []
    for index in range(2):
        t = trace.service("TASK", {"domain": index + 1, "root": ANY, "code_physical": live["image_start"] + binding["programs"]["ab"[index]]["efi_rva"], "entry": CODE, "stack": STACK, "stack_physical": ANY, "stack_lease_slot": 2 * index, "stack_lease_generation": 1, "request": REQUEST, "request_physical": ANY, "request_lease_slot": 2 * index + 1, "request_lease_generation": 1, "generation": 1})
        require(type(t["root"]) is int and t["root"] % 4096 == 0
                and live["image_start"] <= t["root"] and t["root"] + 17 * 4096 <= live["image_end"]
                and _disjoint((t["root"], t["root"] + 17 * 4096), kernel_pool), "region task root not private image-owned pool")
        roots.append((t["root"], t["root"] + 17 * 4096))
        physical.extend((t["stack_physical"], t["request_physical"]))
        tasks.append(t)
    require(_disjoint(*roots), "region task root pools overlap")
    require(len(set(physical)) == 5 and all(type(p) is int and 0 < p <= PROFILE["memory_bytes"] - 4096
            and p % 4096 == 0 and all(_disjoint((p, p + 4096), r) for r in reserved) for p in physical),
            "region physical backing aliases or overlaps reserved memory")
    code_ranges = [(t["code_physical"], t["code_physical"] + 4096) for t in tasks]
    require(_disjoint(*code_ranges) and all(live["image_start"] <= p[0] < p[1] <= live["image_end"]
            and all(_disjoint(p, r) for r in roots + [kernel_pool]) for p in code_ranges), "region code/root ranges overlap")

    def mapping(domain, phases, slot, generation, va=DATA, backing=frame, charged=None):
        for phase in phases:
            trace.service("MAP_EVENT", {"domain": domain, "phase": phase, "va": va, "frame": backing, "lease_slot": slot, "lease_generation": generation, "charged": (3 if domain == 1 else 2) if charged is None else charged})

    retire = ("fence", "clear", "invalidate", "quiesce")
    previous = [None, None]
    resumes, counters = [0, 0], [0, 0]
    charge, map_token, current_cap, fp_hash = [3, 2], [0, 0], [CAP1, CAP1], [None, None]
    stopped = set()
    trap_bounds = None
    stages = []
    request_count = 0
    switch_count, last_task = 0, None
    for index, stage, opcode in _plan(case):
        domain = index + 1
        require(index not in stopped, "region attempted stopped task resume")
        if last_task is not None and last_task != index:
            switch_count += 1
        last_task = index
        expected = {"task": index, "domain": domain, "generation": 1, "root": tasks[index]["root"], "first": int(resumes[index] == 0), "resumes": resumes[index]}
        if previous[index] is None:
            context = {k: 0 for k in REGS}
            context.update(r2=CASES.index(case), r3=CAP1, rip=CODE, rsp=STACK + 4080, cs=0x33, ss=0x2b, rflags=2, fp_sha256=RESET_HASH)
        else:
            context = previous[index]
        trace.service("RESUME", {**expected, **context})
        resumes[index] += 1
        fault = opcode == 0
        if not fault:
            counters[index] += 1
        counter = counters[index]
        pointer = {"cross_page": REQUEST + 4048, "unmapped_buffer": REQUEST + 4096, "overflow_buffer": (1 << 64) - 8}.get(stage, DATA if fault else REQUEST)
        length = 88 if stage == "short_buffer" else 96
        label = f"region_{'ab'[index]}_{stage}" + ("" if fault else "_trap")
        program = binding["programs"]["ab"[index]]
        require(program["size_bytes"] == 4096 and label in program["offsets"]
                and type(program["offsets"][label]) is int and 0 <= program["offsets"][label] < 4096,
                "region continuation lacks compiled label binding")
        instruction = bytes.fromhex(program["instruction_bytes"][label])
        status = {"cross_page": 7, "unmapped_buffer": 7, "overflow_buffer": 13, "short_buffer": 1, "bad_magic": 1, "bad_version": 2, "bad_operation": 3, "private_stack": 4, "private_request": 4, "stale_mapping": 5, "foreign": 4, "stale": 5, "collision": 14, "busy_release": 12, "foreign_mapping": 4, "write_authority": 9, "old_cap": 5, "revoked_mapping": 5}.get(stage, 0)
        require(instruction.startswith(bytes.fromhex("48c70734120000" if stage == "write_fault" else "488b07")) if fault
                else instruction.startswith(b"\x48\x83\xf8" + bytes([status])), "region compiled continuation instruction differs")
        flags = (0x10097 if case == "sharing" else 0x10046) if fault else 2 if stage == "stale" else 0x97 if stage == "unmap" and index == 0 and case == "sharing" else 0x46
        raw = {"vector": 14 if fault else 128, "error": (7 if case == "sharing" else 4) if fault else 0, "rip": CODE + program["offsets"][label], "cs": 0x33, "rflags": flags, "rsp": STACK + 4080, "cr2": DATA if fault else (DATA if 1 in stopped and case != "authority" else 0)}
        trace.take("TESSRYN_K01_EXCEPTION", raw)
        tr = trace.service("TRAP", {**dict.fromkeys(TRAP_FIELDS, ANY), **raw, "ss": 0x2b, "task": index, "domain": domain, "root": tasks[index]["root"], "rdi": pointer, "rsi": length, "request_counter": counter})
        bounds = tr["trap_start"], tr["trap_end"], tr["frame"]
        require(all(type(p) is int for p in bounds) and bounds[0] % 16 == 0 and bounds[1] - bounds[0] == 32768
                and bounds[2] == bounds[1] - 176 and live["image_start"] <= bounds[0] < bounds[1] <= live["image_end"]
                and all(_disjoint(bounds[:2], p) for p in roots + code_ranges + [kernel_pool])
                and (trap_bounds is None or trap_bounds == bounds), "region trap frame is not the private bounded stack")
        trap_bounds = bounds
        fp = tr["fp_sha256"]
        require(type(fp) is str and re.fullmatch("[0-9a-f]{64}", fp) and fp not in (RESET_HASH, "0" * 64)
                and (fp_hash[index] is None or fp_hash[index] == fp) and fp != fp_hash[1 - index],
                "region per-task legacy FP state changed or aliases peer")
        fp_hash[index] = fp
        # Snapshot GPRs are verified by the actual next user continuation too.
        # Bind every raw register, including the otherwise caller-clobbered pair.
        rd, rc = 0, 0
        if stage == "writable_unmap": rd, rc = SEED, WRITTEN
        elif stage == "delegate": rd = MAP_A2
        elif stage == "first_yield" and index == 0: rd, rc = CAP1, 2
        elif stage == "read_confirmed": rd, rc = WRITTEN, WRITTEN
        elif stage == "old_cap": rd, rc = CAP2, 1
        elif stage == "reunmap": rd = MAP_A3
        registers = [counter, map_token[index], CASES.index(case), current_cap[index], 0, 0,
                     0 if resumes[index] == 1 else charge[index], 0 if resumes[index] == 1 else charge[index],
                     pointer, length, (0xaaaaaaaa55555555 if index == 0 else 0xbbbbbbbb66666666),
                     (0x4141414141414141 if index == 0 else 0x4242424242424242), rd, rc, REQUEST]
        require(all(tr[f"r{i}"] == value for i, value in enumerate(registers)), "region actual user GPR behavior differs at " + stage)
        stages.append(f"{'ab'[index]}:{stage}")
        if fault:
            payload("after_fault", frame, True)
            trace.service("STOP", {"task": index, "reason": "fault", **{k: raw[k] for k in ("vector", "error", "rip", "cr2")}})
            stopped.add(index)
            if case == "sharing":
                mapping(2, retire, 5, 1)
                cap("deferred", 2)
            else:
                cap("release", 2)
            continue
        request_count += 1
        valid = stage not in ("cross_page", "unmapped_buffer", "overflow_buffer", "short_buffer")
        kwargs = {}
        if opcode in (2, 3, 4, 6): kwargs.update(cap=current_cap[index], domain=domain)
        if opcode == 2: kwargs.update(length=4096, va=DATA, rights=7 if stage in ("map", "remap") and index == 0 or stage == "write_authority" else 5)
        if stage == "delegate": kwargs.update(argument=2, length=4096, rights=5)
        if opcode == 5: kwargs["argument"] = MAP_A1 if stage == "stale_mapping" else MAP_A2 if stage == "foreign_mapping" else map_token[index]
        if stage == "foreign": kwargs["domain"] = 2 if index == 0 else 1
        if stage == "stale": kwargs["cap"] = CAP2
        if stage == "private_stack": kwargs["cap"] = 0x100000000
        if stage == "private_request": kwargs["cap"] = 0x100000001
        if stage == "collision": kwargs["va"] = STACK
        if stage == "allocate": kwargs = {"length": 4096}
        if stage == "old_cap": kwargs["cap"] = CAP1
        if stage == "bad_magic": kwargs["magic"] = b"\0ESSRGN1"
        if stage == "bad_version": kwargs["version"] = 2
        trace.service("REQUEST", {"task": index, "caller": domain, "pointer": pointer, "length": length, "valid": int(valid), "request_id": counter, "bytes": _request_bytes(counter, opcode, **kwargs) if valid else "none"})
        value, cap_domain = 0, 0
        if stage in ("map", "readonly_remap", "remap"):
            generation = 1 if stage == "map" else 2 if stage == "readonly_remap" else 3
            mapping(domain, ("install",), 4 + index, generation)
            value = MAP_B if index else (MAP_A1 if generation == 1 else MAP_A2 if generation == 2 else MAP_A3)
        elif stage == "writable_unmap": mapping(1, retire, 4, 1)
        elif stage == "delegate":
            cap("delegate", 2)
            value, cap_domain = CAP1, 2
        elif stage == "revoke":
            mapping(1, retire, 4, 2)
            mapping(2, retire, 5, 1)
        elif stage == "collision": mapping(1, ("fence", "invalidate", "rollback"), 6, 1, STACK)
        elif stage in ("unmap", "authority_unmap", "reunmap"):
            mapping(domain, retire, 4 + index, 3 if stage == "reunmap" else 2 if index == 0 else 1)
            if index == 0 and stage != "reunmap": cap("release", 2)
        elif stage in ("release", "rerelease"):
            cap("release", domain, 2 if stage == "rerelease" else 1)
            charge[index] = 2
        elif stage == "allocate":
            cap("allocate", 1, 2)
            payload("reused", frame)
            charge[0] = 3
            value, cap_domain = CAP2, 1
        control = "yield" if opcode == 8 else "exit" if opcode == 9 else "continue"
        trace.service("RESPONSE", {"task": index, "caller": domain, "request_id": counter, "opcode": opcode if valid else 0, "status": status, "value": value, "cap_domain": cap_domain, "charged": charge[index], "committed": charge[index], "reserved": 0, "control": control})
        context = {k: tr[k] for k in CONTEXT}
        context.update(r14=status, r12=value, r13=cap_domain, r7=charge[index], r6=charge[index], r5=0)
        previous[index] = context
        if stage in ("map", "readonly_remap", "remap"): map_token[index] = value
        if stage == "allocate": current_cap[index] = value
        if control == "exit":
            trace.service("STOP", {"task": index, "reason": "exit", "vector": 128, "error": 0, "rip": raw["rip"], "cr2": 0})
            stopped.add(index)
            if index == 1: cap("deferred", 2)
    require(stopped == {0, 1} and switch_count == 4, "region both tasks did not terminate after four switches")
    for index, task in enumerate(tasks):
        for i, (va, name) in enumerate(((STACK, "stack"), (REQUEST, "request"))):
            mapping(index + 1, retire, task[name + "_lease_slot"], task[name + "_lease_generation"], va, task[name + "_physical"], 2 - i)
        trace.service("FINAL", {"domain": index + 1, "leaves": 0, "charged": 0, "committed": 0, "reserved": 0})
    trace.service("PASS", {"case": case, "allocated_pages": 0, "mappings": 0, "context_switches": 4})
    require(trace.index == len(trace.rows), "region trace has trailing or unknown evidence")
    return {"case": case, "requests": request_count, "traps": len(stages), "context_switches": switch_count,
            "stages": stages, "task_resumes": resumes, "task_fp_sha256": fp_hash,
            "service_records": trace.records, "final_allocated_pages": 0, "final_mappings": 0,
            "domains": [{"domain": i, "charged": 0, "committed": 0, "reserved": 0, "leaves": 0} for i in (1, 2)]}
