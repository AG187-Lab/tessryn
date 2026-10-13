"""Strict offline observations from one frozen K01 normal serial transcript.

This parser performs no cloud calls and authenticates neither the producer nor
the boot image. Its output is parsed serial observations, not native platform or
recovery qualification. Capture provenance and artifact binding belong to the
caller. The accepted diagnostic contract is implementation commit 5ea06b9.
"""

from __future__ import annotations

import hashlib
import re

CONTRACT_REVISION = "5ea06b998fcc854851e794aea6235b15fa34be65"
MAX_SERIAL_BYTES = 262144
PAGE = 4096
HUGE_PAGE = 1 << 21
LOW_LIMIT = 1 << 32
GUARD = (1 << 47) - HUGE_PAGE
TABLE_CAPACITY = 128
LEAF_CAPACITY = 16384
# repr(C, align(4096)): 128 table pages, followed by rounded-up metadata.
TABLE_POOL_BYTES = (TABLE_CAPACITY + 1) * PAGE
PREFIX = b"TESSRYN_K01_"
CSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
ADDRESS = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,9})")

LIVE_FIELDS = ("image_start", "image_end", "stack_start", "stack_end",
               "map_start", "map_end", "scratch", "runtime_high", "gop_start", "gop_end")
PAGING_FIELDS = ("cr3", "tables", "leaves", "physical_bits", "guard", "free_scope")
MAP_FIELDS = ("descriptors", "stride", "free_pages", "attempt")
CPU_FIELDS = ("cr3", "rsp", "rip", "gdt", "idt", "tss")
MEMORY_FIELDS = ("scratch", "free_pages", "loader", "runtime", "firmware")


def _address(value: str) -> int:
    if ADDRESS.fullmatch(value) is None:
        raise ValueError("invalid diagnostic address")
    return int(value, 16)


def _decimal(value: str) -> int:
    if DECIMAL.fullmatch(value) is None:
        raise ValueError("invalid diagnostic count")
    return int(value)


def _diagnostics(data: bytes) -> list[bytes]:
    """Allow firmware CSI/CRLF without repairing damaged kernel diagnostics."""
    if type(data) is not bytes or not 0 < len(data) <= MAX_SERIAL_BYTES:
        raise ValueError("serial input must be nonempty bounded bytes")
    if not data.endswith(b"\n"):
        raise ValueError("serial input ends with an incomplete line")
    records = []
    inside = False
    terminal = False
    for raw in data.split(b"\n")[:-1]:
        line = raw.removesuffix(b"\r")
        clean = CSI.sub(b"", line)
        if any(byte < 32 and byte != 9 or byte > 126 for byte in clean):
            raise ValueError("unsupported serial character or control sequence")
        if b"tessryn_k" in clean.lower() or b"tessryn original kernel" in clean.lower():
            # Terminal styling at the edges is benign. Removing an escape in
            # the middle of a marker/field would conceal a corrupted capture.
            escapes = list(CSI.finditer(line))
            start, end = 0, len(line)
            for match in escapes:
                if match.start() != start:
                    break
                start = match.end()
            for match in reversed(escapes):
                if match.end() != end:
                    break
                end = match.start()
            edge_clean = line[start:end]
            if edge_clean != clean or not (clean.startswith(PREFIX) or clean == b"TESSRYN ORIGINAL KERNEL"):
                raise ValueError("damaged or prefixed kernel diagnostic")
            if clean == PREFIX + b"ENTRY":
                inside = True
            records.append(clean)
            if clean == PREFIX + b"PASS":
                inside = False
                terminal = True
        elif inside and clean:
            raise ValueError("unexpected output within kernel boot")
        elif terminal and clean:
            raise ValueError("unexpected output after normal terminal marker")
    return records


class _Transcript:
    def __init__(self, lines: list[bytes]):
        self.lines = lines
        self.cursor = 0

    def next_is(self, name: str) -> bool:
        return self.cursor < len(self.lines) and self.lines[self.cursor] == PREFIX + name.encode("ascii")

    def fields(self, name: str, keys: tuple[str, ...] = ()) -> dict[str, str]:
        if self.cursor >= len(self.lines):
            raise ValueError("normal boot diagnostic sequence is incomplete")
        line = self.lines[self.cursor]
        self.cursor += 1
        parts = line.split(b" ")
        if parts[0] != PREFIX + name.encode("ascii") or len(parts) != len(keys) + 1:
            raise ValueError("normal boot diagnostic order or field layout differs")
        result = {}
        for key, token in zip(keys, parts[1:]):
            if token.count(b"=") != 1 or not token.startswith(key.encode("ascii") + b"="):
                raise ValueError("normal boot diagnostic field layout differs")
            value = token[len(key) + 1:].decode("ascii")
            if not value:
                raise ValueError("normal boot diagnostic field is empty")
            result[key] = value
        return result

    def banner(self) -> None:
        if self.cursor >= len(self.lines) or self.lines[self.cursor] != b"TESSRYN ORIGINAL KERNEL":
            raise ValueError("ready framebuffer banner is missing")
        self.cursor += 1


def _overlap(first: tuple[int, int], second: tuple[int, int]) -> bool:
    return first[0] < second[1] and second[0] < first[1]


def _mapping_bounds(start: int, end: int, bits: int) -> tuple[int, int]:
    if not 0 <= start < end <= min(1 << bits, GUARD):
        raise ValueError("live range exceeds physical, canonical or guard bounds")
    rounded = start // HUGE_PAGE * HUGE_PAGE, (end + HUGE_PAGE - 1) // HUGE_PAGE * HUGE_PAGE
    if rounded[1] > min(1 << bits, GUARD):
        raise ValueError("rounded live mapping exceeds address bounds")
    return rounded


def _minimum_paging(ranges: list[tuple[int, int]], bits: int) -> tuple[int, int]:
    bounds = sorted(_mapping_bounds(start, end, bits) for start, end in [(0, LOW_LIMIT), *ranges])
    merged: list[tuple[int, int]] = []
    for start, end in bounds:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    leaves = sum((end - start) // HUGE_PAGE for start, end in merged)
    if leaves > LEAF_CAPACITY:
        raise ValueError("required live mappings exceed leaf budget")
    # At most LEAF_CAPACITY iterations; omitted runtime descriptors can add
    # leaves/tables, so these are lower bounds rather than a complete map claim.
    slots = {slot for start, end in merged for slot in range(start // HUGE_PAGE, end // HUGE_PAGE)}
    tables = 1 + len({slot >> 18 for slot in slots}) + len({slot >> 9 for slot in slots})
    if tables > TABLE_CAPACITY:
        raise ValueError("required live mappings exceed table budget")
    return tables, leaves


def _framebuffer(stream: _Transcript) -> dict:
    if stream.cursor < len(stream.lines) and stream.lines[stream.cursor] == b"TESSRYN ORIGINAL KERNEL":
        stream.banner()
        fields = stream.fields("FRAMEBUFFER", ("status", "width", "height", "stride", "base", "format", "selection"))
        if fields["status"] != "ready" or fields["format"] not in ("rgbx", "bgrx") or fields["selection"] not in ("firmware-console", "unique-gop"):
            raise ValueError("ready framebuffer profile differs")
        observed = {key: _decimal(fields[key]) for key in ("width", "height", "stride")}
        observed.update(status="ready", base=_address(fields["base"]), format=fields["format"], selection=fields["selection"])
        required = observed["stride"] * observed["height"] * 4
        if (observed["width"] < 80 or observed["height"] < 40 or observed["stride"] < observed["width"]
                or required > 32 * 1024 * 1024 or observed["base"] == 0 or observed["base"] % 4):
            raise ValueError("ready framebuffer dimensions or address differ")
        observed["required_bytes"] = required
        return observed
    fields = stream.fields("FRAMEBUFFER", ("status", "reason"))
    if fields != {"status": "unavailable-serial-only", "reason": "optional-gop"}:
        raise ValueError("optional framebuffer profile differs")
    return fields


def _admission(stream: _Transcript, framebuffer: dict, attempt: int) -> dict:
    fields = stream.fields("LIVE_RANGES", LIVE_FIELDS)
    live = {key: _decimal(value) if key == "runtime_high" else _address(value) for key, value in fields.items()}
    fields = stream.fields("PAGING_READY", PAGING_FIELDS)
    paging = {key: _decimal(fields[key]) for key in ("tables", "leaves", "physical_bits")}
    paging.update(cr3=_address(fields["cr3"]), guard=_address(fields["guard"]), free_scope=fields["free_scope"])
    if (not 32 <= paging["physical_bits"] <= 52 or paging["guard"] != GUARD
            or paging["free_scope"] != "low-conventional" or not 6 <= paging["tables"] <= TABLE_CAPACITY
            or not 2048 <= paging["leaves"] <= LEAF_CAPACITY):
        raise ValueError("prepared paging profile or budget differs")
    fields = stream.fields("RESET_POINTER", ("address", "method"))
    reset = {"address": _address(fields["address"]), "method": fields["method"]}
    if reset["method"] != "uefi-runtime" or reset["address"] == 0:
        raise ValueError("runtime reset pointer profile differs")
    fields = stream.fields("MEMORY_MAP_VALID", MAP_FIELDS)
    memory = {key: _decimal(value) for key, value in fields.items()}
    if (memory["attempt"] != attempt or not 3 <= memory["descriptors"] <= 4096
            or memory["stride"] < 40 or memory["stride"] % 8
            or memory["descriptors"] * memory["stride"] > 16 * PAGE
            or not 1 <= memory["free_pages"] <= LOW_LIMIT // PAGE
            or live["runtime_high"] > memory["descriptors"]):
        raise ValueError("memory inventory or retry attempt differs")

    owned = []
    for name in ("image", "stack", "map"):
        start, end = live[name + "_start"], live[name + "_end"]
        if start == 0 or start % PAGE or end % PAGE:
            raise ValueError("live allocation is not nonzero and page aligned")
        _mapping_bounds(start, end, paging["physical_bits"])
        owned.append((start, end))
    if live["stack_end"] - live["stack_start"] != 32 * PAGE or live["map_end"] - live["map_start"] != 16 * PAGE:
        raise ValueError("live stack or map allocation size differs")
    scratch = live["scratch"]
    if not 0x100000 <= scratch < LOW_LIMIT or scratch % PAGE:
        raise ValueError("normal scratch is not a low conventional page")
    owned.append((scratch, scratch + PAGE))
    for i, current in enumerate(owned):
        if any(_overlap(current, other) for other in owned[:i]):
            raise ValueError("owned live allocations overlap")
    cr3 = paging["cr3"]
    if cr3 % PAGE or not live["image_start"] <= cr3 or cr3 + TABLE_POOL_BYTES > live["image_end"]:
        raise ValueError("complete paging pool does not belong to live image")
    if any(start <= reset["address"] < end for start, end in owned):
        raise ValueError("runtime reset pointer overlaps owned allocation")
    # The map cannot count loader-owned pages or the distinct runtime-code
    # reset page as free conventional RAM, even without its raw descriptors.
    reserved_low_pages = sum(max(0, min(end, LOW_LIMIT) - start) // PAGE for start, end in owned[:3])
    reserved_low_pages += int(reset["address"] < LOW_LIMIT)
    if memory["free_pages"] > LOW_LIMIT // PAGE - reserved_low_pages:
        raise ValueError("free inventory counts required reserved low pages")
    if reset["address"] >= LOW_LIMIT and live["runtime_high"] == 0:
        raise ValueError("high runtime reset pointer lacks runtime inventory")
    gop = live["gop_start"], live["gop_end"]
    if framebuffer["status"] == "ready":
        if gop[0] != framebuffer["base"] or gop[1] - gop[0] < framebuffer["required_bytes"]:
            raise ValueError("framebuffer metadata differs from live range")
        _mapping_bounds(*gop, paging["physical_bits"])
        if any(_overlap(gop, other) for other in owned):
            raise ValueError("framebuffer overlaps owned live allocation")
        owned.append(gop)
    elif gop != (0, 0):
        raise ValueError("missing framebuffer has a nonempty live range")
    required_tables, required_leaves = _minimum_paging([*owned, (reset["address"], reset["address"] + 1)], paging["physical_bits"])
    if paging["tables"] < required_tables or paging["leaves"] < required_leaves:
        raise ValueError("prepared paging cannot cover printed live ranges")
    if paging["tables"] > 6 + 2 * (paging["leaves"] - 2048):
        raise ValueError("prepared table count exceeds possible leaf structure")
    if live["runtime_high"] == 0:
        # Every omitted runtime descriptor is already covered by low4GiB;
        # printed high live ranges therefore complete the mapping inventory.
        if (paging["tables"], paging["leaves"]) != (required_tables, required_leaves):
            raise ValueError("paging counts differ from complete low runtime inventory")
    elif paging["physical_bits"] == 32 or paging["tables"] < 7 or paging["leaves"] < 2049:
        raise ValueError("high runtime inventory lacks possible high mappings")
    return {"live_ranges": live, "paging": paging, "reset_pointer": reset, "memory_map": memory}


def parse_native_serial(data: bytes) -> dict:
    """Parse one normal boot; reject inconsistency without reflecting raw text.

    Firmware prefix text and complete ANSI CSI at diagnostic edges are permitted. A
    complete capture must end in LF; kernel fields follow the frozen source's
    exact order and spelling. All failure, fixture and extra boot markers are
    rejected. Runtime descriptor contents and provenance are not in this serial
    contract and cannot be independently reconstructed from these observations.
    """
    stream = _Transcript(_diagnostics(data))
    stream.fields("ENTRY")
    framebuffer = _framebuffer(stream)
    admissions = []
    while True:
        if len(admissions) == 8:
            raise ValueError("firmware admission exceeds eight attempts")
        admission = _admission(stream, framebuffer, len(admissions) + 1)
        if admissions:
            first = admissions[0]
            stable = tuple(key for key in LIVE_FIELDS if key not in ("scratch", "runtime_high"))
            if (any(admission["live_ranges"][key] != first["live_ranges"][key] for key in stable)
                    or admission["reset_pointer"] != first["reset_pointer"]
                    or any(admission["paging"][key] != first["paging"][key] for key in ("cr3", "physical_bits", "guard", "free_scope"))):
                raise ValueError("live allocations or CPU profile changed during retry")
        admissions.append(admission)
        if stream.next_is("EXIT_BOOT_SERVICES_OK"):
            stream.fields("EXIT_BOOT_SERVICES_OK")
            break
        stream.fields("EXIT_BOOT_SERVICES_RETRY")

    final = admissions[-1]
    live = final["live_ranges"]
    fields = stream.fields("CPU_OWNED", CPU_FIELDS)
    cpu = {key: _address(fields[key]) for key in ("cr3", "rsp", "rip")}
    cpu.update({key: fields[key] for key in ("gdt", "idt", "tss")})
    if (cpu["cr3"] != final["paging"]["cr3"] or any(cpu[key] != "owned" for key in ("gdt", "idt", "tss"))
            or not live["image_start"] <= cpu["rip"] < live["image_end"]
            or not live["stack_start"] <= cpu["rsp"] < live["stack_end"] or cpu["rsp"] % 8):
        raise ValueError("post-handoff CPU differs from final admitted image and stack")
    fields = stream.fields("MEMORY_OWNERSHIP_OK", MEMORY_FIELDS)
    memory = {"scratch": _address(fields["scratch"]), "free_pages": _decimal(fields["free_pages"]),
              **{key: fields[key] for key in ("loader", "runtime", "firmware")}}
    if (memory["scratch"] != live["scratch"] or memory["free_pages"] != final["memory_map"]["free_pages"]
            or memory["loader"] != "reserved" or memory["runtime"] != "reserved" or memory["firmware"] != "quarantined"):
        raise ValueError("owned memory readback differs from final admission")
    stream.fields("PASS")
    if stream.cursor != len(stream.lines):
        raise ValueError("extra kernel diagnostics or duplicate boot after terminal marker")
    return {"schema_version": 1, "format": "tessryn-native-normal-serial-observations", "status": "parsed",
            "scope": "offline serial observations only; producer, image, native boot and recovery unqualified",
            "contract_revision": CONTRACT_REVISION,
            "serial": {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)},
            "exit_attempts": len(admissions), "framebuffer": framebuffer, "admissions": admissions,
            "cpu_owned": cpu, "memory_ownership": memory, "terminal_marker": "TESSRYN_K01_PASS"}
