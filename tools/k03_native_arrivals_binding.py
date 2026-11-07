"""Bind the compiled workload inputs and user payload to COFF and linked EFI."""

import struct

from tools.build_kernel import inspect_pe
from tools.k02_region_protocol import digest, require
from tools.k03_native_arrivals_protocol import PROFILE_SYMBOL
from tools.k03_smp_protocol import descriptor_bytes

PROGRAM_LABELS = (
    "user_start", "loop", "after_inc", "after_sum", "before_dec", "after_dec",
    "complete", "complete_return",
)
_RELOC_WIDTHS = {0: 0, 1: 8, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4, 7: 4, 8: 4, 9: 4, 10: 2, 11: 4, 12: 1, 13: 4, 14: 4, 16: 4}
_USER_CODE = bytes.fromhex("66b82b00668ee84c396f087510f048ff074d01e2f39048ffc975f2cd800f0b")
_USER_OFFSETS = dict(zip(PROGRAM_LABELS, (0, 13, 17, 20, 22, 25, 27, 29), strict=True))


def coff_binding(obj, efi, expected_profile):
    require(len(obj) >= 20, "native workload COFF header truncated")
    machine, count, _, sym_at, sym_count, optional, _ = struct.unpack_from("<HHIIIHH", obj)
    str_at = sym_at + sym_count * 18
    require(machine == 0x8664 and optional == 0 and 0 < count <= 4096 and sym_count <= 1_000_000
            and 20 + count * 40 <= sym_at and str_at + 4 <= len(obj), "native workload COFF tables malformed")
    str_size, = struct.unpack_from("<I", obj, str_at)
    require(4 <= str_size <= len(obj) - str_at, "native workload COFF string table malformed")
    section_rows = []
    for index in range(count):
        at = 20 + index * 40
        size, raw, relocs = struct.unpack_from("<III", obj, at + 16)
        reloc_count = struct.unpack_from("<H", obj, at + 32)[0]
        flags = struct.unpack_from("<I", obj, at + 36)[0]
        require((raw > 0 and raw + size <= len(obj) or raw == 0 and reloc_count == 0 and (size == 0 or flags & 0x80))
                and relocs + reloc_count * 10 <= len(obj), "native workload COFF section truncated")
        section_rows.append((raw, size, relocs, reloc_count, flags))
    wanted = {"K03_SMP_CONTRACT", "smp_trampoline_start", "smp_trampoline_end", PROFILE_SYMBOL,
              "smp_workload_program_start", "smp_workload_program_end",
              *("smp_workload_" + label for label in PROGRAM_LABELS)}
    symbols = {}
    index = 0
    while index < sym_count:
        at = sym_at + index * 18
        raw = obj[at:at + 8]
        if raw[:4] == bytes(4):
            offset = struct.unpack_from("<I", raw, 4)[0]
            end = obj.find(b"\0", str_at + offset, str_at + str_size)
            require(4 <= offset < str_size and end >= 0, "native workload COFF symbol name malformed")
            raw = obj[str_at + offset:end]
        name = raw.rstrip(b"\0").decode("ascii")
        value, section, _, storage, auxiliary = struct.unpack_from("<IhHBB", obj, at + 8)
        if name in wanted:
            require(name not in symbols and storage == 2 and 1 <= section <= count, "native workload COFF symbol ambiguous")
            symbols[name] = (section, value)
        index += auxiliary + 1
        require(index <= sym_count, "native workload COFF auxiliary symbol truncated")
    require(set(symbols) == wanted, "native workload binding symbols missing")

    def extract(name, length, executable):
        section, start = symbols[name]
        raw, size, reloc, reloc_count, flags = section_rows[section - 1]
        require(raw and start + length <= size and flags & 0x40000000 and not flags & 0x80000080
                and bool(flags & 0x20000000) == executable, "native workload COFF binding section differs")
        for index in range(reloc_count):
            position, target, kind = struct.unpack_from("<IIH", obj, reloc + index * 10)
            width = _RELOC_WIDTHS.get(kind)
            require(width is not None and target < sym_count and position + width <= size
                    and (not width or position + width <= start or position >= start + length),
                    "native workload relocation overlaps an immutable binding")
        return obj[raw + start:raw + start + length]

    pe = struct.unpack_from("<I", efi, 60)[0]
    optional = struct.unpack_from("<H", efi, pe + 20)[0]
    sections = inspect_pe(efi)["sections"]
    image_size = struct.unpack_from("<I", efi, pe + 24 + 56)[0]

    def linked(data, executable):
        at = efi.find(data)
        require(at >= 0 and efi.find(data, at + 1) == -1, "native workload linked binding is absent or ambiguous")
        matches = []
        for index, row in enumerate(sections):
            raw = struct.unpack_from("<I", efi, pe + 24 + optional + index * 40 + 20)[0]
            size = min(row["size_bytes"], row["virtual_size"])
            if raw <= at and at + len(data) <= raw + size:
                require(row["flags"] & 0x40000000 and not row["flags"] & 0x80000000
                        and bool(row["flags"] & 0x20000000) == executable, "native workload linked permissions differ")
                matches.append(row["rva"] + at - raw)
        require(len(matches) == 1 and matches[0] + len(data) <= image_size, "native workload linked binding escaped image")
        return {"size_bytes": len(data), "sha256": digest(data), "efi_file_offset": at, "efi_rva": matches[0]}

    def page(stem):
        section, start = symbols[stem + "_start"]
        require(symbols[stem + "_end"] == (section, start + 4096), "native workload executable binding is not one page")
        return extract(stem + "_start", 4096, True)

    descriptor = extract("K03_SMP_CONTRACT", 96, False)
    require(descriptor == descriptor_bytes("rendezvous"), "native workload inherited bootstrap differs")
    profile = extract(PROFILE_SYMBOL, len(expected_profile), False)
    require(profile == expected_profile, "native workload actual compiled offers differ")
    payload = page("smp_workload_program")
    section, start = symbols["smp_workload_program_start"]
    offsets = {}
    for name in PROGRAM_LABELS:
        label_section, label = symbols["smp_workload_" + name]
        require(label_section == section and start <= label < start + len(payload), "native workload label escaped CPL3 page")
        offsets[name] = label - start
    require(offsets == _USER_OFFSETS and payload[:len(_USER_CODE)] == _USER_CODE
            and not any(payload[len(_USER_CODE):]), "native workload CPL3 loop or completion instructions differ")
    program = linked(payload, True)
    require(program["efi_rva"] % 4096 == 0, "native workload CPL3 page is misaligned")
    return {
        "profile": linked(profile, False),
        "program": {**program, "offsets": offsets},
        "bootstrap": {
            "descriptor": linked(descriptor, False), "trampoline": linked(page("smp_trampoline"), True),
            "image_size": image_size,
            "executable_ranges": [[row["rva"], row["rva"] + row["virtual_size"]]
                                  for row in sections if row["flags"] & 0x20000000],
        },
    }
