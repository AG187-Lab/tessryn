#!/usr/bin/env python3
"""Build three bounded source-bound isolated CPL3 cases with the checked K01 tools."""
from __future__ import annotations
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k03_smp_user_protocol import (CASES, PROFILE, ARTIFACT_TYPE, SCOPE, require, digest, regular_bytes,
    file_ref, write_json, fresh_output, retain_private_error, descriptor_bytes, case_flags)
from tools.k03_smp_user_provenance import COMPILER_SOURCES, runtime_hashes, canonical, expected_commands
from tools.build_fixture import source_identity
from tools.build_kernel import compiler_profile, copy_notices, inspect_pe
from tools.g03.process import run_bounded
from tools.k01_media import make_disk
from tools.setup_uefi import verify_installation


def coff_binding(obj, efi, case):
    """Bind inherited AP bootstrap and the original copied CPL3 program."""
    from tools.k03_smp_protocol import descriptor_bytes as bootstrap_descriptor
    from tools.k03_smp_user_protocol import DESCRIPTOR_SIZE
    require(len(obj) >= 20, "SMP user COFF header truncated")
    machine, count, _, symbol_at, symbol_count, optional, _ = struct.unpack_from("<HHIIIHH", obj)
    strings = symbol_at + symbol_count * 18
    require(machine == 0x8664 and optional == 0 and 0 < count <= 4096 and symbol_count <= 1_000_000
        and 20 + count * 40 <= len(obj) and strings + 4 <= len(obj), "SMP user COFF tables malformed")
    string_size = struct.unpack_from("<I", obj, strings)[0]
    require(4 <= string_size <= len(obj) - strings, "SMP user COFF strings truncated")
    sections = []
    relocation_widths = {0: 0, 1: 8, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4, 7: 4, 8: 4, 9: 4, 10: 2, 11: 4, 12: 1, 13: 4, 14: 4, 16: 4}
    for index in range(count):
        at = 20 + index * 40
        size, raw, relocs = struct.unpack_from("<III", obj, at + 16)
        reloc_count = struct.unpack_from("<H", obj, at + 32)[0]
        flags = struct.unpack_from("<I", obj, at + 36)[0]
        require((raw > 0 and raw + size <= len(obj) or raw == 0 and reloc_count == 0 and (size == 0 or flags & 0x80))
            and relocs + reloc_count * 10 <= len(obj), "SMP user COFF section truncated")
        for index in range(reloc_count):
            position, target, kind = struct.unpack_from("<IIH", obj, relocs + index * 10)
            require(kind in relocation_widths and target < symbol_count and position + relocation_widths[kind] <= size,
                "SMP user COFF relocation type/target/span malformed")
        sections.append((raw, size, relocs, reloc_count, flags))
    wanted = {"K03_SMP_CONTRACT", "smp_trampoline_start", "smp_trampoline_end", "K03_SMP_USER_CONTRACT", "smp_user_program_start", "smp_user_program_end",
        "smp_user_bsp_start", "smp_user_loop_start", "smp_user_loop_end", "smp_user_warmup_start", "smp_user_warmup_end",
        "smp_user_yield", "smp_user_after_yield", "smp_user_peer_fault", "smp_user_forged_fault"}
    symbols, index = {}, 0
    while index < symbol_count:
        at = symbol_at + index * 18
        name = obj[at:at + 8]
        if name[:4] == bytes(4):
            offset = struct.unpack_from("<I", name, 4)[0]
            end = obj.find(b"\0", strings + offset, strings + string_size)
            require(4 <= offset < string_size and end >= 0, "SMP user COFF symbol name malformed")
            name = obj[strings + offset:end]
        else:
            name = name.rstrip(b"\0")
        name = name.decode("ascii")
        value, section, _, storage, auxiliary = struct.unpack_from("<IhHBB", obj, at + 8)
        if name in wanted:
            require(name not in symbols and storage == 2 and 1 <= section <= count, "SMP user binding symbol duplicate/undefined")
            symbols[name] = section, value
        index += auxiliary + 1
        require(index <= symbol_count, "SMP user COFF auxiliary symbols truncated")
    require(set(symbols) == wanted, "SMP user compiled binding symbols missing")

    def extract(name, length):
        section, start = symbols[name]
        raw, size, relocs, relcount, flags = sections[section - 1]
        executable = name in ("smp_user_program_start", "smp_trampoline_start")
        require(raw > 0 and not flags & 0x80 and start + length <= size
            and flags & 0x40000000 and not flags & 0x80000000 and bool(flags & 0x20000000) == executable,
            "SMP user binding exceeds expected read-only initialized COFF section")
        for index in range(relcount):
            position, _, kind = struct.unpack_from("<IIH", obj, relocs + index * 10)
            width = relocation_widths[kind]
            require(width == 0 or position + width <= start or position >= start + length,
                "SMP user relocation fixup intersects immutable descriptor/program")
        return obj[raw + start:raw + start + length]

    require(symbols["smp_trampoline_end"] == (symbols["smp_trampoline_start"][0], symbols["smp_trampoline_start"][1] + 4096),
        "SMP user trampoline must occupy exactly one page")
    trampoline = extract("smp_trampoline_start", 4096)
    inherited = extract("K03_SMP_CONTRACT", 96)
    require(inherited == bootstrap_descriptor("rendezvous"), "SMP user inherited bootstrap contract differs")
    descriptor = extract("K03_SMP_USER_CONTRACT", DESCRIPTOR_SIZE)
    require(descriptor == descriptor_bytes(case), "SMP user compiled contract differs")
    start = symbols["smp_user_program_start"]
    require(symbols["smp_user_program_end"] == (start[0], start[1] + 4096), "SMP user program must occupy exactly one page")
    code = extract("smp_user_program_start", 4096)
    labels = {}
    for name in wanted - {"K03_SMP_CONTRACT", "smp_trampoline_start", "smp_trampoline_end", "K03_SMP_USER_CONTRACT", "smp_user_program_start", "smp_user_program_end"}:
        section, offset = symbols[name]
        require(section == start[0] and start[1] <= offset < start[1] + 4096, "SMP user label escapes program page")
        labels[name.removeprefix("smp_user_")] = offset - start[1]
    require(labels["bsp_start"] == 0 and labels["warmup_end"] == labels["yield"]
        and all(code[labels[name]:labels[name] + 7] == bytes.fromhex("66b82b00668ee8") for name in ("bsp_start", "warmup_start")),
        "SMP user entry does not exercise the declared GS selector reload")
    require(labels["loop_end"] == labels["loop_start"] + 8
        and code[labels["loop_start"]:labels["loop_end"]] == bytes.fromhex("f048ff07f390ebf8"), "SMP user loop bytes differ")
    require(labels["after_yield"] == labels["yield"] + 2 and code[labels["yield"]:labels["after_yield"]] == b"\xcd\x80",
        "SMP user yield continuation is not after INT128")
    require(code[labels["forged_fault"]:labels["forged_fault"] + 2] == b"\xcd\x42", "SMP user forged interrupt is not INT66")
    require(code[labels["peer_fault"]:labels["peer_fault"] + 3] == bytes.fromhex("488b06"), "SMP user peer probe is not MOV RAX,[RSI]")
    require(labels["warmup_start"] < labels["warmup_end"], "SMP user finite warmup bounds invalid")
    pe_info = inspect_pe(efi)
    pe = struct.unpack_from("<I", efi, 60)[0]
    optional = struct.unpack_from("<H", efi, pe + 20)[0]

    def linked(data, executable):
        at = efi.find(data)
        require(at >= 0 and efi.find(data, at + 1) < 0, "SMP user binding bytes not unique and unchanged in EFI")
        matches = []
        for index in range(len(pe_info["sections"])):
            row = pe + 24 + optional + index * 40
            rva, size, raw = struct.unpack_from("<III", efi, row + 12)
            flags = struct.unpack_from("<I", efi, row + 36)[0]
            if raw <= at and at + len(data) <= raw + size:
                require(flags & 0x40000000 and not flags & 0x80000000 and bool(flags & 0x20000000) == executable,
                    "SMP user linked binding permissions differ")
                matches.append(rva + at - raw)
        require(len(matches) == 1, "SMP user binding section ambiguous")
        return {"size_bytes": len(data), "sha256": digest(data), "efi_file_offset": at, "efi_rva": matches[0]}

    program = linked(code, True)
    require(program["efi_rva"] % 4096 == 0, "SMP user linked program page is not aligned")
    bootstrap = {"descriptor": linked(inherited, False), "trampoline": linked(trampoline, True),
        "image_size": struct.unpack_from("<I", efi, pe + 24 + 56)[0],
        "executable_ranges": [[row["rva"], row["rva"] + row["virtual_size"]] for row in pe_info["sections"] if row["flags"] & 0x20000000]}
    return {"bootstrap": bootstrap, "descriptor": linked(descriptor, False),
        "program": {**program, "offsets": labels, "instruction_bytes": {name: code[offset:offset + 16].hex() for name, offset in labels.items()}}}


def dependency_paths(data, snapshot):
    import shlex
    result = set()
    for line in data.replace("\\\n", " ").splitlines():
        if not line or line.startswith("#") or ": " not in line:
            continue
        for token in shlex.split(line.split(": ", 1)[1]):
            path = Path(token)
            if not path.is_absolute(): path = snapshot / path
            require(path.is_relative_to(snapshot) and ".." not in path.parts, "SMP user compiler dependency escapes snapshot")
            regular_bytes(path, 16 << 20)
            result.add(path.relative_to(snapshot).as_posix())
    require(result, "SMP user compiler dependency list empty")
    return result


def build(out):
    out = fresh_output(out)
    receipts = []
    try:
        source, runtime = source_identity(), runtime_hashes()
        profile = compiler_profile()
        prefix = ROOT / "build/uefi"
        retained = {}
        for path in sorted((ROOT / "kernel").rglob("*")):
            require(not path.is_symlink(), "SMP user compiler snapshot contains alias")
            if path.is_file(): retained[path.relative_to(ROOT).as_posix()] = regular_bytes(path, 16 << 20)
        require(len(retained) <= 512 and sum(map(len, retained.values())) <= 64 << 20
            and set(COMPILER_SOURCES) <= set(retained), "SMP user compiler snapshot incomplete/oversized")
        commands, bindings, artifacts, dependencies = {}, {}, [], set()
        with tempfile.TemporaryDirectory(prefix="source-", dir=out) as temporary:
            snapshot = Path(temporary)
            for name, data in retained.items():
                path = snapshot / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data); path.chmod(0o400)
            for case in CASES:
                directory = out / case; directory.mkdir()
                efi, obj, dep = (directory / name for name in ("BOOTX64.EFI", "kernel.obj", "kernel.d"))
                args = ["kernel/main.rs", *profile["toolchain"]["rust_flags"], "-Dwarnings", *case_flags(case),
                    f"--emit=link,obj={obj},dep-info={dep}", f"--remap-path-prefix={prefix}=rust-toolchain",
                    f"--remap-path-prefix={out}=smp-user-build", f"--remap-path-prefix={snapshot}=tessryn",
                    "-Clinker=" + str(profile["linker"]), "-o", str(efi)]
                execution = run_bounded([str(profile["compiler"]), *args], snapshot, 90, 1 << 20)
                row = {"role": case, "status": execution.status, "returncode": execution.returncode, "elapsed_seconds": execution.elapsed_seconds}
                for stream in ("stdout", "stderr"):
                    log = directory / (stream + ".log"); log.write_bytes(getattr(execution, stream)); row[stream] = file_ref(out, log)
                receipts.append(row)
                require(execution.status == "completed" and execution.returncode == 0, "SMP user compilation failed; diagnostics retained privately")
                require(all(str(ROOT).encode() not in getattr(execution, s) for s in ("stdout", "stderr")), "SMP user successful compiler output contains local paths")
                dependencies.update(dependency_paths(dep.read_text(), snapshot)); dep.unlink()
                commands[case] = [a.replace(str(snapshot), "tessryn").replace(str(prefix), "rust-toolchain").replace(str(out), "smp-user-build") for a in args]
                bindings[case] = coff_binding(regular_bytes(obj), regular_bytes(efi), case)
                (directory / "boot.img").write_bytes(make_disk(regular_bytes(efi)))
                for name in ("BOOTX64.EFI", "kernel.obj", "boot.img"):
                    artifacts.append({**file_ref(out, directory / name), "case": case})
            require(all(regular_bytes(snapshot / n, 16 << 20) == d for n, d in retained.items()), "SMP user compiler snapshot changed")
        require(dependencies == set(COMPILER_SOURCES), "SMP user actual compiler closure differs")
        require(commands == expected_commands(profile), "SMP user normalized compiler commands differ")
        refs = []
        for name in sorted(set(COMPILER_SOURCES) | set(runtime)):
            path = out / "sources" / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(retained[name] if name in retained else regular_bytes(ROOT / name, 16 << 20)); refs.append(file_ref(out, path))
        manifest = {"format": "tessryn-k03-smp-user-build/v1", "artifact_type": ARTIFACT_TYPE,
            "source": source, "source_files": {n: digest(retained[n]) for n in COMPILER_SOURCES},
            "runtime_files": runtime, "retained_sources": refs, "toolchain": profile["toolchain"],
            "profile": PROFILE, "cases": list(CASES), "scope": SCOPE, "qualification": "not_established",
            "compile_commands": commands, "compile": receipts, "bindings": bindings, "artifacts": artifacts, "notices": copy_notices(out)}
        require(source_identity() == source and runtime_hashes() == runtime and verify_installation() == profile["toolchain"]["setup"]
            and all(regular_bytes(ROOT / n, 16 << 20) == d for n, d in retained.items()), "SMP user inputs changed during build")
        write_json(out / "manifest.json", manifest)
        return manifest
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        retain_private_error(out, error)
        write_json(out / "build-failure.json", {"status": "fail", "reason": type(error).__name__, "compile": receipts})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--out", type=Path, required=True); args = parser.parse_args()
    try: build(args.out)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, "SMP user build rejected: " + type(error).__name__ + "\n")
    print("SMP user cases built; qualification not established")
    return 0

if __name__ == "__main__": raise SystemExit(main())
