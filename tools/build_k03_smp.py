#!/usr/bin/env python3
"""Build two bounded source-bound AP bootstrap cases with the checked K01 tools."""
from __future__ import annotations
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k03_smp_protocol import (CASES, PROFILE, ARTIFACT_TYPE, SCOPE, require, digest, regular_bytes,
    file_ref, write_json, fresh_output, retain_private_error, descriptor_bytes, case_flags)
from tools.k03_smp_provenance import COMPILER_SOURCES, runtime_hashes, canonical, expected_commands
from tools.build_fixture import source_identity
from tools.build_kernel import compiler_profile, copy_notices, inspect_pe
from tools.g03.process import run_bounded
from tools.k01_media import make_disk
from tools.setup_uefi import verify_installation


def coff_binding(obj, efi, case):
    require(len(obj) >= 20, "SMP COFF header truncated")
    machine, count, _, symbol_at, symbol_count, optional, _ = struct.unpack_from("<HHIIIHH", obj)
    strings = symbol_at + symbol_count * 18
    require(machine == 0x8664 and optional == 0 and 0 < count <= 4096 and symbol_count <= 1_000_000
        and 20 + count * 40 <= len(obj) and strings + 4 <= len(obj), "SMP COFF tables malformed")
    string_size = struct.unpack_from("<I", obj, strings)[0]
    require(4 <= string_size <= len(obj) - strings, "SMP COFF strings truncated")
    sections = []
    for i in range(count):
        at = 20 + i * 40
        size, raw, relocs = struct.unpack_from("<III", obj, at + 16)
        reloc_count = struct.unpack_from("<H", obj, at + 32)[0]
        flags = struct.unpack_from("<I", obj, at + 36)[0]
        require((raw > 0 and raw + size <= len(obj) or raw == 0 and reloc_count == 0 and (size == 0 or flags & 0x80))
            and relocs + reloc_count * 10 <= len(obj), "SMP COFF section truncated")
        sections.append((raw, size, relocs, reloc_count, flags))
    wanted = {"K03_SMP_CONTRACT", "smp_trampoline_start", "smp_trampoline_end", "smp_heartbeat_start", "smp_heartbeat_end"}
    symbols, i = {}, 0
    while i < symbol_count:
        at = symbol_at + i * 18
        name = obj[at:at + 8]
        if name[:4] == bytes(4):
            offset = struct.unpack_from("<I", name, 4)[0]
            end = obj.find(b"\0", strings + offset, strings + string_size)
            require(4 <= offset < string_size and end >= 0, "SMP COFF symbol name malformed")
            name = obj[strings + offset:end]
        else:
            name = name.rstrip(b"\0")
        name = name.decode("ascii")
        value, section, _, storage, auxiliary = struct.unpack_from("<IhHBB", obj, at + 8)
        if name in wanted:
            require(name not in symbols and storage == 2 and 1 <= section <= count, "SMP binding symbol duplicate/undefined")
            symbols[name] = section, value
        i += auxiliary + 1
        require(i <= symbol_count, "SMP COFF auxiliary symbols truncated")
    require(set(symbols) == wanted, "SMP compiled binding symbols missing")

    def extract(name, length):
        section, start = symbols[name]
        raw, size, relocs, relcount, flags = sections[section - 1]
        require(raw > 0 and not flags & 0x80 and start + length <= size, "SMP binding exceeds stored initialized COFF section")
        for j in range(relcount):
            position = struct.unpack_from("<I", obj, relocs + j * 10)[0]
            require(not start <= position < start + length, "SMP immutable descriptor/trampoline has relocations")
        return obj[raw + start:raw + start + length]

    require(symbols["smp_trampoline_end"] == (symbols["smp_trampoline_start"][0], symbols["smp_trampoline_start"][1] + 4096), "SMP trampoline must occupy exactly one page")
    descriptor, trampoline = extract("K03_SMP_CONTRACT", 96), extract("smp_trampoline_start", 4096)
    require(symbols["smp_heartbeat_end"] == (symbols["smp_heartbeat_start"][0], symbols["smp_heartbeat_start"][1] + 8), "SMP heartbeat loop must be exactly eight bytes")
    heartbeat = extract("smp_heartbeat_start", 8)
    require(heartbeat == bytes.fromhex("f048ff07f390ebf8"), "SMP heartbeat is not locked increment/pause/local backjump")
    require(descriptor == descriptor_bytes(case), "SMP compiled contract differs")
    pe_info = inspect_pe(efi)
    pe = struct.unpack_from("<I", efi, 60)[0]
    optional = struct.unpack_from("<H", efi, pe + 20)[0]
    image_size = struct.unpack_from("<I", efi, pe + 24 + 56)[0]

    def linked(data, is_descriptor=False, executable=False):
        at = efi.find(data)
        require(at >= 0 and efi.find(data, at + 1) < 0, "SMP binding bytes not unique and unchanged in EFI")
        matches = []
        for i in range(len(pe_info["sections"])):
            row = pe + 24 + optional + i * 40
            rva, size, raw = struct.unpack_from("<III", efi, row + 12)
            flags = struct.unpack_from("<I", efi, row + 36)[0]
            if raw <= at and at + len(data) <= raw + size:
                require(flags & 0x40000000 and not flags & 0x80000000
                    and (not is_descriptor or not flags & 0x20000000) and (not executable or flags & 0x20000000), "SMP linked binding permissions differ")
                matches.append(rva + at - raw)
        require(len(matches) == 1, "SMP binding section ambiguous")
        return {"size_bytes": len(data), "sha256": digest(data), "efi_file_offset": at, "efi_rva": matches[0]}

    return {"descriptor": linked(descriptor, True), "trampoline": linked(trampoline), "heartbeat": linked(heartbeat, executable=True),
        "image_size": image_size, "executable_ranges": [[r["rva"], r["rva"] + r["virtual_size"]]
            for r in pe_info["sections"] if r["flags"] & 0x20000000]}


def dependency_paths(data, snapshot):
    import shlex
    result = set()
    for line in data.replace("\\\n", " ").splitlines():
        if not line or line.startswith("#") or ": " not in line:
            continue
        for token in shlex.split(line.split(": ", 1)[1]):
            path = Path(token)
            if not path.is_absolute(): path = snapshot / path
            require(path.is_relative_to(snapshot) and ".." not in path.parts, "SMP compiler dependency escapes snapshot")
            regular_bytes(path, 16 << 20)
            result.add(path.relative_to(snapshot).as_posix())
    require(result, "SMP compiler dependency list empty")
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
            require(not path.is_symlink(), "SMP compiler snapshot contains alias")
            if path.is_file(): retained[path.relative_to(ROOT).as_posix()] = regular_bytes(path, 16 << 20)
        require(len(retained) <= 512 and sum(map(len, retained.values())) <= 64 << 20
            and set(COMPILER_SOURCES) <= set(retained), "SMP compiler snapshot incomplete/oversized")
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
                    f"--emit=link,obj={obj},dep-info={dep}", f"--remap-path-prefix={snapshot}=tessryn",
                    f"--remap-path-prefix={prefix}=rust-toolchain", f"--remap-path-prefix={out}=smp-build",
                    "-Clinker=" + str(profile["linker"]), "-o", str(efi)]
                execution = run_bounded([str(profile["compiler"]), *args], snapshot, 90, 1 << 20)
                row = {"role": case, "status": execution.status, "returncode": execution.returncode, "elapsed_seconds": execution.elapsed_seconds}
                for stream in ("stdout", "stderr"):
                    log = directory / (stream + ".log"); log.write_bytes(getattr(execution, stream)); row[stream] = file_ref(out, log)
                receipts.append(row)
                require(execution.status == "completed" and execution.returncode == 0, "SMP compilation failed; diagnostics retained privately")
                require(all(str(ROOT).encode() not in getattr(execution, s) for s in ("stdout", "stderr")), "SMP successful compiler output contains local paths")
                dependencies.update(dependency_paths(dep.read_text(), snapshot)); dep.unlink()
                commands[case] = [a.replace(str(snapshot), "tessryn").replace(str(prefix), "rust-toolchain").replace(str(out), "smp-build") for a in args]
                bindings[case] = coff_binding(regular_bytes(obj), regular_bytes(efi), case)
                (directory / "boot.img").write_bytes(make_disk(regular_bytes(efi)))
                for name in ("BOOTX64.EFI", "kernel.obj", "boot.img"):
                    artifacts.append({**file_ref(out, directory / name), "case": case})
            require(all(regular_bytes(snapshot / n, 16 << 20) == d for n, d in retained.items()), "SMP compiler snapshot changed")
        require(dependencies == set(COMPILER_SOURCES), "SMP actual compiler closure differs")
        require(commands == expected_commands(profile), "SMP normalized compiler commands differ")
        refs = []
        for name in sorted(set(COMPILER_SOURCES) | set(runtime)):
            path = out / "sources" / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(retained[name] if name in retained else regular_bytes(ROOT / name, 16 << 20)); refs.append(file_ref(out, path))
        manifest = {"format": "tessryn-k03-smp-build/v1", "artifact_type": ARTIFACT_TYPE,
            "source": source, "source_files": {n: digest(retained[n]) for n in COMPILER_SOURCES},
            "runtime_files": runtime, "retained_sources": refs, "toolchain": profile["toolchain"],
            "profile": PROFILE, "cases": list(CASES), "scope": SCOPE, "qualification": "not_established",
            "compile_commands": commands, "compile": receipts, "bindings": bindings, "artifacts": artifacts, "notices": copy_notices(out)}
        require(source_identity() == source and runtime_hashes() == runtime and verify_installation() == profile["toolchain"]["setup"]
            and all(regular_bytes(ROOT / n, 16 << 20) == d for n, d in retained.items()), "SMP inputs changed during build")
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
        parser.exit(1, "SMP build rejected: " + type(error).__name__ + "\n")
    print("SMP bootstrap cases built; qualification not established")
    return 0

if __name__ == "__main__": raise SystemExit(main())
