#!/usr/bin/env python3
"""Build source-bound HPET timer scenarios and the original K03 policy."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k03_timer_protocol import (CASES, PROFILE, ARTIFACT_TYPE, SCOPE, DESCRIPTOR_SIZE,
    require, digest, regular_bytes, file_ref, write_json, fresh_output, case_flags, descriptor_bytes, retain_private_error, SCHEDULER_SHA256)
from tools.k03_timer_provenance import COMPILER_SOURCES, runtime_hashes, canonical
from tools.build_fixture import source_identity
from tools.build_kernel import compiler_profile, copy_notices, inspect_pe
from tools.build_k02_native import compile_flags, dependency_paths
from tools.k01_media import make_disk
from tools.g03.process import run_bounded
from tools.setup_uefi import verify_installation


def coff_regions(data):
    require(len(data) >= 20, "region COFF header truncated")
    machine, count, _, symbols_at, symbols_count, optional, _ = struct.unpack_from("<HHIIIHH", data)
    strings_at = symbols_at + symbols_count * 18
    require(machine == 0x8664 and optional == 0 and 0 < count <= 4096 and symbols_count <= 1_000_000
            and 20 + count * 40 <= len(data) and strings_at + 4 <= len(data), "region COFF tables invalid")
    strings_size = struct.unpack_from("<I", data, strings_at)[0]
    require(4 <= strings_size <= len(data) - strings_at, "region COFF strings truncated")
    sections = []
    for i in range(count):
        at = 20 + i * 40
        size, raw, relocations = struct.unpack_from("<III", data, at + 16)
        relocation_count = struct.unpack_from("<H", data, at + 32)[0]
        require(raw + size <= len(data) and relocations + relocation_count * 10 <= len(data), "region COFF section truncated")
        sections.append({"raw": raw, "size": size, "relocations": relocations, "relocation_count": relocation_count})
    symbols, i = {}, 0
    while i < symbols_count:
        at = symbols_at + i * 18
        name = data[at:at + 8]
        if name[:4] == bytes(4):
            offset = struct.unpack_from("<I", name, 4)[0]
            end = data.find(b"\0", strings_at + offset, strings_at + strings_size)
            require(4 <= offset < strings_size and end >= 0, "region COFF symbol name invalid")
            name = data[strings_at + offset:end]
        else:
            name = name.rstrip(b"\0")
        try:
            name = name.decode("ascii")
        except UnicodeError as error:
            raise ValueError("region COFF symbol name is not ASCII") from error
        value, section, _, storage, auxiliary = struct.unpack_from("<IhHBB", data, at + 8)
        relevant = name == "K03_TIMER_CONTRACT" or re.fullmatch(r"(?:region_program_[ab]_(?:start|end)|(?:region|timer)_[ab]_[a-z0-9_]+)", name)
        if relevant and storage == 2:
            require(name not in symbols and 1 <= section <= count, "region symbol duplicate or undefined")
            symbols[name] = (section, value)
        elif relevant and (name.endswith(("_trap", "_start", "_end")) or name == "K03_TIMER_CONTRACT"):
            raise ValueError("region evidence symbol is not externally defined")
        i += auxiliary + 1
        require(i <= symbols_count, "region COFF auxiliary symbols truncated")
    return sections, symbols


def object_bytes(obj, sections, location, length):
    section, start = location
    info = sections[section - 1]
    require(0 <= start and start + length <= info["size"], "region symbol exceeds COFF section")
    for i in range(info["relocation_count"]):
        address = struct.unpack_from("<I", obj, info["relocations"] + i * 10)[0]
        require(not start <= address < start + length, "region immutable program/descriptor has relocations")
    return obj[info["raw"] + start:info["raw"] + start + length]


def linked_region(efi, raw, executable):
    inspect_pe(efi)
    at = efi.find(raw)
    require(at >= 0 and efi.find(raw, at + 1) < 0, "region bytes are not unique and unchanged in linked EFI")
    pe = struct.unpack_from("<I", efi, 60)[0]
    count, optional = struct.unpack_from("<H", efi, pe + 6)[0], struct.unpack_from("<H", efi, pe + 20)[0]
    found = []
    for i in range(count):
        section = pe + 24 + optional + i * 40
        rva, size, start = struct.unpack_from("<III", efi, section + 12)
        flags = struct.unpack_from("<I", efi, section + 36)[0]
        if start <= at and at + len(raw) <= start + size:
            require(flags & 0x40000000 and bool(flags & 0x20000000) == executable and not flags & 0x80000000,
                    "region linked section permissions differ")
            found.append(rva + at - start)
    require(len(found) == 1, "region linked section ambiguous")
    return {"size_bytes": len(raw), "sha256": digest(raw), "efi_file_offset": at, "efi_rva": found[0]}


def timer_binding(obj, efi, case):
    sections, symbols = coff_regions(obj)
    require("K03_TIMER_CONTRACT" in symbols, "timer compiled descriptor missing")
    descriptor = object_bytes(obj, sections, symbols["K03_TIMER_CONTRACT"], DESCRIPTOR_SIZE)
    require(descriptor == descriptor_bytes(case), "region compiled descriptor differs from scenario/profile")
    result = {"descriptor": linked_region(efi, descriptor, False), "programs": {}}
    used = {"K03_TIMER_CONTRACT"}
    for name in ("a", "b"):
        start, end = "region_program_" + name + "_start", "region_program_" + name + "_end"
        require(start in symbols and end in symbols and symbols[end] == (symbols[start][0], symbols[start][1] + 4096),
                "region program must occupy exactly one COFF page")
        code = object_bytes(obj, sections, symbols[start], 4096)
        offsets = {}
        for label, (section, offset) in symbols.items():
            if label.startswith(("timer_" + name + "_", "region_" + name + "_")):
                require(section == symbols[start][0] and symbols[start][1] <= offset < symbols[start][1] + 4096,
                        "region stage label exceeds program page")
                offset -= symbols[start][1]
                if label.endswith("_trap"):
                    require(offset >= 2 and code[offset - 2:offset] == b"\xcd\x80", "region syscall continuation is not post-INT80")
                offsets[label] = offset
                used.add(label)
        require(any(label.endswith("_trap") for label in offsets), "region program has no bound syscall continuation")
        require({f"timer_{name}_spin_start", f"timer_{name}_spin_end"} <= set(offsets)
                and offsets[f"timer_{name}_spin_start"] < offsets[f"timer_{name}_spin_end"], "timer nontrapping spin bounds incomplete")
        binding = linked_region(efi, code, True)
        require(binding["efi_rva"] % 4096 == 0, "region linked program page is not aligned")
        result["programs"][name] = {**binding, "offsets": offsets,
            "instruction_bytes": {label: code[offset:offset + 16].hex() for label, offset in offsets.items()}}
        used.update((start, end))
    require(set(symbols) == used, "region unknown compiled evidence symbol")
    require(result["programs"]["a"]["sha256"] != result["programs"]["b"]["sha256"], "region programs must be independent code pages")
    return result


def compilation_sources():
    retained, total = {}, 0
    for directory in ("kernel", "kernel-core", "scheduler-core", "interfaces"):
        base = ROOT / directory
        require(not base.is_symlink() and base.is_dir(), "region source directory invalid")
        for path in sorted(base.rglob("*")):
            require(not path.is_symlink(), "region compiler source aliases another path")
            if path.is_dir():
                continue
            data = regular_bytes(path, 16 << 20)
            total += len(data)
            require(len(retained) < 512 and total <= 64 << 20, "region compiler source snapshot exceeds bounds")
            retained[path.relative_to(ROOT).as_posix()] = data
    require(set(COMPILER_SOURCES) <= set(retained), "region required compiler sources unavailable")
    return retained


def build(out):
    out = fresh_output(out)
    dependencies, commands, receipts, bindings = set(), {}, [], {}
    try:
        source, runtime = source_identity(), runtime_hashes()
        profile = compiler_profile()
        setup = profile["toolchain"]["setup"]
        prefix = ROOT / "build/uefi"
        retained = compilation_sources()
        require(digest(retained["scheduler-core/lib.rs"]) == SCHEDULER_SHA256, "K03 reference policy changed")
        libraries = {"core": out / "libtessryn_owned_memory.rlib", "scheduler": out / "libtessryn_scheduler.rlib"}
        with tempfile.TemporaryDirectory(prefix="source-", dir=out) as temporary:
            snapshot = Path(temporary)
            for name, data in retained.items():
                path = snapshot / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o400)

            def public(value):
                return str(value).replace(str(snapshot), "tessryn").replace(str(prefix), "rust-toolchain").replace(str(out), "timer-build").replace(str(ROOT), "tessryn")

            def compile_one(name, target, library=False):
                depfile = target.parent / (name + ".d")
                emits = f"link,dep-info={depfile}" + ("" if library else f",obj={target.parent / 'kernel.obj'}")
                source_name = "kernel-core/lib.rs" if name == "core" else "scheduler-core/lib.rs" if name == "scheduler" else "kernel/main.rs"
                flags = compile_flags(profile, library)
                if name == "scheduler":
                    flags = ["--crate-name=tessryn_scheduler" if flag.startswith("--crate-name=") else flag for flag in flags]
                arguments = [source_name, *flags,
                    *([] if library else case_flags(name)), "--emit=" + emits,
                    f"--remap-path-prefix={prefix}=rust-toolchain", f"--remap-path-prefix={out}=timer-build",
                    f"--remap-path-prefix={snapshot}=tessryn"]
                if not library:
                    arguments += [f'-Clinker={profile["linker"]}', "--extern", f"tessryn_owned_memory={libraries['core']}",
                                  "--extern", f"tessryn_scheduler={libraries['scheduler']}"]
                arguments += ["-o", str(target)]
                execution = run_bounded([str(profile["compiler"]), *arguments], snapshot, 90, 1 << 20)
                logs = []
                for stream in ("stdout", "stderr"):
                    log = target.parent / (name + "-" + stream + ".log")
                    log.write_bytes(getattr(execution, stream))
                    logs.append(file_ref(out, log))
                receipts.append({"role": name, "status": execution.status, "returncode": execution.returncode,
                    "elapsed_seconds": execution.elapsed_seconds, "stdout": logs[0], "stderr": logs[1]})
                require(execution.status == "completed" and execution.returncode == 0, "region compilation failed; raw diagnostics retained privately")
                require(not any(str(ROOT).encode() in getattr(execution, stream) or str(snapshot).encode() in getattr(execution, stream)
                                for stream in ("stdout", "stderr")), "region successful compiler diagnostics contain local paths")
                found = dependency_paths(depfile.read_text(), snapshot, set(libraries.values()))
                require(all(name in retained for name in found), "region compiler read unretained source")
                dependencies.update(found)
                depfile.unlink()
                commands[name] = [public(argument) for argument in arguments]

            artifacts = []
            for role, library in libraries.items():
                compile_one(role, library, True)
                artifacts.append({**file_ref(out, library), "kind": "target_rlib", "target": PROFILE["target"],
                                  "crate": "tessryn_owned_memory" if role == "core" else "tessryn_scheduler"})
            for case in CASES:
                directory = out / case
                directory.mkdir()
                efi = directory / "BOOTX64.EFI"
                compile_one(case, efi)
                obj = directory / "kernel.obj"
                efi_bytes = regular_bytes(efi)
                bindings[case] = timer_binding(regular_bytes(obj), efi_bytes, case)
                disk = directory / "boot.img"
                disk.write_bytes(make_disk(efi_bytes))
                for path, kind in ((efi, "kernel_efi"), (disk, "boot_disk"), (obj, "compiler_object")):
                    artifacts.append({**file_ref(out, path), "kind": kind, "case": case})
            require(all(regular_bytes(snapshot / name, 16 << 20) == data for name, data in retained.items()), "region source snapshot changed during compilation")
        require(dependencies == set(COMPILER_SOURCES), "region compiler dependency set differs from reviewed profile")
        sources = {name: digest(retained[name]) for name in sorted(dependencies)}
        source_refs = []
        for name in sorted(set(sources) | set(runtime)):
            data = retained[name] if name in retained else regular_bytes(ROOT / name, 16 << 20)
            path = out / "sources" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            source_refs.append(file_ref(out, path))
        manifest = {"schema_version": 1, "artifact_type": ARTIFACT_TYPE, "source": source,
            "source_files": sources, "source_files_sha256": digest(canonical(sources).encode()), "runtime_files": runtime,
            "retained_sources": source_refs, "toolchain": profile["toolchain"], "profile": PROFILE, "cases": list(CASES),
            "qualification": "not_established", "compile_commands": commands, "compile": receipts,
            "bindings": bindings, "artifacts": artifacts, "notices": copy_notices(out), "scope": SCOPE}
        require(source_identity() == source and compilation_sources() == retained and runtime_hashes() == runtime
                and verify_installation() == setup, "region source, runtime or pinned tools changed during build")
        write_json(out / "manifest.json", manifest)
        return manifest
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        retain_private_error(out, error)
        write_json(out / "build-failure.json", {"status": "failed", "reason": type(error).__name__, "compile": receipts,
            "qualification": "not_established", "raw_diagnostics_published": False})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.out)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, "K03 timer build rejected: " + type(error).__name__ + "\n")
    print("K03 timer service scenarios built; qualification not established")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
