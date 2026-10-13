#!/usr/bin/env python3
"""Build the four-case, single-CPU K02 UEFI enforcement experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_fixture import sha256, source_identity
from tools.build_kernel import compiler_profile, copy_notices, inspect_pe
from tools.k01_media import make_disk
from tools.setup_uefi import verify_installation

CASES = ("own_page", "foreign_read", "kernel_read", "readonly_write")
ARTIFACT_TYPE = "tessryn-k02-native-single-cpu"
CPU = "max,phys-bits=48,la57=off,nx=on,pcid=off,pge=off"
PROFILE = {"architecture": "x86_64", "target": "x86_64-unknown-uefi",
           "machine": "q35,accel=tcg", "cpu": CPU, "cpus": 1,
           "memory_bytes": 256 * 1024 * 1024, "physical_bits": 48,
           "paging_levels": 4, "nx": True, "pcid": False, "global_pages": False}
SCOPE = "four original-kernel single-CPU QEMU enforcement cases; full K02 protocol, physical hardware, SMP and DMA unqualified"
PROBE_SYMBOLS = ("k02_probe_own_write", "k02_probe_own_read", "k02_probe_own_return",
                 "k02_probe_foreign_read", "k02_probe_kernel_read", "k02_probe_readonly_write")


def coff_probes(data: bytes) -> tuple[bytes, dict[str, int]]:
    """Extract actual assembler labels from the compiler's x64 COFF object."""
    if len(data) < 20:
        raise ValueError("COFF object truncated")
    machine, count, _, symbols_at, symbols_count, optional, _ = struct.unpack_from("<HHIIIHH", data)
    if machine != 0x8664 or optional != 0 or not 0 < count <= 4096 or symbols_count > 1_000_000:
        raise ValueError("unsupported x64 COFF object")
    strings_at = symbols_at + symbols_count * 18
    if count * 40 + 20 > len(data) or strings_at + 4 > len(data):
        raise ValueError("COFF section/symbol table truncated")
    strings_size = struct.unpack_from("<I", data, strings_at)[0]
    if strings_size < 4 or strings_at + strings_size > len(data):
        raise ValueError("COFF strings truncated")
    sections = []
    for index in range(count):
        at = 20 + index * 40
        size, raw = struct.unpack_from("<II", data, at + 16)
        if raw + size > len(data):
            raise ValueError("COFF section data truncated")
        sections.append((raw, size))
    wanted = set(PROBE_SYMBOLS) | {"k02_user_code_start", "k02_user_code_end"}
    found = {}
    index = 0
    while index < symbols_count:
        at = symbols_at + index * 18
        name = data[at:at + 8]
        if name[:4] == b"\0" * 4:
            offset = struct.unpack_from("<I", name, 4)[0]
            if not 4 <= offset < strings_size:
                raise ValueError("COFF symbol string offset invalid")
            end = data.find(b"\0", strings_at + offset, strings_at + strings_size)
            if end < 0:
                raise ValueError("COFF symbol string unterminated")
            name = data[strings_at + offset:end]
        else:
            name = name.rstrip(b"\0")
        value, section, _, _, auxiliary = struct.unpack_from("<IhHBB", data, at + 8)
        decoded = name.decode("utf-8")
        if decoded in wanted:
            if decoded in found or not 1 <= section <= count:
                raise ValueError("COFF probe label duplicate or undefined")
            found[decoded] = (section, value)
        index += 1 + auxiliary
        if index > symbols_count:
            raise ValueError("COFF auxiliary symbols truncated")
    if set(found) != wanted:
        raise ValueError("actual COFF probe labels incomplete")
    section, start = found["k02_user_code_start"]
    if found["k02_user_code_end"] != (section, start + 4096):
        raise ValueError("user probe code must occupy exactly one page")
    raw, size = sections[section - 1]
    if start + 4096 > size:
        raise ValueError("probe page exceeds COFF section")
    offsets = {}
    for label in PROBE_SYMBOLS:
        seg, value = found[label]
        if seg != section or not start <= value < start + 4096:
            raise ValueError("probe label exceeds user code page")
        offsets[label] = value - start
    if len(set(offsets.values())) != len(offsets):
        raise ValueError("probe instructions alias")
    return data[raw + start:raw + start + 4096], offsets


def probe_binding(obj: bytes, efi: bytes) -> dict:
    code, offsets = coff_probes(obj)
    locations = []
    start = 0
    while (at := efi.find(code, start)) >= 0:
        locations.append(at)
        start = at + 1
    if len(locations) != 1:
        raise ValueError("linked EFI must contain the unique unchanged probe code page")
    inspect_pe(efi)
    pe = struct.unpack_from("<I", efi, 60)[0]
    count = struct.unpack_from("<H", efi, pe + 6)[0]
    optional = struct.unpack_from("<H", efi, pe + 20)[0]
    rvas = []
    for index in range(count):
        at = pe + 24 + optional + index * 40
        rva, size, raw = struct.unpack_from("<III", efi, at + 12)
        if raw <= locations[0] and locations[0] + len(code) <= raw + size:
            rvas.append(rva + locations[0] - raw)
    if len(rvas) != 1 or rvas[0] % 4096:
        raise ValueError("linked user code page must have a unique page-aligned RVA")
    return {"size_bytes": len(code), "sha256": hashlib.sha256(code).hexdigest(),
            "efi_file_offset": locations[0], "efi_rva": rvas[0], "offsets": offsets,
            "instruction_bytes": {label: code[offset:offset + 16].hex() for label, offset in offsets.items()}}


def dependency_paths(raw: str, root: Path, generated: set[Path]) -> list[str]:
    """Read rustc's actual dependency list, including include_str!/path modules."""
    paths: set[str] = set()
    for line in raw.replace("\\\n", " ").splitlines():
        if not line or line.startswith("#") or ": " not in line:
            continue
        for token in shlex.split(line.split(": ", 1)[1]):
            path = Path(token)
            if not path.is_absolute():
                path = root / path
            original = path
            for parent in (original, *original.parents):
                if parent == root:
                    break
                if parent.is_symlink():
                    raise ValueError("compiler dependency must not traverse source symlinks")
            path = path.resolve()
            if path in generated:
                continue
            if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
                raise ValueError("compiler dependency escapes regular repository sources")
            paths.add(path.relative_to(root).as_posix())
    if not paths:
        raise ValueError("compiler emitted no source dependencies")
    return sorted(paths)


def compile_flags(profile: dict, library: bool = False) -> list[str]:
    flags = list(profile["toolchain"]["rust_flags"])
    flags = [flag for flag in flags if not flag.startswith("--crate-name=")
             and not flag.startswith("--crate-type=")]
    if library:
        flags = [flag for flag in flags if not flag.startswith("-Clink-arg=")]
    return [*flags, "--crate-name=" + ("tessryn_owned_memory" if library else "tessryn_k02_native"),
            "--crate-type=" + ("rlib" if library else "bin")]


def case_flags(case: str) -> list[str]:
    if case not in CASES:
        raise ValueError("unknown K02 native case")
    return ["--cfg", "k01_emulator", "--cfg", "k02_native", "--cfg", f'k02_case="{case}"']


def build(out: Path) -> dict:
    out = out.resolve()
    if not out.is_relative_to(ROOT / "build"):
        raise ValueError("K02 output must be in ignored build/")
    out.mkdir(parents=True, exist_ok=False)
    source = source_identity()
    profile = compiler_profile()
    setup = profile["toolchain"]["setup"]
    prefix = ROOT / "build/uefi"
    library = out / "libtessryn_owned_memory.rlib"
    dependencies: set[str] = set()
    commands: dict[str, list[str]] = {}

    def compile_one(name: str, src: str, target: Path, flags: list[str]) -> None:
        depfile = target.parent / (name + ".d")
        emits = f"link,dep-info={depfile}"
        if name != "core":
            emits += f",obj={target.parent / 'kernel.obj'}"
        arguments = [src, *flags, f"--emit={emits}",
                     f"--remap-path-prefix={ROOT}=tessryn",
                     f"--remap-path-prefix={prefix}=rust-toolchain",
                     f"--remap-path-prefix={out}=k02-build"]
        if name != "core":
            arguments += [f"-Clinker={profile['linker']}", "--extern", f"tessryn_owned_memory={library}"]
        arguments += ["-o", str(target)]
        execution = subprocess.run([str(profile["compiler"]), *arguments], cwd=ROOT,
                                   capture_output=True, text=True, timeout=90)
        log = (execution.stdout + execution.stderr).replace(str(prefix), "rust-toolchain").replace(str(out), "k02-build").replace(str(ROOT), "tessryn")
        (target.parent / (name + "-build.log")).write_text(log)
        if execution.returncode:
            raise ValueError(f"K02 {name} compile failed; inspect build log")
        paths = dependency_paths(depfile.read_text(), ROOT, {library})
        dependencies.update(paths)
        depfile.unlink()
        commands[name] = [arg.replace(str(prefix), "rust-toolchain").replace(str(out), "k02-build").replace(str(ROOT), "tessryn") for arg in arguments]

    compile_one("core", "kernel-core/lib.rs", library, compile_flags(profile, True))
    artifacts = [{"path": library.name, "kind": "target_rlib", "crate": "tessryn_owned_memory",
                  "target": PROFILE["target"], "sha256": sha256(library), "size_bytes": library.stat().st_size}]
    probes = {}
    for case in CASES:
        directory = out / case
        directory.mkdir()
        efi = directory / "BOOTX64.EFI"
        compile_one(case, "kernel/main.rs", efi, [*compile_flags(profile), *case_flags(case)])
        validation = inspect_pe(efi.read_bytes())
        obj = directory / "kernel.obj"
        probes[case] = probe_binding(obj.read_bytes(), efi.read_bytes())
        disk = directory / "boot.img"
        disk.write_bytes(make_disk(efi.read_bytes()))
        for path, kind in ((efi, "kernel_efi"), (disk, "boot_disk"), (obj, "compiler_object")):
            artifacts.append({"path": path.relative_to(out).as_posix(), "kind": kind, "case": case,
                              "sha256": sha256(path), "size_bytes": path.stat().st_size,
                              "pe_validation": validation if kind == "kernel_efi" else None})
    files = {name: sha256(ROOT / name) for name in sorted(dependencies)}
    if "kernel-core/lib.rs" not in files or "kernel/main.rs" not in files or "kernel/entry.S" not in files:
        raise ValueError("actual compiler dependencies lack kernel/core/assembly")
    manifest = {"schema_version": 1, "artifact_type": ARTIFACT_TYPE, "source": source,
                "source_files": files, "source_files_sha256": hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "toolchain": profile["toolchain"], "profile": PROFILE, "cases": list(CASES),
                "compile_commands": commands, "probes": probes, "artifacts": artifacts, "notices": copy_notices(out),
                "scope": SCOPE}
    if source_identity() != source or verify_installation() != setup:
        raise ValueError("source or checked toolchain changed during K02 build")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(args.out)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"K02 build rejected: {error}\n")
    print(json.dumps({"status": "built", "cases": result["cases"], "scope": SCOPE}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
