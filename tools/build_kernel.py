#!/usr/bin/env python3
"""Build the original K01 UEFI kernel and deterministic removable boot media."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_fixture import sha256, source_identity, public_linker_version
from tools.k01_media import make_disk, make_iso
from tools.setup_uefi import verify_installation

CASES = ("normal", "int3", "invalid_opcode", "page_fault", "panic", "reboot")


def inspect_pe(data: bytes) -> dict:
    """Require a relocatable x86-64 EFI application with no foreign imports."""
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("kernel lacks a DOS/PE header")
    offset = struct.unpack_from("<I", data, 60)[0]
    if offset + 24 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        raise ValueError("kernel lacks a valid PE signature")
    machine, count, stamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, offset + 4)
    optional = offset + 24
    sections_offset = optional + optional_size
    if (machine != 0x8664 or count == 0 or stamp != 0 or optional_size < 160
            or sections_offset + count * 40 > len(data) or characteristics & 1):
        raise ValueError("kernel must be deterministic relocatable PE64 x86-64")
    magic = struct.unpack_from("<H", data, optional)[0]
    entry = struct.unpack_from("<I", data, optional + 16)[0]
    subsystem = struct.unpack_from("<H", data, optional + 68)[0]
    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    if magic != 0x20b or subsystem != 10 or directory_count < 6 or directory_count > 16 or 112 + directory_count * 8 > optional_size:
        raise ValueError("kernel must be a PE32+ EFI application")
    if any(struct.unpack_from("<II", data, optional + 112 + index * 8) != (0, 0)
           for index in (1, 13) if index < directory_count):
        raise ValueError("kernel must not import a foreign OS runtime")
    relocations = struct.unpack_from("<II", data, optional + 112 + 5 * 8)
    if not all(relocations):
        raise ValueError("kernel needs UEFI base relocations")
    sections = []
    for index in range(count):
        at = sections_offset + index * 40
        name = data[at:at + 8].rstrip(b"\0").decode("ascii")
        virtual_size, rva, size, raw = struct.unpack_from("<IIII", data, at + 8)
        flags = struct.unpack_from("<I", data, at + 36)[0]
        if size and (raw < sections_offset + count * 40 or raw + size > len(data)):
            raise ValueError("PE section extends outside artifact")
        if flags & 0xa0000000 == 0xa0000000:
            raise ValueError("kernel section is writable and executable")
        sections.append({"name": name, "rva": rva, "virtual_size": virtual_size,
                         "size_bytes": size, "flags": flags})
    if not any(row["flags"] & 0x20000000 and row["rva"] <= entry < row["rva"] + row["virtual_size"] for row in sections):
        raise ValueError("kernel entry must belong to executable code")
    if not any(row["rva"] <= relocations[0] and relocations[0] + relocations[1] <= row["rva"] + row["size_bytes"] for row in sections):
        raise ValueError("kernel base relocation directory must belong to stored section bytes")
    return {"format": "PE32+", "architecture": "x86_64", "subsystem": "EFI_APPLICATION",
            "entry_rva": entry, "timestamp": stamp, "imports": [], "relocations": True,
            "sections": sections}


def build(out: Path) -> dict:
    out = out.resolve()
    if not out.is_relative_to(ROOT / "build"):
        raise ValueError("kernel output must be inside ignored build/")
    out.mkdir(parents=True, exist_ok=False)
    source = source_identity()
    setup = verify_installation()
    prefix = ROOT / "build" / "uefi"
    compiler = prefix / "bin" / "rustc"
    version = subprocess.check_output([str(compiler), "--version", "--verbose"], text=True, timeout=30).strip()
    host = next(line[6:] for line in version.splitlines() if line.startswith("host: "))
    linker = prefix / "lib" / "rustlib" / host / "bin" / "rust-lld"
    lock = json.loads((ROOT / "toolchain.lock.json").read_text())
    linker_version = public_linker_version(subprocess.check_output([str(linker), "-flavor", "gnu", "--version"], text=True, timeout=30).strip(), lock["rust"]["llvm_revision"])
    flags = ["--edition=2024", "--crate-name=tessryn_kernel", "--crate-type=bin",
             "--target=x86_64-unknown-uefi", "-Cpanic=abort", "-Copt-level=1", "-Ccodegen-units=1",
             "-Cdebuginfo=2", "-Cforce-frame-pointers=yes", "-Cno-redzone=yes", "-Cembed-bitcode=no",
             "-Clink-arg=/timestamp:0", "-Clink-arg=/debug:none"]
    notices = []
    notice_directory = out / "notices"
    notice_directory.mkdir()
    notice_sources = [("tessryn", name, ROOT / name) for name in ("LICENSE", "NOTICE")]
    notice_sources.extend(("rust", name, prefix / "notices" / "rust" / name)
                          for name in ("LICENSE-APACHE", "LICENSE-MIT", "COPYRIGHT"))
    for component, name, original in notice_sources:
        destination = notice_directory / f"{component}-{name}"
        destination.write_bytes(original.read_bytes())
        notices.append({"component": component, "path": destination.relative_to(out).as_posix(),
                        "sha256": sha256(destination), "size_bytes": destination.stat().st_size})
    artifacts = []
    for case in (*CASES, "deployment"):
        directory = out / case
        directory.mkdir()
        path = directory / "BOOTX64.EFI"
        case_flags = ["--cfg", f'k01_case="{"normal" if case == "deployment" else case}"']
        if case != "deployment":
            case_flags.extend(["--cfg", "k01_emulator"])
        command = [str(compiler), "kernel/main.rs", *flags, *case_flags,
                   f"-Clinker={linker}", f"--remap-path-prefix={ROOT}=tessryn",
                   f"--remap-path-prefix={prefix}=rust-toolchain", "-o", str(path)]
        execution = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
        log = (execution.stdout + execution.stderr).replace(str(ROOT), "tessryn").replace(str(prefix), "rust-toolchain")
        (directory / "build.log").write_text(log)
        if execution.returncode:
            raise ValueError(f"kernel {case} compile failed; inspect build.log")
        validation = inspect_pe(path.read_bytes())
        (directory / "boot.img").write_bytes(make_disk(path.read_bytes()))
        if case in ("normal", "deployment"):
            (directory / "boot.iso").write_bytes(make_iso(path.read_bytes()))
        for name in ("BOOTX64.EFI", "boot.img", "boot.iso"):
            artifact = directory / name
            if artifact.exists():
                artifacts.append({"path": artifact.relative_to(out).as_posix(), "case": case,
                                  "sha256": sha256(artifact), "size_bytes": artifact.stat().st_size,
                                  "rust_case_flags": case_flags,
                                  "pe_validation": validation if name == "BOOTX64.EFI" else None})
    manifest = {"schema_version": 1, "artifact_type": "tessryn-k01-kernel", "source": source,
                "toolchain": {"rustc_version": version, "linker_version": linker_version, "rust_flags": flags,
                              "setup": setup}, "artifacts": artifacts, "notices": notices,
                "capabilities": {"uefi_kernel": "implemented_requires_execution_evidence",
                                 "native_gpu": "unavailable", "network": "unavailable", "inference": "unavailable"}}
    if verify_installation() != setup or source_identity() != source:
        raise ValueError("source or toolchain changed during build; build into a new directory")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = build(args.out)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"kernel build rejected: {error}\n")
    print(json.dumps({"status": "built", "artifacts": len(manifest["artifacts"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
