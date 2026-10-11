#!/usr/bin/env python3
"""Build original ROM fixtures and validate a separate freestanding Rust ELF probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fixtures.rom import make_rom  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command: list[str]) -> str:
    return subprocess.check_output(command, cwd=ROOT, text=True, timeout=30).strip()


def source_identity() -> dict:
    revision = command_output(["git", "rev-parse", "HEAD"])
    dirty = bool(command_output(["git", "status", "--porcelain", "--untracked-files=all"]))
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, timeout=30,
    ).decode().split("\0")
    digest = hashlib.sha256()
    for name in sorted(set(filter(None, names))):
        path = ROOT / name
        if path.is_file():
            digest.update(name.encode() + b"\0" + sha256(path).encode() + b"\0")
        else:
            digest.update(name.encode() + b"\0deleted\0")
    return {"revision": revision, "dirty": dirty, "tree_sha256": digest.hexdigest()}


def inspect_elf(path: Path) -> dict:
    """Check layout/runtime requirements directly, with no external inspection tool."""
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Rust probe must be little-endian ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    _, kind, machine, _, entry, phoff, shoff, _, _, phsize, phcount, shsize, shcount, strings_index = header
    if kind != 2 or machine != 62 or phsize != 56 or shsize != 64:
        raise ValueError("Rust probe must be an x86_64 ELF executable")
    if phoff + phsize * phcount > len(data) or shoff + shsize * shcount > len(data):
        raise ValueError("ELF table extends past artifact")
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + index * phsize) for index in range(phcount)]
    if any(item[0] in (2, 3) for item in headers):
        raise ValueError("freestanding probe must not require a dynamic loader")
    loads = [item for item in headers if item[0] == 1]
    if not loads or not any(item[1] & 1 and item[3] <= entry < item[3] + item[6] for item in loads):
        raise ValueError("entry must be in an executable load segment")
    if entry != 0x100000 or any(item[1] & 3 == 3 for item in loads):
        raise ValueError("probe layout must start at 1 MiB without writable executable segments")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shsize) for index in range(shcount)]
    if strings_index >= len(sections):
        raise ValueError("invalid ELF section string table")

    def section_bytes(section: tuple) -> bytes:
        offset, size = section[4:6]
        if offset + size > len(data):
            raise ValueError("ELF section extends past artifact")
        return data[offset:offset + size]

    names = section_bytes(sections[strings_index])
    named = {}
    for section in sections:
        offset = section[0]
        if offset >= len(names):
            raise ValueError("invalid ELF section name")
        name = names[offset:].split(b"\0", 1)[0].decode("ascii")
        named[name] = section
    required = {".debug_info", ".debug_line", ".symtab"}
    if not required.issubset(named) or any(named[name][5] == 0 for name in required):
        raise ValueError("probe must retain DWARF debug information and symbols")
    symbols = named[".symtab"]
    if symbols[6] >= len(sections) or symbols[9] != 24:
        raise ValueError("invalid ELF symbol table")
    strings = section_bytes(sections[symbols[6]])
    undefined = []
    entry_symbol = False
    symbols_data = section_bytes(symbols)
    if len(symbols_data) % 24:
        raise ValueError("invalid ELF symbol table size")
    for offset in range(0, len(symbols_data), 24):
        name_at, _, _, section_index, value, _ = struct.unpack_from("<IBBHQQ", symbols_data, offset)
        if name_at >= len(strings):
            raise ValueError("invalid ELF symbol name")
        name = strings[name_at:].split(b"\0", 1)[0].decode("ascii")
        if name and section_index == 0:
            undefined.append(name)
        entry_symbol |= name == "fixture_entry" and value == entry
    if undefined or not entry_symbol:
        raise ValueError("probe must define fixture_entry and have no undefined symbols")
    return {
        "format": "ELF64", "architecture": "x86_64", "entry_address": entry,
        "dynamic_loader": False, "undefined_symbols": [],
        "debug_sections": sorted(required - {".symtab"}), "entry_symbol": "fixture_entry",
        "executed": False,
    }


def resolve_tool(name: str, environment: str) -> Path:
    selected = os.environ.get(environment)
    local = ROOT / "build" / "toolchain" / "bin" / name
    candidate = selected or (str(local) if local.is_file() else shutil.which(name))
    if not candidate:
        raise ValueError(f"{name} unavailable; run python3 tools/setup_toolchain.py")
    path = Path(candidate).resolve()
    if not path.is_file():
        raise ValueError(f"{name} unavailable; selected tool is not a file")
    return path


def build(out: Path) -> dict:
    source = source_identity()
    lock = json.loads((ROOT / "toolchain.lock.json").read_text())
    out = out.resolve()
    if not out.is_relative_to(ROOT / "build"):
        raise ValueError("fixture outputs must be inside ignored build/")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError("output directory must be empty for a fresh build")
    compiler = resolve_tool("rustc", "TESSRYN_RUSTC")
    qemu = resolve_tool("qemu-system-x86_64", "TESSRYN_QEMU")
    rust_version = command_output([str(compiler), "--version", "--verbose"])
    if f"release: {lock['rust']['version']}\n" not in rust_version + "\n" or f"commit-hash: {lock['rust']['revision']}\n" not in rust_version + "\n":
        raise ValueError("Rust compiler version/revision does not match toolchain.lock.json")
    qemu_version = command_output([str(qemu), "--version"]).splitlines()[0]
    if qemu_version.split()[:4] != ["QEMU", "emulator", "version", lock["qemu"]["version"]]:
        raise ValueError("QEMU version does not match toolchain.lock.json")
    sysroot = Path(command_output([str(compiler), "--print", "sysroot"]))
    host_line = next(line for line in rust_version.splitlines() if line.startswith("host: "))
    host = host_line.split(": ", 1)[1]
    linker = sysroot / "lib" / "rustlib" / host / "bin" / "rust-lld"
    if not linker.is_file():
        raise ValueError("bundled rust-lld unavailable; use the pinned upstream toolchain")
    rust_flags = [
        "--edition=2024", "--crate-name=g03_probe", "--crate-type=bin",
        "--target=x86_64-unknown-none", "-Cpanic=abort", "-Copt-level=1",
        "-Ccodegen-units=1", "-Ccode-model=small", "-Crelocation-model=static",
        "-Cdebuginfo=2", "-Cdwarf-version=4", "-Cforce-frame-pointers=yes",
        "-Cno-redzone=yes", "-Cembed-bitcode=no", "-Clink-arg=--build-id=none",
        "-Clink-arg=-Tfixtures/rust-probe.ld",
    ]
    command = [str(compiler), "fixtures/rust-probe.rs", *rust_flags,
               f"-Clinker={linker}", f"--remap-path-prefix={ROOT}=tessryn",
               f"--remap-path-prefix={sysroot}=rust-toolchain", "-o", str(out / "rust-probe.elf")]
    built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    log = (built.stdout + built.stderr).replace(str(ROOT), "tessryn").replace(str(sysroot), "rust-toolchain")
    (out / "build.log").write_text(log)
    if built.returncode:
        raise ValueError("Rust probe compilation failed; inspect build.log")
    validation = inspect_elf(out / "rust-probe.elf")
    (out / "pass.rom").write_bytes(make_rom())
    (out / "hang.rom").write_bytes(make_rom(hang=True))
    artifacts = []
    for name, role in (("pass.rom", "emulator_pass_fixture"), ("hang.rom", "emulator_timeout_fixture"), ("rust-probe.elf", "compiler_layout_debug_probe")):
        artifact = out / name
        artifacts.append({"path": name, "sha256": sha256(artifact), "size_bytes": artifact.stat().st_size, "role": role})
    original = {
        "name": "g03-original-fixtures", "source": "https://github.com/AG187-Lab/tessryn",
        "revision": source["revision"], "license": "Apache-2.0",
        "roles": ["test_fixture", "compiler_layout_debug_probe"],
        "modified_files": ["fixtures/rom.py", "fixtures/rust-probe.rs", "fixtures/rust-probe.ld"],
        "notices": ["LICENSE"], "distribution_requirements": "Preserve the repository Apache-2.0 license.",
    }
    components = [original]
    for name, spec, roles, notices in (
        ("rust", lock["rust"], ["build_tool", "freestanding_core_and_compiler_builtins"], ["LICENSE-APACHE", "LICENSE-MIT", "COPYRIGHT"]),
        ("qemu", lock["qemu"], ["external_emulator"], ["COPYING", "COPYING.LIB", "LICENSE"]),
    ):
        components.append({
            "name": name, "version": spec["version"], "revision": spec["revision"],
            "source": spec.get("url", spec.get("hash_source")), "license": spec["license"],
            "archive_sha256": spec.get("sha256", spec["hosts"][host]["sha256"] if name == "rust" else None),
            "roles": roles, "modified_files": [], "notices": notices,
            "distribution_requirements": "External tool; retain upstream licenses/notices. Tool binaries are not committed or included in fixture artifacts.",
        })
    components[1]["target_library"] = lock["rust"]["target_library"]
    components[1]["source"] = lock["rust"]["hosts"][host]["url"]
    components.append({
        "name": "rust-bundled-llvm-linker", "revision": lock["rust"]["llvm_revision"],
        "source": "https://github.com/rust-lang/llvm-project/tree/" + lock["rust"]["llvm_revision"],
        "license": "Apache-2.0 WITH LLVM-exception", "roles": ["build_linker"],
        "modified_files": [], "notices": ["https://github.com/rust-lang/llvm-project/blob/" + lock["rust"]["llvm_revision"] + "/llvm/LICENSE.TXT"],
        "archive_sha256": lock["rust"]["hosts"][host]["sha256"],
        "distribution_requirements": "Bundled external linker; preserve LLVM notices if distributing it. Not included in fixture artifacts.",
    })
    components.append({
        "name": "ninja", "version": lock["ninja"]["version"],
        "source": lock["ninja"]["source"], "license": lock["ninja"]["license"],
        "archive_sha256": lock["ninja"]["hosts"][host]["sha256"],
        "roles": ["qemu_build_dependency"], "modified_files": [],
        "notices": [lock["ninja"]["notice"]["url"]],
        "notice_sha256": lock["ninja"]["notice"]["sha256"],
        "distribution_requirements": "Build-only external tool, not distributed in fixture artifacts.",
    })
    components.extend({
        "name": item["name"], "version": item["version"], "source": item["url"],
        "archive_sha256": item["sha256"], "license": item["license"],
        "roles": ["qemu_build_dependency"], "modified_files": [],
        "notices": ["upstream wheel .dist-info/licenses or .dist-info/LICENSE*"],
        "distribution_requirements": "Build-only dependency retained under build/toolchain; not distributed in fixture artifacts.",
    } for item in lock["qemu_python_build_dependencies"])
    manifest = {
        "schema_version": 1, "artifact_type": "test_fixture", "source": source,
        "toolchain": {
            "rustc": {"version": rust_version, "sha256": sha256(compiler)},
            "rust_lld": {"version": command_output([str(linker), "-flavor", "gnu", "--version"]), "sha256": sha256(linker)},
            "qemu": {"version": qemu_version, "sha256": sha256(qemu)},
            "python": {"version": platform_python_version(), "sha256": sha256(Path(sys.executable).resolve())},
            "binary_target": lock["rust"]["target"], "rust_flags": rust_flags,
        },
        "components": components, "artifacts": artifacts, "binary_validation": validation,
        "capabilities": {"tessryn_kernel_boot": "unavailable", "native_gpu": "unavailable", "model_inference": "unavailable"},
    }
    setup_record = ROOT / "build" / "toolchain" / "installed.json"
    if setup_record.is_file():
        setup = json.loads(setup_record.read_text())
        manifest["toolchain"]["qemu_setup"] = setup
        components[2]["omitted_source_links"] = setup.get("qemu_extraction", {}).get("omitted_links", [])
        components[2]["modified_files"] = [name.split("/", 1)[1] for name in components[2]["omitted_source_links"]]
    if source_identity() != source:
        raise ValueError("source changed during build; retry with a fresh output directory")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def platform_python_version() -> str:
    return ".".join(str(number) for number in sys.version_info[:3])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="fresh output directory inside build/")
    args = parser.parse_args()
    try:
        result = build(ROOT / args.out)
        print(json.dumps({"status": "fixture_build_pass", "artifacts": result["artifacts"], "binary_validation": result["binary_validation"]}, indent=2))
        return 0
    except (OSError, ValueError, StopIteration, subprocess.SubprocessError, struct.error) as error:
        print(f"fixture build failed: {str(error).replace(str(ROOT), 'tessryn')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
