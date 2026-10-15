#!/usr/bin/env python3
"""Build a captured original-kernel microbenchmark with the pinned K01 profile."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
LOADED_SOURCE = Path(__file__).read_bytes()
CONFIG = {"samples": 16, "warmup": 4, "iterations": 128, "seed": 1}
SCOPE = "qemu_guest_microbenchmark"
SCHEDULER_SHA256 = "db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d"
PROFILE_FILE = "planning/native-kernel-benchmark-profile.json"
SOURCE_FILES = (
    "kernel/main.rs", "kernel/benchmark_clock.rs", "kernel/native_benchmarks.rs",
    "kernel/cpu.rs", "kernel/entry.S", "kernel/uefi.rs", "kernel/paging.rs",
    "kernel/diagnostics.rs", "kernel/framebuffer.rs", "kernel-core/lib.rs",
    "kernel-core/capabilities.rs", "kernel-core/frames.rs", "kernel-core/boot_inventory.rs",
    "interfaces/abi-v1/native.rs", "tools/build_native_kernel_benchmarks.py",
    "tools/run_native_kernel_benchmarks.py", "tools/verify_native_kernel_benchmarks.py",
    "tools/build_kernel.py", "tools/build_fixture.py", "tools/setup_uefi.py",
    "tools/setup_toolchain.py", "tools/k01_media.py", "tools/g03/process.py",
    "fixtures/rom.py", "toolchain.lock.json", "uefi-toolchain.lock.json", "LICENSE", "NOTICE", PROFILE_FILE,
)
ARTIFACT_ROLES = {"BOOTX64.EFI": "kernel_efi", "boot.img": "boot_disk",
                  "libtessryn_owned_memory.rlib": "memory_rlib",
                  "libtessryn_scheduler.rlib": "scheduler_rlib"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path: Path, limit: int = 128 << 20) -> bytes:
    """Read a bounded stable regular file, rejecting every symlink ancestor."""
    path = Path(os.path.abspath(path))
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("input must be a bounded regular file")
            chunks, size = [], 0
            while block := os.read(fd, min(65536, limit + 1 - size)):
                chunks.append(block)
                size += len(block)
                if size > limit:
                    raise ValueError("input exceeds byte budget")
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("input changed while reading")
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(descriptor)


def exclusive_directory(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if not path.is_relative_to(ROOT / "build"):
        raise ValueError("output must be within ignored build/")
    # Parent creation is allowed, but no existing ancestor may redirect output.
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise ValueError("output ancestors must not be symlinks")
        if not parent.exists():
            parent.mkdir(mode=0o700)
    path.mkdir(mode=0o700, exist_ok=False)
    return path


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def write_json(path: Path, value: dict) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    temporary = path.with_name(path.name + ".tmp")
    write_bytes(temporary, data)
    os.link(temporary, path)
    temporary.unlink()


def reference(path: Path, base: Path) -> dict:
    data = regular_bytes(path)
    return {"file": path.relative_to(base).as_posix(), "sha256": digest(data), "size": len(data)}


def unchanged(bindings: dict[Path, bytes]) -> None:
    if any(regular_bytes(path) != data for path, data in bindings.items()):
        raise ValueError("bound source or retained input changed")


@contextmanager
def captured_runtime(snapshot: Path):
    """Import captured helper bytes, never a preexisting Python module cache.

    Existing K01 helpers address the checked live toolchain. Their source comes
    from the retained snapshot; only module-level filesystem roots are remapped.
    """
    # A manifest's self-consistent hashes do not authorize host Python code.
    # Historical packets must use their matching reviewed checkout before run.
    for name in SOURCE_FILES:
        if name.endswith(".py") and regular_bytes(snapshot / name, 2 << 20) != regular_bytes(ROOT / name, 2 << 20):
            raise ValueError("retained runtime source differs from reviewed checkout: " + name)
    saved = {name: module for name, module in sys.modules.items()
             if name == "tools" or name.startswith("tools.") or name == "fixtures" or name.startswith("fixtures.")}
    old_path, old_bytecode = sys.path[:], sys.dont_write_bytecode
    try:
        for name in saved:
            sys.modules.pop(name, None)
        sys.dont_write_bytecode = True
        for name in ("tools", "fixtures"):
            package = types.ModuleType(name)
            package.__path__ = [str(snapshot / name)]
            sys.modules[name] = package
        modules = {key: importlib.import_module(name) for key, name in (
            ("kernel", "tools.build_kernel"), ("process", "tools.g03.process"),
            ("verifier", "tools.verify_native_kernel_benchmarks"))}
        for name, module in list(sys.modules.items()):
            if name == "tools" or name.startswith("tools."):
                for key, value in list(vars(module).items()):
                    if isinstance(value, Path) and value.is_relative_to(snapshot):
                        setattr(module, key, ROOT / value.relative_to(snapshot))
        yield modules
    finally:
        for name in list(sys.modules):
            if name == "tools" or name.startswith("tools.") or name == "fixtures" or name.startswith("fixtures."):
                sys.modules.pop(name, None)
        sys.modules.update(saved)
        sys.path[:] = old_path
        sys.dont_write_bytecode = old_bytecode


def public_log(data: bytes) -> bytes:
    # Compiler diagnostics can mention arbitrary absolute paths. Keep the byte
    # budget even if redaction expands a short /tmp spelling on Linux.
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"(?<![A-Za-z0-9])/(?:[^\s\x00\"'<>])+", "<host-path>", text)
    return text.encode()[:len(data)].decode("utf-8", errors="ignore").encode()


def receipt(result, out: Path, name: str, *, exact: bool = False) -> dict:
    logs = {}
    for stream in ("stdout", "stderr"):
        data = getattr(result, stream)
        if not exact:
            data = public_log(data)
        path = out / f"{name}-{stream}.log"
        write_bytes(path, data)
        logs[stream] = reference(path, out)
    return {"status": result.status, "reason": result.reason,
            "returncode": result.returncode, "elapsed_seconds": result.elapsed_seconds, **logs}


def budgets(timeout: float, max_log_bytes: int) -> None:
    if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 120
            or type(max_log_bytes) is not int or not 0 < max_log_bytes <= 1 << 20):
        raise ValueError("execution budgets exceed supported bounds")


def dependency_paths(raw: str, snapshot: Path, generated: set[Path]) -> set[str]:
    paths = set()
    for line in raw.replace("\\\n", " ").splitlines():
        if not line or line.startswith("#") or ": " not in line:
            continue
        for token in shlex.split(line.split(": ", 1)[1]):
            path = Path(token)
            if not path.is_absolute():
                path = snapshot / path
            path = Path(os.path.abspath(path))
            if path in generated:
                continue
            if not path.is_relative_to(snapshot):
                raise ValueError("compiler dependency escapes retained sources")
            regular_bytes(path, 2 << 20)
            paths.add("sources/" + path.relative_to(snapshot).as_posix())
    if not paths:
        raise ValueError("compiler emitted no retained source dependencies")
    return paths


def compile_flags(profile: dict, crate: str, library: bool) -> list[str]:
    flags = [flag for flag in profile["toolchain"]["rust_flags"]
             if not flag.startswith(("--crate-name=", "--crate-type="))
             and not (library and flag.startswith("-Clink-arg="))]
    return [*flags, "-Dwarnings", "--crate-name=" + crate,
            "--crate-type=" + ("rlib" if library else "bin")]


def build(out: Path, scheduler_source: Path | None = None, *, timeout: float = 120,
          max_log_bytes: int = 262144) -> dict:
    budgets(timeout, max_log_bytes)
    out = exclusive_directory(out)
    manifest = {"schema_version": 1, "kind": "native_kernel_benchmark_build",
                "status": "failed", "reason": "build incomplete", "evidence_scope": SCOPE,
                "native_qualification": False, "config": CONFIG.copy(), "profile": None,
                "sources": [], "artifacts": [], "notices": [], "toolchain": None,
                "compile_commands": {}, "compiler_dependencies": [], "compile": []}
    started = time.monotonic()
    try:
        if regular_bytes(Path(__file__)) != LOADED_SOURCE:
            raise ValueError("running builder source changed since import")
        bindings = {ROOT / name: regular_bytes(ROOT / name, 2 << 20) for name in SOURCE_FILES}
        scheduler = scheduler_source or ROOT / "build/native-inputs/scheduler-core.rs"
        scheduler_data = regular_bytes(scheduler, 2 << 20)
        if digest(scheduler_data) != SCHEDULER_SHA256:
            raise ValueError("scheduler source differs from immutable K03 pin")
        bindings[scheduler] = scheduler_data
        snapshot = out / "sources"
        for source, data in bindings.items():
            relative = "scheduler-core/lib.rs" if source == scheduler else source.relative_to(ROOT).as_posix()
            target = snapshot / relative
            write_bytes(target, data)
            target.chmod(0o444)
            manifest["sources"].append(reference(target, out))
        retained = {out / row["file"]: regular_bytes(out / row["file"]) for row in manifest["sources"]}
        profile_data = bindings[ROOT / PROFILE_FILE]
        write_bytes(out / "profile.json", profile_data)
        retained[out / "profile.json"] = profile_data
        manifest["profile"] = reference(out / "profile.json", out)
        with captured_runtime(snapshot) as runtime:
            verifier, kernel = runtime["verifier"], runtime["kernel"]
            verifier.validate_profile(json.loads(profile_data))
            profile = kernel.compiler_profile()
            manifest["toolchain"] = profile["toolchain"]
            notice_inputs = [(ROOT / name, "notices/tessryn-" + name) for name in ("LICENSE", "NOTICE")]
            setup = profile["toolchain"]["setup"]
            notice_inputs += [(ROOT / "build/uefi" / spec["path"], "notices/rust-" + name)
                              for name, spec in setup["rust_notices"].items()]
            notice_inputs.append((ROOT / "build/uefi" / setup["firmware"]["notice"]["path"], "notices/firmware-NOTICE"))
            for source, filename in notice_inputs:
                data = regular_bytes(source, 2 << 20)
                bindings[source] = data
                target = out / filename
                write_bytes(target, data)
                target.chmod(0o444)
                retained[target] = data
                manifest["notices"].append(reference(target, out))
            unchanged(bindings)
            unchanged(retained)
            generated = {out / name for name in ARTIFACT_ROLES}
            dependencies = set()
            for name, src, target, crate, library in (
                    ("memory", "kernel-core/lib.rs", "libtessryn_owned_memory.rlib", "tessryn_owned_memory", True),
                    ("scheduler", "scheduler-core/lib.rs", "libtessryn_scheduler.rlib", "tessryn_scheduler", True),
                    ("kernel", "kernel/main.rs", "BOOTX64.EFI", "tessryn_native_benchmarks", False)):
                flags = compile_flags(profile, crate, library)
                arguments = [str(snapshot / src), *flags]
                depfile = out / (name + ".d")
                arguments += [f"--emit=link,dep-info={depfile}",
                              f"--remap-path-prefix={ROOT}=tessryn",
                              f"--remap-path-prefix={out}=native-build"]
                if not library:
                    arguments += ["--cfg", "k01_emulator", "--cfg", "native_benchmarks",
                                  f"-Clinker={profile['linker']}",
                                  "--extern", f"tessryn_owned_memory={out / 'libtessryn_owned_memory.rlib'}",
                                  "--extern", f"tessryn_scheduler={out / 'libtessryn_scheduler.rlib'}"]
                arguments += ["-o", str(out / target)]
                def portable(arg):
                    return arg.replace(str(out), "native-build").replace(str(ROOT / "build/uefi"), "rust-toolchain").replace(str(ROOT), "tessryn")
                manifest["compile_commands"][name] = [portable(arg) for arg in arguments]
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise ValueError("build deadline exhausted")
                execution = runtime["process"].run_bounded([str(profile["compiler"]), *arguments], snapshot, remaining, max_log_bytes)
                manifest["compile"].append(receipt(execution, out, name))
                if execution.status != "completed" or execution.returncode != 0:
                    raise ValueError("bounded compile failed: " + execution.status)
                dependencies.update(dependency_paths(regular_bytes(depfile, 2 << 20).decode(), snapshot, generated))
                depfile.unlink()
                unchanged(bindings)
                unchanged(retained)
            manifest["compiler_dependencies"] = sorted(dependencies)
            required = {"sources/kernel/main.rs", "sources/kernel/entry.S", "sources/kernel-core/lib.rs", "sources/scheduler-core/lib.rs"}
            if not required <= dependencies or not dependencies <= {row["file"] for row in manifest["sources"]}:
                raise ValueError("actual compiler source closure differs from captured inputs")
            efi = regular_bytes(out / "BOOTX64.EFI")
            kernel.inspect_pe(efi)
            write_bytes(out / "boot.img", kernel.make_disk(efi))
            for filename, role in ARTIFACT_ROLES.items():
                manifest["artifacts"].append({**reference(out / filename, out), "role": role})
            if kernel.verify_installation() != profile["toolchain"]["setup"]:
                raise ValueError("checked compiler or runtime libraries changed")
            unchanged(bindings)
            unchanged(retained)
            manifest["status"], manifest["reason"] = "built", "captured sources compiled with checked K01 profile"
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as error:
        reason = "build rejected: " + type(error).__name__ + (": " + str(error) if isinstance(error, ValueError) else "")
        manifest["reason"] = public_log(reason.encode()).decode()[:1024]
    write_json(out / "manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--scheduler-source", type=Path)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--max-log-bytes", type=int, default=262144)
    args = parser.parse_args()
    try:
        result = build(args.out, args.scheduler_source, timeout=args.timeout, max_log_bytes=args.max_log_bytes)
    except (OSError, ValueError) as error:
        parser.exit(2, "native benchmark build setup rejected: " + type(error).__name__ + "\n")
    print(json.dumps({"status": result["status"], "reason": result["reason"], "evidence_scope": SCOPE}))
    return 0 if result["status"] == "built" else 1


if __name__ == "__main__":
    raise SystemExit(main())
