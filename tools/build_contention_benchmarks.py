#!/usr/bin/env python3
"""Compile captured two-CPU contention sources with the checked SMP toolchain."""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.contention_benchmark_protocol import (SCOPE, PROFILE_FILE, COMPILER_SOURCES, RUNTIME_FILES,
    FLAGS, require, digest, regular_bytes, strict_json, file_ref, fresh_output, write_json, retain_private_error,
    runtime_hashes, canonical, profile as benchmark_profile, expected_command, descriptor_binding)
from tools.build_fixture import source_identity
from tools.build_kernel import compiler_profile, copy_notices
from tools.build_k03_smp import coff_binding, dependency_paths
from tools.k01_media import make_disk
from tools.g03.process import run_bounded
from tools.setup_uefi import verify_installation
LOADED_RUNTIME = runtime_hashes()


def build(out: Path) -> dict:
    out = fresh_output(out)
    receipts = []
    try:
        source, runtime = source_identity(), runtime_hashes()
        require(source["dirty"] is False, "contention acceptance build requires clean committed source")
        require(runtime == LOADED_RUNTIME, "contention loaded build helpers changed since import")
        profile_bytes = regular_bytes(ROOT / PROFILE_FILE, 2 << 20)
        require(canonical(strict_json(profile_bytes)) == canonical(benchmark_profile()), "contention profile differs")
        checked = compiler_profile()
        prefix = ROOT / "build/uefi"
        retained = {}
        for path in sorted((ROOT / "kernel").rglob("*")):
            require(not path.is_symlink(), "contention compiler input aliases another file")
            if path.is_file(): retained[path.relative_to(ROOT).as_posix()] = regular_bytes(path, 16 << 20)
        require(len(retained) <= 512 and sum(map(len, retained.values())) <= 64 << 20
            and set(COMPILER_SOURCES) <= set(retained), "contention compiler closure exceeds bounds")
        efi, obj, dep = (out / name for name in ("BOOTX64.EFI", "kernel.obj", "kernel.d"))
        with tempfile.TemporaryDirectory(prefix="source-", dir=out) as temporary:
            snapshot = Path(temporary)
            for name, data in retained.items():
                path = snapshot / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data); path.chmod(0o400)
            args = ["kernel/main.rs", *checked["toolchain"]["rust_flags"], "-Dwarnings", *FLAGS,
                f"--emit=link,obj={obj},dep-info={dep}", f"--remap-path-prefix={prefix}=rust-toolchain",
                f"--remap-path-prefix={out}=contention-build", f"--remap-path-prefix={snapshot}=tessryn",
                "-Clinker=" + str(checked["linker"]), "-o", str(efi)]
            execution = run_bounded([str(checked["compiler"]), *args], snapshot, 90, 1 << 20)
            receipt = {"status": execution.status, "returncode": execution.returncode, "elapsed_seconds": execution.elapsed_seconds}
            for stream in ("stdout", "stderr"):
                log = out / (stream + ".log"); log.write_bytes(getattr(execution, stream)); receipt[stream] = file_ref(out, log)
            receipts.append(receipt)
            require(execution.status == "completed" and execution.returncode == 0, "contention compilation failed; raw logs remain private")
            require(all(str(ROOT).encode() not in getattr(execution, stream) for stream in ("stdout", "stderr")), "contention successful compiler logs contain host paths")
            dependencies = dependency_paths(regular_bytes(dep, 2 << 20).decode(), snapshot)
            require(dependencies == set(COMPILER_SOURCES), "contention actual compiler dependencies differ")
            dep.unlink()
            command = [a.replace(str(snapshot), "tessryn").replace(str(prefix), "rust-toolchain").replace(str(out), "contention-build") for a in args]
            require(command == expected_command(checked), "contention compiler flags differ")
            require(all(regular_bytes(snapshot / n, 16 << 20) == d for n, d in retained.items()), "contention source snapshot changed")
        binding = coff_binding(regular_bytes(obj), regular_bytes(efi), "rendezvous")
        config_binding = descriptor_binding(regular_bytes(obj), regular_bytes(efi))
        (out / "boot.img").write_bytes(make_disk(regular_bytes(efi)))
        (out / "profile.json").write_bytes(profile_bytes)
        refs = []
        for name in sorted(set(COMPILER_SOURCES) | set(runtime)):
            path = out / "sources" / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(retained[name] if name in retained else regular_bytes(ROOT / name, 16 << 20))
            refs.append(file_ref(out, path))
        manifest = {"format": "tessryn-contention-build/v1", "scope": SCOPE, "hardware_qualified": False,
            "inference_qualified": False, "source": source,
            "source_files": {name: digest(retained[name]) for name in COMPILER_SOURCES}, "runtime_files": runtime,
            "retained_sources": refs, "toolchain": checked["toolchain"], "profile": file_ref(out, out / "profile.json"),
            "compile_command": command, "compile": receipt, "smp_binding": binding, "config_binding": config_binding,
            "artifacts": [file_ref(out, out / n) for n in ("BOOTX64.EFI", "kernel.obj", "boot.img")],
            "notices": copy_notices(out)}
        require(source_identity() == source and runtime_hashes() == runtime and verify_installation() == checked["toolchain"]["setup"]
            and all(regular_bytes(ROOT / n, 16 << 20) == d for n, d in retained.items()), "contention source or checked tools changed during build")
        write_json(out / "manifest.json", manifest)
        return manifest
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        retain_private_error(out, error)
        write_json(out / "build-failure.json", {"status": "fail", "reason": type(error).__name__, "compile": receipts})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try: build(args.out)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, "contention build rejected: " + type(error).__name__ + "\n")
    print("Contention guest image built; hardware and inference qualification unavailable")
    return 0

if __name__ == "__main__": raise SystemExit(main())
