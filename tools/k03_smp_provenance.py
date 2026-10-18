"""Bind the SMP bootstrap packet to reviewed Git bytes and checked tools."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from tools.k03_smp_protocol import ROOT, PROFILE, CASES, CONTRACT_NAME, require, digest, regular_bytes, portable_path, case_flags
from tools.g03.process import run_bounded
from tools.build_kernel import compiler_profile

COMPILER_SOURCES = ("kernel/main.rs", "kernel/cpu.rs", "kernel/diagnostics.rs", "kernel/framebuffer.rs",
    "kernel/paging.rs", "kernel/uefi.rs", "kernel/entry.S", "kernel/smp.rs", "kernel/smp_entry.S", "kernel/smp_acpi.rs")
RUNTIME_FILES = ("tools/build_k03_smp.py", "tools/run_k03_smp.py", "tools/verify_k03_smp.py",
    "tools/k03_smp_protocol.py", "tools/k03_smp_provenance.py", "tools/k03_smp_trace.py",
    "tools/check_k03_smp_host.py", "tools/summarize_k03_smp_failure.py", "tools/k02_region_protocol.py",
    "tools/build_kernel.py", "tools/build_fixture.py", "tools/setup_toolchain.py", "tools/setup_uefi.py",
    "tools/setup_k02_toolchain.py", "tools/k01_media.py", "tools/g03/__init__.py", "tools/g03/process.py",
    "fixtures/rom.py", "tests/k03_smp_acpi.rs", "toolchain.lock.json", "uefi-toolchain.lock.json", "planning/k02-toolchain.lock.json",
    CONTRACT_NAME, ".github/workflows/k03-smp.yml")


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError("SMP metadata must be finite bounded JSON") from error


def runtime_hashes():
    return {name: digest(regular_bytes(ROOT / name, 16 << 20)) for name in RUNTIME_FILES}


def git_bytes(arguments, limit=16 << 20):
    command = ["/usr/bin/env", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1",
        "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "/usr/bin/git", "-c", "protocol.allow=never", "--no-replace-objects", *arguments]
    execution = run_bounded(command, ROOT, 15, limit)
    require(execution.status == "completed" and execution.returncode == 0, "SMP source Git identity unavailable")
    return execution.stdout


def committed_sources(revision):
    require(type(revision) is str and re.fullmatch("[0-9a-f]{40}|[0-9a-f]{64}", revision), "SMP revision must be complete")
    require(git_bytes(["cat-file", "-t", revision]).strip() == b"commit", "SMP source must name a commit")
    git_bytes(["merge-base", "--is-ancestor", revision, "HEAD"])
    rows = git_bytes(["ls-tree", "-r", "-z", "--full-tree", revision]).split(b"\0")
    require(rows[-1] == b"" and len(rows) <= 8193, "SMP source tree exceeds bounds")
    sources, cache, total = {}, {}, 0
    for row in rows[:-1]:
        metadata, name = row.split(b"\t", 1)
        mode, kind, oid = metadata.split(b" ")
        name = name.decode("utf-8")
        portable_path(name)
        require(name not in sources and mode in (b"100644", b"100755") and kind == b"blob"
            and re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", oid), "SMP source requires unique regular blobs")
        if oid not in cache:
            cache[oid] = git_bytes(["cat-file", "blob", oid.decode("ascii")])
        data = cache[oid]; total += len(data)
        require(total <= 256 << 20, "SMP source bytes exceed bound")
        sources[name] = (mode.decode("ascii"), data)
    return sources


def validate_source(manifest):
    source = manifest.get("source")
    require(type(source) is dict and set(source) == {"revision", "dirty", "tree_sha256", "snapshot_algorithm"}
        and source["dirty"] is False and source["snapshot_algorithm"] == "git-worktree-v2", "SMP full acceptance requires clean source")
    sources = committed_sources(source["revision"])
    hashed = hashlib.sha256()
    for name, (mode, data) in sorted(sources.items()):
        hashed.update(name.encode() + b"\0" + mode.encode() + b"\0" + digest(data).encode() + b"\0")
    require(hashed.hexdigest() == source["tree_sha256"], "SMP snapshot differs from committed source")
    for key, expected in (("source_files", COMPILER_SOURCES), ("runtime_files", RUNTIME_FILES)):
        rows = manifest.get(key)
        require(type(rows) is dict and set(rows) == set(expected), "SMP source closure differs")
        for name, sha in rows.items():
            require(name in sources and digest(sources[name][1]) == sha, "SMP source differs from commit")
            if key == "runtime_files":
                require(regular_bytes(ROOT / name, 16 << 20) == sources[name][1], "SMP evaluator differs from reviewed checkout")
    for name in ("LICENSE", "NOTICE"):
        row = next((r for r in manifest["notices"] if r.get("path") == "notices/tessryn-" + name), None)
        require(row is not None and name in sources and row["sha256"] == digest(sources[name][1])
            and row["size_bytes"] == len(sources[name][1]), "SMP notice differs from committed origin")
    return {"revision": source["revision"], "tree_sha256": source["tree_sha256"],
        "compiler_dependencies": len(COMPILER_SOURCES), "runtime_files": len(RUNTIME_FILES)}


def expected_commands(profile):
    linker = Path(profile["linker"])
    prefix = ROOT / "build/uefi"
    require(linker.is_relative_to(prefix), "SMP linker outside pinned toolchain")
    return {case: ["kernel/main.rs", *profile["toolchain"]["rust_flags"], "-Dwarnings", *case_flags(case),
        f"--emit=link,obj=smp-build/{case}/kernel.obj,dep-info=smp-build/{case}/kernel.d",
        "--remap-path-prefix=rust-toolchain=rust-toolchain", "--remap-path-prefix=smp-build=smp-build",
        "--remap-path-prefix=tessryn=tessryn", "-Clinker=rust-toolchain/" + linker.relative_to(prefix).as_posix(),
        "-o", f"smp-build/{case}/BOOTX64.EFI"] for case in CASES}


def validate_toolchain(manifest):
    profile = compiler_profile()
    require(canonical(manifest.get("toolchain")) == canonical(profile["toolchain"])
        and canonical(manifest.get("compile_commands")) == canonical(expected_commands(profile)), "SMP checked toolchain/commands differ")
    return profile["toolchain"]
