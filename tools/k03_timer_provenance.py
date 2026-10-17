"""Bind region acceptance to committed source and the checked host toolchain."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from tools.k03_timer_protocol import ROOT, PROFILE, CASES, CONTRACT_NAME, SCHEDULER_SHA256, require, digest, regular_bytes, portable_path, case_flags
from tools.g03.process import run_bounded
from tools.build_kernel import compiler_profile
from tools.build_k02_native import compile_flags

RUNTIME_FILES = (
    "tools/build_k03_timer.py", "tools/run_k03_timer.py",
    "tools/verify_k03_timer.py", "tools/k03_timer_protocol.py",
    "tools/k03_timer_provenance.py", "tools/summarize_k03_timer_failure.py",
    "tools/k03_timer_trace.py", "tools/k02_region_protocol.py",
    "tools/check_k03_timer_host.py", "tools/setup_k02_toolchain.py", "planning/k02-toolchain.lock.json",
    "tools/build_k02_native.py", "tools/run_k02_native.py", "tools/verify_k02_native.py", "tools/run_kernel.py",
    "tools/build_kernel.py", "tools/build_fixture.py", "tools/k01_media.py",
    "tools/setup_toolchain.py", "tools/setup_uefi.py", "tools/g03/__init__.py", "tools/g03/process.py",
    "tools/g03/evidence.py", "fixtures/rom.py", "toolchain.lock.json",
    "uefi-toolchain.lock.json", CONTRACT_NAME, ".github/workflows/k03-timer.yml",
)
COMPILER_SOURCES = (
    "interfaces/abi-v1/native.rs", "kernel-core/boot_inventory.rs", "kernel-core/capabilities.rs",
    "kernel-core/frames.rs", "kernel-core/lib.rs", "kernel/cpu.rs", "kernel/diagnostics.rs",
    "kernel/entry.S", "kernel/framebuffer.rs", "kernel/main.rs", "kernel/paging.rs", "kernel/uefi.rs",
    "kernel/k02.rs", "kernel/k02_cpu.rs", "kernel/k02_entry.S", "kernel/k02_memory.rs",
    "kernel/k02_paging.rs", "kernel/k02_sha256.rs", "kernel/region_service.rs",
    "kernel/region_runtime.rs", "kernel/region_entry.S", "kernel/timer_runtime.rs", "kernel/timer_programs.S",
    "kernel/preempt_policy.rs", "kernel/preempt_timer.rs", "scheduler-core/lib.rs",
)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError("region metadata must be finite bounded JSON") from error


def runtime_hashes():
    return {name: digest(regular_bytes(ROOT / name, 16 << 20)) for name in RUNTIME_FILES}


def git_bytes(arguments, limit=16 << 20):
    command = ["/usr/bin/env", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
               "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0",
               "/usr/bin/git", "-c", "protocol.allow=never", "--no-replace-objects", *arguments]
    result = run_bounded(command, ROOT, 15, limit)
    require(result.status == "completed" and result.returncode == 0, "region source Git identity unavailable")
    return result.stdout


def committed_sources(revision):
    require(type(revision) is str and re.fullmatch("[0-9a-f]{40}|[0-9a-f]{64}", revision), "region source revision must be complete")
    require(git_bytes(["cat-file", "-t", revision]).strip() == b"commit", "region source must name a commit")
    git_bytes(["merge-base", "--is-ancestor", revision, "HEAD"])
    entries = git_bytes(["ls-tree", "-r", "-z", "--full-tree", revision]).split(b"\0")
    require(entries[-1] == b"" and len(entries) <= 8193, "region committed source tree exceeds bounds")
    sources, cache, total = {}, {}, 0
    for row in entries[:-1]:
        try:
            metadata, name = row.split(b"\t", 1)
            mode, kind, oid = metadata.split(b" ")
            name = name.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise ValueError("region committed source tree malformed") from error
        portable_path(name)
        require(name not in sources and mode in (b"100644", b"100755") and kind == b"blob"
                and re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", oid), "region source requires unique regular blobs")
        if oid not in cache:
            cache[oid] = git_bytes(["cat-file", "blob", oid.decode("ascii")])
        data = cache[oid]
        total += len(data)
        require(total <= 256 << 20, "region committed source bytes exceed bound")
        sources[name] = (mode.decode("ascii"), data)
    return sources


def validate_source(manifest):
    source = manifest.get("source")
    require(type(source) is dict and set(source) == {"revision", "dirty", "tree_sha256", "snapshot_algorithm"}
            and source["dirty"] is False and source["snapshot_algorithm"] == "git-worktree-v2", "region full acceptance requires clean source")
    sources = committed_sources(source["revision"])
    hashed = hashlib.sha256()
    for name, (mode, data) in sorted(sources.items()):
        hashed.update(name.encode() + b"\0" + mode.encode() + b"\0" + digest(data).encode() + b"\0")
    require(hashed.hexdigest() == source["tree_sha256"], "region source snapshot differs from committed bytes")
    files = manifest.get("source_files")
    require(type(files) is dict and set(files) == set(COMPILER_SOURCES), "region exact compiler dependencies differ")
    require(manifest.get("source_files_sha256") == digest(canonical(files).encode()), "region compiler dependency hash differs")
    for name, value in files.items():
        require(name in sources and digest(sources[name][1]) == value, "region compiler source differs from commit")
    require(files["scheduler-core/lib.rs"] == SCHEDULER_SHA256, "K03 reference policy bytes changed")
    runtime = manifest.get("runtime_files")
    require(type(runtime) is dict and set(runtime) == set(RUNTIME_FILES), "region reviewed host runtime closure differs")
    for name, value in runtime.items():
        require(name in sources and digest(sources[name][1]) == value
                and regular_bytes(ROOT / name, 16 << 20) == sources[name][1], "region evaluator/locks differ from reviewed checkout")
    for name in ("LICENSE", "NOTICE"):
        row = next((row for row in manifest.get("notices", []) if row.get("path") == "notices/tessryn-" + name), None)
        require(row is not None and name in sources and row["sha256"] == digest(sources[name][1])
                and row["size_bytes"] == len(sources[name][1]), "region Tessryn notice differs from committed source")
    return {"revision": source["revision"], "tree_sha256": source["tree_sha256"],
            "compiler_dependencies": len(files), "reviewed_runtime_files": len(runtime)}


def expected_commands(profile):
    prefix = ROOT / "build/uefi"
    linker = Path(profile["linker"])
    require(linker.is_relative_to(prefix), "region linker outside pinned toolchain")
    commands = {}
    libraries = {"core": "libtessryn_owned_memory.rlib", "scheduler": "libtessryn_scheduler.rlib"}
    for name in (*libraries, *CASES):
        library = name in libraries
        directory = "timer-build" + ("" if library else "/" + name)
        emits = "link,dep-info=" + directory + "/" + name + ".d"
        if not library:
            emits += ",obj=" + directory + "/kernel.obj"
        flags = compile_flags(profile, library)
        if name == "scheduler":
            flags = ["--crate-name=tessryn_scheduler" if flag.startswith("--crate-name=") else flag for flag in flags]
        source = "kernel-core/lib.rs" if name == "core" else "scheduler-core/lib.rs" if name == "scheduler" else "kernel/main.rs"
        command = [source, *flags,
                   *([] if library else case_flags(name)), "--emit=" + emits,
                   "--remap-path-prefix=rust-toolchain=rust-toolchain",
                   "--remap-path-prefix=timer-build=timer-build", "--remap-path-prefix=tessryn=tessryn"]
        if not library:
            command += ["-Clinker=rust-toolchain/" + linker.relative_to(prefix).as_posix(),
                        "--extern", "tessryn_owned_memory=timer-build/libtessryn_owned_memory.rlib",
                        "--extern", "tessryn_scheduler=timer-build/libtessryn_scheduler.rlib"]
        command += ["-o", directory + ("/" + libraries[name] if library else "/BOOTX64.EFI")]
        commands[name] = command
    return commands


def validate_toolchain(manifest):
    require(canonical(manifest.get("profile")) == canonical(PROFILE), "region CPU/target profile differs")
    try:
        profile = compiler_profile()
    except Exception as error:
        raise ValueError("region full verification needs checked current-host UEFI tools") from error
    require(canonical(manifest.get("toolchain")) == canonical(profile["toolchain"]), "region toolchain differs from checked host tools")
    require(canonical(manifest.get("compile_commands")) == canonical(expected_commands(profile)), "region compiler flags/linker/input differ")
    return profile["toolchain"]
