#!/usr/bin/env python3
"""Build one original-kernel image, register the native sweep, and replay its evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import math
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.build_fixture import source_identity
from tools.build_k02_native import compile_flags, dependency_paths
from tools.build_kernel import compiler_profile, copy_notices
from tools.g03.process import run_bounded
from tools.k01_media import make_disk
from tools.k02_region_protocol import digest, file_ref, fresh_output, read_ref, regular_bytes, require, strict_json, write_json
from tools.k03_native_arrivals_binding import coff_binding
from tools.k03_native_arrivals_protocol import (
    CONFIG_FILE, CONFIG_NAME, DIRECTED, HARD_QUANTUM_UNIT_NS, MAX_LOG_BYTES, PROFILE_FILE, PROFILE_INCLUDE,
    PROFILE_MAX_BYTES, PROFILE_SHA256, QUANTUMS, RUN_LIMIT_NS, SCALE_NS, SCHEDULE, SCOPE, SOFT_DIVISOR,
    TICK_NS, TIMEOUT_SECONDS, WORK_ITERATIONS,
    config_bytes, load_profile, profile_bytes,
)
from tools.k03_smp_budget import _inventory, _scheduler_archive
from tools.k03_smp_budget_protocol import LIBRARY, RUNTIME_FILES, SCHEDULER_SHA256, SCHEDULER_SOURCE
from tools.k03_smp_user_protocol import case_flags
from tools.k03_smp_user_provenance import COMPILER_SOURCES as USER_COMPILER_SOURCES, canonical, git_bytes
from tools.run_k03_smp_user import launcher_command, qemu_command
from tools.verify_k03_smp_user import completed, validate_notices

FORMAT = "tessryn-native-scheduled-arrivals"
BUILD_NAME = "native-arrival-build"
ENV = Path("/usr/bin/env")
FIRMWARE = {"code": "code.fd", "vars": "vars.fd", "notice": "NOTICE"}
FILES = (LIBRARY, "kernel.obj", "BOOTX64.EFI", "boot.img")
ROLES = ("scheduler", "guest")
TWINS = ("a", "b")
DEPENDENCIES = {
    "scheduler": {SCHEDULER_SOURCE},
    "guest": {*USER_COMPILER_SOURCES, "kernel/smp_workload.rs", "kernel/smp_workload_policy.rs", PROFILE_INCLUDE},
}
EXTRA_QEMU_ARGS = ["-fw_cfg", f"name={CONFIG_NAME},file={CONFIG_FILE}"]
MAX_SUMMARY_BYTES = 32 << 20
REPLAY_INPUTS = tuple(sorted(set(RUNTIME_FILES) | {
    PROFILE_FILE, "tools/k03_native_arrivals.py", "tools/k03_native_arrivals_binding.py",
    "tools/k03_native_arrivals_protocol.py", "tools/k03_native_arrivals_trace.py", "tools/scheduled_arrival_trace.py",
}))
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, struct.error, subprocess.SubprocessError)


def _format(kind):
    return f"{FORMAT}-{kind}/v1"


def _json(path, limit=4 << 20):
    return strict_json(regular_bytes(path, limit))


def _commands(profile, out, snapshot, prefix, linker):
    library = out / LIBRARY
    remap = [f"--remap-path-prefix={prefix}=rust-toolchain", f"--remap-path-prefix={out}={BUILD_NAME}",
             f"--remap-path-prefix={snapshot}=tessryn"]
    scheduler_flags = [arg.replace("--crate-name=tessryn_owned_memory", "--crate-name=tessryn_scheduler")
                       for arg in compile_flags(profile, True)]
    return {
        "scheduler": [SCHEDULER_SOURCE, *scheduler_flags, "-Dwarnings", *remap,
                      f"--emit=link,dep-info={out}/scheduler.d", "-o", str(library)],
        "guest": ["kernel/main.rs", *profile["toolchain"]["rust_flags"], "-Dwarnings",
                  *case_flags("rendezvous"), "--cfg", "k03_smp_workload",
                  *remap, f"--emit=link,obj={out}/kernel.obj,dep-info={out}/guest.d",
                  "-Clinker=" + str(linker), "--extern", f"tessryn_scheduler={library}",
                  "-o", str(out / "BOOTX64.EFI")],
    }


def _settings(profile, workload):
    source = source_identity()
    require(source["dirty"] is False and source["snapshot_algorithm"] == "git-worktree-v2",
            "native workload requires a clean committed checkout")
    prefix = ROOT / "build/uefi"
    require(profile["linker"].is_relative_to(prefix), "native workload linker escaped pinned toolchain")
    commands = _commands(profile, Path(BUILD_NAME), Path("tessryn"), Path("rust-toolchain"),
                         Path("rust-toolchain") / profile["linker"].relative_to(prefix))
    return {
        "format": _format("registration"), "scope": SCOPE, "source": source,
        "toolchain": profile["toolchain"], "commands": commands,
        "replay_inputs": {name: digest(regular_bytes(ROOT / name, 16 << 20)) for name in REPLAY_INPUTS},
        "workload_sha256": PROFILE_SHA256, "compiled_table_sha256": digest(profile_bytes(workload)),
        "clock_tick_ns": TICK_NS, "offer_tick_ns": SCALE_NS, "work_iterations": WORK_ITERATIONS,
        "hard_quantum_unit_ns": HARD_QUANTUM_UNIT_NS, "soft_grant_divisor": SOFT_DIVISOR,
        "guest_run_limit_ns": RUN_LIMIT_NS,
        "schedule": [{"scenario": name, "quantum": quantum} for name, quantum in SCHEDULE],
        "qemu_command": [*qemu_command(), *EXTRA_QEMU_ARGS], "timeout_seconds": TIMEOUT_SECONDS,
        "max_log_bytes": MAX_LOG_BYTES, "capture_authentication": "unverified_offline",
        "launcher_sha256": digest(regular_bytes(ENV, 16 << 20)),
    }


def _emulator(settings):
    qemu = ROOT / "build/toolchain/bin/qemu-system-x86_64"
    expected = settings["toolchain"]["setup"]["verified_tools"]["qemu"]["sha256"]
    require(digest(regular_bytes(qemu, 256 << 20)) == expected
            and digest(regular_bytes(ENV, 16 << 20)) == settings["launcher_sha256"],
            "native workload emulator or launcher differs")
    return qemu


def _process(process):
    return {"status": process.status, "returncode": process.returncode, "elapsed_seconds": process.elapsed_seconds}


def _logs(out, path, process, prefix=""):
    refs = []
    for stream in ("stdout", "stderr"):
        leaf = path / (prefix + stream + ".log")
        leaf.write_bytes(getattr(process, stream))
        refs.append(file_ref(out, leaf))
    return refs


def _read_logs(out, refs, prefix):
    paths = tuple(prefix + stream + ".log" for stream in ("stdout", "stderr"))
    rows = _inventory(refs, paths)
    result = tuple(read_ref(out, rows[path], MAX_LOG_BYTES) for path in paths)
    require(sum(map(len, result)) <= MAX_LOG_BYTES, "native workload combined logs exceed byte bound")
    return result


def _compiler_sources(table):
    rows = git_bytes(["ls-files", "-z", "--", "kernel", SCHEDULER_SOURCE], 1 << 20).split(b"\0")
    require(rows[-1] == b"" and 0 < len(rows) <= 128, "unexpected native compiler source count")
    tracked = {row.decode() for row in rows[:-1]}
    names = set.union(*DEPENDENCIES.values()) - {PROFILE_INCLUDE}
    require(PROFILE_INCLUDE not in tracked and names <= tracked, "unexpected native compiler inputs")
    sources = {name: regular_bytes(ROOT / name, 4 << 20) for name in names}
    sources[PROFILE_INCLUDE] = table
    require(digest(sources[SCHEDULER_SOURCE]) == SCHEDULER_SHA256, "native workload scheduler policy changed")
    return sources


def _build(out, twin, profile, sources, expected):
    directory = out / twin
    directory.mkdir()
    prefix = ROOT / "build/uefi"
    receipts = []
    with tempfile.TemporaryDirectory(prefix="sources-", dir=out) as temporary:
        snapshot = Path(temporary)
        for name, data in sources.items():
            path = snapshot / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o400)
        commands = _commands(profile, directory, snapshot, prefix, profile["linker"])
        for role, command in commands.items():
            normalized = [arg.replace(str(prefix), "rust-toolchain").replace(str(directory), BUILD_NAME)
                          .replace(str(snapshot), "tessryn") for arg in command]
            require(normalized == expected[role], "native compiler command differs from preregistration")
            process = run_bounded([str(profile["compiler"]), *command], snapshot, 90, MAX_LOG_BYTES)
            row = {"role": role, **_process(process), "logs": _logs(out, directory, process, role + "-")}
            receipts.append(row)
            write_json(directory / "compile.json", receipts)
            require(completed(row), "native workload compilation failed; diagnostics retained locally")
            require(all(not any(str(path).encode() in data for path in (ROOT, snapshot))
                        for data in (process.stdout, process.stderr)), "native workload compiler logs contain local paths")
            dep_file = directory / (role + ".d")
            generated = {directory / LIBRARY} if role == "guest" else set()
            names = dependency_paths(regular_bytes(dep_file, 1 << 20).decode(), snapshot, generated)
            dep_file.unlink()
            require(set(names) == DEPENDENCIES[role],
                    "native workload compiler dependencies differ")
            row["dependencies"] = {name: digest(sources[name]) for name in names}
            write_json(directory / "compile.json", receipts)
        require(all(regular_bytes(snapshot / name, 4 << 20) == data for name, data in sources.items()),
                "native workload compiler snapshot changed")
    (directory / "boot.img").write_bytes(make_disk(regular_bytes(directory / "BOOTX64.EFI")))
    return file_ref(out, directory / "compile.json"), [file_ref(out, directory / name) for name in FILES]


def _check_builds(out, builds, compiles, table, sources):
    files = _inventory(builds, {f"{twin}/{name}" for twin in TWINS for name in FILES})
    receipt_paths = _inventory(compiles, {f"{twin}/compile.json" for twin in TWINS})
    dependencies = {}
    first = {}
    for twin in TWINS:
        path = f"{twin}/compile.json"
        receipts = strict_json(read_ref(out, receipt_paths[path], 1 << 20))
        require(type(receipts) is list and tuple(row["role"] for row in receipts) == ROLES,
                "native workload compile receipt roles differ")
        for row in receipts:
            require(set(row) == {"role", "status", "returncode", "elapsed_seconds", "logs", "dependencies"}
                    and completed(row), "native workload compile receipt invalid")
            role = row["role"]
            deps = row["dependencies"]
            require(type(deps) is dict and deps and all(name in sources and digest(sources[name]) == sha
                                                       for name, sha in deps.items()),
                    "native workload compiler source closure differs")
            require(set(deps) == DEPENDENCIES[role], "native workload compiler dependencies incomplete")
            require(twin == TWINS[0] or dependencies[role] == deps, "native workload compiler twins differ")
            dependencies[role] = deps
            require(all(str(ROOT).encode() not in data for data in _read_logs(out, row["logs"], f"{twin}/{role}-")),
                    "native workload compiler logs contain local paths")
        for name in FILES:
            data = read_ref(out, files[f"{twin}/{name}"])
            if twin == TWINS[0]:
                first[name] = data
            else:
                require(first[name] == data, "native workload twin artifacts differ")
    _scheduler_archive(first[LIBRARY])
    require(make_disk(first["BOOTX64.EFI"]) == first["boot.img"], "native workload boot media differs from linked EFI")
    return files, coff_binding(first["kernel.obj"], first["BOOTX64.EFI"], table)


def _seed_firmware(out, settings):
    rows = []
    (out / "firmware").mkdir()
    for role, leaf in FIRMWARE.items():
        origin = settings["toolchain"]["setup"]["firmware"][role]
        data = regular_bytes(ROOT / "build/uefi" / origin["path"], 16 << 20)
        require(len(data) == origin["size_bytes"] and digest(data) == origin["sha256"],
                "native workload firmware origin differs")
        path = out / "firmware" / leaf
        path.write_bytes(data)
        rows.append(file_ref(out, path))
    return rows


def _configs(out):
    (out / "selectors").mkdir()
    rows = []
    for scenario, quantum in sorted(set(SCHEDULE)):
        path = out / "selectors" / f"{scenario}-{quantum}.bin"
        path.write_bytes(config_bytes(scenario, quantum))
        rows.append(file_ref(out, path))
    return rows


def _register(out):
    profile = compiler_profile()
    workload = load_profile()
    table = profile_bytes(workload)
    settings = _settings(profile, workload)
    sources = _compiler_sources(table)
    compiles, artifacts = [], []
    for twin in TWINS:
        receipt, files = _build(out, twin, profile, sources, settings["commands"])
        compiles.append(receipt)
        artifacts.extend(files)
    _, binding = _check_builds(out, artifacts, compiles, table, sources)
    _emulator(settings)
    require(_settings(compiler_profile(), load_profile()) == settings, "native workload source or pinned tools changed")
    (out / "scheduled-arrival-profile.json").write_bytes(regular_bytes(ROOT / PROFILE_FILE, PROFILE_MAX_BYTES))
    reg = {**settings, "artifacts": artifacts, "compile_receipts": compiles, "binding": binding,
           "firmware": _seed_firmware(out, settings), "selectors": _configs(out), "notices": copy_notices(out),
           "workload": file_ref(out, out / "scheduled-arrival-profile.json"),
           "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    path = out / "registration.json"
    write_json(path, reg)
    return reg, digest(regular_bytes(path, 4 << 20))


def _registration(out):
    raw = regular_bytes(out / "registration.json", 4 << 20)
    reg = strict_json(raw)
    profile = compiler_profile()
    workload = load_profile()
    table = profile_bytes(workload)
    settings = _settings(profile, workload)
    extra = {"artifacts", "compile_receipts", "binding", "firmware", "selectors", "notices", "workload", "created_at_utc"}
    require(type(reg) is dict and set(reg) == set(settings) | extra
            and canonical({name: reg[name] for name in settings}) == canonical(settings),
            "native workload registration differs from reviewed source and pinned tools")
    created = datetime.fromisoformat(reg["created_at_utc"].replace("Z", "+00:00"))
    require(created.utcoffset() == timezone.utc.utcoffset(None), "native workload registration time is not UTC")
    require(reg["workload"]["path"] == "scheduled-arrival-profile.json"
            and load_profile(read_ref(out, reg["workload"], PROFILE_MAX_BYTES)) == workload,
            "native workload retained PR #70 inputs differ")
    artifacts, binding = _check_builds(out, reg["artifacts"], reg["compile_receipts"], table, _compiler_sources(table))
    require(canonical(binding) == canonical(reg["binding"]), "native workload binary binding differs")
    firmware = _inventory(reg["firmware"], {"firmware/" + leaf for leaf in FIRMWARE.values()})
    for role, leaf in FIRMWARE.items():
        origin = settings["toolchain"]["setup"]["firmware"][role]
        ref = firmware["firmware/" + leaf]
        require(ref["sha256"] == origin["sha256"] and ref["size_bytes"] == origin["size_bytes"],
                "native workload firmware receipt differs from pinned origin")
        read_ref(out, ref, 16 << 20)
    selectors = _inventory(reg["selectors"], {f"selectors/{scenario}-{quantum}.bin" for scenario, quantum in SCHEDULE})
    for scenario, quantum in set(SCHEDULE):
        path = f"selectors/{scenario}-{quantum}.bin"
        require(read_ref(out, selectors[path], 2) == config_bytes(scenario, quantum), "native workload selector differs")
    validate_notices(out, reg["notices"], settings["toolchain"]["setup"])
    _emulator(settings)
    return reg, digest(raw), workload, artifacts, selectors


def _attempt_name(number, scenario, quantum):
    return f"{number:02d}-{scenario}-{quantum}"


def _attempt(out, reg, registration_sha, number, scenario, quantum):
    directory = out / "runs" / _attempt_name(number, scenario, quantum)
    directory.mkdir()
    require(digest(regular_bytes(out / "registration.json", 4 << 20)) == registration_sha,
            "native workload registration changed before launch")
    disk = next(row for row in reg["artifacts"] if row["path"] == "a/boot.img")
    selector = next(row for row in reg["selectors"] if row["path"] == f"selectors/{scenario}-{quantum}.bin")
    qemu = _emulator(reg)
    with tempfile.TemporaryDirectory(prefix="tessryn-arrivals-", dir=Path("/tmp").resolve()) as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o700)
        for row in reg["firmware"]:
            leaf = Path(row["path"]).name
            if leaf != "NOTICE":
                (scratch / leaf).write_bytes(read_ref(out, row, 16 << 20))
        (scratch / "boot.img").write_bytes(read_ref(out, disk))
        (scratch / CONFIG_FILE).write_bytes(read_ref(out, selector, 2))
        process = run_bounded([*launcher_command(qemu, scratch), *EXTRA_QEMU_ARGS], scratch,
                              TIMEOUT_SECONDS, MAX_LOG_BYTES)
    receipt = {"format": _format("attempt"), "number": number, "scenario": scenario, "quantum": quantum,
               "registration_sha256": registration_sha, "disk_sha256": disk["sha256"],
               "selector_sha256": selector["sha256"], "execution": _process(process),
               "logs": _logs(out, directory, process)}
    write_json(directory / "receipt.json", receipt)
    _emulator(reg)
    return receipt


def _observations(out, name, row, workload, binding):
    from tools.k03_native_arrivals_trace import replay_boot

    process = row["execution"]
    require(type(process) is dict and set(process) == {"status", "returncode", "elapsed_seconds"}
            and process["status"] in {"completed", "timeout", "cancelled", "log_limit", "unavailable", "fail"}
            and (process["returncode"] is None or type(process["returncode"]) is int
                 and -(1 << 31) <= process["returncode"] < 1 << 31)
            and type(process["elapsed_seconds"]) in (float, int) and math.isfinite(process["elapsed_seconds"])
            and 0 <= process["elapsed_seconds"] <= TIMEOUT_SECONDS + 2, "native workload process receipt malformed")
    data, stderr = _read_logs(out, row["logs"], f"runs/{name}/")
    if process["status"] != "completed" or process["returncode"] != 33:
        return {"status": "rejected", "reason": "process_did_not_exit_cleanly"}
    try:
        observations = replay_boot(data, process["returncode"], stderr, scenario=row["scenario"], quantum=row["quantum"],
                                   profile=workload, binding=binding)
        require(observations["elapsed_ns"] <= int(process["elapsed_seconds"] * 1_000_000_000) + 20,
                "native workload guest time exceeds observed process duration")
        return {"status": "pass", "observations": observations}
    except ERRORS as error:
        return {"status": "rejected", "reason": "trace_replay_" + type(error).__name__, "detail": str(error)}


def _summarize(out):
    reg, reg_sha, workload, artifacts, selectors = _registration(out)
    names = [_attempt_name(number, *pair) for number, pair in enumerate(SCHEDULE, 1)]
    runs = out / "runs"
    require(runs.is_dir() and not runs.is_symlink(), "native workload attempts directory missing")
    present = {path.name for path in runs.iterdir()}
    require(present == set(names[:len(present)]), "native workload attempts must be a prefix of preregistration")
    results, identities, seen_traces = [], set(), set()
    previous_allows_next = True
    for number, ((scenario, quantum), name) in enumerate(zip(SCHEDULE, names, strict=True), 1):
        result = {"number": number, "scenario": scenario, "quantum": quantum}
        if name not in present:
            results.append({**result, "status": "not_run"})
            continue
        require(previous_allows_next, "native workload continued after failed directed test or cancelled boot")
        attempt = runs / name
        require(attempt.is_dir() and not attempt.is_symlink()
                and {path.name for path in attempt.iterdir()} == {"receipt.json", "stdout.log", "stderr.log"},
                "native workload attempt inventory differs")
        for leaf in ("receipt.json", "stdout.log", "stderr.log"):
            info = (attempt / leaf).lstat()
            identity = (info.st_dev, info.st_ino)
            require(identity not in identities, "native workload attempt files must have independent inodes")
            identities.add(identity)
        path = attempt / "receipt.json"
        row = _json(path)
        expected = {**result, "format": _format("attempt"), "registration_sha256": reg_sha,
                    "disk_sha256": artifacts["a/boot.img"]["sha256"],
                    "selector_sha256": selectors[f"selectors/{scenario}-{quantum}.bin"]["sha256"]}
        require(type(row) is dict and set(row) == set(expected) | {"execution", "logs"}
                and canonical({key: row[key] for key in expected}) == canonical(expected),
                "native workload attempt order or source binding differs")
        result.update(receipt=file_ref(out, path), execution=row["execution"])
        result.update(_observations(out, name, row, workload, reg["binding"]))
        if result["status"] == "pass":
            trace_sha = result["observations"]["trace_sha256"]
            require(trace_sha not in seen_traces, "native workload reused the same guest trace")
            seen_traces.add(trace_sha)
        previous_allows_next = row["execution"]["status"] != "cancelled" and (scenario != DIRECTED or result["status"] == "pass")
        results.append(result)
    require(digest(regular_bytes(out / "registration.json", 4 << 20)) == reg_sha,
            "native workload registration changed during replay")
    coverage = {
        str(quantum): sum(event["kind"] == "offer" for row in results
                          if row["status"] == "pass" and row["scenario"] != DIRECTED and row["quantum"] == quantum
                          for event in row["observations"]["in_slice_events"])
        for quantum in QUANTUMS
    }
    passed = all(row["status"] == "pass" for row in results) and all(coverage.values())
    return {"format": _format("summary"), "status": "pass" if passed else "fail",
            "scope": SCOPE, "registration_sha256": reg_sha, "capture_authentication": "unverified_offline",
            "source": reg["source"], "in_slice_offers_by_quantum": coverage, "attempts": results}


def run(out, *, allow_qemu=False):
    require(allow_qemu is True, "native workload capture requires explicit --allow-qemu")
    out = fresh_output(out)
    try:
        reg, reg_sha = _register(out)
        (out / "runs").mkdir()
        workload = load_profile()
        for number, (scenario, quantum) in enumerate(SCHEDULE, 1):
            row = _attempt(out, reg, reg_sha, number, scenario, quantum)
            if row["execution"]["status"] == "cancelled":
                break
            if scenario == DIRECTED:
                name = _attempt_name(number, scenario, quantum)
                if _observations(out, name, row, workload, reg["binding"])["status"] != "pass":
                    break
        summary = _summarize(out)
        write_json(out / "summary.json", summary)
        return summary
    except ERRORS as error:
        write_json(out / "private-failure.json", {"type": type(error).__name__, "detail": str(error)})
        raise


def verify(out):
    out = Path(out).absolute()
    require(out.is_relative_to(ROOT / "build") and ".." not in out.parts,
            "native workload packet must be under ignored build/")
    retained = _json(out / "summary.json", MAX_SUMMARY_BYTES)
    actual = _summarize(out)
    require(canonical(retained) == canonical(actual), "native workload retained summary differs from replay")
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--out", type=Path)
    modes.add_argument("--verify", type=Path)
    parser.add_argument("--allow-qemu", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify is not None:
            require(not args.allow_qemu, "native workload verification is read-only")
            summary = verify(args.verify)
        else:
            summary = run(args.out, allow_qemu=args.allow_qemu)
    except ERRORS as error:
        parser.exit(1, f"native workload rejected ({type(error).__name__}): {error}\n")
    print(canonical({"status": summary["status"], "registration_sha256": summary["registration_sha256"],
                     "attempts": [{key: row[key] for key in ("scenario", "quantum", "status")} for row in summary["attempts"]]}))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
