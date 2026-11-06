#!/usr/bin/env python3
"""Run and verify the fixed, untimed K03 host-policy workload replay."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "planning/scheduled-arrival-profile.json"
SCHEDULER = "scheduler-core/lib.rs"
ADAPTER = "benchmark-harness/scheduled_arrivals.rs"
RUNNER = "tools/run_scheduled_arrivals.py"
PROCESS = "tools/g03/process.py"
CHECKER = "tools/scheduled_arrival_trace.py"
SOURCE_FILES = (SCHEDULER, ADAPTER, RUNNER, PROCESS, CHECKER)
SCENARIOS = ("steady", "burst", "overload")
QUANTA = (4, 16)
CLASSES = frozenset(("decode", "prefill", "control"))
TRACE_LIMIT = 2 << 20
RESULT_LIMIT = 8 << 20
SCOPE = "synthetic_single_cpu_k03_policy_logical_ticks"
FLAGS = ("--edition=2024", "-Copt-level=3", "-Dwarnings")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def directory_fd(path):
    path = path.absolute()
    require(".." not in path.parts, "directory path must be normalized")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular_bytes(path, limit):
    parent = directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= limit, "file must be bounded, regular and unaliased")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_nlink, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        require(len(data) == before.st_size and identity(before) == identity(after),
                "file changed during read")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def read_json(data):
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, "duplicate JSON field")
            obj[key] = value
        return obj

    def reject_constant(_):
        raise ValueError("nonfinite JSON number")

    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)


def validate_profile(profile):
    require(type(profile) is dict and set(profile) == {"format", "quantums", "scenarios"}
            and profile["format"] == "tessryn-scheduled-arrival-profile/v1"
            and profile["quantums"] == list(QUANTA)
            and all(type(q) is int for q in profile["quantums"]), "invalid profile header")
    scenarios = profile["scenarios"]
    require(type(scenarios) is dict and set(scenarios) == set(SCENARIOS), "wrong scenarios")
    for name in SCENARIOS:
        jobs = scenarios[name]
        require(type(jobs) is list and 1 <= len(jobs) <= 64, "job count outside bounds")
        previous, seen_classes = 0, set()
        for i, job in enumerate(jobs, 1):
            require(type(job) is dict and set(job) == {"id", "domain", "arrival", "work", "cancel", "class"},
                    "invalid job fields")
            require(integer(job["id"], i, i) and integer(job["domain"], 1, 4)
                    and integer(job["arrival"], previous, 100_000)
                    and integer(job["work"], 1, 1024), "invalid job identity, arrival or work")
            require(job["cancel"] is None or integer(job["cancel"], max(job["arrival"], 1), 100_000),
                    "cancellation must follow or coincide with arrival and use a nonzero tick")
            require(type(job["class"]) is str and job["class"] in CLASSES, "invalid job class")
            previous = job["arrival"]
            seen_classes.add(job["class"])
        require(seen_classes == CLASSES, "each scenario must exercise all classes")
    return profile


def planned_runs():
    return [(f"{name}-q{q}.tsv", name, q) for name in SCENARIOS for q in QUANTA]


def fixture_input(jobs, quantum):
    lines = [str(quantum)]
    for job in jobs:
        lines.append("\t".join(str(job[key] or 0) for key in ("id", "domain", "arrival", "work", "cancel")))
    return ("\n".join(lines) + "\n").encode("ascii")


def write_new(path, data):
    parent = directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def check_inventory(packet, *, complete):
    expected = {"registration.json", "profile.json", *(filename for filename, _, _ in planned_runs())}
    if complete:
        expected.add("result.json")
    fd = directory_fd(packet)
    try:
        require(set(os.listdir(fd)) == expected, "packet file inventory differs")
    finally:
        os.close(fd)


def load_reviewed_helper(path, data):
    # Only checked-out helpers execute. Packet contents never supply Python code.
    name = "_scheduled_arrival_" + Path(path).stem
    module = types.ModuleType(name)
    module.__file__ = path
    sys.modules[name] = module  # Dataclasses consult this while defining classes.
    try:
        exec(compile(data, path, "exec", dont_inherit=True), module.__dict__)
    finally:
        sys.modules.pop(name, None)
    return module


LOADED_SOURCES = {path: regular_bytes(ROOT / path, 1 << 20) for path in (RUNNER, PROCESS, CHECKER)}
run_bounded = load_reviewed_helper(PROCESS, LOADED_SOURCES[PROCESS]).run_bounded
validate_trace = load_reviewed_helper(CHECKER, LOADED_SOURCES[CHECKER]).validate_trace


def project_inputs():
    inputs = {path: regular_bytes(ROOT / path, 1 << 20) for path in SOURCE_FILES}
    require(all(inputs[path] == data for path, data in LOADED_SOURCES.items()),
            "loaded runner or helper changed")
    return inputs, regular_bytes(ROOT / PROFILE, 64 << 10)


def compiler_info(path):
    require(path.is_file() and os.access(path, os.X_OK), "installed rustc is required")
    with path.open("rb") as stream:
        require(0 < os.fstat(stream.fileno()).st_size <= 256 << 20, "rustc executable size outside bound")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    version = command([str(path), "--version"], ROOT, 5, "compiler version", 4096).decode("ascii").strip()
    require(valid_version(version), "unrecognized compiler version")
    return {"version": version, "sha256": digest}


def valid_version(value):
    return type(value) is str and re.fullmatch(r"rustc [0-9][ -~]{0,200}", value) is not None and "/" not in value


def command(args, cwd, timeout, stage, limit=TRACE_LIMIT):
    result = run_bounded(args, cwd, timeout, limit)
    require(result.status == "completed" and result.returncode == 0 and not result.stderr,
            f"{stage} failed or produced diagnostics")
    return result.stdout


def summarize(packet, registration_bytes, profile):
    summaries = {}
    for filename, name, quantum in planned_runs():
        trace = regular_bytes(packet / filename, TRACE_LIMIT)
        summaries[filename] = {"scenario": name, "quantum": quantum, "trace_sha256": sha(trace),
                               **validate_trace(trace, profile["scenarios"][name], quantum)}
    return {"format": "tessryn-scheduled-arrival-result/v1", "scope": SCOPE,
            "registration_sha256": sha(registration_bytes), "runs": summaries,
            "hardware_qualified": False, "inference_qualified": False,
            "capture_authentication": "unverified_offline"}


def run(out, rustc=None):
    inputs, profile_bytes = project_inputs()
    profile = validate_profile(read_json(profile_bytes))
    candidate = rustc if rustc is not None else shutil.which("rustc")
    require(candidate is not None, "installed rustc is required")
    invocation = Path(candidate).absolute()
    compiler = invocation.resolve(strict=True)
    rustup = invocation.with_name("rustup")
    require(compiler.name != "rustup" and not (rustup.is_file() and rustup.samefile(compiler)),
            'select the installed compiler with --rustc "$(rustup which rustc)"')
    info = compiler_info(compiler)
    out = Path(out).absolute()
    require(out.resolve() == out and out.is_relative_to(ROOT / "build"),
            "choose an unaliased output directory inside build/")
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    registration = {
        "format": "tessryn-scheduled-arrival-registration/v1", "scope": SCOPE,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "compiler": info, "build_flags": list(FLAGS),
        "profile_sha256": sha(profile_bytes),
        "source_sha256": {path: sha(data) for path, data in inputs.items()},
        "traces": [filename for filename, _, _ in planned_runs()],
    }
    registration_bytes = canonical(registration)
    write_new(out / "registration.json", registration_bytes)
    write_new(out / "profile.json", profile_bytes)

    with tempfile.TemporaryDirectory(prefix="scheduled-arrivals-", dir=out.parent) as temporary:
        stage = Path(temporary)
        write_new(stage / "scheduler.rs", inputs[SCHEDULER])
        write_new(stage / "adapter.rs", inputs[ADAPTER])
        command([str(compiler), "scheduler.rs", *FLAGS, "--crate-name", "tessryn_scheduler",
                 "--crate-type", "rlib", "-o", "libtessryn_scheduler.rlib"], stage, 30, "compile policy")
        command([str(compiler), "adapter.rs", *FLAGS, "--extern",
                 "tessryn_scheduler=libtessryn_scheduler.rlib", "-o", "replay"], stage, 30, "compile replay")
        for filename, name, quantum in planned_runs():
            offer = stage / f"{name}-q{quantum}.input"
            write_new(offer, fixture_input(profile["scenarios"][name], quantum))
            trace = command([str(stage / "replay"), offer.name], stage, 10, f"replay {name} q{quantum}")
            write_new(out / filename, trace)
    require(project_inputs() == (inputs, profile_bytes), "project inputs changed during replay")
    require(compiler_info(compiler) == info, "compiler identity changed during replay")
    check_inventory(out, complete=False)
    require(regular_bytes(out / "profile.json", 64 << 10) == profile_bytes
            and regular_bytes(out / "registration.json", 64 << 10) == registration_bytes,
            "retained registration or profile changed during replay")
    result = summarize(out, registration_bytes, profile)
    result_data = canonical(result)
    require(len(result_data) <= RESULT_LIMIT, "result exceeds packet size bound")
    write_new(out / "result.json", result_data)
    return result


def verify_packet(packet, expected_registration_sha256=None):
    packet = Path(packet).absolute()
    require(packet.resolve() == packet and packet.is_dir(), "packet path is missing or aliased")
    check_inventory(packet, complete=True)
    inputs, reviewed_profile = project_inputs()
    profile_data = regular_bytes(packet / "profile.json", 64 << 10)
    require(profile_data == reviewed_profile, "packet profile differs from reviewed workload")
    profile = validate_profile(read_json(profile_data))
    registration_data = regular_bytes(packet / "registration.json", 64 << 10)
    if expected_registration_sha256 is not None:
        require(sha(registration_data) == expected_registration_sha256, "registration digest differs")
    reg = read_json(registration_data)
    require(type(reg) is dict and set(reg) == {"format", "scope", "created_at_utc", "compiler",
            "build_flags", "profile_sha256", "source_sha256", "traces"}
            and reg["format"] == "tessryn-scheduled-arrival-registration/v1"
            and reg["scope"] == SCOPE and reg["build_flags"] == list(FLAGS)
            and reg["profile_sha256"] == sha(profile_data)
            and reg["source_sha256"] == {path: sha(data) for path, data in inputs.items()}
            and reg["traces"] == [filename for filename, _, _ in planned_runs()],
            "registration differs from reviewed inputs")
    created = reg["created_at_utc"]
    require(type(created) is str and created.endswith("+00:00") and len(created) <= 40,
            "invalid registration UTC timestamp")
    require(datetime.fromisoformat(created).utcoffset() == timedelta(0),
            "invalid registration UTC timestamp")
    compiler = reg["compiler"]
    require(type(compiler) is dict and set(compiler) == {"version", "sha256"}
            and valid_version(compiler["version"]) and type(compiler["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", compiler["sha256"]) is not None,
            "invalid recorded compiler identity")
    result = summarize(packet, registration_data, profile)
    require(regular_bytes(packet / "result.json", RESULT_LIMIT) == canonical(result),
            "stored result differs from raw trace replay")
    check_inventory(packet, complete=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", type=Path)
    mode.add_argument("--verify", type=Path)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--expected-registration-sha256")
    args = parser.parse_args()
    if (args.out and args.expected_registration_sha256) or (args.verify and args.rustc):
        parser.error("--rustc is for capture; --expected-registration-sha256 is for verification")
    try:
        result = (run(args.out, args.rustc) if args.out else
                  verify_packet(args.verify, args.expected_registration_sha256))
    except (ValueError, TypeError, OSError, OverflowError, RecursionError) as exc:
        message = str(exc) if type(exc) is ValueError and not isinstance(exc, (UnicodeError, json.JSONDecodeError)) else type(exc).__name__
        print(f"scheduled arrival replay rejected: {message}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "verified" if args.verify else "observed",
                      "scope": result["scope"], "runs": len(result["runs"]),
                      "registration_sha256": result["registration_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
