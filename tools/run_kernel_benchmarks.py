#!/usr/bin/env python3
"""Build retained sources and measure explicitly scoped host microbenchmarks."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import time
import types
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = (
    "kernel-core/lib.rs", "kernel-core/capabilities.rs", "kernel-core/frames.rs",
    "kernel-core/boot_inventory.rs", "interfaces/abi-v1/native.rs",
    "benchmark-harness/main.rs", "benchmark-harness/ring.rs", "benchmark-harness/tests.rs",
    "tools/run_kernel_benchmarks.py", "tools/verify_kernel_benchmarks.py", "tools/g03/process.py",
)
BUILD_FLAGS = ["--edition=2024", "-Copt-level=3", "-Dwarnings"]
SOURCE_LIMIT = 1024 * 1024
FILE_LIMIT = 256 * 1024 * 1024
SCHEDULER_SHA256 = "db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_log(data: bytes, redactions: dict[str, str]) -> bytes:
    """Redact text without expanding the captured byte budget or splitting UTF-8."""
    text = data.decode("utf-8", errors="replace")
    for private, replacement in sorted(redactions.items(), key=lambda item: -len(item[0])):
        text = text.replace(private, replacement)
    # Compiler failures can include host tool-library paths not otherwise known.
    text = re.sub(r"(?:/Users/|/home/|/private/|/tmp/|/opt/)[^\s\"']+", "<host-path>", text)
    encoded = text.encode("utf-8")
    if len(encoded) > len(data):
        encoded = encoded[:len(data)].decode("utf-8", errors="ignore").encode("utf-8")
    return encoded


def directory_fd(path: Path, *, create: bool = False) -> int:
    """Walk directory components without accepting a symlink ancestor."""
    path = path.absolute()
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular_bytes(path: Path, limit: int = SOURCE_LIMIT) -> bytes:
    """Bound regular-file reads and reject links, special files and torn reads."""
    parent = directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("input must be a bounded regular file")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if len(data) > limit or identity(before) != identity(after):
            raise ValueError("input changed or exceeded its read bound")
        return data


LOADED_RUNNER_BYTES = regular_bytes(Path(__file__))


def load_bound_module(data: bytes, public_name: str) -> types.ModuleType:
    """Execute captured project helpers without cached imports or path-bearing pyc."""
    name = "_kernel_benchmark_snapshot_" + uuid.uuid4().hex
    module = types.ModuleType(name)
    module.__file__ = public_name
    # dataclasses resolves annotations through sys.modules while defining classes.
    sys.modules[name] = module
    try:
        exec(compile(data, public_name, "exec"), module.__dict__)
    finally:
        sys.modules.pop(name, None)
    return module


def validate_config(samples: int, warmup: int, iterations: int, seed: int,
                    timeout_seconds: float, max_log_bytes: int) -> dict:
    config = dict(samples=samples, warmup=warmup, iterations=iterations, seed=seed)
    for key, lower, upper in (("samples", 1, 10000), ("warmup", 0, 10000),
                              ("iterations", 1, 1000000), ("seed", 0, 2**64 - 1)):
        if type(config[key]) is not int or not lower <= config[key] <= upper:
            raise ValueError(f"{key} is outside its integer bounds")
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 120):
        raise ValueError("timeout must be positive, finite and at most 120 seconds")
    if type(max_log_bytes) is not int or not 1 <= max_log_bytes <= 64 * 1024 * 1024:
        raise ValueError("log budget must be between 1 byte and 64 MiB")
    return config


def write_json(path: Path, data: dict) -> None:
    payload = (json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    # Link creates the final name atomically without replacing any racing writer.
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()


def run_benchmarks(root: Path, out: Path, profile: Path, *, rustc: str | None = None,
                   scheduler_source: Path | None = None, samples: int = 100,
                   warmup: int = 20, iterations: int = 1000, seed: int = 1,
                   timeout_seconds: float = 120, max_log_bytes: int = 1024 * 1024) -> dict:
    config = validate_config(samples, warmup, iterations, seed, timeout_seconds, max_log_bytes)
    root, out, profile = root.absolute(), out.absolute(), profile.absolute()
    parent = directory_fd(out.parent, create=True)
    try:
        os.mkdir(out.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    deadline = time.monotonic() + timeout_seconds
    bindings: list[tuple[Path, bytes]] = []
    library_bindings: list[tuple[Path, str]] = []
    redactions = {str(root): "<source>", str(out): "<run>", str(profile): "<profile>"}
    receipts: dict = {"schema_version": 1, "compile": [], "execution": None}
    result = {"schema_version": 1, "kind": "kernel_benchmark_run", "status": "failed",
              "evidence_scope": "host_microbenchmark", "native_qualification": False,
              "valid": False, "registration_sha256": None, "raw_sha256": None,
              "summary": None}
    captured_process = None

    def remaining() -> float:
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise ValueError("run exceeded its shared deadline")
        return budget

    def retain(relative: str, data: bytes) -> dict:
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        if relative == "profile.json" or relative.startswith("sources/"):
            target.chmod(0o444)
        return {"file": relative, "sha256": sha256(data), "size": len(data)}

    def sanitize(data: bytes) -> bytes:
        return sanitize_log(data, redactions)

    def process(command: list[str], label: str, *, measured: bool = False,
                optional_query: bool = False) -> tuple[dict, bytes]:
        captured = captured_process(command, out, remaining(), max_log_bytes)
        stdout = captured.stdout if measured else sanitize(captured.stdout)
        receipt = {"status": captured.status, "reason": captured.reason,
                   "returncode": captured.returncode, "elapsed_seconds": captured.elapsed_seconds,
                   "stdout": retain(f"logs/{label}.stdout", stdout),
                   "stderr": retain(f"logs/{label}.stderr", sanitize(captured.stderr))}
        if measured:
            receipts["execution"] = receipt
        elif label.startswith("compile-"):
            receipts["compile"].append(receipt)
        ordinary_query_failure = optional_query and captured.status in {"completed", "unavailable"}
        if (captured.status != "completed" or captured.returncode != 0) and not ordinary_query_failure:
            raise ValueError(f"{label} failed: {captured.status}")
        if measured and captured.stderr:
            raise ValueError("measured child emitted unexpected stderr")
        return receipt, captured.stdout

    def unchanged() -> None:
        for source, expected in bindings:
            remaining()
            if regular_bytes(source, FILE_LIMIT) != expected:
                raise ValueError("a bound input changed during the run")
        for library, expected in library_bindings:
            remaining()
            if sha256(regular_bytes(library, FILE_LIMIT)) != expected:
                raise ValueError("a compiler library changed during the run")

    try:
        profile_bytes = regular_bytes(profile)
        retained_profile = retain("profile.json", profile_bytes)
        bindings.extend(((profile, profile_bytes), (out / "profile.json", profile_bytes)))
        sources = []
        for relative in SOURCE_FILES:
            remaining()
            original = root / relative
            data = regular_bytes(original)
            if relative == "tools/run_kernel_benchmarks.py" and data != LOADED_RUNNER_BYTES:
                raise ValueError("runner source differs from its loaded implementation")
            sources.append(retain("sources/" + relative, data))
            bindings.extend(((original, data), (out / "sources" / relative, data)))
        verifier = load_bound_module(regular_bytes(out / "sources/tools/verify_kernel_benchmarks.py"),
                                     "sources/tools/verify_kernel_benchmarks.py")
        helper = load_bound_module(regular_bytes(out / "sources/tools/g03/process.py"),
                                   "sources/tools/g03/process.py")
        captured_process = helper.run_bounded
        parsed_profile = verifier.strict_json(profile_bytes)
        enabled = scheduler_source is not None
        verifier.validate_profile(parsed_profile, config, enabled)
        if scheduler_source is not None:
            scheduler_source = scheduler_source.absolute()
            redactions[str(scheduler_source)] = "<scheduler-source>"
            if scheduler_source.is_dir():
                scheduler_source = scheduler_source / "lib.rs"
            data = regular_bytes(scheduler_source)
            if (parsed_profile["scheduler_source_sha256"] != SCHEDULER_SHA256
                    or sha256(data) != SCHEDULER_SHA256):
                raise ValueError("scheduler source differs from its immutable profile pin")
            sources.append(retain("sources/scheduler-core/lib.rs", data))
            bindings.extend(((scheduler_source, data), (out / "sources/scheduler-core/lib.rs", data)))
        unchanged()
        compiler_name = rustc or shutil.which("rustc")
        if not compiler_name:
            raise ValueError("Rust compiler is unavailable")
        compiler = Path(compiler_name).absolute()
        redactions[str(compiler)] = "<rustc>"
        _, sysroot_output = process([str(compiler), "--print", "sysroot"], "rustc-sysroot")
        sysroot = Path(sysroot_output.decode().strip()).resolve(strict=True)
        redactions[str(sysroot)] = "<rust-sysroot>"
        actual_compiler = (sysroot / "bin/rustc").resolve(strict=True)
        compiler_bytes = regular_bytes(actual_compiler, FILE_LIMIT)
        bindings.append((actual_compiler, compiler_bytes))
        _, version_output = process([str(actual_compiler), "-vV"], "rustc-version")
        version = sanitize(version_output).decode().strip()
        host_match = re.search(r"^host: (\S+)$", version, re.MULTILINE)
        if not host_match:
            raise ValueError("compiler does not identify its host target")
        host_target = host_match.group(1)
        fingerprint = hashlib.sha256()
        libraries = sorted((sysroot / "lib/rustlib" / host_target / "lib").iterdir())
        total_library_bytes = 0
        for library in libraries:
            remaining()
            if library.suffix not in (".rlib", ".so", ".dylib", ".a"):
                continue
            data = regular_bytes(library.resolve(strict=True), FILE_LIMIT)
            library_bindings.append((library.resolve(strict=True), sha256(data)))
            total_library_bytes += len(data)
            if total_library_bytes > 1024 * 1024 * 1024:
                raise ValueError("compiler library fingerprint exceeded its bound")
            fingerprint.update(library.name.encode() + b"\0" + sha256(data).encode() + b"\n")
        if not total_library_bytes:
            raise ValueError("compiler target libraries are unavailable")
        processor_model = "unavailable"
        if platform.system() == "Darwin":
            cpu_receipt, cpu_output = process(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
                                              "cpu-model", optional_query=True)
            candidate = cpu_output.decode("ascii", errors="replace").strip()
            if (cpu_receipt["status"] == "completed" and cpu_receipt["returncode"] == 0
                    and candidate and len(candidate) <= 256 and candidate.isascii() and candidate.isprintable()):
                processor_model = candidate
        elif platform.system() == "Linux":
            try:
                cpuinfo = regular_bytes(Path("/proc/cpuinfo"), 1024 * 1024).decode(errors="replace")
            except OSError:
                cpuinfo = ""
            match = re.search(r"^model name\s*:\s*(.+)$", cpuinfo, re.MULTILINE)
            if match and match.group(1).isascii() and len(match.group(1)) <= 256:
                processor_model = match.group(1).strip()
        flags = BUILD_FLAGS + (["--cfg=scheduler_core"] if enabled else [])
        (out / "lib").mkdir()
        command = [str(actual_compiler), "sources/kernel-core/lib.rs", "--crate-name=tessryn_memory",
                   "--crate-type=rlib", *BUILD_FLAGS, "-o", "lib/libtessryn_memory.rlib"]
        process(command, "compile-memory")
        externs = ["--extern", "tessryn_memory=lib/libtessryn_memory.rlib"]
        if enabled:
            process([str(actual_compiler), "sources/scheduler-core/lib.rs", "--crate-name=tessryn_scheduler",
                     "--crate-type=rlib", *BUILD_FLAGS, "-o", "lib/libtessryn_scheduler.rlib"], "compile-scheduler")
            externs += ["--extern", "tessryn_scheduler=lib/libtessryn_scheduler.rlib"]
        process([str(actual_compiler), "sources/benchmark-harness/main.rs", *flags, *externs,
                 "-o", "kernel-benchmark"], "compile-harness")
        unchanged()
        executable = regular_bytes(out / "kernel-benchmark", FILE_LIMIT)
        registration = {"schema_version": 1, "kind": "kernel_benchmark_registration",
                        "evidence_scope": "host_microbenchmark", "config": config,
                        "profile": retained_profile, "sources": sources,
                        "toolchain": {"rustc_sha256": sha256(compiler_bytes), "version": version,
                                      "host_target": host_target, "sysroot_fingerprint": fingerprint.hexdigest(),
                                      "dependency_scope": "rustc_executable_and_host_target_libraries_only"},
                        "host": {"os": platform.system(), "architecture": platform.machine(),
                                 "cpu_count": os.cpu_count() or 1, "processor_model": processor_model},
                        "executable": {"file": "kernel-benchmark", "sha256": sha256(executable), "size": len(executable)},
                        "created_at_utc": datetime.now(timezone.utc).isoformat(), "build_flags": flags,
                        "scheduler_source_enabled": enabled,
                        "clock": {"name": "std::time::Instant", "scope": "host_monotonic", "calibration": "unqualified_timer_pair_overhead_probe"},
                        "warmup_policy": "per_case_discard_before_measurement",
                        "measurement_semantics": "raw_host_elapsed_no_subtraction",
                        "capture_origin": "local_runner_claim_unverified_offline", "native_qualification": False}
        write_json(out / "registration.json", registration)
        result["registration_sha256"] = sha256(regular_bytes(out / "registration.json"))
        _, raw = process([str(out / "kernel-benchmark"), "--samples", str(samples), "--warmup", str(warmup),
                          "--iterations", str(iterations), "--seed", str(seed)], "measurement", measured=True)
        retain("raw.json", raw)
        result["raw_sha256"] = sha256(raw)
        unchanged()
        if regular_bytes(out / "kernel-benchmark", FILE_LIMIT) != executable:
            raise ValueError("benchmark executable changed during execution")
        write_json(out / "run_receipts.json", receipts)
        summary = verifier.verify_run(out, require_result=False)
        result.update(status="observed", valid=True, summary=summary)
    except (Exception, KeyboardInterrupt) as error:
        result["reason"] = sanitize(f"{type(error).__name__}: {error}".encode()).decode()
        if not (out / "run_receipts.json").exists():
            write_json(out / "run_receipts.json", receipts)
    write_json(out / "result.json", result)
    return result


def format_report(result: dict) -> str:
    lines = ["Scope: host_microbenchmark; native_qualification=false",
             "Status: " + result["status"]]
    if not result["valid"]:
        lines.append("Reason: " + result.get("reason", "unavailable"))
        return "\n".join(lines)
    lines.append("Registration SHA-256: " + result["registration_sha256"])
    lines.append("Timed-batch quantiles are amortized batch averages; single-operation quantiles are individual calls.")
    lines.append(f"{'case / implementation':79} {'sample unit':17} {'p50 ns/op':>12} {'p99 ns/op':>12}")
    for row in result["summary"]["cases"]:
        values = row["ns_per_operation"]
        median = f"{values['p50']:.3f}" if values else "unresolved"
        tail = f"{values['p99']:.3f}" if values else "unresolved"
        label = row["case"] + " / " + row["implementation"]
        lines.append(f"{label:79} {row['sample_unit']:17} {median:>12} {tail:>12}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=ROOT / "planning/kernel-benchmark-profile.json")
    parser.add_argument("--rustc")
    parser.add_argument("--scheduler-source", type=Path)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=120)
    parser.add_argument("--max-log-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--json", action="store_true", help="print the complete result receipt instead of the summary table")
    args = parser.parse_args()
    try:
        result = run_benchmarks(ROOT, args.out, args.profile, rustc=args.rustc,
                                scheduler_source=args.scheduler_source, samples=args.samples,
                                warmup=args.warmup, iterations=args.iterations, seed=args.seed,
                                timeout_seconds=args.timeout_seconds, max_log_bytes=args.max_log_bytes)
    except (ValueError, OSError) as error:
        print(f"Benchmark setup refused: {type(error).__name__}")
        return 1
    print(json.dumps(result, sort_keys=True) if args.json else format_report(result))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
