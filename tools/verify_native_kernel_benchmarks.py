#!/usr/bin/env python3
"""Check retained native counter packets for consistency, not execution authenticity."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import uuid
import zlib

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
U64 = (1 << 64) - 1
SCOPE = "qemu_guest_microbenchmark"
TRANSCRIPT_SCOPE = "original_kernel_single_cpu_qemu"
CONFIG = {"samples": 16, "warmup": 4, "iterations": 128, "seed": 1}
SCHEDULER_PIN = "db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d"
CHECKS = ["ring_full_empty_wrap_fifo", "memory_rejects_foreign_bounds_revoked",
          "memory_lifecycle_drained", "native_volatile_zero_and_copy_exact",
          "benchmark_operations_exact", "scheduler_policy_reservations_stops_and_denials",
          "counter_deltas_no_regression", "owned_pages_from_final_handoff"]
UNAVAILABLE = ["nanoseconds", "counter_frequency_qualification", "CPU_cycles",
               "hardware_performance", "native_context_switch_and_wakeup", "SMP",
               "production_queue_runtime", "DMA", "GPU_execution", "inference_performance",
               "independent_capture_authentication", "complete_compiler_dependency_identity"]


def require(value, message: str) -> None:
    if not value:
        raise ValueError(message)


def object_fields(value, fields: set[str], label: str) -> dict:
    require(type(value) is dict and set(value) == fields, label + ": unexpected fields")
    return value


def integer(value, minimum: int, maximum: int, label: str) -> int:
    require(type(value) is int and minimum <= value <= maximum, label + ": out of bounds integer")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(value, label: str) -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            label + ": invalid SHA-256")
    return value


def portable_path(name: str) -> PurePosixPath:
    require(type(name) is str and bool(name) and "\\" not in name, "unsafe packet path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(part not in {".", ".."} for part in path.parts), "unsafe packet path")
    return path


def read_regular(root: Path, name: str, limit: int = MAX_FILE_BYTES) -> bytes:
    path = portable_path(name)
    root = Path(root).absolute()
    require(all(part != ".." for part in root.parts), "unsafe packet root")
    require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK"), "secure bounded reads unavailable")
    directory = None
    try:
        directory = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY)
        for component in (*root.parts[1:], *path.parts[:-1]):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                    "packet file exceeds regular byte limit")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "packet changed during read")
    except OSError as error:
        raise ValueError("packet file unavailable: " + path.name) from error
    finally:
        if directory is not None:
            os.close(directory)
    require(len(data) <= limit, "packet file exceeds byte limit")
    return data


def strict_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite JSON constant")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid JSON packet") from error


def same_json(left, right) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def file_ref(root: Path, value, label: str, limit: int = MAX_FILE_BYTES) -> bytes:
    ref = object_fields(value, {"file", "sha256", "size"}, label)
    portable_path(ref["file"])
    sha(ref["sha256"], label)
    integer(ref["size"], 0, limit, label)
    data = read_regular(root, ref["file"], limit)
    require(len(data) == ref["size"] and digest(data) == ref["sha256"], label + ": file binding mismatch")
    return data


def case_specs() -> list[dict]:
    rows = [("counter_pair", "native_serialized_tsc_probe", 1, 0, 1),
            ("empty_loop", "native_loop_reference", 1, 0, 1)]
    rows += [(f"queue_roundtrip_batch_{n}", "bounded_ring_fixture", n, 0, 2 * n) for n in (1, 8, 64)]
    rows += [(name, "bounded_ring_fixture", 1, 0, 1)
             for name in ("queue_full_rejection", "queue_empty_rejection")]
    rows += [("memory_allocate_revoke_release", "tessryn_memory_policy_metadata", 1, 0, 3),
             ("memory_access_check", "tessryn_memory_policy_metadata", 1, 0, 1),
             ("native_zero_4096", "native_owned_volatile_page", 1, 4096, 1),
             ("native_copy_4096", "native_owned_volatile_page", 1, 4096, 1),
             ("scheduler_policy_dispatch_stop_cycle", "tessryn_scheduler_policy", 1, 0, 2),
             ("scheduler_policy_dispatch_latency", "tessryn_scheduler_policy", 1, 0, 1)]
    return [{"case": name, "implementation": implementation,
             "sample_unit": "single_operation" if name == "scheduler_policy_dispatch_latency" else "timed_batch",
             "batch_size": batch, "bytes_per_operation": size, "operations_per_iteration": operations}
            for name, implementation, batch, size, operations in rows]


def expected_profile() -> dict:
    return {"schema_version": 1, "kind": "native_kernel_benchmark_profile", "scope": SCOPE,
            "config": CONFIG.copy(), "scheduler_source_sha256": SCHEDULER_PIN,
            "limits": {"max_total_operations": 500000, "max_total_bytes": 25165824,
                       "max_log_bytes": MAX_LOG_BYTES, "timeout_seconds": 60},
            "counter": {"name": "tsc", "unit": "tsc_ticks", "serialization": "cpuid_rdtsc_cpuid",
                        "frequency_hz": None, "frequency_qualified": False,
                        "raw_timestamps": "start_ticks_end_ticks"},
            "warmup_policy": "per_case_discard_before_measurement", "cases": case_specs(), "checks": CHECKS.copy(),
            "measurement_semantics": "raw_guest_counter_delta_no_subtraction",
            "qualification": "not_established"}


def validate_profile(profile: dict) -> list[dict]:
    require(same_json(profile, expected_profile()), "unsupported native benchmark profile")
    rounds = CONFIG["samples"] + CONFIG["warmup"]
    operations = sum(rounds * (1 if row["sample_unit"] == "single_operation" else CONFIG["iterations"])
                     * row["operations_per_iteration"] for row in case_specs())
    byte_work = sum(rounds * CONFIG["iterations"] * row["bytes_per_operation"] for row in case_specs())
    require(operations <= profile["limits"]["max_total_operations"]
            and byte_work <= profile["limits"]["max_total_bytes"], "native workload exceeds registered aggregate budget")
    return case_specs()


def expected_checksum(row: dict) -> int:
    name, n, seed = row["case"], CONFIG["iterations"], CONFIG["seed"]
    if name in {"counter_pair", "empty_loop"}:
        value = seed + n * (n - 1) // 2
    elif name.startswith("queue_roundtrip_batch_"):
        length = n * row["batch_size"]
        value = seed + length * seed + length * (length - 1) // 2
    elif name in {"queue_full_rejection", "queue_empty_rejection"}:
        value = seed + n
    elif name == "memory_allocate_revoke_release":
        value = seed + n * (n + 1) // 2
    elif name == "memory_access_check":
        value = seed + n * 1048576 + sum(i % 4096 for i in range(n))
    elif name == "native_zero_4096":
        value = seed
    elif name == "native_copy_4096":
        value = seed + sum(((i % 4096) + seed) % 251 for i in range(n))
    elif name == "scheduler_policy_dispatch_stop_cycle":
        value = seed + sum(i % 32 for i in range(n))
    elif name == "scheduler_policy_dispatch_latency":
        value = seed
    else:
        raise ValueError("unsupported native checksum case")
    return value & U64


def quantiles(values: list[int | float]) -> dict:
    require(bool(values), "empty sample population")
    values = sorted(values)
    pick = lambda p: values[max(0, math.ceil(p * len(values)) - 1)]
    return {"min": values[0], "p50": pick(.5), "p95": pick(.95), "p99": pick(.99),
            "max": values[-1], "mean": sum(values) / len(values)}


def validate_clock(clock) -> dict:
    object_fields(clock, {"counter", "unit", "serialization", "tsc_supported", "rdtscp_supported",
                          "invariant_tsc", "hypervisor_present", "interrupts_masked", "started_cpus", "frequency_hz"}, "clock")
    for key in ("tsc_supported", "rdtscp_supported", "invariant_tsc", "hypervisor_present", "interrupts_masked"):
        require(type(clock[key]) is bool, "clock feature must be boolean")
    require(clock["counter"] == "tsc" and clock["unit"] == "tsc_ticks"
            and clock["serialization"] == "cpuid_rdtsc_cpuid" and clock["tsc_supported"] is True
            and clock["interrupts_masked"] is True and type(clock["started_cpus"]) is int
            and clock["started_cpus"] == 1 and clock["frequency_hz"] is None, "unsupported counter scope")
    return clock


def parse_transcript(stdout: bytes, stderr: bytes = b"", returncode: int = 33, manifest=None) -> dict:
    require(type(stdout) is bytes and len(stdout) <= MAX_LOG_BYTES and not stderr,
            "guest output exceeds bound or emitted stderr")
    require(type(returncode) is int and returncode == 33, "guest did not terminate through expected emulator exit")
    require(stdout.endswith(b"\n"), "truncated guest transcript")
    try:
        lines = stdout.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ValueError("guest transcript must be ASCII") from error
    require(not any(re.search(r"FAIL|PANIC|UNEXPECTED|Triple fault", line, re.I) for line in lines), "guest failure observed")
    ownership = []
    for marker in ("TESSRYN_K01_ENTRY", "TESSRYN_K01_EXIT_BOOT_SERVICES_OK", "TESSRYN_K01_CPU_OWNED"):
        positions = [index for index, line in enumerate(lines) if line == marker or line.startswith(marker + " ")]
        require(len(positions) == 1, "missing or duplicate kernel ownership marker")
        ownership.append(positions[0])
    first = next((index for index, line in enumerate(lines) if line.startswith("TESSRYN_NBENCH_")), -1)
    require(ownership[0] < ownership[1] < ownership[2] < first, "benchmark precedes kernel ownership")
    records = []
    inside = False
    for line in lines:
        if line.startswith("TESSRYN_NBENCH_"):
            inside = True
            require(" " in line, "missing benchmark JSON payload")
            marker, payload = line.split(" ", 1)
            records.append((marker.removeprefix("TESSRYN_NBENCH_"), strict_json(payload.encode("ascii"))))
        elif inside:
            require(not line, "unexpected output inside benchmark transcript")
    require(len(records) == 213, "missing or extra benchmark records")
    require([row[0] for row in records] == ["BEGIN", "CLOCK"] + ["SAMPLE"] * 208 + ["CHECKS", "END", "PASS"],
            "benchmark marker ordering differs")
    begin = {"schema_version": 1, "kind": "native_kernel_benchmark", "scope": TRANSCRIPT_SCOPE,
             **CONFIG, "cases": 13}
    require(same_json(records[0][1], begin), "native begin configuration differs")
    clock = validate_clock(records[1][1])
    require(same_json(records[-3][1], {"checks": CHECKS}), "native correctness checks differ")
    require(same_json(records[-2][1], {"measured_samples": 208, "warmup_discarded": 52}), "native completion counts differ")
    require(same_json(records[-1][1], {"scope": TRANSCRIPT_SCOPE}), "native pass scope differs")
    summaries = []
    cursor = 2
    previous_end = 0
    for row in case_specs():
        elapsed = []
        iterations = 1 if row["sample_unit"] == "single_operation" else CONFIG["iterations"]
        operations = iterations * row["operations_per_iteration"]
        for index in range(CONFIG["samples"]):
            sample = records[cursor][1]
            cursor += 1
            object_fields(sample, {"case", "implementation", "sample_unit", "sample_index", "elapsed_ticks", "start_ticks", "end_ticks",
                                   "operations", "checksum", "batch_size", "bytes_per_operation"}, "sample")
            for key in ("case", "implementation", "sample_unit", "batch_size", "bytes_per_operation"):
                require(type(sample[key]) is type(row[key]) and sample[key] == row[key], "sample case metadata differs")
            require(type(sample["sample_index"]) is int and sample["sample_index"] == index, "sample index missing, duplicated or reordered")
            require(type(sample["operations"]) is int and sample["operations"] == operations, "sample operation count differs")
            require(type(sample["checksum"]) is int and sample["checksum"] == expected_checksum(row), "deterministic workload checksum differs")
            start = integer(sample["start_ticks"], 0, U64, "start ticks")
            end = integer(sample["end_ticks"], 0, U64, "end ticks")
            delta = integer(sample["elapsed_ticks"], 0, U64, "elapsed ticks")
            require(previous_end <= start <= end and end - start == delta,
                    "raw counter timestamps regressed or differ from elapsed ticks")
            previous_end = end
            elapsed.append(delta)
        zeros = elapsed.count(0)
        summaries.append({**row, "sample_count": len(elapsed), "operations_per_sample": operations,
                          "measurement_status": "resolution_limited" if zeros else "observed",
                          "zero_duration_samples": zeros, "elapsed_ticks": quantiles(elapsed),
                          "ticks_per_operation": None if zeros else quantiles([value / operations for value in elapsed]),
                          "quantile_population": "individual_guest_policy_calls" if row["sample_unit"] == "single_operation"
                          else "amortized_timed_batch_averages"})
    return {"evidence_scope": SCOPE, "capture_origin": "unverified_offline", "native_qualification": False,
            "clock": clock, "counter_frequency_qualified": False, "overhead_subtraction": False,
            "quantile_method": "nearest_rank", "cases": summaries, "checks": CHECKS, "unavailable": UNAVAILABLE}


QEMU_COMMAND = ["qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu",
                "max,phys-bits=48,la57=off,nx=on,pcid=off,pge=off", "-m", "256M", "-smp", "1",
                "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none", "-serial", "null",
                "-nic", "none", "-no-reboot", "-device", "VGA,romfile=", "-global", "apic.vapic=off",
                "-drive", "if=pflash,format=raw,readonly=on,file=code.fd", "-drive", "if=pflash,format=raw,file=vars.fd",
                "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9", "-device",
                "isa-debug-exit,iobase=0xf4,iosize=0x04", "-drive", "if=ide,format=raw,snapshot=on,file=boot.img",
                "-boot", "order=c"]
ARTIFACTS = {"BOOTX64.EFI": "kernel_efi", "boot.img": "boot_disk",
             "libtessryn_owned_memory.rlib": "memory_rlib", "libtessryn_scheduler.rlib": "scheduler_rlib"}
SOURCE_FILES = ("kernel/main.rs", "kernel/benchmark_clock.rs", "kernel/native_benchmarks.rs",
                "kernel/cpu.rs", "kernel/entry.S", "kernel/uefi.rs", "kernel/paging.rs", "kernel/diagnostics.rs",
                "kernel/framebuffer.rs", "kernel-core/lib.rs", "kernel-core/capabilities.rs", "kernel-core/frames.rs",
                "kernel-core/boot_inventory.rs", "interfaces/abi-v1/native.rs", "tools/build_native_kernel_benchmarks.py",
                "tools/run_native_kernel_benchmarks.py", "tools/verify_native_kernel_benchmarks.py", "tools/build_kernel.py",
                "tools/build_fixture.py", "tools/setup_uefi.py", "tools/setup_toolchain.py", "tools/k01_media.py",
                "tools/g03/process.py", "fixtures/rom.py", "toolchain.lock.json", "uefi-toolchain.lock.json",
                "planning/native-kernel-benchmark-profile.json", "LICENSE", "NOTICE", "scheduler-core/lib.rs")
NOTICE_NAMES = {"notices/tessryn-LICENSE", "notices/tessryn-NOTICE", "notices/rust-LICENSE-APACHE",
                "notices/rust-LICENSE-MIT", "notices/rust-COPYRIGHT", "notices/firmware-NOTICE"}
RUST_FLAGS = ["--edition=2024", "--crate-name=tessryn_kernel", "--crate-type=bin",
              "--target=x86_64-unknown-uefi", "-Cpanic=abort", "-Copt-level=1", "-Ccodegen-units=1",
              "-Cdebuginfo=2", "-Cforce-frame-pointers=yes", "-Cno-redzone=yes", "-Cembed-bitcode=no",
              "-Clink-arg=/timestamp:0", "-Clink-arg=/debug:none"]


def expected_compile_commands(host: str) -> dict:
    require(type(host) is str and re.fullmatch(r"[A-Za-z0-9_-]{3,100}", host) is not None,
            "invalid compiler host target")
    commands = {}
    for role, source, target, crate in (
            ("memory", "kernel-core/lib.rs", "libtessryn_owned_memory.rlib", "tessryn_owned_memory"),
            ("scheduler", "scheduler-core/lib.rs", "libtessryn_scheduler.rlib", "tessryn_scheduler"),
            ("kernel", "kernel/main.rs", "BOOTX64.EFI", "tessryn_native_benchmarks")):
        library = role != "kernel"
        flags = [flag for flag in RUST_FLAGS if not flag.startswith(("--crate-name=", "--crate-type="))
                 and not (library and flag.startswith("-Clink-arg="))]
        command = ["native-build/sources/" + source, *flags, "-Dwarnings", "--crate-name=" + crate,
                   "--crate-type=" + ("rlib" if library else "bin"),
                   "--emit=link,dep-info=native-build/" + role + ".d",
                   "--remap-path-prefix=tessryn=tessryn", "--remap-path-prefix=native-build=native-build"]
        if not library:
            command += ["--cfg", "k01_emulator", "--cfg", "native_benchmarks",
                        "-Clinker=rust-toolchain/lib/rustlib/" + host + "/bin/rust-lld",
                        "--extern", "tessryn_owned_memory=native-build/libtessryn_owned_memory.rlib",
                        "--extern", "tessryn_scheduler=native-build/libtessryn_scheduler.rlib"]
        commands[role] = [*command, "-o", "native-build/" + target]
    return commands


def canonical_disk(efi: bytes) -> bytes:
    """Reconstruct this profile's deterministic GPT/FAT16 media without executing packet code."""
    require(0 < len(efi) <= 33374208, "EFI size exceeds media bound")
    sector, cluster, fat_sectors, data_sector = 512, 1024, 128, 289
    esp = bytearray(65536 * sector)
    esp[:3], esp[3:11] = b"\xeb\x3c\x90", b"TESSRYN "
    struct.pack_into("<HBHBHHBHHHII", esp, 11, sector, 2, 1, 2, 512, 0, 0xF8, fat_sectors, 32, 64, 2048, 65536)
    esp[36], esp[38] = 0x80, 0x29
    struct.pack_into("<I", esp, 39, zlib.crc32(efi))
    esp[43:54], esp[54:62], esp[62:66], esp[510:512] = b"TESSRYN K01", b"FAT16   ", b"\xfa\xf4\xeb\xfd", b"\x55\xaa"
    count = (len(efi) + cluster - 1) // cluster
    fat = bytearray(fat_sectors * sector)
    struct.pack_into("<4H", fat, 0, 0xFFF8, 0xFFFF, 0xFFFF, 0xFFFF)
    for index in range(4, 4 + count):
        struct.pack_into("<H", fat, index * 2, index + 1 if index < 3 + count else 0xFFFF)
    for copy in range(2):
        start = (1 + copy * fat_sectors) * sector
        esp[start:start + len(fat)] = fat
    def entry(name, attribute, first, size=0):
        value = bytearray(32)
        value[:11], value[11] = name, attribute
        for offset in (16, 18, 24):
            struct.pack_into("<H", value, offset, 0x21)
        struct.pack_into("<HI", value, 26, first, size)
        return value
    root, directory = 257 * sector, data_sector * sector
    esp[root:root + 32] = entry(b"TESSRYN K01", 8, 0)
    esp[root + 32:root + 64] = entry(b"EFI        ", 16, 2)
    for start, own, parent in ((directory, 2, 0), (directory + cluster, 3, 2)):
        esp[start:start + 32] = entry(b".          ", 16, own)
        esp[start + 32:start + 64] = entry(b"..         ", 16, parent)
    esp[directory + 64:directory + 96] = entry(b"BOOT       ", 16, 3)
    esp[directory + cluster + 64:directory + cluster + 96] = entry(b"BOOTX64 EFI", 32, 4, len(efi))
    esp[directory + 2 * cluster:directory + 2 * cluster + len(efi)] = efi
    sectors = ((2048 + 65536 + 33 + 2047) // 2048) * 2048
    last = sectors - 1
    image = bytearray(sectors * sector)
    struct.pack_into("<B3sB3sII", image, 446, 0, b"\0\2\0", 0xEE, b"\xff\xff\xff", 1, last)
    image[510:512] = b"\x55\xaa"
    namespace = uuid.UUID("8a17fda3-1c6a-4b81-9c47-548620637b1a")
    identity = digest(efi)
    guid = uuid.uuid5(namespace, "disk:" + identity).bytes_le
    entries = bytearray(128 * 128)
    struct.pack_into("<16s16sQQQ72s", entries, 0, uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").bytes_le,
                     uuid.uuid5(namespace, "esp:" + identity).bytes_le, 2048, 2048 + 65536 - 1, 0,
                     "Tessryn K01 ESP".encode("utf-16le"))
    def header(current, alternate, table):
        value = bytearray(sector)
        struct.pack_into("<8sIIIIQQQQ16sQIII", value, 0, b"EFI PART", 0x10000, 92, 0, 0,
                         current, alternate, 34, last - 33, guid, table, 128, 128, zlib.crc32(entries))
        struct.pack_into("<I", value, 16, zlib.crc32(value[:92]))
        return value
    image[sector:2 * sector] = header(1, last, 2)
    image[2 * sector:34 * sector] = entries
    image[(last - 32) * sector:last * sector] = entries
    image[last * sector:] = header(last, 1, last - 32)
    image[2048 * sector:(2048 + 65536) * sector] = esp
    return bytes(image)


def validate_receipt(root: Path, receipt, label: str, *, execution=False, log_limit=MAX_LOG_BYTES) -> tuple[bytes, bytes]:
    object_fields(receipt, {"status", "reason", "returncode", "elapsed_seconds", "stdout", "stderr"}, label)
    require(receipt["status"] == "completed" and type(receipt["returncode"]) is int
            and receipt["returncode"] == (33 if execution else 0), label + ": child did not complete successfully")
    require(type(receipt["reason"]) is str and len(receipt["reason"]) <= 1024, "invalid child reason")
    elapsed = receipt["elapsed_seconds"]
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 122,
            "invalid child elapsed duration")
    return (file_ref(root, receipt["stdout"], label + " stdout", log_limit),
            file_ref(root, receipt["stderr"], label + " stderr", log_limit))


def validate_build(manifest_path: Path) -> dict:
    path = Path(manifest_path).absolute()
    root = path.parent
    manifest = strict_json(read_regular(root, path.name))
    object_fields(manifest, {"schema_version", "kind", "status", "reason", "evidence_scope", "native_qualification",
                             "config", "profile", "sources", "artifacts", "toolchain", "compile_commands",
                             "compiler_dependencies", "compile", "notices"}, "build manifest")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
            and manifest["kind"] == "native_kernel_benchmark_build" and manifest["status"] == "built"
            and manifest["evidence_scope"] == SCOPE and manifest["native_qualification"] is False,
            "invalid native build scope or status")
    require(type(manifest["reason"]) is str and len(manifest["reason"]) <= 1024, "invalid build reason")
    require(same_json(manifest["config"], CONFIG), "build configuration differs")
    for field in ("sources", "artifacts", "notices", "compile"):
        require(type(manifest[field]) is list, "invalid build reference collection")
    bounded_refs = [manifest["profile"], *manifest["sources"], *manifest["artifacts"], *manifest["notices"]]
    for receipt in manifest["compile"]:
        require(type(receipt) is dict and {"stdout", "stderr"} <= set(receipt), "invalid compile receipt")
        bounded_refs.extend((receipt["stdout"], receipt["stderr"]))
    total = 0
    for ref in bounded_refs:
        require(type(ref) is dict and "size" in ref, "invalid build file reference")
        total += integer(ref["size"], 0, 64 * 1024 * 1024, "build file size")
    require(len(bounded_refs) <= 150 and total <= 128 * 1024 * 1024, "build closure exceeds aggregate byte budget")
    profile_data = file_ref(root, manifest["profile"], "profile")
    require(manifest["profile"]["file"] == "profile.json", "profile filename differs")
    validate_profile(strict_json(profile_data))
    sources = manifest["sources"]
    require(type(sources) is list and 12 <= len(sources) <= 100, "source closure outside bounds")
    names = set()
    for source in sources:
        data = file_ref(root, source, "source", 2 * 1024 * 1024)
        name = source["file"]
        require(name.startswith("sources/") and name not in names, "duplicate or unsafe source")
        names.add(name)
        if name == "sources/scheduler-core/lib.rs":
            require(digest(data) == SCHEDULER_PIN, "scheduler source pin differs")
        if name == "sources/planning/native-kernel-benchmark-profile.json":
            require(data == profile_data, "profile origin differs")
    require(names == {"sources/" + name for name in SOURCE_FILES}, "source closure differs from exact supported inputs")
    dependencies = manifest["compiler_dependencies"]
    require(type(dependencies) is list and all(type(name) is str for name in dependencies)
            and dependencies == sorted(set(dependencies)) and set(dependencies) <= names,
            "compiler dependency closure differs")
    require({"sources/" + name for name in SOURCE_FILES if name.endswith((".rs", ".S"))} <= set(dependencies),
            "compiler dependencies missing native instrumentation or core inputs")
    artifacts = manifest["artifacts"]
    require(type(artifacts) is list and len(artifacts) == 4, "artifact coverage differs")
    retained = {}
    for artifact in artifacts:
        object_fields(artifact, {"file", "sha256", "size", "role"}, "artifact")
        name = artifact["file"]
        require(name in ARTIFACTS and name not in retained and artifact["role"] == ARTIFACTS[name], "artifact identity differs")
        retained[name] = file_ref(root, {key: artifact[key] for key in ("file", "sha256", "size")}, "artifact", 64 * 1024 * 1024)
        require(bool(retained[name]), "empty build artifact")
    require(retained["BOOTX64.EFI"].startswith(b"MZ") and retained["boot.img"] == canonical_disk(retained["BOOTX64.EFI"]),
            "boot media does not contain the exact declared EFI")
    toolchain = object_fields(manifest["toolchain"], {"rustc_version", "linker_version", "rust_flags", "setup"}, "toolchain")
    require(same_json(toolchain["rust_flags"], RUST_FLAGS), "compiler base flags differ")
    for key in ("rustc_version", "linker_version"):
        require(type(toolchain[key]) is str and 0 < len(toolchain[key]) <= 4096
                and all(character.isprintable() or character == "\n" for character in toolchain[key]),
                "invalid compiler version record")
    setup = toolchain["setup"]
    require(type(setup) is dict, "missing checked toolchain setup")
    require(same_json(manifest["compile_commands"], expected_compile_commands(setup.get("host"))),
            "compile target, flags, configuration or input/output binding differs")
    notices = manifest["notices"]
    require(type(notices) is list and len(notices) == 6, "notice coverage differs")
    notice_names = set()
    source_refs = {row["file"]: row for row in sources}
    for notice in notices:
        data = file_ref(root, notice, "notice", 2 * 1024 * 1024)
        name = notice["file"]
        require(name in NOTICE_NAMES and name not in notice_names, "notice name differs or duplicates")
        notice_names.add(name)
        if name.startswith("notices/tessryn-"):
            source = source_refs["sources/" + name.removeprefix("notices/tessryn-")]
            require(notice["sha256"] == source["sha256"] and notice["size"] == source["size"], "repository notice origin differs")
        else:
            try:
                setup = manifest["toolchain"]["setup"]
                spec = (setup["firmware"]["notice"] if name == "notices/firmware-NOTICE"
                        else setup["rust_notices"][name.removeprefix("notices/rust-")])
                require(notice["sha256"] == spec["sha256"] and type(spec["size_bytes"]) is int
                        and notice["size"] == spec["size_bytes"], "checked tool notice origin differs")
            except (KeyError, TypeError) as error:
                raise ValueError("missing checked notice binding") from error
    compile_receipts = manifest["compile"]
    require(type(compile_receipts) is list and len(compile_receipts) == 3, "compile receipt coverage differs")
    for index, receipt in enumerate(compile_receipts):
        role = ("memory", "scheduler", "kernel")[index]
        require(all(receipt[stream]["file"] == role + "-" + stream + ".log" for stream in ("stdout", "stderr")),
                "compile log role differs")
        validate_receipt(root, receipt, "compile " + str(index))
    return manifest


def verify_packet(directory: Path, *, require_result=False, expected_registration_sha256=None) -> dict:
    root = Path(directory)
    registration_bytes = read_regular(root, "registration.json")
    registration_hash = digest(registration_bytes)
    if expected_registration_sha256 is not None:
        require(registration_hash == sha(expected_registration_sha256, "expected registration"), "expected registration binding mismatch")
    registration = strict_json(registration_bytes)
    object_fields(registration, {"schema_version", "kind", "created_at_utc", "evidence_scope", "native_qualification",
                                 "capture_origin", "build_manifest", "files", "config", "command", "limits",
                                 "runtime", "profile_sha256"}, "registration")
    require(type(registration["schema_version"]) is int and registration["schema_version"] == 1
            and registration["kind"] == "native_kernel_benchmark_registration"
            and registration["evidence_scope"] == SCOPE and registration["native_qualification"] is False
            and registration["capture_origin"] == "local_runner_claim_unverified_offline", "invalid registration scope")
    try:
        created = datetime.fromisoformat(registration["created_at_utc"].replace("Z", "+00:00"))
        require(created.utcoffset() is not None and created.utcoffset().total_seconds() == 0, "registration time must be UTC")
    except (ValueError, AttributeError, TypeError) as error:
        raise ValueError("invalid registration time") from error
    require(same_json(registration["config"], CONFIG) and registration["command"] == QEMU_COMMAND,
            "registered workload/runtime command differs")
    limits = object_fields(registration["limits"], {"timeout_seconds", "max_log_bytes"}, "execution limits")
    integer(limits["max_log_bytes"], 1, MAX_LOG_BYTES, "log limit")
    require(type(limits["timeout_seconds"]) in (int, float) and math.isfinite(limits["timeout_seconds"])
            and 0 < limits["timeout_seconds"] <= 60, "invalid timeout")
    manifest_bytes = file_ref(root, registration["build_manifest"], "build manifest")
    require(registration["build_manifest"]["file"] == "build/manifest.json", "manifest path differs")
    manifest = validate_build(root / "build/manifest.json")
    require(manifest_bytes == read_regular(root, "build/manifest.json"), "manifest changed during validation")
    require(registration["profile_sha256"] == manifest["profile"]["sha256"], "registered profile binding differs")
    files = registration["files"]
    require(type(files) is list and 16 <= len(files) <= 150, "retained file coverage outside bounds")
    declared_total = 0
    for ref in files:
        object_fields(ref, {"file", "sha256", "size"}, "retained file")
        declared_total += integer(ref["size"], 0, 64 * 1024 * 1024, "retained file size")
    require(declared_total <= 128 * 1024 * 1024, "retained packet exceeds aggregate byte budget")
    refs = {}
    for ref in files:
        data = file_ref(root, ref, "retained file", 64 * 1024 * 1024)
        name = ref["file"]
        require(name not in refs and (name.startswith("build/") or name in {"firmware/code.fd", "firmware/vars.fd"}),
                "retained file scope differs")
        refs[name] = ref
    needed = [registration["build_manifest"]]
    build_refs = [manifest["profile"], *manifest["sources"], *manifest["notices"],
                  *({key: row[key] for key in ("file", "sha256", "size")} for row in manifest["artifacts"])]
    for receipt in manifest["compile"]:
        build_refs.extend((receipt["stdout"], receipt["stderr"]))
    needed.extend({**ref, "file": "build/" + ref["file"]} for ref in build_refs)
    require(all(refs.get(ref["file"]) == ref for ref in needed), "registration file closure differs from build")
    require(set(refs) == {ref["file"] for ref in needed} | {"firmware/code.fd", "firmware/vars.fd"},
            "registration includes undeclared files")
    runtime = object_fields(registration["runtime"], {"setup", "emulator_sha256"}, "runtime")
    require(same_json(runtime["setup"], manifest["toolchain"]["setup"]), "runtime toolchain setup differs")
    setup = runtime["setup"]
    try:
        require(sha(runtime["emulator_sha256"], "emulator") == setup["verified_tools"]["qemu"]["sha256"], "emulator binding differs")
        for role in ("code", "vars"):
            row = setup["firmware"][role]
            ref = refs["firmware/" + role + ".fd"]
            require(ref["sha256"] == row["sha256"] and type(row["size_bytes"]) is int
                    and ref["size"] == row["size_bytes"], "firmware binding differs")
    except (KeyError, TypeError) as error:
        raise ValueError("invalid runtime setup binding") from error
    receipts = strict_json(read_regular(root, "run_receipts.json"))
    object_fields(receipts, {"schema_version", "execution"}, "run receipts")
    require(type(receipts["schema_version"]) is int and receipts["schema_version"] == 1, "invalid receipt version")
    require(all(receipts["execution"][stream]["file"] == "qemu-" + stream + ".log" for stream in ("stdout", "stderr")),
            "guest log filenames differ")
    stdout, stderr = validate_receipt(root, receipts["execution"], "guest execution", execution=True,
                                      log_limit=limits["max_log_bytes"])
    require(receipts["execution"]["elapsed_seconds"] <= limits["timeout_seconds"] + 2, "execution exceeded registered timeout")
    summary = parse_transcript(stdout, stderr, receipts["execution"]["returncode"], manifest)
    if require_result:
        result = strict_json(read_regular(root, "result.json"))
        object_fields(result, {"schema_version", "kind", "status", "evidence_scope", "native_qualification", "valid",
                               "registration_sha256", "summary", "reason"}, "result")
        require(type(result["schema_version"]) is int and result["schema_version"] == 1
                and result["kind"] == "native_kernel_benchmark_run" and result["status"] == "observed"
                and result["evidence_scope"] == SCOPE and result["native_qualification"] is False
                and result["valid"] is True and result["registration_sha256"] == registration_hash
                and same_json(result["summary"], summary) and type(result["reason"]) is str
                and len(result["reason"]) <= 1024, "result differs from recomputed packet")
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--expected-registration-sha256")
    args = parser.parse_args(argv)
    try:
        summary = verify_packet(args.directory, require_result=True,
                                expected_registration_sha256=args.expected_registration_sha256)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"valid": False, "reason": str(error), "native_qualification": False}))
        return 1
    print(json.dumps({"valid": True, "summary": summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
