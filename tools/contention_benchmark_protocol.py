"""Separate bounded contract for the two-CPU contention fixture."""
from __future__ import annotations
from pathlib import Path
import struct
from tools.k03_smp_protocol import (ROOT, PROFILE as SMP_PROFILE, require, digest, regular_bytes,
    strict_json, read_ref, file_ref, fresh_output, write_json, retain_private_error)
from tools.k03_smp_provenance import COMPILER_SOURCES as SMP_SOURCES, RUNTIME_FILES as SMP_RUNTIME, canonical

SCOPE = "two_cpu_qemu_contention"
CONFIG = {"samples": 16, "warmup": 4, "iterations": 1024, "cases": 6, "cpus": 2}
NAMES = ("counter_pair", "local_atomic_reference", "separate_64b_lines", "same_64b_line", "shared_atomic_counter", "ping_pong_roundtrip")
PROFILE_FILE = "planning/contention-benchmark-profile.json"
COMPILER_SOURCES = (*SMP_SOURCES, "kernel/contention_benchmarks.rs")
RUNTIME_FILES = tuple(sorted(set(SMP_RUNTIME) | {"tools/contention_benchmark_protocol.py",
    "tools/build_contention_benchmarks.py", "tools/run_contention_benchmarks.py",
    "tools/verify_contention_benchmarks.py", PROFILE_FILE}))
CHECKS = ["exact_peer_generations", "exact_final_counts", "separate_and_shared_64b_layout",
          "bounded_waits", "bsp_clock_no_regression", "original_terminal_stop"]
MAX_LOG_BYTES = 1 << 20
MAX_PACKET_BYTES = 128 << 20
MAGIC = b"TESSRYN-CBENCH1\0"
DESCRIPTOR = MAGIC + struct.pack("<10Q", 1, 6, 16, 4, 1024, 64, 10_000_000, 200_000_000, 20_000_000, 120)
FLAGS = ["--cfg", "k01_emulator", "--cfg", "k03_smp", "--cfg", 'smp_case="rendezvous"', "--cfg", "smp_benchmarks"]
K01_FLAGS = ["--edition=2024", "--crate-name=tessryn_kernel", "--crate-type=bin", "--target=x86_64-unknown-uefi",
    "-Cpanic=abort", "-Copt-level=1", "-Ccodegen-units=1", "-Cdebuginfo=2", "-Cforce-frame-pointers=yes",
    "-Cno-redzone=yes", "-Cembed-bitcode=no", "-Clink-arg=/timestamp:0", "-Clink-arg=/debug:none"]


def profile():
    return {"schema_version": 1, "kind": "contention_benchmark_profile", "scope": SCOPE,
        "hardware_qualified": False, "inference_qualified": False, "config": CONFIG.copy(),
        "platform": dict(SMP_PROFILE), "clock": {"name": "hpet", "owner": "bsp", "unit": "raw_ticks",
            "period_fs": 10_000_000, "cross_cpu_subtraction": False, "overhead_subtraction": False},
        "limits": {"wait_ticks": 200_000_000, "max_polls": 20_000_000, "timeout_seconds": 60, "max_log_bytes": MAX_LOG_BYTES},
        "layout": {"assumed_line_bytes": 64, "hardware_cache_line_qualified": False},
        "cases": [{"case": name, "sample_unit": "counter_pair" if index == 0 else "coordinated_batch_completion",
            "operations": 0 if index == 0 else 1024 if index == 1 else 2048,
            "operation_definition": "no_payload" if index == 0 else "ping_publication_stores_excluding_poll_loads" if index == 5 else "payload_atomic_fetch_adds_excluding_coordination",
            "round_trips": 1024 if index == 5 else 0} for index, name in enumerate(NAMES)],
        "checks": list(CHECKS), "warmup_policy": "per_case_retained_raw_excluded_from_statistics",
        "measurement_semantics": "BSP_raw_HPET_completion_including_peer_coordination_except_adjacent_counter_reference"}


def runtime_hashes():
    return {name: digest(regular_bytes(ROOT / name, 16 << 20)) for name in RUNTIME_FILES}


def expected_command(compiler_profile):
    prefix = ROOT / "build/uefi"
    linker = Path(compiler_profile["linker"])
    require(linker.is_relative_to(prefix), "contention linker escapes checked toolchain")
    return ["kernel/main.rs", *compiler_profile["toolchain"]["rust_flags"], "-Dwarnings", *FLAGS,
        "--emit=link,obj=contention-build/kernel.obj,dep-info=contention-build/kernel.d",
        "--remap-path-prefix=rust-toolchain=rust-toolchain", "--remap-path-prefix=contention-build=contention-build",
        "--remap-path-prefix=tessryn=tessryn", "-Clinker=rust-toolchain/" + linker.relative_to(prefix).as_posix(),
        "-o", "contention-build/BOOTX64.EFI"]


def descriptor_binding(obj: bytes, efi: bytes):
    """Bind the new config symbol's immutable COFF bytes to one read-only EFI range."""
    require(len(obj) >= 20, "contention object truncated")
    machine, count, _, symbols_at, symbols_count, optional, _ = struct.unpack_from("<HHIIIHH", obj)
    strings_at = symbols_at + symbols_count * 18
    require(machine == 0x8664 and optional == 0 and 0 < count <= 4096 and symbols_count <= 1_000_000
        and 20 + count * 40 <= len(obj) and strings_at + 4 <= len(obj), "contention COFF table invalid")
    strings_size = struct.unpack_from("<I", obj, strings_at)[0]
    require(4 <= strings_size <= len(obj) - strings_at, "contention COFF strings invalid")
    matches, index = [], 0
    while index < symbols_count:
        at = symbols_at + index * 18
        raw = obj[at:at + 8]
        if raw[:4] == bytes(4):
            offset = struct.unpack_from("<I", raw, 4)[0]
            end = obj.find(b"\0", strings_at + offset, strings_at + strings_size)
            require(4 <= offset < strings_size and end >= 0, "contention symbol string invalid")
            raw = obj[strings_at + offset:end]
        else: raw = raw.rstrip(b"\0")
        value, section, _, storage, auxiliary = struct.unpack_from("<IhHBB", obj, at + 8)
        if raw == b"CONTENTION_BENCHMARK_CONTRACT":
            require(storage == 2 and 1 <= section <= count, "contention symbol not global stored data")
            matches.append((section, value))
        index += 1 + auxiliary
        require(index <= symbols_count, "contention auxiliary symbols truncated")
    require(len(matches) == 1, "contention compiled descriptor missing or duplicate")
    section, value = matches[0]
    at = 20 + (section - 1) * 40
    size, raw, relocations = struct.unpack_from("<III", obj, at + 16)
    reloc_count = struct.unpack_from("<H", obj, at + 32)[0]
    require(raw > 0 and value + len(DESCRIPTOR) <= size and raw + size <= len(obj)
        and relocations + reloc_count * 10 <= len(obj), "contention object descriptor range invalid")
    for index in range(reloc_count):
        position = struct.unpack_from("<I", obj, relocations + index * 10)[0]
        require(not value <= position < value + len(DESCRIPTOR), "contention descriptor has relocations")
    require(obj[raw + value:raw + value + len(DESCRIPTOR)] == DESCRIPTOR, "contention compiled configuration differs")
    from tools.build_kernel import inspect_pe
    pe_info = inspect_pe(efi)
    location = efi.find(DESCRIPTOR)
    require(location >= 0 and efi.find(DESCRIPTOR, location + 1) < 0, "contention EFI descriptor not unique")
    pe = struct.unpack_from("<I", efi, 60)[0]
    optional = struct.unpack_from("<H", efi, pe + 20)[0]
    rvas = []
    for index in range(len(pe_info["sections"])):
        at = pe + 24 + optional + index * 40
        rva, size, raw = struct.unpack_from("<III", efi, at + 12)
        flags = struct.unpack_from("<I", efi, at + 36)[0]
        if raw <= location and location + len(DESCRIPTOR) <= raw + size:
            require(flags & 0x40000000 and not flags & 0xa0000000, "contention descriptor is writable/executable")
            rvas.append(rva + location - raw)
    require(len(rvas) == 1, "contention linked descriptor range ambiguous")
    return {"size_bytes": len(DESCRIPTOR), "sha256": digest(DESCRIPTOR), "efi_file_offset": location, "efi_rva": rvas[0]}
