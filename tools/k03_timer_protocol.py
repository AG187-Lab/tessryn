"""Frozen inputs for the single-CPU HPET/K03 integration experiment."""
from __future__ import annotations

import struct
from tools.k02_region_protocol import (ROOT, ADDRESSES, OPS, STATUSES, MAX_LOG_BYTES,
    require, digest, regular_bytes, strict_json, portable_path, read_ref, file_ref,
    write_json, fresh_output, retain_private_error, decode_request)

CONTRACT_NAME = "planning/k03-timer.json"
CASES = ("preemption", "budget", "deadline", "forged_irq")
CPU = "max,phys-bits=48,la57=off,nx=on,pcid=off,pge=off,pku=off,pks=off,sgx=off,cet-ss=off,cet-ibt=off,fsgsbase=off"
PROFILE = {"architecture": "x86_64", "target": "x86_64-unknown-uefi", "machine": "q35,accel=tcg,hpet=on",
    "cpu": CPU, "cpu_count": 1, "memory_bytes": 256 << 20, "physical_bits": 48,
    "paging_levels": 4, "page_size": 4096, "nx_enabled": True, "pcid_enabled": False,
    "global_translations": False, "legacy_fp_only": True, "invalidation": "cr3_reload",
    "clock": "hpet64", "hpet_address": 0xfed00000, "clock_period_fs": 10_000_000,
    "timer_route": "legacy_replacement_pic_irq0", "irq_vector": 32, "tsc_clock": False}
ARTIFACT_TYPE = "tessryn-k03-timer"
FORMAT = "tessryn-k03-timer-result/v1"
SCOPE = "bounded original-kernel single-CPU HPET timer and K03 budget integration; physical clocks, arbitrary-program isolation, SMP and DMA unqualified"
MAGIC = b"TESSRYN-TIMER1\0\0"
DESCRIPTOR_SIZE = 144
QUANTUM_NS = 250_000_000
SOFT_NS = 10_000_000
DEFAULT_BUDGET_NS = 2_000_000_000
MAILBOX_OFFSET = 128
MIN_IRQS = 3
SCHEDULER_SHA256 = "db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d"


def case_flags(case):
    require(case in CASES, "unknown K03 timer scenario")
    return ["--cfg", "k01_emulator", "--cfg", "k02_native", "--cfg", "k02_region_service",
            "--cfg", "k03_timer", "--cfg", f'k03_timer_case="{case}"']


def case_limits(case):
    require(case in CASES, "unknown K03 timer scenario")
    return (80_000_000 if case == "budget" else DEFAULT_BUDGET_NS,
            DEFAULT_BUDGET_NS, 100_000_000 if case == "deadline" else 0)


def descriptor_bytes(case):
    budget_a, budget_b, deadline = case_limits(case)
    return MAGIC + struct.pack("<16Q", 1, CASES.index(case), 1, 2, *ADDRESSES.values(), 96,
        QUANTUM_NS, SOFT_NS, budget_a, budget_b, deadline, MAILBOX_OFFSET, MIN_IRQS)
