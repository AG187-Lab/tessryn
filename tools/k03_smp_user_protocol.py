"""Frozen bounded inputs for the two-CPU isolated CPL3 experiment."""
from __future__ import annotations
import struct
from tools.k02_region_protocol import (ROOT, require, digest, regular_bytes, strict_json,
    portable_path, read_ref, file_ref, write_json, fresh_output, retain_private_error)

CASES = ("rendezvous", "peer_read", "forged_ipi")
PROFILE = {"architecture": "x86_64", "target": "x86_64-unknown-uefi",
    "machine": "q35,hpet=on", "accelerator": "tcg,thread=multi",
    "cpu": "max,phys-bits=48,la57=off,nx=on,pcid=off,pge=off,pku=off,pks=off,sgx=off,cet-ss=off,cet-ibt=off,fsgsbase=off,x2apic=off",
    "topology": "2,sockets=1,cores=2,threads=1,maxcpus=2", "cpu_count": 2,
    "memory_bytes": 256 << 20, "lapic": 0xfee00000, "hpet": 0xfed00000,
    "period_fs": 10_000_000, "ipi_vector": 64, "stop_vector": 65,
    "increments": 4096, "timeout_ns": 2_000_000_000, "user_code": 0x100000000,
    "user_stack": 0x100002000, "user_data": 0x100004000, "peer": 0x100200000,
    "root_pool_pages": 17, "context_bytes": 736, "trap_frame_bytes": 176, "fp_bytes": 512,
    "marker_seed": 0x5355455200000000, "register_sentinel": 0x534d505500000000,
    "user_ipi_vector": 66, "yield_vector": 128, "warmup_iterations": 65536, "window_ns": 20_000_000}
SCOPE = "bounded original-kernel two-CPU isolated CPL3 contexts and authenticated peer interrupts; shared budgets, local timers, migration, reclamation, physical clocks, devices and performance unqualified"
FORMAT = "tessryn-k03-smp-user-result/v1"
ARTIFACT_TYPE = "tessryn-k03-smp-user"
CONTRACT_NAME = "planning/k03-smp-user.json"
MAX_LOG_BYTES = 1 << 20
MAGIC = b"TESSRYN-SMPUSR1\0"
DESCRIPTOR_SIZE = 112


def case_flags(case):
    require(case in CASES, "unknown SMP user scenario")
    return ["--cfg", "k01_emulator", "--cfg", "k03_smp", "--cfg", "k03_smp_user", "--cfg", f'smp_user_case="{case}"']


def descriptor_bytes(case):
    require(case in CASES, "unknown SMP user scenario")
    return MAGIC + struct.pack("<12Q", 1, CASES.index(case), 2, PROFILE["user_code"], PROFILE["user_stack"],
        PROFILE["user_data"], PROFILE["peer"], PROFILE["user_ipi_vector"], PROFILE["yield_vector"],
        PROFILE["warmup_iterations"], PROFILE["timeout_ns"], PROFILE["window_ns"])
