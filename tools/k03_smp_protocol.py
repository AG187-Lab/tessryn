"""Frozen bounded inputs for the two-CPU kernel bootstrap experiment."""
from __future__ import annotations
import struct
from tools.k02_region_protocol import (ROOT, require, digest, regular_bytes, strict_json,
    portable_path, read_ref, file_ref, write_json, fresh_output, retain_private_error)

CASES = ("rendezvous", "missing_ap")
PROFILE = {"architecture": "x86_64", "target": "x86_64-unknown-uefi",
    "machine": "q35,hpet=on", "accelerator": "tcg,thread=multi",
    "cpu": "max,phys-bits=48,la57=off,nx=on,pcid=off,pge=off,pku=off,pks=off,sgx=off,cet-ss=off,cet-ibt=off,fsgsbase=off,x2apic=off",
    "topology": "2,sockets=1,cores=2,threads=1,maxcpus=2", "cpu_count": 2,
    "memory_bytes": 256 << 20, "lapic": 0xfee00000, "hpet": 0xfed00000,
    "period_fs": 10_000_000, "ipi_vector": 64, "stop_vector": 65,
    "increments": 4096, "timeout_ns": 2_000_000_000}
SCOPE = "bounded original-kernel two-CPU xAPIC bootstrap and rendezvous; CPL3 SMP, scheduler contention, physical clocks, devices and performance unqualified"
FORMAT = "tessryn-k03-smp-result/v1"
ARTIFACT_TYPE = "tessryn-k03-smp"
CONTRACT_NAME = "planning/k03-smp.json"
MAX_LOG_BYTES = 1 << 20
MAGIC = b"TESSRYN-SMP1\0\0\0\0"


def case_flags(case):
    require(case in CASES, "unknown SMP scenario")
    return ["--cfg", "k01_emulator", "--cfg", "k03_smp", "--cfg", f'smp_case="{case}"']


def descriptor_bytes(case):
    require(case in CASES, "unknown SMP scenario")
    return MAGIC + struct.pack("<10Q", 1, CASES.index(case), 2, PROFILE["lapic"], PROFILE["hpet"],
        PROFILE["period_fs"], PROFILE["ipi_vector"], PROFILE["stop_vector"],
        PROFILE["increments"], PROFILE["timeout_ns"])
