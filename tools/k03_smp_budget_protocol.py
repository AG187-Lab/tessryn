"""Fixed inputs and literal artifact inventory for the two-CPU budget proof."""
from __future__ import annotations

from dataclasses import dataclass
import struct

from tools.k02_region_protocol import require
from tools.k03_smp_user_protocol import PROFILE as USER_PROFILE
from tools.k03_smp_user_provenance import COMPILER_SOURCES as USER_COMPILER_SOURCES

PROFILE_NAME = "k03-smp-budget"
ARTIFACT_TYPE = "tessryn-" + PROFILE_NAME
SCOPE = ("bounded original-kernel two-CPU CPL3 LAPIC preemption and aggregate CPU budget; "
         "migration, reclamation, physical clocks, devices and performance unqualified")
CASES = ("preempt", "late", "fault")
VECTOR = 67
DIVIDE_CONFIG = 3
DIVIDER = 16
AP_TIMER_MULTIPLIER = 4
DOMAIN = 1
MAGIC = b"TESSRYN-SMPBUD1\0"
DESCRIPTOR_SYMBOL = "K03_SMP_BUDGET_CONTRACT"
DESCRIPTOR_SIZE = 136
SCHEDULER_SOURCE = "scheduler-core/lib.rs"
SCHEDULER_SHA256 = "db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d"
LIBRARY = "libtessryn_scheduler.rlib"
COMPILER_ROLES = ("scheduler", *CASES)
COMPILER_SOURCES = (*USER_COMPILER_SOURCES, "kernel/smp_budget.rs", SCHEDULER_SOURCE)
RUNTIME_FILES = (
    "tools/k03_smp_budget.py", "tools/k03_smp_budget_protocol.py", "tools/k03_smp_budget_trace.py",
    "tools/build_k02_native.py", "tools/build_k03_smp_user.py", "tools/build_fixture.py", "tools/build_kernel.py",
    "tools/check_k03_smp_user_host.py", "tools/g03/__init__.py", "tools/g03/process.py", "tools/k01_media.py",
    "tools/k02_region_protocol.py", "tools/k03_smp_protocol.py", "tools/k03_smp_trace.py", "tools/k03_smp_user_protocol.py",
    "tools/k03_smp_user_provenance.py", "tools/k03_smp_user_trace.py", "tools/run_k03_smp_user.py",
    "tools/setup_k02_toolchain.py", "tools/setup_toolchain.py", "tools/setup_uefi.py", "tools/verify_k03_smp_user.py",
    "fixtures/rom.py", "tests/k03_smp_acpi.rs", "toolchain.lock.json", "uefi-toolchain.lock.json",
    "planning/k02-toolchain.lock.json", "planning/k03-smp-budget.json", ".github/workflows/k03-smp-budget.yml",
)
PROFILE = {
    **USER_PROFILE,
    "timer_vector": VECTOR,
    "lapic_divide_configuration": DIVIDE_CONFIG,
    "lapic_divider": DIVIDER,
    "budget_domain": DOMAIN,
    "ap_timer_multiplier": AP_TIMER_MULTIPLIER,
    "scheduler_sha256": SCHEDULER_SHA256,
    "scheduler_owner": "bsp-only",
}


@dataclass(frozen=True)
class Scenario:
    cap_ns: int
    quantum_ns: int
    timer_ns: int
    rounds: int


SCENARIOS = {"preempt": Scenario(1_200_000_000, 800_000_000, 20_000_000, 2),
             "late": Scenario(60_000_000, 40_000_000, 60_000_000, 1),
             "fault": Scenario(1_200_000_000, 800_000_000, 20_000_000, 1)}


def format_name(kind):
    return f"{ARTIFACT_TYPE}-{kind}/v1"


def descriptor_bytes(case):
    scenario = SCENARIOS[case]
    return MAGIC + struct.pack("<15Q", 1, CASES.index(case), 2, DOMAIN, VECTOR, DIVIDE_CONFIG, DIVIDER,
        scenario.cap_ns, scenario.quantum_ns, scenario.timer_ns, scenario.rounds, PROFILE["period_fs"],
        PROFILE["window_ns"], PROFILE["timeout_ns"], AP_TIMER_MULTIPLIER)


def case_flags(case):
    require(case in CASES, "unknown SMP budget case")
    return ["--cfg", "k01_emulator", "--cfg", "k03_smp", "--cfg", "k03_smp_user", "--cfg", 'smp_user_case="rendezvous"',
        "--cfg", "k03_smp_budget", "--cfg", f'smp_budget_case="{case}"']


def artifacts():
    """Fixed relative path to role; the rlib is a first-class twin input."""
    return {LIBRARY: "scheduler", **{f"{case}/{name}": case for case in CASES
            for name in ("BOOTX64.EFI", "kernel.obj", "boot.img")}}


def compile_log(role, stream):
    return f"{role}/{stream}.log"


def success_inventory():
    sources = sorted(set(COMPILER_SOURCES) | set(RUNTIME_FILES))
    notices = ("tessryn-LICENSE", "tessryn-NOTICE", "rust-LICENSE-APACHE", "rust-LICENSE-MIT", "rust-COPYRIGHT")
    twin = ["manifest.json", *artifacts(), *(compile_log(role, stream) for role in COMPILER_ROLES for stream in ("stdout", "stderr")),
            *(f"notices/{name}" for name in notices), *(f"sources/{name}" for name in sources)]
    captures = ("result.json", "registration.json", "stdout.log", "stderr.log", "firmware/code.fd", "firmware/vars.fd", "firmware/NOTICE")
    host = ("result.json", "build-stdout.log", "build-stderr.log", "tests-stdout.log", "tests-stderr.log")
    return [*(f"{name}/{file}" for name in ("a", "b") for file in twin),
            *(f"{case}/{file}" for case in CASES for file in captures), *(f"host/{file}" for file in host), "verification.json"]
