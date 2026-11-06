#!/usr/bin/env python3
"""Describe virtual HPET intervals only after complete K03 timer verification.

Input is one existing timer packet: a/manifest.json, b/manifest.json,
host/result.json and one result.json in each of the four scenario directories.
The trusted checkout's original verifier remains mandatory. Retained Python is
data, never imported or executed. An offline consistency check cannot authenticate
the origin of a capture. Repeated fresh boots are an orchestration responsibility.

Comparator target -> first trusted IRQ sample includes interrupt delivery and
the existing capture path. Capture -> ACCOUNT stop includes deferred attributable
work and logging. Neither endpoint isolates interrupt entry, context switching,
user instructions, or physical latency. No instrumentation cost is subtracted.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import verify_k03_timer as timer_verifier
from tools.k03_timer_protocol import CASES, MAX_LOG_BYTES, digest, regular_bytes, require, strict_json
from tools.k03_timer_provenance import canonical
from tools.k03_timer_trace import _Trace, parse_transcript

FORMAT = "tessryn-preemption-benchmark/v1"
SCOPE = "original_kernel_single_cpu_qemu_hpet_observation"
U64 = (1 << 64) - 1
# The mandatory current timer oracle bounds its entire dispatch loop to 128
# steps (including any no-entry ARM_MISSED). Each dispatch has exactly one
# ACCOUNT and at most one IRQ, so this covers every accepted scenario sample.
MAX_SCENARIO_SAMPLES = 128
CLOCK_PROFILE = {
    "source": "hpet64", "period_fs": 10_000_000, "ns_per_tick": 10,
    "time_domain": "qemu_emulator_virtual_time", "cross_boot_synchronization": "none",
}
METRICS = {
    "irq_capture_delay": "ARM comparator target_raw -> IRQ first trusted capture_raw",
    "irq_capture_to_trusted_stop": "IRQ capture_raw -> ACCOUNT stop_raw after attributable work and deferred logging",
    "irq_target_to_trusted_stop": "ARM comparator target_raw -> matching IRQ ACCOUNT stop_raw",
    "dispatch_to_trusted_stop": "DISPATCH start_raw -> ACCOUNT stop_raw, including no-entry ARM_MISSED",
    "capture_to_trusted_stop": "IRQ/CANCEL capture_raw or ARM_MISSED raw -> matching ACCOUNT stop_raw",
}
UNAVAILABLE = [
    "physical_clock_qualification", "physical_hardware_latency", "pure_interrupt_entry_cost",
    "pure_context_switch_cost", "CPL3_instruction_time", "runnable_to_running_latency",
    "SMP_contention", "cross_boot_clock_synchronization", "inference_performance",
    "independent_capture_authentication", "instrumentation_overhead_subtraction",
]
INPUT_NAMES = ("a/manifest.json", "b/manifest.json", "host/result.json", *(
    case + "/" + name for case in CASES
    for name in ("result.json", "registration.json", "stdout.log", "stderr.log")))


def _integer(value, label):
    require(type(value) is int and 0 <= value <= U64, label + " must be a u64 integer")
    return value


def _duration(start, end):
    _integer(start, "interval start"); _integer(end, "interval end")
    require(end >= start, "preemption benchmark timestamp regressed")
    ticks = end - start
    virtual_ns = ticks * CLOCK_PROFILE["ns_per_tick"]
    require(virtual_ns <= U64, "preemption benchmark conversion overflowed")
    return ticks, virtual_ns


def nearest_rank(values):
    """Exact integer nearest-rank p50/p95/p99; zeros remain observations."""
    require(type(values) is list and len(values) <= MAX_SCENARIO_SAMPLES, "preemption sample bound differs")
    for value in values:
        _integer(value, "statistic observation")
    if not values:
        return None
    ordered, count = sorted(values), len(values)
    result = {"minimum": ordered[0], "maximum": ordered[-1]}
    for percentile in (50, 95, 99):
        result["p" + str(percentile)] = ordered[(percentile * count + 99) // 100 - 1]
    return result


def _statistics(values):
    return {"sample_count": len(values), "ticks": nearest_rank(values),
            "emulator_virtual_ns": nearest_rank([value * CLOCK_PROFILE["ns_per_tick"] for value in values])}


def _extract_capture(case, stdout, stderr, returncode, binding):
    """Replay raw capture authority/contexts before deriving any interval.

    This helper alone has no build, toolchain, registration or execution-origin
    acceptance. Only extract_packet supplies the full existing verification gate.
    """
    observed = parse_transcript(case, stdout, returncode, stderr, binding)
    trace = _Trace(stdout)
    active, task_roots, irq_samples, stops = None, {}, [], []
    sequence, last_stop = -1, None
    clock = None
    for kind, fields in trace.rows:
        if not kind.startswith("TESSRYN_K03_TIMER_"):
            continue
        sequence += 1
        name = kind.removeprefix("TESSRYN_K03_TIMER_")
        if name == "CLOCK":
            require(clock is None and fields["period_fs"] == CLOCK_PROFILE["period_fs"]
                    and fields["qualification"] == "emulator_only", "preemption clock profile differs")
            clock = fields
        elif name == "TASK":
            require(fields["domain"] not in task_roots, "preemption task root repeated")
            task_roots[fields["domain"]] = fields["root"]
        elif name == "DISPATCH":
            require(active is None and (last_stop is None or fields["start_raw"] >= last_stop),
                    "preemption dispatch overlaps a trusted stop")
            active = {"dispatch": fields, "dispatch_sequence": sequence}
        elif name in ("RESUME", "ARM", "TRAP", "IRQ", "CANCEL", "ARM_MISSED"):
            require(active is not None and name not in active, "preemption event absent/repeated within dispatch")
            dispatch = active["dispatch"]
            require(fields["task"] == dispatch["task"], "preemption event rebound to another task")
            if name in ("ARM", "IRQ", "CANCEL", "ARM_MISSED"):
                require(fields["generation"] == dispatch["lease_generation"],
                        "preemption event rebound to another lease generation")
            else:
                require(fields["domain"] == dispatch["domain"]
                        and fields["root"] == task_roots[dispatch["domain"]],
                        "preemption event rebound to another domain/root")
                if name == "RESUME":
                    require(fields["generation"] == dispatch["task_generation"],
                            "preemption resume task generation differs")
                else:
                    require(fields["cs"] == 0x33 and fields["ss"] == 0x2b,
                            "preemption trap is not the admitted CPL3 context")
            active[name], active[name + "_sequence"] = fields, sequence
        elif name == "ACCOUNT":
            require(active is not None, "preemption account lacks a dispatch")
            dispatch = active["dispatch"]
            require(all(fields[key] == dispatch[key] for key in (
                "task", "domain", "lease_generation", "start_raw", "start_ns", "grant_ns", "hard_ns")),
                "preemption account rebound to another dispatch")
            require(clock is not None, "preemption clock absent")
            for prefix in ("start", "capture", "stop"):
                raw, ns = fields[prefix + "_raw"], fields[prefix + "_ns"]
                require(raw >= clock["epoch_raw"]
                        and _duration(clock["epoch_raw"], raw)[1] == ns,
                        "preemption absolute HPET conversion differs")
            elapsed_ticks, elapsed_ns = _duration(fields["start_raw"], fields["stop_raw"])
            _duration(fields["start_raw"], fields["capture_raw"])
            post_ticks, post_ns = _duration(fields["capture_raw"], fields["stop_raw"])
            require(elapsed_ns == fields["elapsed_ns"], "preemption account arithmetic differs")
            capture_kind = {"irq": "IRQ", "arm_missed": "ARM_MISSED"}.get(fields["reason"], "CANCEL")
            require(capture_kind in active and sum(k in active for k in ("IRQ", "CANCEL", "ARM_MISSED")) == 1,
                    "preemption capture kind is ambiguous")
            capture = active[capture_kind]
            raw_key, ns_key = ("raw", "now_ns") if capture_kind == "ARM_MISSED" else ("capture_raw", "capture_ns")
            require((capture[raw_key], capture[ns_key]) == (fields["capture_raw"], fields["capture_ns"]),
                    "preemption account rebound to another capture")
            no_entry = capture_kind == "ARM_MISSED"
            require(no_entry == ("RESUME" not in active and "TRAP" not in active and "ARM" not in active),
                    "preemption missed arm was relabeled as user execution")
            context = None if no_entry else {
                "task_generation": dispatch["task_generation"], "root": active["TRAP"]["root"],
                "resume_index": active["RESUME"]["resumes"], "interrupted_rip": active["TRAP"]["rip"],
                "interrupted_rsp": active["TRAP"]["rsp"], "frame": active["TRAP"]["frame"],
                "fp_sha256": active["TRAP"]["fp_sha256"],
                "sha256": digest(canonical({"resume": active["RESUME"], "trap": active["TRAP"]}).encode()),
            }
            stop = {"sample_index": len(stops), "task": fields["task"], "domain": fields["domain"],
                "cpu": dispatch["cpu"], "lease_generation": fields["lease_generation"],
                "dispatch_sequence": active["dispatch_sequence"], "capture_sequence": active[capture_kind + "_sequence"],
                "account_sequence": sequence, "reason": fields["reason"], "outcome": fields["outcome"],
                "state": fields["state"], "late": bool(fields["late"]), "entered_cpl3": not no_entry,
                "start_raw": fields["start_raw"], "capture_raw": fields["capture_raw"], "stop_raw": fields["stop_raw"],
                "start_emulator_virtual_ns": fields["start_ns"],
                "capture_emulator_virtual_ns": fields["capture_ns"], "stop_emulator_virtual_ns": fields["stop_ns"],
                "grant_emulator_virtual_ns": fields["grant_ns"], "hard_emulator_virtual_ns": fields["hard_ns"],
                "dispatch_to_stop_ticks": elapsed_ticks, "dispatch_to_stop_emulator_virtual_ns": elapsed_ns,
                "capture_to_stop_ticks": post_ticks, "capture_to_stop_emulator_virtual_ns": post_ns, "context": context}
            stops.append(stop)
            if capture_kind == "IRQ":
                arm, trap = active["ARM"], active["TRAP"]
                require(trap["vector"] == 32 and trap["error"] == 0
                        and capture["target_raw"] == arm["target_raw"] == arm["readback_raw"],
                        "preemption IRQ rebound to another comparator/context")
                delay_ticks, delay_ns = _duration(arm["target_raw"], fields["capture_raw"])
                total_ticks, total_ns = _duration(arm["target_raw"], fields["stop_raw"])
                irq_samples.append({"sample_index": len(irq_samples), "trusted_stop_index": stop["sample_index"],
                    "task": fields["task"], "domain": fields["domain"], "cpu": dispatch["cpu"],
                    "lease_generation": fields["lease_generation"], "context": context,
                    "dispatch_sequence": active["dispatch_sequence"], "resume_sequence": active["RESUME_sequence"],
                    "arm_sequence": active["ARM_sequence"], "trap_sequence": active["TRAP_sequence"],
                    "irq_sequence": active["IRQ_sequence"], "account_sequence": sequence,
                    "armed_raw": arm["armed_raw"], "target_raw": arm["target_raw"],
                    "capture_raw": fields["capture_raw"], "stop_raw": fields["stop_raw"],
                    "capture_delay_ticks": delay_ticks, "capture_delay_emulator_virtual_ns": delay_ns,
                    "capture_to_stop_ticks": post_ticks, "capture_to_stop_emulator_virtual_ns": post_ns,
                    "target_to_stop_ticks": total_ticks, "target_to_stop_emulator_virtual_ns": total_ns})
            last_stop, active = fields["stop_raw"], None
    require(active is None and clock is not None, "preemption trace has an unfinished dispatch")
    require(len(stops) == observed["dispatches"]
            and len(irq_samples) == sum(observed["irqs"])
            and [sum(row["task"] == i for row in irq_samples) for i in range(2)] == observed["irqs"]
            and sum(not row["entered_cpl3"] for row in stops) == observed["missed_arms"],
            "preemption observation counts differ from complete replay")
    statistics = {
        "irq_capture_delay": _statistics([row["capture_delay_ticks"] for row in irq_samples]),
        "irq_capture_to_trusted_stop": _statistics([row["capture_to_stop_ticks"] for row in irq_samples]),
        "irq_target_to_trusted_stop": _statistics([row["target_to_stop_ticks"] for row in irq_samples]),
        "dispatch_to_trusted_stop": _statistics([row["dispatch_to_stop_ticks"] for row in stops]),
        "capture_to_trusted_stop": _statistics([row["capture_to_stop_ticks"] for row in stops]),
    }
    return {"case": case, "clock": observed["clock"], "observations": observed,
            "counts": {"irqs": len(irq_samples), "irqs_by_task": observed["irqs"],
                       "trusted_stops": len(stops), "missed_arms": observed["missed_arms"]},
            "irq_samples": irq_samples, "trusted_stop_samples": stops, "statistics": statistics}


def extract_packet(packet_dir):
    """Return analysis of all four original scenarios after mandatory full verification.

    Raises rather than publishing a partial result if any original gate fails.
    Small analysis inputs are snapshotted on both sides of verification; summary
    identity is tied to the exact manifest, registration, receipt and raw bytes.
    """
    root = Path(packet_dir).absolute()
    captured = {name: regular_bytes(root / name, MAX_LOG_BYTES if name.endswith(".log") else 2 << 20)
                for name in INPUT_NAMES}
    analyzer = regular_bytes(ROOT / "tools/preemption_benchmark.py", 1 << 20)
    first, second = root / "a/manifest.json", root / "b/manifest.json"
    verification = timer_verifier.verify(first, second,
        [root / case / "result.json" for case in CASES], root / "host/result.json")
    require(verification["status"] == "pass" and verification["qualification"] == "not_established"
            and verification["capture_authentication"] == "unverified_offline"
            and set(verification["observations"]) == set(CASES), "original timer verification incomplete")
    manifest = strict_json(captured["a/manifest.json"])
    require(verification["source"] == manifest["source"], "verified preemption source identity differs")
    scenarios = {}
    for case in CASES:
        result = strict_json(captured[case + "/result.json"])
        require(result["case"] == case and result["status"] == "pass"
                and result["manifest_sha256"] == digest(captured["a/manifest.json"])
                and result["registration_sha256"] == digest(captured[case + "/registration.json"]),
                "preemption packet scenario/registration was rebound")
        logs = {row["path"]: row for row in result["logs"]}
        require(set(logs) == {"stdout.log", "stderr.log"} and len(result["logs"]) == 2,
                "preemption raw stream coverage differs")
        for stream in logs:
            data = captured[case + "/" + stream]
            require(logs[stream]["sha256"] == digest(data) and logs[stream]["size_bytes"] == len(data),
                    "preemption captured raw bytes were rebound")
        scenario = _extract_capture(case, captured[case + "/stdout.log"], captured[case + "/stderr.log"],
                                    result["execution"]["returncode"], timer_verifier.bound_context(first, manifest, case))
        require(scenario["observations"] == verification["observations"][case] == result["observations"],
                "preemption extraction differs from complete verified replay")
        scenarios[case] = scenario
    for name, data in captured.items():
        require(regular_bytes(root / name, MAX_LOG_BYTES if name.endswith(".log") else 2 << 20) == data,
                "preemption analysis input changed during verification/extraction")
    require(regular_bytes(ROOT / "tools/preemption_benchmark.py", 1 << 20) == analyzer,
            "preemption analyzer source changed during extraction")
    return {"format": FORMAT, "status": "pass", "scope": SCOPE, "qualification": "not_established",
        "capture_authentication": "unverified_offline", "capture_packets_per_scenario": 1,
        "identity": {"source": manifest["source"], "toolchain": manifest["toolchain"],
            "machine_profile": manifest["profile"], "clock_profile": dict(CLOCK_PROFILE),
            "artifact_sha256": {row["path"]: row["sha256"] for row in manifest["artifacts"]},
            "compiler_sources_sha256": manifest["source_files_sha256"], "runtime_sha256": manifest["runtime_files"]},
        "analysis": {"file": "tools/preemption_benchmark.py", "sha256": digest(analyzer),
            "statistic": "integer nearest-rank ceil(p*n/100), per scenario; descriptive only",
            "warmup_discarded": 0, "outliers_discarded": 0, "instrumentation_subtracted": False,
            "cross_scenario_pooling": False, "confidence_intervals": "not_estimated",
            "metric_endpoints": dict(METRICS)},
        "input_refs": [{"path": name, "sha256": digest(data), "size_bytes": len(data)} for name, data in captured.items()],
        "verification": verification, "scenarios": scenarios, "unavailable": list(UNAVAILABLE)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.out.exists() and not args.out.is_symlink(), "preemption analysis output already exists")
        result = extract_packet(args.packet)
        # Exclusive creation publishes only a complete successful analysis.
        with args.out.open("x", encoding="utf-8") as output:
            output.write(canonical(result) + "\n")
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.exit(1, "Preemption analysis rejected: " + type(error).__name__ + "\n")
    print("Verified K03 timer packet analyzed; HPET ticks and QEMU virtual time only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
