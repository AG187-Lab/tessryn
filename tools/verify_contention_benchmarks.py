#!/usr/bin/env python3
"""Replay separate contention packets without executing retained Python code."""
from __future__ import annotations
import argparse
from datetime import datetime
import hashlib
import math
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.contention_benchmark_protocol import (SCOPE, CONFIG, NAMES, CHECKS, COMPILER_SOURCES, RUNTIME_FILES,
    PROFILE_FILE, MAX_LOG_BYTES, MAX_PACKET_BYTES, K01_FLAGS, require, digest, regular_bytes, strict_json, read_ref,
    file_ref, canonical, profile, runtime_hashes, expected_command, descriptor_binding)
from tools.build_k03_smp import coff_binding
from tools.k03_smp_trace import parse_transcript as parse_smp
from tools.k03_smp_provenance import committed_sources
from tools.verify_k03_smp import validate_notices
from tools.k01_media import make_disk
from tools.build_kernel import compiler_profile


def fields(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), label + " fields differ")
    return value


def refs(root, rows, expected, *, limit=64 << 20):
    require(type(rows) is list and len(rows) == len(expected)
        and all(type(row) is dict and set(row) == {"path", "sha256", "size_bytes"} for row in rows)
        and {row["path"] for row in rows} == set(expected), "contention retained file coverage differs")
    require(all(type(row["size_bytes"]) is int and 0 <= row["size_bytes"] <= limit for row in rows)
        and sum(row["size_bytes"] for row in rows) <= MAX_PACKET_BYTES, "contention file inventory exceeds budget")
    return {row["path"]: read_ref(root, row, limit) for row in rows}


def quantiles(values):
    values = sorted(values)
    return {"min": values[0], "p50": values[max(0, math.ceil(.5 * len(values)) - 1)],
        "p95": values[max(0, math.ceil(.95 * len(values)) - 1)],
        "p99": values[max(0, math.ceil(.99 * len(values)) - 1)], "max": values[-1], "mean": sum(values) / len(values)}


def parse_transcript(data, returncode, stderr, binding):
    require(type(data) is bytes and 0 < len(data) <= MAX_LOG_BYTES and data.endswith(b"\n")
        and type(returncode) is int and returncode == 33 and type(stderr) is bytes and stderr == b"",
        "contention process/log boundaries failed")
    require(all(byte == 10 or 32 <= byte < 127 for byte in data), "contention transcript is not canonical ASCII")
    lines = data.splitlines()
    positions = [index for index, line in enumerate(lines) if line.startswith(b"TESSRYN_CBENCH_")]
    require(len(positions) == 126 and positions == list(range(positions[0], len(lines))), "contention records missing, extra or interleaved")
    require(positions[0] > 0 and lines[positions[0] - 1] == b"TESSRYN_K03_SMP_PASS cpus=2 ipis=3 retained=all",
        "contention rows must follow the original acknowledged terminal stop")
    original = b"\n".join(lines[:positions[0]]) + b"\n"
    smp = parse_smp("rendezvous", original, returncode, stderr, binding)
    records = []
    for line in lines[positions[0]:]:
        require(b" " in line, "contention marker missing JSON")
        marker, value = line.split(b" ", 1)
        records.append((marker.decode().removeprefix("TESSRYN_CBENCH_"), strict_json(value)))
    require([kind for kind, value in records] == ["BEGIN", "CLOCK", "LAYOUT"] + ["SAMPLE"] * 120 + ["CHECKS", "END", "PASS"], "contention marker order differs")
    require(canonical(records[0][1]) == canonical({"schema_version": 1, "kind": "contention_benchmark", **CONFIG}), "contention begin configuration differs")
    require(canonical(records[1][1]) == canonical({"name": "hpet", "owner": "bsp", "unit": "raw_ticks", "period_fs": 10_000_000,
        "endpoint": "command_to_acquired_peer_completion", "cross_cpu_subtraction": False}), "contention clock semantics differ")
    layout = fields(records[2][1], ("assumed_line_bytes", "separate_bsp", "separate_ap", "false_bsp", "false_ap", "shared", "ping"), "contention layout")
    require(type(layout["assumed_line_bytes"]) is int and layout["assumed_line_bytes"] == 64
        and all(type(value) is int and 0 <= value < 1 << 64 for value in layout.values()), "contention layout value invalid")
    live_line = next(line for line in reversed(lines[:positions[0]]) if line.startswith(b"TESSRYN_K01_LIVE_RANGES "))
    live = dict(part.split(b"=", 1) for part in live_line.split()[1:])
    image_start, image_end = int(live[b"image_start"], 0), int(live[b"image_end"], 0)
    starts = [layout[key] for key in ("separate_bsp", "separate_ap", "false_bsp", "shared", "ping")]
    require(len(set(starts)) == 5 and all(address % 64 == 0 and image_start <= address and address + 64 <= image_end for address in starts)
        and layout["false_ap"] == layout["false_bsp"] + 8, "contention assumed64B layouts alias or escape owned image")
    def value_from(marker, key):
        line = next(line for line in lines[:positions[0]] if line.startswith(marker + b" "))
        return int(dict(part.split(b"=", 1) for part in line.split()[1:])[key], 0)
    lower = value_from(b"TESSRYN_K03_SMP_CLOCK", b"start")
    upper = value_from(b"TESSRYN_K03_SMP_WORK", b"start")
    previous = lower
    summaries = []
    for case, name in enumerate(NAMES):
        elapsed = []
        expected_bsp = 0 if case == 0 else 1024
        expected_ap = 0 if case <= 1 else 1024
        shared = 2048 if case == 4 else 0
        ping = 2048 if case == 5 else 0
        operations = 0 if case == 0 else 1024 if case == 1 else 2048
        unit = "counter_pair" if case == 0 else "coordinated_batch_completion"
        for ordinal in range(20):
            index = ordinal if ordinal < 4 else ordinal - 4
            row = records[3 + case * 20 + ordinal][1]
            fields(row, ("case", "sample_unit", "phase", "sample_index", "generation", "start_ticks", "end_ticks", "elapsed_ticks",
                "operations", "round_trips", "bsp_count", "ap_count", "shared_count", "ping_turn", "checksum"), "contention sample")
            require(row["case"] == name and row["sample_unit"] == unit
                and row["phase"] == ("warmup" if ordinal < 4 else "measured"), "contention sample case/unit/phase differs")
            for key, expected in {"sample_index": index, "generation": case * 20 + ordinal + 1,
                    "operations": operations, "round_trips": 1024 if case == 5 else 0, "bsp_count": expected_bsp,
                    "ap_count": expected_ap, "shared_count": shared, "ping_turn": ping,
                    "checksum": expected_bsp + expected_ap + shared + ping}.items():
                require(type(row[key]) is int and row[key] == expected, "contention sample final count/generation differs")
            require(all(type(row[key]) is int and 0 <= row[key] < 1 << 64 for key in ("start_ticks", "end_ticks", "elapsed_ticks")), "contention timestamp type differs")
            require(previous <= row["start_ticks"] <= row["end_ticks"] <= upper
                and row["elapsed_ticks"] == row["end_ticks"] - row["start_ticks"] < 200_000_000, "contention timestamps regress, overlap or exceed phase bound")
            previous = row["end_ticks"]
            if ordinal >= 4: elapsed.append(row["elapsed_ticks"])
        zeros = elapsed.count(0)
        summaries.append({"case": name, "sample_unit": unit, "sample_count": 16, "operations_per_sample": operations,
            "round_trips_per_sample": 1024 if case == 5 else 0, "raw_elapsed_ticks": quantiles(elapsed),
            "ticks_per_operation": quantiles([n / operations for n in elapsed]) if operations and not zeros else None,
            "ticks_per_round_trip": quantiles([n / 1024 for n in elapsed]) if case == 5 and not zeros else None,
            "quantile_population": "adjacent_counter_read_pairs" if case == 0 else "amortized_round_trip_batch_averages" if case == 5 else "amortized_coordinated_batch_averages",
            "measurement_status": "resolution_limited" if zeros else "observed", "zero_duration_samples": zeros})
    require(canonical(records[-3][1]) == canonical({"checks": CHECKS})
        and canonical(records[-2][1]) == canonical({"measured_samples": 96, "warmup_samples": 24, "warmup_excluded": 24, "retained": "all"})
        and canonical(records[-1][1]) == canonical({"scope": SCOPE, "hardware_qualified": False, "inference_qualified": False}), "contention completion/check scope differs")
    return {"scope": SCOPE, "hardware_qualified": False, "inference_qualified": False,
        "clock": profile()["clock"], "cases": summaries, "samples": 96, "warmup_samples": 24, "warmup_excluded": 24,
        "layout": layout, "bootstrap": smp, "capture_authentication": "unverified_offline",
        "unavailable": ["hardware_latency", "physical_cache_coherence", "actual_cache_line_qualification", "NUMA", "CPL3_SMP_scheduling", "inference_performance"]}


def validate_build(path):
    path = Path(path).absolute(); root = path.parent
    manifest = strict_json(regular_bytes(path, 2 << 20))
    fields(manifest, ("format", "scope", "hardware_qualified", "inference_qualified", "source", "source_files", "runtime_files",
        "retained_sources", "toolchain", "profile", "compile_command", "compile", "smp_binding", "config_binding", "artifacts", "notices"), "contention build")
    require(manifest["format"] == "tessryn-contention-build/v1" and manifest["scope"] == SCOPE
        and manifest["hardware_qualified"] is False and manifest["inference_qualified"] is False, "contention build qualification differs")
    require(type(manifest["source_files"]) is dict and set(manifest["source_files"]) == set(COMPILER_SOURCES)
        and type(manifest["runtime_files"]) is dict and set(manifest["runtime_files"]) == set(RUNTIME_FILES), "contention source closure differs")
    sources = refs(root, manifest["retained_sources"], {"sources/" + n for n in set(COMPILER_SOURCES) | set(RUNTIME_FILES)}, limit=16 << 20)
    for name, sha in {**manifest["source_files"], **manifest["runtime_files"]}.items():
        require(digest(sources["sources/" + name]) == sha, "contention retained source hash differs")
    validate_source(manifest, sources)
    fields(manifest["profile"], ("path", "sha256", "size_bytes"), "contention profile reference")
    profile_data = read_ref(root, manifest["profile"], 2 << 20)
    require(manifest["profile"]["path"] == "profile.json" and profile_data == sources["sources/" + PROFILE_FILE]
        and canonical(strict_json(profile_data)) == canonical(profile()), "contention registered profile differs")
    artifacts = refs(root, manifest["artifacts"], {"BOOTX64.EFI", "kernel.obj", "boot.img"})
    efi, obj, disk = (artifacts[name] for name in ("BOOTX64.EFI", "kernel.obj", "boot.img"))
    require(make_disk(efi) == disk and coff_binding(obj, efi, "rendezvous") == manifest["smp_binding"]
        and descriptor_binding(obj, efi) == manifest["config_binding"], "contention media/config/bootstrap binding differs")
    setup = manifest["toolchain"]["setup"]
    require(canonical(manifest["toolchain"]) == canonical(compiler_profile()["toolchain"]), "contention toolchain differs from checked pinned origin")
    # Expected flags derive from the retained public profile, including exact
    # host linker role, and do not execute a captured compiler or helper.
    checked = {"toolchain": manifest["toolchain"], "linker": ROOT / "build/uefi/lib/rustlib" / setup["host"] / "bin/rust-lld"}
    require(manifest["compile_command"] == expected_command(checked), "contention compiler command differs")
    require(manifest["toolchain"]["rust_flags"] == K01_FLAGS, "contention compiler base flags differ")
    receipt = fields(manifest["compile"], ("status", "returncode", "elapsed_seconds", "stdout", "stderr"), "contention compile receipt")
    require(receipt["status"] == "completed" and type(receipt["returncode"]) is int and receipt["returncode"] == 0
        and type(receipt["elapsed_seconds"]) in (int, float) and math.isfinite(receipt["elapsed_seconds"])
        and 0 <= receipt["elapsed_seconds"] <= 92, "contention compilation did not complete")
    for stream in ("stdout", "stderr"):
        fields(receipt[stream], ("path", "sha256", "size_bytes"), "contention compile log reference")
        require(receipt[stream]["path"] == stream + ".log", "contention compile log name differs")
        data = read_ref(root, receipt[stream], MAX_LOG_BYTES)
        require(str(ROOT).encode() not in data, "contention successful compiler log contains host path")
    validate_notices(root, manifest["notices"], setup)
    return manifest


def validate_source(manifest, retained):
    source = fields(manifest["source"], ("revision", "dirty", "tree_sha256", "snapshot_algorithm"), "contention source")
    require(source["dirty"] is False and source["snapshot_algorithm"] == "git-worktree-v2", "contention source must be clean committed bytes")
    committed = committed_sources(source["revision"])
    digest_tree = hashlib.sha256()
    for name, (mode, data) in sorted(committed.items()):
        digest_tree.update(name.encode() + b"\0" + mode.encode() + b"\0" + digest(data).encode() + b"\0")
    require(digest_tree.hexdigest() == source["tree_sha256"], "contention declared tree differs from committed source")
    for name, sha in {**manifest["source_files"], **manifest["runtime_files"]}.items():
        require(name in committed and digest(committed[name][1]) == sha
            and retained["sources/" + name] == committed[name][1], "contention retained source differs from declared Git revision")
        if name in RUNTIME_FILES:
            require(regular_bytes(ROOT / name, 16 << 20) == committed[name][1], "contention evaluator differs from trusted reviewed checkout")
    for name in ("LICENSE", "NOTICE"):
        row = next((row for row in manifest["notices"] if row.get("path") == "notices/tessryn-" + name), None)
        require(row is not None and name in committed and row["sha256"] == digest(committed[name][1])
            and row["size_bytes"] == len(committed[name][1]), "contention notice differs from committed origin")


def build_files(manifest):
    return ["manifest.json", manifest["profile"]["path"],
        *(row["path"] for row in manifest["retained_sources"]), *(row["path"] for row in manifest["artifacts"]),
        *(row["path"] for row in manifest["notices"]), manifest["compile"]["stdout"]["path"], manifest["compile"]["stderr"]["path"]]


def verify_packet(directory, *, require_result=True):
    root = Path(directory)
    registration_raw = regular_bytes(root / "registration.json", 2 << 20)
    reg = strict_json(registration_raw)
    fields(reg, ("format", "scope", "hardware_qualified", "inference_qualified", "created_at_utc", "capture_origin", "files", "manifest_sha256",
        "runtime_files", "command", "timeout_seconds", "max_log_bytes", "emulator_sha256", "launcher_sha256", "setup"), "contention registration")
    require(reg["format"] == "tessryn-contention-registration/v1" and reg["scope"] == SCOPE
        and reg["hardware_qualified"] is False and reg["inference_qualified"] is False
        and reg["capture_origin"] == "local_runner_claim_unverified_offline", "contention registration scope differs")
    created = datetime.fromisoformat(reg["created_at_utc"].replace("Z", "+00:00"))
    require(created.utcoffset() is not None and created.utcoffset().total_seconds() == 0, "contention registration time not UTC")
    manifest = validate_build(root / "build/manifest.json")
    expected_files = {"build/" + n for n in build_files(manifest)} | {"firmware/code.fd", "firmware/vars.fd", "firmware/NOTICE"}
    retained = refs(root, reg["files"], expected_files)
    require(reg["manifest_sha256"] == digest(retained["build/manifest.json"]) and reg["runtime_files"] == manifest["runtime_files"], "contention registered build/runtime differs")
    require(canonical(reg["setup"]) == canonical(manifest["toolchain"]["setup"])
        and reg["emulator_sha256"] == reg["setup"]["verified_tools"]["qemu"]["sha256"], "contention runtime tools differ")
    for role, name in (("code", "code.fd"), ("vars", "vars.fd"), ("notice", "NOTICE")):
        row = reg["setup"]["firmware"][role]
        data = retained["firmware/" + name]
        require(digest(data) == row["sha256"] and len(data) == row["size_bytes"], "contention firmware binding differs")
    from tools.run_contention_benchmarks import qemu_command
    require(reg["command"] == qemu_command() and type(reg["timeout_seconds"]) in (int, float)
        and math.isfinite(reg["timeout_seconds"]) and 0 < reg["timeout_seconds"] <= 60
        and type(reg["max_log_bytes"]) is int and reg["max_log_bytes"] == MAX_LOG_BYTES
        and reg["launcher_sha256"] == digest(regular_bytes(Path('/usr/bin/env'), 16 << 20)), "contention registered command/limits/launcher differ")
    result = strict_json(regular_bytes(root / "result.json", 2 << 20))
    fields(result, ("format", "status", "reason", "scope", "hardware_qualified", "inference_qualified", "registration_sha256", "execution", "logs", "observations"), "contention result")
    receipt = fields(result["execution"], ("status", "returncode", "elapsed_seconds"), "contention process")
    require(receipt["status"] == "completed" and type(receipt["returncode"]) is int and receipt["returncode"] == 33
        and type(receipt["elapsed_seconds"]) in (int, float) and math.isfinite(receipt["elapsed_seconds"])
        and 0 <= receipt["elapsed_seconds"] <= reg["timeout_seconds"] + 2, "contention capture did not complete")
    logs = refs(root, result["logs"], {"stdout.log", "stderr.log"}, limit=MAX_LOG_BYTES)
    require(sum(map(len, logs.values())) <= MAX_LOG_BYTES and result["registration_sha256"] == digest(registration_raw), "contention capture registration/log budget differs")
    summary = parse_transcript(logs["stdout.log"], receipt["returncode"], logs["stderr.log"], manifest["smp_binding"])
    summary["identity"] = {"source": manifest["source"], "toolchain": manifest["toolchain"],
        "machine_profile": profile()["platform"], "clock_profile": profile()["clock"],
        "artifact_sha256": {row["path"]: row["sha256"] for row in manifest["artifacts"]},
        "compiler_sources_sha256": manifest["source_files"], "runtime_sha256": manifest["runtime_files"]}
    if require_result:
        require(result["format"] == "tessryn-contention-result/v1" and result["status"] == "pass" and result["scope"] == SCOPE
            and result["hardware_qualified"] is False and result["inference_qualified"] is False
            and result["reason"] == "original SMP stop and bounded contention protocol matched"
            and canonical(result["observations"]) == canonical(summary), "contention stored result differs from raw replay")
    expected = expected_files | {"registration.json", "result.json", "stdout.log", "stderr.log"}
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    require(actual == expected and not any(path.is_symlink() for path in root.rglob("*")), "contention packet has extra/missing/aliased files")
    return summary


def packet_files(directory):
    verify_packet(directory)
    root = Path(directory)
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try: result = verify_packet(args.directory)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        parser.exit(1, "contention verification rejected: " + type(error).__name__ + "\n")
    print(canonical(result))
    return 0

if __name__ == "__main__": raise SystemExit(main())
