#!/usr/bin/env python3
"""Retain original K03, adapter and timer-model checks with pinned host tools."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k03_timer_protocol import require, digest, regular_bytes, file_ref, write_json, fresh_output, retain_private_error, SCHEDULER_SHA256
from tools.build_fixture import source_identity
from tools.g03.process import run_bounded
from tools.setup_k02_toolchain import verified_setup, PREFIX

SOURCES = ("scheduler-core/lib.rs", "scheduler-core/tests.rs", "kernel/preempt_policy.rs", "tests/preempt_policy_host.rs",
           "kernel/preempt_timer.rs", "tests/preempt_timer_host.rs", "kernel/paging.rs", "kernel/k02_paging.rs", "kernel/k02_paging_tests.rs")
EXPECTED_TESTS = {"scheduler": 42, "adapter": 17, "driver": 31}
FORMAT = "tessryn-k03-timer-host/v1"
SCOPE = "host execution of original scheduler policy, adapter and timer models; native IRQ/clock qualification unavailable"


def commands(compiler, snapshot, out):
    compiler, snapshot, out = str(compiler), str(snapshot), Path(out)
    common = [compiler, "--edition=2024", "-Dwarnings", "-Copt-level=1",
              f"--remap-path-prefix={snapshot}=tessryn", f"--remap-path-prefix={out}=timer-host"]
    library = out / "libtessryn_scheduler.rlib"
    result = [("scheduler-library", [*common, "scheduler-core/lib.rs", "--crate-name=tessryn_scheduler", "--crate-type=rlib", "-o", str(library)])]
    for role, source in (("scheduler", "scheduler-core/lib.rs"), ("adapter", "tests/preempt_policy_host.rs"), ("driver", "tests/preempt_timer_host.rs")):
        binary = out / (role + "-tests")
        result.append((role + "-build", [*common, source, "--test", *(["--extern", "tessryn_scheduler=" + str(library)] if role == "adapter" else []), "-o", str(binary)]))
        result.append((role + "-tests", [str(binary), "--test-threads=1"]))
    return result


def normalized_commands():
    return dict(commands("rust-toolchain/bin/rustc", "tessryn", "timer-host"))


def check(out):
    out = fresh_output(out)
    receipts = []
    try:
        source, setup = source_identity(), verified_setup()
        retained = {name: regular_bytes(ROOT / name, 16 << 20) for name in SOURCES}
        require(digest(retained["scheduler-core/lib.rs"]) == SCHEDULER_SHA256, "K03 reference policy changed")
        counts = {}
        with tempfile.TemporaryDirectory(prefix="source-", dir=out) as temporary:
            snapshot = Path(temporary)
            for name, data in retained.items():
                path = snapshot / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o400)
            for role, command in commands(PREFIX / "bin/rustc", snapshot, out):
                execution = run_bounded(command, snapshot, 90, 1 << 20)
                logs = []
                for stream in ("stdout", "stderr"):
                    path = out / (role + "-" + stream + ".log")
                    path.write_bytes(getattr(execution, stream))
                    logs.append(file_ref(out, path))
                normalized = [arg.replace(str(snapshot), "tessryn").replace(str(PREFIX), "rust-toolchain").replace(str(out), "timer-host") for arg in command]
                receipts.append({"role": role, "status": execution.status, "returncode": execution.returncode,
                    "elapsed_seconds": execution.elapsed_seconds, "stdout": logs[0], "stderr": logs[1], "command": normalized})
                require(execution.status == "completed" and execution.returncode == 0, "K03 host check failed; original diagnostics retained privately")
                require(all(str(ROOT).encode() not in getattr(execution, stream) for stream in ("stdout", "stderr")), "successful K03 host diagnostics contain local paths")
                if role.endswith("-tests"):
                    suite = role.removesuffix("-tests")
                    matches = re.findall(rb"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", execution.stdout)
                    require(matches == [str(EXPECTED_TESTS[suite]).encode()], "K03 host test count differs")
                    counts[suite] = EXPECTED_TESTS[suite]
            require(all(regular_bytes(snapshot / name, 16 << 20) == data for name, data in retained.items()), "K03 host snapshot changed")
        require(verified_setup() == setup and source_identity() == source
                and all(regular_bytes(ROOT / name, 16 << 20) == data for name, data in retained.items()), "K03 host inputs changed during tests")
        result = {"format": FORMAT, "status": "pass", "scope": SCOPE, "source": source, "toolchain": setup,
                  "tests": counts, "sources": {name: digest(data) for name, data in retained.items()}, "receipts": receipts}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        retain_private_error(out, error)
        result = {"format": FORMAT, "status": "fail", "reason": type(error).__name__, "receipts": receipts}
    write_json(out / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(args.out)
    except (OSError, ValueError) as error:
        parser.exit(1, "K03 timer host setup rejected: " + type(error).__name__ + "\n")
    print("K03 timer host checks " + result["status"] + "; native IRQ/clock proof unavailable")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
