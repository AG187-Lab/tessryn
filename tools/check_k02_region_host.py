#!/usr/bin/env python3
"""Retain pinned host policy tests; no CPU/MMU execution claim is made."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k02_region_protocol import require, digest, regular_bytes, file_ref, write_json, fresh_output, retain_private_error
from tools.build_fixture import source_identity
from tools.g03.process import run_bounded
from tools.setup_k02_toolchain import verified_setup, PREFIX

SOURCES = ("interfaces/abi-v1/native.rs", "kernel-core/boot_inventory.rs", "kernel-core/capabilities.rs",
    "kernel-core/frames.rs", "kernel-core/lib.rs", "kernel/region_service.rs", "tests/region_service_host.rs")


def check(out):
    out = fresh_output(out)
    receipts = []
    try:
        source, setup = source_identity(), verified_setup()
        retained = {name: regular_bytes(ROOT / name, 16 << 20) for name in SOURCES}
        with tempfile.TemporaryDirectory(prefix="source-", dir=out) as temporary:
            snapshot = Path(temporary)
            for name, data in retained.items():
                path = snapshot / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o400)
            compiler = PREFIX / "bin/rustc"
            common = [str(compiler), "--edition=2024", "-Dwarnings", "-Copt-level=1",
                f"--remap-path-prefix={snapshot}=tessryn", f"--remap-path-prefix={out}=region-host"]
            library, binary = out / "libtessryn_owned_memory.rlib", out / "region-tests"
            commands = [("library", [*common, "kernel-core/lib.rs", "--crate-name=tessryn_owned_memory", "--crate-type=rlib", "-o", str(library)]),
                ("test-build", [*common, "tests/region_service_host.rs", "--test", "--extern", f"tessryn_owned_memory={library}", "-o", str(binary)]),
                ("tests", [str(binary), "--test-threads=1"])]
            test_stdout = b""
            for role, command in commands:
                execution = run_bounded(command, snapshot, 90, 1 << 20)
                logs = []
                for stream in ("stdout", "stderr"):
                    path = out / (role + "-" + stream + ".log")
                    path.write_bytes(getattr(execution, stream))
                    logs.append(file_ref(out, path))
                receipts.append({"role": role, "status": execution.status, "returncode": execution.returncode,
                    "elapsed_seconds": execution.elapsed_seconds, "stdout": logs[0], "stderr": logs[1],
                    "command": [arg.replace(str(snapshot), "tessryn").replace(str(PREFIX), "rust-toolchain").replace(str(out), "region-host") for arg in command]})
                require(execution.status == "completed" and execution.returncode == 0, "region host check failed; raw logs retained privately")
                require(all(str(ROOT).encode() not in getattr(execution, stream)
                            for stream in ("stdout", "stderr")), "region successful host diagnostics contain local paths")
                if role == "tests":
                    test_stdout = execution.stdout
            matches = re.findall(rb"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", test_stdout)
            require(matches == [b"21"], "region host test count/coverage differs")
            require(all(regular_bytes(snapshot / name, 16 << 20) == data for name, data in retained.items()), "region host snapshot changed")
        require(verified_setup() == setup and source_identity() == source
                and all(regular_bytes(ROOT / name, 16 << 20) == data for name, data in retained.items()), "region host inputs changed during test")
        result = {"format": "tessryn-k02-region-host/v1", "status": "pass", "scope": "host policy model; native CPU/TLB execution unqualified",
            "source": source, "toolchain": setup, "tests": 21, "sources": {name: digest(data) for name, data in retained.items()}, "receipts": receipts}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        retain_private_error(out, error)
        result = {"format": "tessryn-k02-region-host/v1", "status": "fail", "reason": type(error).__name__, "receipts": receipts}
    write_json(out / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(args.out)
    except (OSError, ValueError):
        parser.exit(1, "Region host check setup rejected\n")
    print("Region host policy checks " + result["status"] + "; CPU enforcement unqualified")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
