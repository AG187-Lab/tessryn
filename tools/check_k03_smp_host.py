#!/usr/bin/env python3
"""Retain execution of the actual bounded ACPI parser with pinned host rustc."""
from __future__ import annotations
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from tools.k03_smp_protocol import require, digest, regular_bytes, file_ref, fresh_output, retain_private_error, write_json
from tools.build_fixture import source_identity
from tools.g03.process import run_bounded
from tools.setup_k02_toolchain import PREFIX, verified_setup
SOURCES = ("kernel/smp_acpi.rs", "tests/k03_smp_acpi.rs")
EXPECTED_TESTS = 26
FORMAT = "tessryn-k03-smp-host/v1"
SCOPE = "host ACPI parser checks; AP startup and interrupt execution require original guest evidence"


def commands(compiler, snapshot, out):
    return {"build": [str(compiler), "--edition=2024", "-Dwarnings", "--test", "tests/k03_smp_acpi.rs",
        "--remap-path-prefix=" + str(snapshot) + "=tessryn", "--remap-path-prefix=" + str(out) + "=smp-host", "-o", str(Path(out) / "tests")],
        "tests": [str(Path(out) / "tests"), "--test-threads=1"]}


def normalized_commands(): return commands("rust-toolchain/bin/rustc", "tessryn", "smp-host")


def check(out):
    out = fresh_output(out); receipts = []
    try:
        source, setup = source_identity(), verified_setup()
        files = {n: regular_bytes(ROOT / n, 16 << 20) for n in SOURCES}
        with tempfile.TemporaryDirectory(prefix="source-", dir=out) as temporary:
            snapshot = Path(temporary)
            for n, data in files.items():
                path = snapshot / n; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(0o400)
            for role, command in commands(PREFIX / "bin/rustc", snapshot, out).items():
                execution = run_bounded(command, snapshot, 90, 1 << 20)
                row = {"role": role, "status": execution.status, "returncode": execution.returncode, "elapsed_seconds": execution.elapsed_seconds,
                    "command": [a.replace(str(snapshot), "tessryn").replace(str(PREFIX), "rust-toolchain").replace(str(out), "smp-host") for a in command]}
                for stream in ("stdout", "stderr"):
                    path = out / (role + "-" + stream + ".log"); path.write_bytes(getattr(execution, stream)); row[stream] = file_ref(out, path)
                receipts.append(row)
                require(execution.status == "completed" and execution.returncode == 0, "SMP host parser checks failed; diagnostics retained privately")
                require(all(str(ROOT).encode() not in getattr(execution, s) for s in ("stdout", "stderr")), "SMP host successful logs contain local paths")
                if role == "tests":
                    require(EXPECTED_TESTS > 0 and re.findall(rb"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", execution.stdout) == [str(EXPECTED_TESTS).encode()], "SMP parser host test count differs")
            require(all(regular_bytes(snapshot / n, 16 << 20) == data for n, data in files.items()), "SMP host source snapshot changed")
        require(source_identity() == source and verified_setup() == setup and all(regular_bytes(ROOT / n, 16 << 20) == data for n, data in files.items()), "SMP host inputs changed")
        result = {"format": FORMAT, "status": "pass", "scope": SCOPE, "source": source, "toolchain": setup,
            "tests": EXPECTED_TESTS, "sources": {n: digest(d) for n, d in files.items()}, "receipts": receipts}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        retain_private_error(out, error); result = {"format": FORMAT, "status": "fail", "reason": type(error).__name__, "receipts": receipts}
    write_json(out / "result.json", result); return result


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("--out", type=Path, required=True); args = p.parse_args()
    try: result = check(args.out)
    except (OSError, ValueError, subprocess.SubprocessError) as error: p.exit(1, "SMP host setup rejected: " + type(error).__name__ + "\n")
    print("SMP parser host checks " + result["status"])
    return 0 if result["status"] == "pass" else 1
if __name__ == "__main__": raise SystemExit(main())
