#!/usr/bin/env python3
"""Execute the owned-memory core on the host and compile its freestanding target."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.g03.process import run_bounded
from tools import setup_k02_toolchain as setup

KIND = "k02_owned_memory_core"
UNAVAILABLE = ["native_authenticated_dispatch", "CPU_address_space_isolation",
               "page_table_installation_and_TLB_teardown", "hardware_fault_traces",
               "SMP_synchronization", "DMA_and_device_quiescence", "native_runtime_integration"]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def portable(message: str, work: Path | None = None) -> str:
    if work is not None:
        message = message.replace(str(work), "<work>")
    message = message.replace(str(ROOT), "<repo>")
    return re.sub(r"(?:/Users/|/home/|/private/var/|/tmp/)[^\s\"']+", "<host-path>", message)


def execute(command: list[str], *, timeout: int = 60, work: Path | None = None) -> str:
    result = run_bounded(command, ROOT, timeout, 262144)
    output = portable((result.stdout + result.stderr).decode(errors="replace"), work)
    if result.status != "completed" or result.returncode != 0:
        raise ValueError(f"{Path(command[0]).name}: {result.status}/{result.returncode}: {output[:4000]}")
    return output


def test_count(log: str) -> int:
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                           r"(\d+) measured; (\d+) filtered out;", log)
    if len(summaries) != 1:
        raise ValueError("host test execution did not produce one successful summary")
    passed, *excluded = map(int, summaries[0])
    if passed == 0 or any(excluded):
        raise ValueError("host test execution was empty, failed or incomplete")
    return passed


def sources() -> dict[str, str]:
    paths = sorted(list((ROOT / "kernel-core").glob("*.rs")) +
                   list((ROOT / "tests").glob("test_k02*.py")) + [
                       ROOT / "interfaces/abi-v1/native.rs", ROOT / "toolchain.lock.json",
                       ROOT / "planning/k02-toolchain.lock.json", ROOT / "tools/setup_toolchain.py",
                       ROOT / "tools/setup_k02_toolchain.py", ROOT / "tools/g03/process.py",
                       ROOT / "tools/check_k02_core.py", ROOT / ".github/workflows/k02-core.yml"])
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in paths}


def verify(output: Path) -> dict:
    identity = setup.verified_setup()
    compiler = setup.PREFIX / "bin/rustc"
    inputs = sources()
    revision = execute(["/usr/bin/git", "rev-parse", "HEAD"]).strip()
    dirty = bool(execute(["/usr/bin/git", "status", "--porcelain"]).strip())
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="k02-check-", dir=output.parent) as temporary:
        work = Path(temporary)
        common = [str(compiler), "--edition=2024", "-D", "warnings", "-C", "opt-level=1",
                  "--remap-path-prefix", f"{ROOT}=.", "--remap-path-prefix", f"{work}=<work>"]
        host_binary = work / "k02-tests"
        execute(common + ["--test", "--crate-name", "tessryn_memory_tests", "kernel-core/lib.rs",
                          "-o", str(host_binary)], work=work)
        log = execute([str(host_binary), "--test-threads=1"], work=work)
        count = test_count(log)
        target = "x86_64-unknown-none"
        artifacts = []
        # Two compilations from identical source catch nondeterministic target outputs.
        # Keep the output name identical: rustc embeds archive-member names
        # derived from -o, so different filenames are different build inputs.
        for _ in range(2):
            destination = work / "libtessryn_memory.rlib"
            execute(common + ["--crate-type=rlib", "--crate-name", "tessryn_memory",
                              "--target", target, "kernel-core/lib.rs", "-o", str(destination)], work=work)
            artifacts.append(digest(destination))
        if artifacts[0] != artifacts[1]:
            raise ValueError("repeated freestanding core artifacts differ")
        if (inputs != sources() or identity != setup.verified_setup() or
                revision != execute(["/usr/bin/git", "rev-parse", "HEAD"]).strip()):
            raise ValueError("source or toolchain changed during verification")
        retained = output.parent / "libtessryn_memory.rlib"
        shutil.copyfile(work / "libtessryn_memory.rlib", retained)
        result = {
            "schema_version": 1, "kind": KIND, "status": "passed",
            "scope": "host_execution_of_original_no_std_policy_and_freestanding_compilation",
            "source_revision": revision, "source_dirty": dirty, "sources": inputs,
            "toolchain": identity,
            "compiled_checks": ["same_Rust_core_host_tests", "freestanding_x86_64_no_std",
                                "identical_repeated_freestanding_artifact"],
            "host_tests": {"status": "passed", "passed": count, "log": log},
            "artifacts": {"libtessryn_memory.rlib": {"sha256": artifacts[0], "target": target}},
            "unavailable": UNAVAILABLE,
        }
    return result


def write_result(output: Path, value: dict) -> None:
    staged = output.with_suffix(output.suffix + ".tmp")
    staged.write_text(json.dumps(value, indent=2) + "\n")
    staged.replace(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/k02/result.json")
    args = parser.parse_args(argv)
    output = args.output.resolve()
    # This adjacent filename belongs to the retained library. A result receipt
    # must never replace the binary whose digest it reports.
    if output.name == "libtessryn_memory.rlib":
        print("K02 result path uses the reserved library filename", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    write_result(output, {"schema_version": 1, "kind": KIND, "status": "incomplete"})
    try:
        result = verify(output)
        write_result(output, result)
        print(f"K02 core passed: {result['host_tests']['passed']} host tests; repeatable freestanding artifact")
        return 0
    except (OSError, ValueError, StopIteration, subprocess.SubprocessError) as error:
        write_result(output, {"schema_version": 1, "kind": KIND, "status": "failed",
                              "reason": portable(str(error))[:4000], "unavailable": UNAVAILABLE})
        print("K02 core verification failed; see portable result receipt", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
