#!/usr/bin/env python3
"""Run the original K02 policy, native adapter and mapper as host tests.

Synthetic physical addresses and host buffers cannot qualify CPU enforcement.
The separate native builder, emulator runner and verifier provide that evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import setup_k02_toolchain as setup
from tools.check_k02_core import digest, execute, portable, test_count, write_result
from tools.build_fixture import source_identity

SCOPE = "host tests of original ownership policy, native adapter and pure page-table mapper; CPU enforcement unqualified"
SUITES = (("core", "kernel-core/lib.rs", 57),
          ("paging", "tests/k02_paging_host.rs", 14),
          ("adapter", "kernel/k02_memory_host_tests.rs", 6))


def sources() -> dict[str, str]:
    paths = [*sorted((ROOT / "kernel-core").glob("*.rs")),
             *[ROOT / name for name in (
                 "interfaces/abi-v1/native.rs", "kernel/paging.rs",
                 "kernel/k02_paging.rs", "kernel/k02_paging_tests.rs",
                 "tests/k02_paging_host.rs", "kernel/k02_memory.rs",
                 "kernel/k02_memory_tests.rs", "kernel/k02_memory_host_tests.rs",
                 "toolchain.lock.json", "planning/k02-toolchain.lock.json",
                 "tools/setup_toolchain.py", "tools/setup_k02_toolchain.py",
                 "tools/check_k02_core.py", "tools/g03/process.py",
                 "tools/build_fixture.py", "tools/check_k02_native_host.py",
                 ".github/workflows/k02-native.yml")]]
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in paths}


def verify(out: Path) -> dict:
    identity = setup.verified_setup()
    inputs = sources()
    source = source_identity()
    compiler = setup.PREFIX / "bin/rustc"
    common = [str(compiler), "--edition=2024", "-D", "warnings", "-C", "opt-level=1",
              "--remap-path-prefix", f"{ROOT}=tessryn",
              "--remap-path-prefix", f"{out}=k02-host"]
    library = out / "libtessryn_owned_memory.rlib"
    commands = {}

    def run(name: str, command: list[str]) -> str:
        commands[name] = [argument.replace(str(setup.PREFIX), "rust-toolchain")
                         .replace(str(out), "k02-host").replace(str(ROOT), "tessryn")
                         for argument in command]
        log = execute(command, work=out)
        (out / (name + ".log")).write_text(log)
        return log

    run("library-build", [*common, "--crate-type=rlib", "--crate-name=tessryn_owned_memory",
                          "kernel-core/lib.rs", "-o", str(library)])
    tests = {}
    for name, fixture, expected_count in SUITES:
        binary = out / (name + "-tests")
        command = [*common, "--test", fixture, "-o", str(binary)]
        if name == "adapter":
            command += ["--extern", f"tessryn_owned_memory={library}"]
        run(name + "-build", command)
        log = run(name + "-tests", [str(binary), "--test-threads=1"])
        count = test_count(log)
        if count != expected_count:
            raise ValueError("native host suite test count changed")
        tests[name] = {"passed": count, "failed": 0, "ignored": 0,
                       "log": name + "-tests.log"}
    if inputs != sources() or identity != setup.verified_setup() or source != source_identity():
        raise ValueError("source or checked host toolchain changed during verification")
    return {"schema_version": 1, "kind": "tessryn_k02_native_host_tests", "status": "passed",
            "scope": SCOPE, "source": source, "sources": inputs, "toolchain": identity,
            "commands": commands, "tests": tests,
            "logs": [{"path": path.name, "sha256": digest(path), "size_bytes": path.stat().st_size}
                     for path in sorted(out.glob("*.log"))]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.absolute()
    # Each invocation owns a fresh ignored directory. It never replaces an old
    # test result, compiler product or path through a symbolic link.
    if not out.is_relative_to(ROOT / "build") or ".." in out.parts:
        parser.exit(1, "K02 host output must remain in ignored build/\n")
    for parent in (out, *out.parents):
        if parent == ROOT:
            break
        if parent.is_symlink():
            parser.exit(1, "K02 host output must not traverse symbolic links\n")
    created = False
    try:
        out.mkdir(parents=True, exist_ok=False)
        created = True
        write_result(out / "result.json", {"schema_version": 1, "status": "incomplete", "scope": SCOPE})
        result = verify(out)
        write_result(out / "result.json", result)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        if created:
            write_result(out / "result.json", {"schema_version": 1, "status": "failed", "scope": SCOPE,
                                              "reason": portable(str(error), out)[:4000]})
        print("K02 native host checks failed; inspect the scoped result", file=sys.stderr)
        return 1
    print("K02 native host checks passed: 57 core, 14 mapper, 6 adapter; CPU enforcement unqualified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
