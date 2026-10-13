#!/usr/bin/env python3
"""Execute scheduler policy tests on the host and compile its freestanding core."""

from __future__ import annotations

import argparse
import builtins
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]

KIND = "k03_scheduler_policy_core"
ARTIFACT = "libtessryn_scheduler.rlib"
TARGET = "x86_64-unknown-none"
UNAVAILABLE = ["native_authenticated_scheduler_dispatch", "native_CPU_isolation",
               "hardware_monotonic_clock_and_timer_interrupts", "timer_driven_CPU_preemption",
               "native_multi_core_execution_and_SMP_synchronization", "native_runtime_integration",
               "native_cross_core_traces_and_timing_measurements",
               "GPU_and_memory_bandwidth_preemption"]
DEPENDENCIES = ("tools/check_k03_core.py", "tests/test_k03_tooling.py",
                ".github/workflows/k03-core.yml", "tools/setup_k02_toolchain.py",
                "tools/setup_toolchain.py", "tools/g03/__init__.py", "tools/g03/process.py",
                "toolchain.lock.json", "planning/k02-toolchain.lock.json")
RUNTIME_PATHS = ("tools/check_k03_core.py", "tools/setup_toolchain.py", "tools/setup_k02_toolchain.py",
                 "tools/g03/__init__.py", "tools/g03/process.py")
MAX_SOURCE_BYTES = 1_048_576
MAX_SOURCE_FILES = 64


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_source(path: Path) -> bytes:
    """Retain bounded regular bytes once, without following source symlinks."""
    if not path.is_relative_to(ROOT) or any(
            parent.is_symlink() for parent in path.parents if parent.is_relative_to(ROOT)):
        raise ValueError("verification sources must be regular files inside this checkout")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("bounded source reads are unavailable")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
            raise ValueError("verification source must be a bounded regular file")
        value = stream.read(MAX_SOURCE_BYTES + 1)
    if len(value) > MAX_SOURCE_BYTES:
        raise ValueError("verification source byte limit exceeded")
    return value


def hashes(retained: dict[str, bytes]) -> dict[str, str]:
    return {name: hashlib.sha256(value).hexdigest() for name, value in retained.items()}


def fresh_runtime(retained: dict[str, bytes]) -> tuple[ModuleType, ModuleType]:
    """Execute the retained dependency bytes, bypassing import caches and pyc."""
    namespace = f"_tessryn_k03_runtime_{id(retained)}"
    tools = ModuleType(namespace)
    paths = {"setup_toolchain": "tools/setup_toolchain.py", "setup_k02_toolchain": "tools/setup_k02_toolchain.py",
             "g03": "tools/g03/__init__.py", "g03.process": "tools/g03/process.py"}
    modules = {}
    for name, path in paths.items():
        module = ModuleType(namespace + "." + name)
        module.__file__ = str(ROOT / path)
        module.__package__ = "tools.g03" if name.startswith("g03") else "tools"
        modules[name] = module
        # dataclasses resolves its defining module through sys.modules. These
        # private names never replace or reuse a caller's imported tools modules.
        sys.modules[module.__name__] = module
    tools.setup_toolchain = modules["setup_toolchain"]
    tools.setup_k02_toolchain = modules["setup_k02_toolchain"]
    tools.g03 = modules["g03"]
    tools.g03.process = modules["g03.process"]

    def runtime_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name == "tools" or name.startswith("tools."):
            allowed = {"tools": tools, "tools.setup_toolchain": tools.setup_toolchain,
                       "tools.setup_k02_toolchain": tools.setup_k02_toolchain,
                       "tools.g03": tools.g03, "tools.g03.process": tools.g03.process}
            if level or name not in allowed or any(not hasattr(allowed[name], item) for item in fromlist):
                raise ValueError("unbound tooling dependency import")
            return allowed[name] if fromlist else tools
        return builtins.__import__(name, globals, locals, fromlist, level)

    try:
        for name in ("setup_toolchain", "g03", "g03.process", "setup_k02_toolchain"):
            module = modules[name]
            module.__dict__["__builtins__"] = {**vars(builtins), "__import__": runtime_import}
            exec(compile(retained[paths[name]], module.__file__, "exec"), module.__dict__)
    except BaseException:
        for module in modules.values():
            sys.modules.pop(module.__name__, None)
        raise
    return tools.setup_k02_toolchain, tools.g03.process


try:
    LOADED_BYTES = {name: read_source(ROOT / name) for name in RUNTIME_PATHS}
    LOADED_TOOLING = hashes(LOADED_BYTES)
    setup, process = fresh_runtime(LOADED_BYTES)
except Exception:
    # Defer a source/read/exec failure to main so an old receipt and artifact
    # are invalidated before this attempt reports its failure.
    LOADED_TOOLING = None
    setup = process = None


def run_bounded(command: list[str], cwd: Path, timeout: int, limit: int):
    if process is None:
        raise ValueError("verification runtime source is unavailable")
    return process.run_bounded(command, cwd, timeout, limit)


def portable(message: str, work: Path | None = None) -> str:
    if work is not None:
        message = message.replace(str(work), "<work>")
    message = message.replace(str(ROOT), "<repo>")
    return re.sub(r"(?:/Users/|/home/|/private/var/|/var/folders/|/var/tmp/|/private/tmp/|/tmp/)[^\s\"']+",
                  "<host-path>", message)


def execute(command: list[str], *, timeout: int = 60, work: Path | None = None) -> str:
    result = run_bounded(command, ROOT, timeout, 262144)
    output = portable((result.stdout + result.stderr).decode(errors="replace"), work)
    if result.status != "completed" or result.returncode != 0:
        raise ValueError(f"{Path(command[0]).name}: {result.status}/{result.returncode}: {output[:4000]}")
    return output


def test_count(log: str) -> int:
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                           r"(\d+) measured; (\d+) filtered out;", log)
    if len(summaries) != 1 or log.count("test result:") != 1:
        raise ValueError("host test execution did not produce one successful summary")
    passed, *excluded = map(int, summaries[0])
    if passed == 0 or any(excluded):
        raise ValueError("host test execution was empty, failed or incomplete")
    return passed


def source_bytes() -> dict[str, bytes]:
    # Include every Rust module in this standalone core and the exact Python/CI
    # dependency closure. K03 reuses the existing pinned K02 setup unchanged.
    core = ROOT / "scheduler-core"
    paths = sorted(set(core.rglob("*.rs")) | {core / "lib.rs"} |
                   {ROOT / name for name in DEPENDENCIES})
    if len(paths) > MAX_SOURCE_FILES:
        raise ValueError("verification source file limit exceeded")
    return {path.relative_to(ROOT).as_posix(): read_source(path) for path in paths}


def sources() -> dict[str, str]:
    return hashes(source_bytes())


def git_binding() -> tuple[str, str]:
    revision = execute(["/usr/bin/git", "rev-parse", "HEAD"]).strip()
    status = execute(["/usr/bin/git", "status", "--porcelain"]).strip()
    return revision, status


def verify(output: Path) -> dict:
    retained = source_bytes()
    inputs = hashes(retained)
    if LOADED_TOOLING is None or any(inputs.get(name) != value for name, value in LOADED_TOOLING.items()):
        raise ValueError("verification tooling source changed since initialization")
    identity = setup.verified_setup()
    compiler = setup.PREFIX / "bin/rustc"
    revision, status = git_binding()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="k03-check-", dir=output.parent) as temporary:
        work = Path(temporary)
        snapshot = work / "sources"
        for name, value in retained.items():
            if name.startswith("scheduler-core/") and name.endswith(".rs"):
                path = snapshot / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
                path.chmod(0o444)
        source = str(snapshot / "scheduler-core/lib.rs")
        common = [str(compiler), "--edition=2024", "-D", "warnings", "-C", "opt-level=1",
                  "--remap-path-prefix", f"{ROOT}=.", "--remap-path-prefix", f"{work}=<work>",
                  "--remap-path-prefix", f"{snapshot}=."]
        host_binary = work / "k03-tests"
        execute(common + ["--test", "--crate-name", "tessryn_scheduler_tests", source,
                          "-o", str(host_binary)], work=work)
        log = execute([str(host_binary), "--test-threads=1"], work=work)
        count = test_count(log)
        artifacts = []
        # Archive member names depend on the output filename: repeat the exact
        # build inputs, including the destination, to check reproducibility.
        for _ in range(2):
            destination = work / ARTIFACT
            execute(common + ["--crate-type=rlib", "--crate-name", "tessryn_scheduler",
                              "--target", TARGET, source, "-o", str(destination)], work=work)
            artifacts.append(digest(destination))
        if artifacts[0] != artifacts[1]:
            raise ValueError("repeated freestanding scheduler artifacts differ")
        if (inputs != sources() or identity != setup.verified_setup() or
                (revision, status) != git_binding()):
            raise ValueError("source, checkout state or toolchain changed during verification")
        retain_artifact(work / ARTIFACT, output.parent / ARTIFACT)
        result = {
            "schema_version": 1, "kind": KIND, "status": "passed",
            "scope": "host_execution_of_original_no_std_scheduler_policy_and_freestanding_compilation",
            "source_revision": revision, "source_dirty": bool(status), "sources": inputs,
            "toolchain": identity,
            "compiled_checks": ["same_Rust_scheduler_core_host_tests", "freestanding_x86_64_no_std",
                                "identical_repeated_freestanding_artifact"],
            "host_tests": {"status": "passed", "passed": count, "log": log},
            "artifacts": {ARTIFACT: {"sha256": artifacts[0], "target": TARGET}},
            "unavailable": UNAVAILABLE,
        }
    return result


def retain_artifact(source: Path, destination: Path) -> None:
    # Replacement removes an old destination symlink without following it.
    source.replace(destination)


def write_result(output: Path, value: dict) -> None:
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".k03-result-", suffix=".tmp",
                                         dir=output.parent, delete=False) as stream:
            staged = Path(stream.name)
            stream.write(json.dumps(value, indent=2) + "\n")
        staged.replace(output)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/k03/result.json")
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if ARTIFACT in (args.output.name, output.name):
        print("K03 result path uses the reserved library filename", file=sys.stderr)
        return 1
    artifact = output.parent / ARTIFACT
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        write_result(output, {"schema_version": 1, "kind": KIND, "status": "incomplete",
                              "unavailable": UNAVAILABLE})
        # Invalidate a previous artifact before any fallible verification step.
        artifact.unlink(missing_ok=True)
        result = verify(output)
        write_result(output, result)
        print(f"K03 scheduler policy passed: {result['host_tests']['passed']} host tests; repeatable freestanding artifact")
        return 0
    except BaseException as error:
        try:
            artifact.unlink(missing_ok=True)
        except OSError as cleanup_error:
            if not isinstance(error, (OSError, ValueError, StopIteration, subprocess.SubprocessError)):
                raise error from cleanup_error
            error = ValueError(f"{error}; artifact cleanup failed: {cleanup_error}")
        if not isinstance(error, (OSError, ValueError, StopIteration, subprocess.SubprocessError)):
            raise
        try:
            write_result(output, {"schema_version": 1, "kind": KIND, "status": "failed",
                                  "reason": portable(str(error))[:4000], "unavailable": UNAVAILABLE})
        except OSError:
            print("K03 result receipt could not be written", file=sys.stderr)
        print("K03 core verification failed; see portable result receipt", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
