#!/usr/bin/env python3
"""Execute only the declared G03 ROM fixtures using a fixed, bounded QEMU profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import tempfile

from build_fixture import inspect_elf_bytes
from fixtures.rom import make_rom
from g03.evidence import load_json, parse_json, registration_digest, validate_registration, validate_result
from g03.process import run_bounded


ROOT = Path(__file__).resolve().parents[1]
MARKER = b"TESSRYN_G03_FIXTURE_PASS"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def evaluator_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted([Path(__file__), ROOT / "tools/verify_fixture.py", ROOT / "tools/build_fixture.py", ROOT / "tools/setup_toolchain.py",
                        ROOT / "fixtures/rom.py", ROOT / "toolchain.lock.json",
                        *Path(__file__).parent.joinpath("g03").glob("*.py"), *ROOT.joinpath("evidence").glob("*schema*.json")]):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def regular_bytes(path: Path) -> bytes:
    # Check the open descriptor, not a path which could change between stat/read.
    # O_NONBLOCK also avoids hanging if an input is replaced with a FIFO.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 256 * 1024 * 1024:
            raise ValueError("input must be a regular file of at most 256 MiB")
        data = stream.read(256 * 1024 * 1024 + 1)
        if len(data) > 256 * 1024 * 1024:
            raise ValueError("input exceeded 256 MiB while reading")
        return data


def validate_manifest(manifest: dict) -> None:
    """Require the complete, public fixture provenance contract before execution.

    This checks declared identities and pinned sources; it does not authenticate
    a candidate's source checkout or substitute for independently owned builds.
    """
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    def object_keys(value: object, keys: set[str], name: str, optional: set[str] = frozenset()) -> dict:
        require(isinstance(value, dict) and keys <= set(value) <= keys | optional,
                f"incomplete or unsupported {name}")
        return value

    def digest(value: object, name: str) -> None:
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                f"invalid {name} SHA-256")

    def text(value: object, name: str) -> None:
        require(isinstance(value, str) and bool(value.strip()) and "\0" not in value,
                f"invalid {name} text")
        require(not any(prefix in value for prefix in ("/Users/", "/home/", "/private/", "/tmp/"))
                and re.search(r"(?:^|[\s=(])(?:/|[A-Za-z]:[\\/]|\\\\)", value) is None,
                f"{name} exposes a local host path")

    def public(value: object) -> None:
        # Iterate so untrusted nesting never consumes the Python call stack.
        pending = [value]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
            elif isinstance(item, str):
                text(item, "manifest")

    object_keys(manifest, {"schema_version", "artifact_type", "source", "toolchain", "components",
                           "artifacts", "binary_validation", "capabilities"}, "fixture manifest")
    public(manifest)
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
            and manifest["artifact_type"] == "test_fixture", "only version 1 fixture manifests are executable")
    source = object_keys(manifest["source"], {"revision", "dirty", "tree_sha256", "snapshot_algorithm"}, "source identity")
    require(re.fullmatch(r"[0-9a-f]{40}", source["revision"]) is not None
            and type(source["dirty"]) is bool and source["snapshot_algorithm"] == "git-worktree-v2",
            "invalid source revision or snapshot algorithm")
    digest(source["tree_sha256"], "source snapshot")
    lock_bytes = regular_bytes(ROOT / "toolchain.lock.json")
    lock = parse_json(lock_bytes)
    toolchain = object_keys(manifest["toolchain"], {"rustc", "rust_lld", "qemu", "python", "binary_target",
                             "rust_flags", "qemu_setup", "setup_lock_sha256", "rust_target_library_tree_sha256",
                             "rust_library_tree_sha256"}, "toolchain")
    for name in ("rustc", "rust_lld", "qemu", "python"):
        row = object_keys(toolchain[name], {"version", "sha256"}, f"{name} identity")
        text(row["version"], f"{name} version")
        digest(row["sha256"], f"{name} binary")
    rust = toolchain["rustc"]["version"]
    host_match = re.search(r"^host: (\S+)$", rust, re.MULTILINE)
    host = host_match.group(1) if host_match else None
    require(host in lock["rust"]["hosts"] and f"release: {lock['rust']['version']}\n" in rust + "\n"
            and f"commit-hash: {lock['rust']['revision']}\n" in rust + "\n", "Rust identity differs from pinned profile")
    require(re.search(rf"^QEMU emulator version {re.escape(lock['qemu']['version'])}(?:\s|$)", toolchain["qemu"]["version"])
            is not None, "QEMU identity differs from pinned profile")
    require(lock["rust"]["llvm_revision"] in toolchain["rust_lld"]["version"], "linker revision differs from pinned profile")
    python = toolchain["python"]["version"]
    require(re.fullmatch(r"3\.\d+\.\d+", python) is not None and int(python.split(".")[1]) >= 12,
            "unsupported Python runtime")
    require(toolchain["binary_target"] == lock["rust"]["target"], "binary target differs from pinned profile")
    flags = toolchain["rust_flags"]
    require(isinstance(flags, list) and flags and all(isinstance(flag, str) for flag in flags), "Rust flags are missing")
    require(len(set(flags)) == len(flags) and all(not re.search(r"(?:^|[=,])/", flag) and "../" not in flag for flag in flags),
            "Rust flags must be unique and public relative arguments")
    for flag in ("--target=x86_64-unknown-none", "-Cpanic=abort", "-Crelocation-model=static", "-Cdebuginfo=2",
                 "-Cdwarf-version=4", "-Clink-arg=--build-id=none", "-Clink-arg=-Tfixtures/rust-probe.ld"):
        require(flag in flags, "Rust flags omit the freestanding layout/debug profile")
    require(toolchain["setup_lock_sha256"] == sha256(lock_bytes), "setup lock identity differs from current pinned profile")
    digest(toolchain["rust_target_library_tree_sha256"], "target library tree")
    digest(toolchain["rust_library_tree_sha256"], "Rust compiler library tree")
    setup = toolchain["qemu_setup"]
    require(isinstance(setup, dict) and type(setup.get("schema_version")) is int and setup.get("schema_version") == 1 and setup.get("host") == host
            and setup.get("lock_sha256") == toolchain["setup_lock_sha256"]
            and setup.get("rust_target_library_tree_sha256") == toolchain["rust_target_library_tree_sha256"]
            and setup.get("rust_library_tree_sha256") == toolchain["rust_library_tree_sha256"],
            "setup provenance differs from toolchain identities")
    require(setup.get("qemu_configure") == lock["qemu"]["configure"]
            and setup.get("qemu_python_build_dependencies") == lock["qemu_python_build_dependencies"]
            and setup.get("ninja") == lock["ninja"]["version"]
            and setup.get("rustc") == rust.splitlines()[0]
            and setup.get("qemu") == toolchain["qemu"]["version"], "setup dependencies differ from pinned profile")
    require(isinstance(setup.get("verified_tools"), dict), "verified setup binary identities are missing")
    for name in ("rustc", "rust_lld", "qemu"):
        require(setup.get("verified_tools", {}).get(name) == {"sha256": toolchain[name]["sha256"]},
                "setup binary identity differs from manifest")
    require(isinstance(setup.get("qemu_host_compilers"), dict) and bool(setup["qemu_host_compilers"])
            and isinstance(setup.get("qemu_host_dependencies"), list) and bool(setup["qemu_host_dependencies"]),
            "QEMU host build environment is missing")
    for compilers in setup["qemu_host_compilers"].values():
        require(isinstance(compilers, dict) and bool(compilers), "QEMU host compiler records are missing")
        for compiler in compilers.values():
            object_keys(compiler, {"id", "version"}, "QEMU host compiler")
            text(compiler["id"], "QEMU compiler id")
            text(compiler["version"], "QEMU compiler version")
    for dependency in setup["qemu_host_dependencies"]:
        object_keys(dependency, {"name", "version"}, "QEMU host dependency")
        text(dependency["name"], "QEMU dependency name")
        text(dependency["version"], "QEMU dependency version")
    extraction = object_keys(setup.get("qemu_extraction"), {"archive_sha256", "omitted_links"}, "QEMU extraction")
    require(extraction["archive_sha256"] == lock["qemu"]["sha256"] and isinstance(extraction["omitted_links"], list),
            "QEMU extraction differs from pinned archive")
    components = manifest["components"]
    require(isinstance(components, list), "component provenance is missing")
    expected_names = {"g03-original-fixtures", "rust", "qemu", "rust-bundled-llvm-linker", "ninja",
                      *(row["name"] for row in lock["qemu_python_build_dependencies"])}
    indexed = {}
    for row in components:
        object_keys(row, {"name", "source", "license", "roles", "modified_files", "notices", "distribution_requirements"},
                    "component provenance", {"version", "revision", "archive_sha256", "target_library", "notice_sha256", "omitted_source_links"})
        for key in ("name", "source", "license", "distribution_requirements"):
            text(row[key], f"component {key}")
        require(row["name"] not in indexed, "duplicate component provenance")
        require(row["source"].startswith("https://") and bool(row["roles"]) and bool(row["notices"]), "component source/roles/notices are missing")
        for key in ("roles", "modified_files", "notices"):
            require(isinstance(row[key], list) and all(isinstance(item, str) and item.strip() for item in row[key]),
                    f"invalid component {key}")
        indexed[row["name"]] = row
    require(set(indexed) == expected_names, "required component provenance is missing or unsupported")
    roles = {"g03-original-fixtures": {"test_fixture", "compiler_layout_debug_probe"},
             "rust": {"build_tool", "freestanding_core_and_compiler_builtins"}, "qemu": {"external_emulator"},
             "rust-bundled-llvm-linker": {"build_linker"}, "ninja": {"qemu_build_dependency"},
             **{row["name"]: {"qemu_build_dependency"} for row in lock["qemu_python_build_dependencies"]}}
    for name, required_roles in roles.items():
        require(set(indexed[name]["roles"]) == required_roles, "component role differs from fixture provenance contract")
    original = indexed["g03-original-fixtures"]
    require(original.get("revision") == source["revision"] and original["source"] == "https://github.com/AG187-Lab/tessryn"
            and original["license"] == "Apache-2.0" and set(original["modified_files"]) == {"fixtures/rom.py", "fixtures/rust-probe.rs", "fixtures/rust-probe.ld"}
            and "LICENSE" in original["notices"], "original fixture provenance differs from source identity")
    for name, spec, archive, url in (
        ("rust", lock["rust"], lock["rust"]["hosts"][host]["sha256"], lock["rust"]["hosts"][host]["url"]),
        ("qemu", lock["qemu"], lock["qemu"]["sha256"], lock["qemu"]["url"]),
        ("ninja", lock["ninja"], lock["ninja"]["hosts"][host]["sha256"], lock["ninja"]["source"]),
        *((row["name"], row, row["sha256"], row["url"]) for row in lock["qemu_python_build_dependencies"]),
    ):
        row = indexed[name]
        require(row.get("version") == spec["version"] and row.get("archive_sha256") == archive
                and row["source"] == url and row["license"] == spec["license"], "external component differs from pinned provenance")
        if "revision" in spec:
            require(row.get("revision") == spec["revision"], "component source revision differs from pinned provenance")
    require(indexed["rust"].get("target_library") == lock["rust"]["target_library"], "target library archive provenance differs")
    linker = indexed["rust-bundled-llvm-linker"]
    require(linker.get("revision") == lock["rust"]["llvm_revision"] and linker.get("archive_sha256") == indexed["rust"]["archive_sha256"]
            and linker["license"] == "Apache-2.0 WITH LLVM-exception"
            and linker["source"] == "https://github.com/rust-lang/llvm-project/tree/" + lock["rust"]["llvm_revision"], "bundled linker provenance differs")
    require(indexed["ninja"].get("notice_sha256") == lock["ninja"]["notice"]["sha256"]
            and indexed["ninja"]["notices"] == [lock["ninja"]["notice"]["url"]], "Ninja notice provenance differs")
    omitted = extraction["omitted_links"]
    require(all(isinstance(name, str) and "/" in name and not name.startswith("/") and ".." not in PurePosixPath(name).parts
                for name in omitted), "invalid omitted QEMU source path")
    require(indexed["qemu"].get("omitted_source_links", []) == omitted
            and indexed["qemu"]["modified_files"] == [name.split("/", 1)[1] for name in omitted], "QEMU extraction changes are not declared")
    require(manifest["capabilities"] == {"tessryn_kernel_boot": "unavailable", "native_gpu": "unavailable", "model_inference": "unavailable"},
            "fixtures cannot establish native capabilities")


def verified_artifact(manifest_path: Path, fixture: str, manifest: dict | None = None) -> bytes:
    manifest = manifest if manifest is not None else parse_json(regular_bytes(manifest_path))
    validate_manifest(manifest)
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest artifacts are missing")
    seen = set()
    selected = None
    expected = {"pass.rom": "emulator_pass_fixture", "hang.rom": "emulator_timeout_fixture", "rust-probe.elf": "compiler_layout_debug_probe"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size_bytes", "role"}:
            raise ValueError("artifact identity/role is incomplete")
        path = PurePosixPath(entry["path"])
        if path.is_absolute() or len(path.parts) != 1 or "\\" in str(path) or str(path) in {".", ".."}:
            raise ValueError("artifact paths must be plain filenames beside the manifest")
        if str(path) in seen:
            raise ValueError("duplicate artifact path")
        seen.add(str(path))
        if entry["path"] not in expected or entry["role"] != expected[entry["path"]] or type(entry["size_bytes"]) is not int:
            raise ValueError("artifact name/role differs from original fixture contract")
        data = regular_bytes(manifest_path.parent / str(path))
        if sha256(data) != entry.get("sha256") or len(data) != entry.get("size_bytes"):
            raise ValueError("artifact hash or length mismatch")
        if str(path) in {"pass.rom", "hang.rom"} and data != make_rom(hang=str(path) == "hang.rom"):
            raise ValueError("ROM differs from the original declared fixture")
        if str(path) == "rust-probe.elf" and inspect_elf_bytes(data) != manifest["binary_validation"]:
            raise ValueError("ELF layout/debug inspection differs from manifest")
        if str(path) == f"{fixture}.rom":
            selected = data
    if seen != set(expected) or selected is None or len(selected) != 65536:
        raise ValueError("selected fixture must be a declared 64 KiB ROM")
    return selected


def fixture_command(fixture: str) -> list[str]:
    return ["qemu-system-x86_64", "-machine", "pc,accel=tcg", "-cpu", "qemu64", "-m", "16M",
            "-smp", "1", "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "none", "-nic", "none", "-no-reboot", "-bios", f"{fixture}.rom",
            "-debugcon", "stdio", "-global", "isa-debugcon.iobase=0xe9", "-global", "apic.vapic=off",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]


def run_emulator(manifest_path: Path, registration_path: Path, out: Path,
                 fixture: str = "pass", timeout_seconds: float = 5,
                 max_log_bytes: int = 65536, qemu: str = "qemu-system-x86_64") -> dict:
    """Own a new result directory; never overwrite a previous experiment.

    Host-owned artifacts are hashed, then copied to scratch. The guest receives
    only its ROM, with no writable disks, shares, network, or passthrough devices.
    """
    if fixture not in {"pass", "hang"}:
        raise ValueError("unknown fixture")
    # Validate budgets before making a result whose schema would be invalid.
    import math
    if isinstance(timeout_seconds, bool) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout must be positive and finite")
    if isinstance(max_log_bytes, bool) or not isinstance(max_log_bytes, int) or max_log_bytes <= 0:
        raise ValueError("log budget must be a positive integer")
    out.mkdir(parents=True, exist_ok=False)
    command = fixture_command(fixture)
    result = {
        "schema_version": 1, "format": "tessryn-evaluation-result",
        "evidence_kind": "implementation_result", "subject": "test_fixture", "status": "fail",
        "bindings": {"evaluator": evaluator_hash(), "artifact_manifest": "0" * 64, "registration": "0" * 64},
        "capabilities": {name: {"status": "unavailable", "reason": reason} for name, reason in {
            "kernel_boot": "Tessryn kernel is not implemented; ROM is a harness fixture",
            "gpu_execution": "No native GPU driver or qualified device artifact exists",
            "inference": "No model execution implementation exists"}.items()},
        "execution": {"command": command, "timeout_seconds": timeout_seconds,
                      "max_log_bytes": max_log_bytes, "elapsed_seconds": 0, "returncode": None,
                      "reason": "input validation did not complete", "emulator": None},
        "logs": [], "actual_sample_count": 0,
        "performance": {"status": "unavailable", "reason": "Fixture wall time is harness metadata, not Tessryn performance"},
    }
    stdout = stderr = b""
    stage = "manifest input read"
    try:
        manifest_bytes = regular_bytes(manifest_path)
        stage = "registration input read"
        registration_bytes = regular_bytes(registration_path)
        result["bindings"].update(artifact_manifest=sha256(manifest_bytes), registration=sha256(registration_bytes))
        registration = parse_json(registration_bytes)
        stage = "registration validation"
        validate_registration(registration)
        result["bindings"]["registration"] = registration_digest(registration)
        if registration["subject"] != "test_fixture":
            raise ValueError("fixture harness requires a fixture protocol registration")
        stage = "artifact integrity validation"
        rom = verified_artifact(manifest_path, fixture, parse_json(manifest_bytes))
        executable = shutil.which(qemu)
        if executable is None:
            result["status"] = "unavailable"
            result["execution"]["reason"] = "QEMU executable is missing"
        else:
            executable = str(Path(executable).resolve())
            stage = "emulator execution setup"
            binary_hash = sha256(regular_bytes(Path(executable)))
            if binary_hash != parse_json(manifest_bytes)["toolchain"]["qemu"]["sha256"]:
                raise ValueError("selected emulator binary differs from manifest provenance")
            with tempfile.TemporaryDirectory(prefix="tessryn-g03-") as temporary:
                scratch = Path(temporary)
                (scratch / f"{fixture}.rom").write_bytes(rom)
                version = run_bounded([executable, "--version"], scratch, min(timeout_seconds, 5), min(8192, max_log_bytes))
                expected_version = load_json(ROOT / "toolchain.lock.json")["qemu"]["version"]
                version_text = version.stdout.decode("utf-8", errors="replace")
                if version.status != "completed" or version.returncode != 0 or not re.search(
                        rf"QEMU emulator version {re.escape(expected_version)}(?:\s|$)", version_text):
                    result["status"] = version.status if version.status in {"timeout", "log_limit", "cancelled"} else "unavailable"
                    result["execution"].update(elapsed_seconds=version.elapsed_seconds, returncode=version.returncode,
                                                reason="QEMU version does not match the pinned profile or version probe failed")
                    stdout, stderr = version.stdout, version.stderr
                else:
                    result["execution"]["emulator"] = {"version": expected_version,
                                                          "binary_sha256": binary_hash}
                    execution = run_bounded([executable, *command[1:]], scratch, timeout_seconds, max_log_bytes)
                    stdout, stderr = execution.stdout, execution.stderr
                    result["execution"].update(elapsed_seconds=execution.elapsed_seconds,
                                                returncode=execution.returncode, reason=execution.reason)
                    result["status"] = execution.status
                    if execution.status == "completed":
                        passed = fixture == "pass" and execution.returncode == 33 and MARKER in stdout
                        result["status"] = "pass" if passed else "fail"
                        result["execution"]["reason"] = ("fixture marker and debug-exit status matched" if passed else
                                                             "fixture marker or expected debug-exit status did not match")
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["status"] = "fail"
        result["execution"]["reason"] = f"{stage} rejected: {type(error).__name__}"
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / name).write_bytes(data)
        result["logs"].append({"path": name, "sha256": sha256(data), "size_bytes": len(data)})
    validate_result(result)
    temporary_result = out / "result.json.tmp"
    temporary_result.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n")
    temporary_result.replace(out / "result.json")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--registration", type=Path, default=ROOT / "evidence/fixture-registration.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixture", choices=["pass", "hang"], default="pass")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--max-log-bytes", type=int, default=65536)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    args = parser.parse_args()
    previous = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        result = run_emulator(args.manifest, args.registration, args.out, args.fixture,
                              args.timeout, args.max_log_bytes, args.qemu)
    except (OSError, ValueError) as error:
        parser.exit(2, f"harness setup rejected: {type(error).__name__}\n")
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps({"status": result["status"], "reason": result["execution"]["reason"],
                      "result": "result.json"}, sort_keys=True))
    return {"pass": 0, "fail": 1, "timeout": 124, "cancelled": 130, "unavailable": 2, "log_limit": 125}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
