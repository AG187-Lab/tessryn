#!/usr/bin/env python3
"""Add checksum-pinned host test libraries to this checkout's G03 Rust setup."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import date
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import setup_toolchain as g03

ROOT = Path(__file__).resolve().parents[1]
PREFIX = ROOT / "build" / "toolchain"
PROFILE = ROOT / "planning" / "k02-toolchain.lock.json"
HOSTS = {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
IDENTITY_FIELDS = ("verified_tools", "rust_target_library_tree_sha256", "rust_library_tree_sha256")


def regular_path(path: Path) -> None:
    """Do not follow mutable setup products into other checkouts or directories."""
    if not path.is_relative_to(ROOT):
        raise ValueError("setup path must remain inside this checkout")
    for parent in (path, *path.parents):
        if parent == ROOT:
            break
        if parent.is_symlink():
            raise ValueError("setup paths must not contain symbolic links")


def read_object(path: Path) -> dict:
    regular_path(path)
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("setup JSON must be an object")
    return value


def digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def load_profile(lock: dict | None = None) -> dict:
    lock = read_object(ROOT / "toolchain.lock.json") if lock is None else lock
    profile = read_object(PROFILE)
    rust = profile.get("rust")
    if (set(profile) != {"schema_version", "g03_lock_sha256", "rust"}
            or type(profile["schema_version"]) is not int or profile["schema_version"] != 1
            or profile["g03_lock_sha256"] != g03.sha256(ROOT / "toolchain.lock.json")
            or not isinstance(rust, dict)
            or set(rust) != {"version", "revision", "hash_source", "manifest_sha256", "hosts"}
            or rust["version"] != lock["rust"]["version"]
            or rust["revision"] != lock["rust"]["revision"]
            or rust["hash_source"] != lock["rust"]["hash_source"]
            or not digest(rust["manifest_sha256"])
            or not isinstance(rust["hosts"], dict) or set(rust["hosts"]) != HOSTS):
        raise ValueError("K02 toolchain profile is malformed or stale")
    for selected_host, spec in rust["hosts"].items():
        pattern = (r"https://static\.rust-lang\.org/dist/([0-9]{4}-[0-9]{2}-[0-9]{2})/rust-std-"
                   + re.escape(rust["version"] + "-" + selected_host) + r"\.tar\.xz")
        if (not isinstance(spec, dict) or set(spec) != {"url", "sha256"}
                or not digest(spec["sha256"]) or not isinstance(spec["url"], str)
                or (match := re.fullmatch(pattern, spec["url"])) is None):
            raise ValueError("K02 host library archive profile is malformed")
        date.fromisoformat(match[1])
    return profile


def verify_base_installation(lock: dict) -> dict:
    """Check existing provenance before executing its compiler or refreshing it."""
    record = read_object(PREFIX / "installed.json")
    tools = record.get("verified_tools")
    selected_host = g03.host()
    if (type(record.get("schema_version")) is not int or record["schema_version"] != 1
            or record.get("host") != selected_host
            or record.get("lock_sha256") != g03.sha256(ROOT / "toolchain.lock.json")
            or not isinstance(record.get("rustc"), str) or not isinstance(tools, dict)):
        raise ValueError("G03 installation receipt is malformed or stale")
    paths = {"rustc": PREFIX / "bin" / "rustc",
             "rust_lld": PREFIX / "lib" / "rustlib" / selected_host / "bin" / "rust-lld"}
    if "qemu" in record:
        paths["qemu"] = PREFIX / "bin" / "qemu-system-x86_64"
    if set(tools) != set(paths):
        raise ValueError("G03 verified tool identity is malformed")
    for name, path in paths.items():
        regular_path(path)
        if not isinstance(tools[name], dict) or tools[name].get("sha256") != g03.sha256(path):
            raise ValueError("G03 installed tool does not match its receipt")
    regular_path(PREFIX / "lib")
    if (record.get("rust_target_library_tree_sha256") != g03.rust_target_library_digest(PREFIX, lock["rust"]["target"])
            or record.get("rust_library_tree_sha256") != g03.regular_tree_digest(PREFIX / "lib")):
        raise ValueError("G03 installed library identity is stale")
    compiler = paths["rustc"]
    sysroot = Path(subprocess.check_output([str(compiler), "--print", "sysroot"], text=True, timeout=30).strip())
    if sysroot.resolve() != PREFIX.resolve():
        raise ValueError("Rust sysroot must belong to this checkout")
    actual = g03.installation_identity(deepcopy(record), lock)
    if any(record.get(field) != actual[field] for field in IDENTITY_FIELDS):
        raise ValueError("G03 installed library or tool identity is stale")
    version = subprocess.check_output([str(compiler), "--version"], text=True, timeout=30).strip()
    if record["rustc"] != version:
        raise ValueError("G03 compiler version receipt is stale")
    return record


def host_library_digest(selected_host: str) -> str:
    directory = PREFIX / "lib" / "rustlib" / selected_host / "lib"
    regular_path(directory)
    for name in ("core", "std", "test"):
        if not any(directory.glob(f"lib{name}-*.rlib")):
            raise ValueError("pinned Rust host test libraries are unavailable")
    return g03.regular_tree_digest(directory)


def receipt(profile: dict, base: dict) -> dict:
    return {
        "schema_version": 1, "kind": "k02_host_test_toolchain", "host": base["host"],
        "profile_sha256": g03.sha256(PROFILE),
        "g03_lock_sha256": profile["g03_lock_sha256"],
        "g03_record_sha256": g03.sha256(PREFIX / "installed.json"),
        "rustc": base["rustc"], "rust_revision": profile["rust"]["revision"],
        "host_library": profile["rust"]["hosts"][base["host"]],
        "rust_host_library_tree_sha256": host_library_digest(base["host"]),
        **{field: base[field] for field in IDENTITY_FIELDS},
    }


def verified_setup() -> dict:
    """Validate both receipts against the current compiler and complete libraries."""
    lock = read_object(ROOT / "toolchain.lock.json")
    profile = load_profile(lock)
    base = verify_base_installation(lock)
    actual = read_object(PREFIX / "k02-installed.json")
    if actual != receipt(profile, base):
        raise ValueError("K02 toolchain receipt is malformed or stale")
    return actual


def write_receipt(path: Path, value: dict) -> None:
    regular_path(path)
    staged = path.with_suffix(path.suffix + ".tmp")
    regular_path(staged)
    staged.write_text(json.dumps(value, indent=2) + "\n")
    staged.replace(path)


def setup() -> dict:
    if sys.version_info < (3, 12):
        raise ValueError("setup requires Python 3.12 or newer")
    regular_path(PREFIX)
    for name in ("k02-installed.json", "k02-installed.json.tmp", "installed.json.tmp"):
        path = PREFIX / name
        regular_path(path)
        path.unlink(missing_ok=True)
    lock = read_object(ROOT / "toolchain.lock.json")
    profile = load_profile(lock)
    for name in ("bin", "lib", "libexec", "share", "etc", "notices", "python-deps", "pip-cache", "sources", "downloads"):
        regular_path(PREFIX / name)
    selected_host = g03.host()
    for spec in (lock["rust"]["hosts"][selected_host], lock["rust"]["target_library"],
                 profile["rust"]["hosts"][selected_host]):
        archive_name = spec["url"].rsplit("/", 1)[1]
        regular_path(PREFIX / "downloads" / archive_name)
        regular_path(PREFIX / "downloads" / (archive_name + ".partial"))
    if not (PREFIX / "installed.json").exists():
        g03.setup(rust_only=True, jobs=1)
    base = verify_base_installation(lock)
    spec = profile["rust"]["hosts"][base["host"]]
    source = g03.extract(g03.fetch(spec))
    (PREFIX / "installed.json").unlink()
    try:
        directory = PREFIX / "lib" / "rustlib" / base["host"] / "lib"
        regular_path(directory)
        g03.fresh_directory(directory)
        g03.run(["sh", str(source / "install.sh"), f"--prefix={PREFIX}", "--disable-ldconfig"])
        host_library_digest(base["host"])
        refreshed = g03.installation_identity(deepcopy(base), lock)
        if any(refreshed[field] != base[field] for field in IDENTITY_FIELDS[:2]):
            raise ValueError("host library installation changed G03 compiler or target identity")
        write_receipt(PREFIX / "installed.json", refreshed)
        result = receipt(profile, refreshed)
        write_receipt(PREFIX / "k02-installed.json", result)
        return verified_setup()
    except BaseException:
        for name in ("installed.json", "installed.json.tmp", "k02-installed.json", "k02-installed.json.tmp"):
            (PREFIX / name).unlink(missing_ok=True)
        raise


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        print(json.dumps(setup(), indent=2))
        return 0
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"K02 toolchain setup failed: {type(error).__name__}; see preceding diagnostics", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
