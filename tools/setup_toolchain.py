#!/usr/bin/env python3
"""Install hash-checked upstream tools inside ignored build/toolchain only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PREFIX = ROOT / "build" / "toolchain"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(spec: dict) -> Path:
    cache = PREFIX / "downloads"
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / spec["url"].rsplit("/", 1)[1]
    if not path.exists():
        print(f"Downloading {path.name}", flush=True)
        temporary = path.with_suffix(path.suffix + ".partial")
        try:
            with urllib.request.urlopen(spec["url"], timeout=60) as response:
                with temporary.open("wb") as output:
                    shutil.copyfileobj(response, output)
            if sha256(temporary) != spec["sha256"]:
                raise ValueError(f"archive hash mismatch: {path.name}")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    if sha256(path) != spec["sha256"]:
        raise ValueError(f"cached archive hash mismatch: {path.name}")
    return path


def extract(archive: Path) -> Path:
    destination = PREFIX / "sources"
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:xz") as source:
        names = set()
        for member in source.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or not name.parts or ".." in name.parts:
                raise ValueError("archive member has an unsafe path")
            names.add(name.parts[0])
        if len(names) != 1:
            raise ValueError("archive must contain one root directory")
        root = destination / names.pop()
        if root.is_symlink() or not root.resolve().is_relative_to(destination.resolve()):
            raise ValueError("archive root escapes local source directory")
        complete = root / ".tessryn-extraction.json"
        if complete.is_file() and json.loads(complete.read_text())["archive_sha256"] == sha256(archive):
            return root
        skipped = []

        def filter_member(member: tarfile.TarInfo, target: str) -> tarfile.TarInfo | None:
            try:
                return tarfile.data_filter(member, target)
            except (tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError):
                # EDK2's X11 build include link is not used by our emulator-only
                # build. Do not materialize links granting access outside setup.
                if "/roms/edk2/" not in member.name:
                    raise
                skipped.append(member.name)
                return None

        with tempfile.TemporaryDirectory(prefix="extract-", dir=destination) as staging:
            source.extractall(staging, filter=filter_member)
            staged_root = Path(staging) / root.name
            (staged_root / complete.name).write_text(json.dumps({
                "archive_sha256": sha256(archive), "omitted_links": skipped,
            }, indent=2) + "\n")
            if root.exists():
                shutil.rmtree(root)
            staged_root.replace(root)
    return root


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> None:
    subprocess.run(command, cwd=cwd or ROOT, check=True, timeout=timeout)


def host() -> str:
    key = (platform.system(), platform.machine())
    supported = {
        ("Darwin", "arm64"): "aarch64-apple-darwin",
        ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
    }
    if key not in supported:
        raise ValueError("setup supports Linux x86_64 and macOS arm64 development hosts")
    return supported[key]


def qemu_version_matches(line: str, version: str) -> bool:
    return line.split()[:4] == ["QEMU", "emulator", "version", version]


def setup(*, rust_only: bool, jobs: int) -> dict:
    if sys.version_info < (3, 12):
        raise ValueError("setup requires Python 3.12 or newer for safe archive extraction")
    lock = json.loads((ROOT / "toolchain.lock.json").read_text())
    selected_host = host()
    PREFIX.mkdir(parents=True, exist_ok=True)
    # Prevent the upstream setup from putting caches in the contributor's home.
    os.environ["PIP_CACHE_DIR"] = str(PREFIX / "pip-cache")
    rust = lock["rust"]
    for spec in (rust["hosts"][selected_host], rust["target_library"]):
        source = extract(fetch(spec))
        print(f"Installing {source.name}", flush=True)
        run(["sh", str(source / "install.sh"), f"--prefix={PREFIX}", "--disable-ldconfig"])
    compiler = PREFIX / "bin" / "rustc"
    compiler_version = subprocess.check_output([str(compiler), "--version"], text=True).strip()
    if not compiler_version.startswith(f"rustc {rust['version']} "):
        raise ValueError("installed Rust compiler does not match lock")
    result = {"schema_version": 1, "host": selected_host, "rustc": compiler_version}
    if not rust_only:
        qemu = lock["qemu"]
        with zipfile.ZipFile(fetch(lock["ninja"]["hosts"][selected_host])) as ninja_zip:
            ninja = PREFIX / "bin" / "ninja"
            ninja.write_bytes(ninja_zip.read("ninja"))
            ninja.chmod(0o755)
        if subprocess.check_output([str(ninja), "--version"], text=True).strip() != lock["ninja"]["version"]:
            raise ValueError("Ninja version does not match lock")
        ninja_notices = PREFIX / "notices" / "ninja"
        ninja_notices.mkdir(parents=True, exist_ok=True)
        shutil.copy2(fetch(lock["ninja"]["notice"]), ninja_notices / "COPYING")
        os.environ["PATH"] = str(PREFIX / "bin") + os.pathsep + os.environ.get("PATH", "")
        python_deps = PREFIX / "python-deps"
        python_deps.mkdir(exist_ok=True)
        for spec in lock["qemu_python_build_dependencies"]:
            with zipfile.ZipFile(fetch(spec)) as wheel:
                for name in wheel.namelist():
                    if not (python_deps / name).resolve().is_relative_to(python_deps.resolve()):
                        raise ValueError("wheel path escapes local dependency directory")
                wheel.extractall(python_deps)
        os.environ["PYTHONPATH"] = str(python_deps)
        source = extract(fetch(qemu))
        output = PREFIX / "qemu-build"
        output.mkdir(exist_ok=True)
        print(f"Configuring QEMU {qemu['version']} (TCG, x86_64 system emulator)", flush=True)
        run([str(source / "configure"), f"--prefix={PREFIX}", *qemu["configure"]], cwd=output)
        print("Building QEMU", flush=True)
        run(["make", f"-j{jobs}", "qemu-system-x86_64"], cwd=output)
        qemu_staging = PREFIX / "bin" / "qemu-system-x86_64.tmp"
        shutil.copy2(output / "qemu-system-x86_64", qemu_staging)
        qemu_staging.replace(PREFIX / "bin" / "qemu-system-x86_64")
        notices = PREFIX / "notices" / "qemu"
        notices.mkdir(parents=True, exist_ok=True)
        for name in ("COPYING", "COPYING.LIB", "LICENSE"):
            if (source / name).is_file():
                shutil.copy2(source / name, notices / name)
        version = subprocess.check_output(
            [str(PREFIX / "bin" / "qemu-system-x86_64"), "--version"], text=True
        ).splitlines()[0]
        if not qemu_version_matches(version, qemu["version"]):
            raise ValueError("built QEMU does not match lock")
        result["qemu"] = version
        result["qemu_configure"] = qemu["configure"]
        result["ninja"] = lock["ninja"]["version"]
        result["qemu_python_build_dependencies"] = lock["qemu_python_build_dependencies"]
        result["qemu_extraction"] = json.loads((source / ".tessryn-extraction.json").read_text())
        dependencies = json.loads((output / "meson-info" / "intro-dependencies.json").read_text())
        result["qemu_host_dependencies"] = sorted(
            [{"name": item["name"], "version": item["version"]} for item in dependencies],
            key=lambda item: item["name"],
        )
        compilers = json.loads((output / "meson-info" / "intro-compilers.json").read_text())
        result["qemu_host_compilers"] = {
            machine: {language: {key: spec[key] for key in ("id", "version")}
                      for language, spec in group.items()}
            for machine, group in compilers.items()
        }
    (PREFIX / "installed.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-only", action="store_true", help="skip building QEMU")
    parser.add_argument("--jobs", type=int, default=4, help="QEMU build parallelism (default: 4)")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    try:
        print(json.dumps(setup(rust_only=args.rust_only, jobs=args.jobs), indent=2))
        return 0
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"toolchain setup failed: {type(error).__name__}; see preceding diagnostics", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
