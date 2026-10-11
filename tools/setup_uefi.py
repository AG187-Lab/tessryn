#!/usr/bin/env python3
"""Install a pinned UEFI Rust sysroot and QEMU firmware in ignored build/uefi.

Run setup_toolchain.py first. This additive setup preserves the G03 toolchain;
firmware is extracted from its pinned QEMU source archive without rebuilding it.
"""

from __future__ import annotations

import argparse
import bz2
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.build_fixture import verified_setup  # noqa: E402
from tools.setup_toolchain import (  # noqa: E402
    host, regular_tree_digest, rust_target_library_digest, sha256,
)

BASE_PREFIX = ROOT / "build" / "toolchain"
PREFIX = ROOT / "build" / "uefi"
DOWNLOADS = BASE_PREFIX / "downloads"
LOCK_PATH = ROOT / "uefi-toolchain.lock.json"
BASE_LOCK_PATH = ROOT / "toolchain.lock.json"


def check_file(path: Path, expected: str, label: str) -> None:
    if path.is_symlink() or not path.is_file() or sha256(path) != expected:
        raise ValueError(f"{label} hash mismatch or unavailable regular file")


def fetch(spec: dict, supplied: Path | None = None) -> Path:
    """A supplied archive and a cached archive are subject to the same hash check."""
    if supplied is not None:
        check_file(supplied, spec["sha256"], "supplied archive")
        return supplied
    if DOWNLOADS.is_symlink():
        raise ValueError("download cache must be a regular directory")
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    filename = spec["url"].rsplit("/", 1)[1]
    if not filename or Path(filename).name != filename:
        raise ValueError("invalid archive filename")
    archive = DOWNLOADS / filename
    if archive.exists() or archive.is_symlink():
        check_file(archive, spec["sha256"], "cached archive")
        return archive
    print(f"Downloading {filename}", flush=True)
    # An unpredictable temporary name prevents following a stale partial symlink.
    with tempfile.NamedTemporaryFile(prefix="uefi-download-", dir=DOWNLOADS, delete=False) as output:
        temporary = Path(output.name)
        try:
            with urllib.request.urlopen(spec["url"], timeout=60) as response:
                shutil.copyfileobj(response, output)
            output.flush()
            check_file(temporary, spec["sha256"], "downloaded archive")
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    return archive


def base_identity(base_lock: dict) -> dict:
    """Bind the extra target to the existing verified G03 binaries and libraries."""
    selected_host = host()
    compiler = BASE_PREFIX / "bin" / "rustc"
    linker = BASE_PREFIX / "lib" / "rustlib" / selected_host / "bin" / "rust-lld"
    qemu = BASE_PREFIX / "bin" / "qemu-system-x86_64"
    record = verified_setup(base_lock, compiler, linker, qemu, BASE_PREFIX, selected_host)
    compiler_identity(compiler, BASE_PREFIX, base_lock["rust"], selected_host)
    return record


def compiler_identity(compiler: Path, prefix: Path, rust: dict, selected_host: str) -> str:
    version = subprocess.check_output([str(compiler), "--version", "--verbose"], text=True, timeout=30)
    for line in (f"release: {rust['version']}", f"commit-hash: {rust['revision']}", f"host: {selected_host}"):
        if line not in version.splitlines():
            raise ValueError("Rust compiler version/revision/host does not match lock")
    sysroot = Path(subprocess.check_output([str(compiler), "--print", "sysroot"], text=True, timeout=30).strip())
    if sysroot.resolve() != prefix.resolve():
        raise ValueError("Rust compiler sysroot does not match UEFI setup directory")
    return version.splitlines()[0]


def validate_locks(lock: dict, base_lock: dict) -> None:
    if lock.get("schema_version") != 1:
        raise ValueError("unsupported UEFI lock schema")
    for key in ("version", "revision"):
        if lock["rust"][key] != base_lock["rust"][key]:
            raise ValueError("UEFI Rust lock must match the base compiler")
    if lock["rust"]["target"] != "x86_64-unknown-uefi":
        raise ValueError("UEFI target lock must select x86_64-unknown-uefi")
    if set(lock["rust"]["notices"]) != {"LICENSE-APACHE", "LICENSE-MIT", "COPYRIGHT"}:
        raise ValueError("UEFI Rust lock must include upstream license and copyright notices")
    for key in ("version", "revision", "url", "sha256"):
        if lock["firmware"]["archive"][key] != base_lock["qemu"][key]:
            raise ValueError("firmware source archive must match pinned base QEMU")
    members = lock["firmware"]["members"]
    if set(members) != {"code", "vars", "notice", "descriptor"}:
        raise ValueError("firmware must include code, vars, notice and descriptor")
    for spec in members.values():
        name = PurePosixPath(spec["member"])
        filename = spec["filename"]
        if name.is_absolute() or ".." in name.parts or Path(filename).name != filename or filename in ("", ".", ".."):
            raise ValueError("unsafe firmware member or output path")
        if spec["compression"] not in ("bz2", "none"):
            raise ValueError("unsupported firmware compression")
        if spec["size_bytes"] < 1 or spec["archive_member_size_bytes"] < 1:
            raise ValueError("firmware sizes must be positive")
    if len({spec["member"] for spec in members.values()}) != len(members):
        raise ValueError("firmware archive members must be distinct")
    if len({spec["filename"] for spec in members.values()}) != len(members):
        raise ValueError("firmware output filenames must be distinct")


def install_target(archive: Path, prefix: Path, rust: dict) -> dict:
    """Execute only a fresh safely extracted installer from the verified archive."""
    check_file(archive, rust["target_library"]["sha256"], "Rust UEFI target archive")
    with tempfile.TemporaryDirectory(prefix="uefi-rust-source-", dir=prefix.parent) as staging:
        with tarfile.open(archive, "r:xz") as source:
            roots = set()
            for member in source.getmembers():
                name = PurePosixPath(member.name)
                if name.is_absolute() or not name.parts or ".." in name.parts:
                    raise ValueError("Rust archive member has an unsafe path")
                roots.add(name.parts[0])
            if len(roots) != 1:
                raise ValueError("Rust archive must contain one root directory")
            source.extractall(staging, filter="data")
        extracted = Path(staging) / roots.pop()
        notices = {}
        (prefix / "notices" / "rust").mkdir(parents=True)
        for name, spec in rust["notices"].items():
            path = extracted / name
            check_file(path, spec["sha256"], f"Rust notice {name}")
            if path.stat().st_size != spec["size_bytes"]:
                raise ValueError("Rust notice size mismatch")
            output = prefix / "notices" / "rust" / name
            shutil.copy2(path, output)
            notices[name] = {"path": "notices/rust/" + name, **spec}
        installer = extracted / "install.sh"
        if installer.is_symlink() or not installer.is_file():
            raise ValueError("Rust archive must contain a regular installer")
        subprocess.run(["sh", str(installer), f"--prefix={prefix}", "--disable-ldconfig"],
                       cwd=ROOT, check=True, timeout=120)
        return notices


def install_firmware(archive: Path, firmware: dict, destination: Path) -> dict:
    """Read selected regular members only; never extract the QEMU source tree."""
    check_file(archive, firmware["archive"]["sha256"], "QEMU firmware archive")
    specs = firmware["members"]
    selected = {spec["member"]: role for role, spec in specs.items()}
    found = {}
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r|xz") as source:
        for member in source:
            if member.name not in selected:
                continue
            role = selected[member.name]
            spec = specs[role]
            if role in found or not member.isfile() or member.size != spec["archive_member_size_bytes"]:
                raise ValueError("firmware archive member type, size or duplication mismatch")
            with source.extractfile(member) as stream:
                compressed = stream.read(member.size + 1)
            if hashlib.sha256(compressed).hexdigest() != spec["archive_member_sha256"]:
                raise ValueError("firmware archive member hash mismatch")
            if spec["compression"] == "bz2":
                decompressor = bz2.BZ2Decompressor()
                contents = decompressor.decompress(compressed, max_length=spec["size_bytes"] + 1)
                if not decompressor.eof or decompressor.unused_data:
                    raise ValueError("firmware compressed member exceeds bound or has trailing data")
            else:
                contents = compressed
            if len(contents) != spec["size_bytes"] or hashlib.sha256(contents).hexdigest() != spec["sha256"]:
                raise ValueError("firmware output size or hash mismatch")
            output = destination / spec["filename"]
            if output.is_symlink():
                raise ValueError("firmware output must not be a symbolic link")
            output.write_bytes(contents)
            found[role] = {"path": "firmware/" + spec["filename"], "sha256": spec["sha256"],
                           "size_bytes": len(contents)}
    if set(found) != set(specs):
        raise ValueError("firmware archive is missing a pinned member")
    descriptor = json.loads((destination / specs["descriptor"]["filename"]).read_text())
    mapping = descriptor.get("mapping", {})
    if (descriptor.get("interface-types") != ["uefi"] or mapping.get("device") != "flash"
            or mapping.get("executable", {}).get("filename") != "@DATADIR@/" + specs["code"]["filename"]
            or mapping.get("nvram-template", {}).get("filename") != "@DATADIR@/" + specs["vars"]["filename"]
            or not any(target.get("architecture") == "x86_64" for target in descriptor.get("targets", []))):
        raise ValueError("QEMU descriptor does not establish the pinned x86_64 firmware pair")
    return found


def verify_record(prefix: Path, record: dict, lock: dict, base_lock: dict, base: dict) -> dict:
    """Verify every consumed tool, firmware byte and Rust library against setup."""
    if (record.get("schema_version") != 1 or record.get("host") != base["host"]
            or record.get("lock_sha256") != sha256(LOCK_PATH)
            or record.get("base_lock_sha256") != sha256(BASE_LOCK_PATH)
            or record.get("base_setup_sha256") != sha256(BASE_PREFIX / "installed.json")
            or record.get("rust_target_archive") != lock["rust"]["target_library"]
            or record.get("firmware_archive") != lock["firmware"]["archive"]):
        raise ValueError("UEFI setup record is stale or provenance does not match locks")
    compiler = prefix / "bin" / "rustc"
    linker = prefix / "lib" / "rustlib" / record["host"] / "bin" / "rust-lld"
    qemu = BASE_PREFIX / "bin" / "qemu-system-x86_64"
    for name, path in (("rustc", compiler), ("rust_lld", linker), ("qemu", qemu)):
        expected = base["verified_tools"][name]["sha256"]
        if record.get("verified_tools", {}).get(name, {}).get("sha256") != expected:
            raise ValueError("UEFI tool record does not match verified base setup")
        check_file(path, expected, name)
    if record.get("rustc") != compiler_identity(compiler, prefix, lock["rust"], record["host"]):
        raise ValueError("UEFI compiler version record does not match selected compiler")
    if record.get("rust_library_tree_sha256") != regular_tree_digest(prefix / "lib"):
        raise ValueError("UEFI Rust runtime library tree does not match setup")
    if record.get("rust_target_library_tree_sha256") != rust_target_library_digest(prefix, lock["rust"]["target"]):
        raise ValueError("UEFI Rust target library tree does not match setup")
    expected_notices = {name: {"path": "notices/rust/" + name, **spec}
                        for name, spec in lock["rust"]["notices"].items()}
    if record.get("rust_notices") != expected_notices:
        raise ValueError("UEFI Rust notices record does not match lock")
    for name, spec in expected_notices.items():
        path = prefix / spec["path"]
        check_file(path, spec["sha256"], f"Rust notice {name}")
        if path.stat().st_size != spec["size_bytes"]:
            raise ValueError("UEFI Rust notice size does not match lock")
    expected_firmware = {role: {"path": "firmware/" + spec["filename"], "sha256": spec["sha256"],
                                "size_bytes": spec["size_bytes"]}
                         for role, spec in lock["firmware"]["members"].items()}
    if record.get("firmware") != expected_firmware:
        raise ValueError("UEFI firmware record does not match lock")
    for role, spec in expected_firmware.items():
        path = prefix / spec["path"]
        check_file(path, spec["sha256"], f"firmware {role}")
        if path.stat().st_size != spec["size_bytes"]:
            raise ValueError("UEFI firmware size does not match lock")
    return record


def verify_installation() -> dict:
    """Return the validated installation record used by the kernel builder."""
    lock = json.loads(LOCK_PATH.read_text())
    base_lock = json.loads(BASE_LOCK_PATH.read_text())
    validate_locks(lock, base_lock)
    base = base_identity(base_lock)
    record_path = PREFIX / "installed.json"
    if record_path.is_symlink() or not record_path.is_file():
        raise ValueError("verified UEFI setup unavailable; run python3 tools/setup_uefi.py")
    record = json.loads(record_path.read_text())
    if not isinstance(record, dict):
        raise ValueError("UEFI setup record must be an object")
    return verify_record(PREFIX, record, lock, base_lock, base)


def setup(*, qemu_source_archive: Path | None = None) -> dict:
    if sys.version_info < (3, 12):
        raise ValueError("UEFI setup requires Python 3.12 or newer for safe archive extraction")
    lock = json.loads(LOCK_PATH.read_text())
    base_lock = json.loads(BASE_LOCK_PATH.read_text())
    validate_locks(lock, base_lock)
    base = base_identity(base_lock)
    if PREFIX.is_symlink() or PREFIX.exists() and not PREFIX.is_dir():
        raise ValueError("UEFI setup product must be a regular directory")
    target_archive = fetch(lock["rust"]["target_library"])
    firmware_archive = fetch(lock["firmware"]["archive"], qemu_source_archive)
    PREFIX.parent.mkdir(parents=True, exist_ok=True)
    # Failed downloads, extraction and installs preserve the previous installation.
    with tempfile.TemporaryDirectory(prefix="uefi-setup-", dir=PREFIX.parent) as temporary:
        staged = Path(temporary) / "sysroot"
        (staged / "bin").mkdir(parents=True)
        shutil.copy2(BASE_PREFIX / "bin" / "rustc", staged / "bin" / "rustc")
        shutil.copytree(BASE_PREFIX / "lib", staged / "lib")
        if regular_tree_digest(staged / "lib") != base["rust_library_tree_sha256"]:
            raise ValueError("copied base Rust library tree does not match verified setup")
        rust_notices = install_target(target_archive, staged, lock["rust"])
        firmware = install_firmware(firmware_archive, lock["firmware"], staged / "firmware")
        record = {
            "schema_version": 1, "host": base["host"],
            "rustc": compiler_identity(staged / "bin" / "rustc", staged, lock["rust"], base["host"]),
            "lock_sha256": sha256(LOCK_PATH), "base_lock_sha256": sha256(BASE_LOCK_PATH),
            "base_setup_sha256": sha256(BASE_PREFIX / "installed.json"),
            "verified_tools": {name: base["verified_tools"][name] for name in ("rustc", "rust_lld", "qemu")},
            "rust_target_archive": lock["rust"]["target_library"],
            "rust_notices": rust_notices,
            "firmware_archive": lock["firmware"]["archive"], "firmware": firmware,
            "rust_target_library_tree_sha256": rust_target_library_digest(staged, lock["rust"]["target"]),
            "rust_library_tree_sha256": regular_tree_digest(staged / "lib"),
        }
        verify_record(staged, record, lock, base_lock, base_identity(base_lock))
        (staged / "installed.json").write_text(json.dumps(record, indent=2) + "\n")
        if PREFIX.exists():
            shutil.rmtree(PREFIX)
        staged.replace(PREFIX)
    return verify_installation()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu-source-archive", type=Path,
                        help="use an existing QEMU source archive after checking its pinned SHA256")
    parser.add_argument("--verify", action="store_true", help="verify the current UEFI setup without reinstalling")
    args = parser.parse_args()
    try:
        result = verify_installation() if args.verify else setup(qemu_source_archive=args.qemu_source_archive)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"UEFI setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
