#!/usr/bin/env python3
"""Build and validate the opt-in IO01 PCI discovery emulator image."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_fixture import source_identity
from tools.build_kernel import compile_command, compiler_profile, copy_notices, inspect_pe
from tools.g03.evidence import parse_json
from tools.k01_media import make_disk
from tools.k02_region_protocol import fresh_output, regular_bytes


PROFILE = {"machine": "pc-q35-11.1", "accelerator": "tcg", "cpu": "qemu64", "vcpus": 1,
           "memory_mib": 256, "segment": 0, "first_bus": 0, "last_bus": 7, "mechanism": "cf8-cfc"}
CASES = ("present", "absent")
CASE_FLAGS = ["--cfg", 'k01_case="normal"', "--cfg", "k01_emulator", "--cfg", "io01_pci"]
ARTIFACT_TYPE = "tessryn-io01-pci"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact(name: str, data: bytes) -> dict:
    return {"path": name, "sha256": digest(data), "size_bytes": len(data)}


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def notice_records(directory: Path) -> list[dict]:
    sources = [("tessryn", name, ROOT / name) for name in ("LICENSE", "NOTICE")]
    sources.extend(("rust", name, ROOT / "build/uefi/notices/rust" / name)
                   for name in ("LICENSE-APACHE", "LICENSE-MIT", "COPYRIGHT"))
    result = []
    for component, name, original in sources:
        relative = f"notices/{component}-{name}"
        raw = regular_bytes(directory / relative, 128 << 10)
        if raw != regular_bytes(original, 128 << 10):
            raise ValueError("IO01 notice differs from the pinned source")
        result.append({"component": component, **artifact(relative, raw)})
    return result


def description(source: dict, toolchain: dict, efi: bytes, disk: bytes, notices: list[dict]) -> dict:
    return {"schema_version": 1, "artifact_type": ARTIFACT_TYPE, "profile": PROFILE,
            "source": source, "toolchain": toolchain, "rust_case_flags": CASE_FLAGS,
            "artifacts": [{**artifact("BOOTX64.EFI", efi), "pe_validation": inspect_pe(efi)},
                          artifact("boot.img", disk)], "notices": notices}


def build(out: Path) -> dict:
    out = fresh_output(out)
    source, compiler = source_identity(), compiler_profile()
    efi_path = out / "BOOTX64.EFI"
    cmd = compile_command(compiler, Path("kernel/main.rs"), efi_path, CASE_FLAGS)
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
    (out / "build.log").write_text((proc.stdout + proc.stderr).replace(str(ROOT), "tessryn"))
    if proc.returncode:
        raise ValueError("IO01 compilation failed; see build.log")
    efi = regular_bytes(efi_path, 1 << 20)
    disk = make_disk(efi)
    (out / "boot.img").write_bytes(disk)
    notices = copy_notices(out)
    if source_identity() != source or compiler_profile()["toolchain"] != compiler["toolchain"]:
        raise ValueError("IO01 source or toolchain changed during the build")
    manifest = description(source, compiler["toolchain"], efi, disk, notices)
    (out / "manifest.json").write_bytes(canonical(manifest))
    return manifest


def validate_build(manifest_path: Path) -> tuple[dict, bytes]:
    """Recheck fixed artifact bytes, provenance, setup and current source."""
    manifest_path = manifest_path.absolute()
    raw = regular_bytes(manifest_path, 1 << 20)
    manifest = parse_json(raw)
    if manifest_path.name != "manifest.json" or manifest.get("artifact_type") != ARTIFACT_TYPE:
        raise ValueError("unsupported IO01 build manifest")
    efi = regular_bytes(manifest_path.parent / "BOOTX64.EFI", 1 << 20)
    disk = regular_bytes(manifest_path.parent / "boot.img", 128 << 20)
    expected = description(source_identity(), compiler_profile()["toolchain"], efi, disk,
                           notice_records(manifest_path.parent))
    if raw != canonical(expected) or disk != make_disk(efi):
        raise ValueError("IO01 manifest, media or exact checkout binding differs")
    return manifest, disk


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--out", type=Path)
    action.add_argument("--compare", type=Path, nargs=2, metavar=("FIRST", "SECOND"))
    args = parser.parse_args()
    try:
        if args.out is not None:
            result = build(args.out)
            print(json.dumps({"status": "built", "source": result["source"], "artifacts": result["artifacts"]}))
        else:
            first, second = args.compare
            if first.resolve() == second.resolve():
                raise ValueError("IO01 twin builds must have separate manifests")
            a, a_disk = validate_build(first)
            b, b_disk = validate_build(second)
            if a != b or a_disk != b_disk:
                raise ValueError("IO01 independently built artifacts differ")
            print(json.dumps({"status": "identical", "source": a["source"], "manifest_sha256": digest(canonical(a))}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"IO01 build/verification rejected ({type(error).__name__})\n")


if __name__ == "__main__":
    raise SystemExit(main())
