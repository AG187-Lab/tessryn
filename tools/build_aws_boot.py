#!/usr/bin/env python3
"""Build original headless UEFI kernels and deterministic fixed-disk AWS inputs.

This tool creates local artifacts only. It never reads cloud credentials or
registers, launches, changes permissions, or deletes an AWS resource.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.aws_media import BLOCK_SIZE, DISK_SIZE_BYTES, write_disk
from tools.build_fixture import sha256, source_identity
from tools.build_kernel import CASES, compiler_profile, compile_command, copy_notices, inspect_pe
from tools.setup_uefi import verify_installation

AWS_PROFILE = {
    "architecture": "x86_64", "firmware": "UEFI", "guest_kernel": "original_tessryn",
    "diagnostics": "bounded_headless_COM1", "uart_io_base": 0x3f8,
    "serial_baud": 115200, "serial_framing": "8n1", "framebuffer": "optional",
    "uart_status": "profile_assumption_requires_exact_AWS_execution_evidence",
    "qemu_debug_ports": "disabled", "active_cpu": "boot_CPU_only",
    "storage": "firmware_loads_FAT32_ESP_before_handoff_no_native_storage_driver",
}
BUILD_CAPABILITIES = {"aws_native_boot": "unqualified_requires_execution_evidence",
                      "aws_recovery": "unqualified_requires_external_control_evidence",
                      "native_gpu": "unavailable", "network": "unavailable", "inference": "unavailable"}


def upload_plan(case: str, disk: dict) -> dict:
    """Describe immutable EBS inputs, without account IDs or resource handles."""
    return {
        "schema_version": 1,
        "format": "tessryn-aws-snapshot-input-plan",
        "status": "local_inputs_only_not_provisioned",
        "case": case,
        "disk_path": f"{case}/boot.img",
        "disk_sha256": disk["sha256"],
        "logical_size_bytes": DISK_SIZE_BYTES,
        "start_snapshot": {"VolumeSize": 1},
        "idempotency": "AWS owner records a fresh attempt-scoped ClientToken; reuse it only for retries of that exact attempt.",
        "put_snapshot_blocks": {
            "DataLength": BLOCK_SIZE,
            "ChecksumAlgorithm": "SHA256",
            "blocks": [{"BlockIndex": row["index"], "sha256": row["sha256"],
                        "Checksum": base64.b64encode(bytes.fromhex(row["sha256"])).decode("ascii")}
                       for row in disk["nonzero_blocks"]],
        },
        "complete_snapshot": {"ChangedBlocksCount": len(disk["nonzero_blocks"])},
        "ami_contract": {
            "Architecture": "x86_64", "VirtualizationType": "hvm", "BootMode": "uefi",
            "RootDeviceName": "/dev/sda1", "root_volume_gib": 1,
            "DeleteOnTermination": True,
            "note": "The AWS resource owner supplies snapshot, AMI, region and device-enablement metadata after approval.",
        },
    }


def build(out: Path) -> dict:
    out = out.resolve()
    if not out.is_relative_to(ROOT / "build"):
        raise ValueError("AWS boot outputs must be inside ignored build/")
    out.mkdir(parents=True, exist_ok=False)
    source = source_identity()
    profile = compiler_profile()
    setup = profile["toolchain"]["setup"]
    notices = copy_notices(out)
    artifacts, plans = [], []
    for case in CASES:
        directory = out / case
        directory.mkdir()
        efi = directory / "BOOTX64.EFI"
        flags = ["--cfg", f'k01_case="{case}"', "--cfg", "k01_aws"]
        command = compile_command(profile, Path("kernel/main.rs"), efi, flags)
        execution = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
        log = (execution.stdout + execution.stderr).replace(str(ROOT), "tessryn")
        (directory / "build.log").write_text(log)
        if execution.returncode:
            raise ValueError(f"AWS {case} kernel compile failed; inspect build.log")
        payload = efi.read_bytes()
        pe = inspect_pe(payload)
        disk = write_disk(directory / "boot.img", payload)
        artifacts.extend((
            {"case": case, "path": f"{case}/BOOTX64.EFI", "sha256": sha256(efi),
             "size_bytes": len(payload), "rust_case_flags": flags, "pe_validation": pe},
            {"case": case, "path": f"{case}/boot.img", "sha256": disk["sha256"],
             "size_bytes": DISK_SIZE_BYTES, "disk": disk},
        ))
        plan_path = directory / "snapshot-inputs.json"
        plan_path.write_text(json.dumps(upload_plan(case, disk), indent=2, sort_keys=True) + "\n")
        plans.append({"path": f"{case}/snapshot-inputs.json", "sha256": sha256(plan_path),
                      "size_bytes": plan_path.stat().st_size})
    if verify_installation() != setup or source_identity() != source:
        raise ValueError("source or toolchain changed during AWS build; use a new directory")
    manifest = {
        "schema_version": 1, "artifact_type": "tessryn-aws-uefi-boot", "source": source,
        "toolchain": profile["toolchain"], "artifacts": artifacts, "notices": notices,
        "snapshot_input_plans": plans,
        "profile": AWS_PROFILE, "capabilities": BUILD_CAPABILITIES,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = build(args.out)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(2, f"AWS boot build rejected: {error}\n")
    print(json.dumps({"status": "built_local_inputs", "artifacts": len(manifest["artifacts"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
