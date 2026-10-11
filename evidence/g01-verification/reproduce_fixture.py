#!/usr/bin/env python3
"""Reproduce original synthetic CLI evidence; never inspect the host hardware."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new output directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    collector = Path(__file__).resolve().parents[2] / "tools/collect_platform_inventory.py"
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "fixture"
        root.mkdir()
        values = {
            "proc/cpuinfo": "processor: 0\nmodel name: Original Synthetic Fixture CPU\nflags: lm sse2\n\n",
            "proc/meminfo": "MemTotal: 65536 kB\n",
            "sys/firmware/efi/fw_platform_size": "64\n",
            "sys/firmware/acpi/tables/APIC": "Original synthetic table fixture\n",
            "sys/class/dmi/id/bios_version": "Original Fixture Version 1\n",
            "sys/class/block/nvme0n1/device/model": "Original Synthetic NVMe\n",
            "sys/class/block/nvme0n1/size": "16\n",
            "sys/class/power_supply/AC/type": "Mains\n",
            "sys/class/power_supply/AC/online": "1\n",
        }
        pci = "sys/bus/pci/devices/0000:01:00.0"
        for field, value in {
            "vendor": "0x1234", "device": "0xabcd", "class": "0x020000",
            "subsystem_vendor": "0x1234", "subsystem_device": "0x0001", "revision": "0x01",
        }.items():
            values[f"{pci}/{field}"] = value + "\n"
        for name, value in values.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8")
        group = root / "sys/kernel/iommu_groups/7"
        (group / "devices").mkdir(parents=True)
        device = root / pci
        (device / "iommu_group").symlink_to(group)
        (group / "devices" / device.name).symlink_to(device)
        command = [sys.executable, str(collector), "--root", str(root)]
        for name, extra in (("synthetic-full.json", []), ("synthetic-public.json", ["--public-summary"])):
            result = subprocess.run(command + extra + ["--out", str(args.output / name)], capture_output=True, text=True, timeout=10)
            assert result.returncode == 0 and not result.stdout and not result.stderr
            report = json.loads((args.output / name).read_text())
            assert report["evidence_kind"] == "synthetic_fixture"
            assert report["support_status"] == "unqualified"
            assert all(item["status"] == "unavailable" for item in report["tessryn_capabilities"].values())
            assert report["measured_admission"]["status"] == "unknown"
        output = args.output / "synthetic-full.json"
        before = hashlib.sha256(output.read_bytes()).hexdigest()
        failure = subprocess.run(command + ["--out", str(output)], capture_output=True, text=True, timeout=10)
        assert failure.returncode == 2 and not failure.stdout
        assert hashlib.sha256(output.read_bytes()).hexdigest() == before
        (args.output / "cli-failure.log").write_text(failure.stderr, encoding="utf-8")
    print("synthetic full collection: exit 0")
    print("synthetic numeric publication: exit 0")
    print("existing output rejected: exit 2; original bytes unchanged")
    print("native boot / GPU execution / inference: unavailable")
    print("physical inventory / rental / performance samples: 0")


if __name__ == "__main__":
    main()
