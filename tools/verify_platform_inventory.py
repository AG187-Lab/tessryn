#!/usr/bin/env python3
"""Verify a retained numeric reference inventory; never qualify hardware.

The operator supplies the expected collector identity and evidence kind. This
checks structure and internal consistency, not physical custody or native access.
Full identity reports require manual public-content review and are not accepted.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


BDF = re.compile(r"[0-9a-f]{4,8}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]")
SHA = re.compile(r"[0-9a-f]{64}")
OMISSIONS = ["cpu_model_architecture_features", "dmi_identity", "driver_names",
             "block_names_models", "power_supply_names"]
REASONS = {
    "not_reported", "not_reported_or_invalid", "malformed_value", "malformed_or_missing",
    "unbound_or_not_reported", "membership_rejected", "link_rejected", "entry_rejected",
    "outside_root", "not_regular", "file_changed", "read_limit", "read_rejected",
    "record_limit", "directory_rejected", "device_rejected", "invalid_bdf", "invalid_name",
    "not_tested_by_reference_inventory", "no_tessryn_measurement",
}
FIELDS = {
    "cpu", "cpu.model", "cpu.features", "memory", "uefi", "acpi", "iommu",
    "pci", "pci.vendor", "pci.device", "pci.subsystem_vendor", "pci.subsystem_device",
    "pci.class", "pci.revision", "pci.driver", "block", "block.size", "block.partition",
    "block.type", "block.model", "power", "power.type", "power.online",
    "dmi.vendor", "dmi.product", "dmi.bios_vendor", "dmi.bios_version", "dmi.bios_date",
}
MAX_BYTES = 16 * 1024 * 1024


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("invalid inventory contract")


def keys(value: object, expected: set[str]) -> dict:
    require(type(value) is dict and set(value) == expected)
    return value


def number(value: object, maximum: int) -> None:
    require(type(value) is int and 0 <= value <= maximum)


def array(value: object, maximum: int) -> list:
    require(type(value) is list and len(value) <= maximum)
    return value


def fact(value: object, check, *, present: bool = False) -> None:
    require(type(value) is dict)
    if value.get("status") == "unavailable":
        keys(value, {"status", "reason"})
        require(value["reason"] in REASONS)
    elif present and value.get("status") == "present":
        keys(value, {"status"})
    else:
        keys(value, {"status", "value"})
        require(value["status"] == "available")
        check(value["value"])


def collection(value: object, member: str, maximum: int) -> list:
    keys(value, {"status", member})
    members = array(value[member], maximum)
    require(value["status"] == ("available" if members else "unavailable"))
    return members


def validate(report: object, expected_sha: str, expected_kind: str) -> None:
    keys(report, {"schema_version", "evidence_kind", "support_status", "collected_utc",
                  "collector_sha256", "cpu", "memory", "firmware", "pci", "block",
                  "power", "tessryn_capabilities", "measured_admission", "diagnostics",
                  "publication_profile", "omitted_identity_fields"})
    require(type(report["schema_version"]) is int and report["schema_version"] == 1)
    require(expected_kind in {"synthetic_fixture", "linux_reference_inventory"})
    require(report["evidence_kind"] == expected_kind and report["support_status"] == "unqualified")
    require(type(expected_sha) is str and SHA.fullmatch(expected_sha) is not None)
    require(report["collector_sha256"] == expected_sha)
    require(report["publication_profile"] == "numeric_summary")
    require(report["omitted_identity_fields"] == OMISSIONS)
    require(type(report["collected_utc"]) is str and len(report["collected_utc"]) <= 40)
    timestamp = datetime.datetime.fromisoformat(report["collected_utc"])
    require(timestamp.utcoffset() == datetime.timedelta(0))
    capabilities = keys(report["tessryn_capabilities"], {"native_boot", "gpu_execution", "inference"})
    for value in capabilities.values():
        require(value == {"status": "unavailable", "reason": "not_tested_by_reference_inventory"})
    require(report["measured_admission"] == {"status": "unknown", "reason": "no_tessryn_measurement"})
    cpu = report["cpu"]
    require(type(cpu) is dict)
    if cpu.get("status") == "available":
        keys(cpu, {"status", "scope", "hypervisor_present"})
        require(cpu["scope"] == "first_logical_cpu")
        fact(cpu["hypervisor_present"], lambda value: require(type(value) is bool))
    else:
        keys(cpu, {"status"})
        require(cpu["status"] == "unavailable")
    memory = report["memory"]
    if type(memory) is dict and memory.get("status") == "available":
        keys(memory, {"status", "reference_os_usable_bytes"})
        number(memory["reference_os_usable_bytes"], 1 << 60)
        require(memory["reference_os_usable_bytes"] % 1024 == 0)
    else:
        fact(memory, lambda value: require(False))
    firmware = keys(report["firmware"], {"uefi_bitness", "acpi_table_presence"})
    fact(firmware["uefi_bitness"], lambda value: require(type(value) is int and value in (32, 64)))
    tables = keys(firmware["acpi_table_presence"], {"APIC", "DMAR", "IVRS"})
    for value in tables.values():
        fact(value, lambda value: require(False), present=True)
    devices = collection(report["pci"], "devices", 1024)
    by_bdf = {}
    for device in devices:
        keys(device, {"bdf", "vendor", "device", "subsystem_vendor", "subsystem_device",
                      "class", "revision", "iommu"})
        require(type(device["bdf"]) is str and BDF.fullmatch(device["bdf"]) is not None)
        require(device["bdf"] not in by_bdf)
        by_bdf[device["bdf"]] = device
        for name in ("vendor", "device", "subsystem_vendor", "subsystem_device", "class", "revision"):
            maximum = 0xFFFFFF if name == "class" else (0xFF if name == "revision" else 0xFFFF)
            fact(device[name], lambda value, cap=maximum: number(value, cap))

        def group(value):
            keys(value, {"group", "members"})
            number(value["group"], 99999999)
            members = array(value["members"], 256)
            require(all(type(x) is str and BDF.fullmatch(x) for x in members))
            require(len(members) == len(set(members)) and members == sorted(members))
            require(device["bdf"] in members)

        fact(device["iommu"], group)
    groups = {}
    for device in devices:
        iommu = device["iommu"]
        if iommu["status"] != "available":
            continue
        group = iommu["value"]
        require(groups.setdefault(group["group"], group["members"]) == group["members"])
        # A truncated PCI list may omit group peers. Any retained peer must agree.
        for peer in group["members"]:
            if peer in by_bdf and by_bdf[peer]["iommu"]["status"] == "available":
                require(by_bdf[peer]["iommu"] == iommu)
    for device in collection(report["block"], "devices", 128):
        keys(device, {"kind", "reference_os_scsi_type", "size_bytes"})
        require(device["kind"] in {"partition", "block_device"})
        fact(device["reference_os_scsi_type"], lambda value: number(value, 31))
        fact(device["size_bytes"], lambda value: (number(value, 1 << 64), require(value % 512 == 0)))
    for supply in collection(report["power"], "ac_supplies", 128):
        keys(supply, {"online"})
        fact(supply["online"], lambda value: number(value, 1))
    for item in array(report["diagnostics"], 128):
        keys(item, {"field", "reason"})
        require(item["field"] in FIELDS)
        require(item["reason"] in REASONS)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def read_report(path: Path) -> tuple[object, str]:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        after = os.fstat(stream.fileno())
        require(stat.S_ISREG(after.st_mode) and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino))
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES)
    report = json.loads(data, object_pairs_hook=pairs,
                        parse_constant=lambda value: require(False))
    return report, hashlib.sha256(data).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-kind", required=True,
                        choices=("synthetic_fixture", "linux_reference_inventory"))
    parser.add_argument("--collector-sha256", help="expected historical source hash; default is current collector")
    args = parser.parse_args(argv)
    try:
        digest = args.collector_sha256 or hashlib.sha256(
            Path(__file__).with_name("collect_platform_inventory.py").read_bytes()).hexdigest()
        report, report_hash = read_report(args.report)
        validate(report, digest, args.expected_kind)
        print(f"Verified numeric inventory contract and collector identity; report SHA-256 {report_hash}.")
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        print("inventory verification failed: invalid report, publication contract or collector identity", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
