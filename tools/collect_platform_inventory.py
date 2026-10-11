#!/usr/bin/env python3
"""Collect public Linux reference facts without probing or changing hardware.

This collector never qualifies Tessryn. Alternate filesystem roots are synthetic
fixtures, even when their data resembles a real machine. Missing facts stay
unavailable. Only regular, bounded files below the selected root are read.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys


BDF = re.compile(r"[0-9a-f]{4,8}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]")
NAME = re.compile(r"[A-Za-z0-9_.-]{1,80}")
PUBLIC_TEXT = re.compile(r"[A-Za-z0-9 ()+.,_@:-]{1,200}")
SENSITIVE_TEXT = re.compile(
    r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    r"|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
    r"|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
    r"|gh[pousr]_|github_pat_|sk-(?:proj-|svcacct-)?[A-Za-z0-9]"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{20,}"
)


def public_text(value: str, pattern: re.Pattern = PUBLIC_TEXT) -> bool:
    if not pattern.fullmatch(value) or SENSITIVE_TEXT.search(value):
        return False
    for token in value.split():
        if ":" not in token:
            continue
        try:
            ipaddress.ip_address(token.strip("()[],;"))
        except ValueError:
            continue
        return False
    return True


def unavailable(reason: str = "not_reported") -> dict:
    return {"status": "unavailable", "reason": reason}


def available(value: object) -> dict:
    return {"status": "available", "value": value}


class Inventory:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("inventory root must be a directory")
        self.diagnostics: list[dict] = []

    def problem(self, field: str, reason: str) -> None:
        # Labels describe fields, never source paths or operating-system errors.
        if len(self.diagnostics) < 128:
            item = {"field": field, "reason": reason}
            if item not in self.diagnostics:
                self.diagnostics.append(item)

    def safe(self, path: Path) -> Path:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(self.root):
            raise ValueError("outside_root")
        return resolved

    def read(self, path: Path, field: str, limit: int = 4096, *, first_record: bool = False) -> str | None:
        try:
            resolved = self.safe(path)
            # Reject device nodes and FIFOs before opening them. The second
            # check below also rejects replacement between stat and open.
            before = resolved.stat()
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("not_regular")
            fd = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                after = os.fstat(stream.fileno())
                if not stat.S_ISREG(after.st_mode):
                    raise ValueError("not_regular")
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise ValueError("file_changed")
                data = stream.read(limit + 1)
            if first_record and b"\n\n" in data:
                data = data.split(b"\n\n", 1)[0]
            if len(data) > limit:
                raise ValueError("read_limit")
            return data.decode("utf-8").strip()
        except FileNotFoundError:
            return None
        except (OSError, RuntimeError, UnicodeError, ValueError) as error:
            reason = str(error) if isinstance(error, ValueError) else "read_rejected"
            self.problem(field, reason)
            return None

    def entries(self, path: Path, field: str, limit: int, *, complete_required: bool = False) -> list[Path]:
        try:
            resolved = self.safe(path)
            entries = []
            with os.scandir(resolved) as scan:
                for entry in scan:
                    if len(entries) == limit:
                        self.problem(field, "record_limit")
                        if complete_required:
                            raise ValueError("record_limit")
                        break
                    entries.append(Path(entry.path))
            return sorted(entries, key=lambda entry: entry.name)
        except FileNotFoundError:
            return []
        except (OSError, RuntimeError, ValueError):
            self.problem(field, "directory_rejected")
            return []

    def text(self, path: Path, field: str, pattern: re.Pattern = PUBLIC_TEXT) -> dict:
        value = self.read(path, field)
        if value is None:
            return unavailable()
        if not public_text(value, pattern):
            self.problem(field, "malformed_value")
            return unavailable("malformed_value")
        return available(value)

    def number(self, path: Path, field: str, *, maximum: int, base: int = 10) -> dict:
        value = self.read(path, field)
        if value is None:
            return unavailable()
        pattern = r"(?:0x)?[0-9a-fA-F]{1,16}" if base == 16 else r"[0-9]{1,20}"
        if not re.fullmatch(pattern, value) or not 0 <= int(value, base) <= maximum:
            self.problem(field, "malformed_value")
            return unavailable("malformed_value")
        return available(int(value, base))

    def cpu(self, real_root: bool) -> dict:
        # One logical CPU is enough for this declared scope. Large machines
        # must not lose it because subsequent CPU records exceed a file cap.
        raw = self.read(self.root / "proc/cpuinfo", "cpu", 16384, first_record=True)
        if raw is None:
            return unavailable()
        first = raw.split("\n\n", 1)[0]
        values = dict(line.split(":", 1) for line in first.splitlines() if ":" in line)
        values = {key.strip(): value.strip() for key, value in values.items()}
        model = values.get("model name", values.get("Processor", ""))
        features = values.get("flags", values.get("Features", "")).split()
        if not model or not public_text(model):
            self.problem("cpu.model", "malformed_or_missing")
        if len(features) > 512 or any(not public_text(f, re.compile(r"[a-zA-Z0-9_]{1,64}")) for f in features):
            self.problem("cpu.features", "malformed_value")
            features = []
        arch = platform.machine() if real_root else ("x86_64" if "lm" in features else None)
        return {
            "status": "available",
            "scope": "first_logical_cpu",
            "architecture": available(arch) if arch else unavailable(),
            "model": available(model) if public_text(model) else unavailable(),
            "features": available(sorted(set(features))) if features else unavailable(),
            "hypervisor_present": available("hypervisor" in features) if features else unavailable(),
        }

    def memory(self) -> dict:
        raw = self.read(self.root / "proc/meminfo", "memory", 65536)
        if raw is None:
            return unavailable()
        match = re.search(r"^MemTotal:\s+([0-9]{1,16})\s+kB\s*$", raw, re.MULTILINE)
        if not match or int(match[1]) > (1 << 50):
            self.problem("memory", "malformed_value")
            return unavailable("malformed_value")
        return {"status": "available", "reference_os_usable_bytes": int(match[1]) * 1024}

    def firmware(self) -> dict:
        dmi = self.root / "sys/class/dmi/id"
        fields = {
            "vendor": "sys_vendor", "product": "product_name", "bios_vendor": "bios_vendor",
            "bios_version": "bios_version", "bios_date": "bios_date",
        }
        result = {key: self.text(dmi / file, f"dmi.{key}", re.compile(r"[0-9/.-]{1,32}") if key == "bios_date" else PUBLIC_TEXT) for key, file in fields.items()}
        bitness = self.number(self.root / "sys/firmware/efi/fw_platform_size", "uefi", maximum=64)
        if bitness.get("value") not in (32, 64):
            bitness = unavailable("not_reported_or_invalid")
        tables = {}
        for name in ("APIC", "DMAR", "IVRS"):
            path = self.root / "sys/firmware/acpi/tables" / name
            try:
                resolved = self.safe(path)
                tables[name] = {"status": "present"} if resolved.is_file() else unavailable("not_regular")
            except FileNotFoundError:
                tables[name] = unavailable()
            except (OSError, RuntimeError, ValueError):
                self.problem("acpi", "entry_rejected")
                tables[name] = unavailable("entry_rejected")
        return {"dmi": result, "uefi_bitness": bitness, "acpi_table_presence": tables}

    def iommu_group(self, device: Path) -> dict:
        try:
            group = self.safe(device / "iommu_group")
            if not re.fullmatch(r"[0-9]{1,8}", group.name):
                raise ValueError("invalid_group")
            if group != self.safe(self.root / "sys/kernel/iommu_groups" / group.name):
                raise ValueError("invalid_group")
            members = []
            for entry in self.entries(group / "devices", "iommu", 256, complete_required=True):
                if BDF.fullmatch(entry.name):
                    target = self.safe(entry)
                    expected = self.safe(self.root / "sys/bus/pci/devices" / entry.name)
                    if target != expected or self.safe(expected / "iommu_group") != group:
                        raise ValueError("group_membership_mismatch")
                    members.append(entry.name)
                else:
                    raise ValueError("invalid_group_member")
            if device.name not in members:
                raise ValueError("group_membership_mismatch")
            return available({"group": int(group.name), "members": members})
        except FileNotFoundError:
            return unavailable()
        except (OSError, RuntimeError, ValueError):
            self.problem("iommu", "membership_rejected")
            return unavailable("membership_rejected")

    def pci(self) -> dict:
        devices = []
        for entry in self.entries(self.root / "sys/bus/pci/devices", "pci", 1024):
            if not BDF.fullmatch(entry.name):
                self.problem("pci", "invalid_bdf")
                continue
            try:
                device = self.safe(entry)
                if not device.is_dir():
                    raise ValueError("not_directory")
            except (OSError, RuntimeError, ValueError):
                self.problem("pci", "device_rejected")
                continue
            item = {"bdf": entry.name}
            for field in ("vendor", "device", "subsystem_vendor", "subsystem_device", "class", "revision"):
                maximum = 0xFFFFFF if field == "class" else (0xFF if field == "revision" else 0xFFFF)
                item[field] = self.number(device / field, f"pci.{field}", maximum=maximum, base=16)
            try:
                driver = self.safe(device / "driver").name
                item["reference_os_driver"] = available(driver) if public_text(driver, NAME) else unavailable("malformed_value")
            except FileNotFoundError:
                item["reference_os_driver"] = unavailable("unbound_or_not_reported")
            except (OSError, RuntimeError, ValueError):
                self.problem("pci.driver", "link_rejected")
                item["reference_os_driver"] = unavailable("link_rejected")
            item["iommu"] = self.iommu_group(entry)
            devices.append(item)
        return {"status": "available" if devices else "unavailable", "devices": devices}

    def blocks(self) -> dict:
        devices = []
        for entry in self.entries(self.root / "sys/class/block", "block", 128):
            if not public_text(entry.name, NAME):
                self.problem("block", "invalid_name")
                continue
            try:
                self.safe(entry)
            except (OSError, RuntimeError, ValueError):
                self.problem("block", "device_rejected")
                continue
            sectors = self.number(entry / "size", "block.size", maximum=1 << 55)
            partition = self.number(entry / "partition", "block.partition", maximum=65535)
            devices.append({
                "name": entry.name,
                "kind": "partition" if partition["status"] == "available" else "block_device",
                "reference_os_scsi_type": self.number(entry / "device/type", "block.type", maximum=31),
                "model": self.text(entry / "device/model", "block.model"),
                "size_bytes": available(sectors["value"] * 512) if sectors["status"] == "available" else unavailable(),
            })
        return {"status": "available" if devices else "unavailable", "devices": devices}

    def power(self) -> dict:
        supplies = []
        for entry in self.entries(self.root / "sys/class/power_supply", "power", 128):
            if not public_text(entry.name, NAME):
                continue
            kind = self.read(entry / "type", "power.type")
            if kind != "Mains":
                continue
            supplies.append({"name": entry.name, "online": self.number(entry / "online", "power.online", maximum=1)})
        return {"status": "available" if supplies else "unavailable", "ac_supplies": supplies}


def collect(root: Path) -> dict:
    real_root = os.path.abspath(root) == "/"
    if real_root and platform.system() != "Linux":
        raise ValueError("the default root requires Linux")
    inventory = Inventory(root)
    result = {
        "schema_version": 1,
        "evidence_kind": "linux_reference_inventory" if real_root else "synthetic_fixture",
        "support_status": "unqualified",
        "collected_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "cpu": inventory.cpu(real_root),
        "memory": inventory.memory(),
        "firmware": inventory.firmware(),
        "pci": inventory.pci(),
        "block": inventory.blocks(),
        "power": inventory.power(),
        "tessryn_capabilities": {name: unavailable("not_tested_by_reference_inventory") for name in ("native_boot", "gpu_execution", "inference")},
        "measured_admission": {"status": "unknown", "reason": "no_tessryn_measurement"},
        "diagnostics": inventory.diagnostics,
    }
    return result


def public_summary(report: dict) -> dict:
    """Omit every host-provided free-form string from automatic publication.

    This is a derived inventory, not a complete device identity record. Values
    retained here originate from bounded numeric parsing, fixed collector
    states, PCI address parsing or the collector's own clock/source hash.
    """
    result = {key: report[key] for key in (
        "schema_version", "evidence_kind", "support_status", "collected_utc",
        "collector_sha256", "memory", "tessryn_capabilities",
        "measured_admission", "diagnostics",
    )}
    result["publication_profile"] = "numeric_summary"
    result["omitted_identity_fields"] = [
        "cpu_model_architecture_features", "dmi_identity", "driver_names",
        "block_names_models", "power_supply_names",
    ]
    cpu = report["cpu"]
    result["cpu"] = {"status": cpu["status"]}
    if cpu["status"] == "available":
        result["cpu"].update(scope=cpu["scope"], hypervisor_present=cpu["hypervisor_present"])
    firmware = report["firmware"]
    result["firmware"] = {key: firmware[key] for key in ("uefi_bitness", "acpi_table_presence")}
    result["pci"] = {"status": report["pci"]["status"], "devices": [
        {key: item[key] for key in ("bdf", "vendor", "device", "subsystem_vendor", "subsystem_device", "class", "revision", "iommu")}
        for item in report["pci"]["devices"]
    ]}
    result["block"] = {"status": report["block"]["status"], "devices": [
        {key: item[key] for key in ("kind", "reference_os_scsi_type", "size_bytes")}
        for item in report["block"]["devices"]
    ]}
    result["power"] = {"status": report["power"]["status"], "ac_supplies": [
        {"online": item["online"]} for item in report["power"]["ac_supplies"]
    ]}
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"), help="alternate root is always a synthetic fixture")
    parser.add_argument("--out", type=Path, help="new regular JSON file; existing paths are rejected")
    parser.add_argument("--public-summary", action="store_true", help="omit host-provided identity strings for automatic publication")
    args = parser.parse_args(argv)
    try:
        report = collect(args.root)
        if args.public_summary:
            report = public_summary(report)
        payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.out is None:
            sys.stdout.write(payload)
        else:
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("output must be a new regular file")
                stream.write(payload)
        return 0
    except (OSError, RuntimeError, ValueError):
        print("inventory collection failed: invalid root or output; existing output is never replaced", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
