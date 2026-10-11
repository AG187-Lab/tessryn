"""Original synthetic fixtures verify collection safety, never hardware support."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "tools/collect_platform_inventory.py"
SPEC = importlib.util.spec_from_file_location("platform_inventory", SCRIPT)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "fixture"
        self.root.mkdir()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def device(self, bdf="0000:01:00.0"):
        base = f"sys/bus/pci/devices/{bdf}"
        for field, value in {"vendor": "0x10de", "device": "0x1234", "class": "0x030000", "subsystem_vendor": "0x1028", "subsystem_device": "0xabcd", "revision": "0x01"}.items():
            self.write(f"{base}/{field}", value)
        return self.root / base

    def copied_collector(self):
        source = Path(self.temp.name) / "collector.py"
        source.write_bytes(SCRIPT.read_bytes())
        spec = importlib.util.spec_from_file_location("copied_inventory", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return source, module

    def test_public_whitelist_and_fixture_classification(self):
        self.write("proc/cpuinfo", "processor: 0\nmodel name: Original Fixture CPU\nflags: lm sse2 hypervisor\n\n")
        self.write("proc/meminfo", "MemTotal: 2048 kB\n")
        self.write("sys/class/dmi/id/product_name", "Fixture Notebook")
        self.write("sys/class/dmi/id/product_serial", "PRIVATE_SERIAL")
        self.write("sys/class/dmi/id/product_uuid", "PRIVATE_UUID")
        self.write("etc/hostname", "PRIVATE_HOST")
        self.write("sys/class/net/eth0/address", "PRIVATE_MAC")
        self.write("sys/class/block/nvme0n1/device/serial", "PRIVATE_DISK_SERIAL")
        self.write("sys/class/block/nvme0n1/device/model", "Fixture NVMe")
        self.write("sys/class/block/nvme0n1/size", "16")
        result = inventory.collect(self.root)
        encoded = json.dumps(result)
        self.assertNotIn("PRIVATE", encoded)
        self.assertNotIn(str(self.root), encoded)
        self.assertEqual(result["evidence_kind"], "synthetic_fixture")
        self.assertEqual(result["support_status"], "unqualified")
        self.assertEqual(result["cpu"]["architecture"]["value"], "x86_64")
        self.assertTrue(result["cpu"]["hypervisor_present"]["value"])
        self.assertEqual(result["memory"]["reference_os_usable_bytes"], 2048 * 1024)
        self.assertEqual(result["block"]["devices"][0]["size_bytes"]["value"], 8192)
        self.assertEqual(result["measured_admission"]["status"], "unknown")
        self.assertTrue(all(item["status"] == "unavailable" for item in result["tessryn_capabilities"].values()))

    def test_iommu_membership_correlates_with_pci_device_and_driver(self):
        first = self.device()
        second = self.device("0000:01:00.1")
        group = self.root / "sys/kernel/iommu_groups/7"
        (group / "devices").mkdir(parents=True)
        driver = self.root / "sys/bus/pci/drivers/fixture_driver"
        driver.mkdir(parents=True)
        for device in (first, second):
            (device / "iommu_group").symlink_to(group)
            (group / "devices" / device.name).symlink_to(device)
            (device / "driver").symlink_to(driver)
        result = inventory.collect(self.root)
        item = result["pci"]["devices"][0]
        self.assertEqual(item["vendor"]["value"], 0x10DE)
        self.assertEqual(item["reference_os_driver"]["value"], "fixture_driver")
        self.assertEqual(item["iommu"]["value"], {"group": 7, "members": [first.name, second.name]})

    def test_mismatched_iommu_membership_rejected(self):
        device = self.device()
        group = self.root / "sys/kernel/iommu_groups/3"
        (group / "devices").mkdir(parents=True)
        (device / "iommu_group").symlink_to(group)
        result = inventory.collect(self.root)
        self.assertEqual(result["pci"]["devices"][0]["iommu"]["reason"], "membership_rejected")

    def test_sparse_root_reports_unknown_facts(self):
        result = inventory.collect(self.root)
        self.assertEqual(result["cpu"]["status"], "unavailable")
        self.assertEqual(result["memory"]["status"], "unavailable")
        self.assertEqual(result["firmware"]["uefi_bitness"]["status"], "unavailable")
        self.assertTrue(all(item["status"] == "unavailable" for item in result["firmware"]["acpi_table_presence"].values()))
        self.assertEqual(result["pci"]["status"], "unavailable")
        self.assertEqual(result["power"]["status"], "unavailable")

    def test_extended_linux_pci_domain_and_revision_are_preserved(self):
        device = self.device("10000:02:05.0")
        result = inventory.collect(self.root)
        item = result["pci"]["devices"][0]
        self.assertEqual(item["bdf"], device.name)
        self.assertEqual(item["revision"]["value"], 1)
        self.assertEqual(inventory.public_summary(result)["pci"]["devices"][0]["bdf"], device.name)

    def test_uefi_acpi_and_mains(self):
        self.write("sys/firmware/efi/fw_platform_size", "64")
        self.write("sys/firmware/acpi/tables/APIC", "original table fixture")
        self.write("sys/class/power_supply/AC/type", "Mains")
        self.write("sys/class/power_supply/AC/online", "1")
        self.write("sys/class/power_supply/BAT0/type", "Battery")
        self.write("sys/class/power_supply/BAT0/serial_number", "PRIVATE_BATTERY")
        result = inventory.collect(self.root)
        self.assertEqual(result["firmware"]["uefi_bitness"]["value"], 64)
        self.assertEqual(result["firmware"]["acpi_table_presence"]["APIC"]["status"], "present")
        self.assertEqual(result["power"]["ac_supplies"], [{"name": "AC", "online": {"status": "available", "value": 1}}])

    def test_malformed_numeric_values_and_private_text_are_unavailable(self):
        self.write("proc/meminfo", "MemTotal: -1 kB")
        self.write("sys/firmware/efi/fw_platform_size", "128")
        self.write("sys/class/dmi/id/bios_version", "/private/local/workspace")
        self.write("sys/class/block/sda/size", "9" * 100)
        device = self.device()
        (device / "vendor").write_text("0x10000")
        result = inventory.collect(self.root)
        self.assertEqual(result["memory"]["status"], "unavailable")
        self.assertEqual(result["pci"]["devices"][0]["vendor"]["status"], "unavailable")
        self.assertEqual(result["block"]["devices"][0]["size_bytes"]["status"], "unavailable")
        self.assertNotIn("/private", json.dumps(result))

    def test_escaping_symlink_and_fifo_rejected_without_read(self):
        outside = Path(self.temp.name) / "private"
        outside.write_text("PRIVATE_ESCAPE")
        cpu = self.root / "proc/cpuinfo"
        cpu.parent.mkdir()
        cpu.symlink_to(outside)
        fifo = self.root / "proc/meminfo"
        os.mkfifo(fifo)
        with mock.patch.object(inventory.os, "open", wraps=os.open) as opened:
            result = inventory.collect(self.root)
        self.assertFalse(any(call.args[0] in (fifo, "meminfo") for call in opened.call_args_list))
        self.assertEqual(result["cpu"]["status"], "unavailable")
        self.assertEqual(result["memory"]["status"], "unavailable")
        self.assertNotIn("PRIVATE_ESCAPE", json.dumps(result))
        self.assertEqual({item["reason"] for item in result["diagnostics"]}, {"outside_root", "not_regular"})

    def test_oversized_and_non_utf8_reads_rejected(self):
        self.write("proc/cpuinfo", "x" * 262145)
        path = self.write("sys/class/dmi/id/product_name", "placeholder")
        path.write_bytes(b"\xff")
        result = inventory.collect(self.root)
        self.assertEqual(result["cpu"]["status"], "unavailable")
        self.assertEqual(result["firmware"]["dmi"]["product"]["status"], "unavailable")

    def test_record_counts_bounded(self):
        for i in range(130):
            self.write(f"sys/class/block/loop{i}/size", "0")
        result = inventory.collect(self.root)
        self.assertEqual(len(result["block"]["devices"]), 128)
        self.assertIn({"field": "block", "reason": "record_limit"}, result["diagnostics"])

    def test_identity_text_rejects_network_identifiers_and_credentials(self):
        for value in ("Example test-user@private.example", "PRIVATE 192.0.2.123", "Reference host 2001:db8::1", "PRIVATE 00:11:22:33:44:55", "PRIVATE 12345678-1234-1234-1234-123456789abc", "ghp_SYNTHETIC_EXAMPLE_TOKEN_1234567890123456"):
            with self.subTest(value=value):
                self.write("proc/cpuinfo", f"model name: {value}\nflags: lm\n\n")
                self.write("sys/class/dmi/id/product_name", value)
                self.write("sys/class/block/sda/device/model", value)
                result = inventory.collect(self.root)
                self.assertNotIn(value, json.dumps(result))
                self.assertEqual(result["cpu"]["model"]["status"], "unavailable")
                self.assertEqual(result["firmware"]["dmi"]["product"]["status"], "unavailable")

    def test_large_cpu_file_keeps_only_first_logical_cpu(self):
        first = "processor: 0\nmodel name: Example CPU @ 2.60GHz\nflags: lm sse2\n\n"
        self.write("proc/cpuinfo", first + "x" * 400000)
        result = inventory.collect(self.root)
        self.assertEqual(result["cpu"]["model"]["value"], "Example CPU @ 2.60GHz")
        self.assertEqual(result["cpu"]["scope"], "first_logical_cpu")

    def test_nonreciprocal_iommu_group_is_rejected(self):
        first, second = self.device(), self.device("0000:01:00.1")
        groups = [self.root / f"sys/kernel/iommu_groups/{number}" for number in (7, 8)]
        for group in groups:
            (group / "devices").mkdir(parents=True)
        (first / "iommu_group").symlink_to(groups[0])
        (second / "iommu_group").symlink_to(groups[1])
        for device in (first, second):
            (groups[0] / "devices" / device.name).symlink_to(device)
        (groups[1] / "devices" / second.name).symlink_to(second)
        result = inventory.collect(self.root)
        self.assertEqual(result["pci"]["devices"][0]["iommu"]["status"], "unavailable")
        self.assertEqual(result["pci"]["devices"][1]["iommu"]["status"], "available")

    def test_real_root_cannot_claim_linux_reference_on_another_os(self):
        with mock.patch.object(inventory.platform, "system", return_value="Darwin"):
            with self.assertRaises(ValueError):
                inventory.collect(Path("/"))

    def test_truncated_iommu_group_cannot_appear_complete(self):
        group = self.root / "sys/kernel/iommu_groups/7"
        (group / "devices").mkdir(parents=True)
        first = None
        for number in range(257):
            device = self.device(f"0000:{number // 32:02x}:{number % 32:02x}.0")
            (device / "iommu_group").symlink_to(group)
            (group / "devices" / device.name).symlink_to(device)
            first = first or device
        reader = inventory.Inventory(self.root)
        result = reader.iommu_group(first)
        self.assertEqual(result["status"], "unavailable")
        self.assertIn({"field": "iommu", "reason": "record_limit"}, reader.diagnostics)

    def test_replaced_file_is_not_read_as_the_validated_source(self):
        path = self.write("proc/meminfo", "MemTotal: 2048 kB").resolve()
        real_open = os.open

        def replace_then_open(name, flags, **kwargs):
            if name == "meminfo":
                path.rename(path.with_name("original-meminfo"))
                path.write_text("PRIVATE_REPLACEMENT")
            return real_open(name, flags, **kwargs)

        reader = inventory.Inventory(self.root)
        with mock.patch.object(inventory.os, "open", side_effect=replace_then_open):
            result = reader.memory()
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("PRIVATE_REPLACEMENT", json.dumps(result))
        self.assertIn({"field": "memory", "reason": "file_changed"}, reader.diagnostics)

    def test_replaced_parent_symlink_cannot_read_outside_fixture(self):
        self.write("proc/meminfo", "MemTotal: 2048 kB")
        outside = Path(self.temp.name).resolve() / "outside"
        outside.mkdir()
        (outside / "meminfo").write_text("MemTotal: 999999 kB")
        reader = inventory.Inventory(self.root)
        self.addCleanup(reader.close)
        safe = reader.safe
        path = reader.root / "proc/meminfo"

        def resolve_then_replace(name):
            resolved = safe(name)
            if name == path:
                (reader.root / "proc").rename(reader.root / "original-proc")
                (reader.root / "proc").symlink_to(outside, target_is_directory=True)
            return resolved

        with mock.patch.object(reader, "safe", side_effect=resolve_then_replace):
            result = reader.memory()
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn(999999 * 1024, result.values())
        self.assertIn({"field": "memory", "reason": "read_rejected"}, reader.diagnostics)

    def test_replaced_directory_cannot_enumerate_outside_fixture(self):
        devices = self.root / "sys/class/block"
        devices.mkdir(parents=True)
        outside = Path(self.temp.name).resolve() / "outside"
        outside.mkdir()
        (outside / "PRIVATE_DEVICE").mkdir()
        reader = inventory.Inventory(self.root)
        self.addCleanup(reader.close)
        safe = reader.safe
        path = reader.root / "sys/class/block"
        swapped = False

        def resolve_then_replace(name):
            nonlocal swapped
            resolved = safe(name)
            if name == path and not swapped:
                path.rename(path.with_name("original-block"))
                path.symlink_to(outside, target_is_directory=True)
                swapped = True
            return resolved

        with mock.patch.object(reader, "safe", side_effect=resolve_then_replace):
            result = reader.entries(path, "block", 128)
        self.assertEqual(result, [])
        self.assertIn({"field": "block", "reason": "directory_rejected"}, reader.diagnostics)

    def test_root_descriptor_keeps_authority_when_root_path_is_replaced(self):
        self.write("proc/meminfo", "MemTotal: 2048 kB")
        reader = inventory.Inventory(self.root)
        self.addCleanup(reader.close)
        original = reader.root.with_name("original-fixture")
        reader.root.rename(original)
        reader.root.mkdir()
        (reader.root / "proc").mkdir()
        (reader.root / "proc/meminfo").write_text("MemTotal: 999999 kB")
        result = reader.memory()
        self.assertEqual(result["reference_os_usable_bytes"], 2048 * 1024)

    def test_unrelated_driver_target_is_not_reported_as_a_pci_driver(self):
        device = self.device()
        unrelated = self.root / "PRIVATE_DRIVER"
        unrelated.mkdir()
        (device / "driver").symlink_to(unrelated)
        result = inventory.collect(self.root)
        self.assertEqual(result["pci"]["devices"][0]["reference_os_driver"]["status"], "unavailable")
        self.assertNotIn("PRIVATE_DRIVER", json.dumps(result))

    def test_regular_file_is_not_reported_as_a_block_device(self):
        self.write("sys/class/block/not-a-device", "original fixture")
        result = inventory.collect(self.root)
        self.assertEqual(result["block"]["devices"], [])
        self.assertIn({"field": "block", "reason": "device_rejected"}, result["diagnostics"])

    def test_missing_and_valid_partition_facts_classify_blocks(self):
        self.write("sys/class/block/whole/size", "16")
        self.write("sys/class/block/part/size", "8")
        self.write("sys/class/block/part/partition", "1")
        result = inventory.collect(self.root)
        self.assertEqual([(item["name"], item["kind"]) for item in result["block"]["devices"]],
                         [("part", "partition"), ("whole", "block_device")])

    def test_rejected_partition_facts_do_not_claim_whole_devices(self):
        for value in ("malformed", "0", "65536"):
            with self.subTest(value=value):
                self.write("sys/class/block/fixture0/size", "16")
                self.write("sys/class/block/fixture0/partition", value)
                result = inventory.collect(self.root)
                self.assertEqual(result["block"]["devices"], [])
                self.assertIn({"field": "block.partition", "reason": "entry_rejected"}, result["diagnostics"])

    def test_dangling_and_nonregular_partition_fields_are_rejected(self):
        self.write("sys/class/block/dangling/size", "16")
        (self.root / "sys/class/block/dangling/partition").symlink_to(self.root / "MISSING")
        self.write("sys/class/block/fifo/size", "16")
        os.mkfifo(self.root / "sys/class/block/fifo/partition")
        self.write("sys/class/block/linked/size", "16")
        target = self.write("valid-partition-target", "1")
        (self.root / "sys/class/block/linked/partition").symlink_to(target)
        result = inventory.collect(self.root)
        self.assertEqual(result["block"]["devices"], [])
        self.assertIn({"field": "block.partition", "reason": "entry_rejected"}, result["diagnostics"])

    def test_decode_errors_do_not_publish_exception_text(self):
        path = self.write("proc/cpuinfo", "original fixture")
        path.write_bytes(b"\xff")
        result = inventory.collect(self.root)
        self.assertEqual(result["cpu"]["status"], "unavailable")
        self.assertIn({"field": "cpu", "reason": "read_rejected"}, result["diagnostics"])
        self.assertNotIn("codec", json.dumps(result))

    def test_public_summary_omits_unrecognizable_private_identity_strings(self):
        self.write("proc/cpuinfo", "model name: PRIVATE_MODEL\nflags: lm PRIVATE_FEATURE\n\n")
        self.write("sys/class/dmi/id/product_name", "PRIVATE_PRODUCT")
        self.write("sys/class/dmi/id/bios_version", "PRIVATE_BIOS")
        self.write("sys/class/block/PRIVATE_BLOCK/device/model", "PRIVATE_DISK")
        self.write("sys/class/block/PRIVATE_BLOCK/size", "16")
        self.write("sys/class/power_supply/PRIVATE_AC/type", "Mains")
        self.write("sys/class/power_supply/PRIVATE_AC/online", "1")
        device = self.device()
        driver = self.root / "sys/bus/pci/drivers/PRIVATE_DRIVER"
        driver.mkdir(parents=True)
        (device / "driver").symlink_to(driver)
        full = inventory.collect(self.root)
        self.assertIn("PRIVATE", json.dumps(full))
        summary = inventory.public_summary(full)
        self.assertNotIn("PRIVATE", json.dumps(summary))
        self.assertEqual(summary["publication_profile"], "numeric_summary")
        self.assertEqual(summary["pci"]["devices"][0]["vendor"]["value"], 0x10DE)
        self.assertEqual(summary["block"]["devices"][0]["size_bytes"]["value"], 8192)
        self.assertEqual(summary["collector_sha256"], full["collector_sha256"])
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(inventory.main(["--root", str(self.root), "--public-summary"]), 0)
        self.assertNotIn("PRIVATE", stdout.getvalue())

    def test_stdout_and_no_overwrite_or_symlink_output(self):
        output = Path(self.temp.name) / "inventory.json"
        self.assertEqual(inventory.main(["--root", str(self.root), "--out", str(output)]), 0)
        original = output.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(inventory.main(["--root", str(self.root), "--out", str(output)]), 2)
            link = Path(self.temp.name) / "output-link"
            link.symlink_to(output)
            self.assertEqual(inventory.main(["--root", str(self.root), "--out", str(link)]), 2)
        self.assertEqual(output.read_bytes(), original)
        fifo = Path(self.temp.name) / "output-fifo"
        os.mkfifo(fifo)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(inventory.main(["--root", str(self.root), "--out", str(fifo)]), 2)
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(inventory.main(["--root", str(self.root)]), 0)
        self.assertEqual(json.loads(stdout.getvalue())["evidence_kind"], "synthetic_fixture")

    def test_changed_loaded_source_cannot_publish_new_source_identity(self):
        source, module = self.copied_collector()
        source.write_text(source.read_text() + "\n# Changed after loading.\n")
        output = Path(self.temp.name) / "rejected.json"
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(module.main(["--root", str(self.root), "--out", str(output)]), 2)
        self.assertFalse(output.exists())
        self.assertIn("invalid source", stderr.getvalue())
        self.assertNotIn(str(source), stderr.getvalue())

    def test_source_changed_during_collection_prevents_publication(self):
        source, module = self.copied_collector()
        original_power = module.Inventory.power

        def change_source(reader):
            source.write_text(source.read_text() + "\n# Changed while collecting.\n")
            return original_power(reader)

        with mock.patch.object(module.Inventory, "power", change_source):
            with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(module.main(["--root", str(self.root)]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(str(source), stderr.getvalue())

    def test_source_unavailable_at_initialization_is_a_fixed_cli_failure(self):
        source = Path(self.temp.name) / "PRIVATE_STARTUP.py"
        source.write_bytes(SCRIPT.read_bytes())
        launch = """
from pathlib import Path
import sys
source = Path(sys.argv[1])
contents = source.read_text()
source.unlink()
sys.argv = [str(source), '--root', sys.argv[2]]
exec(compile(contents, str(source), 'exec'), {'__file__': str(source), '__name__': '__main__'})
"""
        result = subprocess.run([sys.executable, "-c", launch, str(source), str(self.root)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("invalid source", result.stderr)
        self.assertNotIn("PRIVATE_STARTUP", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_deferred_stdout_failure_is_reported_before_success(self):
        class FailedFlush(io.StringIO):
            def flush(self):
                raise OSError("PRIVATE_OUTPUT_DETAIL")

        with contextlib.redirect_stdout(FailedFlush()), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(inventory.main(["--root", str(self.root)]), 2)
        self.assertIn("inventory collection failed", stderr.getvalue())
        self.assertNotIn("PRIVATE_OUTPUT_DETAIL", stderr.getvalue())

    def test_closed_stdout_pipe_exits_with_explicit_failure(self):
        process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--root", str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        process.stdout.close()
        self.addCleanup(process.stderr.close)
        try:
            self.assertEqual(process.wait(timeout=5), 2)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        stderr = process.stderr.read().decode("utf-8")
        self.assertIn("inventory collection failed", stderr)
        self.assertNotIn("Exception ignored", stderr)
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
