"""Independent fixed-disk GPT/FAT32 parsing and upload-integrity checks."""

import copy
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import uuid
import zlib

from tools import aws_media


def uint(data, offset, size=4):
    return int.from_bytes(data[offset:offset + size], "little")


class AwsMediaTests(unittest.TestCase):
    payload = bytes(range(256)) * 313 + b"original-native-efi-tail"

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="tessryn-aws-media-")
        cls.root = Path(cls.directory.name)
        cls.path = cls.root / "boot.raw"
        cls.manifest = aws_media.write_disk(cls.path, cls.payload)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def read_at(self, offset, length):
        with self.path.open("rb") as stream:
            stream.seek(offset)
            return stream.read(length)

    def gpt(self, lba):
        raw = self.read_at(lba * 512, 512)
        self.assertEqual(raw[:8], b"EFI PART")
        self.assertEqual(uint(raw, 8), 0x10000)
        size = uint(raw, 12)
        self.assertEqual(size, 92)
        checksum = uint(raw, 16)
        header = bytearray(raw[:size])
        header[16:20] = bytes(4)
        self.assertEqual(zlib.crc32(header), checksum)
        self.assertEqual(raw[size:], bytes(512 - size))
        self.assertEqual(uint(raw, 20), 0)
        table_lba, count, entry_size, table_checksum = struct.unpack_from("<QIII", raw, 72)
        self.assertEqual(count, 128)
        self.assertEqual(entry_size, 128)
        table = self.read_at(table_lba * 512, count * entry_size)
        self.assertEqual(zlib.crc32(table), table_checksum)
        return raw, table

    def test_protective_mbr_and_gpt_backup_at_actual_disk_end(self):
        self.assertEqual(self.path.stat().st_size, 1 << 30)
        last = (1 << 30) // 512 - 1
        mbr = self.read_at(0, 512)
        self.assertEqual(mbr[:446], bytes(446))
        self.assertEqual(mbr[450], 0xee)
        self.assertEqual(uint(mbr, 454), 1)
        self.assertEqual(uint(mbr, 458), last)
        self.assertEqual(mbr[462:510], bytes(48))
        self.assertEqual(mbr[510:], b"\x55\xaa")
        primary, table = self.gpt(1)
        backup, backup_table = self.gpt(last)
        self.assertEqual(table, backup_table)
        self.assertEqual(struct.unpack_from("<QQQQ", primary, 24), (1, last, 34, last - 33))
        self.assertEqual(struct.unpack_from("<QQQQ", backup, 24), (last, 1, 34, last - 33))
        self.assertEqual(uint(primary, 72, 8), 2)
        self.assertEqual(uint(backup, 72, 8), last - 32)
        self.assertEqual(primary[56:72], backup[56:72])
        self.assertNotEqual(primary[56:72], bytes(16))
        self.assertEqual(uuid.UUID(bytes_le=table[:16]),
                         uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"))
        self.assertNotEqual(table[16:32], bytes(16))
        self.assertEqual(struct.unpack_from("<QQQ", table, 32), (2048, 133119, 0))
        self.assertEqual(table[56:128].decode("utf-16le").rstrip("\0"), "Tessryn AWS ESP")
        self.assertEqual(table[128:], bytes(127 * 128))

    def test_independent_fat32_chain_and_payload_recovery(self):
        esp = 2048 * 512
        boot = self.read_at(esp, 512)
        self.assertEqual(boot[510:], b"\x55\xaa")
        sector = uint(boot, 11, 2)
        cluster_sectors = boot[13]
        reserved = uint(boot, 14, 2)
        copies = boot[16]
        fat_sectors = uint(boot, 36)
        sectors = uint(boot, 32)
        self.assertEqual((sector, cluster_sectors, reserved, copies), (512, 1, 32, 2))
        self.assertEqual(uint(boot, 17, 2), 0)  # FAT32 has no fixed root area.
        self.assertEqual(uint(boot, 19, 2), 0)
        self.assertEqual(uint(boot, 22, 2), 0)
        self.assertEqual(uint(boot, 28), 2048)
        self.assertEqual(sectors * sector, 64 * 1024 * 1024)
        self.assertEqual(uint(boot, 40, 2), 0)  # Both FATs are mirrored.
        self.assertEqual(uint(boot, 42, 2), 0)
        self.assertEqual(boot[52:64], bytes(12))
        self.assertEqual(boot[82:90], b"FAT32   ")
        data_sector = reserved + copies * fat_sectors
        clusters = (sectors - data_sector) // cluster_sectors
        self.assertGreaterEqual(clusters, 65525)  # Classification, not label.
        self.assertLess(clusters, 0x0ffffff5)
        fat = self.read_at(esp + reserved * sector, fat_sectors * sector)
        self.assertGreaterEqual(len(fat), 4 * (clusters + 2))
        self.assertEqual(fat, self.read_at(esp + (reserved + fat_sectors) * sector,
                                        fat_sectors * sector))
        self.assertEqual(uint(fat, 0) & 0xfffffff, 0xffffff8)
        self.assertEqual(uint(fat, 4) & 0xfffffff, 0xfffffff)
        allocated = set()

        def chain(first):
            contents = bytearray()
            visited = set()
            cluster = first
            while cluster < 0x0ffffff8:
                self.assertTrue(2 <= cluster < clusters + 2)
                self.assertNotIn(cluster, visited)
                self.assertNotIn(cluster, allocated)
                visited.add(cluster)
                allocated.add(cluster)
                offset = esp + (data_sector + (cluster - 2) * cluster_sectors) * sector
                contents.extend(self.read_at(offset, cluster_sectors * sector))
                cluster = uint(fat, 4 * cluster) & 0xfffffff
            return bytes(contents)

        def directory(contents):
            entries = {}
            for offset in range(0, len(contents), 32):
                entry = contents[offset:offset + 32]
                if not entry[0]:
                    self.assertEqual(contents[offset:], bytes(len(contents) - offset))
                    break
                if entry[11] == 0x08:
                    continue
                self.assertEqual(entry[11] & 0x0f, 0)  # No long-name entries.
                for at in (16, 18, 24):
                    self.assertEqual(uint(entry, at, 2), 0x21)
                self.assertEqual(entry[12:16], bytes(4))
                self.assertEqual(entry[22:24], bytes(2))
                entries[entry[:11]] = entry
            return entries

        def first(entry):
            return uint(entry, 20, 2) << 16 | uint(entry, 26, 2)

        root = directory(chain(uint(boot, 44)))
        self.assertEqual(set(root), {b"EFI        "})
        self.assertEqual(root[b"EFI        "][11], 0x10)
        efi = directory(chain(first(root[b"EFI        "])))
        self.assertEqual(set(efi), {b".          ", b"..         ", b"BOOT       "})
        self.assertEqual(first(efi[b"..         "]), 0)
        self.assertEqual(first(efi[b".          "]), first(root[b"EFI        "]))
        directory_boot = directory(chain(first(efi[b"BOOT       "])))
        self.assertEqual(set(directory_boot), {b".          ", b"..         ", b"BOOTX64 EFI"})
        self.assertEqual(first(directory_boot[b"..         "]), first(root[b"EFI        "]))
        entry = directory_boot[b"BOOTX64 EFI"]
        self.assertEqual(entry[11], 0x20)
        size = uint(entry, 28)
        recovered = chain(first(entry))
        self.assertEqual(size, len(self.payload))
        self.assertEqual(recovered[:size], self.payload)
        self.assertEqual(recovered[size:], bytes(len(recovered) - size))
        allocated_from_fat = {cluster for cluster in range(2, clusters + 2)
                              if uint(fat, 4 * cluster) & 0xfffffff}
        self.assertEqual(allocated_from_fat, allocated)
        info_sector = uint(boot, 48, 2)
        backup_sector = uint(boot, 50, 2)
        self.assertEqual((info_sector, backup_sector), (1, 6))
        info = self.read_at(esp + info_sector * sector, sector)
        self.assertEqual(uint(info, 0), 0x41615252)
        self.assertEqual(uint(info, 484), 0x61417272)
        self.assertEqual(uint(info, 488), clusters - len(allocated))
        self.assertEqual(uint(info, 492), max(allocated) + 1)
        self.assertEqual(uint(info, 508), 0xaa550000)
        self.assertEqual(info[4:484], bytes(480))
        self.assertEqual(info[496:508], bytes(12))
        self.assertEqual(boot, self.read_at(esp + backup_sector * sector, sector))
        self.assertEqual(info, self.read_at(esp + (backup_sector + info_sector) * sector, sector))

    def test_sparse_file_and_zero_gap(self):
        self.assertLess(self.path.stat().st_blocks * 512, 64 * 1024 * 1024)
        self.assertEqual(self.read_at(80 * 1024 * 1024, 512 * 1024), bytes(512 * 1024))
        self.assertEqual(self.read_at(34 * 512, 2048 * 512 - 34 * 512),
                         bytes(2048 * 512 - 34 * 512))

    def test_metadata_upload_blocks_and_whole_disk_hash(self):
        digest = hashlib.sha256()
        with self.path.open("rb") as stream:
            while block := stream.read(512 * 1024):
                digest.update(block)
        self.assertEqual(digest.hexdigest(), self.manifest["sha256"])
        self.assertEqual(self.manifest["efi_sha256"], hashlib.sha256(self.payload).hexdigest())
        actual = [{"index": index, "sha256": hashlib.sha256(block).hexdigest(),
                   "size_bytes": len(block)}
                  for index, block in aws_media.iter_blocks(self.path, self.manifest)]
        self.assertEqual(actual, self.manifest["nonzero_blocks"])
        self.assertEqual(actual[-1]["index"], 2047)  # Backup GPT upload cannot be omitted.

    def test_reproducible_new_files_and_verification(self):
        other = self.root / "repeat.raw"
        self.assertEqual(aws_media.write_disk(other, self.payload), self.manifest)
        self.assertEqual(aws_media.verify_disk(other, self.payload), self.manifest)

    def test_new_file_only_and_symlink_fifo_refusal(self):
        existing = self.root / "existing"
        existing.write_bytes(b"preserve existing file")
        link = self.root / "link"
        link.symlink_to(existing)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (existing, link, fifo, self.root):
            with self.subTest(path=path.name):
                with self.assertRaises((OSError, ValueError)):
                    aws_media.write_disk(path, self.payload)
                with self.assertRaises(ValueError):
                    aws_media.verify_disk(path, self.payload)
                with self.assertRaises(ValueError):
                    list(aws_media.iter_blocks(path))
        self.assertEqual(existing.read_bytes(), b"preserve existing file")
        valid_link = self.root / "valid-link"
        valid_link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            aws_media.verify_disk(valid_link, self.payload)

    def test_payload_bounds_validate_before_creation(self):
        for payload in (None, "efi", 1, b"", bytes(aws_media.MAX_EFI_SIZE + 1)):
            path = self.root / "invalid.raw"
            with self.subTest(kind=type(payload).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    aws_media.write_disk(path, payload)
                self.assertFalse(path.exists())

    def test_failed_verification_retains_artifact_and_never_unlinks_replacement(self):
        target = self.root / "failed-verification.raw"
        with mock.patch.object(aws_media, "verify_disk", side_effect=ValueError("injected failure")):
            with self.assertRaisesRegex(ValueError, "injected failure"):
                aws_media.write_disk(target, self.payload)
        self.assertEqual(target.stat().st_size, 1 << 30)
        replacement = self.root / "replacement.raw"
        replacement.write_bytes(b"unrelated replacement must survive")
        swapped = self.root / "swapped.raw"

        def replace_then_fail(path, payload):
            replacement.replace(path)
            raise ValueError("injected replacement race")

        with mock.patch.object(aws_media, "verify_disk", side_effect=replace_then_fail):
            with self.assertRaisesRegex(ValueError, "injected replacement race"):
                aws_media.write_disk(swapped, self.payload)
        self.assertEqual(swapped.read_bytes(), b"unrelated replacement must survive")

    def test_maximum_payload_fits_esp_and_fsinfo_reports_full(self):
        payload = b"z" * aws_media.MAX_EFI_SIZE
        ranges = dict(aws_media.disk_ranges(payload))
        esp = 2048 * 512
        boot = ranges[esp]
        info = ranges[esp + 512]
        self.assertEqual(uint(info, 488), 0)
        self.assertEqual(uint(info, 492), 0xffffffff)
        fat = ranges[esp + uint(boot, 14, 2) * 512]
        data_sector = uint(boot, 14, 2) + boot[16] * uint(boot, 36)
        count = (uint(boot, 32) - data_sector) // boot[13]
        self.assertEqual(uint(fat, (count + 1) * 4), 0x0fffffff)
        payload_offset = esp + data_sector * 512 + 3 * 512
        self.assertEqual(payload_offset + len(ranges[payload_offset]), esp + 64 * 1024 * 1024)

    def test_regeneration_rejects_corrupted_structures_payload_and_zero_holes(self):
        offsets = (512 + 16, 2048 * 512 + 48, (2048 + 32) * 512 + 20,
                   (2048 + 2080 + 3) * 512 + 11, 700 * 1024 * 1024,
                   (1 << 30) - 512 + 16)
        for offset in offsets:
            old = self.read_at(offset, 1)
            try:
                with self.path.open("r+b") as stream:
                    stream.seek(offset)
                    stream.write(bytes([old[0] ^ 0x40]))
                with self.subTest(offset=offset):
                    with self.assertRaisesRegex(ValueError, "differs from regeneration"):
                        aws_media.verify_disk(self.path, self.payload)
            finally:
                with self.path.open("r+b") as stream:
                    stream.seek(offset)
                    stream.write(old)

    def test_upload_manifest_rejects_omitted_duplicate_or_changed_blocks(self):
        variants = []
        omitted = copy.deepcopy(self.manifest)
        omitted["nonzero_blocks"].pop(0)
        variants.append(omitted)
        duplicate = copy.deepcopy(self.manifest)
        duplicate["nonzero_blocks"].append(duplicate["nonzero_blocks"][-1])
        variants.append(duplicate)
        changed = copy.deepcopy(self.manifest)
        changed["nonzero_blocks"][0]["sha256"] = "0" * 64
        variants.append(changed)
        bad_size = copy.deepcopy(self.manifest)
        bad_size["logical_size_bytes"] -= 1
        variants.append(bad_size)
        for expected in variants:
            with self.assertRaises(ValueError):
                list(aws_media.iter_blocks(self.path, expected))

    def test_malformed_metadata_and_final_whole_checksum_rejected(self):
        variants = ["metadata", {"nonzero_blocks": []}]
        for field, value in (("sha256", "z" * 64), ("nonzero_blocks", {}),
                             ("nonzero_blocks", [None])):
            expected = copy.deepcopy(self.manifest)
            expected[field] = value
            variants.append(expected)
        for field, value in (("index", True), ("index", -1), ("index", 2048),
                             ("size_bytes", 1), ("sha256", "x" * 64)):
            expected = copy.deepcopy(self.manifest)
            expected["nonzero_blocks"][0][field] = value
            variants.append(expected)
        for expected in variants:
            with self.subTest(expected=repr(expected)[:80]):
                with self.assertRaisesRegex(ValueError, "invalid expected AWS disk"):
                    list(aws_media.iter_blocks(self.path, expected))
        expected = copy.deepcopy(self.manifest)
        expected["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "whole checksum differs"):
            list(aws_media.iter_blocks(self.path, expected))

    def test_upload_iterator_detects_file_mutation_and_replacement(self):
        blocks = aws_media.iter_blocks(self.path, self.manifest)
        first_index, _ = next(blocks)
        offset = first_index * 512 * 1024
        old = self.read_at(offset, 1)
        try:
            with self.path.open("r+b") as stream:
                stream.seek(offset)
                stream.write(bytes([old[0] ^ 0x10]))
            with self.assertRaisesRegex(ValueError, "changed while reading"):
                list(blocks)  # Change to an already-read block is caught at the end.
        finally:
            with self.path.open("r+b") as stream:
                stream.seek(offset)
                stream.write(old)
        blocks = aws_media.iter_blocks(self.path, self.manifest)
        next(blocks)
        renamed = self.root / "temporarily-renamed.raw"
        self.path.rename(renamed)
        self.path.symlink_to(renamed)
        try:
            with self.assertRaisesRegex(ValueError, "changed while reading"):
                list(blocks)
        finally:
            self.path.unlink()
            renamed.rename(self.path)

    def test_wrong_payload_and_exact_file_size_required(self):
        with self.assertRaisesRegex(ValueError, "differs from regeneration"):
            aws_media.verify_disk(self.path, b"wrong original EFI")
        short = self.root / "short.raw"
        with short.open("wb") as stream:
            stream.truncate((1 << 30) - 1)
        long = self.root / "long.raw"
        with long.open("wb") as stream:
            stream.truncate((1 << 30) + 1)
        for path in (short, long):
            with self.assertRaisesRegex(ValueError, "exactly 1 GiB"):
                aws_media.verify_disk(path, self.payload)


if __name__ == "__main__":
    unittest.main()
