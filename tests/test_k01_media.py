"""Read produced media through independent FAT/GPT/ISO structure checks."""

import hashlib
import struct
import unittest
import uuid
import zlib

from tools import k01_media


def uint(data, offset, size=4, endian="little"):
    return int.from_bytes(data[offset:offset + size], endian)


class MediaTests(unittest.TestCase):
    payload = bytes(range(256)) * 19 + b"original-kernel-tail"

    def read_fat_file(self, image):
        """Follow the on-disk BPB, directory entries and FAT chain."""
        self.assertEqual(image[510:512], b"\x55\xaa")
        sector = uint(image, 11, 2)
        per_cluster = image[13]
        reserved = uint(image, 14, 2)
        copies = image[16]
        roots = uint(image, 17, 2)
        sectors = uint(image, 19, 2) or uint(image, 32)
        fat_sectors = uint(image, 22, 2)
        self.assertEqual(sector, 512)
        self.assertEqual(copies, 2)
        self.assertEqual(len(image), sectors * sector)
        root_sectors = (roots * 32 + sector - 1) // sector
        data_sector = reserved + copies * fat_sectors + root_sectors
        clusters = (sectors - data_sector) // per_cluster
        self.assertGreaterEqual(clusters, 4085)  # FAT16 classification.
        self.assertLess(clusters, 65525)
        fat = image[reserved * sector:(reserved + fat_sectors) * sector]
        self.assertGreaterEqual(len(fat), 2 * (clusters + 2))
        self.assertEqual(uint(fat, 0, 2), 0xFF00 | image[21])
        self.assertEqual(uint(fat, 2, 2), 0xFFFF)
        self.assertEqual(fat, image[(reserved + fat_sectors) * sector:
                                    (reserved + 2 * fat_sectors) * sector])

        def chain(first):
            contents = bytearray()
            visited = set()
            cluster = first
            while cluster < 0xFFF8:
                self.assertTrue(2 <= cluster < clusters + 2)
                self.assertNotIn(cluster, visited)
                visited.add(cluster)
                offset = (data_sector + (cluster - 2) * per_cluster) * sector
                contents.extend(image[offset:offset + per_cluster * sector])
                cluster = uint(fat, 2 * cluster, 2)
            return bytes(contents)

        def directory(contents):
            entries = {}
            for offset in range(0, len(contents), 32):
                entry = contents[offset:offset + 32]
                if not entry[0]:
                    break
                if entry[0] == 0xE5 or entry[11] == 0x08:
                    continue
                self.assertEqual(uint(entry, 20, 2), 0)  # FAT16 high cluster.
                for date_offset in (16, 18, 24):
                    self.assertEqual(uint(entry, date_offset, 2), 0x0021)
                entries[entry[:11]] = entry
            return entries

        root_at = (reserved + copies * fat_sectors) * sector
        root = directory(image[root_at:root_at + roots * 32])
        self.assertEqual(set(root), {b"EFI        "})
        self.assertEqual(root[b"EFI        "][11], 0x10)
        efi = directory(chain(uint(root[b"EFI        "], 26, 2)))
        self.assertEqual(set(efi), {b".          ", b"..         ", b"BOOT       "})
        self.assertEqual(uint(efi[b"..         "], 26, 2), 0)
        boot = directory(chain(uint(efi[b"BOOT       "], 26, 2)))
        self.assertEqual(set(boot), {b".          ", b"..         ", b"BOOTX64 EFI"})
        self.assertEqual(uint(boot[b"..         "], 26, 2), uint(root[b"EFI        "], 26, 2))
        entry = boot[b"BOOTX64 EFI"]
        self.assertEqual(entry[11], 0x20)
        size = uint(entry, 28)
        data = chain(uint(entry, 26, 2))
        self.assertEqual(len(data), ((size + per_cluster * sector - 1)
                                    // (per_cluster * sector)) * per_cluster * sector)
        self.assertEqual(data[size:], b"\x00" * (len(data) - size))
        return data[:size]

    def test_fat_directory_chain_recovers_verbatim_payload(self):
        image = k01_media.make_esp(self.payload)
        self.assertEqual(image[54:62], b"FAT16   ")
        self.assertEqual(uint(image, 28), 0)
        self.assertEqual(self.read_fat_file(image), self.payload)

    def test_single_cluster_and_full_capacity_boundaries(self):
        for payload in (b"x", b"y" * k01_media.MAX_EFI_SIZE):
            with self.subTest(size=len(payload)):
                self.assertEqual(self.read_fat_file(k01_media.make_esp(payload)), payload)

    def test_gpt_primary_backup_crcs_and_esp(self):
        image = k01_media.make_disk(self.payload)
        sector = 512
        last_lba = len(image) // sector - 1
        self.assertEqual(image[510:512], b"\x55\xaa")
        self.assertEqual(image[446:450], b"\x00\x00\x02\x00")
        self.assertEqual(image[450], 0xEE)
        self.assertEqual(uint(image, 454), 1)
        self.assertEqual(uint(image, 458), last_lba)
        self.assertEqual(image[462:510], b"\x00" * 48)
        tables = []
        headers = []
        for own, alternate in ((1, last_lba), (last_lba, 1)):
            header = image[own * sector:(own + 1) * sector]
            self.assertEqual(header[:8], b"EFI PART")
            self.assertEqual(uint(header, 8), 0x00010000)
            size = uint(header, 12)
            self.assertEqual(size, 92)
            unchecked = bytearray(header[:size])
            unchecked[16:20] = b"\x00" * 4
            self.assertEqual(uint(header, 16), zlib.crc32(unchecked))
            self.assertEqual(uint(header, 24, 8), own)
            self.assertEqual(uint(header, 32, 8), alternate)
            self.assertEqual(header[92:], b"\x00" * (sector - 92))
            table_lba = uint(header, 72, 8)
            entries, entry_size = uint(header, 80), uint(header, 84)
            self.assertEqual((entries, entry_size), (128, 128))
            table = image[table_lba * sector:table_lba * sector + entries * entry_size]
            self.assertEqual(zlib.crc32(table), uint(header, 88))
            tables.append(table)
            headers.append(header)
        self.assertEqual(tables[0], tables[1])
        self.assertEqual(headers[0][40:72], headers[1][40:72])
        table = tables[0]
        self.assertEqual(uuid.UUID(bytes_le=table[:16]),
                         uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"))
        self.assertNotEqual(table[16:32], headers[0][56:72])
        start, end = uint(table, 32, 8), uint(table, 40, 8)
        self.assertEqual(start % 2048, 0)
        self.assertGreaterEqual(start, uint(headers[0], 40, 8))
        self.assertLessEqual(end, uint(headers[0], 48, 8))
        self.assertEqual(table[128:], b"\x00" * (len(table) - 128))
        esp = image[start * sector:(end + 1) * sector]
        self.assertEqual(uint(esp, 28), start)
        self.assertEqual(self.read_fat_file(esp), self.payload)

    def test_iso_catalog_paths_and_efi_image(self):
        image = k01_media.make_iso(self.payload)
        block = 2048
        pvd = image[16 * block:17 * block]
        self.assertEqual(pvd[:7], b"\x01CD001\x01")
        self.assertEqual(uint(pvd, 80), uint(pvd, 84, endian="big"))
        self.assertEqual(uint(pvd, 80) * block, len(image))
        self.assertEqual(uint(pvd, 128, 2), block)
        self.assertEqual(uint(pvd, 130, 2, "big"), block)
        self.assertEqual(pvd[881], 1)
        self.assertEqual(image[18 * block:18 * block + 7], b"\xffCD001\x01")
        boot_record = image[17 * block:18 * block]
        self.assertEqual(boot_record[:7], b"\x00CD001\x01")
        self.assertEqual(boot_record[7:39].rstrip(b"\x00"), b"EL TORITO SPECIFICATION")
        catalog_lba = uint(boot_record, 71)
        catalog = image[catalog_lba * block:(catalog_lba + 1) * block]
        self.assertEqual(catalog[:4], b"\x01\xef\x00\x00")
        self.assertEqual(catalog[30:32], b"\x55\xaa")
        self.assertEqual(sum(struct.unpack("<16H", catalog[:32])) & 0xFFFF, 0)
        self.assertEqual(catalog[32:38], b"\x88\x00\x00\x00\x00\x00")
        self.assertEqual(uint(catalog, 38, 2), 0)  # UEFI consumes to CD end.
        boot_lba = uint(catalog, 40)
        esp = image[boot_lba * block:]
        self.assertEqual(self.read_fat_file(esp), self.payload)
        self.assertEqual(esp, k01_media.make_esp(self.payload))

        root_lba, root_size = uint(pvd, 158), uint(pvd, 166)
        self.assertEqual(root_lba, uint(pvd, 162, endian="big"))
        root = image[root_lba * block:root_lba * block + root_size]
        records = {}
        offset = 0
        while root[offset]:
            length = root[offset]
            self.assertEqual(length % 2, 0)
            record = root[offset:offset + length]
            identifier = record[33:33 + record[32]]
            extent, size = uint(record, 2), uint(record, 10)
            self.assertEqual(extent, uint(record, 6, endian="big"))
            self.assertEqual(size, uint(record, 14, endian="big"))
            self.assertLessEqual(extent * block + size, len(image))
            records[identifier] = (extent, size)
            offset += length
        self.assertEqual(set(records), {b"\x00", b"\x01", b"BOOT.CAT;1", b"EFIBOOT.IMG;1"})
        self.assertEqual(records[b"BOOT.CAT;1"], (catalog_lba, block))
        self.assertEqual(records[b"EFIBOOT.IMG;1"], (boot_lba, len(esp)))
        self.assertEqual(uint(pvd, 132), 10)
        for location, endian in ((140, "little"), (148, "big")):
            path_lba = uint(pvd, location, endian=endian)
            path = image[path_lba * block:path_lba * block + 10]
            self.assertEqual(path[:2], b"\x01\x00")
            self.assertEqual(uint(path, 2, endian=endian), root_lba)
            self.assertEqual(uint(path, 6, 2, endian), 1)
            self.assertEqual(path[8:], b"\x00\x00")

    def test_deterministic_images_and_payload_derived_disk_identity(self):
        for factory in (k01_media.make_esp, k01_media.make_disk, k01_media.make_iso):
            with self.subTest(factory=factory.__name__):
                first = factory(self.payload)
                self.assertEqual(hashlib.sha256(first).digest(),
                                 hashlib.sha256(factory(self.payload)).digest())
        first = k01_media.make_disk(b"first")
        second = k01_media.make_disk(b"second")
        self.assertNotEqual(first[568:584], second[568:584])

    def test_reject_empty_oversize_and_nonbyte_payloads(self):
        oversize = b"x" * (k01_media.MAX_EFI_SIZE + 1)
        for factory in (k01_media.make_esp, k01_media.make_disk, k01_media.make_iso):
            for payload in (b"", oversize):
                with self.subTest(factory=factory.__name__, size=len(payload)):
                    with self.assertRaises(ValueError):
                        factory(payload)
            with self.assertRaises(TypeError):
                factory("BOOTX64.EFI")
        self.assertEqual(k01_media.make_esp(bytearray(b"efi")), k01_media.make_esp(b"efi"))
        self.assertEqual(k01_media.make_esp(memoryview(b"efi")), k01_media.make_esp(b"efi"))


if __name__ == "__main__":
    unittest.main()
