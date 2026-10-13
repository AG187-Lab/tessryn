"""Deterministic x64 UEFI media, constructed without host filesystem utilities.

The EFI executable is packaged verbatim; PE/COFF validation belongs to the
kernel builder. The FAT16 volume is for removable media, including an EFI
El Torito virtual CD. The GPT wrapper is an emulator/removable-disk image,
not an installer or evidence of fixed-disk firmware compatibility.

Format references (no third-party implementation code is included):
https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html
https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html
https://ecma-international.org/publications-and-standards/standards/ecma-119/
"""

from __future__ import annotations

import hashlib
import struct
import uuid
import zlib


SECTOR_SIZE = 512
ESP_SECTORS = 65536  # 32 MiB, with FAT16's cluster count well below 65525.
SECTORS_PER_CLUSTER = 2
RESERVED_SECTORS = 1
FAT_SECTORS = 128
ROOT_ENTRIES = 512
ROOT_SECTORS = ROOT_ENTRIES * 32 // SECTOR_SIZE
DATA_SECTOR = RESERVED_SECTORS + 2 * FAT_SECTORS + ROOT_SECTORS
CLUSTER_COUNT = (ESP_SECTORS - DATA_SECTOR) // SECTORS_PER_CLUSTER
CLUSTER_SIZE = SECTOR_SIZE * SECTORS_PER_CLUSTER
MAX_EFI_SIZE = (CLUSTER_COUNT - 2) * CLUSTER_SIZE  # EFI and BOOT use one each.
ISO_BLOCK_SIZE = 2048
ESP_TYPE_GUID = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
_UUID_NAMESPACE = uuid.UUID("8a17fda3-1c6a-4b81-9c47-548620637b1a")
_FAT_DATE = 0x0021  # 1980-01-01, independent of host clock/time zone.


def _payload(efi: bytes) -> bytes:
    if not isinstance(efi, (bytes, bytearray, memoryview)):
        raise TypeError("EFI payload must be bytes")
    size = efi.nbytes if isinstance(efi, memoryview) else len(efi)
    if not 0 < size <= MAX_EFI_SIZE:
        raise ValueError(f"EFI payload must contain 1 to {MAX_EFI_SIZE} bytes")
    return bytes(efi)


def _fat_directory_entry(name: bytes, attributes: int, cluster: int,
                         size: int = 0) -> bytes:
    entry = bytearray(32)
    entry[:11] = name
    entry[11] = attributes
    struct.pack_into("<H", entry, 16, _FAT_DATE)  # Creation date.
    struct.pack_into("<H", entry, 18, _FAT_DATE)  # Access date.
    struct.pack_into("<H", entry, 24, _FAT_DATE)  # Modification date.
    struct.pack_into("<HI", entry, 26, cluster, size)
    return bytes(entry)


def make_esp(efi: bytes) -> bytes:
    """Return a 32 MiB FAT16 volume containing EFI/BOOT/BOOTX64.EFI."""
    payload = _payload(efi)
    image = bytearray(ESP_SECTORS * SECTOR_SIZE)
    image[:3] = b"\xeb\x3c\x90"
    image[3:11] = b"TESSRYN "
    struct.pack_into("<HBHBHHBHHHII", image, 11,
                     SECTOR_SIZE, SECTORS_PER_CLUSTER, RESERVED_SECTORS,
                     2, ROOT_ENTRIES, 0, 0xF8, FAT_SECTORS, 32, 64,
                     0, ESP_SECTORS)
    image[36] = 0x80
    image[38] = 0x29  # Extended boot signature.
    struct.pack_into("<I", image, 39, zlib.crc32(payload))
    image[43:54] = b"TESSRYN K01"
    image[54:62] = b"FAT16   "
    image[62:66] = b"\xfa\xf4\xeb\xfd"  # Harmless halt if a legacy BIOS runs it.
    image[510:512] = b"\x55\xaa"

    file_clusters = (len(payload) + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    fat = bytearray(FAT_SECTORS * SECTOR_SIZE)
    struct.pack_into("<4H", fat, 0, 0xFFF8, 0xFFFF, 0xFFFF, 0xFFFF)
    for cluster in range(4, 4 + file_clusters):
        next_cluster = cluster + 1 if cluster < 3 + file_clusters else 0xFFFF
        struct.pack_into("<H", fat, cluster * 2, next_cluster)
    for copy in range(2):
        start = (RESERVED_SECTORS + copy * FAT_SECTORS) * SECTOR_SIZE
        image[start:start + len(fat)] = fat

    root = (RESERVED_SECTORS + 2 * FAT_SECTORS) * SECTOR_SIZE
    image[root:root + 32] = _fat_directory_entry(b"TESSRYN K01", 0x08, 0)
    image[root + 32:root + 64] = _fat_directory_entry(b"EFI        ", 0x10, 2)
    efi_dir = DATA_SECTOR * SECTOR_SIZE
    boot_dir = efi_dir + CLUSTER_SIZE
    for start, own, parent in ((efi_dir, 2, 0), (boot_dir, 3, 2)):
        image[start:start + 32] = _fat_directory_entry(b".          ", 0x10, own)
        image[start + 32:start + 64] = _fat_directory_entry(b"..         ", 0x10, parent)
    image[efi_dir + 64:efi_dir + 96] = _fat_directory_entry(b"BOOT       ", 0x10, 3)
    image[boot_dir + 64:boot_dir + 96] = _fat_directory_entry(
        b"BOOTX64 EFI", 0x20, 4, len(payload))
    file_start = efi_dir + 2 * CLUSTER_SIZE
    image[file_start:file_start + len(payload)] = payload
    return bytes(image)


def _gpt_header(current: int, alternate: int, last_usable: int,
                disk_guid: bytes, table_lba: int, table_crc: int) -> bytes:
    header = bytearray(SECTOR_SIZE)
    struct.pack_into("<8sIIIIQQQQ16sQIII", header, 0,
                     b"EFI PART", 0x00010000, 92, 0, 0,
                     current, alternate, 34, last_usable, disk_guid,
                     table_lba, 128, 128, table_crc)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
    return bytes(header)


def make_disk(efi: bytes) -> bytes:
    """Return a GPT disk with protective MBR and primary/backup GPT tables.

    The ESP starts at 1 MiB. The image has no installer or access to host disks.
    Identical payloads produce identical GUIDs, CRCs and padding.
    """
    payload = _payload(efi)
    esp = bytearray(make_esp(payload))
    start_lba = 2048
    struct.pack_into("<I", esp, 28, start_lba)  # FAT hidden sectors.
    total_sectors = ((start_lba + ESP_SECTORS + 33 + 2047) // 2048) * 2048
    last_lba = total_sectors - 1
    last_usable = last_lba - 33
    image = bytearray(total_sectors * SECTOR_SIZE)
    # Protective MBR: no legacy loader, one entry covering all remaining LBAs.
    struct.pack_into("<B3sB3sII", image, 446,
                     0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1, last_lba)
    image[510:512] = b"\x55\xaa"

    identity = hashlib.sha256(payload).hexdigest()
    disk_guid = uuid.uuid5(_UUID_NAMESPACE, "disk:" + identity).bytes_le
    partition_guid = uuid.uuid5(_UUID_NAMESPACE, "esp:" + identity).bytes_le
    entries = bytearray(128 * 128)
    struct.pack_into("<16s16sQQQ72s", entries, 0,
                     ESP_TYPE_GUID.bytes_le, partition_guid,
                     start_lba, start_lba + ESP_SECTORS - 1, 0,
                     "Tessryn K01 ESP".encode("utf-16le"))
    entries_crc = zlib.crc32(entries)
    primary = _gpt_header(1, last_lba, last_usable, disk_guid, 2, entries_crc)
    backup = _gpt_header(last_lba, 1, last_usable, disk_guid, last_lba - 32, entries_crc)
    image[SECTOR_SIZE:2 * SECTOR_SIZE] = primary
    image[2 * SECTOR_SIZE:34 * SECTOR_SIZE] = entries
    image[(last_lba - 32) * SECTOR_SIZE:last_lba * SECTOR_SIZE] = entries
    image[last_lba * SECTOR_SIZE:] = backup
    image[start_lba * SECTOR_SIZE:(start_lba + ESP_SECTORS) * SECTOR_SIZE] = esp
    return bytes(image)


def _both16(value: int) -> bytes:
    return struct.pack("<H", value) + struct.pack(">H", value)


def _both32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _iso_directory_record(name: bytes, extent: int, size: int, directory=False) -> bytes:
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(length)
    record[0] = length
    record[2:10] = _both32(extent)
    record[10:18] = _both32(size)
    record[18:25] = bytes((80, 1, 1, 0, 0, 0, 0))  # 1980-01-01 UTC.
    record[25] = 2 if directory else 0
    record[28:32] = _both16(1)
    record[32] = len(name)
    record[33:33 + len(name)] = name
    return bytes(record)


def make_iso(efi: bytes) -> bytes:
    """Return ISO9660 with one EFI El Torito no-emulation FAT16 boot image.

    UEFI 2.10 section 13.3.2.1 specifies that El Torito SectorCount 0 or 1
    means the ESP extends to CD end. Count 0 is necessary for this 65536-sector
    FAT image, which exceeds the catalog's 16-bit field. The image is last.
    """
    esp = make_esp(efi)
    path_lba, path_be_lba, root_lba, catalog_lba, boot_lba = 19, 20, 21, 22, 23
    total_blocks = boot_lba + len(esp) // ISO_BLOCK_SIZE
    image = bytearray(total_blocks * ISO_BLOCK_SIZE)

    pvd = bytearray(ISO_BLOCK_SIZE)
    pvd[:7] = b"\x01CD001\x01"
    pvd[8:40] = b"TESSRYN".ljust(32, b" ")
    pvd[40:72] = b"TESSRYN_K01".ljust(32, b" ")
    pvd[80:88] = _both32(total_blocks)
    pvd[120:124] = _both16(1)  # Volume set size.
    pvd[124:128] = _both16(1)  # Volume sequence number.
    pvd[128:132] = _both16(ISO_BLOCK_SIZE)
    pvd[132:140] = _both32(10)  # Single root path-table record.
    struct.pack_into("<I", pvd, 140, path_lba)
    struct.pack_into(">I", pvd, 148, path_be_lba)
    pvd[156:190] = _iso_directory_record(b"\x00", root_lba, ISO_BLOCK_SIZE, True)
    pvd[190:813] = b" " * (813 - 190)  # Fixed-width text identifiers.
    fixed_date = b"1980010100000000\x00"
    pvd[813:830] = fixed_date
    pvd[830:847] = fixed_date
    pvd[847:864] = b"0000000000000000\x00"
    pvd[864:881] = fixed_date
    pvd[881] = 1  # File structure version.
    image[16 * ISO_BLOCK_SIZE:17 * ISO_BLOCK_SIZE] = pvd

    boot_record = bytearray(ISO_BLOCK_SIZE)
    boot_record[:7] = b"\x00CD001\x01"
    boot_record[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b"\x00")
    struct.pack_into("<I", boot_record, 71, catalog_lba)
    image[17 * ISO_BLOCK_SIZE:18 * ISO_BLOCK_SIZE] = boot_record
    image[18 * ISO_BLOCK_SIZE:18 * ISO_BLOCK_SIZE + 7] = b"\xffCD001\x01"

    for lba, endian in ((path_lba, "<"), (path_be_lba, ">")):
        start = lba * ISO_BLOCK_SIZE
        image[start:start + 10] = struct.pack(endian + "BBIHBB", 1, 0, root_lba, 1, 0, 0)
    records = b"".join((
        _iso_directory_record(b"\x00", root_lba, ISO_BLOCK_SIZE, True),
        _iso_directory_record(b"\x01", root_lba, ISO_BLOCK_SIZE, True),
        _iso_directory_record(b"BOOT.CAT;1", catalog_lba, ISO_BLOCK_SIZE),
        _iso_directory_record(b"EFIBOOT.IMG;1", boot_lba, len(esp)),
    ))
    image[root_lba * ISO_BLOCK_SIZE:root_lba * ISO_BLOCK_SIZE + len(records)] = records

    catalog = bytearray(ISO_BLOCK_SIZE)
    catalog[0:2] = b"\x01\xef"  # Validation entry, EFI platform.
    catalog[4:28] = b"TESSRYN K01".ljust(24, b"\x00")
    catalog[30:32] = b"\x55\xaa"
    checksum = (-sum(struct.unpack("<16H", catalog[:32]))) & 0xFFFF
    struct.pack_into("<H", catalog, 28, checksum)
    struct.pack_into("<BBHBBHI", catalog, 32, 0x88, 0, 0, 0, 0, 0, boot_lba)
    image[catalog_lba * ISO_BLOCK_SIZE:(catalog_lba + 1) * ISO_BLOCK_SIZE] = catalog
    image[boot_lba * ISO_BLOCK_SIZE:] = esp
    return bytes(image)
