"""Original deterministic fixed-disk UEFI media for the AWS CPU boot profile.

No AWS APIs or host disk utilities are used. The logical disk is exactly 1 GiB,
with a FAT32 ESP at 1 MiB; only nonzero extents need physical host storage.
Format references: UEFI 2.10 sections 5 and 13; Microsoft FAT specification.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import struct
from typing import Iterator
import uuid
import zlib


SECTOR_SIZE = 512
BLOCK_SIZE = 512 * 1024
DISK_SIZE_BYTES = 1024 * 1024 * 1024
ESP_START_LBA = 2048
ESP_SIZE_BYTES = 64 * 1024 * 1024
ESP_SECTORS = ESP_SIZE_BYTES // SECTOR_SIZE
RESERVED_SECTORS = 32
FAT_SECTORS = 1024
SECTORS_PER_CLUSTER = 1
DATA_SECTOR = RESERVED_SECTORS + 2 * FAT_SECTORS
CLUSTER_SIZE = SECTOR_SIZE * SECTORS_PER_CLUSTER
CLUSTER_COUNT = (ESP_SECTORS - DATA_SECTOR) // SECTORS_PER_CLUSTER
MAX_EFI_SIZE = (CLUSTER_COUNT - 3) * CLUSTER_SIZE
LAST_LBA = DISK_SIZE_BYTES // SECTOR_SIZE - 1
LAST_USABLE_LBA = LAST_LBA - 33
ESP_TYPE_GUID = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
_NAMESPACE = uuid.UUID("0bc596af-e646-5e2d-8baa-e22cb9b71e55")
_ZERO_BLOCK = bytes(BLOCK_SIZE)
_FAT_DATE = 0x0021  # 1980-01-01, no host timestamps.


def _payload(efi: bytes) -> bytes:
    if not isinstance(efi, (bytes, bytearray, memoryview)):
        raise TypeError("EFI payload must be bytes")
    size = efi.nbytes if isinstance(efi, memoryview) else len(efi)
    if not 0 < size <= MAX_EFI_SIZE:
        raise ValueError(f"EFI payload must contain 1 to {MAX_EFI_SIZE} bytes")
    return bytes(efi)


def _identities(payload: bytes) -> tuple[uuid.UUID, uuid.UUID]:
    identity = hashlib.sha256(payload).hexdigest()
    return (uuid.uuid5(_NAMESPACE, "disk:" + identity),
            uuid.uuid5(_NAMESPACE, "esp:" + identity))


def _entry(name: bytes, attributes: int, cluster: int, size: int = 0) -> bytes:
    entry = bytearray(32)
    entry[:11] = name
    entry[11] = attributes
    for offset in (16, 18, 24):
        struct.pack_into("<H", entry, offset, _FAT_DATE)
    struct.pack_into("<H", entry, 20, cluster >> 16)
    struct.pack_into("<HI", entry, 26, cluster & 0xffff, size)
    return bytes(entry)


def _gpt_header(current: int, alternate: int, table_lba: int,
                disk_guid: uuid.UUID, table_crc: int) -> bytes:
    header = bytearray(SECTOR_SIZE)
    struct.pack_into("<8sIIIIQQQQ16sQIII", header, 0,
                     b"EFI PART", 0x10000, 92, 0, 0, current, alternate,
                     34, LAST_USABLE_LBA, disk_guid.bytes_le,
                     table_lba, 128, 128, table_crc)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
    return bytes(header)


def disk_ranges(efi: bytes) -> list[tuple[int, bytes]]:
    """Return sorted, nonoverlapping (byte offset, bytes) sparse disk extents."""
    payload = _payload(efi)
    disk_guid, partition_guid = _identities(payload)
    file_clusters = (len(payload) + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    mbr = bytearray(SECTOR_SIZE)
    struct.pack_into("<B3sB3sII", mbr, 446,
                     0, b"\x00\x02\x00", 0xee, b"\xff\xff\xff", 1, LAST_LBA)
    mbr[510:512] = b"\x55\xaa"
    entries = bytearray(128 * 128)
    struct.pack_into("<16s16sQQQ72s", entries, 0,
                     ESP_TYPE_GUID.bytes_le, partition_guid.bytes_le,
                     ESP_START_LBA, ESP_START_LBA + ESP_SECTORS - 1, 0,
                     "Tessryn AWS ESP".encode("utf-16le"))
    table_crc = zlib.crc32(entries)

    boot = bytearray(SECTOR_SIZE)
    boot[:3] = b"\xeb\x58\x90"
    boot[3:11] = b"TESSRYN "
    struct.pack_into("<HBHBHHBHHHII", boot, 11,
                     SECTOR_SIZE, SECTORS_PER_CLUSTER, RESERVED_SECTORS,
                     2, 0, 0, 0xf8, 0, 32, 64, ESP_START_LBA, ESP_SECTORS)
    struct.pack_into("<IHHIHH", boot, 36, FAT_SECTORS, 0, 0, 2, 1, 6)
    boot[64] = 0x80
    boot[66] = 0x29
    struct.pack_into("<I", boot, 67, zlib.crc32(payload))
    boot[71:82] = b"TESSRYN AWS"
    boot[82:90] = b"FAT32   "
    boot[90:94] = b"\xfa\xf4\xeb\xfd"
    boot[510:512] = b"\x55\xaa"
    info = bytearray(SECTOR_SIZE)
    free_clusters = CLUSTER_COUNT - 3 - file_clusters
    struct.pack_into("<I", info, 0, 0x41615252)
    struct.pack_into("<IIII", info, 484, 0x61417272, free_clusters,
                     5 + file_clusters if free_clusters else 0xffffffff, 0)
    struct.pack_into("<I", info, 508, 0xaa550000)

    fat = bytearray(FAT_SECTORS * SECTOR_SIZE)
    struct.pack_into("<5I", fat, 0, 0x0ffffff8, 0x0fffffff,
                     0x0fffffff, 0x0fffffff, 0x0fffffff)
    for cluster in range(5, 5 + file_clusters):
        struct.pack_into("<I", fat, cluster * 4,
                         cluster + 1 if cluster < 4 + file_clusters else 0x0fffffff)
    root = bytearray(CLUSTER_SIZE)
    root[:32] = _entry(b"TESSRYN AWS", 0x08, 0)
    root[32:64] = _entry(b"EFI        ", 0x10, 3)
    efi_dir = bytearray(CLUSTER_SIZE)
    efi_dir[:32] = _entry(b".          ", 0x10, 3)
    efi_dir[32:64] = _entry(b"..         ", 0x10, 0)
    efi_dir[64:96] = _entry(b"BOOT       ", 0x10, 4)
    boot_dir = bytearray(CLUSTER_SIZE)
    boot_dir[:32] = _entry(b".          ", 0x10, 4)
    boot_dir[32:64] = _entry(b"..         ", 0x10, 3)
    boot_dir[64:96] = _entry(b"BOOTX64 EFI", 0x20, 5, len(payload))

    esp = ESP_START_LBA * SECTOR_SIZE
    data = esp + DATA_SECTOR * SECTOR_SIZE
    ranges = [(0, bytes(mbr)),
              (SECTOR_SIZE, _gpt_header(1, LAST_LBA, 2, disk_guid, table_crc)),
              (2 * SECTOR_SIZE, bytes(entries)),
              (esp, bytes(boot)), (esp + SECTOR_SIZE, bytes(info)),
              (esp + 6 * SECTOR_SIZE, bytes(boot)),
              (esp + 7 * SECTOR_SIZE, bytes(info)),
              (esp + RESERVED_SECTORS * SECTOR_SIZE, bytes(fat)),
              (esp + (RESERVED_SECTORS + FAT_SECTORS) * SECTOR_SIZE, bytes(fat)),
              (data, bytes(root)), (data + CLUSTER_SIZE, bytes(efi_dir)),
              (data + 2 * CLUSTER_SIZE, bytes(boot_dir)),
              (data + 3 * CLUSTER_SIZE, payload),
              ((LAST_LBA - 32) * SECTOR_SIZE, bytes(entries)),
              (LAST_LBA * SECTOR_SIZE,
               _gpt_header(LAST_LBA, 1, LAST_LBA - 32, disk_guid, table_crc))]
    return sorted(ranges)


def _expected_blocks(ranges: list[tuple[int, bytes]]) -> Iterator[bytes]:
    cursor = 0
    for start in range(0, DISK_SIZE_BYTES, BLOCK_SIZE):
        end = start + BLOCK_SIZE
        while cursor < len(ranges) and ranges[cursor][0] + len(ranges[cursor][1]) <= start:
            cursor += 1
        block = None
        index = cursor
        while index < len(ranges) and ranges[index][0] < end:
            offset, content = ranges[index]
            left, right = max(start, offset), min(end, offset + len(content))
            if left < right:
                if block is None:
                    block = bytearray(BLOCK_SIZE)
                block[left - start:right - start] = content[left - offset:right - offset]
            index += 1
        yield bytes(block) if block is not None else _ZERO_BLOCK


def _open_disk(path: Path):
    """Open without following a final symlink or blocking on a FIFO."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("cannot open a regular AWS disk image") from exc
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size != DISK_SIZE_BYTES:
        os.close(fd)
        raise ValueError("AWS disk image must be a regular file of exactly 1 GiB")
    return os.fdopen(fd, "rb"), before


def _unchanged(path: Path, stream, before) -> None:
    after = os.fstat(stream.fileno())
    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError("AWS disk image changed while reading") from exc
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (any(getattr(before, key) != getattr(after, key)
            or getattr(before, key) != getattr(current, key) for key in fields)
            or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)):
        raise ValueError("AWS disk image changed while reading")


def verify_disk(path: Path, efi: bytes) -> dict:
    """Require exact deterministic regeneration, including all zero holes.

    Verification reads only regular, exact-size files, retains one descriptor,
    and detects replacement or concurrent modification before returning.
    """
    path = Path(path)
    payload = _payload(efi)
    ranges = disk_ranges(payload)
    stream, before = _open_disk(path)
    digest = hashlib.sha256()
    blocks = []
    with stream:
        for index, expected in enumerate(_expected_blocks(ranges)):
            actual = stream.read(BLOCK_SIZE)
            if actual != expected:
                raise ValueError(f"AWS disk image differs from regeneration in block {index}")
            digest.update(actual)
            if actual != _ZERO_BLOCK:
                blocks.append({"index": index, "sha256": hashlib.sha256(actual).hexdigest(),
                               "size_bytes": BLOCK_SIZE})
        _unchanged(path, stream, before)
    disk_guid, partition_guid = _identities(payload)
    return {"logical_size_bytes": DISK_SIZE_BYTES, "sha256": digest.hexdigest(),
            "efi_sha256": hashlib.sha256(payload).hexdigest(), "efi_size_bytes": len(payload),
            "block_size_bytes": BLOCK_SIZE, "nonzero_blocks": blocks,
            "esp": {"start_lba": ESP_START_LBA, "size_bytes": ESP_SIZE_BYTES,
                    "filesystem": "FAT32", "cluster_size_bytes": CLUSTER_SIZE,
                    "cluster_count": CLUSTER_COUNT, "partition_guid": str(partition_guid),
                    "boot_path": "EFI/BOOT/BOOTX64.EFI"},
            "gpt": {"disk_guid": str(disk_guid), "primary_header_lba": 1,
                    "backup_header_lba": LAST_LBA, "primary_table_lba": 2,
                    "backup_table_lba": LAST_LBA - 32,
                    "first_usable_lba": 34, "last_usable_lba": LAST_USABLE_LBA}}


def write_disk(path: Path, efi: bytes) -> dict:
    """Create a NEW sparse disk, verify it, and return public upload metadata.

    Failed artifacts remain for inspection. Pathname-based failure cleanup cannot
    safely unlink this inode if another process replaces the path concurrently.
    """
    path = Path(path)
    payload = _payload(efi)  # Validate before creating anything.
    ranges = disk_ranges(payload)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.truncate(DISK_SIZE_BYTES)
        for offset, content in ranges:
            stream.seek(offset)
            stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return verify_disk(path, payload)


def iter_blocks(path: Path, expected: dict | None = None) -> Iterator[tuple[int, bytes]]:
    """Yield nonzero 512 KiB upload blocks from one stable file descriptor.

    Pass write_disk/verify_disk metadata to check every block before yielding.
    Exhaust the iterator before completing a snapshot: the final whole-disk
    checksum and file stability check happen when iteration finishes.
    """
    path = Path(path)
    expected_blocks = None
    expected_checksum = None
    if expected is not None:
        def checksum_valid(value):
            return (isinstance(value, str) and len(value) == 64
                    and all(character in "0123456789abcdef" for character in value))

        if (not isinstance(expected, dict)
                or expected.get("logical_size_bytes") != DISK_SIZE_BYTES
                or expected.get("block_size_bytes") != BLOCK_SIZE
                or not checksum_valid(expected.get("sha256"))
                or not isinstance(expected.get("nonzero_blocks"), list)):
            raise ValueError("invalid expected AWS disk metadata")
        expected_checksum = expected["sha256"]
        expected_blocks = {}
        previous = -1
        for entry in expected["nonzero_blocks"]:
            if not isinstance(entry, dict):
                raise ValueError("invalid expected AWS disk block metadata")
            index = entry.get("index")
            checksum = entry.get("sha256")
            if (type(index) is not int or not previous < index < DISK_SIZE_BYTES // BLOCK_SIZE
                    or entry.get("size_bytes") != BLOCK_SIZE
                    or not checksum_valid(checksum)):
                raise ValueError("invalid expected AWS disk block metadata")
            expected_blocks[index] = checksum
            previous = index
    stream, before = _open_disk(path)
    digest = hashlib.sha256()
    with stream:
        for index in range(DISK_SIZE_BYTES // BLOCK_SIZE):
            block = stream.read(BLOCK_SIZE)
            if len(block) != BLOCK_SIZE:
                raise ValueError("AWS disk image changed while reading")
            digest.update(block)
            nonzero = block != _ZERO_BLOCK
            checksum = hashlib.sha256(block).hexdigest() if nonzero else None
            if expected_blocks is not None and (
                    nonzero != (index in expected_blocks)
                    or (nonzero and checksum != expected_blocks[index])):
                raise ValueError(f"AWS disk upload block {index} differs from expected metadata")
            if nonzero:
                yield index, block
        _unchanged(path, stream, before)
        if expected_checksum is not None and digest.hexdigest() != expected_checksum:
            raise ValueError("AWS disk image whole checksum differs from expected metadata")
