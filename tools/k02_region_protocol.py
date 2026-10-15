"""Trusted shared constants and bounded readers for the new region profile."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_NAME = "planning/k02-region-service.json"
CASES = ("sharing", "revocation", "authority")
CPU = "max,phys-bits=48,la57=off,nx=on,pcid=off,pge=off,pku=off,pks=off,sgx=off,cet-ss=off,cet-ibt=off,fsgsbase=off"
PROFILE = {"architecture": "x86_64", "target": "x86_64-unknown-uefi", "machine": "q35,accel=tcg",
           "cpu": CPU, "cpu_count": 1, "memory_bytes": 256 << 20, "physical_bits": 48,
           "paging_levels": 4, "page_size": 4096, "nx_enabled": True, "pcid_enabled": False,
           "global_translations": False, "legacy_fp_only": True, "invalidation": "cr3_reload"}
ARTIFACT_TYPE = "tessryn-k02-region-service"
FORMAT = "tessryn-k02-region-service-result/v1"
SCOPE = "bounded original-kernel single-CPU region service; physical hardware, arbitrary-program isolation, SMP and DMA unqualified"
MAGIC = b"TESSRYN-REGION1\0"
DESCRIPTOR_SIZE = 88
ADDRESSES = {"code": 0x100000000, "stack": 0x100002000, "request": 0x10000F000, "data": 0x100004000}
OPS = {"allocate": 1, "map": 2, "delegate_readonly": 3, "revoke": 4, "unmap": 5,
       "release": 6, "accounting": 7, "yield": 8, "exit": 9}
STATUSES = {"ok": 0, "invalid_descriptor": 1, "unsupported_version": 2, "unsupported_operation": 3,
            "invalid_authority": 4, "stale_handle": 5, "revoked": 6, "bounds": 7,
            "alignment": 8, "insufficient_rights": 9, "capacity": 10, "budget": 11,
            "busy": 12, "overflow": 13, "backend_rejected": 14}
MAX_LOG_BYTES = 1 << 20


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path: Path, limit=64 << 20) -> bytes:
    """Never follow file or ancestor aliases and bound before and after reading."""
    path = Path(path).absolute()
    require(".." not in path.parts, "region input path has parent traversal")
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "region input is not a bounded regular file")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "region input changed during read")
            require(len(data) <= limit, "region input exceeds byte bound")
            return data
    except OSError as error:
        raise ValueError("region input unavailable or aliases another path") from error
    finally:
        os.close(directory)


def strict_json(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate region JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite region JSON")

    def finite_float(text):
        value = float(text)
        require(math.isfinite(value), "nonfinite region JSON")
        return value

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("invalid region JSON") from error
    pending = [(value, 1)]
    while pending:
        node, depth = pending.pop()
        require(depth <= 64, "region JSON exceeds nesting bound")
        children = node.values() if type(node) is dict else node if type(node) is list else ()
        pending.extend((child, depth + 1) for child in children if type(child) in (dict, list))
    return value


def portable_path(name):
    require(type(name) is str and bool(name), "region relative path required")
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name and ".." not in path.parts
            and not any(c in name for c in ("\\", "\n", "\r", "\t")), "unsafe region relative path")
    return path


def read_ref(root, row, limit=64 << 20):
    require(type(row) is dict and set(row) >= {"path", "sha256", "size_bytes"}, "region file reference malformed")
    path = portable_path(row["path"])
    require(type(row["size_bytes"]) is int and 0 <= row["size_bytes"] <= limit
            and type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"]), "region file binding malformed")
    data = regular_bytes(Path(root) / path, limit)
    require(len(data) == row["size_bytes"] and digest(data) == row["sha256"], "region retained file binding differs")
    return data


def file_ref(root, path):
    data = regular_bytes(path)
    return {"path": Path(path).relative_to(root).as_posix(), "sha256": digest(data), "size_bytes": len(data)}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def retain_private_error(out, error):
    """Exact available probe output stays private, outside the success allowlist."""
    metadata = {"type": type(error).__name__, "message": str(error)}
    for stream, attribute in (("stdout", "output"), ("stderr", "stderr")):
        data = getattr(error, attribute, b"") or b""
        data = data.encode("utf-8", errors="replace") if type(data) is str else data
        if type(data) is not bytes:
            data = repr(data).encode("utf-8")
        retained = data[:1 << 20]
        (Path(out) / ("private-probe-" + stream + ".log")).write_bytes(retained)
        metadata[stream] = {"sha256": digest(data), "original_size_bytes": len(data),
                            "retained_size_bytes": len(retained), "truncated": len(retained) != len(data)}
    write_json(Path(out) / "private-failure.json", metadata)


def fresh_output(out):
    out = Path(out).absolute()
    require(out.is_relative_to(ROOT / "build") and ".." not in out.parts, "region output must be under ignored build/")
    for parent in (out, *out.parents):
        require(not parent.is_symlink(), "region output must not traverse aliases")
        if parent == ROOT:
            break
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    return out


def case_flags(case):
    require(case in CASES, "unknown region scenario")
    return ["--cfg", "k01_emulator", "--cfg", "k02_native", "--cfg", "k02_region_service",
            "--cfg", f'k02_service_case="{case}"']


def descriptor_bytes(case):
    require(case in CASES, "unknown region descriptor scenario")
    return MAGIC + struct.pack("<9Q", 1, CASES.index(case), 1, 2, *ADDRESSES.values(), 96)


def decode_request(raw):
    """Decode raw submitted bytes; malformed requests remain observable denials."""
    require(type(raw) is bytes and len(raw) == 96, "region request capture must contain exactly96 bytes")
    magic, version, size, flags, request_id, opcode, reserved0, slot, generation, domain, target, offset, length, va, rights, reserved1 = struct.unpack("<8sHHIQIIII7Q", raw)
    return {"magic_hex": magic.hex(), "version": version, "size": size, "flags": flags,
            "request_id": request_id, "opcode": opcode, "reserved0": reserved0,
            "capability_slot": slot, "capability_generation": generation, "capability_domain": domain,
            "argument": target, "offset": offset, "length": length, "virtual_address": va,
            "rights": rights, "reserved1": reserved1}
