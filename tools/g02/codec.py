"""Strict portable ABI fixture codec; this is not a privileged kernel parser."""

from __future__ import annotations

import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "interfaces" / "abi-v1"
U64_MAX = (1 << 64) - 1
SCALARS = {"u16": ("H", 2), "u32": ("I", 4), "u64": ("Q", 8)}
ABI_V1 = {"major": 1, "minor": 0, "byte_order": "little", "alignment": 8,
          "feature_mask": 0, "max_descriptor_size": 128}


class DescriptorError(ValueError):
    """A descriptor cannot be admitted under the provisional contract."""


def integer(value: object, bits: int, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or not (int(positive) <= value < 1 << bits):
        raise DescriptorError(f"invalid integer: {name}")
    return value


def contract() -> dict:
    return json.loads((PROFILE / "contract.json").read_text())


def _profile(definitions: dict) -> None:
    if definitions.get("abi") != ABI_V1:
        raise DescriptorError("unsupported contract profile; implement a versioned codec")


def _shape(value: object, names: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != names:
        raise DescriptorError(f"invalid fields: {label}")
    return value


def _walk_encode(layout: str, value: dict, definitions: dict) -> bytes:
    spec = definitions["layouts"][layout]
    value = _shape(value, {field["name"] for field in spec["fields"]}, layout)
    data = bytearray(spec["size"])
    for field in spec["fields"]:
        name, kind, offset = field["name"], field["type"], field["offset"]
        if kind in SCALARS:
            fmt, width = SCALARS[kind]
            struct.pack_into("<" + fmt, data, offset, integer(value[name], width * 8, name))
        else:
            nested = _walk_encode(kind, value[name], definitions)
            data[offset:offset + len(nested)] = nested
    return bytes(data)


def _walk_decode(layout: str, data: bytes, definitions: dict) -> dict:
    spec = definitions["layouts"][layout]
    if len(data) != spec["size"]:
        raise DescriptorError("invalid size")
    result = {}
    for field in spec["fields"]:
        name, kind, offset = field["name"], field["type"], field["offset"]
        if kind in SCALARS:
            result[name] = struct.unpack_from("<" + SCALARS[kind][0], data, offset)[0]
        else:
            width = definitions["layouts"][kind]["size"]
            result[name] = _walk_decode(kind, data[offset:offset + width], definitions)
    return result


def _capability(value: dict, *, required: bool = False) -> None:
    if not any(value.values()):
        if required:
            raise DescriptorError("missing capability")
        return
    if not value["domain"] or not value["generation"]:
        raise DescriptorError("incomplete capability")


def _validate(layout: str, value: dict, definitions: dict) -> None:
    if layout == "CapabilityRef":
        _capability(value)
        return
    if layout == "Header":
        raise DescriptorError("header is not a standalone descriptor")
    header = value["header"]
    if (header["major"], header["minor"]) != (1, 0):
        raise DescriptorError("unsupported version")
    spec = definitions["layouts"][layout]
    if header["size"] != spec["size"] or header["kind"] != spec["kind"]:
        raise DescriptorError("invalid size or kind")
    if header["flags"] or header["reserved"] or value.get("reserved", 0):
        raise DescriptorError("nonzero reserved field")
    for field in spec["fields"]:
        if field["type"] == "CapabilityRef":
            _capability(value[field["name"]], required=(layout == "Region" or
                         layout == "Submission" and field["name"] == "completion"))
    if layout == "Negotiation":
        minimum = value["min_major"], value["min_minor"]
        maximum = value["max_major"], value["max_minor"]
        if minimum > maximum or not minimum <= (1, 0) <= maximum:
            raise DescriptorError("unsupported negotiation range")
        if value["required_features"] or value["supported_features"]:
            raise DescriptorError("unsupported features")
        if not value["domain"]:
            raise DescriptorError("invalid domain")
    elif layout == "Region":
        for name in ("owner_task", "length", "budget_id"):
            if not value[name]:
                raise DescriptorError(f"zero {name}")
    elif layout == "Submission":
        if value["operation"] not in definitions["operations"].values():
            raise DescriptorError("unknown operation")
        for name in ("request_id", "task_id", "budget_id"):
            if not value[name]:
                raise DescriptorError(f"zero {name}")
        if value["offset"] + value["length"] > U64_MAX:
            raise DescriptorError("range overflow")
        if value["operation"] in (4, 5):
            if any(value["region"].values()) or value["offset"] or value["length"]:
                raise DescriptorError("control request carries a region")
        else:
            _capability(value["region"], required=True)
    elif layout == "Completion":
        if value["status"] not in definitions["statuses"].values():
            raise DescriptorError("unknown status")
        if value["milestone"] not in definitions["milestones"].values():
            raise DescriptorError("unknown milestone")
        for name in ("request_id", "sequence"):
            if not value[name]:
                raise DescriptorError(f"zero {name}")
        if not value["milestone"]:
            raise DescriptorError("missing milestone")
        if any(value["region"].values()):
            if not value["ownership_generation"]:
                raise DescriptorError("missing ownership generation")
        elif value["produced_length"] or value["ownership_generation"]:
            raise DescriptorError("absent region has ownership metadata")
        if value["milestone"] == 7 and value["status"] == 0:
            raise DescriptorError("fault reported as success")


def decode(layout: str, data: bytes, definitions: dict | None = None) -> dict:
    definitions = contract() if definitions is None else definitions
    _profile(definitions)
    if type(layout) is not str or layout not in definitions["layouts"]:
        raise DescriptorError("unknown layout")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise DescriptorError("descriptor must be a byte frame")
    data = bytes(data)
    value = _walk_decode(layout, data, definitions)
    _validate(layout, value, definitions)
    return value


def encode(layout: str, value: dict, definitions: dict | None = None) -> bytes:
    definitions = contract() if definitions is None else definitions
    _profile(definitions)
    if type(layout) is not str or layout not in definitions["layouts"]:
        raise DescriptorError("unknown layout")
    data = _walk_encode(layout, value, definitions)
    _validate(layout, value, definitions)
    return data
