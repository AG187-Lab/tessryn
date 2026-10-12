"""Fixture model/state admission contract, with no qualified inference backend."""

from __future__ import annotations

import json
import re

from .codec import DescriptorError, PROFILE, U64_MAX, _shape, integer

MEMORY_FIELDS = {"weights", "state", "workspace", "transfer", "reserved_growth", "total"}
STATE_FIELDS = {"kind", "precision", "layout", "ownership_generation", "placement_epoch"}
SHARD_FIELDS = {"index", "count", "layer_start", "layer_end", "state", "memory"}
MODEL_FIELDS = {"schema_version", "model_id", "architecture", "artifact_sha256", "tokenizer_sha256",
                "precision", "layer_count", "operators", "shards"}


def validate_model(value: dict) -> dict:
    """Validate one exact, complete shard group. Reject all implicit conversions."""
    value = _shape(value, MODEL_FIELDS, "model")
    profile = json.loads((PROFILE / "compatibility.json").read_text())["model_profile"]
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise DescriptorError("unsupported model version")
    if type(value["model_id"]) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value["model_id"]):
        raise DescriptorError("invalid model identity")
    for name in ("artifact_sha256", "tokenizer_sha256"):
        if type(value[name]) is not str or not re.fullmatch("[0-9a-f]{64}", value[name]):
            raise DescriptorError("invalid artifact hash")
    if value["architecture"] not in profile["architectures"] or value["precision"] not in profile["precisions"]:
        raise DescriptorError("incompatible model format")
    layer_count = integer(value["layer_count"], 32, "layer_count", positive=True)
    operators = value["operators"]
    if (type(operators) is not list or not operators or any(type(op) is not str or
            op not in profile["operators"] for op in operators) or len(set(operators)) != len(operators)):
        raise DescriptorError("unsupported operator set")
    shards = value["shards"]
    if type(shards) is not list or not 1 <= len(shards) <= 1024:
        raise DescriptorError("invalid shard count")
    next_layer, epoch = 0, None
    for expected_index, shard in enumerate(shards):
        shard = _shape(shard, SHARD_FIELDS, "shard")
        for name in ("index", "count", "layer_start", "layer_end"):
            integer(shard[name], 32, name)
        if shard["index"] != expected_index or shard["count"] != len(shards):
            raise DescriptorError("inconsistent shard group")
        if shard["layer_start"] != next_layer or not next_layer < shard["layer_end"] <= layer_count:
            raise DescriptorError("invalid layer partition")
        next_layer = shard["layer_end"]
        state = _shape(shard["state"], STATE_FIELDS, "state")
        if (state["kind"] not in profile["state_kinds"] or state["layout"] not in profile["state_layouts"] or
                state["precision"] != value["precision"]):
            raise DescriptorError("incompatible state format; conversion required")
        integer(state["ownership_generation"], 32, "ownership_generation", positive=True)
        integer(state["placement_epoch"], 64, "placement_epoch", positive=True)
        if epoch is None:
            epoch = state["placement_epoch"]
        if state["placement_epoch"] != epoch:
            raise DescriptorError("mixed placement epochs")
        memory = _shape(shard["memory"], MEMORY_FIELDS, "memory")
        for name in MEMORY_FIELDS:
            integer(memory[name], 64, name)
        total = sum(memory[name] for name in MEMORY_FIELDS - {"total"})
        if total > U64_MAX or memory["total"] != total:
            raise DescriptorError("invalid complete memory accounting")
    if next_layer != layer_count:
        raise DescriptorError("incomplete layer partition")
    return {"status": "fixture_contract_passed", "shard_count": len(shards), "placement_epoch": epoch,
            "native_inference": "unavailable", "conversion": "none"}


def load_model(text: str) -> dict:
    """Parse and validate a bounded JSON record without ambiguous duplicate keys."""
    if type(text) is not str or len(text.encode()) > 1_048_576:
        raise DescriptorError("model record must be bounded JSON text")

    def unique(pairs):
        value = {}
        for name, item in pairs:
            if name in value:
                raise DescriptorError("duplicate JSON key")
            value[name] = item
        return value

    try:
        value = json.loads(text, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(DescriptorError("nonfinite JSON value")))
    except (ValueError, RecursionError) as error:
        raise DescriptorError(f"invalid model JSON: {error}") from error
    validate_model(value)
    return value
