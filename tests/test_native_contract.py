"""Independent byte vectors and malformed model/ABI boundary cases."""

import copy
import json
import struct
import unittest

from tools.g02.codec import DescriptorError, PROFILE, U64_MAX, contract, decode, encode
from tools.g02.model import load_model, validate_model


def model_fixture():
    def shard(index):
        return {"index": index, "count": 2, "layer_start": index * 2, "layer_end": (index + 1) * 2,
                "state": {"kind": "kv", "precision": "f16", "layout": "contiguous_le_v1",
                          "ownership_generation": 7, "placement_epoch": 3},
                "memory": {"weights": 64, "state": 32, "workspace": 16, "transfer": 8,
                           "reserved_growth": 8, "total": 128}}
    return {"schema_version": 1, "model_id": "original-fixture-v1", "architecture": "conformance_fixture",
            "artifact_sha256": "a" * 64, "tokenizer_sha256": "b" * 64, "precision": "f16",
            "layer_count": 4, "operators": ["copy", "add", "matmul"], "shards": [shard(0), shard(1)]}


class BinaryContractTests(unittest.TestCase):
    def setUp(self):
        self.spec = contract()
        self.vectors = json.loads((PROFILE / "vectors.json").read_text())

    def test_literal_golden_vectors_in_both_directions(self):
        self.assertGreaterEqual(len(self.vectors["positive"]), 4)
        for vector in self.vectors["positive"]:
            with self.subTest(vector=vector["name"]):
                data = bytes.fromhex(vector["hex"])
                self.assertEqual(decode(vector["layout"], data), vector["values"])
                self.assertEqual(encode(vector["layout"], vector["values"]), data)

    def test_negative_golden_frames_are_rejected(self):
        self.assertGreaterEqual(len(self.vectors["negative"]), 8)
        for vector in self.vectors["negative"]:
            with self.subTest(vector=vector["name"]):
                with self.assertRaises(DescriptorError):
                    decode(vector["layout"], bytes.fromhex(vector["hex"]))

    def sample(self, layout):
        return copy.deepcopy(next(v["values"] for v in self.vectors["positive"] if v["layout"] == layout))

    def test_all_descriptor_truncations_and_extra_bytes_reject(self):
        for vector in self.vectors["positive"]:
            data = bytes.fromhex(vector["hex"])
            for size in range(len(data)):
                with self.subTest(vector=vector["name"], size=size), self.assertRaises(DescriptorError):
                    decode(vector["layout"], data[:size])
            with self.assertRaises(DescriptorError):
                decode(vector["layout"], data + b"\0")

    def test_wrong_header_versions_kind_size_reserved_reject(self):
        for key, value in (("major", 2), ("minor", 1), ("kind", 99), ("size", 16),
                           ("flags", 1), ("reserved", 1)):
            sample = self.sample("Submission")
            sample["header"][key] = value
            with self.subTest(key=key), self.assertRaises(DescriptorError):
                encode("Submission", sample)

    def test_encode_rejects_unknown_missing_fields_and_width_coercion(self):
        for value in (True, -1, 1 << 64, "1", 1.0, None):
            sample = self.sample("Submission")
            sample["request_id"] = value
            with self.subTest(value=value), self.assertRaises(DescriptorError):
                encode("Submission", sample)

    def test_malformed_frame_types_have_explicit_errors(self):
        for frame in (None, [0] * 128, 128, "0" * 128):
            with self.subTest(frame=type(frame).__name__), self.assertRaises(DescriptorError):
                decode("Submission", frame)
        for layout in (None, [], {}, 1):
            with self.assertRaises(DescriptorError):
                encode(layout, {})
            with self.assertRaises(DescriptorError):
                decode(layout, b"")
        for change in (lambda v: v.pop("task_id"), lambda v: v.update(extra=0)):
            sample = self.sample("Submission")
            change(sample)
            with self.assertRaises(DescriptorError):
                encode("Submission", sample)

    def test_scalar_encoding_is_explicitly_little_endian_and_unaligned(self):
        sample = {"slot": 0x01020304, "generation": 0x05060708, "domain": 0x1112131415161718}
        raw = bytes.fromhex("04030201080706051817161514131211")
        self.assertEqual(encode("CapabilityRef", sample), raw)
        self.assertEqual(decode("CapabilityRef", (b"x" + raw)[1:]), sample)

    def test_range_overflow_and_unknown_enum_reject(self):
        sample = self.sample("Submission")
        sample["offset"], sample["length"] = U64_MAX, 1
        with self.assertRaisesRegex(DescriptorError, "overflow"):
            encode("Submission", sample)
        for layout, field in (("Submission", "operation"), ("Completion", "status"),
                              ("Completion", "milestone")):
            sample = self.sample(layout)
            sample[field] = 99
            with self.assertRaisesRegex(DescriptorError, "unknown"):
                encode(layout, sample)

    def test_capability_and_control_request_shape(self):
        sample = self.sample("Submission")
        sample["region"]["generation"] = 0
        with self.assertRaisesRegex(DescriptorError, "incomplete"):
            encode("Submission", sample)
        sample = self.sample("Submission")
        sample["operation"] = 4
        with self.assertRaisesRegex(DescriptorError, "control"):
            encode("Submission", sample)
        sample.update(region={"slot": 0, "generation": 0, "domain": 0}, offset=0, length=0,
                      deadline_ns=0, placement_epoch=0)
        self.assertEqual(decode("Submission", encode("Submission", sample)), sample)

    def test_completion_cannot_report_fault_as_success_or_fake_ownership(self):
        sample = self.sample("Completion")
        sample.update(status=0, milestone=7)
        with self.assertRaisesRegex(DescriptorError, "fault"):
            encode("Completion", sample)
        sample = self.sample("Completion")
        sample["region"] = {"slot": 0, "generation": 0, "domain": 0}
        sample["ownership_generation"] = 1
        with self.assertRaisesRegex(DescriptorError, "absent"):
            encode("Completion", sample)
        sample.update(produced_length=0, ownership_generation=0, status=9, milestone=7)
        self.assertEqual(decode("Completion", encode("Completion", sample)), sample)

    def test_negotiation_no_downgrade_or_unknown_features(self):
        sample = self.sample("Negotiation")
        for changes in ({"min_major": 2}, {"max_major": 0}, {"required_features": 1},
                        {"supported_features": 1}, {"domain": 0}):
            altered = sample | changes
            with self.subTest(changes=changes), self.assertRaises(DescriptorError):
                encode("Negotiation", altered)
        sample.update(min_major=0, min_minor=0)
        self.assertEqual(decode("Negotiation", encode("Negotiation", sample)), sample)

    def test_changed_profile_metadata_cannot_relabel_v1_evidence(self):
        vector = self.vectors["positive"][0]
        for field, value in (("major", 2), ("minor", 1), ("feature_mask", 1), ("byte_order", "big"),
                             ("alignment", 4), ("max_descriptor_size", 256), ("major", True),
                             ("major", 1.0), ("minor", False), ("feature_mask", False)):
            altered = copy.deepcopy(self.spec)
            altered["abi"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(DescriptorError, "profile"):
                decode(vector["layout"], bytes.fromhex(vector["hex"]), altered)
            with self.assertRaisesRegex(DescriptorError, "profile"):
                encode(vector["layout"], vector["values"], altered)


class ModelContractTests(unittest.TestCase):
    def reject(self, mutate):
        value = model_fixture()
        mutate(value)
        before = copy.deepcopy(value)
        with self.assertRaises(DescriptorError):
            validate_model(value)
        self.assertEqual(value, before, "rejection must not rewrite the descriptor")

    def test_complete_partition_and_memory_ledger(self):
        result = validate_model(model_fixture())
        self.assertEqual(result["status"], "fixture_contract_passed")
        self.assertEqual(result["shard_count"], 2)
        self.assertEqual(result["native_inference"], "unavailable")

    def test_versions_and_unqualified_models_reject(self):
        for name, value in (("schema_version", True), ("schema_version", 2), ("architecture", "llama"),
                            ("precision", "int4"), ("layer_count", 0), ("layer_count", 1 << 32),
                            ("artifact_sha256", "z" * 64), ("tokenizer_sha256", "A" * 64)):
            with self.subTest(name=name, value=value):
                self.reject(lambda v: v.update({name: value}))

    def test_unknown_or_duplicate_operators_reject(self):
        for operators in ([], ["add", "add"], ["attention"], [True], "add"):
            self.reject(lambda v: v.update(operators=operators))

    def test_partitions_require_exact_coverage_and_count(self):
        for field, value in (("index", 0), ("count", 3), ("layer_start", 1), ("layer_end", 3)):
            self.reject(lambda v: v["shards"][1].update({field: value}))
        self.reject(lambda v: v["shards"].clear())
        self.reject(lambda v: v["shards"].reverse())

    def test_state_conversion_stale_epoch_and_generation_reject(self):
        for field, value in (("precision", "f32"), ("layout", "paged"), ("kind", "unknown"),
                            ("ownership_generation", 0), ("ownership_generation", 1 << 32), ("placement_epoch", 4)):
            self.reject(lambda v: v["shards"][1]["state"].update({field: value}))

    def test_memory_total_growth_and_overflow_reject(self):
        self.reject(lambda v: v["shards"][0]["memory"].update(total=120))
        self.reject(lambda v: v["shards"][0]["memory"].update(reserved_growth=U64_MAX))
        self.reject(lambda v: v["shards"][0]["memory"].update(weights=-1))

    def test_extra_missing_fields_and_bool_counters_reject(self):
        self.reject(lambda v: v.update(qualified=True))
        self.reject(lambda v: v["shards"][0]["state"].pop("layout"))
        self.reject(lambda v: v["shards"][0].update(index=False))
        self.reject(lambda v: v["shards"][0]["memory"].update(total=True))

    def test_json_duplicate_keys_and_nonfinite_values_reject(self):
        text = json.dumps(model_fixture())
        self.assertEqual(load_model(text), model_fixture())
        duplicate = text.replace('"schema_version": 1', '"schema_version": 2, "schema_version": 1')
        for malformed in (duplicate, text.replace('"total": 128', '"total": NaN'), "[", None,
                          "[" * 2000 + "]" * 2000, "x" * 1_048_577):
            with self.subTest(kind=type(malformed).__name__), self.assertRaises(DescriptorError):
                load_model(malformed)


if __name__ == "__main__":
    unittest.main()
