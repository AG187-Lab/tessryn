"""Synthetic fixtures exercise protocol rejection, never native execution."""

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import k02_native_protocol as protocol


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def expectations():
    contract = protocol.read_json(protocol.CONTRACT_PATH)
    domains = {name: index + 1 for index, name in enumerate(protocol.DOMAINS)}
    handles = {name: {"slot": 0, "generation": 1, "domain": domains[name]}
               for name in ("A", "B", "C", "D")}
    handles.update({"B_writeonly": {"slot": 3, "generation": 1, "domain": domains["B"]},
                    "B_byte": {"slot": 4, "generation": 1, "domain": domains["B"]},
                    "old_B": {"slot": 2, "generation": 1, "domain": domains["B"]},
                    "replacement_B": {"slot": 2, "generation": 2, "domain": domains["B"]}})
    pages = {"unauthorized": 0x100000, "readonly": 0x110000, "guard": 0x111000,
             "kernel": 0xFFFF800000100000, "policy": 0xFFFF800000110000,
             "page_table": 0xFFFF800000120000, "data_nx": 0x130000,
             "revoked_B": 0x140000, "revoked_D": 0x150000,
             "reuse_B": 0x160000, "reuse_C": 0x170000}
    rips = {name: 0x400000 + 16 * (index + 1)
            for index, name in enumerate(contract["faults"])}
    rips["nx_fetch"] = pages["data_nx"]
    return {"schema": "tessryn-k02-native-expectations/v1",
            "binding": {**{name: sha("synthetic " + name)[:40] for name in protocol.COMMITS},
                        **{name: sha("synthetic " + name) for name in protocol.BINDING_HASHES},
                        "protocol_sources_sha256": protocol.source_hashes(), "environment": "synthetic"},
            "profile": copy.deepcopy(contract["profile"]), "domains": domains,
            "roots": {name: 0x2000 + index * 4096 for index, name in enumerate(protocol.DOMAINS)},
            "handles": handles,
            "leases": {"B": {"slot": 0, "generation": 1}, "D": {"slot": 1, "generation": 1},
                       "old_B": {"slot": 2, "generation": 1}, "replacement_B": {"slot": 2, "generation": 2}},
            "reuse_frame": 0x200000, "pages": pages, "code": {"start": 0x400000, "end": 0x401000},
            "probe_rips": rips, "user_cs": 0x1B,
            "sentinels": {name: sha("synthetic sentinel " + name) for name in protocol.SENTINELS},
            "case_contexts": {name: {"id": sha("synthetic boot " + name),
                                     "raw_capture_sha256": sha("synthetic raw capture " + name),
                                     "initial_state": "fresh_original_kernel_boot"}
                              for name in contract["cases"]}}


def transcript(expected):
    contract = protocol.read_json(protocol.CONTRACT_PATH)
    return {"schema": "tessryn-k02-native-protocol/v1", "evidence_kind": "synthetic_fixture",
            "binding": copy.deepcopy(expected["binding"]), "profile": copy.deepcopy(expected["profile"]),
            "cases": protocol.expected_cases(expected, contract)}


class NativeProtocolTests(unittest.TestCase):
    def setUp(self):
        self.expected = expectations()
        self.trace = transcript(self.expected)

    def validate(self, trace=None, expected=None):
        # Exercise the same bounded decoding boundary used by the command.
        values = (trace if trace is not None else self.trace,
                  expected if expected is not None else self.expected)
        return protocol.validate(*(protocol.strict_json(json.dumps(value).encode()) for value in values))

    def case(self, name, trace=None):
        return next(item for item in (trace or self.trace)["cases"] if item["case"] == name)

    def event(self, case, name, trace=None):
        return next(item for item in self.case(case, trace)["events"] if item["event"] == name)

    def test_complete_synthetic_contract_passes_protocol_only(self):
        result = self.validate()
        self.assertEqual(result["kind"], "protocol_validation")
        self.assertEqual(result["case_count"], 10)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["native_qualification"], "not_established")
        self.assertEqual(result["hardware_authentication"], "unavailable")

    def test_protocol_source_changes_during_validation_reject(self):
        bound = self.expected["binding"]["protocol_sources_sha256"]
        changed = {**bound, "planning/k02-native-cases.json": sha("changed contract")}
        for returned in ([bound, changed], [bound, bound, changed]):
            with self.subTest(hashes=returned), patch.object(protocol, "source_hashes", side_effect=returned), self.assertRaises(ValueError):
                self.validate()

    def test_external_emulator_and_hardware_labels_still_cannot_qualify(self):
        for environment in ("original_kernel_emulator", "physical_hardware"):
            with self.subTest(environment=environment):
                expected = copy.deepcopy(self.expected)
                expected["binding"]["environment"] = environment
                trace = transcript(expected)
                trace["evidence_kind"] = "external_capture"
                result = self.validate(trace, expected)
                self.assertEqual(result["kind"], "protocol_validation")
                self.assertEqual(result["native_qualification"], "not_established")
                self.assertEqual(result["hardware_authentication"], "unavailable")

    def test_duplicate_nonfinite_unsupported_and_oversized_json_rejects(self):
        inputs = [b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}',
                  b'{"a":Infinity}', b'{"a":-Infinity}', b'{"a":1.0}', b'{"a":null}',
                  b'{"a":-1}', b'"\xff"', b'[' * 14 + b'0' + b']' * 14,
                  json.dumps([0] * 257).encode(), json.dumps("x" * 4097).encode(),
                  json.dumps({"x" * 81: 0}).encode(), b" " * (protocol.MAX_BYTES + 1)]
        for raw in inputs:
            with self.subTest(raw=raw[:60]), self.assertRaises(ValueError):
                protocol.strict_json(raw)

    def test_bounded_file_reader_rejects_fifo_directory_symlink_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            regular = work / "regular.json"
            regular.write_bytes(b'{"value":1}')
            self.assertEqual(protocol.read_json(regular), {"value": 1})
            fifo = work / "fifo"
            os.mkfifo(fifo)
            alias = work / "alias.json"
            alias.symlink_to(regular.name)
            oversized = work / "oversized.json"
            oversized.write_bytes(b"x" * (protocol.MAX_BYTES + 1))
            for path in (fifo, work, alias, oversized):
                with self.subTest(path=path.name), self.assertRaises((ValueError, OSError)):
                    protocol.read_json(path)

    def test_missing_duplicate_reordered_and_unknown_cases_reject(self):
        for change in ("missing", "duplicate", "reordered", "unknown"):
            trace = copy.deepcopy(self.trace)
            cases = trace["cases"]
            if change == "missing":
                cases.pop()
            elif change == "duplicate":
                cases[-1] = copy.deepcopy(cases[0])
            elif change == "reordered":
                cases[0], cases[1] = cases[1], cases[0]
            else:
                cases[0]["case"] = "timeout"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(trace)

    def test_transcript_hashes_profile_or_probe_expectations_cannot_self_authorize(self):
        changes = [lambda trace: trace["binding"].update(kernel_image_sha256=sha("wrong")),
                   lambda trace: trace["binding"].update(raw_capture_sha256=sha("wrong")),
                   lambda trace: trace["profile"].update(nx_enabled=False),
                   lambda trace: trace.update(evidence_kind="external_capture"),
                   lambda trace: trace.update(expected_rip=123),
                   lambda trace: self.event("unauthorized_read", "page_fault", trace).update(rip=123),
                   lambda trace: self.event("unauthorized_read", "page_fault", trace).update(error_code=0)]
        for change in changes:
            trace = copy.deepcopy(self.trace)
            change(trace)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(trace)

    def test_independent_bindings_reject_invalid_or_contradictory_values(self):
        changes = [lambda expected: expected["domains"].update(B=True),
                   lambda expected: expected["domains"].update(B=0),
                   lambda expected: expected["domains"].update(B=expected["domains"]["D"]),
                   lambda expected: expected["roots"].update(B=expected["roots"]["D"]),
                   lambda expected: expected["roots"].update(B=4097),
                   lambda expected: expected.update(reuse_frame=expected["roots"]["B"]),
                   lambda expected: expected.update(reuse_frame=1 << 48),
                   lambda expected: expected["pages"].update(unauthorized=1 << 47),
                   lambda expected: expected["pages"].update(reuse_B=0xFFFF800000000000),
                   lambda expected: expected["pages"].update(guard=0x112000),
                   lambda expected: expected["pages"].update(policy=expected["code"]["start"]),
                   lambda expected: expected["probe_rips"].update(unauthorized_read=0x500000),
                   lambda expected: expected["probe_rips"].update(nx_fetch=0x400100),
                   lambda expected: expected.update(user_cs=0x18),
                   lambda expected: expected.update(user_cs=0x7),
                   lambda expected: expected["handles"]["B"].update(generation=0),
                   lambda expected: expected["handles"]["B"].update(domain=expected["domains"]["A"]),
                   lambda expected: expected["handles"]["replacement_B"].update(generation=1),
                   lambda expected: expected["leases"]["D"].update(slot=expected["leases"]["B"]["slot"]),
                   lambda expected: expected["leases"]["old_B"].update(generation=(1 << 32) - 1),
                   lambda expected: expected["binding"]["protocol_sources_sha256"].update(
                       {"tools/k02_native_protocol.py": sha("stale evaluator")}),
                   lambda expected: expected["binding"].update(raw_capture_sha256="missing"),
                   lambda expected: expected["case_contexts"].update(
                       caller_forgery=copy.deepcopy(expected["case_contexts"]["unauthorized_read"]))]
        for change in changes:
            expected = copy.deepcopy(self.expected)
            change(expected)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(self.trace, expected)

    def test_every_fault_binds_cpl3_exact_probe_full_error_code_and_root(self):
        faults = [event for case in self.trace["cases"] for event in case["events"]
                  if event["event"] == "page_fault"]
        self.assertEqual(len(faults), 16)
        for fault in faults:
            self.assertEqual(fault["vector"], 14)
            self.assertEqual(fault["cs"], 0x1B)
            self.assertEqual(fault["rip"], self.expected["probe_rips"][fault["probe"]])
            self.assertTrue(fault["error_code"] & 4)
            for key, wrong in (("vector", 13), ("cs", 8), ("rip", fault["rip"] + 1),
                               ("cr2", fault["cr2"] + 1), ("error_code", fault["error_code"] | 0x8000),
                               ("root", fault["root"] + 4096), ("recovered", False)):
                trace = copy.deepcopy(self.trace)
                target = next(event for case in trace["cases"] for event in case["events"]
                              if event.get("probe") == fault["probe"])
                target[key] = wrong
                with self.subTest(probe=fault["probe"], key=key), self.assertRaises(ValueError):
                    self.validate(trace)

    def test_recursive_shared_mapping_contract_obeys_core_readonly_owner_rule(self):
        events = self.case("recursive_revocation")["events"]
        self.assertEqual([item["rights"] for item in events if item["event"] == "delegated"], [21, 5])
        mappings = [item for item in events if item["event"] == "mapping_installed"]
        self.assertEqual({item["root"] for item in mappings}, {self.expected["roots"]["B"], self.expected["roots"]["D"]})
        self.assertTrue(all(item["physical_frame"] == self.expected["reuse_frame"] and
                            item["readable"] and not item["writable"] for item in mappings))
        self.assertTrue(all(item["read_executed"] and not item["write_executed"]
                            for item in events if item["event"] == "mapping_primed"))
        for name in ("mapping_installed", "mapping_primed", "clear_pte", "invalidate", "quiesce"):
            trace = copy.deepcopy(self.trace)
            target = self.case("recursive_revocation", trace)["events"]
            target.remove(next(item for item in target if item["event"] == name and item["domain"] == 4))
            with self.subTest(missing_descendant_event=name), self.assertRaises(ValueError):
                self.validate(trace)

    def test_writable_reuse_requires_bound_frame_and_complete_ordered_teardown(self):
        events = self.case("writable_reuse")["events"]
        self.assertEqual([item["event"] for item in events],
                         ["fresh_boot", "backing_owned", "mapping_installed", "mapping_primed", "revoked",
                          "fence", "clear_pte", "invalidate", "quiesce", "lease_released", "capability_released",
                          "scrubbed", "reassigned", "page_fault", "page_fault", "sentinel_unchanged"])
        self.assertTrue(self.event("writable_reuse", "mapping_primed")["write_executed"])
        for name in ("mapping_installed", "mapping_primed", "revoked", "fence", "clear_pte",
                     "invalidate", "quiesce", "lease_released", "capability_released", "scrubbed", "reassigned"):
            trace = copy.deepcopy(self.trace)
            self.event("writable_reuse", name, trace)["physical_frame"] += 4096
            with self.subTest(wrong_frame=name), self.assertRaises(ValueError):
                self.validate(trace)
        for index in range(4, 12):
            trace = copy.deepcopy(self.trace)
            changed = self.case("writable_reuse", trace)["events"]
            changed[index], changed[index + 1] = changed[index + 1], changed[index]
            with self.subTest(swapped=index), self.assertRaises(ValueError):
                self.validate(trace)

    def test_exact_bounds_owns_distinct_writeonly_capability(self):
        events = self.case("exact_bounds")["events"]
        writeonly = next(item for item in events if item.get("rights") == 6 and item["event"] == "delegated")
        denial = next(item for item in events if item.get("operation") == "map_without_read")
        self.assertEqual(writeonly["child"], self.expected["handles"]["B_writeonly"])
        self.assertEqual(denial["capability"], writeonly["child"])
        self.assertNotEqual(writeonly["child"], self.expected["handles"]["B"])
        self.assertFalse(denial["pte_published"])
        byte_cap = next(item for item in events if item["event"] == "delegated" and item["offset"] == 1)
        self.assertEqual(byte_cap["child"], self.expected["handles"]["B_byte"])
        self.assertEqual((byte_cap["offset"], byte_cap["length"], byte_cap["rights"]), (1, 4094, 5))
        byte_denials = [item for item in events if item.get("operation") == "map_byte_slice"]
        self.assertEqual([item["length"] for item in byte_denials], [4094, 4096])
        self.assertTrue(all(item["capability"] == byte_cap["child"] and item["offset"] == 0 and
                            item["capability_offset"] == 1 and item["capability_length"] == 4094 and
                            not item["pte_published"] for item in byte_denials))

    def test_privileged_denials_exercise_owned_lease_and_fenced_phase(self):
        events = self.case("trusted_operation_forgery")["events"]
        denials = [item for item in events if item["event"] == "dispatch_denied"]
        self.assertTrue(all(item["caller"] == self.expected["domains"]["B"] and
                            item["capability"] == self.expected["handles"]["B"] and
                            item["submitted_lease"] == self.expected["leases"]["B"] and
                            item["denial_reason"] == "untrusted_origin" and not item["charge_released"]
                            for item in denials))
        fence_index = next(index for index, item in enumerate(events) if item["event"] == "fence")
        self.assertTrue(events[fence_index]["trusted"])
        self.assertTrue(events[fence_index]["pte_installed"])
        self.assertEqual(events[fence_index + 1]["operation"], "quiesce")
        self.assertEqual(events[fence_index + 1]["lease_phase"], "fenced")
        self.assertTrue(events[fence_index + 1]["pte_installed"])
        retained = events[fence_index + 2]
        self.assertEqual(retained["event"], "mapping_owner_retained")
        self.assertEqual(retained["lease"], self.expected["leases"]["B"])
        self.assertEqual(retained["phase"], "fenced")
        self.assertTrue(retained["pte_installed"])

    def test_fenced_mapping_owner_must_survive_user_quiesce(self):
        for field, wrong in (("phase", "active"), ("pte_installed", False),
                             ("charge_retained", False), ("root", self.expected["roots"]["D"]),
                             ("lease", self.expected["leases"]["replacement_B"]),
                             ("physical_frame", self.expected["reuse_frame"] + 4096)):
            trace = copy.deepcopy(self.trace)
            self.event("trusted_operation_forgery", "mapping_owner_retained", trace)[field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(trace)
        trace = copy.deepcopy(self.trace)
        events = self.case("trusted_operation_forgery", trace)["events"]
        events.remove(self.event("trusted_operation_forgery", "mapping_owner_retained", trace))
        with self.assertRaises(ValueError):
            self.validate(trace)

    def test_stale_case_tears_down_old_owner_and_initializes_independent_victim(self):
        events = self.case("stale_identities")["events"]
        names = [item["event"] for item in events]
        self.assertLess(names.index("fence"), names.index("clear_pte"))
        self.assertLess(names.index("invalidate"), names.index("quiesce"))
        self.assertLess(names.index("quiesce"), names.index("lease_released"))
        self.assertLess(names.index("capability_released"), names.index("retired_generation"))
        self.assertLess(names.index("scrubbed"), names.index("victim_initialized"))
        self.assertLess(names.index("victim_initialized"), names.index("dispatch_denied"))
        initialized = self.event("stale_identities", "victim_initialized")
        self.assertEqual(initialized["physical_frame"], self.expected["reuse_frame"])
        self.assertEqual(initialized["page"], self.expected["pages"]["reuse_C"])
        self.assertEqual(initialized["initial_sha256"], self.expected["sentinels"]["C"])

    def test_forgery_sentinels_generations_keys_and_integer_types_reject(self):
        changes = [lambda trace: self.event("caller_forgery", "dispatch_denied", trace).update(caller=1),
                   lambda trace: self.event("trusted_operation_forgery", "dispatch_denied", trace).update(charge_released=True),
                   lambda trace: self.event("read_only_sharing", "sentinel_unchanged", trace).update(after_sha256=sha("changed")),
                   lambda trace: self.event("writable_reuse", "sentinel_unchanged", trace).update(after_sha256=sha("victim changed")),
                   lambda trace: self.event("stale_identities", "dispatch_denied", trace)["replacement"].update(generation=1),
                   lambda trace: self.event("data_nx", "nx_confirmed", trace).update(enabled=False),
                   lambda trace: self.event("caller_forgery", "backing_owned", trace).update(committed_pages=True),
                   lambda trace: self.event("caller_forgery", "backing_owned", trace).update(extra="untrusted"),
                   lambda trace: self.event("writable_reuse", "invalidate", trace).update(method="none"),
                   lambda trace: self.event("writable_reuse", "quiesce", trace).update(trusted=False),
                   lambda trace: self.event("writable_reuse", "fence", trace).update(charge_retained=False),
                   lambda trace: self.event("writable_reuse", "page_fault", trace).update(timeout=True),
                   lambda trace: self.event("caller_forgery", "fresh_boot", trace).update(untrusted_state_retained=True)]
        for change in changes:
            trace = copy.deepcopy(self.trace)
            change(trace)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(trace)

    def test_cli_stdout_only_does_not_rewrite_inputs_and_redacts_io_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            trace, expected = work / "trace.json", work / "expectations.json"
            trace.write_text(json.dumps(self.trace))
            expected.write_text(json.dumps(self.expected))
            original = {path.name: path.read_bytes() for path in work.iterdir()}
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(protocol.main(["--input", str(trace), "--expectations", str(expected)]), 0)
            self.assertEqual(json.loads(output.getvalue())["kind"], "protocol_validation")
            self.assertEqual({path.name: path.read_bytes() for path in work.iterdir()}, original)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(protocol.main(["--input", str(work / "private-missing"),
                                                "--expectations", str(expected)]), 1)
            failure = json.loads(output.getvalue())
            self.assertEqual(failure["status"], "failed")
            self.assertNotIn(str(work), failure["reason"])
            self.assertEqual(failure["native_qualification"], "not_established")


if __name__ == "__main__":
    unittest.main()
