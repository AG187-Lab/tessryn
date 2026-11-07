"""Check that the native comparison preserves the original workload inputs."""

import json
import unittest
from pathlib import Path

from tools.k03_native_arrivals_protocol import (
    ARM_ORDER,
    DIRECTED,
    PROFILE_FILE,
    PROFILE_MAGIC,
    SCENARIOS,
    SCHEDULE,
    config_bytes,
    load_profile,
    profile_bytes,
)


ROOT = Path(__file__).resolve().parents[1]


class NativeArrivalProtocolTests(unittest.TestCase):
    def test_compiled_table_contains_each_exact_host_offer(self):
        source = json.loads((ROOT / PROFILE_FILE).read_bytes())
        self.assertEqual(load_profile(), source)
        packed = profile_bytes(load_profile())
        self.assertEqual(packed[:16], PROFILE_MAGIC)
        self.assertEqual(tuple(packed[16:19]), (8, 12, 30))

        cursor = 19
        cancellations = 0
        classes = {1: "decode", 2: "prefill", 3: "control"}
        for scenario in SCENARIOS:
            for expected in source["scenarios"][scenario]:
                job, domain, arrival, work, cancel, kind = packed[cursor:cursor + 6]
                decoded = {
                    "id": job,
                    "domain": domain,
                    "arrival": arrival,
                    "work": work,
                    "cancel": cancel or None,
                    "class": classes[kind],
                }
                self.assertEqual(decoded, expected, (scenario, job))
                cancellations += int(cancel != 0)
                cursor += 6

        self.assertEqual(cursor, len(packed))
        self.assertEqual(cancellations, 8)

    def test_rejects_an_otherwise_valid_workload_edit(self):
        source = (ROOT / PROFILE_FILE).read_bytes()
        changed = source.replace(b'"work": 20', b'"work": 21', 1)
        self.assertNotEqual(changed, source)
        with self.assertRaises(ValueError):
            load_profile(changed)

    def test_directed_case_and_balanced_full_workload_share_one_selector_contract(self):
        self.assertEqual(ARM_ORDER, (4, 16, 16, 4))
        self.assertEqual(SCHEDULE[0], (DIRECTED, 4))
        self.assertEqual(len(SCHEDULE), 13)
        for selector, scenario in enumerate(SCENARIOS):
            self.assertEqual(tuple(q for case, q in SCHEDULE if case == scenario), ARM_ORDER)
            self.assertEqual(config_bytes(scenario, 4), bytes((selector, 4)))
            self.assertEqual(config_bytes(scenario, 16), bytes((selector, 16)))
        self.assertEqual(config_bytes(DIRECTED, 4), bytes((3, 4)))

    def test_rejects_unregistered_selectors(self):
        for scenario, quantum in (("unknown", 4), ("steady", 0), ("burst", 4.0), ("overload", 32)):
            with self.subTest(scenario=scenario, quantum=quantum), self.assertRaises(ValueError):
                config_bytes(scenario, quantum)
