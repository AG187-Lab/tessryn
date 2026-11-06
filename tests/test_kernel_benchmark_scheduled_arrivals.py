"""Check open-loop events, trusted-stop semantics and retained packet boundaries."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import run_scheduled_arrivals as replay
from tools.scheduled_arrival_trace import validate_trace


def job(id_, domain, kind, arrival, work, cancel=None):
    return {"id": id_, "domain": domain, "class": kind, "arrival": arrival,
            "work": work, "cancel": cancel}


BURST = [
    job(1, 2, "prefill", 0, 8, 2),
    job(2, 1, "decode", 1, 1, 3),
    job(3, 3, "control", 4, 1, 7),
]
BURST_TRACE = (b"arrive\t0\t1\ndispatch\t0\t1\t0\t4\narrive\t1\t2\n"
               b"cancel\t2\t1\trunning\ncancel\t3\t2\tqueued\nstop\t4\t1\tcanceled\t4\n"
               b"arrive\t4\t3\ndispatch\t4\t3\t4\t1\nstop\t5\t3\tcompleted\t1\n"
               b"cancel\t7\t3\tterminal\nend\t7\n")


class TraceTests(unittest.TestCase):
    def test_running_cancel_charges_through_stop_and_never_dispatched_is_null(self):
        result = validate_trace(BURST_TRACE, BURST, 4)
        running, queued, control = result["jobs"]
        self.assertEqual((running["terminal_tick"], running["charged"],
                          running["running_cancel_drain"]), (4, 4, 2))
        self.assertEqual(queued["outcome"], "canceled_queued")
        self.assertIsNone(queued["first_wait"])
        self.assertIsNone(result["classes"]["decode"]["first_wait"])
        self.assertEqual(control["first_wait"], 0)
        self.assertEqual(control["cancel_disposition"], "terminal")
        self.assertEqual((result["busy_elapsed"], result["idle_elapsed"], result["end_tick"]), (5, 2, 7))

    def test_equal_tick_stop_then_arrival_then_cancel_then_dispatch(self):
        jobs = [job(1, 2, "prefill", 0, 8, 4), job(2, 1, "decode", 4, 1, 5)]
        trace = (b"arrive\t0\t1\ndispatch\t0\t1\t0\t4\nstop\t4\t1\tyield\t4\n"
                 b"arrive\t4\t2\ncancel\t4\t1\tqueued\ndispatch\t4\t2\t4\t1\n"
                 b"stop\t5\t2\tcompleted\t1\ncancel\t5\t2\tterminal\nend\t5\n")
        result = validate_trace(trace, jobs, 4)
        self.assertEqual(result["jobs"][0]["charged"], 4)
        self.assertEqual(result["jobs"][0]["outcome"], "canceled_queued")
        self.assertEqual(result["jobs"][1]["outcome"], "completed")
        with self.assertRaises(ValueError):
            validate_trace(trace.replace(b"stop\t4\t1\tyield\t4\narrive\t4\t2\n",
                                         b"arrive\t4\t2\nstop\t4\t1\tyield\t4\n"), jobs, 4)

    def test_cannot_shorten_cancel_charge_or_release_cpu_early(self):
        for bad in (BURST_TRACE.replace(b"stop\t4\t1\tcanceled\t4", b"stop\t4\t1\tcanceled\t2"),
                    BURST_TRACE.replace(b"cancel\t3\t2\tqueued", b"dispatch\t3\t2\t1\t1"),
                    BURST_TRACE.replace(b"stop\t4\t1\tcanceled", b"stop\t2\t1\tcanceled")):
            with self.subTest(trace=bad), self.assertRaises(ValueError):
                validate_trace(bad, BURST, 4)

    def test_cannot_hide_open_loop_arrivals_or_late_cancels(self):
        for bad in (BURST_TRACE.replace(b"arrive\t1\t2\n", b""),
                    BURST_TRACE.replace(b"cancel\t7\t3\tterminal\nend\t7\n", b"end\t5\n"),
                    BURST_TRACE.replace(b"arrive\t1\t2", b"arrive\t4\t2")):
            with self.subTest(trace=bad), self.assertRaises(ValueError):
                validate_trace(bad, BURST, 4)

    def test_cannot_idle_with_ready_work_or_invent_readiness(self):
        for bad in (BURST_TRACE.replace(b"dispatch\t4\t3\t4", b"dispatch\t5\t3\t4"),
                    BURST_TRACE.replace(b"dispatch\t4\t3\t4", b"dispatch\t4\t3\t0")):
            with self.subTest(trace=bad), self.assertRaises(ValueError):
                validate_trace(bad, BURST, 4)

    def test_verifier_allows_ready_selection_to_come_from_real_policy(self):
        jobs = [job(1, 1, "decode", 0, 1), job(2, 2, "prefill", 0, 1)]
        for first, second in ((1, 2), (2, 1)):
            trace = (f"arrive\t0\t1\narrive\t0\t2\ndispatch\t0\t{first}\t0\t1\n"
                     f"stop\t1\t{first}\tcompleted\t1\ndispatch\t1\t{second}\t0\t1\n"
                     f"stop\t2\t{second}\tcompleted\t1\nend\t2\n").encode()
            result = validate_trace(trace, jobs, 4)
            self.assertEqual(result["jobs"][first - 1]["first_wait"], 0)
            self.assertEqual(result["jobs"][second - 1]["first_wait"], 1)


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.packet = Path(self.temp.name).resolve()
        self.profile = {"format": "tessryn-scheduled-arrival-profile/v1", "quantums": [4, 16],
                        "scenarios": {name: copy.deepcopy(BURST) for name in replay.SCENARIOS}}
        self.inputs = {name: name.encode() for name in replay.SOURCE_FILES}
        self.profile_data = replay.canonical(self.profile)
        self.patch = patch.object(replay, "project_inputs", return_value=(self.inputs, self.profile_data))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.reg = {"format": "tessryn-scheduled-arrival-registration/v1", "scope": replay.SCOPE,
                    "created_at_utc": "2026-11-06T00:00:00+00:00",
                    "compiler": {"version": "rustc 1.96.0", "sha256": "f" * 64},
                    "build_flags": list(replay.FLAGS), "profile_sha256": replay.sha(self.profile_data),
                    "source_sha256": {path: replay.sha(data) for path, data in self.inputs.items()},
                    "traces": [name for name, _, _ in replay.planned_runs()]}
        (self.packet / "profile.json").write_bytes(self.profile_data)
        for filename, _, q in replay.planned_runs():
            trace = BURST_TRACE
            if q == 16:
                trace = (b"arrive\t0\t1\ndispatch\t0\t1\t0\t8\narrive\t1\t2\n"
                         b"cancel\t2\t1\trunning\ncancel\t3\t2\tqueued\narrive\t4\t3\n"
                         b"cancel\t7\t3\tqueued\nstop\t8\t1\tcanceled\t8\nend\t8\n")
            (self.packet / filename).write_bytes(trace)
        self.retain_result()

    def retain_result(self):
        registration = replay.canonical(self.reg)
        (self.packet / "registration.json").write_bytes(registration)
        result = replay.summarize(self.packet, registration, self.profile)
        (self.packet / "result.json").write_bytes(replay.canonical(result))
        return replay.sha(registration)

    def test_verified_packet_rejects_rebound_source_and_external_pin_mismatch(self):
        pin = replay.sha((self.packet / "registration.json").read_bytes())
        self.assertEqual(replay.verify_packet(self.packet, pin)["registration_sha256"], pin)
        self.reg["source_sha256"][replay.SCHEDULER] = "0" * 64
        forged_pin = self.retain_result()
        with self.assertRaisesRegex(ValueError, "registration digest differs"):
            replay.verify_packet(self.packet, pin)
        with self.assertRaisesRegex(ValueError, "registration differs"):
            replay.verify_packet(self.packet, forged_pin)

    def test_packet_rejects_changed_summary_and_unlisted_file(self):
        with (self.packet / "result.json").open("ab") as stream:
            stream.write(b" ")
        with self.assertRaisesRegex(ValueError, "stored result differs"):
            replay.verify_packet(self.packet)
        self.retain_result()
        (self.packet / "extra.tsv").write_bytes(b"irrelevant")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            replay.verify_packet(self.packet)

    def test_timezone_naive_registration_is_rejected_even_if_recomputed(self):
        self.reg["created_at_utc"] = "2026-11-06+00:00"
        self.retain_result()
        with self.assertRaisesRegex(ValueError, "invalid registration UTC"):
            replay.verify_packet(self.packet)

    def test_bound_file_read_rejects_alias_in_ancestor(self):
        alias = self.packet / "alias"
        alias.symlink_to(self.packet, target_is_directory=True)
        with self.assertRaises(OSError):
            replay.regular_bytes(alias / "profile.json", 1 << 20)

    def test_profile_refuses_boolean_timestamp_and_duplicate_workload_id(self):
        profile = copy.deepcopy(self.profile)
        profile["scenarios"]["burst"][0]["arrival"] = False
        with self.assertRaisesRegex(ValueError, "identity, arrival or work"):
            replay.validate_profile(profile)
        profile = copy.deepcopy(self.profile)
        profile["scenarios"]["burst"][1]["id"] = 1
        with self.assertRaisesRegex(ValueError, "identity, arrival or work"):
            replay.validate_profile(profile)
