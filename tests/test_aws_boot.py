"""Synthetic AWS-input evaluator tests; these never claim native AWS execution.

The original Python fixture below implements only bounded serial and QMP test
behavior. No firmware, AWS API, account, or real kernel is executed by it.
"""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import build_aws_boot as builder
from tools import run_aws_boot as runner
from tools import verify_aws_boot as verifier


def transcript(case):
    lines = [*runner.COMMON]
    if case in ("int3", "invalid_opcode", "page_fault"):
        vector = {"int3": 3, "invalid_opcode": 6, "page_fault": 14}[case]
        cr2 = runner.FAULT_ADDRESS if case == "page_fault" else 0
        lines.append(f"TESSRYN_K01_EXCEPTION vector={vector} error=0x0 rip=0x1000 cs=0x8 "
                     f"rflags=0x2 rsp=0x2000 cr2={cr2:#x}")
        if case == "int3":
            lines.extend(("TESSRYN_K01_INT3_RECOVERED fp_state=preserved", "TESSRYN_K01_PASS"))
        else:
            lines.append("TESSRYN_K01_EXPECTED_FAULT")
    else:
        lines.append(runner.CASE_MARKERS[case])
    return ("\n".join(lines) + "\n").encode()


def fake_qmp_child(mode="fresh"):
    """Test child emits a fresh second transcript only after reset and cont."""
    return '''import json, sys, socket
from pathlib import Path
mode = MODE
payload = PAYLOAD
server = socket.socket(socket.AF_UNIX)
server.bind("qmp.sock")
server.listen(1)
connection, _ = server.accept()
connection.sendall(b'{"QMP":{"version":{}}}\\n')
def send(message):
    connection.sendall(json.dumps(message).encode() + b"\\n")
def serial(data):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
if mode == "stale_event":
    send({"event":"RESET", "data":{"guest":False, "reason":"host-qmp-system-reset"}})
serial(payload * (2 if mode == "stale_phase" else 1))
state, reset = "running", False
for line in connection.makefile("rb"):
    request = json.loads(line)
    command = request["execute"]
    result = {}
    if command == "query-status":
        result = {"status":state, "running":state == "running"}
    elif command == "stop":
        state = "paused"
    elif command == "system_reset":
        reset = True
        if mode == "prelaunch":
            state = "prelaunch"
        if mode != "stale_event":
            send({"event":"RESET", "data":{"guest":False, "reason":"host-qmp-system-reset"}})
    elif command == "cont":
        state = "running"
        if reset and mode != "stale_phase":
            serial(payload)
    send({"return":result, "id":request["id"]})
    if command == "quit":
        break
connection.close()
server.close()
'''.replace("MODE", repr(mode)).replace("PAYLOAD", repr(transcript("normal")))


class SerialTests(unittest.TestCase):
    def test_complete_transcripts_and_firmware_csi_crlf(self):
        for case in runner.CASES:
            raw = transcript(case)
            with self.subTest(case=case):
                self.assertTrue(runner.check_serial(case, raw))
                terminal = b"\x1b[2J\x1b[H" + raw.replace(b"\n", b"\r\n\x1b[0m")
                self.assertTrue(runner.check_serial(case, terminal))

    def test_incomplete_unordered_prefixed_and_failed_transcripts_rejected(self):
        raw = transcript("normal")
        bad = (raw[:-1], raw.replace(b"TESSRYN_K01_CPU_OWNED\n", b""),
               raw.replace(b"TESSRYN_K01_PASS", b"prefix TESSRYN_K01_PASS"),
               raw.replace(b"TESSRYN_K01_PASS", b"TESSRYN_K01_PASSIVE"),
               raw + b"TESSRYN_K01_FAIL reason=test\n",
               raw + b"TESSRYN_K01_UNEXPECTED\n",
               raw + b"TESSRYN_K01_\x1b[0mFAIL reason=test\n",
               b"TESSRYN_K01_PASS\n" + raw.replace(b"TESSRYN_K01_PASS\n", b""))
        for data in bad:
            with self.subTest(data=data[-60:]):
                self.assertFalse(runner.check_serial("normal", data))
        self.assertFalse(runner.check_serial("unsupported", raw))

    def test_wrong_vector_error_and_cr2_rejected(self):
        for case in ("int3", "invalid_opcode", "page_fault"):
            raw = transcript(case)
            vector = {"int3": 3, "invalid_opcode": 6, "page_fault": 14}[case]
            for bad in (raw.replace(f"vector={vector}".encode(), b"vector=13"),
                        raw.replace(b"error=0x0", b"error=0x1")):
                with self.subTest(case=case, bad=bad):
                    self.assertFalse(runner.check_serial(case, bad))
        wrong = transcript("page_fault").replace(f"cr2={runner.FAULT_ADDRESS:#x}".encode(), b"cr2=0x1234")
        self.assertFalse(runner.check_serial("page_fault", wrong))

    def test_fault_registers_must_belong_to_ordered_exception_line(self):
        raw = transcript("page_fault")
        wrong_cr2 = raw.replace(f"cr2={runner.FAULT_ADDRESS:#x}".encode(), b"cr2=0x1234")
        for extra in (f"firmware note cr2={runner.FAULT_ADDRESS:#x}\n".encode(),
                      f"TESSRYN_K01_EXCEPTION vector=13 error=0x0 cr2={runner.FAULT_ADDRESS:#x}\n".encode()):
            for data in (extra + wrong_cr2, wrong_cr2 + extra):
                with self.subTest(data=data):
                    self.assertFalse(runner.check_serial("page_fault", data))
        wrong_error = raw.replace(b"error=0x0", b"error=0x1")
        unrelated = f"TESSRYN_K01_EXCEPTION vector=14 error=0x0 cr2={runner.FAULT_ADDRESS:#x}\n".encode()
        self.assertFalse(runner.check_serial("page_fault", unrelated + wrong_error))


class ExecutionTests(unittest.TestCase):
    def run_fixture(self, mode, timeout=2):
        with tempfile.TemporaryDirectory(prefix="tessryn-synthetic-qmp-") as temporary:
            return runner.execute([sys.executable, "-c", fake_qmp_child(mode)], Path(temporary),
                                  "normal", timeout, 65536)

    def test_real_child_observes_external_reset_and_fresh_second_boot(self):
        result = self.run_fixture("fresh")
        self.assertEqual(result.status, "pass", result.reason)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.phases), 2)
        self.assertEqual(result.phases[0]["stdout_end"], result.phases[1]["stdout_begin"])
        for phase in result.phases:
            self.assertTrue(runner.check_serial("normal", result.stdout[phase["stdout_begin"]:phase["stdout_end"]]))
        self.assertEqual([row["execute"] for row in result.controls],
                         ["query-status", "stop", "query-status", "system_reset", "query-status",
                          "cont", "stop", "query-status", "quit"])

    def test_stale_second_transcript_cannot_prove_post_reset_boot(self):
        result = self.run_fixture("stale_phase", 0.5)
        self.assertNotEqual(result.status, "pass")
        self.assertEqual(len(result.phases), 1)
        self.assertIsNotNone(result.returncode)

    def test_external_reset_prelaunch_state_is_nonrunning_and_can_resume(self):
        result = self.run_fixture("prelaunch")
        self.assertEqual(result.status, "pass", result.reason)
        self.assertEqual(result.controls[4]["result"], {"status": "prelaunch", "running": False})
        self.assertEqual(len(result.phases), 2)

    def test_stale_reset_event_cannot_prove_requested_external_reset(self):
        result = self.run_fixture("stale_event")
        self.assertNotEqual(result.status, "pass")
        self.assertIsNotNone(result.returncode)

    def test_selector_failure_precedes_child_and_signal_ownership(self):
        original = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        with patch.object(runner.selectors, "DefaultSelector", side_effect=OSError("injected selector")), patch.object(
                runner.subprocess, "Popen") as spawn:
            with self.assertRaises(OSError):
                runner.execute([], Path("."), "normal", 2, 1000)
            spawn.assert_not_called()
        self.assertEqual({sig: signal.getsignal(sig) for sig in original}, original)

    def test_pipe_initialization_failure_reaps_child_and_restores_signals(self):
        for failure in ("set_blocking", "register"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                original = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
                real_spawn, child = runner.subprocess.Popen, None

                def spawn(*args, **kwargs):
                    nonlocal child
                    child = real_spawn(*args, **kwargs)
                    return child

                selector = selectors.DefaultSelector()
                target = runner.os if failure == "set_blocking" else selector
                try:
                    with patch.object(runner.selectors, "DefaultSelector", return_value=selector), patch.object(
                            runner.subprocess, "Popen", side_effect=spawn), patch.object(
                            target, failure, side_effect=OSError("injected pipe setup")):
                        result = runner.execute([sys.executable, "-c", "import time; time.sleep(60)"],
                                                Path(temporary), "normal", 2, 1000)
                    self.assertEqual(result.status, "fail")
                    self.assertIsNotNone(child)
                    self.assertIsNotNone(child.poll())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child.pid, 0)
                    self.assertTrue(child.stdout.closed)
                    self.assertTrue(child.stderr.closed)
                    self.assertEqual({sig: signal.getsignal(sig) for sig in original}, original)
                finally:
                    if child is not None and child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=1)
                    selector.close()
                    for sig, handler in original.items():
                        signal.signal(sig, handler)

    def test_invalid_budgets_rejected_before_spawn(self):
        for case, timeout, limit in (("bad", 1, 1000), ("normal", False, 1000), ("normal", 0, 1000),
                                     ("normal", 91, 1000), ("normal", float("nan"), 1000),
                                     ("normal", float("inf"), 1000), ("normal", 1, True),
                                     ("normal", 1, 0), ("normal", 1, 1024 * 1024 + 1)):
            with self.subTest(case=case, timeout=timeout, limit=limit), patch.object(
                    runner.subprocess, "Popen") as spawn:
                with self.assertRaises(ValueError):
                    runner.execute([], Path("."), case, timeout, limit)
                spawn.assert_not_called()


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tessryn-synthetic-evidence-")
        self.root = Path(self.directory.name)
        self.manifest_path = self.root / "manifest.json"
        self.result_path = self.root / "result.json"
        self.manifest = {"toolchain": {"setup": {"firmware": {"code": {"sha256": "a" * 64},
                                                              "vars": {"sha256": "b" * 64}},
                                                 "verified_tools": {"qemu": {"sha256": "c" * 64}}}},
                         "artifacts": [{"path": f"{case}/{name}",
                                        "sha256": hashlib.sha256(f"synthetic/{case}/{name}".encode()).hexdigest()}
                                       for case in runner.CASES for name in ("BOOTX64.EFI", "boot.img")]}
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.result, self.logs = self.synthetic_result("normal")

    def tearDown(self):
        self.directory.cleanup()

    def synthetic_result(self, case):
        first = transcript(case)
        stdout = first * (2 if case == "normal" else 1)
        stderr = b"CPU Reset (synthetic test fixture)\n" if case == "reboot" else b""
        commands = (["query-status", "stop", "query-status", "system_reset", "query-status", "cont",
                     "stop", "query-status", "quit"] if case == "normal" else
                    ["query-status"] if case == "reboot" else ["query-status", "stop", "query-status", "quit"])
        messages, controls = [{"QMP": {"version": {}}}, {"return": {}, "id": 1}], []
        for ordinal, command in enumerate(commands):
            identifier = ordinal + 2
            state = "running" if ordinal == 0 else "paused"
            result = {"status": state, "running": state == "running"} if command == "query-status" else {}
            if command == "system_reset":
                messages.append({"event": "RESET", "data": {"guest": False, "reason": "host-qmp-system-reset"}})
            messages.append({"return": result, "id": identifier})
            offset = len(first) if case != "normal" or ordinal < 6 else len(stdout)
            controls.append({"execute": command, "id": identifier, "stdout_offset": offset,
                             "stderr_offset": 0, "result": result})
        logs = {"stdout.log": stdout, "stderr.log": stderr,
                "qmp.jsonl": b"".join(json.dumps(row).encode() + b"\n" for row in messages)}
        hashes = {row["path"]: row["sha256"] for row in self.manifest["artifacts"]}
        result = {"schema_version": 1, "format": "tessryn-aws-headless-result", "case": case,
                  "status": "pass", "reason": "headless serial markers and independent control matched",
                  "scope": "QEMU TCG q35/OVMF only; native AWS unqualified", "capabilities": verifier.CAPABILITIES,
                  "manifest_sha256": hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
                  "evaluator_sha256": "d" * 64, "firmware": self.manifest["toolchain"]["setup"]["firmware"],
                  "emulator_sha256": "c" * 64, "kernel_sha256": hashes[f"{case}/BOOTX64.EFI"],
                  "disk_sha256": hashes[f"{case}/boot.img"], "controls": controls,
                  "phases": [{"index": index, "stdout_begin": index * len(first),
                              "stdout_end": (index + 1) * len(first)}
                             for index in range(2 if case == "normal" else 1)],
                  "execution": {"timeout_seconds": 2, "elapsed_seconds": 0.5, "max_log_bytes": 65536,
                                "command": runner.qemu_command(case), "returncode": 0}}
        return result, logs

    def validate(self, result=None, logs=None, rehash=True):
        result = copy.deepcopy(self.result if result is None else result)
        logs = self.logs if logs is None else logs
        for name, data in logs.items():
            (self.root / name).write_bytes(data)
        if rehash:
            result["logs"] = [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                              for name, data in logs.items()]
        self.result_path.write_text(json.dumps(result))
        with patch.object(verifier, "evaluator_hash", return_value="d" * 64):
            return verifier.validate_result(self.result_path, self.manifest_path, self.manifest)

    def test_declared_synthetic_records_cover_all_cases(self):
        for case in runner.CASES:
            result, logs = self.synthetic_result(case)
            with self.subTest(case=case):
                self.assertEqual(self.validate(result, logs)["case"], case)

    def test_forged_case_manifest_kernel_disk_firmware_and_scope_rejected(self):
        for field, value in (("case", "page_fault"), ("manifest_sha256", "0" * 64),
                             ("evaluator_sha256", "0" * 64), ("kernel_sha256", "0" * 64),
                             ("disk_sha256", "0" * 64), ("emulator_sha256", "0" * 64),
                             ("firmware", {}), ("scope", "native AWS qualified"),
                             ("capabilities", {"aws_native_boot": "pass"})):
            result = copy.deepcopy(self.result)
            result[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(result)

    def test_prelaunch_is_accepted_only_for_post_reset_query(self):
        result, logs = copy.deepcopy(self.result), dict(self.logs)
        messages = [json.loads(line) for line in logs["qmp.jsonl"].splitlines()]
        result["controls"][4]["result"] = {"status": "prelaunch", "running": False}
        next(row for row in messages if row.get("id") == 6)["return"] = result["controls"][4]["result"]
        logs["qmp.jsonl"] = b"".join(json.dumps(row).encode() + b"\n" for row in messages)
        self.assertEqual(self.validate(result, logs)["status"], "pass")
        result["controls"][2]["result"] = {"status": "prelaunch", "running": False}
        next(row for row in messages if row.get("id") == 4)["return"] = result["controls"][2]["result"]
        logs["qmp.jsonl"] = b"".join(json.dumps(row).encode() + b"\n" for row in messages)
        with self.assertRaisesRegex(ValueError, "pause/liveness"):
            self.validate(result, logs)

    def test_forged_controls_offsets_response_identity_and_pause_rejected(self):
        for modification in ("missing", "renamed", "offset", "id", "return", "running"):
            result = copy.deepcopy(self.result)
            if modification == "missing":
                result["controls"].pop()
            elif modification == "renamed":
                result["controls"][3]["execute"] = "query-status"
            elif modification == "offset":
                result["controls"][2]["stdout_offset"] = -1
            elif modification == "id":
                result["controls"][2]["id"] = 99
            elif modification == "return":
                result["controls"][2]["result"] = {"status": "running", "running": True}
            else:
                result["controls"][2]["result"]["running"] = True
            with self.subTest(modification=modification), self.assertRaises(ValueError):
                self.validate(result)

    def test_stale_phases_and_reset_events_rejected_even_when_rehashed(self):
        for modification in ("phase_repeat", "phase_boundary", "missing_reset", "stale_reset", "guest_reset"):
            result, logs = copy.deepcopy(self.result), dict(self.logs)
            messages = [json.loads(line) for line in logs["qmp.jsonl"].splitlines()]
            if modification == "phase_repeat":
                result["phases"][1]["stdout_begin"] = 0
            elif modification == "phase_boundary":
                result["phases"][0]["stdout_end"] -= 1
            elif modification == "missing_reset":
                messages = [row for row in messages if "event" not in row]
            elif modification == "stale_reset":
                event = next(row for row in messages if "event" in row)
                messages.remove(event)
                messages.insert(1, event)
            else:
                next(row for row in messages if "event" in row)["data"]["guest"] = True
            logs["qmp.jsonl"] = b"".join(json.dumps(row).encode() + b"\n" for row in messages)
            with self.subTest(modification=modification), self.assertRaises(ValueError):
                self.validate(result, logs)

    def test_raw_log_hashes_content_and_triple_fault_rejected(self):
        baseline = self.validate()
        changed = dict(self.logs)
        changed["stdout.log"] += b"extra\n"
        with self.assertRaises(ValueError):
            self.validate(baseline, changed, rehash=False)
        changed["stdout.log"] += b"TESSRYN_K01_FAIL reason=synthetic\n"
        with self.assertRaises(ValueError):
            self.validate(logs=changed)
        changed = dict(self.logs)
        changed["stderr.log"] += b"Triple fault\n"
        with self.assertRaises(ValueError):
            self.validate(logs=changed)
        changed = dict(self.logs)
        messages = [json.loads(line) for line in changed["qmp.jsonl"].splitlines()]
        messages[-1]["id"] = 999
        changed["qmp.jsonl"] = b"".join(json.dumps(row).encode() + b"\n" for row in messages)
        with self.assertRaises(ValueError):
            self.validate(logs=changed)

    def test_upload_plan_encodes_exact_block_checksums_and_size(self):
        disk = {"sha256": "e" * 64,
                "nonzero_blocks": [{"index": 0, "sha256": "a" * 64, "size_bytes": 524288},
                                   {"index": 2047, "sha256": "b" * 64, "size_bytes": 524288}]}
        plan = builder.upload_plan("normal", disk)
        self.assertEqual(plan["start_snapshot"]["VolumeSize"], 1)
        self.assertEqual(plan["complete_snapshot"]["ChangedBlocksCount"], 2)
        self.assertEqual(plan["ami_contract"]["BootMode"], "uefi")
        self.assertEqual(plan["logical_size_bytes"], 1 << 30)
        for row, expected in zip(plan["put_snapshot_blocks"]["blocks"], disk["nonzero_blocks"]):
            self.assertEqual(row["BlockIndex"], expected["index"])
            self.assertEqual(base64.b64decode(row["Checksum"]), bytes.fromhex(expected["sha256"]))


if __name__ == "__main__":
    unittest.main()
