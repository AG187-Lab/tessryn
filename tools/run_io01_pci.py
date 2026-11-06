#!/usr/bin/env python3
"""Capture and verify the original kernel's bounded QEMU PCI discovery."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.build_io01_pci import CASES, PROFILE, canonical, validate_build
from tools.check_kernel_display import QMP
from tools.g03.evidence import parse_json
from tools.io01_pci_trace import DONE_PREFIX, EvidenceRejected, require_evidence, verify
from tools.k02_region_protocol import digest, fresh_output, regular_bytes, require, write_json
from tools.setup_uefi import verify_installation

FORMAT = "tessryn-io01-pci-result/v1"
SCOPE = "original-kernel PCI configuration reads on one QEMU q35 TCG profile"
TIMEOUT_SECONDS = 30
MAX_LOG_BYTES = 1 << 20
MAX_QMP_BYTES = 1 << 20
# The pinned QEMU monitor rate-limits guest RTC changes to one per second.
MAX_RTC_EVENTS = TIMEOUT_SECONDS + 2
DONE = re.compile(rb"(?m)^" + re.escape(DONE_PREFIX) + rb"[0-9]{1,4}\r?\n")
FAULT_MARKERS = (b"TESSRYN_IO01_PCI_FAIL", b"TESSRYN_K01_FAIL", b"TESSRYN_K01_UNEXPECTED",
                 b"TESSRYN_K01_EXCEPTION", b"TESSRYN_K01_PANIC")
CONTROLS = ("qmp_capabilities", "query-status", "stop", "query-status", "query-pci", "quit")
LOGS = ("serial.log", "stderr.log", "qmp-recv.log", "qmp-send.log")
FIRMWARE_FILES = {"code": "code.fd", "vars": "vars.fd", "notice": "NOTICE"}
QEMU = ROOT / "build/toolchain/bin/qemu-system-x86_64"


def qemu_command(case: str) -> list[str]:
    require(case in CASES, "unknown PCI case")
    command = ["qemu-system-x86_64", "-machine", PROFILE["machine"] + ",accel=" + PROFILE["accelerator"],
               "-cpu", PROFILE["cpu"], "-m", f"{PROFILE['memory_mib']}M", "-smp", str(PROFILE["vcpus"]),
               "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none", "-serial", "stdio",
               "-nic", "none", "-no-reboot", "-device", "VGA,romfile=", "-global", "apic.vapic=off",
               "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
               "-drive", "if=pflash,format=raw,file=vars.fd",
               "-drive", "if=ide,format=raw,snapshot=on,file=boot.img", "-boot", "order=c",
               "-device", "pcie-root-port,id=io01-port,bus=pcie.0,addr=0x2,slot=2,chassis=1"]
    if case == "present":
        command += ["-device", "nvme,id=io01-nvme,bus=io01-port,addr=0,serial=TESSRYN-PCI"]
    return command + ["-qmp", "unix:qmp.sock,server=on,wait=off"]


class LogLimit(ValueError):
    pass


def append_bounded(target: bytearray, block: bytes, remaining: int) -> None:
    target.extend(block[:remaining])
    if len(block) > remaining:
        raise LogLimit("capture exceeded byte budget")


class RecordedSocket:
    """Keep original QMP bytes, including events and unsuccessful exchanges."""

    def __init__(self, connection):
        self.connection = connection
        self.incoming = bytearray()
        self.outgoing = bytearray()

    def settimeout(self, timeout):
        self.connection.settimeout(timeout)

    def recv(self, size):
        block = self.connection.recv(size)
        append_bounded(self.incoming, block, MAX_QMP_BYTES - len(self.incoming) - len(self.outgoing))
        return block

    def sendall(self, block):
        append_bounded(self.outgoing, block, MAX_QMP_BYTES - len(self.incoming) - len(self.outgoing))
        self.connection.sendall(block)


@dataclass(frozen=True)
class Capture:
    status: str
    reason: str
    returncode: int | None = None
    elapsed_seconds: float = 0
    serial: bytes = b""
    stderr: bytes = b""
    qmp_recv: bytes = b""
    qmp_send: bytes = b""


def capture(case: str, scratch: Path, *, timeout: float = TIMEOUT_SECONDS) -> Capture:
    """Own the QEMU group, socket and nonblocking pipes through bounded cleanup."""
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= TIMEOUT_SECONDS,
            "invalid PCI capture deadline")
    command = qemu_command(case)
    selector = selectors.DefaultSelector()
    started = time.monotonic()
    deadline = started + timeout
    output = {"serial": bytearray(), "stderr": bytearray()}
    cancelled = False
    handlers = {}
    child = connection = recording = None
    status, reason = "unavailable", "emulator process launch failed"
    stage = "process launch"

    def cancel(*_):
        nonlocal cancelled
        cancelled = True

    def pump(delay=0):
        if cancelled:
            raise InterruptedError("capture cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("capture deadline expired")
        for key, _ in selector.select(min(delay, remaining)):
            try:
                block = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not block:
                selector.unregister(key.fileobj)
            else:
                append_bounded(output[key.data], block, MAX_LOG_BYTES - sum(map(len, output.values())))

    try:
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                handlers[sig] = signal.signal(sig, cancel)
        # The executed binary is fixed separately; argv contains only portable
        # names. QEMU's overlay and writable VARS live inside this scratch dir.
        child = subprocess.Popen(command, executable=str(QEMU), cwd=scratch, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                 env={"PATH": os.defpath, "LANG": "C", "TZ": "UTC", "TMPDIR": str(scratch)})
        status, reason = "fail", "emulator capture incomplete"
        for name, pipe in (("serial", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        stage = "QMP connection and negotiation"
        while connection is None:
            pump(0.01)
            require_evidence(child.poll() is None, "emulator exited before QMP connected")
            attempt = socket.socket(socket.AF_UNIX)
            try:
                attempt.settimeout(0.05)
                attempt.connect(str(scratch / "qmp.sock"))
                connection = attempt
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
                attempt.close()
            except BaseException:
                attempt.close()
                raise
        recording = RecordedSocket(connection)
        qmp = QMP(recording, deadline, pump)
        require_evidence(is_status(qmp.command("query-status"), "running", True), "emulator did not start running")
        stage = "terminal serial record"
        while not DONE.search(output["serial"]):
            pump(0.01)
            require_evidence(not any(marker in output["serial"] for marker in FAULT_MARKERS), "guest reported failure")
            require_evidence(child.poll() is None, "emulator exited before terminal serial line")
        stage = "QMP pause and inventory"
        qmp.command("stop")
        require_evidence(is_status(qmp.command("query-status"), "paused", False), "emulator pause not observed")
        require_evidence(type(qmp.command("query-pci")) is list, "query-pci did not return a bus list")
        stage = "QMP quit and process exit"
        qmp.command("quit")
        socket_open = True
        while socket_open or child.poll() is None or selector.get_map():
            pump(0.01)
            if socket_open:
                try:
                    socket_open = bool(recording.recv(4096))
                except socket.timeout:
                    pass
        require_evidence(child.returncode == 0, "emulator did not exit cleanly after QMP quit")
        status, reason = "completed", "serial, QMP and process streams completed"
    except TimeoutError:
        status, reason = "timeout", "emulator or QMP capture exceeded deadline"
    except (InterruptedError, KeyboardInterrupt):
        status, reason = "cancelled", "emulator capture cancelled"
    except LogLimit:
        status, reason = "log_limit", "emulator capture exceeded byte budget"
    except EvidenceRejected as error:
        status, reason = "fail", str(error)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        if child is not None:
            status, reason = "fail", f"{stage} rejected ({type(error).__name__})"
    finally:
        try:
            if child is not None:
                # Sweep the owned group even if its leader already exited.
                for sig, grace in ((signal.SIGTERM, 0.2), (signal.SIGKILL, 1)):
                    try:
                        os.killpg(child.pid, sig)
                    except ProcessLookupError:
                        pass
                    except OSError:
                        status, reason = "fail", "emulator group cleanup failed"
                        if child.poll() is None:
                            try:
                                child.send_signal(sig)
                            except OSError:
                                pass
                    if child.poll() is None:
                        try:
                            child.wait(timeout=grace)
                        except subprocess.TimeoutExpired:
                            if sig == signal.SIGKILL:
                                status, reason = "fail", "emulator leader could not be reaped"
        finally:
            resources = [selector, connection]
            if child is not None:
                resources += [child.stdout, child.stderr]
            for resource in resources:
                if resource is not None:
                    try:
                        resource.close()
                    except OSError:
                        status, reason = "fail", "emulator capture resource cleanup failed"
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return Capture(status, reason, child.returncode if child is not None else None, time.monotonic() - started,
                   bytes(output["serial"]), bytes(output["stderr"]),
                   bytes(recording.incoming) if recording is not None else b"",
                   bytes(recording.outgoing) if recording is not None else b"")


def is_status(value, name, running):
    return type(value) is dict and value.get("status") == name and value.get("running") is running


def qmp_records(data: bytes) -> list[dict]:
    require(data.endswith(b"\n"), "QMP transcript has an incomplete frame")
    lines = data.split(b"\n")[:-1]
    require(0 < len(lines) <= 1024 and all(0 < len(line) <= 65536 for line in lines),
            "QMP transcript has invalid frame bounds")
    return [parse_json(line) for line in lines]


def observations(case, serial, stderr, qmp_recv, qmp_send):
    require_evidence(not stderr, "emulator wrote to stderr")
    require(len(serial) + len(stderr) <= MAX_LOG_BYTES and len(qmp_recv) + len(qmp_send) <= MAX_QMP_BYTES,
            "capture logs exceed their bounds")
    markers = list(DONE.finditer(serial))
    require_evidence(len(markers) == 1 and markers[0].end() == len(serial)
            and not any(marker in serial for marker in FAULT_MARKERS), "missing terminal serial line or unexpected guest output")
    requests = qmp_records(qmp_send)
    require_evidence(len(requests) == len(CONTROLS) and all(type(row.get("id")) is int and row == {"id": i, "execute": op}
            for i, (row, op) in enumerate(zip(requests, CONTROLS), 1)), "unexpected QMP command sequence")
    replies = qmp_records(qmp_recv)
    require_evidence(set(replies[0]) == {"QMP"} and type(replies[0]["QMP"]) is dict, "missing original QMP greeting")
    returned = []
    events = set()
    rtc_path, rtc_count = None, 0
    for row in replies[1:]:
        if "event" in row:
            event = row["event"]
            require_evidence(event in ("RTC_CHANGE", "STOP", "SHUTDOWN")
                    and (event == "RTC_CHANGE" or event not in events) and "id" not in row
                    and "error" not in row and "return" not in row, "unexpected QMP event")
            if event == "RTC_CHANGE":
                # QEMU can deliver a rate-limited boot RTC update after STOP.
                # The event has no effect on the paused PCI inventory.
                data = row.get("data")
                require_evidence("SHUTDOWN" not in events and len(returned) < len(CONTROLS) and type(data) is dict
                        and set(data) == {"offset", "qom-path"} and type(data["offset"]) is int
                        and -(1 << 63) <= data["offset"] < 1 << 63 and type(data["qom-path"]) is str
                        and re.fullmatch(r"/machine/unattached/device\[[0-9]{1,3}\]/rtc", data["qom-path"])
                        and rtc_count < MAX_RTC_EVENTS and (rtc_path is None or data["qom-path"] == rtc_path),
                        "invalid QMP RTC change")
                rtc_path, rtc_count = data["qom-path"], rtc_count + 1
            elif event == "STOP":
                require_evidence(len(returned) in (2, 3) and "data" not in row, "QMP stop is out of order")
            else:
                data = row.get("data")
                require_evidence(len(returned) in (5, 6) and type(data) is dict
                        and data.get("guest") is False and data.get("reason") == "host-qmp-quit",
                        "shutdown was not attributed to the host QMP quit")
            events.add(event)
        else:
            require_evidence(set(row) == {"return", "id"} and type(row["id"]) is int and row["id"] == len(returned) + 1,
                    "unexpected QMP reply")
            returned.append(row["return"])
    require_evidence(len(returned) == len(CONTROLS) and returned[0] == returned[2] == returned[5] == {}
            and is_status(returned[1], "running", True) and is_status(returned[3], "paused", False)
            and type(returned[4]) is list, "QMP replies do not prove the paused PCI observation")
    return verify(serial, returned[4], case)


def reference(name: str, data: bytes) -> dict:
    return {"path": name, "sha256": digest(data), "size_bytes": len(data)}


def load_inputs(manifest_path: Path):
    original = regular_bytes(manifest_path, 2 << 20)
    manifest, disk = validate_build(manifest_path)
    require(regular_bytes(manifest_path, 2 << 20) == original, "manifest changed while checking inputs")
    setup = verify_installation()
    require(setup == manifest["toolchain"]["setup"], "verified emulator setup differs from the build")
    qemu_sha = digest(regular_bytes(QEMU, 256 << 20))
    require(qemu_sha == setup["verified_tools"]["qemu"]["sha256"], "emulator hash differs from verified setup")
    firmware = {}
    for role, name in FIRMWARE_FILES.items():
        row = setup["firmware"][role]
        raw = regular_bytes(ROOT / "build/uefi" / row["path"], 16 << 20)
        require(digest(raw) == row["sha256"] and len(raw) == row["size_bytes"], "firmware bytes differ from verified setup")
        firmware[name] = raw
    return original, disk, qemu_sha, firmware


def bindings(inputs):
    original, disk, qemu_sha, firmware = inputs
    return {"manifest_sha256": digest(original), "boot_image_sha256": digest(disk), "qemu_sha256": qemu_sha,
            "firmware": [reference(name, raw) for name, raw in firmware.items()]}


def execution(case, captured):
    return {"status": captured.status, "reason": captured.reason, "returncode": captured.returncode,
            "elapsed_seconds": captured.elapsed_seconds, "command": qemu_command(case),
            "timeout_seconds": TIMEOUT_SECONDS, "max_log_bytes": MAX_LOG_BYTES, "max_qmp_bytes": MAX_QMP_BYTES}


def header(case):
    return {"format": FORMAT, "case": case, "scope": SCOPE, "qualification": "not_established",
            "capture_origin": "local_runner_claim_unverified_offline"}


def run(manifest_path: Path, out: Path, case: str, *, allow_qemu: bool = False) -> dict:
    require(case in CASES and allow_qemu is True, "explicit --allow-qemu and a known case are required")
    manifest_path = Path(manifest_path).absolute()
    out = fresh_output(out)
    captured = Capture("unavailable", "verified PCI build or emulator setup unavailable")
    bound, observed = None, None
    status, reason = "unavailable", captured.reason
    try:
        inputs = load_inputs(manifest_path)
        bound = bindings(inputs)
        with tempfile.TemporaryDirectory(prefix="tessryn-io01-", dir=Path("/tmp").resolve()) as temporary:
            scratch = Path(temporary)
            for name, raw in inputs[3].items():
                (scratch / name).write_bytes(raw)
            (scratch / "boot.img").write_bytes(inputs[1])
            captured = capture(case, scratch)
        status, reason = captured.status, captured.reason
        require(load_inputs(manifest_path) == inputs, "capture inputs changed")
        if captured.status == "completed":
            observed = observations(case, captured.serial, captured.stderr, captured.qmp_recv, captured.qmp_send)
            status, reason = "pass", "original PCI serial and paused QMP topology matched"
    except EvidenceRejected as error:
        status, reason = "fail", str(error)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        if bound is not None:
            status, reason = "fail", "PCI capture inputs or evidence rejected"
    logs = (captured.serial, captured.stderr, captured.qmp_recv, captured.qmp_send)
    refs = []
    for name, raw in zip(LOGS, logs):
        with (out / name).open("xb") as file:
            file.write(raw)
        refs.append(reference(name, raw))
    result = {**header(case), "status": status, "reason": reason, "bindings": bound,
              "execution": execution(case, captured), "observations": observed, "logs": refs}
    write_json(out / "result.json", result)
    return result


def verify_result(manifest_path: Path, out: Path, case: str) -> dict:
    """Recheck a passed packet; this does not run a guest or authenticate capture."""
    result = parse_json(regular_bytes(out / "result.json", 2 << 20))
    expected = header(case)
    require(set(result) == set(expected) | {"status", "reason", "bindings", "execution", "observations", "logs"}
            and all(result[key] == value for key, value in expected.items()) and result["status"] == "pass"
            and result["reason"] == "original PCI serial and paused QMP topology matched", "not a passed PCI packet")
    require(canonical(result["bindings"]) == canonical(bindings(load_inputs(manifest_path))),
            "PCI packet input bindings differ")
    observed_execution = result["execution"]
    elapsed = observed_execution.get("elapsed_seconds") if type(observed_execution) is dict else None
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= TIMEOUT_SECONDS + 2
            and type(observed_execution.get("returncode")) is int
            and canonical(observed_execution) == canonical(execution(
                case, Capture("completed", "serial, QMP and process streams completed", 0, elapsed))),
            "invalid successful execution record")
    raw = [regular_bytes(out / name, MAX_LOG_BYTES if i < 2 else MAX_QMP_BYTES) for i, name in enumerate(LOGS)]
    require(canonical(result["logs"]) == canonical([reference(name, data) for name, data in zip(LOGS, raw)]),
            "PCI packet raw log hashes differ")
    measured = observations(case, *raw)
    require(canonical(result["observations"]) == canonical(measured), "PCI packet observations differ from raw captures")
    return {**expected, "status": "consistent", "observations": measured, "new_guest_execution": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--allow-qemu", action="store_true")
    mode.add_argument("--verify", action="store_true", help="check an existing packet without starting a guest")
    args = parser.parse_args()
    try:
        result = (verify_result(args.manifest, args.out, args.case) if args.verify
                  else run(args.manifest, args.out, args.case, allow_qemu=args.allow_qemu))
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.exit(1, f"PCI audit rejected: {type(error).__name__}\n")
    print(f"{result['case']}: {result['status']} ({result['qualification']})")
    if result["status"] not in ("pass", "consistent"):
        process = result["execution"]
        print(f"{result['reason']} (capture {process['status']}, exit {process['returncode']})", file=sys.stderr)
    return 0 if result["status"] in ("pass", "consistent") else 1


if __name__ == "__main__":
    raise SystemExit(main())
