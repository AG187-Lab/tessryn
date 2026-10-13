#!/usr/bin/env python3
"""Exercise the exact headless AWS EFI/disk locally, including external reset.

No AWS API is called. Successful runs are QEMU/OVMF evidence only. The guest
has COM1, NVMe firmware boot, no graphics/network and no debug/exit test ports.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
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
from tools.aws_media import BLOCK_SIZE, DISK_SIZE_BYTES, iter_blocks, verify_disk
from tools.build_aws_boot import AWS_PROFILE, BUILD_CAPABILITIES, upload_plan
from tools.build_fixture import sha256
from tools.build_kernel import CASES, inspect_pe
from tools.check_kernel_display import QMP
from tools.g03.evidence import parse_json, _regular_bytes
from tools.run_kernel import COMMON, CASE_MARKERS, evaluator_hash as base_evaluator_hash
from tools.setup_uefi import verify_installation

FAULT_ADDRESS = 0x7fffffe00000


def evaluator_hash() -> str:
    digest = hashlib.sha256(base_evaluator_hash().encode())
    for name in ("tools/build_aws_boot.py", "tools/run_aws_boot.py", "tools/verify_aws_boot.py",
                 "tools/aws_media.py", "tools/check_kernel_display.py"):
        digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes() + b"\0")
    return digest.hexdigest()


def serial_text(data: bytes) -> bytes:
    # Firmware terminal CSI escapes are retained raw and removed only for parsing.
    return re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data).replace(b"\r", b"")


def check_serial(case: str, data: bytes) -> bool:
    if case not in CASES:
        return False
    data = serial_text(data)
    markers = [*COMMON, CASE_MARKERS[case]]
    if case == "int3":
        markers.extend(("TESSRYN_K01_INT3_RECOVERED fp_state=preserved", "TESSRYN_K01_PASS"))
    elif case in ("invalid_opcode", "page_fault"):
        markers.append("TESSRYN_K01_EXPECTED_FAULT")
    cursor = 0
    exception = None
    for marker in markers:
        match = re.search(rb"(?m)^" + re.escape(marker.encode()) + rb"(?=\s|$)[^\n]*\n", data[cursor:])
        if match is None:
            return False
        if marker.startswith("TESSRYN_K01_EXCEPTION"):
            exception = match.group(0)
        cursor += match.end()
    if case in ("invalid_opcode", "page_fault", "int3"):
        vector = {"int3": 3, "invalid_opcode": 6, "page_fault": 14}[case]
        frames = re.findall(rb"(?m)^TESSRYN_K01_EXCEPTION[^\n]*\n", data)
        frame = re.fullmatch(rb"TESSRYN_K01_EXCEPTION vector=([0-9]{1,2}) error=(0x[0-9a-f]{1,16}) rip=(0x[0-9a-f]{1,16}) "
                             rb"cs=(0x[0-9a-f]{1,16}) rflags=(0x[0-9a-f]{1,16}) rsp=(0x[0-9a-f]{1,16}) cr2=(0x[0-9a-f]{1,16})\n",
                             exception or b"")
        if len(frames) != 1 or frame is None or int(frame[1]) != vector or int(frame[2], 16) != 0:
            return False
        if case == "page_fault" and int(frame[7], 16) != FAULT_ADDRESS:
            return False
    elif b"TESSRYN_K01_EXCEPTION" in data:
        return False
    return not any(marker in data for marker in (b"TESSRYN_K01_FAIL", b"TESSRYN_K01_UNEXPECTED"))


def qemu_command(case: str) -> list[str]:
    command = ["qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "qemu64",
               "-m", "2G", "-smp", "2", "-nodefaults", "-no-user-config", "-display", "none",
               "-monitor", "none", "-serial", "stdio", "-nic", "none", "-global", "apic.vapic=off",
               "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
               "-drive", "if=pflash,format=raw,file=vars.fd",
               "-drive", "if=none,id=boot,format=raw,snapshot=on,file=boot.img",
               "-device", "nvme,drive=boot,serial=TESSRYN_BOOT_TEST", "-boot", "order=c",
               "-qmp", "unix:qmp.sock,server=on,wait=off", "-d", "cpu_reset"]
    if case == "reboot":
        command.append("-no-reboot")
    return command


def selected_artifact(manifest_path: Path, manifest: dict, case: str) -> tuple[bytes, dict]:
    if manifest.get("schema_version") != 1 or manifest.get("artifact_type") != "tessryn-aws-uefi-boot":
        raise ValueError("unsupported AWS boot manifest")
    if manifest.get("profile") != AWS_PROFILE or manifest.get("capabilities") != BUILD_CAPABILITIES:
        raise ValueError("AWS profile or qualification scope differs from evaluator")
    rows = manifest["artifacts"]
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("malformed AWS artifact table")
    matches = {name: [row for row in rows if row.get("path") == f"{case}/{name}"]
               for name in ("BOOTX64.EFI", "boot.img")}
    if any(len(value) != 1 for value in matches.values()):
        raise ValueError("missing or duplicate AWS artifact")
    efi_row, disk_row = matches["BOOTX64.EFI"][0], matches["boot.img"][0]
    directory = manifest_path.parent / case
    if directory.is_symlink():
        raise ValueError("AWS artifact directory must not be a symlink")
    efi = _regular_bytes(directory / "BOOTX64.EFI")
    if (efi_row.get("case") != case or disk_row.get("case") != case
            or hashlib.sha256(efi).hexdigest() != efi_row.get("sha256") or len(efi) != efi_row.get("size_bytes")
            or inspect_pe(efi) != efi_row.get("pe_validation")
            or efi_row.get("rust_case_flags") != ["--cfg", f'k01_case="{case}"', "--cfg", "k01_aws"]):
        raise ValueError("AWS EFI identity/profile differs from manifest")
    disk = verify_disk(directory / "boot.img", efi)
    if disk != disk_row.get("disk") or disk["sha256"] != disk_row.get("sha256") or DISK_SIZE_BYTES != disk_row.get("size_bytes"):
        raise ValueError("AWS fixed disk differs from manifest")
    plans = [row for row in manifest.get("snapshot_input_plans", []) if row.get("path") == f"{case}/snapshot-inputs.json"]
    if len(plans) != 1:
        raise ValueError("AWS snapshot input plan missing or duplicate")
    raw_plan = _regular_bytes(directory / "snapshot-inputs.json")
    if (hashlib.sha256(raw_plan).hexdigest() != plans[0].get("sha256")
            or len(raw_plan) != plans[0].get("size_bytes") or parse_json(raw_plan) != upload_plan(case, disk)):
        raise ValueError("AWS snapshot inputs differ from verified disk")
    return efi, disk


@dataclass
class Execution:
    status: str
    reason: str
    returncode: int | None
    elapsed_seconds: float
    stdout: bytes
    stderr: bytes
    qmp_messages: list
    controls: list
    phases: list


def execute(command: list[str], scratch: Path, case: str, timeout: float, max_log_bytes: int) -> Execution:
    if (case not in CASES or isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 90
            or type(max_log_bytes) is not int or not 0 < max_log_bytes <= 1024 * 1024):
        raise ValueError("invalid headless execution budgets")
    selector = selectors.DefaultSelector()
    started, output = time.monotonic(), {"stdout": bytearray(), "stderr": bytearray()}
    deadline = started + timeout
    cancelled, connection, qmp = False, None, None
    status, reason, phases, controls = "fail", "headless boot incomplete", [], []
    handlers = {}

    def cancel(*_):
        nonlocal cancelled
        cancelled = True

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, cancel)
    try:
        child = subprocess.Popen(command, cwd=scratch, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True,
                                 env={"PATH": os.defpath, "LANG": "C", "TZ": "UTC"})
    except OSError:
        selector.close()
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        return Execution("unavailable", "headless emulator launch failed", None, time.monotonic() - started,
                         b"", b"", [], [], [])

    def pump():
        if cancelled:
            raise InterruptedError("headless boot cancelled")
        if time.monotonic() >= deadline:
            raise TimeoutError("headless boot deadline")
        for key, _ in selector.select(0):
            block = os.read(key.fileobj.fileno(), 65536)
            if not block:
                selector.unregister(key.fileobj)
                continue
            remaining = max_log_bytes - sum(map(len, output.values()))
            output[key.data].extend(block[:remaining])
            if len(block) > remaining:
                raise ValueError("headless log budget exceeded")

    def control(name):
        row = {"execute": name, "stdout_offset": len(output["stdout"]), "stderr_offset": len(output["stderr"])}
        answer = qmp.command(name)
        row.update(id=qmp.request_id, result=answer)
        controls.append(row)
        return answer

    try:
        for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while connection is None:
            pump()
            if child.poll() is not None:
                raise ValueError("emulator exited before headless control connection")
            attempt = socket.socket(socket.AF_UNIX)
            try:
                attempt.settimeout(0.05)
                attempt.connect(str(scratch / "qmp.sock"))
                connection = attempt
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
                attempt.close()
                time.sleep(0.01)
            except OSError:
                attempt.close()
                raise
        qmp = QMP(connection, deadline, pump)
        if control("query-status").get("status") != "running":
            raise ValueError("headless emulator is not running")
        begin = 0
        for phase in range(2 if case == "normal" else 1):
            while not check_serial(case, bytes(output["stdout"][begin:])):
                pump()
                if child.poll() is not None and not check_serial(case, bytes(output["stdout"][begin:])):
                    raise ValueError("emulator exited before expected serial markers")
                if b"TESSRYN_K01_FAIL" in output["stdout"]:
                    raise ValueError("kernel reported headless failure")
                time.sleep(0.01)
            if case == "reboot":
                while child.poll() is None or selector.get_map():
                    pump()
                    time.sleep(0.01)
                if child.returncode != 0 or b"CPU Reset" not in output["stderr"] or b"Triple fault" in output["stderr"]:
                    raise ValueError("runtime reset not distinguished from fault")
            else:
                control("stop")
                if control("query-status").get("status") != "paused":
                    raise ValueError("independent host stop was not observed")
                pump()
            end = len(output["stdout"])
            phases.append({"index": phase, "stdout_begin": begin, "stdout_end": end})
            if case == "normal" and phase == 0:
                reset_boundary = len(qmp.messages)
                control("system_reset")
                reset_state = control("query-status")
                if reset_state.get("status") not in ("paused", "prelaunch") or reset_state.get("running") is not False:
                    raise ValueError("reset did not preserve the independent pause")
                if not any(row.get("event") == "RESET" and row.get("data", {}).get("guest") is False
                           and row.get("data", {}).get("reason") == "host-qmp-system-reset"
                           for row in qmp.messages[reset_boundary:]):
                    raise ValueError("external reset event missing")
                begin = len(output["stdout"])
                control("cont")
        if case != "reboot":
            control("quit")
            while child.poll() is None or selector.get_map():
                pump()
                time.sleep(0.01)
            if child.returncode != 0:
                raise ValueError("emulator did not exit after independent recovery control")
        if b"Triple fault" in output["stderr"] or any(marker in output["stdout"] for marker in
                                                     (b"TESSRYN_K01_FAIL", b"TESSRYN_K01_UNEXPECTED")):
            raise ValueError("terminal fault observed")
        status, reason = "pass", "headless serial markers and independent control matched"
    except TimeoutError:
        status, reason = "timeout", "headless boot exceeded deadline"
    except InterruptedError:
        status, reason = "cancelled", "headless boot cancelled"
    except (OSError, ValueError, TypeError, KeyError):
        status, reason = "fail", "headless serial or control evidence rejected"
    finally:
        try:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(child.pid, sig)
                except ProcessLookupError:
                    pass
                if child.poll() is None:
                    try:
                        child.wait(timeout=0.2 if sig == signal.SIGTERM else 1)
                    except subprocess.TimeoutExpired:
                        if sig == signal.SIGKILL:
                            status, reason = "fail", "headless child could not be reaped"
        except OSError:
            status, reason = "fail", "headless process group cleanup failed"
            if child.poll() is None:
                try:
                    child.kill()
                    child.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    status, reason = "fail", "headless child cleanup unavailable"
        finally:
            for resource in (connection, child.stdout, child.stderr, selector):
                if resource is not None:
                    try:
                        resource.close()
                    except OSError:
                        status, reason = "fail", "headless resource cleanup failed"
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return Execution(status, reason, child.returncode, time.monotonic() - started,
                     bytes(output["stdout"]), bytes(output["stderr"]),
                     [] if qmp is None else qmp.messages, controls, phases)


def run(manifest_path: Path, out: Path, case: str, timeout: float = 60) -> dict:
    if case not in CASES:
        raise ValueError("unsupported AWS kernel case")
    out.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1, "format": "tessryn-aws-headless-result", "case": case,
              "status": "fail", "reason": "input validation incomplete", "manifest_sha256": None,
              "evaluator_sha256": evaluator_hash(), "scope": "QEMU TCG q35/OVMF only; native AWS unqualified",
              "execution": {"command": qemu_command(case), "timeout_seconds": timeout, "max_log_bytes": 1024 * 1024,
                            "returncode": None, "elapsed_seconds": 0}, "logs": [], "controls": [], "phases": [],
              "capabilities": {"aws_native_boot": "unqualified", "aws_recovery": "unqualified",
                               "native_gpu": "unavailable", "network": "unavailable", "inference": "unavailable"}}
    stdout = stderr = b""
    messages = []
    try:
        raw = _regular_bytes(manifest_path)
        result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        manifest = parse_json(raw)
        setup = verify_installation()
        if manifest["toolchain"]["setup"] != setup:
            raise ValueError("AWS build tools differ from pinned installation")
        efi, disk = selected_artifact(manifest_path, manifest, case)
        result["kernel_sha256"], result["disk_sha256"] = hashlib.sha256(efi).hexdigest(), disk["sha256"]
        prefix = ROOT / "build" / "uefi"
        firmware = {name: (prefix / row["path"]).read_bytes() for name, row in setup["firmware"].items()}
        if any(hashlib.sha256(data).hexdigest() != setup["firmware"][name]["sha256"] for name, data in firmware.items()):
            raise ValueError("firmware changed")
        qemu = ROOT / "build" / "toolchain" / "bin" / "qemu-system-x86_64"
        if sha256(qemu) != setup["verified_tools"]["qemu"]["sha256"]:
            raise ValueError("emulator changed")
        result["firmware"], result["emulator_sha256"] = setup["firmware"], sha256(qemu)
        with tempfile.TemporaryDirectory(prefix="tessryn-aws-headless-") as temporary:
            scratch = Path(temporary)
            (scratch / "code.fd").write_bytes(firmware["code"])
            (scratch / "vars.fd").write_bytes(firmware["vars"])
            with (scratch / "boot.img").open("xb") as target:
                target.truncate(DISK_SIZE_BYTES)
                for index, data in iter_blocks(manifest_path.parent / case / "boot.img", disk):
                    target.seek(index * BLOCK_SIZE)
                    target.write(data)
            execution = execute([str(qemu), *result["execution"]["command"][1:]], scratch, case, timeout, 1024 * 1024)
        stdout, stderr, messages = execution.stdout, execution.stderr, execution.qmp_messages
        result.update(status=execution.status, reason=execution.reason, controls=execution.controls, phases=execution.phases)
        result["execution"].update(returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
    except (OSError, ValueError, KeyError, TypeError):
        result["status"], result["reason"] = "fail", "AWS input/setup rejected"
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr),
                       ("qmp.jsonl", b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in messages))):
        (out / name).write_bytes(data)
        result["logs"].append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    (out / "result.json.tmp").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (out / "result.json.tmp").replace(out / "result.json")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, default="normal")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    try:
        result = run(args.manifest, args.out, args.case, args.timeout)
    except (OSError, ValueError) as error:
        parser.exit(2, f"AWS headless setup rejected: {error}\n")
    print(json.dumps({"status": result["status"], "reason": result["reason"]}))
    return {"pass": 0, "timeout": 124, "cancelled": 130, "unavailable": 2}.get(result["status"], 1)


if __name__ == "__main__":
    raise SystemExit(main())
