#!/usr/bin/env python3
"""Capture the deployment ISO's QEMU framebuffer for separate visual inspection.

A captured screenshot is evidence of displayed pixels, not a successful boot.
The deployment kernel uses no emulator serial, debug-console or exit devices.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.build_fixture import sha256  # noqa: E402
from tools.k01_media import make_iso  # noqa: E402
from tools.run_kernel import artifact_bytes, evaluator_hash as kernel_evaluator_hash  # noqa: E402
from tools.setup_uefi import verify_installation  # noqa: E402
from tools.g03.evidence import parse_json, _regular_bytes  # noqa: E402

MAX_SCREEN_BYTES = 32 * 1024 * 1024


def evaluator_hash() -> str:
    return hashlib.sha256((ROOT / "tools" / "check_kernel_display.py").read_bytes()
                          + b"\0" + kernel_evaluator_hash().encode()).hexdigest()


def inspect_ppm(data: bytes) -> dict:
    """Validate QEMU's P6 RGB dump without external image libraries."""
    if len(data) > MAX_SCREEN_BYTES:
        raise ValueError("framebuffer dump exceeds size budget")
    index = 0

    def token() -> bytes:
        nonlocal index
        while index < len(data):
            if data[index:index + 1] == b"#":
                end = data.find(b"\n", index)
                if end < 0:
                    raise ValueError("unterminated PPM header comment")
                index = end + 1
            elif data[index:index + 1] in b" \t\r\n":
                index += 1
            else:
                break
        start = index
        while index < len(data) and data[index:index + 1] not in b" \t\r\n#":
            index += 1
        if start == index:
            raise ValueError("incomplete framebuffer PPM header")
        return data[start:index]

    if token() != b"P6":
        raise ValueError("framebuffer dump must be binary RGB PPM")
    try:
        width, height, maximum = int(token()), int(token()), int(token())
    except ValueError as error:
        raise ValueError("invalid framebuffer PPM dimensions") from error
    if not 0 < width <= 8192 or not 0 < height <= 8192 or maximum != 255:
        raise ValueError("unsupported framebuffer PPM dimensions or depth")
    if index >= len(data) or data[index:index + 1] not in b" \t\r\n":
        raise ValueError("framebuffer PPM lacks pixel separator")
    index += 2 if data[index:index + 2] == b"\r\n" else 1
    if width * height * 3 != len(data) - index:
        raise ValueError("framebuffer PPM pixel length does not match dimensions")
    return {"format": "PPM_P6", "width": width, "height": height, "channels": 3}


def qemu_command() -> list[str]:
    return ["qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "qemu64",
            "-m", "256M", "-smp", "1", "-nodefaults", "-no-user-config", "-display", "none",
            "-monitor", "none", "-serial", "none", "-nic", "none", "-no-reboot",
            "-device", "VGA,romfile=", "-global", "apic.vapic=off",
            "-drive", "if=pflash,format=raw,readonly=on,file=code.fd",
            "-drive", "if=pflash,format=raw,file=vars.fd",
            "-drive", "if=ide,format=raw,readonly=on,media=cdrom,file=boot.iso",
            "-boot", "order=d", "-qmp", "unix:qmp.sock,server=on,wait=off"]


def vga_bars(pci: list) -> dict:
    """Select the fixed profile's QEMU standard VGA using its PCI identity."""
    devices = [device for bus in pci for device in bus["devices"]
               if device.get("id", {}).get("vendor") == 0x1234
               and device.get("id", {}).get("device") == 0x1111
               and device.get("class_info", {}).get("class") == 0x0300]
    if len(devices) != 1:
        raise ValueError("capture requires exactly one QEMU standard VGA device")
    regions = devices[0]["regions"]
    bars = {}
    for number, name in ((0, "framebuffer"), (2, "registers")):
        rows = [region for region in regions if region.get("bar") == number and region.get("type") == "memory"]
        if len(rows) != 1:
            raise ValueError("QEMU VGA framebuffer/register BAR missing or duplicate")
        address, size = rows[0].get("address"), rows[0].get("size")
        if type(address) is not int or type(size) is not int or not 0 < address < 2 ** 32 or size <= 0:
            raise ValueError("QEMU VGA BAR is not assigned below 4 GiB")
        bars[name] = {"address": address, "size_bytes": size}
    if bars["registers"]["size_bytes"] < 0x608:
        raise ValueError("QEMU VGA register BAR is too short")
    return bars


def framebuffer_profile(bars: dict, registers: bytes, byteorder: bytes) -> dict:
    """Read the live mode from the pinned QEMU Bochs VBE register layout.

    QEMU hw/display/vga-pci.c exposes 16-bit registers at BAR2+0x500;
    include/hw/display/bochs-vbe.h declares their indices and byteorder value.
    This fixed x86 profile uses EDK2 QemuVideoDxe's 32-bit BGRx mode.
    """
    if len(registers) != 22 or byteorder != struct.pack("<I", 0x1e1e1e1e):
        raise ValueError("QEMU VGA register snapshot or byteorder unsupported")
    values = struct.unpack("<11H", registers)
    identifier, width, height, depth, enabled, _, stride, _, xoffset, yoffset, _ = values
    if (identifier not in range(0xb0c0, 0xb0c6) or depth != 32 or enabled & 0x41 != 0x41
            or xoffset or yoffset or not 0 < width <= 8192 or not 0 < height <= 8192
            or not width <= stride <= 8192):
        raise ValueError("QEMU VGA mode is not an enabled 32-bit linear framebuffer")
    size = stride * height * 4
    if size > MAX_SCREEN_BYTES or size > bars["framebuffer"]["size_bytes"]:
        raise ValueError("QEMU VGA framebuffer exceeds capture or BAR bounds")
    return {"width": width, "height": height, "stride": stride, "pixel_format": "bgrx",
            "address": bars["framebuffer"]["address"], "size_bytes": size,
            "register_bar_address": bars["registers"]["address"],
            "mode_source": "QMP query-pci and live standard VGA Bochs VBE MMIO registers",
            "layout_source": "https://github.com/qemu/qemu/blob/4fc49f46dc95d4a27de2509e7fceb2931e91faeb/include/hw/display/bochs-vbe.h",
            "pixel_format_source": "QEMU little-endian standard VGA; bundled EDK2 QemuVideoDxe 32-bit BGRx"}


def framebuffer_ppm(raw: bytes, profile: dict) -> bytes:
    width, height, stride = (profile[name] for name in ("width", "height", "stride"))
    if len(raw) != profile["size_bytes"] or len(raw) != stride * height * 4 or profile["pixel_format"] != "bgrx":
        raise ValueError("raw framebuffer does not match the observed VGA mode")
    rgb = bytearray(width * height * 3)
    for y in range(height):
        row = raw[y * stride * 4:y * stride * 4 + width * 4]
        start, end = y * width * 3, (y + 1) * width * 3
        rgb[start:end:3], rgb[start + 1:end:3], rgb[start + 2:end:3] = row[2::4], row[1::4], row[0::4]
    return f"P6\n{width} {height}\n255\n".encode() + rgb


class QMP:
    """Match QMP request IDs while retaining asynchronous events as evidence."""

    def __init__(self, connection: socket.socket, deadline: float, pump):
        self.connection, self.deadline, self.pump = connection, deadline, pump
        self.buffer = bytearray()
        self.messages = []
        self.request_id = 0
        self.connection.settimeout(0.05)
        if not isinstance(self.message().get("QMP"), dict):
            raise ValueError("QMP greeting missing")
        self.command("qmp_capabilities")

    def message(self) -> dict:
        while True:
            self.pump()
            if time.monotonic() >= self.deadline:
                raise TimeoutError("display capture exceeded deadline")
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self.buffer[:newline])
                del self.buffer[:newline + 1]
                if len(line) > 65536:
                    raise ValueError("QMP response exceeds budget")
                if not line.strip():
                    continue
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError("QMP response must be an object")
                if len(self.messages) >= 1024:
                    raise ValueError("QMP message count exceeds budget")
                self.messages.append(message)
                return message
            if len(self.buffer) > 65536:
                raise ValueError("QMP response exceeds budget")
            try:
                block = self.connection.recv(4096)
            except socket.timeout:
                continue
            if not block:
                raise ValueError("QMP closed before command completion")
            self.buffer.extend(block)

    def command(self, execute: str, arguments: dict | None = None):
        self.request_id += 1
        request = {"execute": execute, "id": self.request_id}
        if arguments is not None:
            request["arguments"] = arguments
        self.connection.sendall(json.dumps(request).encode() + b"\n")
        while True:
            response = self.message()
            if "event" in response:
                continue
            if response.get("id") != self.request_id:
                raise ValueError("QMP response request identity mismatch")
            if "error" in response or "return" not in response:
                raise ValueError(f"QMP command rejected: {execute}")
            return response["return"]


@dataclass
class Capture:
    status: str
    reason: str
    returncode: int | None
    elapsed_seconds: float
    stdout: bytes
    stderr: bytes
    screenshot: bytes | None
    qmp_messages: list
    memory_snapshots: dict = field(default_factory=dict)
    display_profile: dict = field(default_factory=dict)


def capture(command: list[str], scratch: Path, timeout: float, capture_after: float,
            max_log_bytes: int = 262144) -> Capture:
    """Own a live emulator process, its local socket, pipes and termination."""
    if (not math.isfinite(timeout) or not 0 < timeout <= 30 or not math.isfinite(capture_after)
            or not 0 <= capture_after < timeout or type(max_log_bytes) is not int or max_log_bytes <= 0):
        raise ValueError("display execution budgets must be positive, bounded and finite")
    started = time.monotonic()
    deadline = started + timeout
    output = {"stdout": bytearray(), "stderr": bytearray()}
    handlers = {}
    cancelled = False
    status, reason, screenshot, qmp = "fail", "display capture incomplete", None, None
    snapshots, profile = {}, {}
    connection = None

    def cancel(*_):
        nonlocal cancelled
        cancelled = True

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, cancel)
    try:
        child = subprocess.Popen(command, cwd=scratch, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                 env={"PATH": os.defpath, "LANG": "C", "TZ": "UTC"})
    except OSError:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        return Capture("unavailable", "emulator process launch failed", None,
                       time.monotonic() - started, b"", b"", None, [])
    with selectors.DefaultSelector() as selector:
        for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)

        def pump():
            if cancelled:
                raise InterruptedError("display capture cancelled")
            if time.monotonic() >= deadline:
                raise TimeoutError("display capture exceeded deadline")
            for key, _ in selector.select(0):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                remaining = max_log_bytes - sum(map(len, output.values()))
                output[key.data].extend(block[:remaining])
                if len(block) > remaining:
                    raise ValueError("emulator output exceeds log budget")
            if child.poll() is not None and screenshot is None:
                raise ValueError("emulator exited before framebuffer capture")

        try:
            while connection is None:
                pump()
                attempt = socket.socket(socket.AF_UNIX)
                try:
                    attempt.settimeout(0.05)
                    attempt.connect(str(scratch / "qmp.sock"))
                    connection = attempt
                except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
                    attempt.close()
                    time.sleep(0.05)
            qmp = QMP(connection, deadline, pump)
            state = qmp.command("query-status")
            if not isinstance(state, dict) or state.get("status") != "running":
                raise ValueError("emulator is not running")
            while time.monotonic() < started + capture_after:
                pump()
                time.sleep(0.05)
            # QMP verifies a specific live emulator immediately before capture.
            state = qmp.command("query-status")
            if not isinstance(state, dict) or state.get("status") != "running":
                raise ValueError("emulator stopped before framebuffer capture")
            qmp.command("stop")
            bars = vga_bars(qmp.command("query-pci"))

            def memory_snapshot(name: str, address: int, size: int) -> bytes:
                qmp.command("pmemsave", {"val": address, "size": size, "filename": name})
                path = scratch / name
                if path.is_symlink() or not path.is_file() or path.stat().st_size != size or size > MAX_SCREEN_BYTES:
                    raise ValueError("VGA memory snapshot missing or exceeds budget")
                contents = path.read_bytes()
                snapshots[name] = contents
                return contents

            registers = memory_snapshot("vbe-registers.bin", bars["registers"]["address"] + 0x500, 22)
            byteorder = memory_snapshot("framebuffer-byteorder.bin", bars["registers"]["address"] + 0x604, 4)
            profile = framebuffer_profile(bars, registers, byteorder)
            raw = memory_snapshot("framebuffer.raw", profile["address"], profile["size_bytes"])
            data = framebuffer_ppm(raw, profile)
            inspect_ppm(data)
            screenshot = data
            qmp.command("quit")
            while child.poll() is None or selector.get_map():
                pump()
                time.sleep(0.01)
            if child.returncode != 0:
                raise ValueError("emulator exited unsuccessfully after framebuffer capture")
            status, reason = "captured", "framebuffer captured; visual boot verification remains required"
        except TimeoutError:
            status, reason = "timeout", "display capture exceeded deadline"
        except InterruptedError:
            status, reason = "cancelled", "display capture cancelled"
        except (OSError, ValueError, TypeError, KeyError):
            status, reason = "fail", "emulator display or QMP evidence rejected"
        finally:
            try:
                # Always terminate the process group, including orphaned descendants.
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
                                status, reason = "fail", "emulator could not be reaped"
            except OSError:
                status, reason = "fail", "emulator process group cleanup failed"
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=1)
            finally:
                if connection is not None:
                    connection.close()
                child.stdout.close()
                child.stderr.close()
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)
    return Capture(status, reason, child.returncode, time.monotonic() - started,
                   bytes(output["stdout"]), bytes(output["stderr"]), screenshot,
                   [] if qmp is None else qmp.messages, snapshots, profile)


def run(manifest_path: Path, out: Path, timeout: float = 30) -> dict:
    if isinstance(timeout, bool) or not math.isfinite(timeout) or not 1 <= timeout <= 30:
        raise ValueError("display timeout must be between 1 and 30 seconds")
    out.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1, "format": "tessryn-k01-display-result", "status": "fail",
              "reason": "input validation incomplete", "manifest_sha256": None,
              "evaluator_sha256": evaluator_hash(), "case": "deployment", "media": "iso",
              "scope": "QEMU q35/TCG framebuffer capture; requires separate visual inspection",
              "boot_verification": "requires_visual_inspection", "physical_hardware": "unavailable",
              "execution": {"command": qemu_command(), "timeout_seconds": timeout,
                            "capture_after_seconds": min(10, timeout / 2), "max_log_bytes": 262144,
                            "elapsed_seconds": 0, "returncode": None}, "logs": []}
    execution = Capture("fail", "input/setup rejected", None, 0, b"", b"", None, [])
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 1024 * 1024:
            raise ValueError("manifest must be a bounded regular file")
        manifest_bytes = _regular_bytes(manifest_path)
        result["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        manifest = parse_json(manifest_bytes)
        if manifest.get("schema_version") != 1 or manifest.get("artifact_type") != "tessryn-k01-kernel":
            raise ValueError("unsupported kernel manifest")
        setup = verify_installation()
        if manifest["toolchain"]["setup"] != setup:
            raise ValueError("deployment manifest differs from pinned UEFI setup")
        for name in ("BOOTX64.EFI", "boot.iso"):
            rows = [row for row in manifest["artifacts"] if row.get("path") == "deployment/" + name]
            if len(rows) != 1 or rows[0].get("rust_case_flags") != ["--cfg", 'k01_case="normal"']:
                raise ValueError("deployment artifact must use the physical kernel build profile")
        efi = artifact_bytes(manifest_path, manifest, "BOOTX64.EFI", "deployment")
        media = artifact_bytes(manifest_path, manifest, "boot.iso", "deployment")
        if media != make_iso(efi):
            raise ValueError("deployment ISO differs from declared physical kernel")
        prefix = ROOT / "build" / "uefi"
        firmware = {role: (prefix / setup["firmware"][role]["path"]).read_bytes() for role in ("code", "vars")}
        for role, data in firmware.items():
            if hashlib.sha256(data).hexdigest() != setup["firmware"][role]["sha256"]:
                raise ValueError("firmware changed during snapshot")
        qemu = ROOT / "build" / "toolchain" / "bin" / "qemu-system-x86_64"
        check_qemu = setup["verified_tools"]["qemu"]["sha256"]
        if sha256(qemu) != check_qemu:
            raise ValueError("emulator changed during snapshot")
        result.update(firmware=setup["firmware"], emulator_sha256=check_qemu,
                      kernel_sha256=hashlib.sha256(efi).hexdigest(), iso_sha256=hashlib.sha256(media).hexdigest())
        with tempfile.TemporaryDirectory(prefix="tessryn-display-") as temporary:
            scratch = Path(temporary)
            (scratch / "code.fd").write_bytes(firmware["code"])
            (scratch / "vars.fd").write_bytes(firmware["vars"])
            (scratch / "boot.iso").write_bytes(media)
            execution = capture([str(qemu), *qemu_command()[1:]], scratch, timeout,
                                result["execution"]["capture_after_seconds"])
        if sha256(qemu) != check_qemu:
            execution.status, execution.reason = "fail", "emulator changed during execution"
    except (OSError, ValueError, KeyError, TypeError):
        pass
    result.update(status=execution.status, reason=execution.reason)
    result["execution"].update(returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
    if execution.display_profile:
        result["display_profile"] = execution.display_profile
    logs = [("stdout.log", execution.stdout), ("stderr.log", execution.stderr),
            ("qmp.jsonl", b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in execution.qmp_messages))]
    for filename, contents in logs + list(execution.memory_snapshots.items()):
        (out / filename).write_bytes(contents)
        result["logs"].append({"path": filename, "sha256": hashlib.sha256(contents).hexdigest(), "size_bytes": len(contents)})
    if execution.screenshot is not None:
        (out / "screenshot.ppm").write_bytes(execution.screenshot)
        result["screenshot"] = {"path": "screenshot.ppm", "sha256": hashlib.sha256(execution.screenshot).hexdigest(),
                                "size_bytes": len(execution.screenshot), **inspect_ppm(execution.screenshot)}
    (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    try:
        result = run(args.manifest, args.out, args.timeout)
    except (OSError, ValueError) as error:
        parser.exit(2, f"display capture rejected: {error}\n")
    print(json.dumps({"status": result["status"], "reason": result["reason"]}))
    return {"captured": 0, "timeout": 124, "cancelled": 130, "unavailable": 2}.get(result["status"], 1)


if __name__ == "__main__":
    raise SystemExit(main())
