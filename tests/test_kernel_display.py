"""Check display evidence parsing, QMP identity and bounded child cleanup."""

import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

from tools import check_kernel_display as display


class FramebufferTests(unittest.TestCase):
    def test_rgb_ppm_pixels_and_comments(self):
        # Pixel bytes may be whitespace; consume exactly the header separator.
        self.assertEqual(display.inspect_ppm(b"P6\n# original pixels\n2 1\n255\n\n \t\x00\xff\x80"),
                         {"format": "PPM_P6", "width": 2, "height": 1, "channels": 3})

    def test_ppm_rejects_invalid_depth_dimension_and_truncation(self):
        for data in (b"P3\n1 1\n255\n\0\0\0", b"P6\n0 1\n255\n", b"P6\n1 1\n65535\n\0\0\0",
                     b"P6\n1 1\n255\n\0\0", b"P6\n1 1\n255\n\0\0\0extra", b"P6\n#unterminated"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                display.inspect_ppm(data)

    def test_deployment_emulator_has_no_test_output_or_exit_devices(self):
        command = display.qemu_command()
        self.assertNotIn("-debugcon", command)
        self.assertFalse(any("debug-exit" in value or "iobase=0xe9" in value for value in command))
        self.assertEqual(command[command.index("-serial") + 1], "none")
        self.assertIn("if=ide,format=raw,readonly=on,media=cdrom,file=boot.iso", command)
        self.assertIn("VGA,romfile=", command)
        self.assertIn("apic.vapic=off", command)

    def test_vga_registers_establish_mode_and_padded_bgrx_conversion(self):
        bars = {"framebuffer": {"address": 0x80000000, "size_bytes": 0x1000000},
                "registers": {"address": 0x81000000, "size_bytes": 0x1000}}
        registers = struct.pack("<11H", 0xb0c5, 2, 1, 32, 0x41, 0, 3, 1, 0, 0, 0)
        profile = display.framebuffer_profile(bars, registers, struct.pack("<I", 0x1e1e1e1e))
        ppm = display.framebuffer_ppm(b"\xa0\xff\x80\x00\x03\x02\x01\x00padding!"[:12], profile)
        self.assertEqual(ppm, b"P6\n2 1\n255\n\x80\xff\xa0\x01\x02\x03")
        self.assertEqual(profile["stride"], 3)

    def test_vga_rejects_wrong_depth_offset_disabled_mode_and_bounds(self):
        bars = {"framebuffer": {"address": 1, "size_bytes": 100}, "registers": {"address": 2}}
        for fields in ((0xb0c5, 2, 2, 16, 0x41, 0, 2, 2, 0, 0, 0),
                       (0xb0c5, 2, 2, 32, 0x40, 0, 2, 2, 0, 0, 0),
                       (0xb0c5, 2, 2, 32, 0x41, 0, 2, 2, 1, 0, 0),
                       (0xb0c5, 2, 20, 32, 0x41, 0, 2, 2, 0, 0, 0)):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                display.framebuffer_profile(bars, struct.pack("<11H", *fields), struct.pack("<I", 0x1e1e1e1e))


class QMPTests(unittest.TestCase):
    def qmp_server(self, response):
        client, server = socket.socketpair()

        def serve():
            with server:
                server.sendall(b'{"QMP":{"version":{}}}\n')
                request = json.loads(server.makefile("rb").readline())
                server.sendall(response(request))

        thread = threading.Thread(target=serve)
        thread.start()
        return client, thread

    def test_qmp_async_event_does_not_replace_correlated_command_response(self):
        connection, thread = self.qmp_server(lambda request: b'{"event":"RESUME"}\n' + json.dumps(
            {"return": {}, "id": request["id"]}).encode() + b"\n")
        with connection:
            qmp = display.QMP(connection, time.monotonic() + 2, lambda: None)
        thread.join(2)
        self.assertEqual(len(qmp.messages), 3)
        self.assertEqual(qmp.messages[1], {"event": "RESUME"})

    def test_qmp_rejects_wrong_response_identity_or_command_error(self):
        for failure in ("identity", "error"):
            with self.subTest(failure=failure):
                connection, thread = self.qmp_server(lambda request: json.dumps(
                    {"return": {}, "id": request["id"] + 1} if failure == "identity"
                    else {"error": {"class": "GenericError"}, "id": request["id"]}).encode() + b"\n")
                with connection, self.assertRaises(ValueError):
                    display.QMP(connection, time.monotonic() + 2, lambda: None)
                thread.join(2)


class CaptureTests(unittest.TestCase):
    def test_capture_controls_live_qmp_child_and_retains_actual_pixels(self):
        # A separate original fixture implements the documented QMP messages,
        # writes a real PPM file and exits only after the evaluator requests quit.
        source = '''import json, socket, struct
from pathlib import Path
server = socket.socket(socket.AF_UNIX)
server.bind("qmp.sock")
server.listen(1)
connection, _ = server.accept()
connection.sendall(b'{"QMP":{"version":{}}}\\n')
stream = connection.makefile("rb")
for line in stream:
    request = json.loads(line)
    command = request["execute"]
    result = {"status":"running"} if command == "query-status" else {}
    if command == "query-pci":
        result = [{"devices":[{"id":{"vendor":0x1234,"device":0x1111,"subsystem":0x1100},"class_info":{"class":0x300},
            "regions":[{"bar":0,"type":"memory","address":0x80000000,"size":0x1000000},
                       {"bar":2,"type":"memory","address":0x81000000,"size":0x1000}]}]}]
    if command == "pmemsave":
        name = request["arguments"]["filename"]
        content = {"vbe-registers.bin":struct.pack("<11H",0xb0c5,1,1,32,0x41,0,1,1,0,0,0),
                   "framebuffer-byteorder.bin":struct.pack("<I",0x1e1e1e1e),
                   "framebuffer.raw":b"\\xa0\\xff\\x80\\x00"}[name]
        Path(name).write_bytes(content)
    connection.sendall(json.dumps({"return":result,"id":request["id"]}).encode()+b"\\n")
    if command == "quit":
        break
connection.close()
server.close()
'''
        with tempfile.TemporaryDirectory() as temporary:
            result = display.capture([sys.executable, "-c", source], Path(temporary), 3, 0.1)
        self.assertEqual(result.status, "captured", result.reason)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.screenshot, b"P6\n1 1\n255\n\x80\xff\xa0")
        self.assertIn("visual boot verification remains required", result.reason)
        self.assertEqual(result.memory_snapshots["framebuffer.raw"], b"\xa0\xff\x80\x00")
        self.assertEqual(result.display_profile["pixel_format"], "bgrx")

    def test_process_exiting_without_display_cannot_count_as_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = display.capture([sys.executable, "-c", "print('PASS')"], Path(temporary), 2, 0.1)
        self.assertEqual(result.status, "fail")
        self.assertIsNone(result.screenshot)

    def test_live_child_without_qmp_times_out_and_is_reaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = display.capture([sys.executable, "-c", "import time; time.sleep(60)"],
                                     Path(temporary), 0.2, 0.1)
        self.assertEqual(result.status, "timeout")
        self.assertIsNotNone(result.returncode)
        self.assertLess(result.elapsed_seconds, 2)

    def test_log_flood_stops_child_without_unbounded_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = display.capture([sys.executable, "-c", "import os,time; os.write(1,b'x'*200000); time.sleep(60)"],
                                     Path(temporary), 2, 0.1, 1000)
        self.assertEqual(result.status, "fail")
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 1000)
        self.assertIsNotNone(result.returncode)

    def test_invalid_time_budgets_rejected_before_child_creation(self):
        for timeout, delay in ((31, 10), (float("inf"), 10), (0, 0), (2, 2), (2, -1)):
            with self.subTest(timeout=timeout, delay=delay), self.assertRaises(ValueError):
                display.capture([], Path("."), timeout, delay)


if __name__ == "__main__":
    unittest.main()
