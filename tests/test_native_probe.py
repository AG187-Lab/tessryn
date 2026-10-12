"""Independent compiler mutation checks for host ABI conformance evidence."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from tools.check_native_abi import ROOT, probe_source
from tools.g02.codec import PROFILE, contract
from tools.g03.process import run_bounded


class NativeProbeCompilerTests(unittest.TestCase):
    def setUp(self):
        self.cc = shutil.which("cc")
        if self.cc is None:
            self.skipTest("C compiler unavailable; no compiler evidence produced")
        self.definitions = contract()
        self.vectors = json.loads((PROFILE / "vectors.json").read_text())["positive"]
        self.temporary = tempfile.TemporaryDirectory(prefix="g02-probe-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.header = (PROFILE / "native.h").read_text()

    def compile(self, source, header):
        (self.work / "native.h").write_text(header)
        (self.work / "probe.c").write_text(source)
        result = run_bounded([self.cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                              "probe.c", "-o", "probe"], self.work, 10, 65536)
        self.assertEqual(result.status, "completed", result.reason)
        return result

    def generated_source(self):
        return probe_source(self.definitions, self.vectors, "c")

    def test_actual_c_compiler_accepts_layout_and_emits_every_literal_frame(self):
        result = self.compile(self.generated_source(), self.header)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        run = run_bounded([str(self.work / "probe")], self.work, 10, 65536)
        self.assertEqual((run.status, run.returncode), ("completed", 0))
        expected = "".join(f"{v['name']}:{v['hex'].lower()}\n" for v in self.vectors)
        self.assertEqual(run.stdout.decode(), expected)

    def test_json_assertions_reject_layout_even_when_native_assertions_match_it(self):
        header = self.header.replace("    uint16_t major;\n    uint16_t minor;",
                                     "    uint16_t minor;\n    uint16_t major;", 1)
        header = header.replace("offsetof(tessryn_abi_header, major) == 0",
                                "offsetof(tessryn_abi_header, major) == 2", 1)
        header = header.replace("offsetof(tessryn_abi_header, minor) == 2",
                                "offsetof(tessryn_abi_header, minor) == 0", 1)
        self.assertNotEqual(header, self.header)
        control = self.compile('#include "native.h"\nint main(void) { return 0; }\n', header)
        self.assertEqual(control.returncode, 0, "The mutated native assertions must agree with their layout")
        result = self.compile(self.generated_source(), header)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("JSON offset", result.stderr.decode())

    def test_json_types_reject_signed_scalar_with_identical_size_and_offsets(self):
        original = "    uint16_t minor;"
        self.assertEqual(self.header.count(original), 1)
        header = self.header.replace(original, "    int16_t minor;", 1)
        control = self.compile('#include "native.h"\nint main(void) { return 0; }\n', header)
        self.assertEqual(control.returncode, 0, "Signedness must leave the native layout assertions valid")
        result = self.compile(self.generated_source(), header)
        self.assertNotEqual(result.returncode, 0, "JSON scalar types must reject signed-width drift")
        self.assertIn("JSON type", result.stderr.decode())

    def test_json_assertions_reject_wrong_exported_constants_in_every_group(self):
        mutations = (
            ("TESSRYN_ABI_MAJOR UINT16_C(1)", "TESSRYN_ABI_MAJOR UINT16_C(2)"),
            ("TESSRYN_ABI_MINOR UINT16_C(0)", "TESSRYN_ABI_MINOR UINT16_C(1)"),
            ("TESSRYN_ABI_FEATURE_MASK UINT64_C(0)", "TESSRYN_ABI_FEATURE_MASK UINT64_C(1)"),
            ("TESSRYN_ABI_KIND_SUBMISSION UINT16_C(3)", "TESSRYN_ABI_KIND_SUBMISSION UINT16_C(4)"),
            ("TESSRYN_ABI_OP_EXECUTE UINT32_C(2)", "TESSRYN_ABI_OP_EXECUTE UINT32_C(3)"),
            ("TESSRYN_ABI_STATUS_OK UINT32_C(0)", "TESSRYN_ABI_STATUS_OK UINT32_C(1)"),
            ("TESSRYN_ABI_MILESTONE_OUTPUT_FENCED UINT32_C(5)",
             "TESSRYN_ABI_MILESTONE_OUTPUT_FENCED UINT32_C(6)"),
        )
        for original, altered in mutations:
            with self.subTest(constant=original.split()[0]):
                self.assertEqual(self.header.count(original), 1)
                result = self.compile(self.generated_source(), self.header.replace(original, altered, 1))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("JSON constant", result.stderr.decode())


class NativeProbeBoundaryTests(unittest.TestCase):
    def test_rust_checks_are_freestanding_const_checks_for_every_layout_and_enum(self):
        definitions = contract()
        vectors = json.loads((PROFILE / "vectors.json").read_text())["positive"]
        source = probe_source(definitions, vectors, "rust")
        self.assertTrue(source.startswith("#![no_std]\n"))
        for forbidden in ("fn main", "std::", "print!", "println!"):
            self.assertNotIn(forbidden, source)
        compact = "".join(source.split())
        for layout in definitions["layouts"].values():
            typename = layout["rust_type"]
            self.assertIn(f"size_of::<abi::{typename}>()=={layout['size']}", compact)
            self.assertIn(f"align_of::<abi::{typename}>()=={layout['alignment']}", compact)
            for field in layout["fields"]:
                self.assertIn(f"offset_of!(abi::{typename},{field['name']})=={field['offset']}", compact)
        for group, prefix in (("kinds", "KIND_"), ("operations", "OP_"),
                              ("statuses", "STATUS_"), ("milestones", "MILESTONE_")):
            for name, value in definitions[group].items():
                self.assertIn(f"abi::{prefix}{name.upper()}=={value}", compact)
        self.assertIn("const_:u16=abi::KIND_SUBMISSION;", compact)
        for vector in vectors:
            expected = ",".join(str(byte) for byte in bytes.fromhex(vector["hex"]))
            self.assertIn(f"letexpected:[u8;{len(bytes.fromhex(vector['hex']))}]=[{expected}];", compact)
        self.assertIn("assert!(encoded[", source)

    def test_missing_compiler_cli_replaces_stale_success_with_failed_receipt(self):
        with tempfile.TemporaryDirectory(prefix="g02-failure-test-") as temporary:
            work = Path(temporary)
            output = work / "result.json"
            output.write_text(json.dumps({"status": "passed", "source_revision": "obsolete"}))
            missing = work / "unavailable-compiler"
            command = [sys.executable, str(ROOT / "tools" / "check_native_abi.py"),
                       "--rustc", str(missing), "--cc", str(missing), "--output", str(output)]
            result = run_bounded(command, ROOT, 10, 65536)
            self.assertEqual((result.status, result.returncode), ("completed", 1))
            self.assertIn("G02 conformance failed", result.stderr.decode())
            receipt = json.loads(output.read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["kind"], "g02_host_conformance")
            self.assertNotIn("source_revision", receipt)


if __name__ == "__main__":
    unittest.main()
