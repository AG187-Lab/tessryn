"""Adversarial consistency tests; synthetic packets never assert guest execution."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import verify_native_kernel_benchmarks as verify
from tools.k01_media import make_disk


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def transcript_records():
    clock = {"counter": "tsc", "unit": "tsc_ticks", "serialization": "cpuid_rdtsc_cpuid",
             "tsc_supported": True, "rdtscp_supported": False, "invariant_tsc": False,
             "hypervisor_present": True, "interrupts_masked": True, "started_cpus": 1, "frequency_hz": None}
    rows = [("BEGIN", {"schema_version": 1, "kind": "native_kernel_benchmark",
                       "scope": verify.TRANSCRIPT_SCOPE, **verify.CONFIG, "cases": 13}), ("CLOCK", clock)]
    for case in verify.case_specs():
        count = 1 if case["sample_unit"] == "single_operation" else 128
        for index in range(16):
            start = (len(rows) - 2) * 100
            rows.append(("SAMPLE", {key: case[key] for key in ("case", "implementation", "sample_unit", "batch_size", "bytes_per_operation")}
                         | {"sample_index": index, "elapsed_ticks": index + 1,
                            "start_ticks": start, "end_ticks": start + index + 1,
                            "operations": count * case["operations_per_iteration"], "checksum": verify.expected_checksum(case)}))
    return rows + [("CHECKS", {"checks": verify.CHECKS}),
                   ("END", {"measured_samples": 208, "warmup_discarded": 52}),
                   ("PASS", {"scope": verify.TRANSCRIPT_SCOPE})]


def transcript(rows=None):
    boot = b"TESSRYN_K01_ENTRY\nTESSRYN_K01_EXIT_BOOT_SERVICES_OK\nTESSRYN_K01_CPU_OWNED cr3=0x1000\n"
    return boot + b"".join(b"TESSRYN_NBENCH_" + kind.encode() + b" " + encoded(value)
                           for kind, value in (transcript_records() if rows is None else rows))


def fixture_packet(root):
    """Construct declared receipts only: this fixture has never run a compiler/guest."""
    def retain(name, data):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {"file": name, "sha256": verify.digest(data), "size": len(data)}
    def local(ref):
        return {**ref, "file": ref["file"].removeprefix("build/")}
    def receipt(prefix, stdout, stderr=b"", execution=False):
        return {"status": "completed", "reason": "synthetic unexecuted test receipt", "returncode": 33 if execution else 0,
                "elapsed_seconds": 1, "stdout": retain(prefix + "-stdout.log", stdout),
                "stderr": retain(prefix + "-stderr.log", stderr)}
    refs = []
    profile = retain("build/profile.json", encoded(verify.expected_profile()))
    refs.append(profile)
    sources = []
    for name in verify.SOURCE_FILES:
        data = b"synthetic fixture source, never compiled\n"
        if name == "scheduler-core/lib.rs":
            data = b"synthetic scheduler fixture, never compiled\n"
        elif name == "planning/native-kernel-benchmark-profile.json":
            data = encoded(verify.expected_profile())
        ref = retain("build/sources/" + name, data)
        refs.append(ref)
        sources.append(local(ref))
    efi = b"MZsynthetic unexecuted EFI fixture"
    artifacts = []
    for name, role in verify.ARTIFACTS.items():
        ref = retain("build/" + name, make_disk(efi) if name == "boot.img" else efi)
        refs.append(ref)
        artifacts.append({**local(ref), "role": role})
    setup = {"host": "test-host-target", "verified_tools": {"qemu": {"sha256": "1" * 64}}, "firmware": {}, "rust_notices": {}}
    for role in ("code", "vars"):
        ref = retain("firmware/" + role + ".fd", role.encode())
        refs.append(ref)
        setup["firmware"][role] = {"path": "firmware/" + role + ".fd", "sha256": ref["sha256"], "size_bytes": ref["size"]}
    notices = []
    for name in sorted(verify.NOTICE_NAMES):
        data = b"synthetic fixture source, never compiled\n" if "tessryn-" in name else name.encode()
        ref = retain("build/" + name, data)
        refs.append(ref)
        notices.append(local(ref))
        spec = {"sha256": ref["sha256"], "size_bytes": ref["size"]}
        if name == "notices/firmware-NOTICE":
            setup["firmware"]["notice"] = spec
        elif name.startswith("notices/rust-"):
            setup["rust_notices"][name.removeprefix("notices/rust-")] = spec
    compile_receipts = []
    for role in ("memory", "scheduler", "kernel"):
        row = receipt("build/" + role, b"")
        refs.extend((row["stdout"], row["stderr"]))
        compile_receipts.append({**row, "stdout": local(row["stdout"]), "stderr": local(row["stderr"])})
    commands = verify.expected_compile_commands(setup["host"])
    manifest = {"schema_version": 1, "kind": "native_kernel_benchmark_build", "status": "built", "reason": "synthetic unexecuted fixture",
                "evidence_scope": verify.SCOPE, "native_qualification": False, "config": verify.CONFIG,
                "profile": local(profile), "sources": sources, "artifacts": artifacts,
                "toolchain": {"setup": setup, "rust_flags": verify.RUST_FLAGS,
                              "rustc_version": "rustc fixture never executed", "linker_version": "linker fixture never executed"},
                "compile_commands": commands, "compiler_dependencies": sorted("sources/" + name for name in verify.SOURCE_FILES
                    if name.endswith((".rs", ".S"))), "compile": compile_receipts, "notices": notices}
    build_ref = retain("build/manifest.json", encoded(manifest))
    refs.append(build_ref)
    registration = {"schema_version": 1, "kind": "native_kernel_benchmark_registration", "created_at_utc": "2026-10-13T00:00:00Z",
                    "evidence_scope": verify.SCOPE, "native_qualification": False,
                    "capture_origin": "local_runner_claim_unverified_offline", "build_manifest": build_ref, "files": refs,
                    "config": verify.CONFIG, "command": verify.QEMU_COMMAND,
                    "limits": {"timeout_seconds": 60, "max_log_bytes": verify.MAX_LOG_BYTES},
                    "runtime": {"setup": setup, "emulator_sha256": "1" * 64}, "profile_sha256": profile["sha256"]}
    registration_bytes = encoded(registration)
    retain("registration.json", registration_bytes)
    execution = receipt("qemu", transcript(), execution=True)
    retain("run_receipts.json", encoded({"schema_version": 1, "execution": execution}))
    summary = verify.verify_packet(root)
    result = {"schema_version": 1, "kind": "native_kernel_benchmark_run", "status": "observed", "evidence_scope": verify.SCOPE,
              "native_qualification": False, "valid": True, "registration_sha256": verify.digest(registration_bytes),
              "summary": summary, "reason": "synthetic unexecuted test fixture"}
    retain("result.json", encoded(result))
    return registration, manifest


class NativeTranscriptTests(unittest.TestCase):
    def test_scope_population_and_nearest_rank(self):
        summary = verify.parse_transcript(transcript())
        self.assertFalse(summary["native_qualification"])
        self.assertFalse(summary["counter_frequency_qualified"])
        self.assertEqual(len(summary["cases"]), 13)
        first, single = summary["cases"][0], summary["cases"][-1]
        self.assertEqual(first["elapsed_ticks"]["p50"], 8)
        self.assertEqual(first["elapsed_ticks"]["p95"], 16)
        self.assertEqual(first["quantile_population"], "amortized_timed_batch_averages")
        self.assertEqual(single["quantile_population"], "individual_guest_policy_calls")
        self.assertEqual(single["operations_per_sample"], 1)

    def test_checksum_literals_are_independent_of_generator(self):
        expected = [8129, 8129, 8257, 524801, 33558529, 129, 129, 8257, 134225857, 1, 8257, 1985, 1]
        self.assertEqual([verify.expected_checksum(row) for row in verify.case_specs()], expected)

    def test_zero_preserved_without_averages(self):
        rows = transcript_records()
        rows[2][1]["elapsed_ticks"] = 0
        rows[2][1]["end_ticks"] = rows[2][1]["start_ticks"]
        summary = verify.parse_transcript(transcript(rows))["cases"][0]
        self.assertEqual(summary["zero_duration_samples"], 1)
        self.assertEqual(summary["elapsed_ticks"]["min"], 0)
        self.assertIsNone(summary["ticks_per_operation"])

    def test_exact_profile_rejects_bool_float_and_scope(self):
        for key, value in (("samples", True), ("samples", 16.0), ("seed", 2)):
            profile = copy.deepcopy(verify.expected_profile())
            profile["config"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                verify.validate_profile(profile)
        profile = copy.deepcopy(verify.expected_profile())
        profile["scope"] = "host_microbenchmark"
        with self.assertRaises(ValueError):
            verify.validate_profile(profile)

    def test_malformed_sample_fields_are_rejected(self):
        changes = [("elapsed_ticks", -1), ("elapsed_ticks", 1 << 64), ("elapsed_ticks", True), ("elapsed_ticks", 1.0),
                   ("operations", 1), ("operations", True), ("checksum", False), ("checksum", 7),
                   ("sample_index", True), ("sample_index", 1), ("sample_unit", "single_operation"),
                   ("batch_size", True), ("bytes_per_operation", 4096), ("case", "unknown"),
                   ("start_ticks", True), ("start_ticks", -1), ("end_ticks", 0), ("end_ticks", 2)]
        for key, value in changes:
            rows = transcript_records()
            rows[2][1][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                verify.parse_transcript(transcript(rows))

    def test_clock_qualification_and_types_rejected(self):
        for key, value in (("frequency_hz", 1000000000), ("started_cpus", True), ("started_cpus", 2),
                           ("interrupts_masked", False), ("invariant_tsc", 1), ("tsc_supported", False),
                           ("serialization", "rdtsc")):
            rows = transcript_records()
            rows[1][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify.parse_transcript(transcript(rows))

    def test_missing_duplicate_reordered_and_failed_records(self):
        base = transcript_records()
        variants = [base[:-1], base + [base[-1]], base[:3] + base[4:],
                    base[:3] + [base[2]] + base[4:], [base[1], base[0], *base[2:]],
                    [*base[:-1], ("FAIL", {"reason": "counter_regression"})]]
        for rows in variants:
            with self.subTest(records=len(rows)), self.assertRaises(ValueError):
                verify.parse_transcript(transcript(rows))

    def test_completion_checks_and_partial_bytes_rejected(self):
        for position, key, value in ((-3, "checks", verify.CHECKS[:-1]), (-2, "warmup_discarded", 0),
                                     (-2, "measured_samples", 208.0), (-1, "scope", "hardware")):
            rows = transcript_records()
            rows[position][1][key] = value
            with self.subTest(position=position), self.assertRaises(ValueError):
                verify.parse_transcript(transcript(rows))
        for raw in (transcript()[:-1], transcript() + b"unexpected\n", transcript().replace(b"TESSRYN_K01_CPU_OWNED", b"missing"),
                    transcript().replace(b'"elapsed_ticks": 1,', b'"elapsed_ticks": 1, "elapsed_ticks": 2,', 1),
                    transcript() + b"TESSRYN_NBENCH_FAIL {}\n", transcript().replace(b"TESSRYN_NBENCH_BEGIN", b"\xff", 1)):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                verify.parse_transcript(raw)
        with self.assertRaises(ValueError):
            verify.parse_transcript(transcript(), b"diagnostic")
        with self.assertRaises(ValueError):
            verify.parse_transcript(transcript(), returncode=True)

    def test_exceptions_and_mixed_k02_markers_rejected_before_begin(self):
        base = transcript()
        markers = (b"TESSRYN_K01_EXCEPTION vector=6 error=0 rip=0x1234 cs=0x38 rflags=0x2 rsp=0x8000 cr2=0x0",
                   b"TESSRYN_K01_EXCEPTION_UNKNOWN", b"TESSRYN_K02_FP_RESTORE_MISMATCH first_offset=6",
                   b"TESSRYN_K02_PASS case=own_page", b"TESSRYN_K02_MATRIX_PASS case=exact_bounds")
        for marker in markers:
            for position in (0, base.index(b"TESSRYN_NBENCH_BEGIN"), len(base)):
                raw = base[:position] + marker + b"\n" + base[position:]
                with self.subTest(marker=marker, position=position), self.assertRaisesRegex(
                        ValueError, "guest exception or mixed K02 transcript"):
                    verify.parse_transcript(raw)

    def test_harmless_firmware_and_kernel_startup_still_accepted(self):
        startup = (b"Firmware: loading Tessryn\n"
                   b"TESSRYN_K01_FRAMEBUFFER status=ready width=800 height=600\n"
                   b"TESSRYN_K01_LIVE_RANGES image_start=0x1000 image_end=0x2000\n"
                   b"TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY\n")
        self.assertEqual(verify.parse_transcript(startup + transcript()), verify.parse_transcript(transcript()))

    def test_media_reconstruction_matches_frozen_existing_format(self):
        for efi in (b"MZfixture", b"MZ" + bytes(range(256)) * 5):
            self.assertEqual(verify.canonical_disk(efi), make_disk(efi))

    def test_raw_timestamp_delta_and_cross_case_regression(self):
        rows = transcript_records()
        rows[18][1]["start_ticks"] = 0
        rows[18][1]["end_ticks"] = rows[18][1]["elapsed_ticks"]
        with self.assertRaises(ValueError):
            verify.parse_transcript(transcript(rows))

    def test_production_scheduler_pin_is_immutable(self):
        self.assertEqual(verify.SCHEDULER_PIN, "db4a54a871d0a853ebdbacf13a672b19738d0b0e525cdcd87f9953ff9d5c996d")

    def test_expected_profile_returns_independent_mutable_collections(self):
        profile = verify.expected_profile()
        profile["config"]["samples"] = True
        profile["checks"].clear()
        profile["cases"][0]["case"] = "changed"
        self.assertEqual(verify.expected_profile()["config"]["samples"], 16)
        self.assertEqual(len(verify.expected_profile()["checks"]), 8)
        self.assertEqual(verify.expected_profile()["cases"][0]["case"], "counter_pair")
        with self.assertRaises(ValueError):
            verify.validate_profile(profile)


class NativePacketTests(unittest.TestCase):
    def setUp(self):
        pin = mock.patch.object(verify, "SCHEDULER_PIN", verify.digest(b"synthetic scheduler fixture, never compiled\n"))
        pin.start()
        self.addCleanup(pin.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "packet"
        self.root.mkdir()
        self.registration, self.manifest = fixture_packet(self.root)

    def test_packet_and_external_registration_pin(self):
        pin = verify.digest((self.root / "registration.json").read_bytes())
        summary = verify.verify_packet(self.root, require_result=True, expected_registration_sha256=pin)
        self.assertEqual(len(summary["cases"]), 13)
        with self.assertRaises(ValueError):
            verify.verify_packet(self.root, expected_registration_sha256="0" * 64)

    def test_raw_log_binding_and_summary_tampering_rejected(self):
        path = self.root / "qemu-stdout.log"
        path.write_bytes(path.read_bytes().replace(b'"elapsed_ticks": 1,', b'"elapsed_ticks": 9,', 1))
        with self.assertRaises(ValueError):
            verify.verify_packet(self.root)

    def test_rebound_pre_begin_exception_cannot_preserve_observed_result(self):
        path = self.root / "qemu-stdout.log"
        raw = path.read_bytes().replace(b"TESSRYN_NBENCH_BEGIN",
            b"TESSRYN_K01_EXCEPTION vector=6 error=0 rip=0x1234 cs=0x38 rflags=0x2 rsp=0x8000 cr2=0x0\n"
            b"TESSRYN_NBENCH_BEGIN", 1)
        path.write_bytes(raw)
        receipt_path = self.root / "run_receipts.json"
        receipts = json.loads(receipt_path.read_bytes())
        receipts["execution"]["stdout"].update(sha256=verify.digest(raw), size=len(raw))
        receipt_path.write_bytes(encoded(receipts))
        with self.assertRaisesRegex(ValueError, "guest exception or mixed K02 transcript"):
            verify.verify_packet(self.root, require_result=True)

    def test_failed_execution_and_result_rejected(self):
        path = self.root / "run_receipts.json"
        receipt = json.loads(path.read_bytes())
        receipt["execution"]["status"] = "timeout"
        path.write_bytes(encoded(receipt))
        with self.assertRaises(ValueError):
            verify.verify_packet(self.root)

    def test_contradictory_compile_flags_and_wrong_cfg_or_input_rejected(self):
        path = self.root / "build/manifest.json"
        original = path.read_bytes()
        for role, extra in (("kernel", ["-Copt-level=3"]), ("memory", ["--target=x86_64-unknown-linux-gnu"]),
                            ("kernel", ["--cfg", "k02_native"]), ("scheduler", ["--extern", "foreign=other.rlib"])):
            manifest = json.loads(original)
            manifest["compile_commands"][role] += extra
            path.write_bytes(encoded(manifest))
            with self.subTest(role=role, extra=extra), self.assertRaises(ValueError):
                verify.validate_build(path)
        path.write_bytes(original)

    def test_source_artifact_and_notice_binding_rejected(self):
        for name in ("build/sources/kernel/main.rs", "build/BOOTX64.EFI", "build/notices/firmware-NOTICE"):
            path = self.root / name
            before = path.read_bytes()
            path.write_bytes(before + b"changed")
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify.verify_packet(self.root)
            path.write_bytes(before)

    def test_symlink_file_directory_and_ancestor_rejected(self):
        source = self.root / "qemu-stdout.log"
        original = source.read_bytes()
        source.unlink()
        target = self.root / "actual.log"
        target.write_bytes(original)
        source.symlink_to(target)
        with self.assertRaises(ValueError):
            verify.verify_packet(self.root)
        source.unlink()
        source.write_bytes(original)
        alias = self.root.parent / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            verify.verify_packet(alias)
        with self.assertRaises(ValueError):
            verify.read_regular(self.root, "../packet/registration.json")


if __name__ == "__main__":
    unittest.main()
