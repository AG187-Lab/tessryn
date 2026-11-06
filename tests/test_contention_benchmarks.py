"""Synthetic protocol/provenance boundaries; these are not execution evidence."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
from tools.g03.process import ProcessResult
from tools import contention_benchmark_protocol as protocol
from tools import verify_contention_benchmarks as verifier
from tools import build_contention_benchmarks as builder
from tools import run_contention_benchmarks as runner
from tests.test_k03_smp_trace import TRACES, BINDINGS


def fixture_records():
    rows = [("BEGIN", {"schema_version": 1, "kind": "contention_benchmark", **protocol.CONFIG}),
        ("CLOCK", {"name": "hpet", "owner": "bsp", "unit": "raw_ticks", "period_fs": 10_000_000,
            "endpoint": "command_to_acquired_peer_completion", "cross_cpu_subtraction": False}),
        ("LAYOUT", {"assumed_line_bytes": 64, "separate_bsp": 0xe048000, "separate_ap": 0xe048040,
            "false_bsp": 0xe048080, "false_ap": 0xe048088, "shared": 0xe0480c0, "ping": 0xe048100})]
    for case, name in enumerate(protocol.NAMES):
        bsp = 0 if case == 0 else 1024
        ap = 0 if case <= 1 else 1024
        shared = 2048 if case == 4 else 0
        ping = 2048 if case == 5 else 0
        for ordinal in range(20):
            start = 200000 + (case * 20 + ordinal) * 100
            elapsed = 90 if ordinal < 4 else 20
            rows.append(("SAMPLE", {"case": name, "sample_unit": "counter_pair" if case == 0 else "coordinated_batch_completion",
                "phase": "warmup" if ordinal < 4 else "measured", "sample_index": ordinal if ordinal < 4 else ordinal - 4,
                "generation": case * 20 + ordinal + 1, "start_ticks": start, "end_ticks": start + elapsed, "elapsed_ticks": elapsed,
                "operations": 0 if case == 0 else 1024 if case == 1 else 2048, "round_trips": 1024 if case == 5 else 0,
                "bsp_count": bsp, "ap_count": ap, "shared_count": shared, "ping_turn": ping, "checksum": bsp + ap + shared + ping}))
    return rows + [("CHECKS", {"checks": protocol.CHECKS}),
        ("END", {"measured_samples": 96, "warmup_samples": 24, "warmup_excluded": 24, "retained": "all"}),
        ("PASS", {"scope": protocol.SCOPE, "hardware_qualified": False, "inference_qualified": False})]


def transcript(rows=None, original=None):
    records = fixture_records() if rows is None else rows
    return (TRACES["rendezvous"] if original is None else original) + b"".join(
        ("TESSRYN_CBENCH_" + marker + " " + json.dumps(value, separators=(",", ":")) + "\n").encode() for marker, value in records)


class ContentionTests(unittest.TestCase):
    def parse(self, data=None):
        return verifier.parse_transcript(transcript() if data is None else data, 33, b"", BINDINGS["rendezvous"])

    def test_all_raw_warmups_retained_but_only_measured_enter_statistics(self):
        result = self.parse()
        self.assertEqual((result["samples"], result["warmup_samples"], result["warmup_excluded"]), (96, 24, 24))
        self.assertEqual(len(result["cases"]), 6)
        for case in result["cases"]:
            self.assertEqual(case["sample_count"], 16)
            self.assertEqual(case["raw_elapsed_ticks"]["max"], 20)
        self.assertIsNone(result["cases"][0]["ticks_per_operation"])
        self.assertEqual(result["bootstrap"]["ipi_acknowledgments"], 3)
        self.assertIs(result["hardware_qualified"], False)

    def test_zero_resolution_samples_are_retained_without_rate_claim(self):
        rows = fixture_records()
        rows[7][1]["end_ticks"] = rows[7][1]["start_ticks"]
        rows[7][1]["elapsed_ticks"] = 0
        result = self.parse(transcript(rows))
        self.assertEqual(result["cases"][0]["zero_duration_samples"], 1)
        self.assertEqual(result["cases"][0]["measurement_status"], "resolution_limited")

    def test_missing_duplicate_reordered_or_interleaved_records_reject(self):
        original = fixture_records()
        for rows in (original[:3] + original[4:], original + [original[-1]],
                     original[:3] + [original[4], original[3]] + original[5:]):
            with self.subTest(), self.assertRaises(ValueError): self.parse(transcript(rows))
        with self.assertRaises(ValueError):
            self.parse(transcript().replace(b"TESSRYN_CBENCH_SAMPLE", b"TESSRYN_K03_SMP_CPU injected=1\nTESSRYN_CBENCH_SAMPLE", 1))

    def test_every_raw_count_and_type_is_enforced(self):
        for field, value in (("bsp_count", True), ("ap_count", 1025), ("shared_count", 2049),
                             ("ping_turn", 2047), ("checksum", 1), ("operations", -1),
                             ("round_trips", 1), ("generation", 7), ("sample_index", 1), ("phase", "discarded")):
            rows = fixture_records(); rows[3][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.parse(transcript(rows))

    def test_clock_regression_delta_overflow_and_enclosing_timeline_reject(self):
        for values in ({"start_ticks": 0}, {"end_ticks": 200000}, {"elapsed_ticks": 1},
                       {"start_ticks": 1 << 64}, {"start_ticks": True},
                       {"start_ticks": 4000000, "end_ticks": 4000090}):
            rows = fixture_records(); rows[3][1].update(values)
            with self.subTest(values=values), self.assertRaises(ValueError): self.parse(transcript(rows))
        rows = fixture_records(); rows[4][1].update(start_ticks=200000, end_ticks=200090)
        with self.assertRaises(ValueError): self.parse(transcript(rows))

    def test_layout_alignment_disjointness_and_owned_image_boundaries(self):
        for field, value in (("separate_ap", 0xe048000), ("false_ap", 0xe048090),
                             ("shared", 0x100000), ("ping", 0xe048101), ("assumed_line_bytes", True)):
            rows = fixture_records(); rows[2][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.parse(transcript(rows))

    def test_original_ack_stop_and_failure_markers_cannot_be_hidden(self):
        for original in (TRACES["rendezvous"].replace(b"ack=4", b"ack=3"),
                         TRACES["rendezvous"].replace(b"stable=29746", b"stable=29747"),
                         b"TESSRYN_K01_EXCEPTION vector=14\n" + TRACES["rendezvous"], TRACES["missing_ap"]):
            with self.subTest(), self.assertRaises(ValueError): self.parse(transcript(original=original))

    def test_stderr_exit_json_duplicate_nonfinite_truncation_and_hardware_scope_reject(self):
        for code, stderr in ((True, b""), (0, b""), (33, b"unexpected diagnostic")):
            with self.subTest(code=code), self.assertRaises(ValueError):
                verifier.parse_transcript(transcript(), code, stderr, BINDINGS["rendezvous"])
        raw = transcript()
        for data in (raw[:-1], raw + b"trailing\n", raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1),
                     raw.replace(b'"elapsed_ticks":90', b'"elapsed_ticks":NaN', 1),
                     raw.replace(b'"hardware_qualified":false', b'"hardware_qualified":true')):
            with self.subTest(), self.assertRaises(ValueError): self.parse(data)

    def test_unique_descriptor_binds_fixed_config_and_rejects_old_smp_object(self):
        self.assertEqual(len(protocol.DESCRIPTOR), 96)
        self.assertEqual(struct.unpack('<10Q', protocol.DESCRIPTOR[16:]), (1,6,16,4,1024,64,10000000,200000000,20000000,120))
        from tests.test_k03_smp_tooling import binary_fixture
        obj, efi = binary_fixture()
        with self.assertRaises(ValueError): protocol.descriptor_binding(obj, efi)

    def test_committed_source_rebinding_cannot_relabel_changed_captured_bytes(self):
        name = "kernel/contention_benchmarks.rs"
        committed = {name: ('100644', b'original'), 'LICENSE': ('100644', b'license'), 'NOTICE': ('100644', b'notice')}
        hashed = hashlib.sha256()
        for key, (mode, data) in sorted(committed.items()):
            hashed.update(key.encode()+b'\0'+mode.encode()+b'\0'+protocol.digest(data).encode()+b'\0')
        manifest = {"source": {"revision": "a"*40, "dirty": False, "snapshot_algorithm": "git-worktree-v2", "tree_sha256": hashed.hexdigest()},
            "source_files": {name: protocol.digest(b'original')}, "runtime_files": {},
            "notices": [{"path": 'notices/tessryn-'+key, "sha256": protocol.digest(data), "size_bytes": len(data)} for key, (_, data) in committed.items() if key in ('LICENSE','NOTICE')]}
        with mock.patch.object(verifier, 'committed_sources', return_value=committed):
            verifier.validate_source(manifest, {'sources/'+name: b'original'})
            manifest['source_files'][name] = protocol.digest(b'altered')
            with self.assertRaises(ValueError): verifier.validate_source(manifest, {'sources/'+name: b'altered'})
            manifest['source']['dirty'] = True
            with self.assertRaises(ValueError): verifier.validate_source(manifest, {'sources/'+name: b'altered'})

    def test_profile_closure_imported_helpers_and_ping_cost_labels(self):
        self.assertIn('tools/run_k03_smp.py', protocol.RUNTIME_FILES)
        self.assertIn('tools/k03_smp_trace.py', protocol.RUNTIME_FILES)
        self.assertIn('kernel/contention_benchmarks.rs', protocol.COMPILER_SOURCES)
        self.assertEqual(protocol.profile()['cases'][-1]['operation_definition'], 'ping_publication_stores_excluding_poll_loads')
        self.assertFalse(protocol.profile()['layout']['hardware_cache_line_qualified'])
        self.assertEqual(protocol.strict_json(protocol.regular_bytes(protocol.ROOT/protocol.PROFILE_FILE)), protocol.profile())

    def test_optin_and_deadline_precede_output_creation(self):
        for allow, timeout in ((False, 60), (True, True), (True, float('nan')), (True, 61)):
            with self.subTest(allow=allow, timeout=timeout), self.assertRaises(ValueError):
                runner.run(Path('missing'), protocol.ROOT/'build/not-created-by-contention-test', allow_qemu=allow, timeout=timeout)

    def test_dirty_build_and_probe_failure_leave_failed_receipt(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary).resolve()/'dirty'
            with mock.patch.object(builder, 'fresh_output', side_effect=lambda _: (out.mkdir(), out)[1]), \
                 mock.patch.object(builder, 'source_identity', return_value={'dirty': True}):
                with self.assertRaises(ValueError): builder.build(out)
            self.assertEqual(protocol.strict_json((out/'build-failure.json').read_bytes())['status'], 'fail')
            self.assertFalse((out/'manifest.json').exists())

    def test_qemu_admits_two_cpus_and_no_instruction_count_pseudo_clock(self):
        command = runner.qemu_command()
        self.assertEqual(command[command.index('-smp')+1], '2,sockets=1,cores=2,threads=1,maxcpus=2')
        self.assertEqual(command[command.index('-accel')+1], 'tcg,thread=multi')
        self.assertNotIn('-icount', command)

    def test_probe_failures_publish_failed_result_without_execution(self):
        import subprocess
        for error in (subprocess.TimeoutExpired(['rustc','--version'], 30),
                      subprocess.CalledProcessError(1, ['rustc','--version'])):
            with tempfile.TemporaryDirectory() as temporary:
                out = Path(temporary).resolve()/'packet'
                source = Path(temporary)/'manifest.json'; source.write_text('{}')
                with mock.patch.object(runner, 'fresh_output', side_effect=lambda _: (out.mkdir(),out)[1]), \
                     mock.patch.object(verifier, 'validate_build', side_effect=error), \
                     mock.patch.object(runner, 'run_bounded') as child:
                    result = runner.run(source,out,allow_qemu=True)
                child.assert_not_called()
                self.assertEqual(result['status'],'fail')
                self.assertIsNone(result['observations'])
                self.assertIsNone(result['registration_sha256'])
                self.assertEqual(result['execution']['status'],'unavailable')
                self.assertEqual((out/'stdout.log').read_bytes(),b'')
                self.assertEqual(protocol.strict_json((out/'result.json').read_bytes()),result)

    def test_timeout_log_limit_and_changed_capture_inputs_never_pass(self):
        for state in ('timeout','log_limit','changed-input'):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve(); image=root/'image'; image.mkdir(); out=root/'packet'
                (image/'manifest.json').write_text('{}');(image/'boot.img').write_bytes(b'disk')
                qemu=root/'build/toolchain/bin/qemu-system-x86_64';qemu.parent.mkdir(parents=True);qemu.write_bytes(b'not executed')
                firmware={}
                for role in ('code','vars','notice'):
                    path=root/'build/uefi/firmware'/role;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(role.encode())
                    firmware[role]={'path':'firmware/'+role,'sha256':protocol.digest(role.encode()),'size_bytes':len(role)}
                setup={'firmware':firmware,'verified_tools':{'qemu':{'sha256':protocol.digest(qemu.read_bytes())}}}
                runtime={'trusted.py':'a'*64}
                manifest={'runtime_files':runtime,'source_files':{},'toolchain':{'setup':setup},'artifacts':[]}
                def child(command,cwd,timeout,limit):
                    self.assertTrue((out/'registration.json').is_file())
                    self.assertIsNone(protocol.strict_json((out/'result.json').read_bytes())['observations'])
                    if state=='changed-input':
                        qemu.write_bytes(b'changed after capture')
                    return ProcessResult('completed' if state=='changed-input' else state,'bounded fixture',33 if state=='changed-input' else -9,.01,b'exact partial raw bytes',b'')
                with mock.patch.object(runner,'ROOT',root), \
                     mock.patch.object(runner,'fresh_output',side_effect=lambda _: (out.mkdir(),out)[1]), \
                     mock.patch.object(verifier,'validate_build',return_value=manifest), \
                     mock.patch.object(verifier,'build_files',return_value=['manifest.json','boot.img']), \
                     mock.patch.object(verifier,'verify_packet') as accept, \
                     mock.patch.object(runner,'runtime_hashes',return_value=runtime), \
                     mock.patch.object(runner,'LOADED_RUNTIME',runtime), \
                     mock.patch.object(runner,'compiler_profile',return_value={'toolchain':{'setup':setup}}), \
                     mock.patch.object(runner,'verify_installation',return_value=setup), \
                     mock.patch.object(runner,'run_bounded',side_effect=child):
                    result=runner.run(image/'manifest.json',out,allow_qemu=True)
                accept.assert_not_called()
                self.assertEqual(result['status'],'fail')
                self.assertIsNone(result['observations'])
                self.assertIsNotNone(result['registration_sha256'])
                self.assertEqual((out/'stdout.log').read_bytes(),b'exact partial raw bytes')

    def test_runtime_drift_since_import_is_rejected_before_tool_queries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();out=root/'packet';source=root/'manifest.json';source.write_text('{}')
            manifest={'runtime_files':{'changed':'b'*64},'source_files':{}}
            with mock.patch.object(runner,'fresh_output',side_effect=lambda _: (out.mkdir(),out)[1]), \
                 mock.patch.object(verifier,'validate_build',return_value=manifest), \
                 mock.patch.object(runner,'runtime_hashes',return_value=manifest['runtime_files']), \
                 mock.patch.object(runner,'compiler_profile') as tool:
                result=runner.run(source,out,allow_qemu=True)
            tool.assert_not_called()
            self.assertEqual(result['status'],'fail')
            self.assertIsNone(result['observations'])

if __name__ == '__main__': unittest.main()
