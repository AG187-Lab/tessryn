"""Synthetic provenance/format tests do not supply AP execution evidence."""
from __future__ import annotations
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock
from tools import k03_smp_protocol as protocol, k03_smp_provenance as provenance
from tools import build_k03_smp as build, run_k03_smp as runner, verify_k03_smp as verifier
from tools import check_k03_smp_host as host, summarize_k03_smp_failure as failure
from tools.g03.process import ProcessResult


def binary_fixture():
    trampoline=(b'SMP unit trampoline fixture!'*160)[:4096].ljust(4096,b'\0')
    text=trampoline+bytes.fromhex('f048ff07f390ebf8');descriptor=protocol.descriptor_bytes('rendezvous')
    names=[('smp_trampoline_start',0,1),('smp_trampoline_end',4096,1),('smp_heartbeat_start',4096,1),('smp_heartbeat_end',4104,1),('K03_SMP_CONTRACT',0,2)]
    strings=bytearray(b'\0'*4);symbols=bytearray()
    for name,offset,section in names:
        index=len(strings);strings.extend(name.encode()+b'\0');symbols.extend(struct.pack('<IIIhHBB',0,index,offset,section,0,2,0))
    struct.pack_into('<I',strings,0,len(strings));raw=20+3*40;symbol_at=raw+len(text)+len(descriptor)
    obj=bytearray(struct.pack('<HHIIIHH',0x8664,3,0,symbol_at,5,0,0))
    for name,size,pointer,flags in ((b'.text',len(text),raw,0x60000020),(b'.rdata',96,raw+len(text),0x40000040),(b'.bss',1<<20,0,0xc0000080)):
        obj.extend(struct.pack('<8sIIIIIIHHI',name,0,0,size,pointer,0,0,0,0,flags))
    obj.extend(text+descriptor+symbols+strings)
    efi=bytearray(5632);efi[:2]=b'MZ';struct.pack_into('<I',efi,60,128);efi[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',efi,132,0x8664,2,0,0,0,240,0x22);o=152
    struct.pack_into('<H',efi,o,0x20b);struct.pack_into('<I',efi,o+16,0x1000);struct.pack_into('<I',efi,o+56,0x4000)
    struct.pack_into('<I',efi,o+60,512);struct.pack_into('<H',efi,o+68,10);struct.pack_into('<I',efi,o+108,16)
    struct.pack_into('<II',efi,o+112+5*8,0x3000,8)
    for i,(name,virtual,rva,size,pointer,flags) in enumerate(((b'.text',len(text),0x1000,4608,512,0x60000020),(b'.rdata',112,0x3000,512,5120,0x40000040))):
        struct.pack_into('<8sIIIIIIHHI',efi,o+240+i*40,name,virtual,rva,size,pointer,0,0,0,0,flags)
    efi[512:512+len(text)]=text;struct.pack_into('<II',efi,5120,0x1000,8);efi[5136:5232]=descriptor
    return bytes(obj),bytes(efi)


class SmpToolingTests(unittest.TestCase):
    def test_profile_descriptor_and_contract_are_exact(self):
        contract=protocol.strict_json(protocol.regular_bytes(protocol.ROOT/protocol.CONTRACT_NAME))
        self.assertEqual(contract['cases'],list(protocol.CASES));self.assertEqual(contract['cpu_count'],2)
        for i,case in enumerate(protocol.CASES):
            raw=protocol.descriptor_bytes(case);self.assertEqual(len(raw),96);self.assertEqual(raw[:16],b'TESSRYN-SMP1\0\0\0\0')
            self.assertEqual(struct.unpack('<10Q',raw[16:]),(1,i,2,0xfee00000,0xfed00000,10000000,64,65,4096,2000000000))
        command=runner.qemu_command();self.assertEqual(command[command.index('-smp')+1],protocol.PROFILE['topology'])
        self.assertEqual(command[command.index('-accel')+1],'tcg,thread=multi');self.assertNotIn('-icount',command)

    def test_coff_bss_metadata_is_legal_but_only_initialized_bindings_are_read(self):
        obj,efi=binary_fixture();binding=build.coff_binding(obj,efi,'rendezvous');self.assertEqual(binding['heartbeat']['size_bytes'],8)
        self.assertGreater(struct.unpack_from('<I',obj,20+80+16)[0],len(obj))
        for at,value,fmt in ((20+80+36,0xc0000000,'<I'),(20+80+32,1,'<H'),(20+36,0x600000a0,'<I')):
            changed=bytearray(obj);struct.pack_into(fmt,changed,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):build.coff_binding(bytes(changed),efi,'rendezvous')
        for data in (b'',obj[:19],obj[:-1]):
            with self.assertRaises((ValueError,struct.error)):build.coff_binding(data,efi,'rendezvous')
        changed=bytearray(obj);changed[140+4096]^=1
        with self.assertRaises(ValueError):build.coff_binding(bytes(changed),efi,'rendezvous')
        with self.assertRaises(ValueError):build.coff_binding(obj,efi,'missing_ap')

    def test_twin_manifests_must_be_distinct_directories_and_inodes(self):
        with self.assertRaisesRegex(ValueError,'distinct'):verifier.verify(Path('same/manifest.json'),Path('same/manifest.json'),None,[])
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();a=root/'a';b=root/'b';a.mkdir();b.mkdir();first=a/'manifest.json';second=b/'manifest.json'
            first.write_bytes(b'{}');os.link(first,second)
            with self.assertRaisesRegex(ValueError,'distinct'):verifier.verify(first,second,None,[])
            second.unlink();second.write_bytes(b'{}')
            with mock.patch.object(verifier,'validate_build',side_effect=ValueError('past identity gate')):
                with self.assertRaisesRegex(ValueError,'past identity gate'):verifier.verify(first,second,None,[])

    def test_strict_json_and_nofollow_bounded_file_references(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}',b'['*80+b'0'+b']'*80):
            with self.assertRaises(ValueError):protocol.strict_json(raw)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();path=root/'data';path.write_bytes(b'abc');alias=root/'alias';alias.symlink_to(path)
            for value,limit in ((alias,3),(path,2)):
                with self.assertRaises(ValueError):protocol.regular_bytes(value,limit)
            for name,size in (('../data',3),('data',True)):
                with self.assertRaises(ValueError):protocol.read_ref(root,{'path':name,'size_bytes':size,'sha256':protocol.digest(b'abc')})

    def test_host_snapshot_and_static_python_import_closure_are_complete(self):
        self.assertEqual(host.EXPECTED_TESTS,26);self.assertEqual(set(host.SOURCES),{'kernel/smp_acpi.rs','tests/k03_smp_acpi.rs'})
        self.assertIn('tests/k03_smp_acpi.rs',provenance.RUNTIME_FILES)
        self.assertIn('#[path = "../kernel/smp_acpi.rs"]',(protocol.ROOT/'tests/k03_smp_acpi.rs').read_text())
        pending=['tools/build_k03_smp.py','tools/run_k03_smp.py','tools/verify_k03_smp.py','tools/check_k03_smp_host.py','tools/summarize_k03_smp_failure.py'];seen=set()
        while pending:
            name=pending.pop()
            if name in seen:continue
            seen.add(name)
            for node in ast.walk(ast.parse((protocol.ROOT/name).read_bytes())):
                modules=[n.name for n in node.names] if isinstance(node,ast.Import) else [node.module] if isinstance(node,ast.ImportFrom) and node.level==0 and node.module else []
                for module in modules:
                    candidate=Path(*module.split('.')).with_suffix('.py')
                    if (protocol.ROOT/candidate).is_file():pending.append(candidate.as_posix())
                    for parent in Path(*module.split('.')).parents:
                        init=parent/'__init__.py'
                        if (protocol.ROOT/init).is_file():pending.append(init.as_posix())
        self.assertLessEqual(seen,set(provenance.RUNTIME_FILES))

    def test_actual_dependency_list_rejects_external_compiler_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'main.rs').write_text('')
            self.assertEqual(build.dependency_paths('out: main.rs\n',root),{'main.rs'})
            for raw in ('out: /etc/passwd\n','out: ../main.rs\n',''):
                with self.assertRaises(ValueError):build.dependency_paths(raw,root)

    def test_source_requires_clean_commit_current_runtime_and_notice_origins(self):
        sources={name:('100644',(protocol.ROOT/name).read_bytes()) for name in set(provenance.COMPILER_SOURCES)|set(provenance.RUNTIME_FILES)|{'LICENSE','NOTICE'}}
        def snapshot(rows):
            h=hashlib.sha256()
            for name,(mode,data) in sorted(rows.items()):h.update(name.encode()+b'\0'+mode.encode()+b'\0'+protocol.digest(data).encode()+b'\0')
            return h.hexdigest()
        value={'source':{'revision':'1'*40,'dirty':False,'snapshot_algorithm':'git-worktree-v2','tree_sha256':snapshot(sources)},
            'source_files':{n:protocol.digest(sources[n][1]) for n in provenance.COMPILER_SOURCES},'runtime_files':{n:protocol.digest(sources[n][1]) for n in provenance.RUNTIME_FILES},
            'notices':[{'path':'notices/tessryn-'+n,'sha256':protocol.digest(sources[n][1]),'size_bytes':len(sources[n][1])} for n in ('LICENSE','NOTICE')]}
        with mock.patch.object(provenance,'committed_sources',return_value=sources):
            self.assertEqual(provenance.validate_source(value)['runtime_files'],24)
            for name in provenance.RUNTIME_FILES:
                changed=copy.deepcopy(value);changed_sources=dict(sources);changed_sources[name]=('100644',sources[name][1]+b'changed')
                changed['runtime_files'][name]=protocol.digest(changed_sources[name][1]);changed['source']['tree_sha256']=snapshot(changed_sources)
                with self.subTest(name=name),mock.patch.object(provenance,'committed_sources',return_value=changed_sources),self.assertRaises(ValueError):provenance.validate_source(changed)
        changed=copy.deepcopy(value);changed['source']['dirty']=True
        with mock.patch.object(provenance,'committed_sources') as git:
            with self.assertRaisesRegex(ValueError,'clean'):provenance.validate_source(changed)
            git.assert_not_called()
        with mock.patch.object(provenance,'git_bytes') as git:
            for revision in ('HEAD','1'*39,'1'*40+'\nwarning'):
                with self.assertRaises(ValueError):provenance.committed_sources(revision)
            git.assert_not_called()

    def test_public_cli_probe_and_output_errors_are_type_only(self):
        for module,method,args in ((build,'build',['--out','build/private-path']), (host,'check',['--out','build/private-path']),
            (runner,'run',['--manifest','build/private-path','--out','build/private-output','--case','rendezvous','--allow-qemu'])):
            error=subprocess.TimeoutExpired('/private/secret-command',30,output=b'private-token')
            stderr=io.StringIO()
            with self.subTest(module=module.__name__),mock.patch.object(sys,'argv',[module.__file__,*args]),mock.patch.object(module,method,side_effect=error),redirect_stderr(stderr),self.assertRaises(SystemExit):module.main()
            self.assertNotIn('secret-command',stderr.getvalue());self.assertNotIn('private-token',stderr.getvalue())
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary)/'exists';out.write_text('keep');stderr=io.StringIO()
            args=['x','--first','a','--second','b','--host-result','h','--result','r','--out',str(out)]
            with mock.patch.object(sys,'argv',args),redirect_stderr(stderr),self.assertRaises(SystemExit):verifier.main()
            self.assertNotIn(temporary,stderr.getvalue());self.assertEqual(out.read_text(),'keep')

    def test_runner_requires_opt_in_and_capture_only_cannot_be_final_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();out=root/'out';out.mkdir()
            with mock.patch.object(runner,'fresh_output',return_value=out),mock.patch.object(runner,'run_bounded') as launch:
                result=runner.run(root/'manifest.json',out,'rendezvous')
            self.assertEqual(result['status'],'fail');launch.assert_not_called()
            result['status']='captured';result['capture_only']=True;(out/'result.json').write_text(json.dumps(result))
            with self.assertRaisesRegex(ValueError,'complete acceptance'):verifier.verify_capture(out/'result.json',root/'manifest.json',{})

    def test_firmware_notice_and_success_notice_origin_are_not_self_authorized(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'notices').mkdir();rows=[];setup={'rust_notices':{}}
            for component,name in (('tessryn','LICENSE'),('tessryn','NOTICE'),('rust','LICENSE-APACHE'),('rust','LICENSE-MIT'),('rust','COPYRIGHT')):
                data=(protocol.ROOT/name).read_bytes() if component=='tessryn' else name.encode();path=root/'notices'/(component+'-'+name);path.write_bytes(data)
                rows.append({'component':component,**protocol.file_ref(root,path)})
                if component=='rust':setup['rust_notices'][name]={'sha256':protocol.digest(data),'size_bytes':len(data)}
            verifier.validate_notices(root,rows,setup)
            for i in (0,2):
                row=rows[i];path=root/row['path'];original=path.read_bytes();path.write_bytes(b'rebound');new=copy.deepcopy(rows);new[i].update(protocol.file_ref(root,path))
                with self.assertRaises(ValueError):verifier.validate_notices(root,new,setup)
                path.write_bytes(original)

    def test_failure_summary_excludes_original_messages_and_untrusted_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'rendezvous').mkdir();secret='/Users/private token'
            (root/'rendezvous/result.json').write_text(json.dumps({'reason':secret,'execution':{'status':secret,'returncode':True}}))
            (root/'rendezvous/stderr.log').write_text(secret);summary=failure.summarize(root)
            self.assertNotIn(secret,json.dumps(summary));self.assertIsNone(summary['cases']['rendezvous']['returncode']);self.assertFalse(summary['raw_output_published'])

    def test_success_workflow_is_exact_source_bound_and_failure_output_is_separate(self):
        workflow=(protocol.ROOT/'.github/workflows/k03-smp.yml').read_text();block=workflow.split('name: k03-smp-bootstrap-evidence',1)[1].split('retention-days: 14',1)[0]
        actual=[line.strip() for line in block.split('path: |',1)[1].split('if-no-files-found:',1)[0].splitlines() if line.strip()]
        expected=[]
        for twin in ('a','b'):
            p=f'build/k03-smp/{twin}/';expected.append(p+'manifest.json')
            for case in protocol.CASES:expected.extend(p+case+'/'+n for n in ('BOOTX64.EFI','kernel.obj','boot.img','stdout.log','stderr.log'))
            expected.extend(p+'notices/'+n for n in ('tessryn-LICENSE','tessryn-NOTICE','rust-LICENSE-APACHE','rust-LICENSE-MIT','rust-COPYRIGHT'))
            expected.extend(p+'sources/'+n for n in set(provenance.COMPILER_SOURCES)|set(provenance.RUNTIME_FILES))
        for case in protocol.CASES:expected.extend('build/k03-smp/'+case+'/'+n for n in ('result.json','registration.json','stdout.log','stderr.log','firmware/code.fd','firmware/vars.fd','firmware/NOTICE'))
        expected.extend('build/k03-smp/host/'+n for n in ('result.json','build-stdout.log','build-stderr.log','tests-stdout.log','tests-stderr.log'));expected.append('build/k03-smp/verification.json')
        self.assertEqual(len(actual),120);self.assertEqual(len(actual),len(set(actual)));self.assertEqual(set(actual),set(expected))
        self.assertIn('include-hidden-files: true',block);self.assertNotIn('*',''.join(actual));self.assertIn('if: success()',workflow);self.assertIn('if: failure()',workflow)
        self.assertIn('--host-result build/k03-smp/host/result.json',workflow)

    def test_runner_pre_and_post_capture_subprocess_failures_keep_original_receipt(self):
        for post_capture in (False, True):
            with self.subTest(post_capture=post_capture), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                out = root / "capture"
                out.mkdir()
                manifest_path = root / "manifest.json"
                manifest_path.write_text("{}")
                qemu = root / "build/toolchain/bin/qemu-system-x86_64"
                qemu.parent.mkdir(parents=True)
                qemu.write_bytes(b"checked emulator fixture")
                setup = {"verified_tools": {"qemu": {"sha256": protocol.digest(qemu.read_bytes())}}, "firmware": {}}
                for role in ("code", "vars"):
                    path = root / "build/uefi" / (role + ".fd")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(role.encode())
                    setup["firmware"][role] = {"path": path.name, "sha256": protocol.digest(path.read_bytes()), "size_bytes": len(role)}
                notice_path = root / "build/uefi/NOTICE"
                notice_path.write_bytes(b"firmware redistribution notice fixture")
                setup["firmware"]["notice"] = {"path": "NOTICE", "sha256": protocol.digest(notice_path.read_bytes()), "size_bytes": notice_path.stat().st_size}
                manifest = {"runtime_files": {}, "source_files": {}, "toolchain": {"setup": setup},
                            "artifacts": [{"case": "rendezvous", "path": "rendezvous/boot.img"}]}
                error = subprocess.TimeoutExpired("private-command", 30, output=b"private-token")
                probes = [setup, error] if post_capture else [error]
                raw = ProcessResult("completed", "synthetic process receipt", 33, 1.25,
                                    b"original captured stdout\n", b"/Users/private-workspace private-token\n")
                with mock.patch.object(runner, "ROOT", root), mock.patch.object(runner, "fresh_output", return_value=out), \
                        mock.patch.object(verifier, "validate_build", return_value=manifest), \
                        mock.patch.object(runner, "runtime_hashes", return_value={}), \
                        mock.patch.object(runner, "validate_toolchain"), \
                        mock.patch.object(runner, "verify_installation", side_effect=probes), \
                        mock.patch.object(runner, "read_ref", return_value=b"disk fixture"), \
                        mock.patch.object(runner, "run_bounded", return_value=raw) as process:
                    result = runner.run(manifest_path, out, "rendezvous", allow_qemu=True, capture_only=True)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["reason"], "SMP capture rejected: TimeoutExpired")
                self.assertNotIn("private-command", json.dumps(result))
                self.assertNotIn("private-token", json.dumps(result))
                self.assertEqual(process.call_count, int(post_capture))
                self.assertEqual((out / "stdout.log").read_bytes(), raw.stdout if post_capture else b"")
                self.assertEqual((out / "stderr.log").read_bytes(), raw.stderr if post_capture else b"")
                self.assertEqual(result["execution"]["returncode"], 33 if post_capture else None)
                self.assertEqual(json.loads((out / "result.json").read_text()), result)
                self.assertEqual((out / "private-probe-stdout.log").read_bytes(), b"private-token")
                if post_capture:
                    self.assertEqual((out / "firmware/NOTICE").read_bytes(), notice_path.read_bytes())


if __name__=='__main__':unittest.main()
