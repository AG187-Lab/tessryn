"""Synthetic format/negative tests; these fixtures are not native executions."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import sys
import unittest
from unittest.mock import patch

from tools.build_k02_native import (ARTIFACT_TYPE, CASES, CPU, PROFILE, SCOPE, PROBE_SYMBOLS, case_flags,
                                    coff_probes, compile_flags, dependency_paths, probe_binding)
from tools.run_k02_native import qemu_command, launcher_command
from tools import run_k02_native
from tools.g03.process import run_bounded
from tools.verify_k02_native import parse_transcript, validate_build, USER_CODE, USER_STACK
from tools.k01_media import make_disk
from tools.build_kernel import inspect_pe


def synthetic_object():
    code = bytearray((x * 7 + 3) % 256 for x in range(4096))
    offsets = {name: index * 16 for index, name in enumerate(PROBE_SYMBOLS)}
    code[offsets['k02_probe_own_return']:offsets['k02_probe_own_return'] + 2] = b'\xcd\x80'
    labels = {'k02_user_code_start': 0, 'k02_user_code_end': 4096, **offsets}
    strings = bytearray(b'\0' * 4)
    symbols = bytearray()
    for name, value in labels.items():
        at = len(strings)
        strings.extend(name.encode() + b'\0')
        symbols.extend(struct.pack('<IIIhHBB', 0, at, value, 1, 0, 2, 0))
    struct.pack_into('<I', strings, 0, len(strings))
    header = struct.pack('<HHIIIHH', 0x8664, 1, 0, 60 + 4096, len(labels), 0, 0)
    section = bytearray(40)
    section[:5] = b'.text'
    struct.pack_into('<II', section, 16, 4096, 60)
    return header + section + code + symbols + strings, bytes(code), offsets


def synthetic_efi(code):
    data = bytearray(0x1400)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 2, 0, 0, 0, 0xf0, 0x2022)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b)
    struct.pack_into('<I', data, optional + 16, 0x1000)
    struct.pack_into('<H', data, optional + 68, 10)
    struct.pack_into('<I', data, optional + 108, 16)
    struct.pack_into('<II', data, optional + 112 + 5 * 8, 0x3000, 12)
    for index, (name, rva, size, raw, flags) in enumerate(((b'.text', 0x1000, 4096, 0x200, 0x60000020), (b'.reloc', 0x3000, 512, 0x1200, 0x42000040))):
        at = optional + 0xf0 + index * 40
        data[at:at + len(name)] = name
        struct.pack_into('<IIII', data, at + 8, size, rva, size, raw)
        struct.pack_into('<I', data, at + 36, flags)
    data[0x200:0x1200] = code
    struct.pack_into('<IIHH', data, 0x1200, 0x1000, 12, 0xa000, 0)
    return bytes(data)


def synthetic_serial(case, binding):
    offsets = binding['offsets']
    instruction = USER_CODE + offsets['k02_probe_own_write' if case == 'own_page' else 'k02_probe_' + case]
    expected = USER_CODE + offsets['k02_probe_own_return'] + 2 if case == 'own_page' else instruction
    target = {'own_page': USER_CODE + 0x1000, 'foreign_read': USER_CODE + 0x3000,
              'readonly_write': USER_CODE + 0x4000, 'kernel_read': 0x170000}[case]
    vector,error,kind = (128,0,'controlled_return') if case == 'own_page' else (14,{'foreign_read':4,'kernel_read':5,'readonly_write':7}[case],'expected_page_fault')
    mappings = [('own',2,USER_CODE+0x1000,0x300000,1),('stack',2,USER_CODE+0x2000,0x301000,1),
                ('readonly',2,USER_CODE+0x4000,0x302000,0),('foreign',1,USER_CODE+0x3000,0x303000,0)]
    lines = ['TESSRYN_K01_ENTRY',
             'TESSRYN_K01_LIVE_RANGES image_start=0x100000 image_end=0x200000 stack_start=0x220000 stack_end=0x240000 map_start=0x240000 map_end=0x250000 scratch=0x250000 runtime_high=0 gop_start=0x80000000 gop_end=0x80200000',
             'TESSRYN_K01_EXIT_BOOT_SERVICES_OK','TESSRYN_K01_CPU_OWNED cr3=0x100000',
             'TESSRYN_K02_PROFILE physical_bits=48 cpu_count=1 paging_levels=4 nx_supported=1 nx_enabled=1 pcid_enabled=0 global_translations=0 la57_enabled=0 cr4=0x620 efer_low=0xd00',
             'TESSRYN_K02_INVENTORY descriptors=25 available_pages=10000 protected_state=0x170000 source=final_successful_handoff']
    lines += [f'TESSRYN_K02_MAPPING role={role} domain={domain} virtual={va:#x} physical={pa:#x} page_bytes=4096 writable={writable} nx=1' for role,domain,va,pa,writable in mappings]
    lines += [f'TESSRYN_K02_USER_ENTER case={case} domain=2 root=0x120000 code={USER_CODE:#x} code_physical={0x100000+binding["efi_rva"]:#x} stack_start={USER_STACK:#x} stack_end={USER_STACK+4096:#x} instruction={instruction:#x} probe_rip={expected:#x} target={target:#x} trap_start=0x180000 trap_end=0x184000',
              f'TESSRYN_K02_TRAP case={case} domain=2 vector={vector} error={error:#x} rip={expected:#x} cs=0x33 ss=0x2b rflags=0x2 rsp={USER_STACK+4000:#x} cr2={target:#x} frame=0x183d00 kind={kind}',
              'TESSRYN_K02_SENTINELS victim_unchanged=1 foreign_unchanged=1 own_verified=1 pages_scrubbed=4 victim=0x302000 foreign=0x303000 own=0x300000']
    lines += [f'TESSRYN_K02_TEARDOWN virtual={va:#x} physical={pa:#x} order=fence_pte_remove_cr3_reload_quiesce' for _,_,va,pa,_ in mappings]
    lines += [f'TESSRYN_K02_PASS case={case} cpl3_observed=1 owned_pages_after=0 scope=single_cpu_emulated_protection_slice']
    return ('\n'.join(lines)+'\n').encode()


class K02NativeToolingTests(unittest.TestCase):
    def setUp(self):
        self.obj, self.code, self.offsets = synthetic_object()
        self.binding = probe_binding(self.obj, synthetic_efi(self.code))

    def test_actual_coff_labels_and_unique_linked_code_binding(self):
        code, offsets = coff_probes(self.obj)
        self.assertEqual(code, self.code)
        self.assertEqual(offsets, self.offsets)
        self.assertEqual(self.binding['efi_rva'], 0x1000)
        self.assertEqual(self.binding['instruction_bytes']['k02_probe_own_return'][:4], 'cd80')

    def test_coff_bounds_and_missing_labels_rejected(self):
        for raw in (self.obj[:19], self.obj[:-1], self.obj[:4200]):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                coff_probes(raw)
        raw = self.obj.replace(b'k02_probe_foreign_read\0', b'k02_probe_foreign_fake\0')
        with self.assertRaises(ValueError):
            coff_probes(raw)

    def test_relocated_or_duplicate_code_blob_cannot_bind(self):
        efi = synthetic_efi(self.code)
        with self.assertRaises(ValueError):
            probe_binding(self.obj, efi.replace(self.code, b'\0' * 4096))
        with self.assertRaises(ValueError):
            probe_binding(self.obj, efi + self.code)

    def test_uefi_library_abi_and_kernel_case_flags_are_explicit(self):
        profile = {'toolchain': {'rust_flags': ['--target=x86_64-unknown-uefi', '--crate-name=tessryn_kernel', '--crate-type=bin', '-Clink-arg=/debug:none']}}
        flags = compile_flags(profile, True)
        self.assertIn('--crate-type=rlib', flags)
        self.assertIn('--crate-name=tessryn_owned_memory', flags)
        self.assertIn('--target=x86_64-unknown-uefi', flags)
        self.assertFalse(any(x.startswith('-Clink-arg=') for x in flags))
        with self.assertRaises(ValueError):
            case_flags('normal')

    def test_bounded_emulator_profile_disables_pcid_globals_la57_and_network(self):
        command = qemu_command()
        self.assertEqual(command[command.index('-cpu') + 1], CPU)
        self.assertEqual(command[command.index('-smp') + 1], '1')
        self.assertEqual(command[command.index('-nic') + 1], 'none')
        self.assertIn('-no-user-config', command)

    def test_actual_bounded_child_creates_temporary_file_inside_its_fresh_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            scratch=Path(temporary).resolve()
            child=Path(sys.executable).resolve()
            args=['-I','-S','-B','-c','import tempfile; f=tempfile.NamedTemporaryFile(delete=False); f.write(b"context"); f.close(); print(f.name)']
            result=run_bounded(launcher_command(child,args,scratch),scratch,5,4096)
            self.assertEqual(result.status,'completed')
            self.assertEqual(result.returncode,0)
            created=Path(result.stdout.decode().strip())
            self.assertEqual(created.parent,scratch)
            self.assertEqual(created.read_bytes(),b'context')

    def test_all_four_synthetic_transcript_shapes(self):
        for case in CASES:
            with self.subTest(case=case):
                self.assertEqual(parse_transcript(case, synthetic_serial(case, self.binding), 33, b'', self.binding)['pass']['case'], case)

    def test_low_conventional_frames_accept_but_null_reserved_and_shared_backing_do_not(self):
        raw = synthetic_serial('foreign_read', self.binding)
        low = raw
        for old,new in [(b'0x300000',b'0x1000'),(b'0x301000',b'0x2000'),
                        (b'0x302000',b'0x3000'),(b'0x303000',b'0x4000')]:
            low = low.replace(old,new)
        self.assertEqual(parse_transcript('foreign_read',low,33,b'',self.binding)['mappings'][0]['physical'],'0x1000')
        for invalid in [b'0x0',b'0x1001',b'0x100000000',b'0x170000',b'0x230000',b'0x240000',b'0x250000',b'0x80000000']:
            with self.subTest(physical=invalid),self.assertRaises(ValueError):
                parse_transcript('foreign_read',low.replace(b'physical=0x1000',b'physical='+invalid),33,b'',self.binding)
        with self.assertRaises(ValueError):
            parse_transcript('foreign_read',raw.replace(b'0x303000',b'0x302000'),33,b'',self.binding)

    def test_both_independent_victims_and_all_four_scrubs_are_required(self):
        raw = synthetic_serial('foreign_read',self.binding)
        for before,after in [(b'foreign_unchanged=1',b'foreign_unchanged=0'),
                             (b'victim_unchanged=1',b'victim_unchanged=0'),
                             (b'foreign=0x303000',b'foreign=0x302000'),
                             (b'pages_scrubbed=4',b'pages_scrubbed=3')]:
            with self.subTest(field=before),self.assertRaises(ValueError):
                parse_transcript('foreign_read',raw.replace(before,after),33,b'',self.binding)

    def test_evaluator_identity_binds_transitive_helpers_and_both_toolchain_locks(self):
        dependencies=('tools/build_fixture.py','tools/setup_toolchain.py','tools/g03/evidence.py',
                      'toolchain.lock.json','uefi-toolchain.lock.json')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name in run_k02_native.EVALUATOR_FILES:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((run_k02_native.ROOT/name).read_bytes())
            with patch.object(run_k02_native,'ROOT',root):
                original=run_k02_native.evaluator_hash()
                for name in dependencies:
                    path=root/name;before=path.read_bytes();path.write_bytes(before+b'\nSYNTHETIC_MUTATION\n')
                    with self.subTest(dependency=name):
                        self.assertNotEqual(run_k02_native.evaluator_hash(),original)
                    path.write_bytes(before)

    def test_actual_fault_error_address_and_instruction_are_required(self):
        raw = synthetic_serial('readonly_write', self.binding)
        for before, after in [(b'error=0x7', b'error=0x5'), (b'cs=0x33', b'cs=0x8'), (b'cr2=0x100004000', b'cr2=0x100003000'), (b'probe_rip=0x100000050', b'probe_rip=0x100000051'), (b'frame=0x183d00', b'frame=0x100002100')]:
            with self.subTest(field=before), self.assertRaises(ValueError):
                parse_transcript('readonly_write', raw.replace(before, after), 33, b'', self.binding)

    def test_bare_pass_duplicates_profile_drift_and_trailing_restart_rejected(self):
        raw = synthetic_serial('own_page', self.binding)
        for changed in [b'TESSRYN_K02_PASS case=own_page\n', b'TESSRYN_K01_ENTRY\n' + raw,
                        raw.replace(b'nx_enabled=1', b'nx_enabled=0'), raw + b'TESSRYN_K01_ENTRY\n',
                        raw.replace(b'case=own_page domain=', b'case=own_page case=own_page domain=')]:
            with self.subTest(data=changed[:50]), self.assertRaises(ValueError):
                parse_transcript('own_page', changed, 33, b'', self.binding)
        with self.assertRaises(ValueError):
            parse_transcript('own_page', raw, 0, b'', self.binding)
        with self.assertRaises(ValueError):
            parse_transcript('own_page', raw, 33, b'Triple fault', self.binding)

    def test_manifest_checks_real_bytes_uefi_linkage_and_notice_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            efi = synthetic_efi(self.code)
            artifacts = []
            def row(name, data, **extra):
                path = out / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                return {'path': name, 'sha256': hashlib.sha256(data).hexdigest(),
                        'size_bytes':len(data), **extra}
            artifacts.append(row('libtessryn_owned_memory.rlib', b'SYNTHETIC_RLIB',
                                 target='x86_64-unknown-uefi', crate='tessryn_owned_memory'))
            commands = {'core':['kernel-core/lib.rs','--target=x86_64-unknown-uefi','--crate-type=rlib','--crate-name=tessryn_owned_memory']}
            for case in CASES:
                artifacts.extend([row(case+'/BOOTX64.EFI',efi,case=case,pe_validation=inspect_pe(efi)),
                                  row(case+'/boot.img',make_disk(efi),case=case),
                                  row(case+'/kernel.obj',self.obj,case=case)])
                commands[case] = ['kernel/main.rs','--target=x86_64-unknown-uefi','--crate-type=bin',
                                  *case_flags(case),'--extern','tessryn_owned_memory=k02-build/libtessryn_owned_memory.rlib']
            sources = {name:'a'*64 for name in ['kernel/main.rs','kernel/entry.S','kernel-core/lib.rs','interfaces/abi-v1/native.rs']}
            notices = [row('notices/'+name,b'SYNTHETIC_NOTICE') for name in ['tessryn-LICENSE','tessryn-NOTICE','rust-LICENSE-APACHE','rust-LICENSE-MIT','rust-COPYRIGHT']]
            manifest = {'schema_version':1,'artifact_type':ARTIFACT_TYPE,'profile':PROFILE,'cases':list(CASES),
                        'scope':SCOPE,'artifacts':artifacts,'probes':{case:self.binding for case in CASES},
                        'compile_commands':commands,'source_files':sources,
                        'source_files_sha256':hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'notices':notices}
            path = out/'manifest.json'
            def check(value):
                path.write_text(json.dumps(value));return validate_build(path)
            self.assertEqual(check(manifest),manifest)
            changed=copy.deepcopy(manifest); changed['artifacts'][0]['target']='x86_64-unknown-none'
            with self.assertRaises(ValueError):check(changed)
            changed=copy.deepcopy(manifest); changed['compile_commands']['core'][1]='--target=x86_64-unknown-none'
            with self.assertRaises(ValueError):check(changed)
            changed=copy.deepcopy(manifest); changed['notices'][0]['path']='../external'
            with self.assertRaises(ValueError):check(changed)
            changed=copy.deepcopy(manifest); changed['artifacts'].append(changed['artifacts'][0])
            with self.assertRaises(ValueError):check(changed)
            (out/'own_page/kernel.obj').write_bytes(b'changed-object')
            with self.assertRaises(ValueError):check(manifest)


if __name__ == '__main__':
    unittest.main()
