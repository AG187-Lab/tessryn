"""SYNTHETIC artifact contracts and fail-closed matrix tooling boundaries."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools import build_k02_matrix as build
from tools import run_k02_matrix as run
from tools.verify_k02_matrix import parse_transcript,initialized_digest,reset_fp_digest,validate_result,verify
from tools.build_k02_native import PROBE_SYMBOLS
from tools.build_kernel import inspect_pe
from tools.run_kernel import artifact_bytes


def synthetic_pair(case='recursive_revocation'):
    code=bytearray((i*7+3)%256 for i in range(4096))
    labels={name:i*16 for i,name in enumerate(PROBE_SYMBOLS)}
    for i,name in enumerate(build.FAULT_LABELS):
        at=labels.setdefault(name,128+i*16);labels[name+'_return']=at+5
        spec=build.CONTRACT['faults'][name.removeprefix('k02_probe_')]
        code[at:at+5]=b'\x48\x89\x37\xcd\x80' if spec['error_code']&2 else b'\x48\x8b\x07\xcd\x80'
    for name,at,end in (('read',512,5),('write',528,5),('request',544,2)):
        labels['k02_probe_'+name]=at;labels['k02_probe_'+name+('_trap' if name=='request' else '_return')]=at+end
        opcode={'read':b'\x48\x8b\x07\xcd\x80','write':b'\x48\x89\x37\xcd\x80','request':b'\xcd\x80'}[name]
        code[at:at+len(opcode)]=opcode
    labels['k02_probe_boundary_snapshot']=768
    labels['k02_probe_boundary_snapshot_return']=768+len(build.BOUNDARY_OPCODES)
    code[768:768+len(build.BOUNDARY_OPCODES)]=build.BOUNDARY_OPCODES
    labels.update(k02_user_code_start=0,k02_user_code_end=4096)
    raw=build.MAGIC+struct.pack('<21Q',1,build.CASES.index(case),1,2,3,4,*build.ADDRESSES,*build.SEEDS)
    requests=b'TESSRYN-K02R-V1\0'+b''.join(struct.pack('<8Q',*row) for row in build.REQUEST_ROWS)
    symbol_rows=[(name,1,value) for name,value in labels.items()]+[('K02_MATRIX_CONTRACT',2,0),('K02_MATRIX_REQUESTS',2,len(raw))]
    strings=bytearray(b'\0'*4);symbols=bytearray()
    for name,section,value in symbol_rows:
        at=len(strings);strings.extend(name.encode()+b'\0');symbols.extend(struct.pack('<IIIhHBB',0,at,value,section,0,2,0))
    struct.pack_into('<I',strings,0,len(strings));table=100+4096+len(raw)+len(requests)
    obj=bytearray(struct.pack('<HHIIIHH',0x8664,2,0,table,len(symbol_rows),0,0))
    for name,size,where in ((b'.text',4096,100),(b'.rdata',len(raw)+len(requests),4196)):
        section=bytearray(40);section[:len(name)]=name;struct.pack_into('<II',section,16,size,where);obj.extend(section)
    obj.extend(code+raw+requests+symbols+strings)
    efi=bytearray(0x1c00);efi[:2]=b'MZ';struct.pack_into('<I',efi,60,0x80);efi[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',efi,0x84,0x8664,3,0,0,0,0xf0,0x2022)
    optional=0x98;struct.pack_into('<H',efi,optional,0x20b);struct.pack_into('<I',efi,optional+16,0x1000)
    struct.pack_into('<I',efi,optional+60,0x200)
    struct.pack_into('<H',efi,optional+68,10);struct.pack_into('<I',efi,optional+108,16);struct.pack_into('<II',efi,optional+112+5*8,0x4000,12)
    for i,(name,rva,size,where,flags) in enumerate(((b'.text',0x1000,4096,0x200,0x60000020),(b'.rdata',0x3000,2048,0x1200,0x40000040),(b'.reloc',0x4000,512,0x1a00,0x42000040))):
        at=optional+0xf0+i*40;efi[at:at+len(name)]=name;struct.pack_into('<IIII',efi,at+8,size,rva,size,where);struct.pack_into('<I',efi,at+36,flags)
    efi[0x200:0x1200]=code;efi[0x1200:0x1200+len(raw)+len(requests)]=raw+requests;struct.pack_into('<IIHH',efi,0x1a00,0x1000,12,0xa000,0)
    return bytes(obj),bytes(efi),raw


def synthetic_trace(case,binding):
    """SYNTHETIC full wire shape; never substituted for an emulator capture."""
    a=binding['descriptor']['addresses'];seeds=binding['descriptor']['seeds'];code=binding['code']
    roots={i:0x120000+(i-1)*0x20000 for i in range(1,5)};pa=0xd000
    lines=['TESSRYN_K01_ENTRY',
           'TESSRYN_K01_LIVE_RANGES image_start=0x100000 image_end=0x300000 stack_start=0x310000 stack_end=0x330000 map_start=0x340000 map_end=0x350000 scratch=0x400000 runtime_high=0 gop_start=0x80000000 gop_end=0x80200000',
           'TESSRYN_K01_EXIT_BOOT_SERVICES_OK','TESSRYN_K01_CPU_OWNED cr3=0x110000 rsp=0x32ff00 rip=0x101000 gdt=owned idt=owned tss=owned',
           'TESSRYN_K02_PROFILE physical_bits=48 cpu_count=1 paging_levels=4 nx_supported=1 nx_enabled=1 pcid_enabled=0 global_translations=0 la57_enabled=0 cr4=0x620 efer_low=0xd00',
           'TESSRYN_K02_MATRIX_CPU cr0=0x80010033 wp_enabled=1 pke_enabled=0 pks_enabled=0 cet_enabled=0 sgx_supported=0 osxsave_enabled=0 fxsave_mxcsr_mask=65535']
    def record(kind,**values):lines.append('TESSRYN_K02_MATRIX_'+kind+' '+' '.join(key+'='+str(value) for key,value in values.items()))
    for domain,root in roots.items():record('ROOT',domain=domain,root=root,pool_end=root+17*4096)
    record('INVENTORY',case=case,descriptors=25,available_pages=10000,protected_state=0x1e0000,baseline_pages=12,source='final_successful_handoff')
    sequence=0
    def event(name,**values):
        nonlocal sequence
        record('EVENT',sequence=sequence,event=name,**values);sequence+=1
    def cap(prefix,domain,generation=1,slot=3):return {prefix+'_slot':slot,prefix+'_generation':generation,prefix+'_domain':domain}
    def common(domain,va,slot,generation=1):return {'domain':domain,'root':roots[domain],'page':va,'physical_frame':pa,'lease_slot':slot,'lease_generation':generation,'charge_retained':1}
    def mapping(domain,va,slot,writable,generation=1):event('mapping_installed',**common(domain,va,slot,generation),length=4096,readable=1,writable=writable,executable=0)
    def probe(name,domain,va,kind,rax=0):
        fault=kind=='fault';instruction=binding['faults'][name]['rip'] if fault else a['code']+code['offsets']['k02_probe_'+kind]
        suffix='_trap' if kind=='request' else '_return'
        rip=instruction if fault else a['code']+code['offsets']['k02_probe_'+kind+suffix];error=binding['faults'][name]['error_code'] if fault else 0
        record('USER_ENTER',probe=name,domain=domain,root=roots[domain],instruction=instruction,probe_rip=rip,target=va,
               stack_start=a['stack'],stack_end=a['stack']+4096,trap_start=0x250000,trap_end=0x258000,code_physical=0x100000+code['efi_rva'])
        saved={'vector':14 if fault else 128,'error':error,'rip':rip,'cs':0x33,'rflags':0x10002 if fault else 2,
               'rsp':a['stack']+4080,'cr2':va if fault else 0}
        lines.append('TESSRYN_K01_EXCEPTION '+' '.join(key+'='+str(value) for key,value in saved.items()))
        record('TRAP',probe=name,domain=domain,root=roots[domain],**saved,ss=0x2b,frame=0x257f50,rax=rax)
        if fault:event('page_fault',probe=name,domain=domain,root=roots[domain],vector=14,cs=0x33,rip=rip,cr2=va,error_code=error,recovered=1)
    def prime(domain,va,slot,writable):
        if writable:probe('prime_write',domain,va,'write');probe('prime_read',domain,va,'read',seeds['write'])
        else:probe('prime_read',domain,va,'read',seeds['victim'])
        event('mapping_primed',**common(domain,va,slot),read_executed=1,write_executed=writable)
    def remove(domain,va,slot,generation=1):
        values=common(domain,va,slot,generation)
        event('fence',**values);event('clear_pte',**values);event('invalidate',**values,method='cr3_reload');event('quiesce',**values,trusted=1)
    def request(recipe,domain=2,claim=2,submitted=None):
        probe('request',domain,a['request'],'request')
        words=list(build.REQUEST_ROWS[recipe])
        if submitted is not None:words[6]=submitted[0]|(submitted[1]<<32)
        event('request_observed',recipe=recipe,caller=domain,claimed_caller=claim,pointer=a['request'],
              physical_frame=0x5000+domain*4096,**{'word'+str(i):word for i,word in enumerate(words)})
    def denied(recipe,operation,reason,claim=2,domain=2,slot=3,generation=1,submitted=None,phase=None,**extra):
        request(recipe,claim=claim,submitted=submitted)
        values=dict(caller=2,claimed_caller=claim,operation=operation,origin='CPL3',cs=0x33,
                    **cap('capability',domain,generation,slot),pte_published=0,charge_released=0,denial_reason=reason)
        if submitted is not None:values.update(submitted_lease_slot=submitted[0],submitted_lease_generation=submitted[1])
        if phase is not None:values.update(lease_phase=phase,pte_installed=1)
        event('dispatch_denied',**values,**extra)
    probe('boundary_snapshot',2,a['request'],'boundary_snapshot')
    event('boundary_sanitized',domain=2,root=roots[2],page=a['request'],physical_frame=0x7000,length=640,gpr_words=16,gpr_zeroed=1,fp_bytes=512,fcw=895,mxcsr=8064,mxcsr_mask=65535,fp_sha256=reset_fp_digest(65535),osxsave_enabled=0,kernel_fp_restored=1)
    event('fresh_boot',case=case,reset='original_kernel_entry',untrusted_state_retained=0)
    if case!='kernel_isolation':
        owner=2 if case in ('writable_reuse','stale_identities') else 1
        event('backing_owned',**cap('capability',owner),physical_frame=pa,length=4096,charge_owner=owner,
              committed_pages=1,reserved_pages=0,charged_pages=1,domain_charged_pages=4,baseline_pages=3)
    if case=='caller_forgery':
        denied(0,'map','InvalidAuthority',claim=1,domain=1)
        event('owner_retained',**cap('capability',1))
    elif case in ('trusted_operation_forgery','exact_bounds'):
        event('delegated',**cap('parent',1),**cap('child',2),offset=0,length=4096,rights=5)
        mapping(2,a['readonly'],12,0)
        values=common(2,a['readonly'],12)
        if case=='trusted_operation_forgery':
            for recipe,operation in ((1,'fence'),(2,'quiesce'),(3,'allocator_admin'),(4,'complete_lease'),(5,'activate_reserved')):
                denied(recipe,operation,'untrusted_origin',submitted=(12,1))
            event('fence',**values);event('trusted_fence_state',**values,trusted=1,phase='fenced',pte_installed=1)
            denied(2,'quiesce','untrusted_origin',submitted=(12,1),phase='fenced')
            event('mapping_owner_retained',**values,phase='fenced',pte_installed=1)
            event('owner_retained',**cap('capability',1),charge_retained=1)
            event('clear_pte',**values);event('invalidate',**values,method='cr3_reload');event('quiesce',**values,trusted=1)
        else:
            probe('guard_read',2,a['guard'],'fault')
            event('delegated',**cap('parent',1),**cap('child',2,slot=4),offset=1,length=4094,rights=5)
            denied(6,'map_byte_slice','Alignment',slot=4,capability_offset=1,capability_length=4094,offset=0,length=4094)
            denied(7,'map_byte_slice','Bounds',slot=4,capability_offset=1,capability_length=4094,offset=0,length=4096)
            remove(2,a['readonly'],12);event('lease_released',lease_slot=12,lease_generation=1,physical_frame=pa,charge_retained=1)
            event('delegated',**cap('parent',1),**cap('child',2,slot=5),offset=0,length=4096,rights=6)
            denied(8,'map_without_read','InsufficientRights',slot=5,rights=6)
    elif case=='recursive_revocation':
        event('delegated',**cap('parent',1),**cap('child',2),offset=0,length=4096,rights=21)
        event('delegated',**cap('parent',2),**cap('child',4),offset=0,length=4096,rights=5)
        mapping(2,a['revoked_B'],12,0);prime(2,a['revoked_B'],12,0);mapping(4,a['revoked_D'],13,0);prime(4,a['revoked_D'],13,0)
        event('descendants_revoked',**cap('root_capability',1),**cap('descendant_B',2),**cap('descendant_D',4),charge_retained=1)
        for domain,va,slot in ((2,a['revoked_B'],12),(4,a['revoked_D'],13)):
            request(11 if domain==2 else 12,domain,domain)
            values=dict(domain=domain,**cap('capability',domain),lease_slot=slot,lease_generation=1,denial_reason='Revoked',charge_retained=1)
            event('revoked_request_denied',**values,operation='map',origin='CPL3',cs=0x33,caller=domain,claimed_caller=domain)
            event('revoked_request_denied',**values,operation='complete_lease',origin='trusted_backend',trusted=1)
            remove(domain,va,slot)
        event('mapping_leases_released',B_slot=12,B_generation=1,D_slot=13,D_generation=1,charge_retained=1)
        for name in ('recursive_B_read','recursive_B_write','recursive_D_read','recursive_D_write'):
            spec=binding['faults'][name];probe(name,2 if spec['domain']=='B' else 4,a[spec['page']],'fault')
        event('capabilities_released',**cap('D',4),**cap('B',2),**cap('A',1),charge_released=1)
    elif case in ('writable_reuse','stale_identities'):
        mapping(2,a['reuse_B'],12,1);prime(2,a['reuse_B'],12,1)
        event('revoked',**cap('capability',2),physical_frame=pa,charge_retained=1);remove(2,a['reuse_B'],12)
        event('lease_released',lease_slot=12,lease_generation=1,physical_frame=pa,charge_retained=1)
        event('capability_released',**cap('capability',2),physical_frame=pa,charge_released=1)
        digest=initialized_digest(seeds['C'])
        if case=='stale_identities':event('retired_generation',**cap('capability',2),lease_slot=12,lease_generation=1,released=1)
        event('scrubbed',physical_frame=pa,length=4096,trusted=1,zero_before_payload=1)
        if case=='writable_reuse':
            mapping(3,a['reuse_C'],12,0,2);probe('new_owner_read',3,a['reuse_C'],'read',seeds['C'])
            event('reassigned',physical_frame=pa,**cap('capability',3),domain=3,root=roots[3],page=a['reuse_C'],initial_sha256=digest)
            probe('reuse_B_read',2,a['reuse_B'],'fault');probe('reuse_B_write',2,a['reuse_B'],'fault')
            event('sentinel_unchanged',page=a['reuse_C'],before_sha256=digest,after_sha256=digest);remove(3,a['reuse_C'],12,2)
        else:
            event('backing_owned',**cap('capability',3),physical_frame=pa,length=4096,charge_owner=3,committed_pages=1,reserved_pages=0,charged_pages=1,domain_charged_pages=4,baseline_pages=3)
            event('delegated',**cap('parent',3),**cap('child',2,2),offset=0,length=4096,rights=5)
            mapping(2,a['reuse_B'],12,0,2)
            event('victim_initialized',**cap('capability',3),domain=3,root=roots[3],physical_frame=pa,page=a['reuse_C'],length=4096,initial_sha256=digest)
            denied(9,'release_stale_capability','StaleHandle')
            event('backend_stale_lease_denied',operation='fence',origin='trusted_backend',trusted=1,submitted_lease_slot=12,submitted_lease_generation=1,replacement_lease_slot=12,replacement_lease_generation=2,denial_reason='StaleLease',replacement_phase='active',pte_installed=1,charge_released=0)
            values=common(2,a['reuse_B'],12,2)
            event('replacement_retained',**cap('capability',2,2),**values,phase='active',pte_installed=1)
            request(10);probe('replacement_read',2,a['reuse_B'],'read',seeds['C'])
            event('replacement_read_authorized',caller=2,**cap('capability',2,2),offset=0,length=4096,physical_frame=pa)
            event('fence',**values);event('trusted_fence_state',**values,trusted=1,phase='fenced',pte_installed=1)
            event('sentinel_unchanged',page=a['reuse_C'],before_sha256=digest,after_sha256=digest)
            event('clear_pte',**values);event('invalidate',**values,method='cr3_reload');event('quiesce',**values,trusted=1)
    elif case in ('unauthorized_read','read_only_sharing','data_nx'):
        if case!='unauthorized_read':event('delegated',**cap('parent',1),**cap('child',2),offset=0,length=4096,rights=5)
        domain=1 if case=='unauthorized_read' else 2
        va=a[{'unauthorized_read':'unauthorized','read_only_sharing':'readonly','data_nx':'data_nx'}[case]]
        mapping(domain,va,12,0);probe('nx_data_read' if case=='data_nx' else 'protection_read',domain,va,'read',seeds['victim'])
        digest=initialized_digest(seeds['victim'])
        if case=='data_nx':event('nx_confirmed',supported=1,enabled=1)
        else:event('read_observed',domain=domain,page=va,sha256=digest)
        probe({'unauthorized_read':'unauthorized_read','read_only_sharing':'readonly_write','data_nx':'nx_fetch'}[case],2,va,'fault')
        if case=='read_only_sharing':event('sentinel_unchanged',page=va,before_sha256=digest,after_sha256=digest)
        remove(domain,va,12)
    else:
        probe('supervisor_prime',2,a['own'],'read',seeds['victim']^2)
        for role,va in (('kernel',0x100000),('policy',0x1e0000),('page_table',roots[2])):
            probe(role+'_read',2,va,'fault');probe(role+'_write',2,va,'fault')
            header=bytearray.fromhex(binding['supervisor_kernel_header_hex']);struct.pack_into('<Q',header,binding['supervisor_kernel_imagebase_offset'],0x100000)
            digest=hashlib.sha256(header+b'\0'*(4096-len(header))).hexdigest() if role=='kernel' else hashlib.sha256(('SYNTHETIC_'+role).encode()).hexdigest()
            event('sentinel_unchanged',page=va,before_sha256=digest,after_sha256=digest)
    record('CASE_COMPLETE',case=case,allocated_pages=12)
    for domain in range(1,5):record('ACCOUNTING',domain=domain,charged_pages=0,committed_pages=0,reserved_pages=0)
    record('PASS',case=case,owned_pages_after=0,scope='single_cpu_emulated_matrix_case')
    return ('\n'.join(lines)+'\n').encode()


class MatrixToolingTests(unittest.TestCase):
    def test_compilation_snapshot_retains_exact_regular_bytes_and_rejects_aliases_and_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for directory in ('kernel','kernel-core','interfaces'):(root/directory).mkdir()
            expected={'kernel/main.rs':b'SYNTHETIC_MAIN','kernel/entry.S':b'SYNTHETIC_ASSEMBLY',
                      'kernel/k02_matrix.rs':b'SYNTHETIC_MATRIX','kernel-core/lib.rs':b'SYNTHETIC_POLICY'}
            for name,data in expected.items():(root/name).write_bytes(data)
            with patch.object(build,'ROOT',root):
                self.assertEqual(build.compilation_sources(),expected)
                (root/'kernel/alias.rs').symlink_to(root/'kernel/main.rs')
                with self.assertRaises(ValueError):build.compilation_sources()
                (root/'kernel/alias.rs').unlink()
                with (root/'kernel/oversized.rs').open('wb') as stream:stream.truncate((16<<20)+1)
                with self.assertRaises(ValueError):build.compilation_sources()

    def test_privilege_snapshot_cannot_accept_dirty_state_or_unadmitted_extended_state(self):
        case='caller_forgery';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
        raw=synthetic_trace(case,binding)
        for before,after in ((b'gpr_zeroed=1',b'gpr_zeroed=0'),(b'kernel_fp_restored=1',b'kernel_fp_restored=0'),
                             (reset_fp_digest(65535).encode(),b'a'*64),(b'osxsave_enabled=0',b'osxsave_enabled=1'),
                             (b'fcw=895',b'fcw=0'),(b'mxcsr=8064',b'mxcsr=0')):
            with self.subTest(field=before),self.assertRaises(ValueError):parse_transcript(case,raw.replace(before,after),33,b'',binding)

    def test_result_acceptance_rechecks_every_raw_case_and_execution_identity(self):
        # Fully synthetic files exercise the verifier; no QEMU/qualification claim.
        for case in build.CASES:
            obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
            binding.update(supervisor_kernel_header_hex=efi[:0x200].hex(),supervisor_kernel_imagebase_offset=0xb0)
            raw=synthetic_trace(case,binding)
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);(root/case).mkdir()
                (root/case/'BOOTX64.EFI').write_bytes(efi)
                manifest={'bindings':{case:build.matrix_binding(obj,efi,case)},'toolchain':{'setup':{'verified_tools':{'qemu':{'sha256':'b'*64}},'firmware':{}}},
                          'artifacts':[{'path':case+'/BOOTX64.EFI','case':case,'sha256':hashlib.sha256(efi).hexdigest(),'size_bytes':len(efi),'pe_validation':inspect_pe(efi)}]}
                mp=root/'manifest.json';mp.write_text(json.dumps(manifest))
                logs=[]
                for name,data in (('stdout.log',raw),('stderr.log',b'')):
                    (root/name).write_bytes(data);logs.append({'path':name,'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data)})
                directory='/tmp/tessryn-k02m-synthetic_'+case
                result={'format':run.FORMAT,'case':case,'scope':build.SCOPE,'status':'pass','reason':run.PASS_REASON,
                        'capture_only':False,'qualification':'not_established','manifest_sha256':hashlib.sha256(mp.read_bytes()).hexdigest(),
                        'evaluator_sha256':run.evaluator_hash(),'emulator_sha256':'b'*64,'firmware':{},'logs':logs,
                        'execution':{'command':run.qemu_command(),'timeout_seconds':45,'max_log_bytes':1_048_576,'returncode':33,'elapsed_seconds':1,
                            'launcher':{'temporary_directory':directory,'executable':'/usr/bin/env','sha256':'c'*64,
                            'command':['/usr/bin/env','TMPDIR='+directory,*run.qemu_command()],
                            'tool_path_record':'absolute hash-checked QEMU executed; command displays its pinned role',
                            'temporary_scope':'fresh private owned directory removed after child reap'}},
                        'observations':parse_transcript(case,raw,33,b'',binding)}
                rp=root/'result.json';rp.write_text(json.dumps(result))
                self.assertEqual(validate_result(rp,mp,manifest),result)
                variants=[dict(result,capture_only=True),dict(result,evaluator_sha256='d'*64),
                          dict(result,observations={}),dict(result,status='captured')]
                for changed in variants:
                    rp.write_text(json.dumps(changed))
                    with self.subTest(case=case,change=set(changed)),self.assertRaises(ValueError):validate_result(rp,mp,manifest)
                rp.write_text(json.dumps(result));(root/'stdout.log').write_bytes(raw+b'TESSRYN_K02_MATRIX_PASS\n')
                with self.assertRaises(ValueError):validate_result(rp,mp,manifest)

    @patch('tools.verify_k02_matrix.validate_source',return_value={'verified':'SYNTHETIC boundary'})
    @patch('tools.verify_k02_matrix.validate_toolchain',return_value={})
    def test_full_matrix_requires_clean_twins_all_ten_cases_and_fresh_contexts(self,_toolchain,_source):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);first=root/'first.json';second=root/'second.json'
            first.write_bytes(b'SYNTHETIC');second.write_bytes(b'SYNTHETIC')
            manifest={'matrix_complete':True,'cases':list(build.CASES),'source':{'dirty':False,'revision':'a'*40,'snapshot_algorithm':'git-worktree-v2','tree_sha256':'b'*64}}
            rows=[{'case':case,'execution':{'launcher':{'temporary_directory':'/tmp/tessryn-k02m-'+str(i)}},'observations':{}} for i,case in enumerate(build.CASES)]
            with patch('tools.verify_k02_matrix.validate_build',return_value=manifest),patch('tools.verify_k02_matrix.validate_result',side_effect=rows):
                self.assertEqual(verify(first,second,[root/str(i) for i in range(10)])['status'],'pass')
            for wrong in (rows[:-1],rows[:-1]+[rows[0]],rows[:-1]+[dict(rows[-1],execution=rows[0]['execution'])]):
                with patch('tools.verify_k02_matrix.validate_build',return_value=manifest),patch('tools.verify_k02_matrix.validate_result',side_effect=wrong),self.assertRaises(ValueError):
                    verify(first,second,[root/str(i) for i in range(len(wrong))])
            for changed in (dict(manifest,matrix_complete=False),dict(manifest,source=dict(manifest['source'],dirty=True))):
                with patch('tools.verify_k02_matrix.validate_build',return_value=changed),self.assertRaises(ValueError):verify(first,second,[])
            second.write_bytes(b'DIFFERENT')
            with patch('tools.verify_k02_matrix.validate_build',return_value=manifest),self.assertRaises(ValueError):verify(first,second,[])

    def test_each_request_case_binds_caller_recipe_denial_and_positive_generation_control(self):
        for case in ('caller_forgery','trusted_operation_forgery','exact_bounds','stale_identities'):
            obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
            raw=synthetic_trace(case,binding)
            self.assertEqual(parse_transcript(case,raw,33,b'',binding)['pass']['case'],case)
            changes=[(b'origin=CPL3',b'origin=trusted_backend'),
                     (b'pte_published=0',b'pte_published=1'),
                     (b'charge_released=0',b'charge_released=1'),
                     (b'word7='+str(build.REQUEST_MAGIC).encode(),b'word7=0')]
            for before,after in changes:
                with self.subTest(case=case,field=before),self.assertRaises(ValueError):
                    parse_transcript(case,raw.replace(before,after),33,b'',binding)
        case='trusted_operation_forgery';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
        lines=synthetic_trace(case,binding).splitlines()
        # Repeated identical USER_ENTER lines must check their own hardware
        # exception, never reuse the first occurrence's otherwise-valid frame.
        exceptions=[i for i,line in enumerate(lines) if line.startswith(b'TESSRYN_K01_EXCEPTION ')]
        lines[exceptions[-1]]=lines[exceptions[-1]].replace(b'cs=51',b'cs=8')
        with self.assertRaises(ValueError):parse_transcript(case,b'\n'.join(lines)+b'\n',33,b'',binding)

    def test_four_protection_shapes_require_read_controls_faults_and_whole_page_digests(self):
        for case in ('unauthorized_read','read_only_sharing','kernel_isolation','data_nx'):
            obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
            binding.update(supervisor_kernel_header_hex=efi[:0x200].hex(),supervisor_kernel_imagebase_offset=0xb0)
            observed=parse_transcript(case,synthetic_trace(case,binding),33,b'',binding)
            self.assertEqual(observed['pass']['case'],case)
            self.assertEqual(len(observed['user_probes']),8 if case=='kernel_isolation' else 3)
        case='data_nx';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case);raw=synthetic_trace(case,binding)
        for before,after in ((b'enabled=1',b'enabled=0'),(b'error=21',b'error=5'),
                             (b'rax='+str(build.SEEDS[0]).encode(),b'rax=0')):
            with self.subTest(field=before),self.assertRaises(ValueError):parse_transcript(case,raw.replace(before,after),33,b'',binding)
        case='kernel_isolation';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
        binding.update(supervisor_kernel_header_hex=efi[:0x200].hex(),supervisor_kernel_imagebase_offset=0xb0);raw=synthetic_trace(case,binding)
        with self.assertRaises(ValueError):parse_transcript(case,raw.replace(next(line.split(b'before_sha256=')[1].split()[0] for line in raw.splitlines() if b'event=sentinel_unchanged' in line),b'a'*64),33,b'',binding)
        with self.assertRaises(ValueError):parse_transcript(case,raw.replace(b'after_sha256=',b'after_sha256=0000'),33,b'',binding)
    def test_both_complete_synthetic_lifetime_cases_have_exact_controls_and_events(self):
        for case,events,probes in (('recursive_revocation',30,9),('writable_reuse',22,6)):
            obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
            observed=parse_transcript(case,synthetic_trace(case,binding),33,b'',binding)
            self.assertEqual((len(observed['events']),len(observed['user_probes'])),(events,probes))
            self.assertEqual(observed,json.loads(json.dumps(observed)))

    def test_lifetime_fault_origin_compiled_ip_and_priming_controls_cannot_be_forged(self):
        case='recursive_revocation';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case);raw=synthetic_trace(case,binding)
        for before,after in ((b'cs=51',b'cs=8'),(b'ss=43',b'ss=16'),(b'error=6',b'error=4'),
                             (b'rflags=65538',b'rflags=65539'),(b'frame=2457424',b'frame=268435456'),
                             (b'capability_generation=1',b'capability_generation=2'),
                             (b'denial_reason=Revoked',b'denial_reason=Busy'),
                             (b'charge_retained=1',b'charge_retained=0'),
                             (b'rax='+str(build.SEEDS[0]).encode(),b'rax=0')):
            with self.subTest(field=before),self.assertRaises(ValueError):parse_transcript(case,raw.replace(before,after),33,b'',binding)
        name='recursive_D_write';rip=binding['faults'][name]['rip']
        with self.assertRaises(ValueError):parse_transcript(case,raw.replace(str(rip).encode(),str(rip+1).encode()),33,b'',binding)

    def test_reuse_requires_same_frame_fresh_lease_zero_scrub_and_bound_whole_page_hash(self):
        case='writable_reuse';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case);raw=synthetic_trace(case,binding)
        digest=initialized_digest(build.SEEDS[1]).encode()
        for before,after in ((b'lease_generation=2',b'lease_generation=1'),(b'zero_before_payload=1',b'zero_before_payload=0'),
                             (digest,b'a'*64),(b'capability_domain=3',b'capability_domain=2'),
                             (b'allocated_pages=12',b'allocated_pages=13'),(b'owned_pages_after=0',b'owned_pages_after=1')):
            with self.subTest(field=before),self.assertRaises(ValueError):parse_transcript(case,raw.replace(before,after),33,b'',binding)
        lines=raw.splitlines();i=next(i for i,line in enumerate(lines) if b'event=reassigned ' in line)
        lines[i]=lines[i].replace(b'physical_frame=53248',b'physical_frame=57344')
        with self.assertRaises(ValueError):parse_transcript(case,b'\n'.join(lines)+b'\n',33,b'',binding)

    def test_order_missing_duplicate_and_extra_capture_events_reject(self):
        case='writable_reuse';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case);raw=synthetic_trace(case,binding);lines=raw.splitlines()
        index=next(i for i,line in enumerate(lines) if b'event=invalidate ' in line)
        swapped=lines[:];swapped[index],swapped[index+1]=swapped[index+1],swapped[index]
        variants=[b'\n'.join(swapped)+b'\n',b'\n'.join(lines[:index]+lines[index+1:])+b'\n',
                  b'TESSRYN_K01_ENTRY\n'+raw,raw+b'TESSRYN_K01_ENTRY\n',
                  raw.replace(b'sequence=4 ',b'sequence=3 '),raw.replace(b'nx_enabled=1',b'nx_enabled=0'),
                  raw.replace(b'event=scrubbed ',b'event=scrubbed synthetic=1 ')]
        for changed in variants:
            with self.subTest(raw=changed[:40]),self.assertRaises(ValueError):parse_transcript(case,changed,33,b'',binding)

    def test_protected_regions_and_retained_bounds_cannot_alias_or_reverse(self):
        case='recursive_revocation';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case);raw=synthetic_trace(case,binding)
        contract=0x100000+binding['descriptor']['efi_rva'];code=0x100000+binding['code']['efi_rva']
        root_before=f'domain=1 root={0x120000} pool_end={0x120000+17*4096}'.encode()
        variants=[raw.replace(root_before,f'domain=1 root={contract} pool_end={contract+17*4096}'.encode()),
                  raw.replace(b'protected_state='+str(0x1e0000).encode(),b'protected_state='+str(contract).encode()),
                  raw.replace(b'protected_state='+str(0x1e0000).encode(),b'protected_state='+str(code).encode()),
                  raw.replace(b'stack_end=0x330000',b'stack_end=0x300000'),
                  raw.replace(b'map_start=0x340000',b'map_start=0x340001'),
                  raw.replace(b'gop_end=0x80200000',b'gop_end=0x70000000')]
        for changed in variants:
            with self.subTest(raw=changed[:50]),self.assertRaises(ValueError):parse_transcript(case,changed,33,b'',binding)
    def test_actual_object_descriptor_and_all_probe_labels_bind_to_efi(self):
        obj,efi,raw=synthetic_pair();binding=build.matrix_binding(obj,efi,'recursive_revocation')
        self.assertEqual(binding['descriptor']['size_bytes'],184)
        self.assertEqual(binding['descriptor']['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(binding['descriptor']['case_id'],7)
        self.assertEqual(binding['faults']['nx_fetch']['rip'],0x100006000)
        self.assertEqual(len({row['rip'] for row in binding['faults'].values()}),16)
        self.assertEqual(binding['faults']['recursive_D_write']['error_code'],6)

    def test_wrong_case_magic_constants_and_descriptor_region_are_rejected(self):
        obj,efi,raw=synthetic_pair()
        with self.assertRaises(ValueError):build.matrix_binding(obj,efi,'writable_reuse')
        for changed in (raw.replace(build.MAGIC,b'BROKEN-CONTRACT!!'),raw[:32]+struct.pack('<Q',9)+raw[40:],raw[:-8]+struct.pack('<Q',1)):
            with self.subTest(descriptor=changed[:32]),self.assertRaises(ValueError):
                build.matrix_binding(obj.replace(raw,changed),efi.replace(raw,changed),'recursive_revocation')
        with self.assertRaises(ValueError):build.matrix_binding(obj,efi+raw,'recursive_revocation')

    def test_compiled_fault_opcode_and_cpl3_return_label_are_required(self):
        obj,efi,_=synthetic_pair();binding=build.matrix_binding(obj,efi,'recursive_revocation');offset=binding['code']['offsets']['k02_probe_recursive_B_read']
        bad=bytearray(obj);bad[100+offset]=0x90;bad_efi=bytearray(efi);bad_efi[0x200+offset]=0x90
        with self.assertRaisesRegex(ValueError,'opcodes'):build.matrix_binding(bytes(bad),bytes(bad_efi),'recursive_revocation')
        table=struct.unpack_from('<I',obj,8)[0];count=struct.unpack_from('<I',obj,12)[0];strings_at=table+count*18
        bad=bytearray(obj)
        for i in range(count):
            at=table+i*18;name_at=struct.unpack_from('<I',obj,at+4)[0];end=obj.index(b'\0',strings_at+name_at)
            if obj[strings_at+name_at:end]==b'k02_probe_request_trap':
                value=struct.unpack_from('<I',obj,at+8)[0];struct.pack_into('<I',bad,at+8,value+1);break
        with self.assertRaisesRegex(ValueError,'return label'):build.matrix_binding(bytes(bad),efi,'recursive_revocation')

    def test_generic_control_cannot_be_replaced_by_constant_or_nontrap_instruction(self):
        case='recursive_revocation';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
        for label in ('read','write','request'):
            bad=copy.deepcopy(binding);bad['code']['instruction_bytes']['k02_probe_'+label]='90'+bad['code']['instruction_bytes']['k02_probe_'+label][2:]
            with self.subTest(label=label),self.assertRaisesRegex(ValueError,'control opcode'):
                parse_transcript(case,synthetic_trace(case,bad),33,b'',bad)

    def test_descriptor_is_readonly_and_code_is_executable(self):
        obj,efi,_=synthetic_pair()
        for offset,flags in ((0x188+40+36,0xc0000040),(0x188+36,0x40000020)):
            bad=bytearray(efi);struct.pack_into('<I',bad,offset,flags)
            with self.assertRaises(ValueError):build.matrix_binding(obj,bytes(bad),'recursive_revocation')

    def test_matrix_subset_uses_declared_order_and_never_changes_case_flags(self):
        self.assertEqual(build.selected_cases(['writable_reuse','recursive_revocation']),('recursive_revocation','writable_reuse'))
        for names in (['writable_reuse','writable_reuse'],['own_page']):
            with self.assertRaises(ValueError):build.selected_cases(names)
        flags=build.case_flags('writable_reuse');self.assertIn('k02_matrix',flags);self.assertIn('k02_matrix_case="writable_reuse"',flags)

    def test_original_runner_artifact_boundary_requires_bound_pe_validation(self):
        _,efi,_=synthetic_pair()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'recursive_revocation').mkdir();(root/'recursive_revocation/BOOTX64.EFI').write_bytes(efi)
            row={'path':'recursive_revocation/BOOTX64.EFI','case':'recursive_revocation',
                 'sha256':hashlib.sha256(efi).hexdigest(),'size_bytes':len(efi),'pe_validation':inspect_pe(efi)}
            manifest={'artifacts':[row]}
            self.assertEqual(artifact_bytes(root/'manifest.json',manifest,'BOOTX64.EFI','recursive_revocation'),efi)
            del row['pe_validation']
            with self.assertRaises(ValueError):artifact_bytes(root/'manifest.json',manifest,'BOOTX64.EFI','recursive_revocation')

    def test_unknown_common_records_framing_and_handoff_reordering_reject(self):
        case='caller_forgery';obj,efi,_=synthetic_pair(case);binding=build.matrix_binding(obj,efi,case)
        raw=synthetic_trace(case,binding);lines=raw.splitlines()
        variants=[raw.replace(b'TESSRYN_K01_ENTRY',b'TESSRYN_K01_ENTRY synthetic=1'),
                  raw.replace(b'cr3=0x110000 rsp=0x32ff00 rip=0x101000 gdt=owned idt=owned tss=owned',b'fabricated=1')]
        for marker in (b'TESSRYN_K01_UNREGISTERED vector=255',b'TESSRYN_K01_EXCEPTION_BOGUS vector=255',b'TESSRYN_K02_UNREGISTERED bogus=1'):
            variants.append(raw.replace(b'TESSRYN_K02_PROFILE',marker+b'\nTESSRYN_K02_PROFILE'))
        live=lines.pop(1);lines.insert(len(lines)-1,live);variants.append(b'\n'.join(lines)+b'\n')
        for changed in variants:
            with self.subTest(change=changed[:60]),self.assertRaises(ValueError):parse_transcript(case,changed,33,b'',binding)

    def test_matrix_cpu_profile_excludes_extra_protection_modes_and_network(self):
        command=run.qemu_command();cpu=command[command.index('-cpu')+1]
        for item in ('pku=off','pks=off','sgx=off','cet-ss=off','cet-ibt=off','phys-bits=48'):self.assertIn(item,cpu)
        self.assertEqual(command[command.index('-smp')+1],'1');self.assertEqual(command[command.index('-nic')+1],'none')

    def test_capture_only_is_not_event_or_full_matrix_acceptance(self):
        obj,efi,_=synthetic_pair();binding=build.matrix_binding(obj,efi,'recursive_revocation')
        with self.assertRaises(ValueError):
            parse_transcript('recursive_revocation',b'TESSRYN_K02_MATRIX_PASS\n',33,b'',binding)
        with self.assertRaises(ValueError):
            parse_transcript('caller_forgery',b'TESSRYN_K02_MATRIX_PASS\n',33,b'',binding)

    def test_file_backed_runner_preserves_diagnostics_and_fails_closed_after_capture(self):
        # SYNTHETIC file inputs and explicit child boundary; no QEMU execution.
        obj,efi,_=synthetic_pair();case='recursive_revocation'
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);art=root/'artifacts';(art/case).mkdir(parents=True)
            rows=[]
            from tools.k01_media import make_disk
            for name,data in (('BOOTX64.EFI',efi),('kernel.obj',obj),('boot.img',make_disk(efi))):
                (art/case/name).write_bytes(data);rows.append({'path':case+'/'+name,'case':case,
                    'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data),
                    'pe_validation':inspect_pe(efi) if name=='BOOTX64.EFI' else None})
            qemu=root/'build/toolchain/bin/qemu-system-x86_64';qemu.parent.mkdir(parents=True);qemu.write_bytes(b'SYNTHETIC_TOOL')
            fw=root/'build/uefi/firmware';fw.mkdir(parents=True)
            setup={'verified_tools':{'qemu':{'sha256':hashlib.sha256(qemu.read_bytes()).hexdigest()}},'firmware':{}}
            for role in ('code','vars'):
                data=('SYNTHETIC_'+role).encode();(fw/(role+'.fd')).write_bytes(data)
                setup['firmware'][role]={'path':'firmware/'+role+'.fd','sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data)}
            manifest={'schema_version':1,'qualification':'not_established','artifact_type':build.ARTIFACT_TYPE,'profile':build.PROFILE,'scope':build.SCOPE,
                      'cases':[case],'toolchain':{'setup':setup},'artifacts':rows,
                      'bindings':{case:build.matrix_binding(obj,efi,case)}}
            mp=art/'manifest.json';mp.write_text(json.dumps(manifest));raw=b'SYNTHETIC_UNACCEPTED_GUEST_TRACE\n'
            child=SimpleNamespace(status='completed',reason='synthetic child boundary',stdout=raw,
                                  stderr=b'SYNTHETIC_DIAGNOSTIC\n',returncode=33,elapsed_seconds=0.01)
            with patch.object(run,'ROOT',root),patch.object(run,'verify_installation',return_value=setup),patch.object(run,'evaluator_hash',return_value='a'*64),patch.object(run,'run_bounded',return_value=child) as dispatch:
                diagnostic=run.run(mp,root/'capture',case,capture_only=True)
                self.assertEqual(diagnostic['status'],'captured');self.assertEqual(diagnostic['qualification'],'not_established')
                self.assertIsNone(diagnostic['observations']);self.assertEqual((root/'capture/stdout.log').read_bytes(),raw)
                admitted=run.run(mp,root/'acceptance',case)
                self.assertEqual(admitted['status'],'fail');self.assertIn('missing or duplicate',admitted['reason'])
                self.assertEqual((root/'acceptance/stdout.log').read_bytes(),raw)
                self.assertEqual((root/'acceptance/stderr.log').read_bytes(),child.stderr)
                for call in dispatch.call_args_list:
                    argv,workdir,timeout,limit=call.args
                    self.assertEqual(argv[0],'/usr/bin/env');self.assertEqual(argv[1],'TMPDIR='+str(workdir))
                    self.assertEqual(argv[2],str(qemu));self.assertLessEqual(timeout,60);self.assertLessEqual(limit,1_048_576)
            with patch.object(run,'ROOT',root),patch.object(run,'verify_installation',return_value=setup),patch.object(run,'evaluator_hash',side_effect=['a'*64,'b'*64]),patch.object(run,'run_bounded',return_value=child):
                changed=run.run(mp,root/'evaluator-changed',case,capture_only=True)
                self.assertEqual(changed['status'],'fail');self.assertIsNone(changed['observations'])
                self.assertEqual(changed['execution']['returncode'],33)
                self.assertEqual(changed['execution']['elapsed_seconds'],child.elapsed_seconds)
                self.assertEqual((root/'evaluator-changed/stdout.log').read_bytes(),raw)
            with patch.object(run,'evaluator_hash',side_effect=ValueError('SYNTHETIC evaluator failure')),patch.object(run,'run_bounded') as dispatch:
                failed=run.run(mp,root/'initial-evaluator-failed',case)
                self.assertEqual(failed['status'],'fail');self.assertIsNone(failed['evaluator_sha256']);dispatch.assert_not_called()
                self.assertTrue((root/'initial-evaluator-failed/result.json').is_file())


if __name__=='__main__':unittest.main()
