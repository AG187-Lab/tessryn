#!/usr/bin/env python3
"""Verify independently bound matrix artifacts and original guest observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.build_k02_matrix import ARTIFACT_TYPE,CASES,PROFILE,SCOPE,REQUEST_ROWS,case_flags,matrix_binding,selected_cases
from tools.build_fixture import sha256
from tools.g03.evidence import _regular_bytes,parse_json
from tools.k01_media import make_disk
from tools.run_kernel import artifact_bytes
from tools.run_k02_matrix import FORMAT,PASS_REASON,evaluator_hash,qemu_command
from tools.k02_matrix_provenance import validate_source,validate_toolchain


def require(value,reason):
    if not value:raise ValueError(reason)


def validate_build(path:Path):
    raw=_regular_bytes(path);require(len(raw)<=2<<20,'matrix manifest exceeds bound');m=parse_json(raw)
    require(m['schema_version']==1 and m['artifact_type']==ARTIFACT_TYPE and m['profile']==PROFILE and m['scope']==SCOPE and m['qualification']=='not_established','matrix build scope/profile differs')
    selected=selected_cases(m['cases']);require(list(selected)==m['cases'] and type(m['matrix_complete']) is bool and m['matrix_complete']==(selected==CASES),'matrix subset/order differs')
    expected={'libtessryn_owned_memory.rlib'}|{case+'/'+name for case in selected for name in ('BOOTX64.EFI','boot.img','kernel.obj')}
    require(len(m['artifacts'])==len(expected) and {r['path'] for r in m['artifacts']}==expected,'matrix artifact allowlist differs')
    for row in m['artifacts']:
        p=Path(row['path']);require(not p.is_absolute() and '..' not in p.parts,'matrix artifact path invalid')
        data=_regular_bytes(path.parent/p);require(len(data)==row['size_bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'matrix artifact bytes differ')
    library=next(r for r in m['artifacts'] if r['path']=='libtessryn_owned_memory.rlib')
    require(library['target']==PROFILE['target'] and library['crate']=='tessryn_owned_memory','matrix core target differs')
    require(set(m['compile_commands'])=={'core',*selected},'matrix compile command set differs')
    for case,command in m['compile_commands'].items():
        require(type(command) is list and all(type(arg) is str for arg in command) and '--target=x86_64-unknown-uefi' in command and not any('x86_64-unknown-none' in arg for arg in command),'matrix target retargeted')
        if case=='core':require(command[0]=='kernel-core/lib.rs' and '--crate-type=rlib' in command and '--crate-name=tessryn_owned_memory' in command,'matrix ownership core compilation differs')
        else:
            i=command.index('--cfg');require(command[0]=='kernel/main.rs' and command[i:i+8]==case_flags(case) and '--crate-type=bin' in command and '--extern' in command and 'tessryn_owned_memory=k02-matrix-build/libtessryn_owned_memory.rlib' in command,'matrix case flags/core linkage differ')
    require(set(m['bindings'])==set(selected),'matrix binding set differs')
    for case in selected:
        efi=artifact_bytes(path,m,'BOOTX64.EFI',case);obj=artifact_bytes(path,m,'kernel.obj',case)
        require(make_disk(efi)==artifact_bytes(path,m,'boot.img',case) and matrix_binding(obj,efi,case)==m['bindings'][case],'matrix original probe/contract/media binding differs')
    require(m['protocol_sources_sha256']=={name:sha256(ROOT/name) for name in ('planning/k02-native-cases.json','tools/k02_native_protocol.py')},'matrix reviewed protocol differs')
    files=m['source_files'];require(type(files) is dict and all(not Path(name).is_absolute() and '..' not in Path(name).parts for name in files),'matrix source paths differ')
    require(hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()==m['source_files_sha256'],'matrix dependency map hash differs')
    require(all(name in files for name in ('kernel-core/lib.rs','kernel/main.rs','kernel/entry.S','kernel/k02_matrix.rs','kernel/k02_entry.S')),'matrix real source dependencies missing')
    expected_notices={'notices/'+name for name in ('tessryn-LICENSE','tessryn-NOTICE','rust-LICENSE-APACHE','rust-LICENSE-MIT','rust-COPYRIGHT')}
    require(len(m['notices'])==5 and {r['path'] for r in m['notices']}==expected_notices,'matrix notice allowlist differs')
    for row in m['notices']:
        data=_regular_bytes(path.parent/row['path']);require(len(data)==row['size_bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'matrix notice bytes differ')
    return m


def fields(line,marker):
    require(line.startswith(marker+' '),'matrix marker framing differs')
    result={}
    for token in line[len(marker)+1:].split():
        require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*=[A-Za-z0-9_:.+-]+',token) is not None,'matrix fields malformed')
        key,value=token.split('=',1);require(key not in result,'duplicate matrix field');result[key]=value
    return result


def number(text):
    require(type(text) is str and re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)',text) is not None,'matrix integer malformed')
    value=int(text,16 if text.startswith('0x') else 10);require(0<=value<1<<64,'matrix integer exceeds u64');return value


def same(row,expected):
    require(set(row)==set(expected),'matrix event field set differs')
    for key,value in expected.items():
        actual=number(row[key]) if type(value) is int else row[key]
        require(actual==value,'matrix event '+key+' differs')


def initialized_digest(seed):
    return hashlib.sha256(b''.join(struct.pack('<Q',seed^index) for index in range(512))).hexdigest()


def reset_fp_digest(mask):
    data=bytearray(512);struct.pack_into('<H',data,0,0x37f)
    struct.pack_into('<II',data,24,0x1f80,mask)
    return hashlib.sha256(data).hexdigest()


def bound_context(manifest_path,manifest,case):
    """Add an expected loaded PE-header digest from retained original bytes."""
    context=dict(manifest['bindings'][case])
    efi=artifact_bytes(manifest_path,manifest,'BOOTX64.EFI',case)
    pe=struct.unpack_from('<I',efi,60)[0]
    headers=struct.unpack_from('<I',efi,pe+24+60)[0]
    require(0<headers<=4096 and headers<=len(efi),'matrix PE header extent unsupported')
    context['supervisor_kernel_header_hex']=efi[:headers].hex()
    context['supervisor_kernel_imagebase_offset']=pe+48
    return context


def parse_transcript(case,data,returncode,stderr,binding):
    require(case in CASES,'matrix case not admitted')
    require(type(returncode) is int and returncode==33 and len(data)<=1_048_576 and b'triple fault' not in stderr.lower(),'matrix guest exit/output bound differs')
    try:lines=[line.strip() for line in data.decode('ascii').splitlines() if line.strip()]
    except UnicodeError as error:raise ValueError('matrix serial output is not ASCII') from error
    require(not any('FAIL' in line or 'PANIC' in line or 'UNEXPECTED' in line for line in lines),'kernel failure observed')
    common_names={'ENTRY','FRAMEBUFFER','LIVE_RANGES','PAGING_READY','RESET_POINTER','MEMORY_MAP_VALID','EXIT_BOOT_SERVICES_OK','CPU_OWNED','EXCEPTION'}
    matrix_names={'CPU','ROOT','INVENTORY','EVENT','USER_ENTER','TRAP','CASE_COMPLETE','ACCOUNTING','PASS'}
    allowed={'TESSRYN_K01_'+name for name in common_names}|{'TESSRYN_K02_MATRIX_'+name for name in matrix_names}|{'TESSRYN_K02_PROFILE'}
    require(all(line.split(' ',1)[0] in allowed for line in lines if line.startswith('TESSRYN_')),'unknown Tessryn hardware record')
    for name in common_names-{'EXCEPTION'}:
        require(sum(line.split(' ',1)[0]=='TESSRYN_K01_'+name for line in lines)<=1,'duplicate common hardware record')
    def only(marker):
        values=[line for line in lines if line==marker or line.startswith(marker+' ')]
        require(len(values)==1,'matrix handoff marker missing or duplicate');return values[0]
    entry=only('TESSRYN_K01_ENTRY');ebs=only('TESSRYN_K01_EXIT_BOOT_SERVICES_OK');cpu=only('TESSRYN_K01_CPU_OWNED')
    require(entry=='TESSRYN_K01_ENTRY' and ebs=='TESSRYN_K01_EXIT_BOOT_SERVICES_OK','common handoff marker framing differs')
    live_line=only('TESSRYN_K01_LIVE_RANGES');live=fields(live_line,'TESSRYN_K01_LIVE_RANGES')
    require(set(live)=={'image_start','image_end','stack_start','stack_end','map_start','map_end','scratch','runtime_high','gop_start','gop_end'},'matrix live range fields differ')
    image_start,image_end=number(live['image_start']),number(live['image_end'])
    require(0<image_start<image_end<=1<<47 and image_start%4096==image_end%4096==0,'matrix image range invalid')
    retained=[(image_start,image_end)]
    for start,end in (('stack_start','stack_end'),('map_start','map_end')):
        lo,hi=number(live[start]),number(live[end])
        require(0<lo<hi<=1<<47 and lo%4096==hi%4096==0,'matrix retained allocation bounds invalid')
        require(all(not(lo<b and a<hi) for a,b in retained),'matrix live allocations overlap');retained.append((lo,hi))
    scratch=number(live['scratch']);require(4096<=scratch<=(1<<48)-4096 and scratch%4096==0 and all(not(scratch<b and a<scratch+4096) for a,b in retained),'matrix scratch reservation invalid')
    gop_lo,gop_hi=number(live['gop_start']),number(live['gop_end'])
    require((gop_lo==gop_hi==0) or (0<gop_lo<gop_hi<=1<<47 and gop_lo%4096==0),'matrix GOP reservation bounds invalid')
    owned=fields(cpu,'TESSRYN_K01_CPU_OWNED')
    require(set(owned)=={'cr3','rsp','rip','gdt','idt','tss'} and owned['gdt']==owned['idt']==owned['tss']=='owned','actual CPU ownership fields differ')
    require(number(owned['cr3'])%4096==0 and image_start<=number(owned['cr3'])<image_end
            and image_start<=number(owned['rip'])<image_end
            and number(live['stack_start'])<=number(owned['rsp'])<number(live['stack_end']),'actual CPU root/stack/instruction ownership differs')
    require(lines.index(entry)<lines.index(live_line)<lines.index(ebs)<lines.index(cpu),'firmware/CPU ownership order differs')
    profile_line=only('TESSRYN_K02_PROFILE');profile=fields(profile_line,'TESSRYN_K02_PROFILE')
    expected_profile={'physical_bits':48,'cpu_count':1,'paging_levels':4,'nx_supported':1,'nx_enabled':1,
                      'pcid_enabled':0,'global_translations':0,'la57_enabled':0}
    require(set(profile)==set(expected_profile)|{'cr4','efer_low'},'matrix CPU profile fields differ')
    for key,value in expected_profile.items():require(number(profile[key])==value,'matrix CPU profile differs')
    cr4=number(profile['cr4']);require(cr4&((1<<7)|(1<<12)|(1<<17)|(1<<22)|(1<<23)|(1<<24))==0 and number(profile['efer_low'])&(1<<11),'matrix protection controls differ')
    require(lines.index(cpu)<lines.index(profile_line),'matrix precedes owned CPU')
    code=binding['code'];descriptor=binding['descriptor'];addresses=descriptor['addresses'];seeds=descriptor['seeds']
    for label,opcode in (('read','488b07cd80'),('write','488937cd80'),('request','cd80')):
        require(code['instruction_bytes']['k02_probe_'+label].startswith(opcode),'matrix compiled control opcode differs')
    require(descriptor['case_id']==CASES.index(case) and descriptor['domains']==dict(zip('ABCD',(1,2,3,4))),'compiled matrix case/domain binding differs')
    code_physical=image_start+code['efi_rva'];contract_physical=image_start+descriptor['efi_rva']
    require(image_start<=code_physical and code_physical+4096<=image_end and image_start<=contract_physical and contract_physical+184<=image_end,'compiled code/contract exceeds loaded image')
    rows=[(line.split(' ',1)[0].removeprefix('TESSRYN_K02_MATRIX_'),fields(line,line.split(' ',1)[0])) for line in lines if line.startswith('TESSRYN_K02_MATRIX_')]
    row_positions=[i for i,line in enumerate(lines) if line.startswith('TESSRYN_K02_MATRIX_')]
    require(bool(rows) and lines.index(profile_line)<next(i for i,l in enumerate(lines) if l.startswith('TESSRYN_K02_MATRIX_')),'matrix metadata precedes CPU profile')
    cursor=0;sequence=0;observed_events=[];observed_probes=[]
    def take(kind):
        nonlocal cursor
        require(cursor<len(rows) and rows[cursor][0]==kind,'matrix ordered '+kind+' record missing')
        row=rows[cursor][1];cursor+=1;return row
    state=take('CPU');mask=number(state.get('fxsave_mxcsr_mask','invalid'))
    require(0<mask<1<<32 and mask&0x1f80==0x1f80,'matrix legacy FP mask invalid')
    same(state,{'cr0':number(state.get('cr0','invalid')),'wp_enabled':1,'pke_enabled':0,'pks_enabled':0,'cet_enabled':0,'sgx_supported':0,'osxsave_enabled':0,'fxsave_mxcsr_mask':mask})
    require(cr4&(1<<18)==0,'matrix extended CPU state is not admitted')
    require(number(state['cr0'])&(1<<16),'actual write protection is disabled')
    roots={};pools=[]
    for domain in range(1,5):
        row=take('ROOT');require(set(row)=={'domain','root','pool_end'} and number(row['domain'])==domain,'matrix domain root metadata differs')
        lo,hi=number(row['root']),number(row['pool_end'])
        require(lo%4096==hi%4096==0 and image_start<=lo<hi<=image_end and hi-lo==17*4096,'matrix domain pool not image-owned')
        require(all(not(lo<end and start<hi) for start,end in pools),'matrix root pools overlap')
        require(not(lo<code_physical+4096 and code_physical<hi),'matrix root pool overlaps trusted probe code')
        require(not(lo<contract_physical+184 and contract_physical<hi),'matrix root pool overlaps immutable contract')
        pools.append((lo,hi));roots[domain]=lo
    inventory=take('INVENTORY')
    require(set(inventory)=={'case','descriptors','available_pages','protected_state','baseline_pages','source'}
            and inventory['case']==case and inventory['source']=='final_successful_handoff'
            and number(inventory['descriptors'])>0 and number(inventory['available_pages'])>=13
            and number(inventory['baseline_pages'])==12,'matrix admitted inventory differs')
    policy=number(inventory['protected_state']);require(policy%4096==0 and image_start<=policy and policy+24576<=image_end and all(not(policy<hi and lo<policy+24576) for lo,hi in pools),'matrix policy storage is not separately protected')
    require(not(policy<code_physical+4096 and code_physical<policy+24576) and not(policy<contract_physical+184 and contract_physical<policy+24576),'matrix policy overlaps trusted code or immutable contract')
    def event(name,expected):
        nonlocal sequence
        row=take('EVENT');same(row,{'sequence':sequence,'event':name,**expected});sequence+=1;observed_events.append(row);return row
    def peek_event(name):
        require(cursor<len(rows) and rows[cursor][0]=='EVENT' and rows[cursor][1].get('event')==name,'matrix ordered '+name+' event missing');return rows[cursor][1]
    def capability(prefix,domain,generation=1):return {prefix+'_slot':3,prefix+'_generation':generation,prefix+'_domain':domain}
    def lease_values(row):
        slot,generation=number(row['lease_slot']),number(row['lease_generation'])
        require(12<=slot<32 and 1<=generation<1<<32,'matrix target lease identity invalid');return {'lease_slot':slot,'lease_generation':generation}
    def frame_valid(pa):
        require(4096<=pa<=(1<<32)-4096 and pa%4096==0,'matrix admitted target frame invalid')
        for start,end in (('image_start','image_end'),('stack_start','stack_end'),('map_start','map_end'),('gop_start','gop_end')):
            lo,hi=number(live[start])&~4095,(number(live[end])+4095)&~4095
            require(not(pa<hi and lo<pa+4096),'matrix target overlaps a live reserved range')
        scratch=number(live['scratch']);require(not(pa<scratch+4096 and scratch<pa+4096),'matrix target overlaps retained scratch')
    def common(domain,va,lease,pa):return {'domain':domain,'root':roots[domain],'page':va,'physical_frame':pa,**lease,'charge_retained':1}
    def install(domain,va,pa,writable,reused=None):
        row=peek_event('mapping_installed');lease=lease_values(row)
        if reused is None:require(lease['lease_generation']==1,'fresh matrix target lease generation differs')
        else:require(lease=={'lease_slot':reused['lease_slot'],'lease_generation':reused['lease_generation']+1},'replacement lease did not advance same slot')
        event('mapping_installed',{**common(domain,va,lease,pa),'length':4096,'readable':1,'writable':int(writable),'executable':0});return lease
    def probe(name,domain,va,kind,value=None):
        entry_cursor=cursor
        entered=take('USER_ENTER');trap=take('TRAP')
        controls=('read','write','request','boundary_snapshot')
        instruction=addresses['code']+code['offsets']['k02_probe_'+kind] if kind in controls else binding['faults'][name]['rip']
        suffix='_trap' if kind=='request' else '_return'
        rip=addresses['code']+code['offsets']['k02_probe_'+kind+suffix] if kind in controls else instruction
        ts,te=number(entered['trap_start']),number(entered['trap_end'])
        require(image_start<=ts<te<=image_end and te-ts==32768,'matrix trap stack is not image-owned')
        require(all(not(ts<end and start<te) for start,end in [*pools,(policy,policy+24576),(code_physical,code_physical+4096),(contract_physical,contract_physical+184)]),'matrix trap stack aliases protected state')
        if observed_probes:
            previous=observed_probes[0]['enter']
            require((ts,te)==(number(previous['trap_start']),number(previous['trap_end'])),'matrix dedicated trap stack changed between probes')
        same(entered,{'probe':name,'domain':domain,'root':roots[domain],'instruction':instruction,'probe_rip':rip,'target':va,
                      'stack_start':addresses['stack'],'stack_end':addresses['stack']+4096,'trap_start':ts,'trap_end':te,'code_physical':code_physical})
        fault=kind=='fault';error=binding['faults'][name]['error_code'] if fault else 0
        require(set(trap)=={'probe','domain','root','vector','error','rip','cs','ss','rflags','rsp','cr2','frame','rax'},'matrix trap fields differ')
        frame,flags=number(trap['frame']),number(trap['rflags'])
        require(ts<=frame and frame+176<=te and flags&((3<<12)|(1<<9)|(1<<10)|(1<<14)|(1<<17))==0,'matrix trap frame/flags invalid')
        require(flags==(0x10002 if fault else 2),'matrix saved user flags differ from declared transition')
        same(trap,{'probe':name,'domain':domain,'root':roots[domain],'vector':14 if fault else 128,'error':error,'rip':rip,'cs':0x33,'ss':0x2b,
                   'rflags':flags,'rsp':addresses['stack']+4096-16,'cr2':va if fault else number(trap['cr2']),'frame':frame,'rax':number(trap['rax'])})
        if value is not None:require(number(trap['rax'])==value,'matrix user read/control value differs')
        # The independent common exception record must carry the same saved
        # hardware frame, immediately between user entry and matrix trap.
        at=row_positions[entry_cursor];require(at+2<len(lines) and lines[at+1].startswith('TESSRYN_K01_EXCEPTION ') and lines[at+2].startswith('TESSRYN_K02_MATRIX_TRAP '),'matrix raw exception frame missing or reordered')
        exception=fields(lines[at+1],'TESSRYN_K01_EXCEPTION');same(exception,{k:number(trap[k]) for k in ('vector','error','rip','cs','rflags','rsp','cr2')})
        observed_probes.append({'enter':entered,'trap':trap})
        if fault:event('page_fault',{'probe':name,'domain':domain,'root':roots[domain],'vector':14,'cs':0x33,'rip':rip,'cr2':va,'error_code':error,'recovered':1})
    def primed(domain,va,lease,pa,writable):
        if writable:probe('prime_write',domain,va,'write');probe('prime_read',domain,va,'read',seeds['write'])
        else:probe('prime_read',domain,va,'read',seeds['victim'])
        event('mapping_primed',{**common(domain,va,lease,pa),'read_executed':1,'write_executed':int(writable)})
    def teardown(domain,va,lease,pa):
        metadata=common(domain,va,lease,pa)
        event('fence',metadata);event('clear_pte',metadata);event('invalidate',{**metadata,'method':'cr3_reload'});event('quiesce',{**metadata,'trusted':1})
    request_pages={}
    def request(recipe,domain=2,claim=2,submitted=None):
        require(binding['requests']['rows']==[list(row) for row in REQUEST_ROWS],'matrix immutable request recipes differ')
        probe('request',domain,addresses['request'],'request')
        row=peek_event('request_observed');physical=number(row['physical_frame']);frame_valid(physical)
        require(physical!=pa and (domain not in request_pages or request_pages[domain]==physical),'matrix request aliases target or changed backing')
        require(all(other==domain or backing!=physical for other,backing in request_pages.items()),'matrix domain request pages alias')
        request_pages[domain]=physical
        words=list(REQUEST_ROWS[recipe])
        if submitted is not None:words[6]=submitted['lease_slot']|(submitted['lease_generation']<<32)
        event('request_observed',{'recipe':recipe,'caller':domain,'claimed_caller':claim,'pointer':addresses['request'],
              'physical_frame':physical,**{'word'+str(i):word for i,word in enumerate(words)}})
    def denied(recipe,operation,reason,handle_domain=2,slot=3,generation=1,claim=2,submitted=None,phase=None,extra=None):
        request(recipe,claim=claim,submitted=submitted)
        expected={'caller':2,'claimed_caller':claim,'operation':operation,'origin':'CPL3','cs':0x33,
                  'capability_slot':slot,'capability_generation':generation,'capability_domain':handle_domain,
                  'pte_published':0,'charge_released':0,'denial_reason':reason}
        if submitted is not None:expected.update({'submitted_lease_slot':submitted['lease_slot'],'submitted_lease_generation':submitted['lease_generation']})
        if phase is not None:expected.update(lease_phase=phase,pte_installed=1)
        if extra:expected.update(extra)
        event('dispatch_denied',expected)
    probe('boundary_snapshot',2,addresses['request'],'boundary_snapshot',0)
    boundary=peek_event('boundary_sanitized');request_frame=number(boundary['physical_frame']);frame_valid(request_frame)
    request_pages[2]=request_frame
    event('boundary_sanitized',{'domain':2,'root':roots[2],'page':addresses['request'],'physical_frame':request_frame,
          'length':640,'gpr_words':16,'gpr_zeroed':1,'fp_bytes':512,'fcw':0x37f,'mxcsr':0x1f80,
          'mxcsr_mask':mask,'fp_sha256':reset_fp_digest(mask),'osxsave_enabled':0,'kernel_fp_restored':1})
    event('fresh_boot',{'case':case,'reset':'original_kernel_entry','untrusted_state_retained':0})
    pa=None
    if case!='kernel_isolation':
        owner=2 if case in ('writable_reuse','stale_identities') else 1
        first=peek_event('backing_owned');pa=number(first['physical_frame']);frame_valid(pa)
        require(pa!=request_frame,'matrix target aliases boundary request backing')
        event('backing_owned',{**capability('capability',owner),'physical_frame':pa,'length':4096,'charge_owner':owner,'committed_pages':1,'reserved_pages':0,'charged_pages':1,'domain_charged_pages':4,'baseline_pages':3})
    if case=='caller_forgery':
        denied(0,'map','InvalidAuthority',handle_domain=1,claim=1)
        event('owner_retained',capability('capability',1))
    elif case in ('trusted_operation_forgery','exact_bounds'):
        event('delegated',{**capability('parent',1),**capability('child',2),'offset':0,'length':4096,'rights':5})
        active=install(2,addresses['readonly'],pa,False)
        if case=='trusted_operation_forgery':
            for recipe,operation in ((1,'fence'),(2,'quiesce'),(3,'allocator_admin'),(4,'complete_lease'),(5,'activate_reserved')):
                denied(recipe,operation,'untrusted_origin',submitted=active)
            metadata=common(2,addresses['readonly'],active,pa)
            event('fence',metadata);event('trusted_fence_state',{**metadata,'trusted':1,'phase':'fenced','pte_installed':1})
            denied(2,'quiesce','untrusted_origin',submitted=active,phase='fenced')
            event('mapping_owner_retained',{**metadata,'phase':'fenced','pte_installed':1})
            event('owner_retained',{**capability('capability',1),'charge_retained':1})
            event('clear_pte',metadata);event('invalidate',{**metadata,'method':'cr3_reload'});event('quiesce',{**metadata,'trusted':1})
        else:
            probe('guard_read',2,addresses['guard'],'fault')
            event('delegated',{**capability('parent',1),'child_slot':4,'child_generation':1,'child_domain':2,'offset':1,'length':4094,'rights':5})
            extra={'capability_offset':1,'capability_length':4094,'offset':0}
            denied(6,'map_byte_slice','Alignment',slot=4,extra={**extra,'length':4094})
            denied(7,'map_byte_slice','Bounds',slot=4,extra={**extra,'length':4096})
            teardown(2,addresses['readonly'],active,pa)
            event('lease_released',{**active,'physical_frame':pa,'charge_retained':1})
            event('delegated',{**capability('parent',1),'child_slot':5,'child_generation':1,'child_domain':2,'offset':0,'length':4096,'rights':6})
            denied(8,'map_without_read','InsufficientRights',slot=5,extra={'rights':6})
    elif case=='recursive_revocation':
        event('delegated',{**capability('parent',1),**capability('child',2),'offset':0,'length':4096,'rights':21})
        event('delegated',{**capability('parent',2),**capability('child',4),'offset':0,'length':4096,'rights':5})
        b=install(2,addresses['revoked_B'],pa,False);primed(2,addresses['revoked_B'],b,pa,False)
        d=install(4,addresses['revoked_D'],pa,False);require(b['lease_slot']!=d['lease_slot'],'recursive descendant leases alias');primed(4,addresses['revoked_D'],d,pa,False)
        event('descendants_revoked',{**capability('root_capability',1),**capability('descendant_B',2),**capability('descendant_D',4),'charge_retained':1})
        for domain,va,lease in ((2,addresses['revoked_B'],b),(4,addresses['revoked_D'],d)):
            request(11 if domain==2 else 12,domain,domain)
            metadata={'domain':domain,**capability('capability',domain),**lease,'denial_reason':'Revoked','charge_retained':1}
            event('revoked_request_denied',{**metadata,'operation':'map','origin':'CPL3','cs':0x33,'caller':domain,'claimed_caller':domain})
            event('revoked_request_denied',{**metadata,'operation':'complete_lease','origin':'trusted_backend','trusted':1})
            teardown(domain,va,lease,pa)
        event('mapping_leases_released',{'B_slot':b['lease_slot'],'B_generation':b['lease_generation'],'D_slot':d['lease_slot'],'D_generation':d['lease_generation'],'charge_retained':1})
        for name in ('recursive_B_read','recursive_B_write','recursive_D_read','recursive_D_write'):
            spec=binding['faults'][name];domain=2 if spec['domain']=='B' else 4;probe(name,domain,addresses[spec['page']],'fault')
        event('capabilities_released',{**capability('D',4),**capability('B',2),**capability('A',1),'charge_released':1})
    elif case in ('writable_reuse','stale_identities'):
        b=install(2,addresses['reuse_B'],pa,True);primed(2,addresses['reuse_B'],b,pa,True)
        event('revoked',{**capability('capability',2),'physical_frame':pa,'charge_retained':1});teardown(2,addresses['reuse_B'],b,pa)
        event('lease_released',{**b,'physical_frame':pa,'charge_retained':1});event('capability_released',{**capability('capability',2),'physical_frame':pa,'charge_released':1})
        digest=initialized_digest(seeds['C'])
        if case=='stale_identities':event('retired_generation',{**capability('capability',2),**b,'released':1})
        event('scrubbed',{'physical_frame':pa,'length':4096,'trusted':1,'zero_before_payload':1})
        if case=='writable_reuse':
            c=install(3,addresses['reuse_C'],pa,False,b);probe('new_owner_read',3,addresses['reuse_C'],'read',seeds['C'])
            event('reassigned',{'physical_frame':pa,**capability('capability',3),'domain':3,'root':roots[3],'page':addresses['reuse_C'],'initial_sha256':digest})
            for name in ('reuse_B_read','reuse_B_write'):probe(name,2,addresses['reuse_B'],'fault')
            event('sentinel_unchanged',{'page':addresses['reuse_C'],'before_sha256':digest,'after_sha256':digest});teardown(3,addresses['reuse_C'],c,pa)
        else:
            event('backing_owned',{**capability('capability',3),'physical_frame':pa,'length':4096,'charge_owner':3,'committed_pages':1,'reserved_pages':0,'charged_pages':1,'domain_charged_pages':4,'baseline_pages':3})
            event('delegated',{**capability('parent',3),**capability('child',2,2),'offset':0,'length':4096,'rights':5})
            replacement=install(2,addresses['reuse_B'],pa,False,b)
            event('victim_initialized',{**capability('capability',3),'domain':3,'root':roots[3],'physical_frame':pa,'page':addresses['reuse_C'],'length':4096,'initial_sha256':digest})
            denied(9,'release_stale_capability','StaleHandle')
            event('backend_stale_lease_denied',{'operation':'fence','origin':'trusted_backend','trusted':1,
                  'submitted_lease_slot':b['lease_slot'],'submitted_lease_generation':b['lease_generation'],
                  'replacement_lease_slot':replacement['lease_slot'],'replacement_lease_generation':replacement['lease_generation'],
                  'denial_reason':'StaleLease','replacement_phase':'active','pte_installed':1,'charge_released':0})
            metadata=common(2,addresses['reuse_B'],replacement,pa)
            event('replacement_retained',{**capability('capability',2,2),**metadata,'phase':'active','pte_installed':1})
            request(10);probe('replacement_read',2,addresses['reuse_B'],'read',seeds['C'])
            event('replacement_read_authorized',{'caller':2,**capability('capability',2,2),'offset':0,'length':4096,'physical_frame':pa})
            event('fence',metadata);event('trusted_fence_state',{**metadata,'trusted':1,'phase':'fenced','pte_installed':1})
            event('sentinel_unchanged',{'page':addresses['reuse_C'],'before_sha256':digest,'after_sha256':digest})
            event('clear_pte',metadata);event('invalidate',{**metadata,'method':'cr3_reload'});event('quiesce',{**metadata,'trusted':1})
    elif case in ('unauthorized_read','read_only_sharing','data_nx'):
        if case!='unauthorized_read':event('delegated',{**capability('parent',1),**capability('child',2),'offset':0,'length':4096,'rights':5})
        domain=1 if case=='unauthorized_read' else 2
        va=addresses[{'unauthorized_read':'unauthorized','read_only_sharing':'readonly','data_nx':'data_nx'}[case]]
        lease=install(domain,va,pa,False)
        name='nx_data_read' if case=='data_nx' else 'protection_read'
        probe(name,domain,va,'read',seeds['victim']);digest=initialized_digest(seeds['victim'])
        if case=='data_nx':event('nx_confirmed',{'supported':1,'enabled':1})
        else:event('read_observed',{'domain':domain,'page':va,'sha256':digest})
        fault_name={'unauthorized_read':'unauthorized_read','read_only_sharing':'readonly_write','data_nx':'nx_fetch'}[case]
        probe(fault_name,2,va,'fault')
        if case=='read_only_sharing':event('sentinel_unchanged',{'page':va,'before_sha256':digest,'after_sha256':digest})
        teardown(domain,va,lease,pa)
    elif case=='kernel_isolation':
        probe('supervisor_prime',2,addresses['own'],'read',seeds['victim']^2)
        header=bytearray.fromhex(binding['supervisor_kernel_header_hex']);offset=binding['supervisor_kernel_imagebase_offset']
        require(type(offset) is int and 0<=offset<=len(header)-8 and 0<len(header)<=4096,'matrix original PE header binding differs')
        # EDK2 updates the PE OptionalHeader.ImageBase when it relocates the
        # original image. Predict exactly that field from the actual handoff;
        # every remaining retained header byte must still match the artifact.
        struct.pack_into('<Q',header,offset,image_start)
        kernel_digest=hashlib.sha256(header+b'\0'*(4096-len(header))).hexdigest()
        pages={'kernel':image_start,'policy':policy,'page_table':roots[2]}
        require(len(set(pages.values()))==3,'matrix supervisor targets alias')
        for role,va in pages.items():
            probe(role+'_read',2,va,'fault');probe(role+'_write',2,va,'fault')
            row=peek_event('sentinel_unchanged');before=row.get('before_sha256','')
            require(re.fullmatch(r'[0-9a-f]{64}',before) is not None,'matrix actual supervisor digest malformed')
            if role=='kernel':require(before==kernel_digest,'matrix loaded PE-header bytes differ from original artifact')
            event('sentinel_unchanged',{'page':va,'before_sha256':before,'after_sha256':before})
    complete=take('CASE_COMPLETE');same(complete,{'case':case,'allocated_pages':12})
    accounting=[]
    for domain in range(1,5):
        row=take('ACCOUNTING');same(row,{'domain':domain,'charged_pages':0,'committed_pages':0,'reserved_pages':0});accounting.append(row)
    final=take('PASS');same(final,{'case':case,'owned_pages_after':0,'scope':'single_cpu_emulated_matrix_case'})
    require(cursor==len(rows) and lines[-1].startswith('TESSRYN_K02_MATRIX_PASS ') and sum(line.startswith('TESSRYN_K01_EXCEPTION ') for line in lines)==len(observed_probes),'matrix trailing/duplicate hardware evidence')
    return {'profile':profile,'cpu':state,'roots':{str(k):v for k,v in roots.items()},'inventory':inventory,'target_frame':pa,
            'events':observed_events,'user_probes':observed_probes,'case_complete':complete,'accounting':accounting,'pass':final}


def validate_result(path,manifest_path,manifest):
    raw=_regular_bytes(path);require(len(raw)<=2<<20,'matrix result exceeds bound');result=parse_json(raw)
    require(result['format']==FORMAT and result['case'] in CASES and result['scope']==SCOPE
            and result['status']=='pass' and result['reason']==PASS_REASON
            and result['capture_only'] is False and result['qualification']=='not_established'
            and result['manifest_sha256']==sha256(manifest_path)
            and result['evaluator_sha256']==evaluator_hash(),'matrix result identity/status differs')
    setup=manifest['toolchain']['setup']
    require(result['emulator_sha256']==setup['verified_tools']['qemu']['sha256']
            and result['firmware']==setup['firmware'],'matrix emulator/firmware differs')
    execution=result['execution']
    require(execution['command']==qemu_command()
            and type(execution['timeout_seconds']) in (int,float) and math.isfinite(execution['timeout_seconds']) and 0<execution['timeout_seconds']<=60
            and type(execution['max_log_bytes']) is int and 0<execution['max_log_bytes']<=1_048_576
            and type(execution['elapsed_seconds']) in (int,float) and math.isfinite(execution['elapsed_seconds'])
            and 0<=execution['elapsed_seconds']<=execution['timeout_seconds']+1.5,'matrix execution budget differs')
    launch=execution['launcher'];directory=Path(launch['temporary_directory'])
    require(directory.is_absolute() and directory.parent.as_posix() in ('/tmp','/private/tmp')
            and re.fullmatch(r'tessryn-k02m-[a-z0-9_]+',directory.name) is not None
            and launch['executable']=='/usr/bin/env' and re.fullmatch(r'[0-9a-f]{64}',launch['sha256']) is not None
            and launch['command']==['/usr/bin/env','TMPDIR='+str(directory),*qemu_command()]
            and launch['tool_path_record']=='absolute hash-checked QEMU executed; command displays its pinned role'
            and launch['temporary_scope']=='fresh private owned directory removed after child reap','matrix execution launcher differs')
    require(len(result['logs'])==2 and {row['path'] for row in result['logs']}=={'stdout.log','stderr.log'},'matrix raw log allowlist differs')
    logs={}
    for row in result['logs']:
        data=_regular_bytes(path.parent/row['path'])
        require(len(data)==row['size_bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'matrix raw log bytes differ')
        logs[row['path']]=data
    require(sum(map(len,logs.values()))<=execution['max_log_bytes'],'matrix raw logs exceed budget')
    observed=parse_transcript(result['case'],logs['stdout.log'],execution['returncode'],logs['stderr.log'],bound_context(manifest_path,manifest,result['case']))
    require(result['observations']==observed,'matrix recorded observations differ from original trace')
    return result


def verify(first,second,results):
    a=validate_build(first);b=validate_build(second)
    require(_regular_bytes(first)==_regular_bytes(second) and a==b,'matrix twin builds differ')
    require(a['matrix_complete'] and tuple(a['cases'])==CASES,'diagnostic subset cannot qualify the ten-case matrix')
    source=a['source']
    require(source['dirty'] is False and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',source['revision']) is not None
            and source['snapshot_algorithm']=='git-worktree-v2'
            and re.fullmatch(r'[0-9a-f]{64}',source['tree_sha256']) is not None,'matrix acceptance requires clean reviewed source')
    source_receipt=validate_source(a);validate_toolchain(a)
    seen={};contexts=set()
    for path in results:
        result=validate_result(path,first,a);case=result['case']
        context=result['execution']['launcher']['temporary_directory']
        require(case not in seen and context not in contexts,'matrix duplicate case or reused boot context')
        seen[case]=result['observations'];contexts.add(context)
    require(set(seen)==set(CASES),'ten fresh matrix boot cases incomplete')
    return {'format':'tessryn-k02-matrix-verification/v1','status':'pass','scope':SCOPE,
            'qualification':'single_cpu_emulated_matrix_only','source':source,
            'source_verification':source_receipt,'checked_current_host_toolchain':True,
            'manifest_sha256':sha256(first),'evaluator_sha256':evaluator_hash(),'cases':seen}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--first',type=Path,required=True)
    p.add_argument('--second',type=Path,required=True);p.add_argument('--result',type=Path,action='append',default=[]);p.add_argument('--out',type=Path)
    args=p.parse_args()
    try:r=verify(args.first,args.second,args.result)
    except (ValueError,OSError,TypeError,KeyError) as error:p.exit(1,f'Matrix verification rejected: {error}\n')
    if args.out:args.out.open('x').write(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':r['status'],'scope':SCOPE}));return 0


if __name__=='__main__':raise SystemExit(main())
