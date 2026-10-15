#!/usr/bin/env python3
"""Build independently bound original-kernel K02 matrix cases for UEFI."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_fixture import sha256, source_identity
from tools.build_kernel import compiler_profile, copy_notices, inspect_pe
from tools.build_k02_native import compile_flags, dependency_paths, probe_binding
from tools.k01_media import make_disk
from tools.k02_native_protocol import strict_json
from tools.g03.evidence import _regular_bytes
from tools.g03.process import run_bounded
from tools.setup_uefi import verify_installation

CONTRACT_PATH = ROOT / 'planning/k02-native-cases.json'
CONTRACT_BYTES = _regular_bytes(CONTRACT_PATH)
CONTRACT = strict_json(CONTRACT_BYTES)
CASES = tuple(CONTRACT['cases'])
CPU = 'max,phys-bits=48,la57=off,nx=on,pcid=off,pge=off,pku=off,pks=off,sgx=off,cet-ss=off,cet-ibt=off'
PROFILE = {**CONTRACT['profile'], 'target':'x86_64-unknown-uefi', 'machine':'q35,accel=tcg',
           'cpu':CPU, 'memory_bytes':256 * 1024 * 1024}
ARTIFACT_TYPE = 'tessryn-k02-native-matrix'
SCOPE = 'ten-case original-kernel single-CPU emulated matrix; physical hardware, SMP and DMA unqualified'
MAGIC = b'TESSRYN-K02M-V1\0'
DESCRIPTOR_SIZE = 184
ADDRESS_NAMES = ('code','own','stack','request','unauthorized','readonly','guard','data_nx',
                 'revoked_B','revoked_D','reuse_B','reuse_C')
ADDRESSES = (0x100000000,0x100001000,0x100002000,0x10000f000,0x100003000,
             0x100004000,0x100005000,0x100006000,0x100007000,0x100008000,
             0x100009000,0x10000a000)
SEEDS = (0x5445535356494354,0x544553534e455743,0x5445535357524954)
CONTROL_LABELS = ('k02_probe_read','k02_probe_read_return','k02_probe_write',
                  'k02_probe_write_return','k02_probe_request','k02_probe_request_trap',
                  'k02_probe_boundary_snapshot','k02_probe_boundary_snapshot_return')
BOUNDARY_OPCODES = b'\x48\x0f\xae\x07'+b''.join(
    bytes((rex,0x89,modrm))+struct.pack('<I',512+8*index)
    for index,(rex,modrm) in enumerate(((0x4c,0xbf),(0x4c,0xb7),(0x4c,0xaf),(0x4c,0xa7),
        (0x4c,0x9f),(0x4c,0x97),(0x4c,0x8f),(0x4c,0x87),
        (0x48,0xbf),(0x48,0xb7),(0x48,0xaf),(0x48,0x9f),
        (0x48,0x97),(0x48,0x8f),(0x48,0x87),(0x48,0xa7))))+b'\xcd\x80'
FAULT_LABELS = tuple('k02_probe_' + name for name in CONTRACT['faults'] if name != 'nx_fetch')
LABELS = (*CONTROL_LABELS,*FAULT_LABELS,*(name+'_return' for name in FAULT_LABELS))
REQUEST_MAGIC = 0x4b30325245515631
REQUEST_ROWS = tuple((op, slot | (generation << 32), domain, 0, length, rights, 0, REQUEST_MAGIC)
    for op,slot,generation,domain,length,rights in (
        (1,3,1,1,4096,5),(2,3,1,2,4096,5),(3,3,1,2,4096,5),
        (4,3,1,2,4096,5),(5,3,1,2,4096,5),(6,3,1,2,4096,5),
        (1,4,1,2,4094,5),(1,4,1,2,4096,5),(1,5,1,2,4096,6),
        (7,3,1,2,4096,1),(8,3,2,2,4096,1),(1,3,1,2,4096,5),
        (1,3,1,4,4096,5)))


def selected_cases(names: list[str] | None) -> tuple[str,...]:
    names = list(CASES) if not names else names
    if len(set(names)) != len(names) or any(name not in CASES for name in names):
        raise ValueError('unsupported or repeated matrix case')
    return tuple(name for name in CASES if name in names)


def case_flags(case: str) -> list[str]:
    if case not in CASES:
        raise ValueError('unknown matrix case')
    return ['--cfg','k01_emulator','--cfg','k02_native','--cfg','k02_matrix',
            '--cfg',f'k02_matrix_case="{case}"']


def coff_symbols(data: bytes) -> tuple[list[dict],dict[str,tuple[int,int]]]:
    if len(data) < 20:
        raise ValueError('COFF header truncated')
    machine,count,_,symbols_at,symbols_count,optional,_ = struct.unpack_from('<HHIIIHH',data)
    strings_at = symbols_at + symbols_count * 18
    if machine != 0x8664 or optional or not 0 < count <= 4096 or symbols_count > 1_000_000 or 20+count*40 > len(data) or strings_at+4 > len(data):
        raise ValueError('COFF tables invalid')
    size = struct.unpack_from('<I',data,strings_at)[0]
    if size < 4 or strings_at+size > len(data):
        raise ValueError('COFF strings invalid')
    sections=[]
    for i in range(count):
        at=20+i*40; length,raw,relocations=struct.unpack_from('<III',data,at+16)
        relocation_count=struct.unpack_from('<H',data,at+32)[0]
        if raw+length > len(data) or relocations+relocation_count*10 > len(data):
            raise ValueError('COFF section/relocations truncated')
        sections.append({'raw':raw,'size':length,'relocations':relocations,'relocation_count':relocation_count})
    symbols={};i=0
    while i < symbols_count:
        at=symbols_at+i*18;name=data[at:at+8]
        if name[:4] == b'\0'*4:
            offset=struct.unpack_from('<I',name,4)[0]
            end=data.find(b'\0',strings_at+offset,strings_at+size)
            if not 4 <= offset < size or end < 0:
                raise ValueError('COFF symbol name invalid')
            name=data[strings_at+offset:end]
        else:
            name=name.rstrip(b'\0')
        value,section,_,storage,auxiliary=struct.unpack_from('<IhHBB',data,at+8)
        decoded=name.decode('utf-8')
        if decoded in (*LABELS,'K02_MATRIX_CONTRACT','K02_MATRIX_REQUESTS','k02_user_code_start','k02_user_code_end'):
            if decoded in symbols or storage != 2 or not 1 <= section <= count:
                raise ValueError('matrix symbol is duplicate or not defined external')
            symbols[decoded]=(section,value)
        i+=1+auxiliary
        if i > symbols_count:
            raise ValueError('COFF auxiliary symbols truncated')
    return sections,symbols


def linked_region(efi: bytes, raw: bytes, executable: bool) -> dict:
    inspect_pe(efi)
    location=efi.find(raw)
    if location < 0 or efi.find(raw,location+1) >= 0:
        raise ValueError('compiled matrix region is not unique and unchanged in EFI')
    pe=struct.unpack_from('<I',efi,60)[0];count=struct.unpack_from('<H',efi,pe+6)[0]
    optional=struct.unpack_from('<H',efi,pe+20)[0];found=[]
    for i in range(count):
        at=pe+24+optional+i*40;rva,size,start=struct.unpack_from('<III',efi,at+12)
        flags=struct.unpack_from('<I',efi,at+36)[0]
        if start <= location and location+len(raw) <= start+size:
            if not flags & 0x40000000 or bool(flags & 0x20000000) != executable or flags & 0x80000000:
                raise ValueError('matrix region section permissions differ')
            found.append(rva+location-start)
    if len(found) != 1:
        raise ValueError('matrix region section is ambiguous')
    return {'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'efi_file_offset':location,'efi_rva':found[0]}


def matrix_binding(obj: bytes, efi: bytes, case: str) -> dict:
    if case not in CASES:
        raise ValueError('unknown matrix binding case')
    sections,symbols=coff_symbols(obj)
    if set(symbols) != set((*LABELS,'K02_MATRIX_CONTRACT','K02_MATRIX_REQUESTS','k02_user_code_start','k02_user_code_end')):
        raise ValueError('compiled matrix labels/contract incomplete')
    code_section,code_start=symbols['k02_user_code_start']
    code=probe_binding(obj,efi)
    offsets={}
    for name in LABELS:
        section,value=symbols[name]
        if section != code_section or not code_start <= value < code_start+4096:
            raise ValueError('matrix instruction exceeds bound code page')
        offsets[name]=value-code_start
    if len({offsets[name] for name in FAULT_LABELS}) != len(FAULT_LABELS):
        raise ValueError('matrix fault instructions alias')
    for name in FAULT_LABELS:
        if offsets[name+'_return'] != offsets[name]+5:
            raise ValueError('matrix fault return is not exact post-INT80 label')
    for name,distance in (('read',5),('write',5),('request',2)):
        end='trap' if name=='request' else 'return'
        if offsets['k02_probe_'+name+'_'+end] != offsets['k02_probe_'+name]+distance:
            raise ValueError('matrix controlled return label differs')
    code_raw=efi[code['efi_file_offset']:code['efi_file_offset']+4096]
    start=offsets['k02_probe_boundary_snapshot'];end=offsets['k02_probe_boundary_snapshot_return']
    if end-start!=len(BOUNDARY_OPCODES) or code_raw[start:end]!=BOUNDARY_OPCODES:
        raise ValueError('compiled matrix boundary register/FP snapshot opcodes differ')
    linked_code=linked_region(efi,code_raw,True)
    if linked_code['efi_rva']!=code['efi_rva']:
        raise ValueError('matrix executable code section differs')
    for name,spec in CONTRACT['faults'].items():
        if name=='nx_fetch':continue
        at=offsets['k02_probe_'+name]
        expected=b'\x48\x89\x37\xcd\x80' if spec['error_code'] & 2 else b'\x48\x8b\x07\xcd\x80'
        if code_raw[at:at+5]!=expected:
            raise ValueError('compiled matrix load/store and controlled trap opcodes differ')
    section,start=symbols['K02_MATRIX_CONTRACT'];info=sections[section-1]
    if start+DESCRIPTOR_SIZE > info['size']:
        raise ValueError('matrix contract exceeds COFF section')
    for i in range(info['relocation_count']):
        address=struct.unpack_from('<I',obj,info['relocations']+i*10)[0]
        if start <= address < start+DESCRIPTOR_SIZE:
            raise ValueError('matrix contract must contain no relocated pointers')
    raw=obj[info['raw']+start:info['raw']+start+DESCRIPTOR_SIZE]
    if raw[:16] != MAGIC:
        raise ValueError('matrix contract magic differs')
    words=struct.unpack_from('<21Q',raw,16)
    if words != (1,CASES.index(case),1,2,3,4,*ADDRESSES,*SEEDS):
        raise ValueError('compiled matrix contract constants/case differ')
    descriptor={**linked_region(efi,raw,False),'version':1,'case_id':words[1],
                'domains':dict(zip('ABCD',words[2:6])),
                'addresses':dict(zip(ADDRESS_NAMES,words[6:18])),
                'seeds':dict(zip(('victim','C','write'),words[18:21]))}
    code['offsets'].update(offsets)
    code['instruction_bytes'].update({name:efi[code['efi_file_offset']+offset:code['efi_file_offset']+offset+16].hex() for name,offset in offsets.items()})
    faults={name:{**spec,'rip':ADDRESSES[7] if name=='nx_fetch' else ADDRESSES[0]+offsets['k02_probe_'+name]} for name,spec in CONTRACT['faults'].items()}
    section,start=symbols['K02_MATRIX_REQUESTS'];info=sections[section-1]
    expected=b'TESSRYN-K02R-V1\0'+b''.join(struct.pack('<8Q',*row) for row in REQUEST_ROWS)
    if start+len(expected)>info['size']:
        raise ValueError('matrix request contract exceeds COFF section')
    for i in range(info['relocation_count']):
        address=struct.unpack_from('<I',obj,info['relocations']+i*10)[0]
        if start<=address<start+len(expected):raise ValueError('matrix request contract contains relocated pointers')
    requests=obj[info['raw']+start:info['raw']+start+len(expected)]
    if requests!=expected:raise ValueError('compiled matrix request recipes differ')
    return {'code':code,'descriptor':descriptor,'faults':faults,
            'requests':{**linked_region(efi,requests,False),'rows':[list(row) for row in REQUEST_ROWS]}}


def compilation_sources() -> dict[str,bytes]:
    """Retain the source tree before rustc reads it; reject source aliases."""
    retained={};total=0
    for directory in ('kernel','kernel-core','interfaces'):
        base=ROOT/directory
        if base.is_symlink() or not base.is_dir():
            raise ValueError('matrix compilation source directory must be regular')
        for path in sorted(base.rglob('*')):
            if path.is_symlink():raise ValueError('matrix compilation sources must not contain symlinks')
            if path.is_dir():continue
            if len(retained)>=512 or path.stat().st_size>16<<20:
                raise ValueError('matrix compilation source bounds exceeded')
            data=_regular_bytes(path);total+=len(data)
            if len(data)>16<<20 or total>64<<20:raise ValueError('matrix compilation source bounds exceeded')
            retained[path.relative_to(ROOT).as_posix()]=data
    if not all(name in retained for name in ('kernel-core/lib.rs','kernel/main.rs','kernel/entry.S','kernel/k02_matrix.rs')):
        raise ValueError('matrix compilation sources lack original kernel inputs')
    return retained


def build(out: Path, names: list[str] | None = None) -> dict:
    selected=selected_cases(names);candidate=out.absolute()
    for parent in (candidate,*candidate.parents):
        if parent==ROOT:break
        if parent.is_symlink():raise ValueError('matrix output must not traverse symlinks')
    out=candidate.resolve()
    if not out.is_relative_to(ROOT/'build'):
        raise ValueError('matrix output must be under ignored build/')
    out.mkdir(parents=True,exist_ok=False)
    source=source_identity();profile=compiler_profile();setup=profile['toolchain']['setup'];prefix=ROOT/'build/uefi'
    retained=compilation_sources()
    if _regular_bytes(CONTRACT_PATH)!=CONTRACT_BYTES:
        raise ValueError('matrix case contract changed since initialization')
    library=out/'libtessryn_owned_memory.rlib';dependencies=set();commands={}
    with tempfile.TemporaryDirectory(prefix='matrix-sources-',dir=out) as temporary:
        snapshot=Path(temporary)
        for name,data in retained.items():
            path=snapshot/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o400)
        def normalized(value):
            return value.replace(str(prefix),'rust-toolchain').replace(str(snapshot),'tessryn').replace(str(out),'k02-matrix-build').replace(str(ROOT),'tessryn')
        def compile_one(name,src,target,flags):
            depfile=target.parent/(name+'.d');emits=f'link,dep-info={depfile}'
            if name!='core':emits+=f',obj={target.parent / "kernel.obj"}'
            # rustc applies the last matching remap: the nested random snapshot
            # must win over the general output-directory mapping.
            arguments=[src,*flags,f'--emit={emits}',f'--remap-path-prefix={prefix}=rust-toolchain',
                       f'--remap-path-prefix={out}=k02-matrix-build',f'--remap-path-prefix={snapshot}=tessryn']
            if name!='core':arguments += [f'-Clinker={profile["linker"]}','--extern',f'tessryn_owned_memory={library}']
            arguments += ['-o',str(target)]
            execution=run_bounded([str(profile['compiler']),*arguments],snapshot,90,1_048_576)
            (target.parent/(name+'-build.log')).write_bytes(normalized((execution.stdout+execution.stderr).decode('utf-8',errors='replace')).encode())
            if execution.status!='completed' or execution.returncode!=0:
                failure={'status':execution.status,'reason':execution.reason,'case':name,
                         'returncode':execution.returncode,'elapsed_seconds':execution.elapsed_seconds,
                         'command':[normalized(str(profile['compiler'])),*[normalized(arg) for arg in arguments]],
                         'source_files':{key:hashlib.sha256(data).hexdigest() for key,data in retained.items()}}
                (target.parent/'build-failure.json').write_text(json.dumps(failure,indent=2,sort_keys=True)+'\n')
                raise ValueError('matrix '+name+' compilation failed; inspect retained build diagnostics')
            paths=dependency_paths(depfile.read_text(),snapshot,{library})
            if any(path not in retained for path in paths):raise ValueError('compiler dependency was not in retained source snapshot')
            dependencies.update(paths);depfile.unlink()
            commands[name]=[normalized(arg) for arg in arguments]
        compile_one('core','kernel-core/lib.rs',library,compile_flags(profile,True))
        artifacts=[{'path':library.name,'kind':'target_rlib','crate':'tessryn_owned_memory','target':PROFILE['target'],'sha256':sha256(library),'size_bytes':library.stat().st_size}];bindings={}
        for case in selected:
            directory=out/case;directory.mkdir();efi=directory/'BOOTX64.EFI'
            compile_one(case,'kernel/main.rs',efi,[*compile_flags(profile),*case_flags(case)])
            obj=directory/'kernel.obj';object_bytes=_regular_bytes(obj);efi_bytes=_regular_bytes(efi)
            bindings[case]=matrix_binding(object_bytes,efi_bytes,case);validation=inspect_pe(efi_bytes)
            disk=directory/'boot.img';disk.write_bytes(make_disk(efi_bytes))
            for p,kind in ((efi,'kernel_efi'),(disk,'boot_disk'),(obj,'compiler_object')):
                artifacts.append({'path':p.relative_to(out).as_posix(),'kind':kind,'case':case,'sha256':sha256(p),'size_bytes':p.stat().st_size,
                                  'pe_validation':validation if kind=='kernel_efi' else None})
        if any(_regular_bytes(snapshot/name)!=data for name,data in retained.items()):
            raise ValueError('retained compiler sources changed during build')
    files={name:hashlib.sha256(retained[name]).hexdigest() for name in sorted(dependencies)}
    protocol={name:sha256(ROOT/name) for name in ('planning/k02-native-cases.json','tools/k02_native_protocol.py')}
    manifest={'schema_version':1,'artifact_type':ARTIFACT_TYPE,'source':source,'source_files':files,
              'source_files_sha256':hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
              'protocol_sources_sha256':protocol,'toolchain':profile['toolchain'],'profile':PROFILE,
              'cases':list(selected),'matrix_complete':selected==CASES,'qualification':'not_established',
              'compile_commands':commands,'bindings':bindings,'artifacts':artifacts,'notices':copy_notices(out),'scope':SCOPE}
    if source_identity()!=source or compilation_sources()!=retained or verify_installation()!=setup or _regular_bytes(CONTRACT_PATH)!=CONTRACT_BYTES or protocol!={name:sha256(ROOT/name) for name in protocol}:
        raise ValueError('matrix source, protocol or pinned setup changed during build')
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--case',choices=CASES,action='append');args=p.parse_args()
    try:m=build(args.out,args.case)
    except (OSError,ValueError,subprocess.SubprocessError) as error:p.exit(1,f'Matrix build rejected: {error}\n')
    print(json.dumps({'status':'built','cases':m['cases'],'matrix_complete':m['matrix_complete'],'qualification':'not_established'}));return 0


if __name__=='__main__':raise SystemExit(main())
