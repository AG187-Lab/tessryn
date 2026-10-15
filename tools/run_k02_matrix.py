#!/usr/bin/env python3
"""Capture a fresh bounded original-kernel K02 matrix case with pinned QEMU."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.build_k02_matrix import ARTIFACT_TYPE,CASES,PROFILE,SCOPE,matrix_binding
from tools.build_fixture import sha256
from tools.g03.evidence import _regular_bytes,parse_json
from tools.g03.process import run_bounded
from tools.k01_media import make_disk
from tools.run_kernel import artifact_bytes
from tools.run_k02_native import launcher_command,qemu_command as slice_command,EVALUATOR_FILES as SLICE_FILES
from tools.setup_uefi import verify_installation

FORMAT='tessryn-k02-native-matrix-result/v1'
PASS_REASON='compiled matrix request, ordered policy and actual CPL3 evidence matched'
EVALUATOR_FILES=('tools/build_k02_matrix.py','tools/run_k02_matrix.py','tools/verify_k02_matrix.py',
                 'tools/k02_matrix_provenance.py','tools/k02_native_protocol.py','planning/k02-native-cases.json',*SLICE_FILES)


def evaluator_hash():
    digest=hashlib.sha256()
    for name in EVALUATOR_FILES:digest.update(name.encode()+b'\0'+_regular_bytes(ROOT/name)+b'\0')
    return digest.hexdigest()


def qemu_command():
    command=slice_command();command[command.index('-cpu')+1]=PROFILE['cpu'];return command


def run(manifest_path:Path,out:Path,case:str,timeout:float=45,max_log_bytes:int=1_048_576,capture_only:bool=False):
    if case not in CASES or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60 or type(max_log_bytes) is not int or not 0<max_log_bytes<=1_048_576 or type(capture_only) is not bool:
        raise ValueError('matrix case or bounded execution options invalid')
    out.mkdir(parents=True,exist_ok=False);stdout=stderr=b''
    result={'format':FORMAT,'case':case,'status':'fail','reason':'inputs incomplete','qualification':'not_established',
            'scope':SCOPE,'capture_only':capture_only,'manifest_sha256':None,'evaluator_sha256':None,
            'execution':{'command':qemu_command(),'timeout_seconds':timeout,'max_log_bytes':max_log_bytes,
                         'returncode':None,'elapsed_seconds':0},'observations':None,'logs':[]}
    try:
        initial_evaluator=evaluator_hash();result['evaluator_sha256']=initial_evaluator
        raw=_regular_bytes(manifest_path)
        if len(raw)>2<<20:raise ValueError('matrix manifest exceeds bound')
        manifest=parse_json(raw);result['manifest_sha256']=hashlib.sha256(raw).hexdigest()
        if manifest.get('schema_version')!=1 or manifest.get('qualification')!='not_established' or manifest['artifact_type']!=ARTIFACT_TYPE or manifest['profile']!=PROFILE or manifest['scope']!=SCOPE or case not in manifest['cases']:
            raise ValueError('matrix build case/profile differs')
        setup=verify_installation()
        if setup!=manifest['toolchain']['setup']:raise ValueError('matrix checked target/sysroot changed')
        efi=artifact_bytes(manifest_path,manifest,'BOOTX64.EFI',case)
        obj=artifact_bytes(manifest_path,manifest,'kernel.obj',case)
        disk=artifact_bytes(manifest_path,manifest,'boot.img',case)
        if make_disk(efi)!=disk or matrix_binding(obj,efi,case)!=manifest['bindings'][case]:
            raise ValueError('matrix media or immutable probe/contract binding differs')
        qemu=ROOT/'build/toolchain/bin/qemu-system-x86_64';result['emulator_sha256']=sha256(qemu)
        if result['emulator_sha256']!=setup['verified_tools']['qemu']['sha256']:raise ValueError('matrix QEMU changed')
        result['firmware']=setup['firmware']
        with tempfile.TemporaryDirectory(prefix='tessryn-k02m-',dir=Path('/tmp').resolve()) as temporary:
            scratch=Path(temporary)
            for role in ('code','vars'):
                row=setup['firmware'][role];data=_regular_bytes(ROOT/'build/uefi'/row['path'])
                if hashlib.sha256(data).hexdigest()!=row['sha256'] or len(data)!=row['size_bytes']:raise ValueError('matrix firmware changed')
                (scratch/(role+'.fd')).write_bytes(data)
            (scratch/'boot.img').write_bytes(disk);env_hash=sha256(Path('/usr/bin/env'))
            result['execution']['launcher']={'executable':'/usr/bin/env','sha256':env_hash,
                'command':['/usr/bin/env','TMPDIR='+str(scratch),*qemu_command()],
                'temporary_directory':str(scratch),
                'tool_path_record':'absolute hash-checked QEMU executed; command displays its pinned role',
                'temporary_scope':'fresh private owned directory removed after child reap'}
            execution=run_bounded(launcher_command(qemu,qemu_command()[1:],scratch),scratch,timeout,max_log_bytes)
            stdout,stderr=execution.stdout,execution.stderr
            result['execution'].update(returncode=execution.returncode,elapsed_seconds=execution.elapsed_seconds)
            result['status'],result['reason']=execution.status,execution.reason
            if sha256(Path('/usr/bin/env'))!=env_hash:raise ValueError('matrix launcher changed during execution')
        if evaluator_hash()!=initial_evaluator:raise ValueError('matrix evaluator changed during execution')
        if sha256(qemu)!=result['emulator_sha256']:raise ValueError('matrix QEMU changed during execution')
        if hashlib.sha256(_regular_bytes(manifest_path)).hexdigest()!=result['manifest_sha256']:
            raise ValueError('matrix manifest changed during execution')
        if execution.status=='completed':
            if execution.returncode!=33 or b'Triple fault' in stderr:raise ValueError('matrix guest exit or triple fault differs')
            if capture_only:
                result['status']='captured';result['reason']='raw bounded diagnostic capture; no event acceptance or qualification'
            else:
                from tools.verify_k02_matrix import bound_context,parse_transcript
                result['observations']=parse_transcript(case,stdout,execution.returncode,stderr,bound_context(manifest_path,manifest,case))
                if evaluator_hash()!=initial_evaluator:raise ValueError('matrix evaluator changed during acceptance')
                result['status']='pass';result['reason']=PASS_REASON
    except (OSError,ValueError,KeyError,TypeError) as error:
        reason=str(error) if isinstance(error,ValueError) else type(error).__name__
        result['status']='fail';result['observations']=None;result['reason']='matrix input or observed execution rejected: '+reason
    for name,data in (('stdout.log',stdout),('stderr.log',stderr)):
        (out/name).write_bytes(data);result['logs'].append({'path':name,'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data)})
    (out/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--case',choices=CASES,required=True)
    p.add_argument('--timeout',type=float,default=45);p.add_argument('--capture-only',action='store_true',help='retain diagnostic raw execution without event acceptance')
    args=p.parse_args();r=run(args.manifest,args.out,args.case,args.timeout,capture_only=args.capture_only)
    print(json.dumps({k:r[k] for k in ('status','case','reason','qualification','scope')}));return 0 if r['status'] in ('pass','captured') else 1


if __name__=='__main__':raise SystemExit(main())
