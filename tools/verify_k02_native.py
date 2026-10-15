#!/usr/bin/env python3
"""Check twin builds and four bounded K02 single-CPU emulator observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_k02_native import ARTIFACT_TYPE, CASES, PROFILE, SCOPE, case_flags, probe_binding
from tools.build_fixture import sha256
from tools.g03.evidence import parse_json, _regular_bytes
from tools.k01_media import make_disk
from tools.run_kernel import artifact_bytes
from tools.run_k02_native import FORMAT, PASS_REASON, evaluator_hash, qemu_command

USER_CODE = 0x1_0000_0000
USER_OWN = USER_CODE + 0x1000
USER_STACK = USER_CODE + 0x2000
USER_FOREIGN = USER_CODE + 0x3000
USER_READONLY = USER_CODE + 0x4000
FAULTS = {"foreign_read": (4, USER_FOREIGN), "kernel_read": (5, None),
          "readonly_write": (7, USER_READONLY)}


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def fields(line: str, marker: str) -> dict[str, str]:
    require(line.startswith(marker + " "), "serial marker framing differs")
    result = {}
    for token in line[len(marker) + 1:].split():
        require(re.fullmatch(r"[a-z][a-z_0-9]*=[A-Za-z0-9_:.+-]+", token) is not None,
                "serial fields malformed")
        key, value = token.split("=", 1)
        require(key not in result, "duplicate serial field")
        result[key] = value
    return result


def number(value: str) -> int:
    require(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", value) is not None, "serial integer malformed")
    parsed = int(value, 16 if value.startswith("0x") else 10)
    require(0 <= parsed < 1 << 64, "serial integer exceeds u64")
    return parsed


def parse_transcript(case: str, data: bytes, returncode: int | None,
                     stderr: bytes, probe: dict) -> dict:
    """Accept only the concrete four-case hardware wire contract, not PR57 JSON."""
    require(case in CASES and type(returncode) is int and returncode == 33 and len(data) <= 262144 and b"Triple fault" not in stderr,
            "case, output bound or emulator exit differs")
    try:
        lines = [line.strip() for line in data.decode("ascii").splitlines() if line.strip()]
    except UnicodeError as error:
        raise ValueError("serial output is not ASCII") from error
    require(sum(line == "TESSRYN_K01_ENTRY" for line in lines) == 1, "fresh boot entry missing or duplicated")
    require(not any("FAIL" in line or "PANIC" in line or "UNEXPECTED" in line for line in lines), "kernel failure marker observed")
    for marker in ("TESSRYN_K01_EXIT_BOOT_SERVICES_OK", "TESSRYN_K01_CPU_OWNED"):
        require(sum(line.startswith(marker) for line in lines) == 1, "owned handoff marker missing or duplicated")
    live_lines = [line for line in lines if line.startswith("TESSRYN_K01_LIVE_RANGES ")]
    require(len(live_lines) == 1, "live image/map/stack evidence missing or duplicate")
    live = fields(live_lines[0], "TESSRYN_K01_LIVE_RANGES")
    image_start, image_end = number(live["image_start"]), number(live["image_end"])
    require(image_start < image_end <= 1 << 47, "loaded image bounds invalid")
    events = [line for line in lines if line.startswith("TESSRYN_K02_")]
    names = ("PROFILE", "INVENTORY", "MAPPING", "MAPPING", "MAPPING", "MAPPING",
             "USER_ENTER", "TRAP", "SENTINELS", "TEARDOWN", "TEARDOWN", "TEARDOWN", "TEARDOWN", "PASS")
    require(len(events) == len(names) and all(line.startswith("TESSRYN_K02_" + name + " ") for line, name in zip(events, names)), "K02 ordered event contract incomplete")
    rows = [fields(line, "TESSRYN_K02_" + name) for name, line in zip(names, events)]
    profile, inventory = rows[:2]
    expected_profile = {"physical_bits":"48", "cpu_count":"1", "paging_levels":"4",
        "nx_supported":"1", "nx_enabled":"1", "pcid_enabled":"0", "global_translations":"0", "la57_enabled":"0"}
    require(set(profile) == set(expected_profile) | {"cr4", "efer_low"} and all(profile[k] == v for k,v in expected_profile.items()), "actual CPU/paging admission differs")
    require(number(profile['cr4']) & ((1 << 7) | (1 << 12) | (1 << 17)) == 0 and number(profile['efer_low']) & (1 << 11) != 0, "actual control register admission differs")
    require(set(inventory) == {"descriptors","available_pages","protected_state","source"}
            and number(inventory['descriptors']) > 0 and number(inventory['available_pages']) >= 4
            and inventory['source'] == 'final_successful_handoff'
            and image_start <= number(inventory['protected_state']) < image_end, "owned inventory source/protected state differs")
    require(lines.index(events[0]) > next(i for i,line in enumerate(lines) if line.startswith('TESSRYN_K01_CPU_OWNED')), "K02 precedes CPU ownership")
    mappings = rows[2:6]
    expected_maps = [('own',2,USER_OWN,1),('stack',2,USER_STACK,1),
                     ('readonly',2,USER_READONLY,0),('foreign',1,USER_FOREIGN,0)]
    for row,(role,domain,va,writable) in zip(mappings,expected_maps):
        require(set(row) == {'role','domain','virtual','physical','page_bytes','writable','nx'}
                and row['role'] == role and number(row['domain']) == domain
                and number(row['virtual']) == va and number(row['page_bytes']) == 4096
                and number(row['writable']) == writable and row['nx'] == '1', "native mapping role/domain/permissions differ")
        pa = number(row['physical'])
        # BootInventory admits conventional non-runtime RAM below 4 GiB;
        # the native adapter additionally excludes the null page. K01's
        # separate scratch-selection floor does not constrain these frames.
        require(4096 <= pa <= (1 << 32) - 4096 and pa % 4096 == 0,
                "owned physical page invalid")
        for start,end in [('image_start','image_end'),('stack_start','stack_end'),('map_start','map_end'),('gop_start','gop_end')]:
            lo,hi = number(live[start]),number(live[end])
            lo,hi = lo & ~4095,(hi + 4095) & ~4095
            require(not (pa < hi and lo < pa + 4096), "owned frame overlaps a live reserved range")
        scratch = number(live['scratch'])
        require(not (pa < scratch + 4096 and scratch < pa + 4096),
                "owned frame overlaps retained K01 scratch")
    physical = [number(row['physical']) for row in mappings]
    require(len(set(physical)) == 4, "foreign, delegated and owned page backing is not distinct")
    entered, trap, sentinels = rows[6:9]
    require(set(entered) == {'case','domain','root','code','code_physical','stack_start','stack_end','instruction','probe_rip','target','trap_start','trap_end'}, "user entry schema differs")
    require(entered['case'] == case and entered['domain'] == '2' and number(entered['code']) == USER_CODE
            and number(entered['code_physical']) == image_start + probe['efi_rva']
            and number(entered['stack_start']) == USER_STACK and number(entered['stack_end']) == USER_STACK + 4096,
            "trusted code image/VA or user stack differs")
    root = number(entered['root'])
    require(root % 4096 == 0 and image_start <= root and root + 16 * 4096 <= image_end, "private root pool not image-owned")
    instruction_label = 'k02_probe_own_write' if case == 'own_page' else 'k02_probe_' + case
    expected_instruction = USER_CODE + probe['offsets'][instruction_label]
    expected_rip = USER_CODE + probe['offsets']['k02_probe_own_return'] + 2 if case == 'own_page' else expected_instruction
    target = {'own_page':USER_OWN,'foreign_read':USER_FOREIGN,'readonly_write':USER_READONLY,
              'kernel_read':number(inventory['protected_state'])}[case]
    require(number(entered['instruction']) == expected_instruction and number(entered['probe_rip']) == expected_rip
            and number(entered['target']) == target, "probe instruction/RIP/target differs from compiled code")
    lo,hi = number(entered['trap_start']),number(entered['trap_end'])
    require(image_start <= lo < hi <= image_end and hi-lo >= 4096, "dedicated trap stack not image-owned")
    require(set(trap) == {'case','domain','vector','error','rip','cs','ss','rflags','rsp','cr2','frame','kind'}
            and trap['case'] == case and trap['domain'] == '2', "normalized trap schema/domain differs")
    require(number(trap['cs']) == 0x33 and number(trap['ss']) == 0x2b
            and USER_STACK <= number(trap['rsp']) < USER_STACK + 4096
            and lo <= number(trap['frame']) and number(trap['frame']) + 176 <= hi,
            "normalized trap is outside owned stack or CPL3 context")
    require(number(trap['rflags']) & ((3 << 12) | (1 << 9) | (1 << 10) | (1 << 14) | (1 << 17)) == 0,
            "unsafe user flags in trap frame")
    vector,error,kind = (128,0,'controlled_return') if case == 'own_page' else (14,FAULTS[case][0],'expected_page_fault')
    require(number(trap['vector']) == vector and number(trap['error']) == error and number(trap['rip']) == expected_rip
            and trap['kind'] == kind and (case == 'own_page' or number(trap['cr2']) == target),
            "actual hardware fault/return cause or probe address differs")
    exceptions = [line for line in lines if line.startswith('TESSRYN_K01_EXCEPTION')]
    require(len(exceptions) == 1, "actual raw hardware exception missing, duplicated or unknown")
    raw_exception = fields(exceptions[0], 'TESSRYN_K01_EXCEPTION')
    exception_fields = {'vector', 'error', 'rip', 'cs', 'rflags', 'rsp', 'cr2'}
    require(set(raw_exception) == exception_fields
            and all(number(raw_exception[key]) == number(trap[key]) for key in exception_fields),
            "raw hardware exception differs from normalized trap")
    entered_at = lines.index(events[6])
    require(entered_at + 2 < len(lines) and lines[entered_at + 1] == exceptions[0]
            and lines[entered_at + 2] == events[7], "raw hardware exception is outside the ordered user entry/trap boundary")
    require(set(sentinels) == {'victim_unchanged','foreign_unchanged','own_verified','pages_scrubbed','victim','foreign','own'}
            and sentinels['victim_unchanged'] == sentinels['foreign_unchanged'] == sentinels['own_verified'] == '1'
            and number(sentinels['pages_scrubbed']) == 4
            and number(sentinels['victim']) == physical[2] and number(sentinels['foreign']) == physical[3]
            and number(sentinels['own']) == physical[0],
            "sentinel data or scrub/ownership accounting differs")
    teardowns = rows[9:13]
    for row,mapping in zip(teardowns,mappings):
        require(set(row) == {'virtual','physical','order'} and row['virtual'] == mapping['virtual']
                and row['physical'] == mapping['physical']
                and row['order'] == 'fence_pte_remove_cr3_reload_quiesce', "mapping lease teardown order/identity differs")
    require(rows[-1] == {'case':case,'cpl3_observed':'1','owned_pages_after':'0','scope':'single_cpu_emulated_protection_slice'}
            and lines[-1] == events[-1], "terminal acceptance or remaining allocation differs")
    return {'profile':profile,'inventory':inventory,'mappings':mappings,'user_enter':entered,
            'trap':trap,'sentinels':sentinels,'teardown':teardowns,'pass':rows[-1]}



def validate_build(path: Path) -> dict:
    data = _regular_bytes(path)
    require(len(data) <= 2 << 20, "manifest exceeds bound")
    manifest = parse_json(data)
    require(manifest["schema_version"] == 1 and manifest["artifact_type"] == ARTIFACT_TYPE and manifest["profile"] == PROFILE and manifest["cases"] == list(CASES) and manifest["scope"] == SCOPE, "build profile/scope differs")
    rows = manifest["artifacts"]
    expected = {"libtessryn_owned_memory.rlib"} | {f"{case}/{name}" for case in CASES for name in ("BOOTX64.EFI", "boot.img", "kernel.obj")}
    require(len(rows) == len(expected) and {row['path'] for row in rows} == expected, "K02 artifact allowlist differs")
    for row in rows:
        relative = Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts, "artifact path invalid")
        raw = _regular_bytes(path.parent / relative)
        require(hashlib.sha256(raw).hexdigest() == row['sha256'] and len(raw) == row['size_bytes'], "artifact hash or size differs")
    library = next(row for row in rows if row['path'] == 'libtessryn_owned_memory.rlib')
    require(library['target'] == PROFILE['target'] and library['crate'] == 'tessryn_owned_memory', "ownership library was not built for the UEFI ABI")
    commands = manifest['compile_commands']
    require(set(commands) == {'core', *CASES}, "compile command set differs")
    for name, command in commands.items():
        require(type(command) is list and all(type(arg) is str for arg in command)
                and '--target=x86_64-unknown-uefi' in command
                and not any('x86_64-unknown-none' in arg for arg in command),
                "compiler target was changed or retargeted")
        if name == 'core':
            require(command[0] == 'kernel-core/lib.rs' and '--crate-type=rlib' in command
                    and '--crate-name=tessryn_owned_memory' in command,
                    "ownership policy crate compilation differs")
        else:
            require(command[0] == 'kernel/main.rs' and '--crate-type=bin' in command
                    and '--extern' in command and 'tessryn_owned_memory=k02-build/libtessryn_owned_memory.rlib' in command,
                    "kernel does not link its freshly built UEFI library")
            start = command.index('--cfg')
            require(command[start:start + 6] == case_flags(name), "case compilation flags differ")
    for case in CASES:
        efi = artifact_bytes(path, manifest, 'BOOTX64.EFI', case)
        disk = artifact_bytes(path, manifest, 'boot.img', case)
        obj = artifact_bytes(path, manifest, 'kernel.obj', case)
        require(disk == make_disk(efi) and probe_binding(obj, efi) == manifest['probes'][case], "media or compiler-bound probes differ")
    files = manifest['source_files']
    require(type(files) is dict and all(type(name) is str and not Path(name).is_absolute()
            and '..' not in Path(name).parts and type(digest) is str and re.fullmatch(r'[0-9a-f]{64}',digest)
            for name,digest in files.items()), "compiler dependency paths/hashes invalid")
    require(hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == manifest['source_files_sha256'], "source dependency manifest differs")
    require(all(name in files for name in ('kernel/main.rs', 'kernel/entry.S', 'kernel-core/lib.rs', 'interfaces/abi-v1/native.rs')), "real kernel/core/ABI dependencies missing")
    expected_notices = {'notices/tessryn-LICENSE','notices/tessryn-NOTICE',
                        'notices/rust-LICENSE-APACHE','notices/rust-LICENSE-MIT','notices/rust-COPYRIGHT'}
    require(len(manifest['notices']) == 5 and {row['path'] for row in manifest['notices']} == expected_notices,
            "notice allowlist differs")
    for row in manifest['notices']:
        raw = _regular_bytes(path.parent / row['path'])
        require(hashlib.sha256(raw).hexdigest() == row['sha256'] and len(raw) == row['size_bytes'], "notice bytes differ")
    return manifest


def validate_result(path: Path, manifest_path: Path, manifest: dict) -> dict:
    result = parse_json(_regular_bytes(path))
    require(result['format'] == FORMAT and result['case'] in CASES and result['scope'] == SCOPE and result['status'] == 'pass' and result['reason'] == PASS_REASON and result['manifest_sha256'] == sha256(manifest_path) and result['evaluator_sha256'] == evaluator_hash(), "result identity/status differs")
    setup = manifest['toolchain']['setup']
    require(result['emulator_sha256'] == setup['verified_tools']['qemu']['sha256'] and result['firmware'] == setup['firmware'], "emulator/firmware differs")
    exe = result['execution']
    require(exe['command'] == qemu_command() and type(exe['timeout_seconds']) in (int,float) and math.isfinite(exe['timeout_seconds']) and 0 < exe['timeout_seconds'] <= 60 and type(exe['max_log_bytes']) is int and 0 < exe['max_log_bytes'] <= 1_048_576 and type(exe['elapsed_seconds']) in (int,float) and math.isfinite(exe['elapsed_seconds']) and 0 <= exe['elapsed_seconds'] <= exe['timeout_seconds'] + 1.5, "execution profile/budget differs")
    launch = exe['launcher']
    directory = Path(launch['temporary_directory'])
    require(directory.is_absolute() and directory.parent.as_posix() in ('/tmp','/private/tmp')
            and re.fullmatch(r'tessryn-k02-[a-z0-9_]+',directory.name) is not None
            and launch['executable'] == '/usr/bin/env'
            and re.fullmatch(r'[0-9a-f]{64}',launch['sha256']) is not None
            and launch['command'] == ['/usr/bin/env','TMPDIR=' + str(directory),*qemu_command()]
            and launch['tool_path_record'] == 'absolute hash-checked QEMU executed; command displays its pinned role'
            and launch['temporary_scope'] == 'fresh private owned directory removed after child reap',
            "actual temporary-storage launcher differs")
    require(len(result['logs']) == 2 and {r['path'] for r in result['logs']} == {'stdout.log','stderr.log'}, "raw log allowlist differs")
    logs = {}
    for row in result['logs']:
        raw = _regular_bytes(path.parent / row['path'])
        require(hashlib.sha256(raw).hexdigest() == row['sha256'] and len(raw) == row['size_bytes'], "raw log hash differs")
        logs[row['path']] = raw
    require(sum(map(len,logs.values())) <= exe['max_log_bytes'], "raw logs exceed budget")
    observations = parse_transcript(result['case'], logs['stdout.log'], exe['returncode'], logs['stderr.log'], manifest['probes'][result['case']])
    require(observations == result['observations'], "recorded observations differ from raw hardware trace")
    return result


def verify(first: Path, second: Path, results: list[Path]) -> dict:
    a, b = validate_build(first), validate_build(second)
    require(_regular_bytes(first) == _regular_bytes(second) and a == b, "independent builds differ")
    seen = {}
    contexts = set()
    for path in results:
        result = validate_result(path, first, a)
        require(result['case'] not in seen, "duplicate execution case")
        context = result['execution']['launcher']['temporary_directory']
        require(context not in contexts, "cases reused the same execution/firmware context")
        contexts.add(context)
        seen[result['case']] = result['observations']
    require(set(seen) == set(CASES), "four fresh boot cases incomplete")
    return {'format':'tessryn-k02-native-verification/v1','status':'pass','scope':SCOPE,
            'manifest_sha256':sha256(first),'evaluator_sha256':evaluator_hash(),'cases':seen}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--first',type=Path,required=True)
    parser.add_argument('--second',type=Path,required=True)
    parser.add_argument('--result',type=Path,action='append',default=[])
    parser.add_argument('--out',type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.first,args.second,args.result)
        if args.out:
            with args.out.open('x') as f:f.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
    except (OSError,ValueError,KeyError,TypeError) as error:
        parser.exit(1,f'K02 native verification rejected: {error}\n')
    print(json.dumps({'status':result['status'],'scope':SCOPE}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
