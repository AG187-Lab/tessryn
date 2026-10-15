"""Bind full matrix acceptance to local Git and the checked current-host tools.

These checks validate provenance declarations, not a reproduction of compilation.
Full verification needs the corresponding pinned toolchain installed on this host;
an archive's self-asserted foreign-host toolchain is never a trust anchor.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

from tools.build_kernel import compiler_profile
from tools.build_k02_matrix import PROFILE, case_flags, selected_cases
from tools.build_k02_native import compile_flags
from tools.g03.process import run_bounded

ROOT = Path(__file__).resolve().parents[1]
MAX_FILES = 8192
MAX_BLOB_BYTES = 16 << 20
MAX_TREE_BYTES = 256 << 20
COMPILER_SOURCES = (
    'interfaces/abi-v1/native.rs', 'kernel-core/boot_inventory.rs',
    'kernel-core/capabilities.rs', 'kernel-core/frames.rs', 'kernel-core/lib.rs',
    'kernel/cpu.rs', 'kernel/diagnostics.rs', 'kernel/entry.S', 'kernel/framebuffer.rs',
    'kernel/k02.rs', 'kernel/k02_cpu.rs', 'kernel/k02_entry.S', 'kernel/k02_matrix.rs',
    'kernel/k02_matrix_protection.rs', 'kernel/k02_matrix_requests.rs',
    'kernel/k02_memory.rs', 'kernel/k02_paging.rs', 'kernel/k02_sha256.rs',
    'kernel/main.rs', 'kernel/paging.rs', 'kernel/uefi.rs',
)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def runtime_paths():
    # Lazy import keeps the verifier/runner integration free of import cycles.
    from tools.run_k02_matrix import EVALUATOR_FILES
    return tuple(sorted(set((*EVALUATOR_FILES, 'tools/k02_matrix_provenance.py'))))


def regular_source(name):
    """Read reviewed bytes through directory descriptors, never source aliases."""
    relative = PurePosixPath(name)
    require(type(name) is str and relative.as_posix() == name and not relative.is_absolute()
            and bool(relative.parts) and all(part not in ('', '.', '..') for part in relative.parts)
            and not any(character in name for character in ('\\', '\r', '\n', '\t')),
            'matrix provenance source path is invalid')
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in relative.parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        child = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(child, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_BLOB_BYTES,
                    'matrix reviewed source must be a bounded regular file')
            data = stream.read(MAX_BLOB_BYTES + 1)
            require(len(data) <= MAX_BLOB_BYTES, 'matrix reviewed source exceeds its bound')
            return data
    except OSError as error:
        raise ValueError('matrix reviewed source is unavailable or aliases another path') from error
    finally:
        os.close(descriptor)


def git_bytes(arguments, limit=8 << 20):
    """Read local Git objects with bounded output and no implicit remote fetch."""
    command = ['/usr/bin/env', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
               'GIT_NO_REPLACE_OBJECTS=1', 'GIT_NO_LAZY_FETCH=1', 'GIT_TERMINAL_PROMPT=0',
               '/usr/bin/git', '-c', 'protocol.allow=never', '--no-replace-objects', *arguments]
    result = run_bounded(command, ROOT, 15, limit)
    require(result.status == 'completed' and result.returncode == 0,
            'matrix source revision is unavailable, unrelated, or exceeds local Git bounds')
    return result.stdout


def committed_sources(revision):
    require(type(revision) is str and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', revision),
            'matrix source revision must be a complete Git object identity')
    require(git_bytes(['cat-file', '-t', revision]).strip() == b'commit',
            'matrix source identity does not name a commit')
    git_bytes(['merge-base', '--is-ancestor', revision, 'HEAD'])
    entries = git_bytes(['ls-tree', '-r', '-z', '--full-tree', revision]).split(b'\0')
    require(entries[-1] == b'' and len(entries) <= MAX_FILES + 1,
            'matrix committed source tree exceeds its file bound')
    sources = {}
    cache = {}
    total = 0
    for entry in entries[:-1]:
        try:
            metadata, name_bytes = entry.split(b'\t', 1)
            mode, kind, object_id = metadata.split(b' ')
            name = name_bytes.decode('utf-8')
        except (ValueError, UnicodeError) as error:
            raise ValueError('matrix committed source tree is malformed') from error
        relative = PurePosixPath(name)
        require(relative.as_posix() == name and not relative.is_absolute() and bool(relative.parts)
                and all(part not in ('', '.', '..') for part in relative.parts)
                and not any(character in name for character in ('\\', '\r', '\n', '\t'))
                and name not in sources, 'matrix committed source path is invalid')
        require(mode in (b'100644', b'100755') and kind == b'blob'
                and re.fullmatch(rb'[0-9a-f]{40}|[0-9a-f]{64}', object_id),
                'matrix committed sources require regular files, without symlinks or submodules')
        if object_id not in cache:
            cache[object_id] = git_bytes(['cat-file', 'blob', object_id.decode('ascii')], MAX_BLOB_BYTES)
        data = cache[object_id]
        total += len(data)
        require(total <= MAX_TREE_BYTES, 'matrix committed source tree exceeds its byte bound')
        sources[name] = (mode.decode('ascii'), data)
    return sources


def validate_source(manifest):
    source = manifest.get('source')
    require(type(source) is dict and set(source) == {'revision', 'dirty', 'tree_sha256', 'snapshot_algorithm'}
            and source['dirty'] is False and source['snapshot_algorithm'] == 'git-worktree-v2'
            and type(source['tree_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', source['tree_sha256']),
            'matrix full acceptance requires a clean git-worktree-v2 source identity')
    sources = committed_sources(source['revision'])
    tree = hashlib.sha256()
    for name, (mode, data) in sorted(sources.items()):
        tree.update(name.encode() + b'\0' + mode.encode() + b'\0' + digest(data).encode() + b'\0')
    require(tree.hexdigest() == source['tree_sha256'], 'matrix committed source snapshot hash differs')
    files = manifest.get('source_files')
    require(type(files) is dict and set(files) == set(COMPILER_SOURCES),
            'matrix exact compiler dependency set differs')
    for name, expected in files.items():
        require(name in sources and type(expected) is str and re.fullmatch(r'[0-9a-f]{64}', expected)
                and digest(sources[name][1]) == expected,
                'matrix compiler dependency differs from committed source')
    require(manifest.get('source_files_sha256') == digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()),
            'matrix compiler dependency map hash differs')
    runtime = runtime_paths()
    for name in runtime:
        require(name in sources and regular_source(name) == sources[name][1],
                'matrix source revision evaluator or locks differ from reviewed checkout')
    return {'revision': source['revision'], 'tree_sha256': tree.hexdigest(),
            'compiler_dependencies': len(files), 'reviewed_runtime_files': len(runtime)}


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError('matrix toolchain metadata must be finite JSON') from error


def expected_commands(profile, cases):
    prefix = ROOT / 'build/uefi'
    linker = Path(profile['linker'])
    require(linker.is_relative_to(prefix), 'matrix checked linker is outside the pinned UEFI toolchain')
    public_linker = 'rust-toolchain/' + linker.relative_to(prefix).as_posix()
    commands = {}
    for name in ('core', *cases):
        core = name == 'core'
        src = 'kernel-core/lib.rs' if core else 'kernel/main.rs'
        directory = 'k02-matrix-build' + ('' if core else '/' + name)
        emits = 'link,dep-info=' + directory + '/' + name + '.d'
        if not core:
            emits += ',obj=' + directory + '/kernel.obj'
        command = [src, *compile_flags(profile, core), *([] if core else case_flags(name)),
                   '--emit=' + emits, '--remap-path-prefix=rust-toolchain=rust-toolchain',
                   '--remap-path-prefix=k02-matrix-build=k02-matrix-build',
                   '--remap-path-prefix=tessryn=tessryn']
        if not core:
            command += ['-Clinker=' + public_linker, '--extern',
                        'tessryn_owned_memory=k02-matrix-build/libtessryn_owned_memory.rlib']
        command += ['-o', directory + ('/libtessryn_owned_memory.rlib' if core else '/BOOTX64.EFI')]
        commands[name] = command
    return commands


def validate_toolchain(manifest):
    require(canonical(manifest.get('profile')) == canonical(PROFILE), 'matrix native target profile differs')
    cases = manifest.get('cases')
    require(type(cases) is list and bool(cases) and all(type(name) is str for name in cases)
            and list(selected_cases(cases)) == cases, 'matrix toolchain case list differs')
    try:
        profile = compiler_profile()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise ValueError('matrix full verification needs the checked current-host UEFI toolchain') from error
    require(canonical(manifest.get('toolchain')) == canonical(profile['toolchain']),
            'matrix archive toolchain differs from checked current-host UEFI toolchain')
    require(canonical(manifest.get('compile_commands')) == canonical(expected_commands(profile, cases)),
            'matrix compiler, linker, target, flags or source remapping differs')
    return profile['toolchain']
