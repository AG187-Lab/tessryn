"""SYNTHETIC local Git fixtures; no toolchain install or hardware execution."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import k02_matrix_provenance as provenance
from tools.build_k02_matrix import PROFILE


class SourceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.files = {name: ('SYNTHETIC ' + name + '\n').encode()
                      for name in {*provenance.COMPILER_SOURCES, *provenance.runtime_paths(), 'README.md', 'fixture.sh'}}
        for name, data in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.root / 'fixture.sh').chmod(0o755)
        self.git('init', '-q')
        self.revision = self.commit()
        self.binding = patch.object(provenance, 'ROOT', self.root)
        self.binding.start()
        self.addCleanup(self.binding.stop)

    def git(self, *arguments):
        result = subprocess.run(['/usr/bin/git', '-c', 'user.name=Synthetic Fixture',
                                 '-c', 'user.email=synthetic@example.invalid',
                                 '-c', 'commit.gpgsign=false', *arguments],
                                cwd=self.root, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10,
                                env={'PATH': os.defpath, 'LANG': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
                                     'GIT_CONFIG_GLOBAL': '/dev/null'})
        return result.stdout.decode().strip()

    def commit(self):
        self.git('add', '--all')
        self.git('commit', '-q', '--allow-empty', '-m', 'SYNTHETIC provenance fixture')
        return self.git('rev-parse', 'HEAD')

    def manifest(self):
        tree = hashlib.sha256()
        for name, data in sorted(self.files.items()):
            mode = '100755' if name == 'fixture.sh' else '100644'
            tree.update(name.encode() + b'\0' + mode.encode() + b'\0' + hashlib.sha256(data).hexdigest().encode() + b'\0')
        files = {name: hashlib.sha256(self.files[name]).hexdigest() for name in provenance.COMPILER_SOURCES}
        return {'source': {'revision': self.revision, 'dirty': False, 'snapshot_algorithm': 'git-worktree-v2',
                           'tree_sha256': tree.hexdigest()}, 'source_files': files,
                'source_files_sha256': hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}

    def test_git_blobs_and_executable_mode_reconstruct_exact_snapshot(self):
        result = provenance.validate_source(self.manifest())
        self.assertEqual(result['revision'], self.revision)
        self.assertEqual(result['compiler_dependencies'], 21)

    def test_later_evidence_commit_does_not_require_source_to_equal_head(self):
        manifest = self.manifest()
        (self.root / 'evidence').mkdir()
        (self.root / 'evidence/result.json').write_text('{"synthetic": true}\n')
        self.assertNotEqual(self.commit(), self.revision)
        self.assertEqual(provenance.validate_source(manifest)['revision'], self.revision)

    def test_dirty_partial_unavailable_and_wrong_snapshot_identities_reject(self):
        mutations = ({'dirty': True}, {'dirty': 0}, {'revision': self.revision[:12]},
                     {'revision': '0' * 40}, {'tree_sha256': 'a' * 64},
                     {'snapshot_algorithm': 'invented'})
        for changes in mutations:
            manifest = self.manifest()
            manifest['source'].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                provenance.validate_source(manifest)

    def test_unrelated_locally_available_revision_is_not_an_accepted_ancestor(self):
        manifest = self.manifest()
        self.git('checkout', '-q', '--orphan', 'unrelated')
        (self.root / 'README.md').write_bytes(b'SYNTHETIC unrelated root tree\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'unrelated'):
            provenance.validate_source(manifest)

    def test_self_consistent_but_false_dependency_hashes_and_omissions_reject(self):
        for operation in ('alter', 'omit', 'traversal'):
            manifest = self.manifest()
            files = manifest['source_files']
            if operation == 'alter':
                files['kernel/main.rs'] = 'a' * 64
            elif operation == 'omit':
                files.pop('kernel/k02_memory.rs')
            else:
                files['../foreign.rs'] = 'a' * 64
            manifest['source_files_sha256'] = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                provenance.validate_source(manifest)

    def test_current_evaluator_and_locks_must_match_historical_revision(self):
        for name in ('tools/k02_matrix_provenance.py', 'toolchain.lock.json', 'uefi-toolchain.lock.json'):
            target = self.root / name
            original = target.read_bytes()
            target.write_bytes(original + b'changed\n')
            try:
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'evaluator or locks differ'):
                    provenance.validate_source(self.manifest())
            finally:
                target.write_bytes(original)

    def test_committed_symlink_is_rejected_even_outside_dependency_set(self):
        (self.root / 'alias').symlink_to('README.md')
        revision = self.commit()
        manifest = self.manifest()
        manifest['source']['revision'] = revision
        with self.assertRaisesRegex(ValueError, 'without symlinks'):
            provenance.validate_source(manifest)

    def test_reviewed_source_symlink_cannot_supply_current_runtime_bytes(self):
        target = self.root / 'tools/k02_matrix_provenance.py'
        target.unlink()
        target.symlink_to('../README.md')
        with self.assertRaisesRegex(ValueError, 'aliases'):
            provenance.validate_source(self.manifest())

    def test_tree_file_blob_and_aggregate_bounds_fail_closed(self):
        for name, limit in (('MAX_FILES', 1), ('MAX_BLOB_BYTES', 1), ('MAX_TREE_BYTES', 1)):
            with self.subTest(bound=name), patch.object(provenance, name, limit), self.assertRaises(ValueError):
                provenance.validate_source(self.manifest())


class ToolchainProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.root = provenance.ROOT
        self.profile = {'compiler': self.root / 'build/uefi/bin/rustc',
                        'linker': self.root / 'build/uefi/lib/rustlib/synthetic-host/bin/rust-lld',
                        'toolchain': {'setup': {'host': 'SYNTHETIC', 'checked_lock': 'a' * 64},
                                      'rustc_version': 'SYNTHETIC rustc', 'linker_version': 'SYNTHETIC lld',
                                      'rust_flags': ['--edition=2024', '--target=x86_64-unknown-uefi',
                                                     '--crate-name=tessryn_kernel', '--crate-type=bin',
                                                     '-Cpanic=abort', '-Copt-level=1',
                                                     '-Clink-arg=/timestamp:0', '-Clink-arg=/debug:none']}}
        self.binding = patch.object(provenance, 'compiler_profile', return_value=self.profile)
        self.binding.start()
        self.addCleanup(self.binding.stop)

    def manifest(self):
        cases = ['kernel_isolation']
        return {'profile': copy.deepcopy(PROFILE), 'cases': cases,
                'toolchain': copy.deepcopy(self.profile['toolchain']),
                'compile_commands': provenance.expected_commands(self.profile, cases)}

    def test_checked_current_host_profile_and_exact_commands_are_accepted(self):
        self.assertEqual(provenance.validate_toolchain(self.manifest()), self.profile['toolchain'])

    def test_archive_cannot_self_assert_a_foreign_host_or_target(self):
        manifest = self.manifest()
        manifest['toolchain']['setup']['host'] = 'foreign-host'
        with self.assertRaisesRegex(ValueError, 'current-host'):
            provenance.validate_toolchain(manifest)
        manifest = self.manifest()
        manifest['profile']['cpu_count'] = True
        with self.assertRaisesRegex(ValueError, 'target profile'):
            provenance.validate_toolchain(manifest)

    def test_appended_overrides_foreign_linker_and_removed_flags_reject(self):
        for operation in ('retarget', 'linker', 'omit', 'extra_case'):
            manifest = self.manifest()
            commands = manifest['compile_commands']
            if operation == 'retarget':
                commands['core'].append('--target=x86_64-unknown-none')
            elif operation == 'linker':
                commands['kernel_isolation'] = [arg.replace('rust-toolchain/', 'foreign/') for arg in commands['kernel_isolation']]
            elif operation == 'omit':
                commands['core'].remove('-Cpanic=abort')
            else:
                commands['foreign'] = commands['core']
            with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, 'compiler, linker'):
                provenance.validate_toolchain(manifest)

    def test_unavailable_checked_profile_does_not_fall_back_to_archive_claim(self):
        for error in (ValueError('SYNTHETIC unavailable'), FileNotFoundError(), subprocess.CalledProcessError(1, 'synthetic')):
            with self.subTest(error=type(error).__name__), patch.object(provenance, 'compiler_profile', side_effect=error):
                with self.assertRaisesRegex(ValueError, 'checked current-host'):
                    provenance.validate_toolchain(self.manifest())


if __name__ == '__main__':
    unittest.main()
