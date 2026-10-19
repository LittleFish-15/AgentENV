"""Exact-source/offline entry tests. No Cargo build, SDK or remote host calls."""
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import types
import unittest
import uuid

DIRECTORY = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('make_build_single', DIRECTORY / 'make_build_single.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class BuildSingleTests(unittest.TestCase):
    def setUp(self):
        self.repo = DIRECTORY.parents[1]
        self.path = self.repo / ('.ub-build-unit-' + uuid.uuid4().hex[:12])
        self.path.mkdir(mode=0o755)
        self.module = types.ModuleType('build_entry')
        self.module.__file__ = str(self.path / 'build_modified_a.py')
        text = (DIRECTORY / 'build_single_entry.py.in').read_text().replace('@PAYLOAD@', '{}', 1)
        exec(compile(text, self.module.__file__, 'exec'), self.module.__dict__)
        self.module.ROOT = self.path
        (self.path / 'src').mkdir()

    def tearDown(self):
        assert self.path.resolve().is_relative_to(self.repo.resolve())
        shutil.rmtree(self.path)

    def metadata(self, data, mode='100644'):
        return {'mode': mode, 'oid': self.module.object_id('blob', data), 'size': len(data)}

    def archive(self, data, metadata, extra=()):
        path = self.path / 'AgentENV-ae9c626.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, content in data.items():
                info = tarfile.TarInfo('pclin1212-AgentENV-ae9c626/' + name)
                if metadata[name]['mode'] == '120000':
                    info.type = tarfile.SYMTYPE
                    info.linkname = content.decode()
                    archive.addfile(info)
                else:
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            for info in extra:
                archive.addfile(info, io.BytesIO(b''))
        return path

    def fixture(self):
        base = {'old.txt': b'baseline\n'}
        final = {'old.txt': b'modified\n', 'new.py': b'print("fixture")\n'}
        before = {name: self.metadata(data) for name, data in base.items()}
        after = {name: self.metadata(data) for name, data in final.items()}
        git_dir = self.path / 'fixture-objects'
        git_dir.mkdir()
        tree = self.module.git_tree(git_dir, final, after)
        raw = 'tree ' + tree + '\nauthor Fixture <fixture@local.invalid> 1 +0000\ncommitter Fixture <fixture@local.invalid> 1 +0000\n\nfixture\n'
        payload = {'base_commit': 'a' * 40, 'source_commit': self.module.object_id('commit', raw.encode()),
                   'source_tree': tree, 'commit_raw': raw, 'files': before,
                   'updates': {name: dict(after[name], text=data.decode()) for name, data in final.items()}}
        self.archive(base, before)
        return payload

    def test_real_baseline_and_tip_reconstruct_the_actual_git_tree(self):
        payload = g.payload_at(g.git('rev-parse', 'HEAD').decode().strip())
        archive = self.repo.parents[1] / 'AgentENV-ae9c626.tar.gz'
        # The archived upstream source is an external read-only local fixture.
        previous_root = self.module.ROOT
        self.module.ROOT = self.repo.parents[1]
        try:
            base = self.module.read_archive(archive, payload['files'])
        finally:
            self.module.ROOT = previous_root
        data, files = self.module.desired_tree(base, payload['files'], payload['updates'])
        git_dir = self.path / 'real-objects'
        git_dir.mkdir()
        self.assertEqual(self.module.git_tree(git_dir, data, files), payload['source_tree'])
        self.assertEqual(self.module.object_id('commit', payload['commit_raw'].encode()), payload['source_commit'])

    def test_materialization_is_separate_and_uses_exact_commit(self):
        payload = self.fixture()
        original = (self.path / 'AgentENV-ae9c626.tar.gz').read_bytes()
        target, origin, reused = self.module.prepare_source(payload)
        self.assertFalse(reused)
        self.assertEqual((target / 'old.txt').read_bytes(), b'modified\n')
        self.assertEqual((target / 'new.py').read_bytes(), b'print("fixture")\n')
        actual = subprocess.check_output(['git', '-C', str(target), 'rev-parse', 'HEAD']).decode().strip()
        self.assertEqual(actual, payload['source_commit'])
        self.assertEqual((self.path / 'AgentENV-ae9c626.tar.gz').read_bytes(), original)
        self.assertEqual((target / '.git/shallow').read_text().strip(), actual)

    def test_resume_keeps_prepared_sources_without_needing_original_input(self):
        payload = self.fixture()
        target, _, _ = self.module.prepare_source(payload)
        before = (target / 'old.txt').stat().st_mtime_ns
        (self.path / 'AgentENV-ae9c626.tar.gz').unlink()
        again, _, reused = self.module.prepare_source(payload)
        self.assertEqual(again, target)
        self.assertTrue(reused)
        self.assertEqual((target / 'old.txt').stat().st_mtime_ns, before)

    def test_modified_existing_independent_source_is_not_overwritten(self):
        payload = self.fixture()
        target, _, _ = self.module.prepare_source(payload)
        (target / 'old.txt').write_bytes(b'operator change\n')
        with self.assertRaises(ValueError):
            self.module.prepare_source(payload)
        self.assertEqual((target / 'old.txt').read_bytes(), b'operator change\n')

    def test_unknown_existing_source_directory_is_preserved(self):
        payload = self.fixture()
        target = self.path / 'src' / ('agentenv-ub-' + payload['source_commit'][:12])
        target.mkdir()
        (target / 'keep').write_bytes(b'keep')
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.module.prepare_source(payload)
        self.assertEqual((target / 'keep').read_bytes(), b'keep')

    def test_unsafe_paths_are_rejected(self):
        for path in ('../outside', '/etc/file', 'a/../file', '.git/config', 'bad\\file', 'a//b', 'a\0b', ''):
            with self.assertRaises(ValueError, msg=path):
                self.module.relative(path)

    def test_wrong_base_content_is_rejected_before_materialization(self):
        expected = {'file': self.metadata(b'original')}
        path = self.archive({'file': b'changed!'}, expected)
        with self.assertRaises(ValueError):
            self.module.read_archive(path, expected)

    def test_unknown_archive_member_and_symlink_are_rejected(self):
        files = {'file': self.metadata(b'data')}
        path = self.archive({'file': b'data'}, files, [tarfile.TarInfo('pclin1212-AgentENV-ae9c626/../outside')])
        with self.assertRaises(ValueError):
            self.module.read_archive(path, files)
        link = tarfile.TarInfo('pclin1212-AgentENV-ae9c626/file')
        link.type, link.linkname = tarfile.SYMTYPE, '/etc/passwd'
        path = self.archive({}, files, [link])
        with self.assertRaises(ValueError):
            self.module.read_archive(path, files)

    def test_generated_script_handles_bom_and_crlf_and_remains_source_only(self):
        payload = self.fixture()
        source = g.render(payload)
        delivered = ('\ufeff' + source.replace('\n', '\r\n')).encode()
        module = types.ModuleType('delivery')
        exec(compile(delivered, 'build_modified_a.py', 'exec'), module.__dict__)
        self.assertEqual(module.PAYLOAD, payload)
        self.assertNotIn('zipfile', source)
        self.assertNotIn('urllib.request', source)
        self.assertNotIn('base64', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
