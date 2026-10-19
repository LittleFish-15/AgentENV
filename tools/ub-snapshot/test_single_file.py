"""Single-file payload and entrypoint checks, without SDK calls."""
import ast
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import types
import unittest
import uuid
from unittest.mock import patch

DIRECTORY = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('make_single_file', DIRECTORY / 'make_single_file.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class SingleFileTests(unittest.TestCase):
    def setUp(self):
        self.repo = DIRECTORY.parents[1]
        self.path = self.repo / ('.ub-single-unit-' + uuid.uuid4().hex[:12])
        self.path.mkdir(mode=0o755)
        self.source = generator.render('a' * 40)
        self.module = types.ModuleType('single_entry_' + uuid.uuid4().hex)
        self.module.__file__ = str(self.path / 'ub_layer_once.py')
        exec(compile(self.source, self.module.__file__, 'exec'), self.module.__dict__)
        self.module.ROOT = self.path
        self.uid = self.path.stat().st_uid

    def tearDown(self):
        assert self.path.resolve().is_relative_to(self.repo.resolve())
        shutil.rmtree(self.path)

    def test_payloads_are_exact_actual_sources(self):
        self.assertEqual(set(self.module.PAYLOADS), {'bridge.cpp', 'ub_layer_broker.py', 'sdk_smoke.py'})
        for name, source in self.module.PAYLOADS.items():
            self.assertEqual(source, (DIRECTORY / name).read_text(encoding='utf-8'))
            if name.endswith('.py'):
                ast.parse(source)
        self.assertNotIn('zipfile', self.source)

    def test_script_survives_windows_bom_and_crlf_text_transfer(self):
        delivered = ('\ufeff' + self.source.replace('\n', '\r\n')).encode('utf-8')
        module = types.ModuleType('crlf_entry')
        exec(compile(delivered, 'ub_layer_once.py', 'exec'), module.__dict__)
        self.assertEqual(module.PAYLOADS, self.module.PAYLOADS)

    def test_preparation_creates_only_three_required_sources(self):
        directory = self.path / 'helpers'
        result = self.module.prepare_payloads(directory, self.uid)
        self.assertEqual(result, directory / 'sdk_smoke.py')
        self.assertEqual({p.name for p in directory.iterdir()}, set(self.module.PAYLOADS))
        for path in directory.iterdir():
            self.assertEqual(path.read_text(), self.module.PAYLOADS[path.name])

    def test_identical_existing_files_are_reused_without_rewriting(self):
        directory = self.path / 'helpers'
        self.module.prepare_payloads(directory, self.uid)
        before = {p.name: (p.stat().st_mtime_ns, p.stat().st_ino) for p in directory.iterdir()}
        self.module.prepare_payloads(directory, self.uid)
        after = {p.name: (p.stat().st_mtime_ns, p.stat().st_ino) for p in directory.iterdir()}
        self.assertEqual(before, after)

    def test_different_existing_source_is_preserved_and_blocks_execution(self):
        directory = self.path / 'helpers'
        self.module.prepare_payloads(directory, self.uid)
        target = directory / 'sdk_smoke.py'
        target.write_text('different source')
        with self.assertRaises(ValueError):
            self.module.prepare_payloads(directory, self.uid)
        self.assertEqual(target.read_text(), 'different source')

    def test_incomplete_old_source_is_not_overwritten(self):
        directory = self.path / 'helpers'
        directory.mkdir()
        target = directory / 'bridge.cpp'
        target.write_text('partial')
        with self.assertRaises(ValueError):
            self.module.prepare_payloads(directory, self.uid)
        self.assertEqual(target.read_text(), 'partial')

    def test_existing_source_bom_crlf_is_read_without_rewriting(self):
        directory = self.path / 'helpers'
        directory.mkdir()
        target = directory / 'bridge.cpp'
        delivered = ('\ufeff' + self.module.PAYLOADS['bridge.cpp'].replace('\n', '\r\n')).encode('utf-8')
        target.write_bytes(delivered)
        self.module.prepare_payloads(directory, self.uid)
        self.assertEqual(target.read_bytes(), delivered)

    def test_unexpected_helper_cache_is_preserved_and_rejected(self):
        directory = self.path / 'helpers'
        directory.mkdir()
        unknown = directory / '__pycache__'
        unknown.mkdir()
        with self.assertRaises(ValueError):
            self.module.prepare_payloads(directory, self.uid)
        self.assertTrue(unknown.is_dir())

    def test_path_outside_experiment_root_is_rejected(self):
        with self.assertRaises(ValueError):
            self.module.checked(self.path.parent / 'outside')
        with self.assertRaises(ValueError):
            self.module.checked(self.path / 'helpers/../file')

    def test_importing_single_file_does_not_create_sdk_or_experiment_state(self):
        self.assertEqual(list(self.path.iterdir()), [])
        self.assertEqual(self.module.SOURCE_COMMIT, 'a' * 40)


if __name__ == '__main__':
    unittest.main(verbosity=2)
