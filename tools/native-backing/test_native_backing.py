import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
import shutil
import uuid

spec = importlib.util.spec_from_file_location('native_backing', Path(__file__).with_name('native_backing.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class ContractTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / '.test-output'
        parent.mkdir(exist_ok=True)
        self.root = parent / uuid.uuid4().hex
        self.root.mkdir()
        def cleanup():
            target = self.root.resolve()
            if target.parent != parent.resolve():
                raise ValueError('Test cleanup escaped its own directory')
            shutil.rmtree(target)
        self.addCleanup(cleanup)
        self.source = self.root / 'image.json'
        self.source.write_text(json.dumps({'lowers': [{'digest': 'sha256:' + 'a' * 64,
                                                       'size': 123, 'file': '/node-a/base'}]}))

    def args(self, kind, images, budget):
        return argparse.Namespace(kind=kind, source=str(self.source), image=list(map(str, images)),
                                  socket='/tmp/native-test/provider.sock', max_bytes=budget,
                                  output=str(self.root / 'output'))

    def test_identity_is_path_independent_and_layout_bound(self):
        first = native.image_identity(self.source, 4096)
        self.source.write_text(self.source.read_text().replace('/node-a/base', '/node-b/layer'))
        self.assertEqual(first, native.image_identity(self.source, 4096))
        self.assertNotEqual(first, native.image_identity(self.source, 8192))
        expected = b'[4096,[{"digest":"sha256:' + b'a' * 64 + b'","size":123}]]'
        self.assertEqual(first, 'sha256:' + hashlib.sha256(expected).hexdigest())

    def test_missing_identity_is_not_treated_as_empty_image(self):
        self.source.write_text('{"lowers":[{"size":4096,"digest":""}]}')
        with self.assertRaises(ValueError):
            native.image_identity(self.source, 4096)

    def test_mutable_upper_cannot_be_hidden_by_source_binding(self):
        config = json.loads(self.source.read_text())
        config['upper'] = {'data': 'private.data'}
        self.source.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            native.image_identity(self.source, 4096)

    def test_memory_binding_is_full_linear_image_not_stored_length(self):
        image = self.root / 'linear.raw'
        image.write_bytes(bytes(range(256)) * 16)
        native.prepare(self.args('memory', [image], 4096))
        binding = json.loads((self.root / 'output/binding.json').read_text())
        self.assertEqual(binding['backing']['bytes'], 4096)
        self.assertEqual(binding['memoryImage'], native.image_identity(self.source, 4096))
        self.assertEqual(binding['backing']['sha256'], native.digest_file(image)[0])

    def test_memory_budget_rejects_before_activation(self):
        image = self.root / 'linear.raw'
        image.write_bytes(b'x' * 8192)
        with self.assertRaises(ValueError):
            native.prepare(self.args('memory', [image], 4096))
        self.assertFalse((self.root / 'output/binding.json').exists())

    def test_rootfs_alignment_and_budget(self):
        image = self.root / 'filesystem.erofs'
        image.write_bytes(b'x' * 4096)
        with self.assertRaises(ValueError):
            native.prepare(self.args('rootfs', [image], 4096))

    def test_existing_output_is_never_overwritten(self):
        output = self.root / 'output'
        output.mkdir()
        sentinel = output / 'binding.json'
        sentinel.write_text('preserve')
        with self.assertRaises(FileExistsError):
            native.prepare(self.args('memory', [], 4096))
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_socket_name_must_fit_linux_unix_limit(self):
        image = self.root / 'linear.raw'
        image.write_bytes(b'x' * 4096)
        for path in ('relative.sock', '/' + 'a' * 108):
            with self.assertRaises(ValueError):
                native.make_spec(image, path)

    def test_negative_or_boolean_sizes_cannot_bypass_fixture_budget(self):
        image = self.root / 'linear.raw'
        image.write_bytes(b'x' * 4096)
        spec = native.make_spec(image, '/tmp/native-test/provider.sock')
        for bad in (-4096, True, 0):
            invalid = dict(spec, bytes=bad)
            with self.assertRaises(ValueError):
                native.validate_catalog({'version': 1, 'objects': [{'backing': invalid}]}, spec['socket'], 4096)

    def test_duplicate_catalog_rejected_before_any_allocation(self):
        image = self.root / 'linear.raw'
        image.write_bytes(b'x' * 4096)
        spec = native.make_spec(image, '/tmp/native-test/provider.sock')
        entry = {'backing': spec, 'path': str(image)}
        with self.assertRaises(ValueError):
            native.validate_catalog({'version': 1, 'objects': [entry, entry]}, spec['socket'], 8192)

    def test_catalog_budget_uses_all_validated_objects(self):
        image = self.root / 'linear.raw'
        image.write_bytes(b'x' * 4096)
        spec = native.make_spec(image, '/tmp/native-test/provider.sock')
        other = dict(spec, objectId='second')
        catalog = {'version': 1, 'objects': [{'backing': spec}, {'backing': other}]}
        with self.assertRaises(ValueError):
            native.validate_catalog(catalog, spec['socket'], 4096)

    def test_framing_rejects_oversized_and_truncated_messages(self):
        # Socketpair is supported on Windows too; this exercises actual I/O.
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.sendall(struct.pack('>I', 4097))
        with self.assertRaises(ValueError):
            native.receive_json(b)
        a.sendall(struct.pack('>I', 12) + b'{}')
        a.shutdown(socket.SHUT_WR)
        with self.assertRaises(EOFError):
            native.receive_json(b)


if __name__ == '__main__':
    unittest.main()
