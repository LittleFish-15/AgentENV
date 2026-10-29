import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import zlib

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prepare', HERE / 'round002_prepare.py')
prepare = importlib.util.module_from_spec(spec); spec.loader.exec_module(prepare)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.root = (HERE.parents[1] / 't' / ('r2-' + uuid.uuid4().hex[:8])).resolve()
        self.root.mkdir(parents=True, mode=0o755)
        prepare.ROOT = self.root

    def put(self, name, data):
        p = self.root / name; p.parent.mkdir(parents=True, exist_ok=True, mode=0o755); p.write_bytes(data)
        return p

    def test_expected_digest_is_not_reported_as_fresh_hash(self):
        p = self.put('layer', b'payload')
        row = prepare.file_facts(p, 7, hashlib.sha256(b'payload').hexdigest())
        self.assertEqual(row['hashEvidence'], 'expected_reference_not_recomputed_this_round')

    def test_fresh_hash_mismatch_stops(self):
        p = self.put('artifact', b'actual')
        with self.assertRaises(RuntimeError):
            prepare.file_facts(p, 6, '0' * 64, True)

    def test_source_path_cannot_read_credentials_or_escape(self):
        p = self.put('.ssh/api-key', b'do-not-read')
        with self.assertRaises(RuntimeError): prepare.source_path(p)
        with self.assertRaises(RuntimeError): prepare.source_path(self.root / '..' / 'outside')

    def test_receiver_destination_escape_is_rejected(self):
        for value in ('../outside', '/etc/file', 'dir/../file', 'a\\b'):
            with self.subTest(value=value), self.assertRaises(RuntimeError): prepare.relative_name(value)

    def test_export_manifest_deduplicates_content_and_does_not_claim_transfer(self):
        a = self.put('artifact-a', b'same'); b = self.put('artifact-b', b'same')
        selected = []
        for p, destination in ((a, 'artifacts/original/file'), (b, 'artifacts/dax/file')):
            selected.append({'sourcePath': str(p), 'bytes': 4, 'sha256': None,
                'placements': [{'node': 'node-c', 'path': destination, 'executable': False}]})
        row = prepare.compile_export({'files': selected, 'maxLogicalBytes': 100, 'sessionId': 'fixture-session'}, 'fixture-boot')
        self.assertEqual(len(row['objects']), 1)
        self.assertEqual(row['uniqueContentBytes'], 4)
        self.assertEqual(row['logicalSelectedBytes'], 8)
        self.assertFalse(row['allPayloadContentHashesVerified'])
        self.assertFalse(row['transferExecuted'])

    def test_duplicate_receiver_path_is_not_overwritten(self):
        p = self.put('file', b'1')
        item = {'sourcePath': str(p), 'bytes': 1, 'sha256': hashlib.sha256(b'1').hexdigest(),
                'placements': [{'node': 'node-c', 'path': 'same/path', 'executable': False}]}
        with self.assertRaises(RuntimeError):
            prepare.compile_export({'files': [item, item], 'maxLogicalBytes': 100, 'sessionId': 'fixture'}, 'boot')

    def test_original_runtime_secret_values_are_not_serialized(self):
        raw = (f'deps_path = {json.dumps(str(self.root))}\n[api]\napi_key="DO_NOT_REPORT_SECRET"\n').encode()
        p = self.put('runtime.toml', raw)
        row = prepare.configuration_hints([{'path': str(p), 'sha256': hashlib.sha256(raw).hexdigest()}])
        self.assertNotIn('DO_NOT_REPORT_SECRET', json.dumps(row))
        self.assertFalse(row[0]['originalConfigIncludedInTransfer'])

    def test_private_key_is_not_read_or_uploaded(self):
        private = self.put('id_ed25519', b'PRIVATE_TEST_BYTES_NEVER_READ')
        encoded = base64.b64encode(struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + b'x' * 32).decode()
        public = self.put('id_ed25519.pub', ('ssh-ed25519 ' + encoded + '\n').encode())
        original_stat = Path.stat; original_text = Path.read_text
        def fake_stat(path, *args, **kwargs):
            s = original_stat(path, *args, **kwargs)
            if path == private:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
            return s
        def read_public_only(path, *args, **kwargs):
            self.assertNotEqual(path, private)
            return original_text(path, *args, **kwargs)
        with patch.object(Path, 'stat', fake_stat), patch.object(Path, 'read_text', read_public_only):
            text = prepare.verify_key_files(private, public, owner=0)
        self.assertEqual(text, 'ssh-ed25519 ' + encoded)
        self.assertNotIn('PRIVATE_TEST_BYTES', text)

    def test_kernel_reader_is_the_pinned_reviewed_source(self):
        raw = zlib.decompress(base64.b64decode(prepare.KERNEL_SOURCE_Z64, validate=True))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), prepare.KERNEL_SOURCE_SHA)


if __name__ == '__main__': unittest.main()
