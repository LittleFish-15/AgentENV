"""Smoke transfer/receipt guards without calling any installed SDK."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
import uuid
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('sdk_smoke', Path(__file__).with_name('sdk_smoke.py'))
s = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = s
spec.loader.exec_module(s)
b = s.b


class SmokeGuards(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[2]
        self.path = self.root / ('.ub-smoke-unit-' + uuid.uuid4().hex[:12])
        self.path.mkdir(mode=0o755)
        self.replica = b.Replica(str(self.path / 'b.sock'), 'jwk_aenv_' + 'a' * 32,
                                 'b' * 32, 'sha256:' + 'c' * 64, b.CHUNK * 3 // 2, b.ALIGN)

    def tearDown(self):
        assert self.path.resolve().is_relative_to(self.root)
        shutil.rmtree(self.path)

    def token(self, replica):
        return base64.urlsafe_b64encode(json.dumps(b.asdict(replica)).encode()).decode()

    def test_peer_uses_exact_owner_identity_without_creating_an_object(self):
        parsed = s.peer_replica(self.token(self.replica))
        self.assertEqual(parsed, self.replica)

    def test_peer_rejects_expanded_budget_or_wrong_payload(self):
        for replica in (b.replace(self.replica, mappingBytes=2 * b.ALIGN),
                        b.replace(self.replica, fileBytes=1),
                        b.replace(self.replica, objectName='another-users-object')):
            with self.assertRaises(ValueError):
                s.peer_replica(self.token(replica))

    def test_peer_rejects_truncated_or_unbounded_token(self):
        for token in ('', 'x' * 4097, '???', self.token(self.replica)[:-7]):
            with self.assertRaises((ValueError, UnicodeError, json.JSONDecodeError)):
                s.peer_replica(token)

    def test_unresolved_receipt_is_preserved_and_blocks_new_random_names(self):
        reports = self.path / 'relay/reports'
        output = reports / 'node-a-ub-layer-sdk-old'
        output.mkdir(parents=True)
        pending = self.path / 'pending.json'
        record = {'version': 1, 'node': 'node-a', 'uid': 1204,
                  'report_directory': str(output), 'state': 'OWNERSHIP_UNRESOLVED'}
        b.atomic_json(pending, record)
        before = pending.read_bytes()
        with patch.object(b, 'ROOT', self.path), self.assertRaises(ValueError):
            s.previous_guard(pending, 'node-a')
        self.assertEqual(pending.read_bytes(), before)

    def test_confirmed_release_allows_next_run_but_wrong_node_never_does(self):
        output = self.path / 'relay/reports/node-b-ub-layer-sdk-old'
        output.mkdir(parents=True)
        pending = self.path / 'pending.json'
        record = {'version': 1, 'node': 'node-b', 'uid': 1204,
                  'report_directory': str(output), 'state': 'PEER_RELEASED'}
        b.atomic_json(pending, record)
        with patch.object(b, 'ROOT', self.path):
            self.assertEqual(s.previous_guard(pending, 'node-b'), record)
            with self.assertRaises(ValueError):
                s.previous_guard(pending, 'node-a')


if __name__ == '__main__':
    unittest.main(verbosity=2)
