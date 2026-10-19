"""P0 controls on local fixtures; not Linux/SDK/Guest acceptance."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import types
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cow_p0_tested', HERE / 'cow_p0.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Tests(unittest.TestCase):
    def setUp(self):
        self.root = HERE.parent / ('.p0-' + uuid.uuid4().hex[:7])
        self.root.mkdir(mode=0o755)
        self.scope = patch.object(p, 'ROOT', self.root)
        self.scope.start()

    def tearDown(self):
        self.scope.stop()
        assert self.root.resolve().parent == HERE.parent.resolve()
        shutil.rmtree(self.root)

    def read(self, path, limit=p.LIMIT):
        path = p.safe(path)
        raw = path.read_bytes()
        p.require(len(raw) <= limit, 'Input exceeds read limit')
        return raw

    def test_smaps_keeps_private_anonymous_and_separate_hugetlb(self):
        result = p.parse_smaps('1000-2000 rw-p 0000 00:00 0\nRss: 12 kB\nPss: 8 kB\nAnonymous: 4 kB\nPrivate_Dirty: 4 kB\nKernelPageSize: 64 kB\n2000-3000 rw-p 0000 00:00 0\nRss: 8 kB\nPss: 8 kB\nPrivate_Hugetlb: 2048 kB\n')
        self.assertEqual(result['bytes']['Rss'], 20 * 1024)
        self.assertEqual(result['bytes']['Anonymous'], 4096)
        self.assertEqual(result['bytes']['Private_Hugetlb'], 2048 * 1024)
        self.assertEqual(result['reported_page_sizes_bytes'], [65536])
        self.assertEqual(result['vma_count'], 2)
        self.assertEqual(result['scope'], 'whole_process_not_guest_ram')

    def test_catalog_separates_memory_rootfs_and_withholds_sensitive_fields(self):
        digest = 'sha256:' + 'a' * 64
        record = {'id': 'snapshot1', 'committed': {'context': {'env': 'private'},
                  'memory_layers': [{'digest': digest, 'size': 512}],
                  'rootfs_layers': [{'External': {'digest': digest, 'size': 4096,
                                                  'repo_blob_url': 'https://secret.invalid/token'}}]}}
        with patch.object(p, 'file_meta', return_value={'available': True}):
            row = p.catalog_projection(self.root / 'repo/catalog/records/snapshot1.json', record)
        self.assertEqual([x['kind'] for x in row['layers']], ['memory', 'rootfs'])
        self.assertNotIn('private', json.dumps(row))
        self.assertNotIn('secret.invalid', json.dumps(row))
        self.assertFalse(row['content_hashes_verified'])

    def test_inventory_does_not_read_layer_contents_or_other_json(self):
        state = self.root / 'deployment/state'
        state.mkdir(parents=True)
        (state / 'image.json').write_text(json.dumps({'lowers': [{'file': 'base.bin'}],
            'upper': {'data': 'upper.bin'}, 'auth': 'secret'}))
        (state / 'base.bin').write_bytes(b'do not read')
        (state / 'credentials.json').write_text('secret')
        read_paths = []
        def reader(path, limit=p.LIMIT):
            read_paths.append(path.name)
            return self.read(path, limit)
        with patch.object(p, 'read_file', reader), patch.object(p, 'file_meta', return_value={'available': True}):
            result = p.layer_inventory(self.root / 'deployment')
        self.assertEqual(read_paths, ['image.json'])
        self.assertEqual(len(result['configs']), 1)
        self.assertFalse(result['configs'][0]['lowers'][0]['digest_verified'])
        self.assertNotIn('secret', json.dumps(result))

    def test_oversize_metadata_is_reported_not_silently_empty(self):
        state = self.root / 'deployment/state'
        state.mkdir(parents=True)
        (state / 'image.json').write_bytes(b' ' * (p.LIMIT + 1))
        with patch.object(p, 'read_file', self.read):
            result = p.layer_inventory(self.root / 'deployment')
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['errors']), 1)

    def test_paths_cannot_escape_workspace(self):
        with self.assertRaises(RuntimeError):
            p.safe(self.root.parent / 'outside')
        self.assertFalse(p.file_meta(self.root.parent / 'outside')['available'])

    def test_api_whitelist_and_pagination_never_forward_tokens(self):
        response = types.SimpleNamespace(status=200,
            read=lambda n: json.dumps([{'templateID': 't1', 'buildStatus': 'ready',
                                       'envVars': {'SECRET': 'dont-print'}}]).encode(),
            getheader=lambda key: 'private-next-page')
        connection = unittest.mock.Mock()
        connection.getresponse.return_value = response
        with patch.object(p, 'read_file', return_value=b'e2b_keep_private'), \
                patch.object(p.http.client, 'HTTPConnection', return_value=connection):
            result = p.api_inventory(self.root, 18080, '/v2/templates', ('templateID', 'buildStatus'))
        self.assertFalse(result['complete'])
        self.assertNotIn('dont-print', json.dumps(result))
        self.assertNotIn('private-next-page', json.dumps(result))
        self.assertEqual(connection.request.call_args.args[:2], ('GET', '/v2/templates'))
        connection.close.assert_called_once()
        with self.assertRaises(RuntimeError):
            p.api_inventory(self.root, 18080, '/sandboxes', ())

    def test_failure_does_not_dump_subprocess_or_http_response(self):
        error = ValueError('token=private')
        self.assertNotIn('private', json.dumps(p.failure(error)))
        self.assertEqual(p.failure(PermissionError(13, 'denied'))['errno'], 13)

    def test_health_failure_report_is_retained_and_never_repairs_proxy(self):
        base = self.root / 'deployments/agentenv-ub-b019f27'
        libexec = base / 'libexec'
        libexec.mkdir(parents=True)
        launcher = libexec / 'deploy_b_ub.py'
        launcher.write_text('# fixture')
        receipt = {'node': 'node-b', 'launcher': str(launcher),
                   'launcher_sha256': p.hashlib.sha256(launcher.read_bytes()).hexdigest()}
        (base / 'installation.json').write_text(json.dumps(receipt))
        report = {'status': 'STOPPED_B_UB_HEALTH', 'error': 'proxy absent'}
        def run(args, **kwargs):
            self.assertEqual(args[-2:], ['health', '--post-disconnect'])
            kwargs['stdout'].write(('BEGIN_RETURN_REPORT\n' + json.dumps(report) + '\nEND_RETURN_REPORT').encode())
            return types.SimpleNamespace(returncode=1)
        with patch.object(p, 'read_file', self.read), patch.object(p.subprocess, 'run', run):
            result = p.service_health('node-b', self.root)
        self.assertFalse(result['verified'])
        self.assertEqual(result['report'], report)


if __name__ == '__main__':
    unittest.main(verbosity=2)
