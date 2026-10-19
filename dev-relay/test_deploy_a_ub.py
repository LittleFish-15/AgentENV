"""Local isolation/install checks; no actual SDK/systemd/device calls or services.

Windows fixtures substitute Unix ownership/mode checks, while exercising actual
inventory, hashes, file copies, config/credential generation and atomic writes.
"""
import asyncio
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import shutil
import socket
import stat
import sys
import tempfile
import types
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('a_ub_deploy_test', HERE / 'deploy_a_ub.py')
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.root = HERE.parent / ('.deploy-unit-' + uuid.uuid4().hex[:6])
        self.root.mkdir(mode=0o755)
        self.base = self.root / 'baseline'
        self.dest = self.root / 'modified'
        self.runtime = self.root / 'run'
        self.artifacts = self.root / 'artifacts'
        for path in (self.base, self.artifacts):
            path.mkdir()
        self.bin_hashes = {}
        for name in m.BINARIES:
            data = ('modified-' + name).encode()
            (self.artifacts / name).write_bytes(data)
            self.bin_hashes[name] = hashlib.sha256(data).hexdigest()
        deps = ('firecracker/1.15.1-patch-v3/firecracker', 'kernel/vmlinux-6.1.175/vmlinux.bin',
                'tools/0.1.1/tools.ext4', 'regctl/v0.11.5/regctl',
                'overlaybd/bin/overlaybd-create', 'overlaybd/bin/overlaybd-apply',
                'overlaybd/bin/overlaybd-commit', 'overlaybd/bin/overlaybd-resize')
        for relative in deps:
            self.file(self.base / 'deps' / relative, ('offline-' + relative).encode())
        for name in ('ip', 'iptables-save', 'iptables-restore', 'debugfs', 'mkfs.ext4', 'resize2fs', 'jq', 'curl', 'umoci', 'zstd'):
            self.file(self.base / 'native/bin' / name, ('native-' + name).encode())
        self.file(self.base / 'state/old-snapshot', b'original-business-state')
        self.file(self.base / 'config/api-key', b'original-private-key')
        self.file(self.base / 'logs/private.log', b'original-private-log')
        self.baseline_before = self.snapshot(self.base)
        self.calls = []
        self.original_mkdir = m.mkdir
        self.original_stable = m.stable_file
        self.original_is_dir = Path.is_dir
        self.original_read_text = Path.read_text
        self.original_stat = os.stat
        self.patches = [patch.object(m, 'ROOT', self.root), patch.object(m, 'BASE', self.base),
                        patch.object(m, 'D', self.dest), patch.object(m, 'RUNTIME', self.runtime),
                        patch.object(m, 'LAUNCHER', self.dest / 'libexec/deploy_a_ub.py'),
                        patch.object(m, 'ARTIFACTS', self.artifacts), patch.object(m, 'BINARIES', self.bin_hashes),
                        patch.object(m, 'safe', self.safe), patch.object(m, 'mkdir', self.directory),
                        patch.object(m, 'stable_file', self.stable), patch.object(m, 'baseline', return_value='1234'),
                        patch.object(m, 'no_caps'), patch.object(m, 'properties', return_value={'LoadState': 'not-found'}),
                        patch.object(m.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=8 * 1024**3)),
                        patch.object(m.shutil, 'which', return_value='/fixture/native/tool'),
                        patch.object(m, 'run', self.command),
                        patch.object(Path, 'is_char_device', return_value=True),
                        patch.object(Path, 'is_dir', lambda p: True if p.as_posix() == '/sys/module/ublk_drv' else self.original_is_dir(p)),
                        patch.object(Path, 'read_text', lambda p, *a, **k: 'fixture-boot' if p.as_posix() == '/proc/sys/kernel/random/boot_id' else self.original_read_text(p, *a, **k)),
                        patch.object(m.os, 'stat', self.file_stat),
                        patch.object(m.subprocess, 'Popen', side_effect=AssertionError('Installer must not start services/processes'))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        assert self.root.resolve().parent == HERE.parent.resolve()
        shutil.rmtree(self.root)

    def file(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def file_stat(self, path, *args, **kwargs):
        value = Path(path).as_posix() if not isinstance(path, int) else ''
        if value in ('/proc/self/ns/net', '/proc/self/ns/mnt'):
            return types.SimpleNamespace(st_ino=11 if value.endswith('net') else 12)
        return self.original_stat(path, *args, **kwargs)

    def snapshot(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}

    def safe(self, path, exists=False):
        path = Path(path)
        if not path.is_absolute() or not path.is_relative_to(self.root) or path.resolve() != path:
            raise RuntimeError('redirected/outside test workspace')
        if exists and not path.exists():
            raise RuntimeError('missing input')
        return path

    def directory(self, path):
        self.safe(path)
        path.mkdir(parents=True, exist_ok=True, mode=0o755)

    def stable(self, path, limit=512 * 1024**2):
        data, meta = self.original_stable(path, limit)
        if path == self.dest / 'config/api-key' and os.name == 'nt':
            meta = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
        return data, meta

    def command(self, command, env=None, timeout=25):
        self.calls.append([str(x) for x in command])
        if str(command[0]) == '/usr/bin/ldd':
            return 0, 'statically linked'
        if list(command[1:]) == ['--version']:
            return 0, 'aenv 0.2.2'
        raise AssertionError('Unexpected command during install: ' + str(command))

    def fake_port(self, occupied=False):
        class Port:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def bind(self, address):
                if occupied:
                    raise OSError('address in use')
        return patch.object(m.socket, 'socket', return_value=Port())

    def test_install_copies_dependencies_but_not_original_state_or_credentials(self):
        with self.fake_port():
            result = m.install()
        self.assertEqual(result['status'], 'A_UB_INSTALLED_AWAITING_NEW_UNIT_APPROVAL')
        self.assertFalse(result['runtime_started'])
        self.assertEqual(self.snapshot(self.base), self.baseline_before)
        self.assertFalse((self.dest / 'state/old-snapshot').exists())
        self.assertFalse((self.dest / 'logs/private.log').exists())
        self.assertNotEqual((self.dest / 'config/api-key').read_bytes(), b'original-private-key')
        self.assertTrue((self.dest / 'cli/bin/aenv-ub').is_file())
        self.assertFalse((self.dest / 'cli/bin/aenv').exists())
        self.assertIn('127.0.0.1:18081', (self.dest / 'cli/config/aenv/credentials').read_text())
        self.assertTrue((self.dest / 'deps/tools/0.1.1/tools.ext4').is_file())
        self.assertTrue(all(call[0] == '/usr/bin/ldd' or call[1:] == ['--version'] for call in self.calls))

    def test_unknown_existing_deployment_is_preserved(self):
        self.file(self.dest / 'unknown', b'keep')
        with self.fake_port(), self.assertRaises(RuntimeError):
            m.install()
        self.assertEqual((self.dest / 'unknown').read_bytes(), b'keep')
        self.assertFalse((self.dest / 'bin').exists())

    def test_occupied_new_port_does_not_create_deployment_or_stop_listener(self):
        with self.fake_port(occupied=True), self.assertRaises(OSError):
            m.install()
        self.assertFalse(self.dest.exists())
        self.assertEqual(self.snapshot(self.base), self.baseline_before)
        self.assertEqual(self.calls, [])

    def test_wrong_modified_binary_hash_stops_before_install_writes(self):
        (self.artifacts / 'server').write_bytes(b'wrong')
        with self.fake_port(), self.assertRaisesRegex(RuntimeError, 'hash differs'):
            m.install()
        self.assertFalse(self.dest.exists())

    def test_different_existing_file_is_never_overwritten(self):
        self.file(self.dest / 'keep', b'original')
        with self.assertRaises(RuntimeError):
            m.put(self.dest / 'keep', b'replacement')
        self.assertEqual((self.dest / 'keep').read_bytes(), b'original')

    def test_configs_separate_roots_daemon_and_API_and_do_not_reuse_retired_UB_indices(self):
        import tomllib
        with patch.object(m, 'D', PurePosixPath('/home/jwk/agent/deployments/modified')), \
                patch.object(m, 'RUNTIME', PurePosixPath('/home/jwk/agent/r/modified')):
            cfg = tomllib.loads(m.config_text())
            self.assertEqual(cfg['ublk']['daemon_socket_path'], str(m.RUNTIME / 'ublk.sock'))
            self.assertEqual(cfg['runtime_path'], str(m.RUNTIME))
            self.assertEqual(cfg['home_path'], str(m.D / 'state'))
            self.assertNotIn('baseline', m.config_text())
        with patch.dict(os.environ, {'AENV_UB_MEMORY_REPLICAS': 'retired-index', 'HTTP_PROXY': 'private-proxy'}):
            env = m.environment()
        self.assertEqual(env['API_ADDR'], '127.0.0.1:18081')
        self.assertNotIn('AENV_UB_MEMORY_REPLICAS', env)
        self.assertNotIn('HTTP_PROXY', env)

    def test_namespace_guard_blocks_privileged_launcher_before_devices_or_children(self):
        receipt = {'host_netns': 1, 'host_mntns': 2}
        with patch.object(m, 'installed', return_value=receipt), \
                patch.object(m, 'properties', return_value={'MainPID': str(os.getpid())}), \
                patch.object(m.os, 'stat', return_value=types.SimpleNamespace(st_ino=1)), \
                patch.object(m.os, 'execve', create=True) as execve:
            with self.assertRaisesRegex(RuntimeError, 'host namespaces'):
                m.inside()
        execve.assert_not_called()

    def test_disconnect_check_never_starts_a_replacement_proxy(self):
        self.runtime.mkdir()
        with self.assertRaisesRegex(RuntimeError, 'did not survive'):
            m.host_proxy(True)


class RelayTest(unittest.TestCase):
    def test_actual_local_TCP_bytes_round_trip_through_relay(self):
        async def scenario():
            async def echo(reader, writer):
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
                writer.close()
            backend = await asyncio.start_server(echo, '127.0.0.1', 0)
            backend_port = backend.sockets[0].getsockname()[1]
            async def front(reader, writer):
                remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', backend_port)
                await m.relay(reader, writer, remote_reader, remote_writer)
            frontend = await asyncio.start_server(front, '127.0.0.1', 0)
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', frontend.sockets[0].getsockname()[1])
                data = bytes(range(256)) * 500
                writer.write(data)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)), 5), data)
                writer.close()
                await writer.wait_closed()
                await asyncio.sleep(0.05)
            finally:
                frontend.close()
                backend.close()
                await frontend.wait_closed()
                await backend.wait_closed()
        asyncio.run(scenario())


if __name__ == '__main__':
    unittest.main(verbosity=2)
