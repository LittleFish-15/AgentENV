import ast
import base64
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('four_ssh_setup', Path(__file__).with_name('four_ssh_setup.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
KEY = 'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))).decode()


class TransportTests(unittest.TestCase):
    def test_existing_keys_preserved_append_and_revoke(self):
        original = b'# keep\nrestrict ssh-ed25519 existing-key old-comment\n'
        added = m.revised_authorized_keys(original, KEY)
        self.assertEqual(added, original + m.authorized_line(KEY))
        self.assertEqual(m.revised_authorized_keys(added, KEY, True), original)

    def test_install_and_revoke_idempotent(self):
        added = m.revised_authorized_keys(b'', KEY)
        self.assertEqual(m.revised_authorized_keys(added, KEY), added)
        self.assertEqual(m.revised_authorized_keys(b'', KEY, True), b'')

    def test_missing_newline_preserves_previous_text(self):
        original = b'# no terminal newline'
        added = m.revised_authorized_keys(original, KEY)
        self.assertEqual(added, original + b'\n' + m.authorized_line(KEY))
        self.assertEqual(m.revised_authorized_keys(added, KEY, True), original + b'\n')

    def test_refuse_conflicting_marker_and_duplicate_key(self):
        with self.assertRaises(RuntimeError):
            m.revised_authorized_keys(('restrict broken ' + m.COMMENT + '\n').encode(), KEY)
        with self.assertRaises(RuntimeError):
            m.revised_authorized_keys((KEY + ' another-use\n').encode(), KEY)
        with self.assertRaises(RuntimeError):
            m.revised_authorized_keys(m.authorized_line(KEY) * 2, KEY)

    def test_key_validation(self):
        self.assertEqual(m.public_key(KEY + ' label'), KEY)
        for value in ('ssh-rsa AAAA', KEY + '\n' + KEY, KEY + ' label extra', 'ssh-ed25519 AAAA'):
            with self.assertRaises((RuntimeError, ValueError)):
                m.public_key(value)

    def test_isolated_ssh_options(self):
        args = m.ssh_args()
        for option in ('-oStrictHostKeyChecking=yes', '-oIdentityAgent=none', '-oIdentitiesOnly=yes',
                       '-oClearAllForwardings=yes', '-oRequestTTY=no', '-oBatchMode=yes'):
            self.assertIn(option, args)
        self.assertEqual(args[-1], 'jwk@agent1')
        self.assertIn('/dev/null', args)
        self.assertNotIn('-oStrictHostKeyChecking=no', args)

    def test_remote_source_and_install_remove_are_same_pure_contract(self):
        for remove in (False, True):
            source = m.remote_code(KEY, remove)
            ast.parse(source)
            scope = {}
            # Exercise pure editing logic on Windows; Linux-only flock is not run.
            exec(source[:source.index('need(os.getuid()')].replace(',fcntl', ''), scope)
            self.assertEqual(scope['REMOVE'], remove)
            self.assertEqual(scope['revised_authorized_keys'](b'#keep\n', KEY),
                             m.revised_authorized_keys(b'#keep\n', KEY))
            self.assertNotIn('sshd_config', source)
            self.assertNotIn('sudo', source)
            self.assertIn('current==old', source)


if __name__ == '__main__':
    unittest.main()
