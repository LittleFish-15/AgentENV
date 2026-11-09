import ast,importlib.util,sys,types,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace())
s=importlib.util.spec_from_file_location('restored',H/'Y_restored_readonly_entry_v1.py');e=importlib.util.module_from_spec(s);s.loader.exec_module(e)
class Entry(unittest.TestCase):
    def test_fresh_session_and_state(self):
        self.assertEqual(e.SESSION,'y-restored-readonly-20261109-v1')
        self.assertEqual(str(e.STATE).replace('\\','/'),'/home/jwk/y-aenv-control/relay-restored-20261109')
    def test_bootstrap_is_service_inspection(self):
        self.assertTrue(e.BOOTSTRAP['path'].endswith('/Y_readonly_service011.py'))
        import hashlib
        source=(H.parent/'y-jwk-aenv-20261107/Y_readonly_service011.py').read_bytes()
        self.assertEqual(e.BOOTSTRAP['sha256'],hashlib.sha256(source).hexdigest())
    def test_fixed_wrapper_actual_newlines(self):
        tree=ast.parse((H/'Y_restored_readonly_entry_v1.py').read_text())
        script=next(n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,bytes) and n.value.startswith(b'#!/bin/bash'))
        self.assertEqual(script.count(bytes([10])),4)
        self.assertIn(b'/relay-restored-20261109/entry.py',script)
    def test_child_has_no_github_tokens(self):
        result=e.child_environment({'GITHUB_TOKEN':'secret','E2B_API_KEY':'secret'})
        self.assertNotIn('GITHUB_TOKEN',result);self.assertNotIn('E2B_API_KEY',result)
    def test_no_old_dispatch_or_build_queue(self):
        source=(H/'Y_restored_readonly_entry_v1.py').read_text()
        self.assertNotIn('entry-dispatch',source);self.assertNotIn('y-reuse-compile',source)
        self.assertNotIn("SESSION='y-aenv-20261107-v1'",source)
        self.assertIn("'scope':'read-only-diagnosis'",source)
        self.assertIn('Existing Y entry differs; preserved',source)
if __name__=='__main__':unittest.main()
