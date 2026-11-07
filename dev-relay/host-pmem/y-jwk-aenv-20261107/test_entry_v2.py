"""Y TLS mode and newline regression, plus inherited identity/task checks."""
import ast,importlib.util,ssl,unittest,urllib.request
from pathlib import Path
import test_entry as original
H=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('y_entry_v2_under_test',H/'Y_root_entry_v2.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
original.e=e
class Compatibility(unittest.TestCase):
    def test_github_uses_explicit_insecure_context(self):
        client=e.API.GitHub('fixture-token')
        https=[h for h in client.opener.handlers if isinstance(h,urllib.request.HTTPSHandler)]
        self.assertEqual(len(https),1)
        self.assertEqual(https[0]._context.verify_mode,ssl.CERT_NONE)
        self.assertFalse(https[0]._context.check_hostname)
        self.assertEqual(client.token,'fixture-token')
    def test_global_tls_defaults_preserved(self):
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
    def test_fixed_entry_has_actual_newlines(self):
        tree=ast.parse((H/'Y_root_entry_v2.py').read_text())
        scripts=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,bytes) and n.value.startswith(b'#!/bin/bash')]
        self.assertEqual(len(scripts),1)
        self.assertEqual(scripts[0],b'#!/bin/bash\nset -eu\numask 077\nexec /usr/bin/python3 -I -B /home/jwk/y-aenv-control/relay/entry.py\n')
        self.assertNotIn(b'\\n',scripts[0])
    def test_source_and_redirect_checks_retained(self):
        client=e.API.GitHub()
        self.assertTrue(any(isinstance(h,e.API.NoRedirect) for h in client.opener.handlers))
        source=(H/'Y_root_entry_v2.py').read_text()
        self.assertIn("sha(raw)==entry['sha256']",source)
        self.assertIn("job['rootEntrySha256']==pin",source)
        self.assertIn('GitHub public transport check failed before token input',source)
def load_tests(loader,tests,pattern):
    suite=loader.loadTestsFromTestCase(original.Validation)
    suite.addTests(loader.loadTestsFromTestCase(Compatibility))
    return suite
if __name__=='__main__':unittest.main()
