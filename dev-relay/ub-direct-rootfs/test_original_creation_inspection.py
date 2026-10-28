import ast,datetime,importlib.util,unittest
from pathlib import Path
P=Path(__file__).with_name('B_inspect_original_creation_failure_v1.py')
spec=importlib.util.spec_from_file_location('inspect_create',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Inspector(unittest.TestCase):
    def test_window_retains_multiline_error_not_other_periods(self):
        t=datetime.datetime(2026,10,28,tzinfo=datetime.timezone.utc).timestamp()
        raw=b'2026-10-27T00:00:00Z ERROR older\n2026-10-28T00:00:00Z ERROR restore failed\nCaused by: missing dependency\n2026-10-29T00:00:00Z ERROR later\n'
        lines=m.selected_log(raw,t-1,t+1)
        self.assertEqual(len(lines),2);self.assertIn('missing dependency',lines[-1])
    def test_credentials_redacted(self):
        text=m.redact('ERROR e2b_SUPERSECRET password=hidden bearer abc.def api_key=value')
        for secret in ('SUPERSECRET','hidden','abc.def','api_key=value'):self.assertNotIn(secret,text)
    def test_only_get_http_request(self):
        tree=ast.parse(P.read_text());calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='request']
        self.assertEqual(len(calls),1);self.assertEqual(ast.literal_eval(calls[0].args[0]),'GET')
    def test_no_deletion_or_service_commands(self):
        tree=ast.parse(P.read_text());attrs={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse({'unlink','remove','rmtree','system','Popen','run'}.intersection(attrs))
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='replace'
                             and isinstance(n.func.value,ast.Name) and n.func.value.id=='os' for n in ast.walk(tree)))
if __name__=='__main__':unittest.main()
