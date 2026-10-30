import ast
import importlib.util
from pathlib import Path
import unittest
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('read_only',HERE/'C_run_maintenance_v13.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def test_nested_structured_secrets_are_redacted(self):
        row={'sandboxID':'known-id','envdAccessToken':'secret-x','nested':[{'api_key':'secret-y','message':'private-key-value'}]}
        result=m.redact(row,'private-key-value')
        self.assertEqual(result['sandboxID'],'known-id')
        self.assertEqual(result['envdAccessToken'],'[REDACTED]')
        self.assertEqual(result['nested'][0]['api_key'],'[REDACTED]')
        self.assertNotIn('private-key-value',str(result))
    def test_plain_logs_remove_known_key_and_bearer(self):
        result=m.redact('failure api_key=abc123 Authorization: Bearer opaqueToken and known-secret','known-secret')
        for secret in ('abc123','opaqueToken','known-secret'):self.assertNotIn(secret,result)
        self.assertIn('failure',result)
    def test_diagnostic_has_no_mutating_demo_calls(self):
        tree=ast.parse((HERE/'C_run_maintenance_v13.py').read_text())
        calls={node.func.attr for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)}
        self.assertFalse(calls & {'release','retire','close_pair','publish','runtime','start','launch','chmod','chown','unlink','mkdir','makedirs'})

if __name__=='__main__':unittest.main()
