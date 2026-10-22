import ast
import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent


class ServicePatchTests(unittest.TestCase):
    def test_actual_embedded_service_uses_correct_relay_budgets(self):
        path=HERE/'prepare_lazy_four_service_relay_v2.py'
        spec=importlib.util.spec_from_file_location('candidate_service',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        raw=base64.b64decode(module.BASE_SOURCE_B64)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),module.BASE_SOURCE_SHA)
        m=module.make_module({'binaries':{},'config':'fixture','apiPort':18082})
        self.assertEqual(m._bounded_relay.__kwdefaults__['timeout'],360)
        self.assertEqual(m.GUEST_COMMAND_SECONDS,300)
        self.assertEqual(m.CLI_COMMAND_SECONDS,330)
        tree=ast.parse(raw)
        relay=next(n for n in tree.body if isinstance(n,ast.AsyncFunctionDef) and n.name=='relay')
        self.assertIn('_bounded_relay',ast.get_source_segment(raw.decode(),relay))

    def test_diagnostics_never_record_request_payload(self):
        source=(HERE/'prepare_lazy_four_service_relay_v2.py').read_text(encoding='utf-8')
        node=next(n for n in ast.parse(source).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BASE_SOURCE_B64' for t in n.targets))
        base=base64.b64decode(ast.literal_eval(node.value)).decode()
        fn=next(n for n in ast.parse(base).body if isinstance(n,ast.FunctionDef) and n.name=='proxy_relay_event')
        body=ast.get_source_segment(base,fn)
        self.assertIn('8*1024**2',body)
        self.assertNotIn('api-key',body)
        self.assertNotIn('reader.read',body)


if __name__=='__main__':unittest.main()
