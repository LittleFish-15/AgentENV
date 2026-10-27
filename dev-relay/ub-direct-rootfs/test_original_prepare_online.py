import ast,hashlib,types,unittest
from pathlib import Path
HERE=Path(__file__).parent
source=(HERE/'test_resourcefix_online.py').read_text()
source=source.replace('B_start_measurement_after_gate_v2.py','B_start_measurement_after_gate_v3.py')
source=source.replace('next-measure-resourcefix-original-a-r.sh','next-measure-prepared-original-a-r.sh')
# The prior pure-transport test uses a minimal pipeline double. Stub only the
# new preparation hook; separately verify its real placement in each entry.
source=source.replace("guards=tests(","transport.m.prepare_original_template=lambda pipeline,node:None\nguards=tests(")
module=types.ModuleType('online_preparation_tests');module.__file__=str(HERE/'test_resourcefix_online.py')
exec(compile(source,module.__file__,'exec'),module.__dict__)
class Hooks(unittest.TestCase):
    def test_preparation_before_b_handoff_and_start(self):
        s=(HERE/'B_start_measurement_after_gate_v3.py').read_text();main=s[s.index('def main():'):]
        self.assertLess(main.index("prepare_original_template(pipeline,'b')"),main.index("pipeline.next_command('NEXT_A_ORIGINAL_COMMAND'"))
        self.assertLess(main.index("prepare_original_template(pipeline,'b')"),main.index("pipeline.measure('b','original'"))
    def test_a_original_preparation_only_before_measurement(self):
        s=(HERE/'B_start_measurement_after_gate_v3.py').read_text();fn=s[s.index('def run_online('):s.index('import argparse',s.index('def run_online('))]
        self.assertIn("if phase.startswith('original-'):prepare_original_template(pipeline,node)",fn)
        self.assertLess(fn.index('prepare_original_template'),fn.index('return pipeline.run'))
    def test_helper_embedded_exactly(self):
        self.assertIn((HERE/'prepare_original_measurement_template.py').read_text(),(HERE/'B_start_measurement_after_gate_v3.py').read_text())
if __name__=='__main__':
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(x) for x in (module.transport,module.guards))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(module.Composition))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(Hooks))
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())
