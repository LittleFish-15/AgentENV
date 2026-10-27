import types,unittest
from pathlib import Path
HERE=Path(__file__).parent
source=(HERE/'test_original_prepare_online.py').read_text().replace('B_start_measurement_after_gate_v3.py','B_start_measurement_after_gate_v4.py')
source=source.replace('next-measure-prepared-original-a-r.sh','next-measure-cli-ready-original-a-r.sh')
source=source.replace('prepare_original_measurement_template.py','prepare_original_measurement_template_v2.py')
m=types.ModuleType('baseline_cli_online');m.__file__=str(HERE/'test_original_prepare_online.py')
exec(compile(source,m.__file__,'exec'),m.__dict__)
if __name__=='__main__':
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(x) for x in (m.module.transport,m.module.guards))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(m.module.Composition))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(m.Hooks))
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())
