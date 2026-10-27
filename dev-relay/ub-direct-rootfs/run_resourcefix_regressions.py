"""Run existing composition/replay tests with the actual three-field schema."""
import sys,types,unittest
from pathlib import Path
HERE=Path(__file__).parent
sys.path.insert(0,str(HERE))
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.ModuleType('fcntl'))
def schema(s):return s.replace("{'cpu_count':2,'memory_mib':4096}","{'cpu_count':2,'memory_mib':4096,'disk_size_mib':10240}")
mapping={'full_comparison_admission_deletefix.py':'resourcefix_admission.py',
         'deletefix_comparison_aggregation_body.py':'resourcefix_aggregation_body.py',
         'actual_comparison_cohort_deletefix.py':'resourcefix_cohort.py',
         'native_group_replay.py':'resourcefix_native_replay.py'}
def load(name,file):
    p=HERE/mapping.get(file,file);m=types.ModuleType(name);m.__file__=str(p);sys.modules[name]=m
    source=p.read_text(encoding='utf-8')
    if file.startswith('test_'):source=schema(source)
    exec(compile(source,str(p),'exec'),m.__dict__);return m
source=(HERE/'test_deletefix_measurement.py').read_text()
start=source.index('def load(');end=source.index("if sys.platform==",start)
source=source[:start]+source[end:]
source=schema(source).replace("source=(HERE/'test_full_pair_comparison.py').read_text()","source=schema((HERE/'test_full_pair_comparison.py').read_text())")
m=types.ModuleType('resourcefix_existing');m.__file__=str(HERE/'test_deletefix_measurement.py')
m.__dict__.update(load=load,schema=schema)
exec(compile(source,m.__file__,'exec'),m.__dict__)
replay_tests=load('resourcefix_replay_tests','test_native_group_replay.py')
suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(x) for x in
    (m.composition,m.aggregate_tests,m.cohort_tests,replay_tests))
suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(m.Aliases))
result=unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(not result.wasSuccessful())
