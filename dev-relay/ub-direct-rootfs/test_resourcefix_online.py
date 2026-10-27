import ast,base64,hashlib,importlib.util,json,sys,types,unittest,zlib
from pathlib import Path
HERE=Path(__file__).parent
def tests(file,changes):
    source=(HERE/file).read_text()
    for old,new in changes:source=source.replace(old,new)
    m=types.ModuleType(file);m.__file__=str(HERE/file)
    exec(compile(source,m.__file__,'exec'),m.__dict__);return m
transport=tests('test_measurement_online.py',[
    ('AB_deletefix_measurement_online_v1.py','B_start_measurement_after_gate_v2.py'),
    ("json.dumps({'encoding':'base64','content':base64.b64encode(raw).decode()}).encode()",'raw'),
    ("'ready-a'","'original-a'")])
guards=tests('test_measurement_start_after_gate.py',[
    ('B_start_measurement_after_gate_v1.py','B_start_measurement_after_gate_v2.py'),
    ('next-measure-online-original-a-r.sh','next-measure-resourcefix-original-a-r.sh')])
m=transport.m
class Composition(unittest.TestCase):
    def test_pipeline_pin_and_new_cache_names(self):
        raw=(HERE/m.PIPELINE_NAME).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),m.PIPELINE_SHA)
        self.assertEqual(len(raw),m.PIPELINE_BYTES)
        self.assertEqual(m.NAME,'B_start_measurement_after_gate_v2.py')
    def test_b_self_loader_preserves_transport_constants(self):
        online=m.online_module()
        self.assertEqual(online.NAME,m.NAME);self.assertEqual(online.PIPELINE_SHA,m.PIPELINE_SHA)
    def test_a_bootstrap_uses_same_new_entry(self):
        raw=(HERE/m.NAME).read_bytes()
        text=m.online_command('original-a','a',{'bundle':{}},'a'*40,hashlib.sha256(raw).hexdigest(),len(raw))
        self.assertIn(m.NAME,text)
        ast.parse(text.split("<<'ONLINE_MEASUREMENT_RELAY'\n")[1].rsplit('\nONLINE_MEASUREMENT_RELAY',1)[0],feature_version=(3,11))
if __name__=='__main__':
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(x) for x in (transport,guards))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(Composition))
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())
