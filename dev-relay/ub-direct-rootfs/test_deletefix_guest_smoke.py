import ast,importlib.util,sys,types,unittest
from pathlib import Path
HERE=Path(__file__).parent
if sys.platform=='win32':sys.modules['fcntl']=types.ModuleType('fcntl')
spec=importlib.util.spec_from_file_location('smoke',HERE/'deletefix_guest_smoke_body.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class SmokeContracts(unittest.TestCase):
    def test_shared_memory_id_attributed_to_exact_guest_and_key(self):
        key=str(m.D/'state/snapshot-local-cache/runtime'/'template'/'memory/image.json')
        line='sid=guest created or acquired shared read-only ublk device key='+key+' dev_id=13'
        self.assertEqual(m.memory_id(line,'guest','template'),13)
        for text in (line.replace('sid=guest','sid=other'),line.replace('key=','wrong='),line+'\n'+line.replace('dev_id=13','dev_id=14')):
            with self.assertRaises(RuntimeError):m.memory_id(text,'guest','template')
    def test_removed_memory_is_distinct_from_idle(self):
        self.assertEqual(m.memory_release_evidence('',13,True)['state'],'removed')
    def test_idle_requires_refcount_zero_and_placeholder_for_same_device(self):
        released='releasing shared device (refcount reached 0) dev_id=13'
        idle='device returned to idle pool on placeholder dev_id=13'
        self.assertEqual(m.memory_release_evidence(released+'\n'+idle,13,False)['state'],'idle-on-placeholder')
        for text in ('',released,idle,released+'\n'+idle.replace('13','14')):
            self.assertIsNone(m.memory_release_evidence(text,13,False))
    def test_packet_reuses_exact_helpers_and_timeouts(self):
        value=(HERE/'A_deletefix_real_guest_smoke_v1.py').read_bytes();scope={'__name__':'loaded_test'}
        exec(compile(value,'<smoke-packet>','exec'),scope)
        ready=scope['embedded']('test_ready',scope['READY_Z64'],scope['READY_SHA'])
        deploy=(HERE/'AB_deploy_direct_deletefix_v2.py').read_bytes()
        import hashlib
        self.assertEqual(hashlib.sha256(deploy).hexdigest(),'b879e57841935e4516a28badf7e7f32ccaf53c94e5f6721ef7b803afb489ac65')
        command=ready.module('replay').shell_command(ready.module('pair').guest_command('94cdf2e7927e466e80a3c0e0853d87a4'),'MARKER')
        self.assertIn('timeout -s TERM -k 5 300',command)
        original=(HERE.parent/'ub-direct-rootfs-design-20261026/actual_guest_ready_body.py').read_text()
        self.assertIn('time.monotonic()-start<330',original)
        body=(HERE/'deletefix_guest_smoke_body.py').read_text()
        self.assertIn("ready.D=D;ready.WORK=WORK;ready.DEPLOY_SHA=",body)
        self.assertIn('runtime.case.delete(sid)',body)
        self.assertNotIn('delete-reviewed-dead',body)
        self.assertNotIn('SIGKILL',body)


if __name__=='__main__':unittest.main()
