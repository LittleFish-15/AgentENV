import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reuse_stage',HERE/'stage_reused_service.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
CANDIDATE=(HERE/'prepare_lazy_four_reuse_v2.py').read_bytes()

def inputs(node):
    lib=m.library(CANDIDATE,Path('candidate.py'),m.CANDIDATE_PIN);lib.select_node(node)
    definition={'node':node,'rootfsBinding':None,'apiPort':18082,'config':'fixture config',
                'binaries':{'server':m.sha(b'fixture binary')}}
    receipt={'node':node,'commit':m.CORE,'unit':lib.UNIT,'runtime':str(lib.RUNTIME),
             'binaries':definition['binaries'],'revision':'aenv-native-coordinated-v4',
             'boot_id':'fixture-boot','launcher':'old launcher','launcher_sha256':'old hash',
             'launcher_dependencies':{'old.py':'old hash'}}
    return definition,receipt

class ReuseStageTests(unittest.TestCase):
    def test_both_nodes_build_isolated_launcher_without_changing_inputs(self):
        for node in ('node-a','node-b'):
            d,r=inputs(node);before=json.dumps([d,r],sort_keys=True)
            files=m.build_payload(CANDIDATE,json.dumps(d).encode(),json.dumps(r).encode(),node)
            new=json.loads(files['installation.json'])
            self.assertEqual(set(files),{'native_prepare.py','native_base.py','native_service.py','installation.json'})
            self.assertIn('libexec/lazy-v2/native_service.py',new['launcher'].replace('\\','/'))
            self.assertEqual(new['binaries'],r['binaries']);self.assertEqual(new['boot_id'],r['boot_id'])
            self.assertEqual(new['launcher_sha256'],m.sha(files['native_service.py']))
            self.assertEqual(json.dumps([d,r],sort_keys=True),before)
            self.assertIn(m.CANDIDATE_PIN,files['native_service.py'].decode())

    def test_actual_installed_check_reads_new_receipt_and_new_dependencies(self):
        d,r=inputs('node-b');files=m.build_payload(CANDIDATE,json.dumps(d).encode(),json.dumps(r).encode(),'node-b')
        lib=m.library(CANDIDATE,Path('candidate.py'),m.CANDIDATE_PIN);lib.select_node('node-b')
        runtime=lib.make_module(d);prefix=m.D/'libexec/lazy-v2'
        read_paths=[]
        def load(path):
            read_paths.append(path);self.assertEqual(path,prefix/'installation.json')
            return json.loads(files['installation.json'])
        def stable(path):
            if path==m.D/'bin/server':return b'fixture binary',None
            if path==m.D/'config/runtime.toml':return d['config'].encode(),None
            self.assertEqual(path.parent,prefix)
            return files[path.name],None
        runtime.load=load;runtime.stable_file=stable;runtime.safe=lambda p,*args:p
        with mock.patch.object(Path,'read_text',return_value='fixture-boot'):
            checked=runtime.installed()
        self.assertEqual(checked['node'],'node-b');self.assertEqual(read_paths,[prefix/'installation.json'])

    def test_mismatch_and_unreleased_states_stop(self):
        d,r=inputs('node-a');r['commit']='unknown'
        with self.assertRaises(RuntimeError):m.build_payload(CANDIDATE,json.dumps(d).encode(),json.dumps(r).encode(),'node-a')
        with self.assertRaises(RuntimeError):m.build_payload(CANDIDATE+b'\n',b'{}',b'{}','node-a')
        journal={'phase':'quiesced','sandboxIds':[],'openRequests':[],'outcomeUncertain':False}
        provider={'state':'released','finalizeAcknowledged':True,'deleteAcknowledged':True}
        m.validate_quiescent(journal,provider,'node-a')
        for key,bad in [('sandboxIds',['guest']),('openRequests',['unknown']),('outcomeUncertain',True),('phase','active')]:
            with self.assertRaises(RuntimeError):m.validate_quiescent(dict(journal,**{key:bad}),provider,'node-a')
        with self.assertRaises(RuntimeError):m.validate_quiescent(journal,dict(provider,deleteAcknowledged=False),'node-a')
        m.validate_quiescent(journal,dict(provider,deleteAcknowledged=None),'node-b')

if __name__=='__main__':unittest.main()
