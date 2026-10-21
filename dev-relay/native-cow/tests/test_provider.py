"""Configuration and pre-SDK guards; never load SDK or call target systems."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('provider_body',HERE.parent/'native_provider_v4.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Provider(unittest.TestCase):
    def released(self,node):
        manifest_sha='sha256:'+hashlib.sha256(json.dumps(self.owner,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        value={'state':'released','format':'native-raw-v1','mode':'pmem',
               'role':'publish' if node=='node-a' else 'import','ownerId':self.owner['ownerId'],
               'manifestSha256':manifest_sha,'finalize_acknowledged':True,
               'base_post_sha256_verified':True,'post_verification_errors':[],
               'objects':[] if node=='node-b' else [{'replica':self.owner['replicas'][0],
                  'creation_confirmed':True,'delete_acknowledged':True}]}
        if node=='node-b':value['imports']=[{'replica':self.owner['replicas'][0],'mapped':True}]
        return value

    def test_exact_completed_owner_and_importer_release_evidence(self):
        for node in ('node-a','node-b'):
            receipt=m.released_state(node,self.released(node),self.owner,self.binding)
            self.assertEqual(receipt['ownerId'],self.owner['ownerId'])
            self.assertEqual(receipt['state'],'released')

    def test_partial_release_or_bad_integrity_cannot_be_reconciled(self):
        for key,value in [('state','unresolved_preserved'),('finalize_acknowledged',False),
                          ('base_post_sha256_verified',False),('ownerId','e'*32)]:
            row=self.released('node-a');row[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                m.released_state('node-a',row,self.owner,self.binding)
        row=self.released('node-a');row['objects'][0]['delete_acknowledged']=False
        with self.assertRaisesRegex(RuntimeError,'deletion not acknowledged'):
            m.released_state('node-a',row,self.owner,self.binding)

    def test_importer_with_allocation_record_cannot_issue_peer_receipt(self):
        row=self.released('node-b');row['objects']=[{}]
        with self.assertRaisesRegex(RuntimeError,'contains an allocation'):
            m.released_state('node-b',row,self.owner,self.binding)

    def test_missing_peer_receipt_rebuilt_only_from_complete_journal(self):
        values={'/session/binding/binding.json':self.binding,'/session/provider/replicas.json':self.owner,
                '/session/provider/owner.json':self.released('node-b')}
        class P(PurePosixPath):
            def exists(self):return str(self) in values
        written=[]
        def put(path,value):values[str(path)]=copy.deepcopy(value);written.append(str(path))
        with patch.object(m,'load',side_effect=lambda p:copy.deepcopy(values[str(p)])),patch.object(m,'put_json',side_effect=put), \
                patch.object(m.os,'open',return_value=9),patch.object(m.os,'close'),patch.object(m.os,'fsync'), \
                patch.object(m.os,'O_DIRECTORY',0,create=True),patch.object(m.os,'O_CLOEXEC',0,create=True):
            result=m.retirement_result('node-b',P('/session'),P('/session/provider'),False)
            again=m.retirement_result('node-b',P('/session'),P('/session/provider'),False)
        self.assertEqual(written,['/session/provider/release.json'])
        self.assertTrue(result['peerReceiptReconstructed'])
        self.assertFalse(again['peerReceiptReconstructed'])
        self.assertFalse(result['newRetireRequestSent'])
        self.assertFalse(result['SDK_called_by_this_wrapper'])

    def test_previous_retire_intent_prevents_a_second_control_request(self):
        class P(PurePosixPath):
            def exists(self):return self.name=='retire-intent.json'
        deployment=P('/home/jwk/agent/deployments/agentenv-native-d3e61ea')
        def load(path):
            if path.name=='cohort-state.json':return {'phase':'quiesced','openRequests':[],'sandboxIds':[],'outcomeUncertain':False}
            if path.name=='owner.json':return {'state':'serving'}
            return {'node':'node-b','apiPort':18084}
        config=('home_path='+json.dumps(str(deployment/'state'))+'\n[snapshot]\nrepository_backend="posix_fs"\n').encode()
        with patch.object(m,'ordinary'),patch.object(m,'DEPLOYMENT',deployment), \
                patch.object(m,'prepared',return_value=(P('/session'),P('/session/provider'),{})), \
                patch.object(m,'load',load),patch.object(m,'read',return_value=config), \
                patch.dict(sys.modules,{'fcntl':types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None),
                                        'aenv_ub_provider':types.SimpleNamespace(contract=object())}), \
                patch.object(m.os,'open',return_value=100),patch.object(m.os,'close'), \
                patch.object(m.os,'O_NOFOLLOW',0,create=True),patch.object(m.os,'O_CLOEXEC',0,create=True), \
                patch.object(m.http.client,'HTTPConnection',side_effect=AssertionError('No second request')):
            with self.assertRaisesRegex(RuntimeError,'already recorded'):
                m.retire(types.SimpleNamespace(node='node-b',peer_receipt=None))

    def setUp(self):
        self.binding={'version':3,'sourceImage':m.SOURCE,'lowerFilesystem':'ext4',
                      'layers':[{'objectId':'image-'+'a'*64,'generation':'a'*32,'sha256':'sha256:'+'a'*64,
                                 'bytes':258*m.MIB,'socket':'/private/provider/data.sock'}]}
        self.owner={'version':1,'ownerId':'b'*32,'mode':'pmem','readers':['node-b-v4'],
                    'replicas':[{'objectName':'aenv_'+'c'*32,'mappingBytes':260*m.MIB,
                                 'identity':{k:v for k,v in self.binding['layers'][0].items() if k!='socket'}}]}

    def test_logical_and_coverage_budgets_are_distinct(self):
        self.assertEqual(m.budgets(self.binding),(260*m.MIB,512*m.MIB))
        for size in (0,1,2048*m.MIB+2*m.MIB):
            value=json.loads(json.dumps(self.binding));value['layers'][0]['bytes']=size
            with self.assertRaises(RuntimeError):m.budgets(value)

    def test_import_requires_exact_new_owner_content_layout_and_reader(self):
        m.validate_owner(self.owner,self.binding)
        for mutate in (lambda x:x.update(readers=['node-b']),lambda x:x.update(version=True),
                       lambda x:x['replicas'][0].update(mappingBytes=128*m.MIB),
                       lambda x:x['replicas'][0]['identity'].update(sha256='sha256:'+'f'*64)):
            value=json.loads(json.dumps(self.owner));mutate(value)
            with self.assertRaises(RuntimeError):m.validate_owner(value,self.binding)

    def test_b_can_never_run_a_publisher_config(self):
        session=PurePosixPath('/home/jwk/agent/r/up-b-v4');work=session/'provider'
        config={'version':1,'mode':'pmem','region':'default','role':'import','workDir':str(work),
                'adapter':str(session/'libaenv-ub.so'),'logicalBudgetBytes':260*m.MIB,'maxCoverageBytes':512*m.MIB,
                'readerId':'node-b-v4','manifest':str(session/'owner-manifest.json')}
        m.validate_node_config('node-b',session,work,config,self.binding)
        config['role']='publish'
        with self.assertRaisesRegex(RuntimeError,'role'):m.validate_node_config('node-b',session,work,config,self.binding)

    def test_unresolved_handoff_prevents_sdk_entry(self):
        class P(PurePosixPath):
            def resolve(self,strict=False):return self
        session=P('/home/jwk/agent/r/up-b-v4');report={'postMapCoverageGuardBytes':512*m.MIB}
        closed=[]
        with patch.object(m,'ROOT',P('/home/jwk/agent')),patch.object(m,'ordinary'), \
                patch.object(m,'prepared',return_value=(session,session/'provider',report)), \
                patch.object(m,'load',return_value={'phase':'authorized'}), \
                patch.object(m,'package',side_effect=AssertionError('SDK source must not be entered')), \
                patch.dict(sys.modules,{'fcntl':types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None)}), \
                patch.object(m.os,'open',return_value=100),patch.object(m.os,'fstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=1204,st_nlink=1)), \
                patch.object(m.os,'close',lambda fd:closed.append(fd)), \
                patch.object(m.os,'O_NOFOLLOW',0,create=True),patch.object(m.os,'O_CLOEXEC',0,create=True):
            with self.assertRaisesRegex(RuntimeError,'Legacy generation'):m.serve('node-b')
        self.assertEqual(closed,[100])

    def test_start_plan_only_creates_exact_capability_free_new_unit(self):
        class P(PurePosixPath):
            def exists(self):return False
            def is_symlink(self):return False
            def read_text(self):return 'test-boot'
        for node in ('node-a','node-b'):
            session=P('/home/jwk/agent/r/up-'+('a' if node=='node-a' else 'b')+'-v4')
            report={'logicalBudgetBytes':260*m.MIB,'postMapCoverageGuardBytes':512*m.MIB}
            def load(path):
                if str(path).endswith('state.json'):return {'phase':'complete'}
                if str(path).endswith('owner-manifest.json'):return self.owner
                return self.binding
            out=io.StringIO()
            with patch.object(m,'ordinary'),patch.object(m,'prepared',return_value=(session,session/'provider',report)), \
                    patch.object(m,'load',load),patch.object(m,'sha',return_value='a'*64),patch.object(m,'Path',P), \
                    patch.object(m,'PAYLOAD',{'modules':{'service.py':'fixture'}}), \
                    patch.object(m.subprocess,'check_output',return_value='LoadState=loaded\nActiveState=active\nMainPID=123\n'), \
                    contextlib.redirect_stdout(out):
                result=m.start_plan(node)
            self.assertFalse(result['SDK_called']);self.assertFalse(result['physicalHardQuota'])
            text=out.getvalue();body=text.split("<<'REAL_ROOTFS_PROVIDER_ROOT'\n")[1].split('\nREAL_ROOTFS_PROVIDER_ROOT')[0]
            ast.parse(body)
            self.assertIn('jwk-ub-real-rootfs-'+node+'-v4.service',body)
            self.assertIn('--property=CapabilityBoundingSet=',body)
            self.assertIn('--property=SupplementaryGroups=ubsmd',body)
            self.assertIn('--property=LimitCORE=0',body)
            self.assertNotIn("'restart'",body);self.assertNotIn("'stop'",body)

    def test_default_plan_is_nonmutating(self):
        with patch.object(sys,'argv',['provider','prepare','--node','node-a']), \
                patch.object(m,'prepare',side_effect=AssertionError('No preparation requested')), \
                contextlib.redirect_stdout(io.StringIO()):self.assertEqual(m.main(),0)

    def test_deleted_record_lock_is_not_a_snapshot_reference(self):
        class Lock:
            name='11111111-2222-3333-4444-555555555555.lock'
            def lstat(self):return types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=1204,st_nlink=1,st_size=0)
            def resolve(self,strict=False):return self
        self.assertFalse(m.retained_snapshot_records(types.SimpleNamespace(iterdir=lambda:iter([Lock()]))))
        unknown=types.SimpleNamespace(name='unknown.lock')
        with self.assertRaisesRegex(RuntimeError,'Unknown catalog'):
            m.retained_snapshot_records(types.SimpleNamespace(iterdir=lambda:iter([unknown])))

    def test_retained_snapshots_block_retirement_before_any_rpc(self):
        class P(PurePosixPath):
            def exists(self):return True
            def resolve(self,strict=False):return self
            def is_dir(self):return True
            def iterdir(self):return iter([self/'retained-snapshot.json'])
        deployment=P('/home/jwk/agent/deployments/agentenv-native-d3e61ea')
        def load(path):
            if str(path).endswith('cohort-state.json'):
                return {'phase':'quiesced','openRequests':[],'sandboxIds':[],'outcomeUncertain':False}
            return {'node':'node-b','apiPort':18084}
        config=('home_path='+json.dumps(str(deployment/'state'))+'\n[snapshot]\nrepository_backend="posix_fs"\n').encode()
        contract=types.SimpleNamespace(send_json=lambda *a:(_ for _ in ()).throw(AssertionError('No retirement RPC')))
        with patch.object(m,'ordinary'),patch.object(m,'DEPLOYMENT',deployment), \
                patch.object(m,'prepared',return_value=(P('/session'),P('/session/provider'),{})), \
                patch.object(m,'load',load),patch.object(m,'read',return_value=config), \
                patch.dict(sys.modules,{'fcntl':types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None),
                                        'aenv_ub_provider':types.SimpleNamespace(contract=contract)}), \
                patch.object(m.os,'open',return_value=100),patch.object(m.os,'close'), \
                patch.object(m.os,'O_NOFOLLOW',0,create=True),patch.object(m.os,'O_CLOEXEC',0,create=True), \
                patch.object(m.http.client,'HTTPConnection',side_effect=AssertionError('No API request needed')):
            with self.assertRaisesRegex(RuntimeError,'Retained snapshot'):
                m.retire(types.SimpleNamespace(node='node-b',peer_receipt=None))


if __name__=='__main__':unittest.main(verbosity=2)
