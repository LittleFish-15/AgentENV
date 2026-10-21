"""Receipt/state-machine checks only; no SSH, sockets, SDK or deletion."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import struct
import os
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('handoff',HERE.parent/'legacy_provider_handoff.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Handoff(unittest.TestCase):
    def setUp(self):
        self.manifest={'version':1,'ownerId':'0'*32,'mode':'pmem','readers':['node-b'],
            'replicas':[{'objectName':'aenv_'+'1'*32,'mappingBytes':67108864,
                         'identity':{'objectId':'image-fixture','generation':'2'*32,'sha256':'sha256:'+'3'*64,'bytes':67108864}}]}
        p=patch.object(m,'OLD_SHA',m.digest(self.manifest));p.start();self.addCleanup(p.stop)
        self.b={'state':'released','objects':[],'ownerId':self.manifest['ownerId'],'manifestSha256':'sha256:'+m.OLD_SHA,
                'finalize_acknowledged':True,'base_post_sha256_verified':True}
        self.receipt={'version':1,'ownerId':self.manifest['ownerId'],'readerId':'node-b','manifestSha256':'sha256:'+m.OLD_SHA,'state':'released'}
        self.a=dict(self.b,objects=[{'replica':self.manifest['replicas'][0],'creation_confirmed':True,'delete_acknowledged':True}])
        self.state={'phase':'fenced','nonce':'a'*32}

    def request(self,operation,**kwargs):return dict(operation=operation,nonce=self.state['nonce'],**kwargs)

    def test_authorize_then_complete_requires_actual_owner_release(self):
        state,done=m.apply_fence_request(self.state,self.request('authorize'),self.manifest)
        self.assertEqual(state['phase'],'authorized');self.assertFalse(done)
        state2,done=m.apply_fence_request(state,self.request('complete',ownerState=self.a),self.manifest)
        self.assertEqual(state2['phase'],'complete');self.assertTrue(done)
        self.assertEqual(state2['ownerStateSha256'],m.digest(self.a))

    def test_cancel_only_before_authorization(self):
        _,done=m.apply_fence_request(self.state,self.request('cancel'),self.manifest);self.assertTrue(done)
        with self.assertRaisesRegex(RuntimeError,'Cannot cancel'):
            m.apply_fence_request(dict(self.state,phase='authorized'),self.request('cancel'),self.manifest)

    def test_refusal_releases_fence_only_with_serving_unchanged_owner(self):
        serving=json.loads(json.dumps(self.a));serving['state']='serving';serving['objects'][0]['delete_acknowledged']=False
        request=self.request('declined',ownerState=serving,retireReply={'state':'refused','reason':'active lease'})
        result,done=m.apply_fence_request(dict(self.state,phase='authorized'),request,self.manifest)
        self.assertTrue(done);self.assertEqual(result['phase'],'cancelled')
        request['retireReply']={'state':'unknown'}
        with self.assertRaises(RuntimeError):m.apply_fence_request(dict(self.state,phase='authorized'),request,self.manifest)

    def test_b_release_must_be_same_owner_and_generation(self):
        m.validate_b_release(self.manifest,self.b,self.receipt)
        for key,value in [('ownerId','f'*32),('manifestSha256','sha256:'+'f'*64),('objects',[{}]),('finalize_acknowledged',False)]:
            bad=dict(self.b);bad[key]=value
            with self.assertRaises(RuntimeError):m.validate_b_release(self.manifest,bad,self.receipt)

    def test_partial_deletion_and_integrity_failure_cannot_finish(self):
        for mutate in (lambda a:a.update(state='unresolved_preserved'),lambda a:a.update(finalize_acknowledged=False),
                       lambda a:a.update(base_post_sha256_verified=False),lambda a:a['objects'][0].update(delete_acknowledged=False),
                       lambda a:a['objects'][0]['replica'].update(objectName='aenv_'+'9'*32)):
            bad=json.loads(json.dumps(self.a));mutate(bad)
            with self.assertRaises(RuntimeError):m.validate_a_release(self.manifest,bad)

    def test_different_nonce_never_changes_fence(self):
        for operation in ('authorize','complete','cancel','status'):
            with self.assertRaisesRegex(RuntimeError,'nonce'):
                m.apply_fence_request(self.state,dict(self.request(operation),nonce='b'*32),self.manifest)

    def test_foreign_or_large_generation_is_out_of_scope(self):
        manifest=json.loads(json.dumps(self.manifest));manifest['replicas'][0]['identity']['bytes']=2**30
        with self.assertRaises(RuntimeError):m.validate_manifest(manifest)

    def test_completed_resume_never_contacts_owner_or_remote(self):
        def read(path):
            if path==m.A_PROVIDER/'replicas.json':return self.manifest
            if path==m.A_WORK/'state.json':return {'phase':'complete','nonce':'a'*32}
            if path==m.A_WORK/'owner-release.json':return self.a
            raise AssertionError(str(path))
        with patch.object(m,'account'),patch.object(m,'read',read),patch.object(m,'remote',side_effect=AssertionError('No network')), \
                patch.object(m,'lock_sdk',side_effect=AssertionError('Do not interrupt a newer SDK owner')):
            result=m.transition_a(True)
        self.assertFalse(result['retireResent'])

    def test_refused_transition_exit_is_not_success(self):
        with patch.object(sys,'argv',['handoff','transition-a','--run']), \
                patch.object(m,'transition_a',return_value={'status':'LEGACY_RETIREMENT_REFUSED_OLD_OWNER_PRESERVED'}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(),1)

    def test_lost_terminal_reply_still_releases_confirmed_fence(self):
        # Real worker loop and state transitions; substitute OS/transport only.
        messages=[self.request('authorize'),self.request('complete',ownerState=self.a)]
        accepted=[];closed=[];saved=[]
        class Connection:
            def __init__(self,value,fail):
                raw=m.canonical(value);self.input=struct.pack('>I',len(raw))+raw;self.fail=fail
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def settimeout(self,t):pass
            def recv(self,n):part=self.input[:n];self.input=self.input[n:];return part
            def sendall(self,data):
                if self.fail:raise BrokenPipeError('Lost completion reply')
        class Listener:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def bind(self,p):pass
            def listen(self,n):pass
            def accept(self):
                self_index=len(accepted)
                if self_index>=2:raise AssertionError('Terminal transition must exit even when reply was lost')
                accepted.append(self_index)
                return Connection(messages[self_index],self_index==1),None
        class FakeWork:
            def __init__(self,name='work'):self.name=name
            @property
            def parent(self):return self
            def resolve(self,strict=False):return self
            def exists(self):return False
            def mkdir(self,mode):pass
            def __truediv__(self,name):return self.name+'/'+name
        def read(path):
            return {'replicas.json':self.manifest,'release.json':self.receipt,'owner.json':self.b}[path.name]
        def proc(path):
            return types.SimpleNamespace(read_text=lambda:'1 (fixture) '+' '.join(['0']*19+['123']) if str(path).endswith('/stat') else 'fixture-boot')
        with patch.object(m,'account'),patch.object(m,'B_WORK',FakeWork()),patch.object(m,'lock_sdk',return_value=99), \
                patch.object(m,'next_ready',return_value={'contentIdentity':{'sha256':'fixture'}}), \
                patch.object(m,'read',read),patch.object(m,'Path',proc),patch.object(m,'save',lambda p,v:saved.append(json.loads(json.dumps(v)))), \
                patch.object(m,'same_uid'),patch.object(m.os,'chmod'),patch.object(m.os,'close',lambda fd:closed.append(fd)), \
                patch.object(m.socket,'socket',return_value=Listener()),patch.object(m.socket,'AF_UNIX',1,create=True):
            m.fence_worker(self.state['nonce'])
        self.assertEqual(closed,[99]);self.assertEqual(saved[-1]['phase'],'complete')
        self.assertEqual(len(accepted),2)


if __name__=='__main__':unittest.main(verbosity=2)
