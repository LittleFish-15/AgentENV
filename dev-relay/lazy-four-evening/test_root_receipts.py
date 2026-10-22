import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

m=load('root_receipts')
NONCE='a'*32

class RootReceiptTests(unittest.TestCase):
    def test_nonce_and_result_identity_are_required(self):
        for nonce in ('../other','a'*31,'a'*33,'A'*32,None):
            with self.assertRaises(RuntimeError):m.receipt_directory(nonce)
        value={'status':'ROOT_OPERATION_COMPLETED','nonce':NONCE,'sequence':1,'operation':'observe'}
        self.assertTrue(m.validate_root_result(value,NONCE,1,'observe'))
        for key,bad in [('nonce','b'*32),('sequence',2),('operation','runtime-stop'),('status','unknown')]:
            with self.assertRaises(RuntimeError):m.validate_root_result(dict(value,**{key:bad}),NONCE,1,'observe')
        self.assertFalse(m.validate_root_result(dict(value,status='ROOT_OPERATION_STOPPED_PRESERVE_STATE'),NONCE,1,'observe'))

    def test_user_owned_or_writable_hierarchy_rejected(self):
        directory=m.receipt_directory(NONCE)
        for uid,mode in ((1204,0o755),(0,0o777),(0,0o775),(0,0o700)):
            meta=SimpleNamespace(st_uid=uid,st_mode=stat.S_IFDIR|mode)
            with mock.patch.object(Path,'resolve',lambda p,**kw:p),mock.patch.object(Path,'lstat',return_value=meta):
                with self.assertRaises(RuntimeError):m.trusted_receipt_directory(directory)

    def test_project_directory_not_a_reply_authority(self):
        for p in (Path('/home/jwk/agent/r/run'),m.RECEIPT_BASE/'other'):
            with self.assertRaises(RuntimeError):m.trusted_receipt_directory(p)
        with self.assertRaises(RuntimeError):m.read_root_receipt(Path('/home/jwk/agent/ready.json'),NONCE)

    def test_existing_generation_never_reused(self):
        meta=SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o755)
        def mkdir(path,*args,**kwargs):raise FileExistsError(str(path))
        with mock.patch.object(m.os,'geteuid',return_value=0,create=True),mock.patch.object(Path,'resolve',lambda p,**kw:p),mock.patch.object(Path,'lstat',return_value=meta),mock.patch.object(Path,'mkdir',mkdir):
            with self.assertRaises(FileExistsError):m.create_receipt_directory(NONCE)

    def test_supervisor_failure_leaves_only_cleanup_channel(self):
        root=load('lazy_four_root_v2')
        scope={'nonce':NONCE};raw=json.dumps(scope).encode();calls=[];replies=[]
        operations={1:'observe',2:'runtime-lazy',3:'runtime-stop',4:'finish'}
        class Supervisor:
            def __init__(self,scope):pass
            def execute(self,operation):
                calls.append(operation)
                if operation=='observe':raise RuntimeError('injected observation failure')
                return {'state':'ok'}
        def read(path,*args,**kwargs):
            if path.name=='scope.json':return raw
            seq=int(path.name.split('.')[0])
            return json.dumps({'nonce':NONCE,'sequence':seq,'operation':operations[seq]}).encode()
        with mock.patch.object(sys,'argv',['root','--scope','scope.json','--sha256',hashlib.sha256(raw).hexdigest()]),mock.patch.object(root,'Supervisor',Supervisor),mock.patch.object(root,'read',read),mock.patch.object(root,'create_receipt_directory',return_value=Path('/run/agentenv-lazy-four')/NONCE),mock.patch.object(root,'reply',side_effect=lambda p,v:replies.append((p,v))),mock.patch.object(Path,'resolve',lambda p,**kw:p),mock.patch.object(Path,'stat',return_value=SimpleNamespace(st_uid=1204)),mock.patch.object(Path,'exists',return_value=True),contextlib.redirect_stdout(io.StringIO()):
            root.main()
        self.assertEqual(calls,['observe','runtime-stop','finish'])
        self.assertEqual([v['status'] for _,v in replies[1:]],['ROOT_OPERATION_STOPPED_PRESERVE_STATE','ROOT_OPERATION_STOPPED_PRESERVE_STATE','ROOT_OPERATION_COMPLETED','ROOT_OPERATION_COMPLETED'])
        self.assertEqual([v['sequence'] for _,v in replies[1:]],[1,2,3,4])
        self.assertTrue(all('/run/agentenv-lazy-four/' in p.as_posix() for p,_ in replies))

if __name__=='__main__':unittest.main()
