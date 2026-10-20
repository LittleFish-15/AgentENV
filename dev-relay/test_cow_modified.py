"""Local import/profile/config tests. No target service or Guest is exercised."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path,PurePosixPath
import shutil
import types
import unittest
import uuid
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
S=load('modified_tested','cow_modified_once.py')
D=load('deploy_tested','deploy_a_ub.py')
def need(ok,why):
    if not ok:raise RuntimeError(why)

class Configuration(unittest.TestCase):
    def test_only_three_settings_change_and_launcher_still_requires_exact_match(self):
        root=PurePosixPath('/home/jwk/agent');base=root/'deployments/agentenv-ub-b019f27'
        with patch.object(D,'ROOT',root),patch.object(D,'D',base),patch.object(D,'RUNTIME',root/'r/ub-a-b019'):
            before=D.config_text().encode()
        self.assertEqual(hashlib.sha256(before).hexdigest(),S.ORIGINAL_CONFIG_SHA)
        with patch.object(S,'H',types.SimpleNamespace(need=need)),patch.object(S,'MOD',base),patch.object(S,'SHORT',root/'r/fc-a-ub'):
            after=S.config_candidate(before)
            raw=(HERE/'deploy_a_ub.py').read_bytes();launcher=S.launcher_candidate(raw)
        env={'__name__':'changed_launcher'}
        exec(compile(launcher,'changed_launcher','exec'),env)
        env.update(ROOT=root,D=base,RUNTIME=root/'r/ub-a-b019')
        self.assertEqual(env['config_text']().encode(),after)
        self.assertEqual(after.replace(b'work_dir = "/home/jwk/agent/r/fc-a-ub"\n',b'')
                         .replace(b'serial_dir = "/home/jwk/agent/deployments/agentenv-ub-b019f27/logs/firecracker"\n',b'')
                         .replace(b'log_level = "Info"\n',b''),before)
        self.assertIn("== config_text().encode()",launcher.decode())
        self.assertNotIn(b'api_key',after)

    def test_unknown_config_or_launcher_is_preserved(self):
        with patch.object(S,'H',types.SimpleNamespace(need=need)):
            with self.assertRaisesRegex(RuntimeError,'Unknown'):S.config_candidate(b'[firecracker]\ncustom=true\n')
            with self.assertRaisesRegex(RuntimeError,'Unexpected'):S.launcher_candidate(b'pass\n')

    def test_pinned_engine_and_root_block_syntax(self):
        self.assertEqual(hashlib.sha256((HERE/'cow_controlled_once.py').read_bytes()).hexdigest(),S.ENGINE_SHA)
        ast.parse("scope={}\n"+S.ROOT_RESTART)
        self.assertEqual(S.ROOT_RESTART.count("'/usr/bin/systemctl','restart',scope['unit']"),1)
        self.assertNotIn("exec(",S.ROOT_RESTART)
        self.assertNotIn('stop',S.ROOT_RESTART)

class Files(unittest.TestCase):
    def setUp(self):
        self.root=(HERE.parent/('.modified-test-'+uuid.uuid4().hex[:8])).resolve();self.root.mkdir(mode=0o755)
        self.old=self.root/'original';self.repo=self.old/'state/snapshot-store/repository';self.repo.mkdir(parents=True)
        def safe(p):
            need(p.resolve()==p and p.is_relative_to(self.root),'Redirected/outside input');return p
        self.helper=types.SimpleNamespace(need=need,safe=safe,read=lambda p:p.read_bytes())
    def tearDown(self):
        assert self.root.parent==HERE.parent.resolve();shutil.rmtree(self.root)
    def seed(self):
        sid='12345678-1234-1234-1234-123456789abc'
        layers=[{'digest':'sha256:'+hashlib.sha256(('layer'+str(i)).encode()).hexdigest(),'size':6} for i in range(16)]
        record={'id':sid,'resources':{'cpu_count':1,'memory_mib':512},
                'committed':{'memory_layers':layers[:2],'rootfs_layers':[{'Managed':x} for x in layers[2:]],
                             'attached_drives':[],'volume_snapshots':[]}}
        (self.repo/'catalog/records').mkdir(parents=True)
        (self.repo/'catalog/records'/(sid+'.json')).write_text(json.dumps(record))
        (self.repo/'snapshots'/sid).mkdir(parents=True);(self.repo/'snapshots'/sid/'commit').write_bytes(b'committed')
        return sid,record
    def test_complete_logical_layer_chain_selected_without_copying_unrelated_snapshots(self):
        sid,record=self.seed()
        with patch.object(S,'H',self.helper),patch.object(S,'OLD',self.old):
            selected,raw,files=S.selected_inputs({'measurement_snapshot_id':sid})
        self.assertEqual(selected,sid);self.assertEqual(json.loads(raw),record);self.assertEqual(len(files),18)
        self.assertTrue(all(k.startswith(('managed-layers/','snapshots/'+sid+'/')) for k in files))
        self.assertNotIn('mem.bin',files)
    def test_external_or_extra_dependencies_stop(self):
        sid,record=self.seed()
        for kind in ('external','drive','startup'):
            modified=json.loads(json.dumps(record));c=modified['committed']
            if kind=='external':c['rootfs_layers'][0]={'External':{'url':'not-used'}}
            if kind=='drive':c['attached_drives']=[{'id':'extra'}]
            if kind=='startup':c['memory_startup']={'size':1}
            (self.repo/'catalog/records'/(sid+'.json')).write_text(json.dumps(modified))
            with patch.object(S,'H',self.helper),patch.object(S,'OLD',self.old),self.assertRaises(RuntimeError):
                S.selected_inputs({'measurement_snapshot_id':sid})
    def copy(self,source,target,expected):
        original_fstat=os.fstat
        def fstat(fd):
            s=original_fstat(fd)
            return types.SimpleNamespace(st_mode=s.st_mode,st_uid=1204,st_size=s.st_size,st_dev=s.st_dev,st_ino=s.st_ino,st_mtime_ns=s.st_mtime_ns)
        with patch.object(S,'H',self.helper),patch.object(S.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True), \
             patch.object(S.os,'O_NONBLOCK',getattr(os,'O_NONBLOCK',0),create=True),patch.object(S.os,'fstat',fstat):
            return S.copy_new(source,target,expected)
    def test_copy_digest_and_independent_inode(self):
        src=self.root/'source';dst=self.root/'target';src.write_bytes(b'content')
        h=hashlib.sha256(b'content').hexdigest();r=self.copy(src,dst,h)
        self.assertEqual(dst.read_bytes(),b'content');self.assertNotEqual(src.stat().st_ino,dst.stat().st_ino)
        self.assertFalse(r['reused']);self.assertTrue(self.copy(src,dst,h)['reused'])
    def test_bad_digest_or_existing_conflict_never_publishes_or_overwrites(self):
        src=self.root/'source';dst=self.root/'target';src.write_bytes(b'content')
        with self.assertRaisesRegex(RuntimeError,'digest'):self.copy(src,dst,'0'*64)
        self.assertFalse(dst.exists());self.assertFalse(list(self.root.glob('*.part')))
        dst.write_bytes(b'existing')
        with self.assertRaisesRegex(RuntimeError,'conflict'):self.copy(src,dst,None)
        self.assertEqual(dst.read_bytes(),b'existing')
    def test_existing_cross_deployment_hardlink_rejected(self):
        src=self.root/'source';dst=self.root/'target';src.write_bytes(b'content');os.link(src,dst)
        with self.assertRaisesRegex(RuntimeError,'hardlink'):self.copy(src,dst,None)

class Routing(unittest.TestCase):
    def test_cli_pending_and_inline_root_scope_all_select_modified(self):
        c=types.SimpleNamespace();p=types.SimpleNamespace();r=types.SimpleNamespace()
        h=types.SimpleNamespace(read=lambda path:b'from pathlib import Path\nBASE=Path("/old")\nUNIT="old"\nSHORT=Path("/old")\n')
        with patch.object(S,'C',c),patch.object(S,'P',p),patch.object(S,'R',r),patch.object(S,'H',h):
            source=S.configure_engine()
        self.assertEqual(c.PORT,18081);self.assertEqual(c.BASE,S.MOD);self.assertEqual(c.PENDING,S.PENDING)
        self.assertIs(p.restore,S.restore);self.assertIs(p.inventory_empty,S.empty)
        self.assertEqual(r.UNIT,S.UNIT);self.assertEqual(r.SHORT,S.SHORT)
        env={};exec(source,env)
        self.assertEqual(env['BASE'],S.MOD);self.assertEqual(env['UNIT'],S.UNIT);self.assertEqual(env['SHORT'],S.SHORT)
    def test_http_requests_use_modified_port_and_process_guard(self):
        calls=[]
        class Connection:
            def __init__(self,host,port,timeout):calls.append(('connect',host,port))
            def request(self,*a,**kw):calls.append(('request',a[0],a[1]))
            def getresponse(self):return types.SimpleNamespace(status=204,read=lambda n:b'',getheader=lambda k:None)
            def close(self):pass
        api=object.__new__(S.Api);api.unit=S.UNIT;api.port=18081;api.identity=[5,'t'];api.key='fixture'
        with patch.object(S,'H',types.SimpleNamespace(need=need)),patch.object(S,'state',return_value=[5,'t']),patch.object(S.http.client,'HTTPConnection',Connection):
            self.assertEqual(api.call('GET','/health'),(204,None))
        self.assertEqual(calls[0],('connect','127.0.0.1',18081))
        with patch.object(S,'H',types.SimpleNamespace(need=need)),patch.object(S,'state',return_value=[6,'new']),self.assertRaisesRegex(RuntimeError,'changed'):
            api.call('GET','/health')
    def test_restore_goes_to_supplied_modified_api_and_keeps_ownership(self):
        calls=[]
        api=types.SimpleNamespace(call=lambda *a,**kw:calls.append((a,kw)) or (201,{'sandboxID':'child'}),key='hidden')
        helper=types.SimpleNamespace(need=need,ID=__import__('re').compile('[a-z]+'),error_summary=lambda *a:{})
        with patch.object(S,'H',helper):
            self.assertEqual(S.restore(api,'same-template','run','pair-a'),'child')
        args,kw=calls[0]
        self.assertEqual(args[0:2],('POST','/sandboxes'))
        self.assertEqual(args[2]['metadata'],{'cow_marker_run':'run','cow_marker_role':'pair-a'})
        self.assertEqual(args[2]['templateID'],'same-template')
        self.assertEqual(args[2]['timeout'],900)

if __name__=='__main__':unittest.main(verbosity=2)
