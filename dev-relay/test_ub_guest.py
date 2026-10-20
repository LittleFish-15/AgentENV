"""Synthetic root protocol and SDK ownership tests; no target allocation/restart."""
import ast,contextlib,hashlib,importlib.util,io,json,os,shutil,stat,struct,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
T=load('ub_guest_test','ub_guest_once.py')
Q=load('ub_root_test','ub_guest_root.py')
def need(ok,why):
    if not ok:raise RuntimeError(why)

class Basic(unittest.TestCase):
    def test_launcher_only_adds_two_index_environment_values(self):
        raw=b"def environment():\n    return {'API_ADDR': '127.0.0.1:' + str(PORT)}\n"
        with patch.object(T,'H',types.SimpleNamespace(need=need)):
            new=T.enable_launcher(raw,Path('/owned/index.json'))
            with self.assertRaises(RuntimeError):T.enable_launcher(new,Path('/owned/index.json'))
        env={'PORT':18081};exec(new,env)
        self.assertEqual(env['environment'](),{'API_ADDR':'127.0.0.1:18081','AENV_UB_MEMORY_REPLICAS':str(Path('/owned/index.json')),'AENV_UB_ROOTFS_REPLICAS':str(Path('/owned/index.json'))})
    def test_meter_counts_only_wrapped_mapping_reads(self):
        mapping=types.SimpleNamespace(read=lambda o,n:b'x'*n)
        meter=T.Meter([types.SimpleNamespace(objectName='own',layerDigest='digest')])
        mapping.read(0,8);self.assertEqual(meter.snapshot()['own']['read_calls'],0)
        self.assertEqual(meter.wrap('own',mapping).read(0,7),b'x'*7)
        self.assertEqual(meter.snapshot()['own']['SDK_bytes_returned_to_broker'],7)
    def test_root_source_pin_and_complete_inline_syntax(self):
        raw=(HERE/'ub_guest_root.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),T.ROOT_DRIVER_SHA)
        engine=load('engine_for_syntax','cow_controlled_once.py')
        ast.parse((HERE/'cow_ram_readonly.py').read_text()+engine.WIRE_SOURCE+raw.decode()+'\nroot_ub_session({}, {})\n')

class RootProtocol(unittest.TestCase):
    def fixture(self,nonempty=False,bad_peer=False,sample=False,bad_fallback=False):
        sent=[];restarts=[];state={'pid':60,'mode':'enabled'}
        replicas=[{'layerDigest':'d'+str(i),'allowRepositoryFallback':False} for i in range(16)]
        index=json.dumps({'state':'ready','replicas':replicas}).encode()
        class P:
            def __init__(self,s):self.s=str(s);self.name=self.s.rsplit('/',1)[-1]
            def __truediv__(self,x):return P(self.s+'/'+x)
            @property
            def parent(self):return P(self.s.rsplit('/',1)[0])
            def __eq__(self,x):return isinstance(x,P) and self.s==x.s
            def __str__(self):return self.s
            def resolve(self,**kw):return self
            def read_text(self):return 'boot'
            def lstat(self):return types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=1204,st_dev=1,st_ino=2)
        class Client:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def settimeout(self,*a):pass
            def connect(self,*a):pass
            def getsockopt(self,*a):return struct.pack('3i',1000,99 if bad_peer else 1204,1205)
        class HTTP:
            def __init__(self,*a,**kw):pass
            def request(self,m,p,**kw):self.path=p
            def getresponse(self):
                raw=b'' if self.path=='/health' else (b'[{}]' if nonempty and state['mode']=='baseline' else b'[]')
                return types.SimpleNamespace(status=204 if self.path=='/health' else 200,read=lambda n:raw,getheader=lambda _:None)
            def close(self):pass
        def command(args,**kw):
            if args[1]=='restart':restarts.append(args[2]);state['pid']+=1;return types.SimpleNamespace()
            if args[2]=='jwk-aenv-ae9c626-node-a.service':return types.SimpleNamespace(stdout='ActiveState=active\nMainPID=50\n')
            return types.SimpleNamespace(stdout='LoadState=loaded\nActiveState=active\nMainPID='+str(state['pid'])+'\nUser=jwk\nGroup=jwk\nPrivateNetwork=yes\nPrivateMounts=yes\n')
        scope={'run_id':'a'*32,'snapshot_id':'template','catalog_sha256':'hash','boot_id':'boot',
               'memory_bytes':512*1024**2,'main_pid':61,'main_start_ticks':'61','children':[{'sid':'a'},{'sid':'b'}]}
        messages=iter([{'op':'activate'}]+([{'op':'sample','phase':'baseline','scope':scope,'marker_targets':{}}] if sample else [])+[{'op':'deactivate'}])
        def receive(c):
            value=next(messages)
            if value['op']=='deactivate':state['mode']='baseline'
            return value
        def owned(p,*a):
            if str(p).endswith('api-key'):return b'e2b_fixture'
            if str(p)=='/index':return index
            if str(p).endswith('image.json'):
                lowers=[{'digest':r['layerDigest'],'ub':dict(r)} for r in replicas[:14]]
                if bad_fallback:lowers[0]['ub']['allowRepositoryFallback']=True
                return json.dumps({'lowers':lowers}).encode()
            return state['mode'].encode()
        hashes=lambda v:{p:hashlib.sha256(v).hexdigest() for p in ('config/runtime.toml','libexec/deploy_a_ub.py','installation.json')}
        review={'run_id':'a'*32,'boot_id':'boot','original':[50,'50'],'before':[60,'60'],
                'snapshot_id':'template','catalog_sha256':'hash','rootfs_digests':['d'+str(i) for i in range(14)],
                'index_path':'/index','index_sha256':hashlib.sha256(index).hexdigest(),
                'enabled_hashes':hashes(b'enabled'),'baseline_hashes':hashes(b'baseline')}
        endpoint={'path':'/root/r/ub-control-'+'a'*16+'.sock','identity':[1,2],'pid':1000,'ticks':'1000'}
        # Imports inside the reviewed function resolve to substituted modules; no real root operation.
        class BindingError(RuntimeError):
            def __init__(self,message,diagnostics):super().__init__(message);self.diagnostics=diagnostics
        env={'require':need,'ROOT':P('/root'),'BASE':P('/modified'),'UNIT':'jwk-aenv-ub-b019f27-node-a.service',
             'identity':lambda p:(1,str(p)),'owned':owned,'wire_receive':receive,'wire_send':lambda c,v:sent.append(v),
             'BindingError':BindingError,'collect_scope':lambda scope:{'status':'fixture'},
             'bind':lambda scope,child:{'sandbox_id':child['sid'],'cwd':P('/cwd/'+child['sid'])}}
        fn=types.FunctionType(Q.root_ub_session.__code__,env)
        with patch('pathlib.Path',P),patch('os.geteuid',lambda:0,create=True), \
             patch('os.uname',lambda:types.SimpleNamespace(nodename='server1'),create=True), \
             patch('socket.AF_UNIX',1,create=True),patch('socket.SO_PEERCRED',1,create=True),patch('socket.socket',lambda *a:Client()), \
             patch('subprocess.run',command),patch('http.client.HTTPConnection',HTTP),contextlib.redirect_stdout(io.StringIO()):
            fn(review,endpoint)
        return sent,restarts
    def test_exact_unit_activated_then_restored(self):
        sent,restarts=self.fixture()
        self.assertEqual(restarts,['jwk-aenv-ub-b019f27-node-a.service']*2)
        self.assertTrue(sent[-1]['safe_off']);self.assertTrue(sent[-1]['healthy'])
    def test_nonempty_inventory_blocks_restore_restart(self):
        sent,restarts=self.fixture(nonempty=True)
        self.assertEqual(len(restarts),1);self.assertFalse(sent[-1]['ok'])
    def test_wrong_peer_never_restarts(self):
        sent,restarts=self.fixture(bad_peer=True);self.assertEqual(restarts,[])
    def test_actual_rootfs_configuration_requires_all_exact_ub_refs(self):
        sent,_=self.fixture(sample=True)
        result=next(x for x in sent if x.get('op')=='sample')
        self.assertTrue(result['ok']);self.assertEqual(len(result['report']['UB_rootfs_bindings']),2)
    def test_fallback_enabled_configuration_is_rejected_with_diagnostics(self):
        sent,_=self.fixture(sample=True,bad_fallback=True)
        result=next(x for x in sent if x.get('op')=='sample')
        self.assertFalse(result['ok']);self.assertIn('binding_diagnostics',result)

class GuestLifecycle(unittest.TestCase):
    def fixture(self,fail=False):
        root=(HERE.parent/('.ub-guest-life-'+uuid.uuid4().hex[:8])).resolve();root.mkdir(mode=0o755)
        E=load('ub_engine_lifecycle','cow_controlled_once.py')
        calls=[];alive={};counter=[0]
        H=types.SimpleNamespace(need=need,save=lambda p,v:p.write_text(json.dumps(v)))
        def restore(api,snapshot,run,role):
            self.assertEqual(snapshot,'template');counter[0]+=1
            sid='child'+str(counter[0]);alive[sid]=True;calls.append(('restore',role));return sid
        def api_call(method,path,**kw):
            sid=path.rsplit('/',1)[1];calls.append((method,path))
            self.assertNotEqual(method,'POST')
            if method=='DELETE':alive[sid]=False;return 204,None
            return (200,{'metadata':{'cow_marker_run':'a'*32}}) if alive[sid] else (404,None)
        R=types.SimpleNamespace(find_firecrackers=lambda p:[10,11],identity=lambda p:(1,'ticks'))
        report={'run_id':'a'*32,'snapshot_id':'template','catalog_sha256':'hash','restore_calls':0,
                'restore_outcome_uncertain':False,'known_sandboxes':[],'cleanup_attempted':[],'released_sandboxes':[]}
        def measurement(self,*a):
            if fail:raise RuntimeError('measurement failed')
        try:
            with patch.object(T,'C',E),patch.object(T,'H',H),patch.object(T,'S',types.SimpleNamespace(empty=lambda api:None)), \
                 patch.object(T,'R',R),patch.object(E,'H',H),patch.object(E,'BASE',root), \
                 patch.object(E,'PENDING',root/'pending.json'),patch.object(E,'P',types.SimpleNamespace(restore=restore)), \
                 patch.object(Path,'read_text',lambda p,*a,**kw:'boot' if str(p).endswith('boot_id') else p.open(*a,**kw).read()):
                cls=T.experiment_class(None,None)
                with patch.object(cls,'measure',measurement),patch.object(cls,'check',return_value={}):
                    e=cls(types.SimpleNamespace(identity=(5,'t'),key='fixture',call=api_call),root,report,
                          {'run_id':'seed','restored_marker_status':{}})
                    if fail:
                        with self.assertRaisesRegex(RuntimeError,'measurement failed'):e.run('')
                    else:e.run('')
            return report,calls
        finally:
            assert root.parent==HERE.parent.resolve();shutil.rmtree(root)
    def test_exact_three_restores_without_new_snapshot(self):
        r,calls=self.fixture()
        self.assertEqual(r['restore_calls'],3);self.assertEqual(len(r['released_sandboxes']),3)
        self.assertEqual([v for k,v in calls if k=='restore'],['pair-a','pair-b','base-verifier'])
        self.assertTrue(r['base_marker_verified']);self.assertTrue(r['temporary_cli_credentials_removed'])
    def test_failed_measurement_cleans_pair_and_does_not_create_verifier(self):
        r,calls=self.fixture(True)
        self.assertEqual(r['restore_calls'],2);self.assertEqual(len(r['released_sandboxes']),2)
        self.assertTrue(r['temporary_cli_credentials_removed'])

class Owner(unittest.TestCase):
    def fixture(self,mode='ok'):
        root=(HERE.parent/('.ub-session-'+uuid.uuid4().hex[:8])).resolve();root.mkdir(mode=0o755)
        work=root/'work';work.mkdir();mod=root/'modified'
        for p in ('config','libexec'):(mod/p).mkdir(parents=True)
        (root/'r').mkdir()
        raw=b"def environment():\n    return {'API_ADDR': '127.0.0.1:' + str(PORT)}\n"
        initial={'config/runtime.toml':b'config','libexec/deploy_a_ub.py':raw,'installation.json':b'{}'}
        for rel,data in initial.items():(mod/rel).write_bytes(data)
        prep=root/'prep.json';prep.write_text(json.dumps({'config_after_sha256':hashlib.sha256(b'config').hexdigest(),
                'launcher_after_sha256':hashlib.sha256(raw).hexdigest(),'installation_after_sha256':hashlib.sha256(b'{}').hexdigest()}))
        marker=root/'marker.json';marker.write_text('{}')
        events=[];pid=[60,'old'];report={'run_id':'a'*32}
        def save(path,value):path.write_text(json.dumps(value))
        H=types.SimpleNamespace(need=need,read=lambda p:p.read_bytes(),safe=lambda p:p,save=save,ChildFailure=type('ChildFailure',(RuntimeError,),{}))
        class Native:
            def __init__(self,*a):self.allocation_calls=0;self.mappings=[]
            def allocate(self,r):self.allocation_calls+=1
            def map(self,r,writable=False):
                m=types.SimpleNamespace(backing_coverage=128*1024**2,read=lambda o,n:b'x'*n);self.mappings.append(m);return m
        class Publisher:
            def __init__(self,b,j):self.backend=b;self.state={'objects':[]}
            def publish(self,selected,path,budget):
                replicas=[];maps=[]
                for i,(digest,(_,size)) in enumerate(selected.items()):
                    r=types.SimpleNamespace(objectName='own'+str(i),layerDigest=digest,fileBytes=size,mappingBytes=4194304)
                    self.backend.allocate(r);self.state['objects'].append({'creation_confirmed':True,'delete_acknowledged':False})
                    if mode=='publish_fail' and i==1:raise RuntimeError('publication failed')
                    replicas.append(r);maps.append(self.backend.map(r))
                return replicas,maps
            def cleanup(self):
                events.append('SDK-cleanup')
                for item in self.state['objects']:item['delete_acknowledged']=True
        class Condition:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def wait_for(self,fn,timeout):return fn()
        class Broker:
            def __init__(self,replicas,maps):
                self.condition=Condition();self.active=0
                for m in maps:m.read(0,10)
            def start(self,*a):pass
            def stop(self):events.append('broker-stop');return {'active_leases':0}
        def verify(*a):
            events.append('verify')
            if mode=='bad_payload':raise RuntimeError('bad payload')
        b=types.SimpleNamespace(NativeBackend=Native,Publisher=Publisher,Broker=Broker,atomic_json=save,
                                index_for=lambda rs,state='ready':{'state':state,'replicas':[vars(r) for r in rs]},verify_mapping=verify)
        C=types.SimpleNamespace(WIRE_SOURCE='',wire_receive=lambda c:{'hello':'a'*32},PHASES=['baseline','a_first','a_repeat','b_disjoint'])
        S=types.SimpleNamespace(PREP=prep,OLD=root/'old',state=lambda unit:[50,'original'] if unit==T.OLD_UNIT else pid[:],
                                Api=lambda *a:types.SimpleNamespace(identity=pid[:]),empty=lambda *a:None,configure_engine=lambda:'pass\n')
        R=types.SimpleNamespace(identity=lambda p:(1,'ticks'),whole_process_metrics=lambda *a:{'available':True})
        class Stream:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def bind(self,p):Path(p).touch()
            def listen(self,*a):pass
            def settimeout(self,*a):pass
            def accept(self):return self,None
            def getsockopt(self,*a):return struct.pack('3i',99,0,0)
            def close(self):pass
        def rpc(client,msg):
            events.append(msg['op'])
            if msg['op']=='activate':pid[:]=[61,'enabled'];return {'identity':pid[:]}
            if mode=='restore_fail':raise RuntimeError('root restore failed')
            pid[:]=[62,'off'];return {'safe_off':True,'healthy':True}
        class Experiment:
            def __init__(self,api,work,g,prepare):self.g=g
            def run(self,source):
                self.g.update(released_sandboxes=['a','b','c'],base_marker_verified=True,
                    measurements={p:{'matches_expected':True} for p in C.PHASES},
                    repeat_write_observation={'stable_pfn_and_gpa_identity_between_windows':True})
        try:
            with patch.object(T,'ROOT',root),patch.object(T,'MOD',mod),patch.object(T,'PENDING',root/'pending.json'), \
                 patch.object(T,'H',H),patch.object(T,'S',S),patch.object(T,'C',C),patch.object(T,'P',types.SimpleNamespace(PENDING=marker)), \
                 patch.object(T,'R',R),patch.object(T,'rpc',rpc),patch.object(T,'experiment_class',lambda *a:Experiment), \
                 patch.object(T.socket,'AF_UNIX',1,create=True),patch.object(T.socket,'SO_PEERCRED',1,create=True), \
                 patch.object(T.socket,'socket',lambda *a:Stream()),patch.object(T.os,'chmod'), \
                 patch.object(Path,'read_text',lambda p,*a,**kw:'boot' if str(p).endswith('boot_id') else p.open(*a,**kw).read()), \
                 contextlib.redirect_stdout(io.StringIO()):
                selected={'digest'+str(i):(root/'source',1000) for i in range(16)}
                T.session(types.SimpleNamespace(b=b),root/'lib',selected,{'rootfs':[]},
                          {'snapshot_id':'template','catalog_sha256':'hash','marker_seed':'seed'},work,report,'pass\n')
            for rel,data in initial.items():self.assertEqual((mod/rel).read_bytes(),data)
            return report,events
        finally:
            assert root.parent==HERE.parent.resolve();shutil.rmtree(root)
    def test_success_restores_runtime_before_sdk_release(self):
        r,e=self.fixture()
        self.assertEqual(r['status'],'A_UB_ALL_LAYERS_GUEST_CONTROLLED_COMPLETED')
        self.assertEqual(r['allocation_calls_observed'],16)
        self.assertLess(e.index('deactivate'),e.index('broker-stop'));self.assertLess(e.index('broker-stop'),e.index('SDK-cleanup'))
    def test_post_guest_hash_failure_still_releases_owned_objects(self):
        r,e=self.fixture('bad_payload');self.assertTrue(r['SDK_resources_released'])
        self.assertFalse(r['all_UB_payloads_verified_after_Guest_exit']);self.assertTrue(r['status'].startswith('STOPPED'))
    def test_unconfirmed_runtime_restore_preserves_sdk_ownership(self):
        r,e=self.fixture('restore_fail');self.assertNotIn('SDK-cleanup',e);self.assertFalse(r['SDK_resources_released'])
    def test_publication_failure_cleans_before_any_service_action(self):
        r,e=self.fixture('publish_fail');self.assertNotIn('activate',e);self.assertIn('SDK-cleanup',e)
        self.assertEqual(r['allocation_calls_observed'],2)

if __name__=='__main__':unittest.main(verbosity=2)
