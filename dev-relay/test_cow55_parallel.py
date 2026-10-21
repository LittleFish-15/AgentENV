import concurrent.futures,contextlib,copy,hashlib,importlib.util,json,os,shutil,threading,time,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('parallel55_test',Path(__file__).with_name('cow55_parallel.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Checkpoints(unittest.TestCase):
    def test_disappeared_worker_without_receipt_not_adopted(self):
        state={'run_id':'run','input_sha256':'pin','status':'COW55_TEMPLATE_PREPARATION_RUNNING','worker_pid':123,'worker_start_ticks':'ticks','worker_finished':False}
        with patch.object(m,'B',types.SimpleNamespace(STATE='state',INPUT_SHA='pin',read_json=lambda p:state)),patch.object(m,'same_process',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'orphan'):m.handoff({'source_run_id':'run'})
    def test_only_known_build_poll_is_transferable(self):
        for stage in ('BUILDING','WAITING_ASYNC'):
            self.assertTrue(m.transferable({'cases':[{'state':'READY'},{'state':stage},{'state':'RESOLVED'}]}))
        for stage in ('DOWNLOADING','CREATE_INTENT','CREATED','BUILD_INTENT','IMAGE_VERIFIED'):
            self.assertFalse(m.transferable({'cases':[{'state':stage},{'state':'RESOLVED'}]}))
    def test_guard_resumes_on_exception(self):
        calls=[]
        class Sock:
            def close(self):pass
            def fileno(self):return 9
            def settimeout(self,x):pass
            def recv(self,n):return b'R'
            def sendall(self,x):pass
        watch=types.SimpleNamespace(wait=lambda timeout:0)
        sig=types.SimpleNamespace(SIGSTOP=19,SIGCONT=18)
        with patch.object(m,'serial_identity',return_value=True),patch.object(m.socket,'socketpair',return_value=(Sock(),Sock())),patch.object(m.subprocess,'Popen',return_value=watch),patch.object(m.os,'kill',side_effect=lambda p,s:calls.append((p,s))),patch.object(m,'signal',sig),patch.object(Path,'read_text',return_value='State:\tT (stopped)\n'):
            with self.assertRaisesRegex(RuntimeError,'fixture'):
                with m.guarded_stop(123,'ticks'):raise RuntimeError('fixture')
        self.assertEqual(calls,[(123,19),(123,18)])
    def test_failed_watchdog_handshake_never_stops(self):
        calls=[]
        class Sock:
            def close(self):pass
            def fileno(self):return 9
            def settimeout(self,x):pass
            def recv(self,n):return b''
            def sendall(self,x):pass
        with patch.object(m,'serial_identity',return_value=True),patch.object(m.socket,'socketpair',return_value=(Sock(),Sock())),patch.object(m.subprocess,'Popen',return_value=types.SimpleNamespace(wait=lambda timeout:0)),patch.object(m.os,'kill',side_effect=lambda *a:calls.append(a)):
            with self.assertRaises(RuntimeError):
                with m.guarded_stop(123,'ticks'):pass
        self.assertEqual(calls,[])
    def test_watchdog_releases_on_parent_socket_EOF(self):
        calls=[]
        class Sock:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def settimeout(self,x):pass
            def sendall(self,x):pass
            def recv(self,n):return b''
        with patch.object(m,'serial_identity',return_value=True),patch.object(m.socket,'socket',return_value=Sock()),patch.object(m.os,'kill',side_effect=lambda *a:calls.append(a)),patch.object(m,'signal',types.SimpleNamespace(SIGCONT=18)):
            m.watchdog(9,123,'ticks')
        self.assertEqual(calls,[(123,18)])

class CacheAndJournal(unittest.TestCase):
    def setUp(self):
        self.root=(Path.cwd()/('.cow55-parallel-test-'+uuid.uuid4().hex)).resolve();self.root.mkdir()
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        if os.name=='nt':
            # Test-owned regular files only. Linux production retains both flags.
            for flag in ('O_NOFOLLOW','O_NONBLOCK'):
                if not hasattr(os,flag):self.stack.enter_context(patch.object(os,flag,0,create=True))
        mkdir=os.mkdir
        self.stack.enter_context(patch.object(os,'mkdir',side_effect=lambda p,mode=0o777,**kw:mkdir(p,0o755 if os.name=='nt' else mode,**kw)))
        self.calls=[];self.data=b'verified shared layer';self.digest='sha256:'+hashlib.sha256(self.data).hexdigest()
        def download(cmd,env,out,timeout):
            self.calls.append(cmd);time.sleep(.01);out.write_bytes(self.data)
        self.h=types.SimpleNamespace(safe=lambda p:p,read=lambda p,*a:p.read_bytes(),checked_process=download,save=lambda p,v:p.write_text(json.dumps(v)))
        self.b=types.SimpleNamespace(MAX_IMAGE=8*1024**3,BASE=self.root,DIGEST=r'sha256:[0-9a-f]{64}',capacity=lambda:None,STATE=self.root/'state.json')
        self.stack.enter_context(patch.object(m,'H',self.h));self.stack.enter_context(patch.object(m,'B',self.b))
    def tearDown(self):
        self.stack.close();self.assertEqual(self.root.parent,Path.cwd().resolve());self.assertTrue(self.root.name.startswith('.cow55-parallel-test-'));shutil.rmtree(self.root)
    def cache(self):return m.BlobCache({'work_directory':str(self.root/'batch'),'cases':[{} for _ in range(3)]},self.root/'cas',{})
    def test_ten_requests_same_digest_download_once(self):
        cache=self.cache();d={'digest':self.digest,'size':len(self.data)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:paths=list(pool.map(lambda _:cache.get(d,'example/repo'),range(10)))
        self.assertEqual(len(self.calls),1);self.assertEqual(len(set(paths)),1)
        self.assertEqual(paths[0].read_bytes(),self.data)
    def test_existing_batch_blob_reused_without_network(self):
        p=self.root/'batch/case-01/image/blobs/sha256'/self.digest.split(':')[1];p.parent.mkdir(parents=True);p.write_bytes(self.data)
        cache=self.cache();dest=cache.get({'digest':self.digest,'size':len(self.data)},'example/repo')
        self.assertEqual(self.calls,[]);self.assertEqual(dest.stat().st_ino,p.stat().st_ino)
    def test_corrupt_existing_blob_stops_without_redownload(self):
        p=self.root/'batch/case-01/image/blobs/sha256'/self.digest.split(':')[1];p.parent.mkdir(parents=True);p.write_bytes(b'x'*len(self.data))
        with self.assertRaises(RuntimeError):self.cache().get({'digest':self.digest,'size':len(self.data)},'example/repo')
        self.assertEqual(self.calls,[]);self.assertEqual(p.read_bytes(),b'x'*len(self.data))
    def test_failed_download_not_published(self):
        cache=self.cache()
        with patch.object(self.h,'checked_process',side_effect=RuntimeError('network')):
            with self.assertRaises(RuntimeError):cache.get({'digest':self.digest,'size':len(self.data)},'example/repo')
        self.assertFalse((cache.root/self.digest.split(':')[1]).exists())
    def test_other_task_does_not_retry_failed_digest(self):
        cache=self.cache();d={'digest':self.digest,'size':len(self.data)}
        with patch.object(self.h,'checked_process',side_effect=RuntimeError('network')) as download:
            for _ in range(2):
                with self.assertRaises(RuntimeError):cache.get(d,'example/repo')
            self.assertEqual(download.call_count,1)
    def test_same_digest_wrong_size_rejected(self):
        cache=self.cache();cache.get({'digest':self.digest,'size':len(self.data)},'example/repo')
        with self.assertRaises(RuntimeError):cache.get({'digest':self.digest,'size':1},'example/repo')
        self.assertEqual(len(self.calls),1)
    def test_ten_workers_merge_distinct_case_snapshots(self):
        state={'cases':[{'index':i} for i in range(10)]};journal=m.Journal(state)
        def update(i):
            local={'_index':i,'cases':[{'index':i,'count':0}]}
            for n in range(20):local['cases'][0]['count']=n;journal.publish(local)
            local['cases'][0]['count']=999 # must not alter published state
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:list(pool.map(update,range(10)))
        final=json.loads(self.b.STATE.read_text());self.assertEqual([r['index'] for r in final['cases']],list(range(10)))
        self.assertTrue(all(r['count']==19 for r in final['cases']))
    def test_metadata_conflict_preserved(self):
        p=self.root/'meta';p.write_bytes(b'old')
        with self.assertRaises(RuntimeError):m.put_new(p,b'new')
        self.assertEqual(p.read_bytes(),b'old')
    def test_full_cohort_each_case_once_max_ten_and_merge(self):
        state={'original_identity':[1,'start'],'work_directory':str(self.root/'batch'),
               'cases':[{'index':i,'state':'RESOLVED'} for i in range(55)]}
        control={'work_directory':str(self.root),'jobs':10};guard=threading.Lock();active=0;maximum=0;seen=[]
        def execute(i,journal,cache,api):
            nonlocal active,maximum
            with guard:active+=1;maximum=max(maximum,active);seen.append(i)
            time.sleep(.005)
            case={'index':i,'state':'READY','template_id':'id-'+str(i),'build_id':'id-'+str(i),
                  'resources':{'memory_mib':4096},'layer_inventory_summary':{'available':True}}
            journal.publish({'_index':i,'cases':[case]})
            with guard:active-=1
        self.b.Api=lambda identity:types.SimpleNamespace(key='not-a-real-key')
        self.b.empty=lambda api:None;self.b.environment=lambda work:({},{});self.b.verify_ready=lambda c:None
        self.h.runtime_pid=lambda:(1,'start');self.h.redact_child_output=lambda s,e:s
        read_text=Path.read_text
        def read(path,*args,**kwargs):
            return 'MemAvailable: 1073741824 kB\n' if str(path)=='/proc/meminfo' or str(path)=='\\proc\\meminfo' else read_text(path,*args,**kwargs)
        with patch.object(m,'execute',execute),patch.object(m,'ticks',return_value='worker'),patch.object(Path,'read_text',read):m.parallel_run(state,control)
        self.assertEqual(sorted(seen),list(range(55)));self.assertLessEqual(maximum,10);self.assertGreater(maximum,1)
        self.assertTrue(state['final_merge_verified']);self.assertEqual(state['status'],'COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED')
    def test_more_known_active_builds_than_jobs_refused(self):
        s={'cases':[{'state':'BUILDING'} for _ in range(3)]}
        with self.assertRaisesRegex(RuntimeError,'exceed'):m.parallel_run(s,{'jobs':2})

if __name__=='__main__':unittest.main()
