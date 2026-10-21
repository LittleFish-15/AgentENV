import ast,base64,contextlib,hashlib,importlib.util,io,json,os,shutil,threading,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('replay55_test',HERE/'cow55_replay.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ID=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

class SyntaxAndSemantics(unittest.TestCase):
    def test_sources_pinned_and_inline_root_syntax(self):
        source=(HERE/'cow55_reader.py').read_bytes();self.assertEqual(hashlib.sha256(source).hexdigest(),m.READER_SHA)
        ast.parse((HERE/'cow_ram_readonly.py').read_text()+source.decode()+'\ncohort_reader({}, {})\n')
        for name,digest in [('cow55_process_summary.py',m.PROCESS_SUMMARY_SHA),('cow55_rootfs_accounting.py',m.ROOTFS_SUMMARY_SHA)]:self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)
    def test_terminal_action_not_executed(self):
        rows,terminal=m.steps_from(json.dumps({'trajectory':[{'action':'echo first','delay_time':1},{'action':'submit'},{'action':'echo never'}]}))
        self.assertEqual(len(rows),1);self.assertEqual(terminal,'submit');self.assertEqual(rows[0]['delay'],1)
    def test_negative_delay_rejected(self):
        with self.assertRaises(RuntimeError):m.steps_from('{"trajectory":[{"action":"true","delay_time":-1}]}')
    def test_rendered_editor_boundary_normalization(self):
        import shlex
        action=shlex.join(['str_replace_editor','str_replace','x','--old_str','\nold\n','--new_str','\nnew\n'])
        result=shlex.split(m.normalize_action(action));self.assertEqual(result[result.index('--old_str')+1],'old');self.assertEqual(result[result.index('--new_str')+1],'new')
    def test_arbitrary_action_remains_guest_shell_argument(self):
        import shlex
        value=m.shell_command("echo 'hello'; printf '$HOME'",'COW55_END_test')
        self.assertIn('timeout -s TERM -k 5 300',value);self.assertIn('set +o pipefail',value);self.assertIn('cd -- /',value)
        self.assertEqual(shlex.split(value)[9],'/bin/bash')

class FakeApi:
    def __init__(self,identity):self.identity=tuple(identity);self.key='e2b_test_fixture';self.calls=[];self.live={};self.lose_create=False;self.foreign=False
    def call(self,method,path,body=None,timeout=None):
        self.calls.append((method,path,body))
        if path=='/health':return 204,None
        if path=='/v2/sandboxes?limit=1':return 200,[]
        if method=='POST':
            sid=str(uuid.uuid4());self.live[sid]=dict(sandboxID=sid,metadata=body['metadata'])
            if self.lose_create:raise TimeoutError('response lost')
            return 201,{'sandboxID':sid}
        if path.startswith('/v2/sandboxes?metadata='):return 200,list(self.live.values())
        sid=path.rsplit('/',1)[-1]
        if method=='DELETE':self.live.pop(sid,None);return 204,None
        if sid not in self.live:return 404,None
        if self.foreign:return 200,{'metadata':{'cow55_run':'other'}}
        return 200,self.live[sid]

class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.root=(Path.cwd()/('.cow55-replay-test-'+uuid.uuid4().hex)).resolve();self.root.mkdir();self.stack=contextlib.ExitStack()
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        mkdir=os.mkdir;self.stack.enter_context(patch.object(os,'mkdir',side_effect=lambda p,mode=0o777,**kw:mkdir(p,0o755 if os.name=='nt' else mode,**kw)))
        self.stack.enter_context(patch.object(m,'ROOT',self.root));self.stack.enter_context(patch.object(m,'PENDING',self.root/'pending.json'))
        self.stack.enter_context(patch.object(m,'Api',FakeApi));self.stack.enter_context(patch.object(m,'B',types.SimpleNamespace(ID=ID)))
        self.stack.enter_context(patch.object(m,'R',types.SimpleNamespace(find_firecrackers=lambda pid:[])))
        self.stack.enter_context(patch.object(m,'H',types.SimpleNamespace(save=lambda p,v:p.write_text(json.dumps(v)),error_summary=lambda b,k:b)))
        self.stack.enter_context(patch.object(m,'summarize_measurements',return_value={'fixture':True}))
        self.stack.enter_context(patch.object(m.Cohort,'guard',return_value=None))
        raw=json.dumps({'trajectory':[{'action':'false','delay_time':0},{'action':'true','delay_time':0}]}).encode()
        cases=[{'instance_id':'t'+str(i),'template_id':str(uuid.uuid4()),'catalog_sha256':'a'*64,'state':'READY','resources':{'memory_mib':4096}} for i in range(55)]
        for c in cases:c['build_id']=c['template_id']
        inputs={'cohort':{'cases':[{'instance_id':c['instance_id'],'replay_file':str(i),'replay_sha256':hashlib.sha256(raw).hexdigest()} for i,c in enumerate(cases)]},
                'replays':{str(i):base64.b64encode(raw).decode() for i in range(55)}}
        self.c=m.Cohort(self.root,{'run_id':'build','original_identity':[1,'ticks'],'cases':cases},inputs)
    def tearDown(self):
        self.stack.close();self.assertEqual(self.root.parent,Path.cwd().resolve());self.assertTrue(self.root.name.startswith('.cow55-replay-test-'));shutil.rmtree(self.root)
    def test_probe_failure_stops_before_expansion_and_releases(self):
        with patch.object(self.c,'command',return_value={'return_code':1}),contextlib.redirect_stdout(io.StringIO()):self.c.run('','')
        self.assertEqual(sum(v[0]=='POST' for v in self.c.api.calls),1)
        self.assertTrue(self.c.report['all_cohort_guests_released']);self.assertFalse(self.c.credential.exists())
        self.assertEqual(self.c.report['status'],'STOPPED_COW55_REPLAY')
    def test_lost_create_reconciles_then_cleans_without_repost(self):
        self.c.api.lose_create=True
        with contextlib.redirect_stdout(io.StringIO()):self.c.run('','')
        self.assertEqual(sum(v[0]=='POST' for v in self.c.api.calls),1)
        self.assertTrue(self.c.report['all_cohort_guests_released']);self.assertFalse(self.c.api.live)
        self.assertEqual(self.c.jobs[0]['state'],'RECONCILED_FOR_CLEANUP')
    def test_foreign_metadata_never_deleted(self):
        job=self.c.jobs[0]
        with patch.object(self.c,'command',return_value={'return_code':0}):self.c.create(job)
        self.c.api.foreign=True;self.c.cleanup()
        self.assertFalse(any(v[0]=='DELETE' for v in self.c.api.calls));self.assertTrue(self.c.report['cleanup_errors'])
    def test_nonzero_command_can_continue_like_default_runner(self):
        job=self.c.jobs[0];job['sandbox_id']=str(uuid.uuid4())
        with patch.object(self.c,'command',side_effect=[{'return_code':1},{'return_code':0}]),patch.object(self.c,'control',return_value=None):self.c.replay(job)
        self.assertEqual(job['state'],'REPLAY_COMPLETED');self.assertEqual(job['steps_completed'],2);self.assertEqual(job['failed_commands'],1)
    def test_timeout_stops_remaining_steps(self):
        job=self.c.jobs[0];job['sandbox_id']=str(uuid.uuid4())
        with patch.object(self.c,'command',return_value={'return_code':124}) as command:
            with self.assertRaises(RuntimeError):self.c.replay(job)
        self.assertEqual(command.call_count,1);self.assertTrue(self.c.stop.is_set());self.assertEqual(job['state'],'REPLAY_FAILED')
    def test_110_distinct_guests_and_budget(self):
        with patch.object(self.c,'command',return_value={'return_code':0}):
            for job in self.c.jobs:self.c.create(job)
            with self.assertRaises(RuntimeError):self.c.create({'index':110,'template_id':'extra','state':'NOT_CREATED'})
        self.assertEqual(self.c.report['restore_calls'],110);self.assertEqual(len(set(self.c.created)),110)
    def test_summary_produces_process_rootfs_and_physical_tables(self):
        t=self.c.jobs[0]['template_id'];sids=['s1','s2'];work=self.root
        sample=dict(run_id='run',variant='original',mode='continuous',node='node-a',boot_id='boot',phase='replay',template_id=t,
            sample_id='0',sandbox_ids=sids,started_unix=1,finished_unix=2,
            processes=[dict(sandbox_id=s,identity_verified=True,rss_bytes=100,pss_bytes=60) for s in sids])
        files=[dict(file_id=k,node='node-a',boot_id='boot',device=1,inode=i+1,file_bytes=1024,allocated_bytes=1024,resident_bytes=4096) for i,k in enumerate(['L','U1','U2','M'])]
        refs=[]
        for i,s in enumerate(sids):
            for kind,k in [('rootfs_lower','L'),('rootfs_upper','U'+str(i+1)),('memory_lower','M')]:refs.append(dict(template_id=t,sandbox_id=s,file_id=k,kind=kind))
        cache=dict(sample_id='0',started_unix=1,finished_unix=2,files=files,references=refs,devices={},errors=[],complete_reference_inventory=True,
                   template_phases={t:'replay'},template_phase_stable={t:True})
        physical=dict(template_id=t,phase='replay',available=True,physical={'compound_attribution_complete':True,
            'categories':{'ordinary_file':{'shared_unique_bytes':40,'consumer_bytes':100},'ordinary_anon':{'shared_unique_bytes':0,'consumer_bytes':60}},
            'snapshot_file_shared_bytes_excluding_special_pages':40,'all_selected_guest_ram':{'shared_unique_bytes':40}})
        for channel,value in [('process',{'samples':[sample],'sweep_started_unix':1,'sweep_finished_unix':2}),('cache',cache),('physical',physical)]:
            (work/'measurements'/(channel+'.jsonl')).write_text(json.dumps(value)+'\n')
        loader=m.load
        # setUp replaces the summary routine; use its original function here.
        spec=importlib.util.spec_from_file_location('unpatched_summary',HERE/'cow55_replay.py');fresh=importlib.util.module_from_spec(spec);spec.loader.exec_module(fresh)
        fresh.H=m.H;fresh.ROOT=m.ROOT
        with patch.object(fresh,'load',side_effect=lambda path,digest,name:loader(HERE/path.name,digest,name)):
            result=fresh.summarize_measurements(work,{t:'fixture'})
        self.assertEqual(result['replay_process_rows'],2);self.assertEqual(result['minimum_template_paired_samples'],1)
        self.assertEqual(result['replay_rootfs_template_count'],1);self.assertEqual(result['templates_with_valid_physical_sample'],1)
        text=(work/'measurement-summary.md').read_text(encoding='utf-8');self.assertIn(t,text);self.assertIn('fixture',text)

if __name__=='__main__':unittest.main()
