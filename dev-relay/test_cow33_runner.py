import ast, base64, contextlib, hashlib, importlib.util, io, json, os, shutil, types, unittest, uuid
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def module(name):
    s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
engine=module('cow55_replay');driver=module('cow33_driver');driver.ENGINE=engine

class DeviceBudget(unittest.TestCase):
    def current(self,count=10):return {'limit':64,'char_ids':list(range(count)),'block_size_bytes':{}}
    def test_first_batch_17_fits_with_10_unknown(self):
        v=driver.device_budget(self.current(),17)
        self.assertTrue(v['fits']);self.assertEqual(v['required_new_slots_estimate'],51);self.assertEqual(v['reserve_slots'],2)
    def test_unknown_existing_devices_not_assumed_reusable(self):
        self.assertFalse(driver.device_budget(self.current(20),17)['fits'])
    def test_second_batch_counts_reusable_sizes_not_just_devices(self):
        c=self.current(61);c['block_size_bytes']={str(i):(4 if i<27 else 64)*1024**3 for i in range(10,61)}
        old={'ublk_before':self.current(),'ublk_before_cleanup':c,'ublk_after_cleanup':c}
        v=driver.device_budget(c,16,old);self.assertTrue(v['fits']);self.assertEqual(v['required_new_slots_estimate'],0)
        wrong=dict(c,block_size_bytes={str(i):8*1024**3 for i in range(10,61)})
        self.assertFalse(driver.device_budget(wrong,16,old)['fits'])
    def test_external_new_device_blocks_second_batch(self):
        c=self.current(61);old={'ublk_before':self.current(),'ublk_before_cleanup':c,'ublk_after_cleanup':c}
        with self.assertRaises(RuntimeError):driver.device_budget(self.current(62),16,old)
    def test_different_kernel_limit_is_not_silently_accepted(self):
        with self.assertRaises(RuntimeError):driver.device_budget(dict(self.current(),limit=256),17)

class SmallCohorts(unittest.TestCase):
    def setUp(self):
        self.root=Path.cwd()/('.cow33-test-'+uuid.uuid4().hex);self.root.mkdir(mode=0o755)
        self.stack=contextlib.ExitStack();self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        mkdir=os.mkdir;self.stack.enter_context(patch.object(os,'mkdir',side_effect=lambda p,mode=0o777,**kw:mkdir(p,0o755 if os.name=='nt' else mode,**kw)))
        self.stack.enter_context(patch.object(engine,'ROOT',self.root));self.stack.enter_context(patch.object(engine,'PENDING',self.root/'pending.json'))
        self.stack.enter_context(patch.object(engine,'H',types.SimpleNamespace(save=lambda p,v:p.write_text(json.dumps(v)),error_summary=lambda v,k:v)))
        self.stack.enter_context(patch.object(engine,'B',types.SimpleNamespace(ID=r'[0-9a-f-]{36}')))
        self.stack.enter_context(patch.object(engine,'R',types.SimpleNamespace(find_firecrackers=lambda p:[])))
        self.stack.enter_context(patch.object(engine.Cohort,'guard',return_value=None))
        self.stack.enter_context(patch.object(engine,'summarize_measurements',return_value={'fixture':True}))
        class Api:
            def __init__(s,identity):s.identity=identity;s.key='e2b_fixture';s.live={};s.created=0
            def call(s,method,path,body=None,timeout=None):
                if path=='/health':return 204,None
                if path=='/v2/sandboxes?limit=1':return 200,[]
                if method=='POST':
                    sid=str(uuid.uuid4());s.live[sid]={'sandboxID':sid,'metadata':body['metadata']};s.created+=1;return 201,{'sandboxID':sid}
                sid=path.rsplit('/',1)[-1]
                if method=='DELETE':s.live.pop(sid,None);return 204,None
                return (200,s.live[sid]) if sid in s.live else (404,None)
        self.stack.enter_context(patch.object(engine,'Api',Api))
    def tearDown(self):
        self.stack.close();self.assertEqual(self.root.parent,Path.cwd());self.assertTrue(self.root.name.startswith('.cow33-test-'));shutil.rmtree(self.root)
    def create_cohort(self,count):
        raw=json.dumps({'trajectory':[{'action':'true','delay_time':0}]}).encode();cases=[];built=[];replays={}
        for i in range(count):
            key=str(i);sid=str(uuid.uuid4());cases.append({'instance_id':key,'replay_file':key,'replay_sha256':hashlib.sha256(raw).hexdigest()})
            built.append({'instance_id':key,'state':'READY','resources':{'memory_mib':4096},'template_id':sid,'build_id':sid,'catalog_sha256':'a'*64})
            replays[key]=base64.b64encode(raw).decode()
        return engine.Cohort(self.root,{'original_identity':[1,'1'],'run_id':'fixture','cases':built},
            {'cohort':{'cases':cases},'replays':replays},template_count=count,admission_workers=1)
    def test_17_templates_budget_34_and_cleanup(self):
        c=self.create_cohort(17)
        with patch.object(c,'command',return_value={'return_code':0}):
            for job in c.jobs:c.create(job)
        self.assertEqual(c.api.created,34);self.assertEqual(c.report['max_guests'],34)
        with self.assertRaises(RuntimeError):c.create({'index':34,'template_id':'extra','state':'NOT_CREATED'})
        c.cleanup();self.assertFalse(c.api.live);self.assertEqual(len(c.report['released_sandboxes']),34)
    def test_16_templates_zero_create_failure_does_not_count_phantom_templates(self):
        c=self.create_cohort(16)
        with patch.object(c,'guard',side_effect=RuntimeError('preflight fixture')):c.run('','')
        self.assertEqual(c.report['replay_completed_templates'],0);self.assertEqual(c.report['template_count'],16)
        self.assertEqual(c.report['restore_calls'],0);self.assertEqual(c.report['max_guests'],32)

class Reporting(unittest.TestCase):
    def test_phase_transition_does_not_delay_short_replay_for_300_seconds(self):
        reader=module('cow55_reader')
        self.assertEqual(reader.physical_wave_wait_seconds('baseline','replay',10),0)
        self.assertEqual(reader.physical_wave_wait_seconds('replay','final_hold',10),0)
        self.assertEqual(reader.physical_wave_wait_seconds('replay','replay',10),290)
        self.assertEqual(reader.physical_wave_wait_seconds('replay','replay',350),0)
    def test_markdown_uses_actual_reducer_field_names(self):
        process=module('cow55_process_summary');s=process.Summary()
        s.add(dict(run_id='r',variant='original',mode='continuous',node='node-a',boot_id='boot',phase='replay',template_id='template',
            sample_id='0',sandbox_ids=['a','b'],started_unix=1,finished_unix=2,
            processes=[dict(sandbox_id=i,identity_verified=True,rss_bytes=4*1024**2,pss_bytes=3*1024**2) for i in ('a','b')]))
        rows=[dict(r,batch_number=1,trajectory='fixture') for r in s.result()['rows']]
        text=driver.summary_markdown({'reported_batches':1,'completed_templates':1,'process_rows':rows,'rootfs_rows':[],
            'physical_rows':[],'batches':[],'global_file_cache_sweeps_by_batch':[]})
        self.assertIn('|4.000|4.000|3.000|3.000|1.000|1.000|2.000|2.000|1|1|',text)
        self.assertIn('1/2',text);self.assertIn('1/33',text)
    def test_reader_scope_is_explicit_and_phase_change_invalidated(self):
        source=(HERE/'cow55_reader.py').read_text();ast.parse(source)
        self.assertIn('count in (16,17,55)',source);self.assertIn('PHASE_CHANGED_DURING_PAIR_SAMPLE',source)
        self.assertEqual(hashlib.sha256((HERE/'cow55_reader.py').read_bytes()).hexdigest(),engine.READER_SHA)
    def test_bundle_embeds_exact_reviewable_sources(self):
        builder=module('build_cow33_once');builder.build();bundle=module('cow33_once')
        for name in ('cow55_replay','cow55_reader','cow33_selection'):
            self.assertEqual(bundle._embedded(name),(HERE/(name+'.py')).read_bytes())
        self.assertEqual(bundle.EXPECTED_RUNTIME,(3713139,'35114697'))

if __name__=='__main__':unittest.main()
