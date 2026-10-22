import ast, builtins, contextlib, importlib.util, io, json, types, unittest, uuid
from pathlib import Path
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


p=load('global_packet',HERE/'cow4_global_cache_once.py')
root=load('global_root',HERE/'rootfs-access/global_drop_root.py')


@contextlib.contextmanager
def directory():
    d=HERE/('.global-test-'+uuid.uuid4().hex);d.mkdir(mode=0o777)
    try:yield d
    finally:
        for f in d.iterdir():
            if f.is_file():f.unlink()
        d.rmdir()


def baseline():
    return {'monotonic_ns':1000000000,'host':{'Cached':1000},'lower_resident_bytes':0,
            'known_other_file_cache':{'complete_for_listed_prefixes':True,'observed_resident_bytes':100}}


def frame():
    return {'experiment_phase':'replay','sample_id':0,
            'residency_probe':{'started_monotonic_ns':2000000000,'finished_monotonic_ns':3000000000,
                              'whole_lower_resident_bytes':8192,'host_memory_before':{'Cached':10000},'host_memory_after':{'Cached':11000}},
            'known_other_file_cache':{'complete_for_listed_prefixes':True,'observed_resident_bytes':1000,'category_bytes':{}},
            'global_accessed_resident_union_bytes':4096,'global_same_template_shared_accessed_resident_bytes':0,'templates':[]}


class GlobalTests(unittest.TestCase):
    def test_read_sizes_are_scoped_to_successful_lower_reads_in_replay_window(self):
        rows=[{'kind':'header'},
              {'source':'s','allowed_lower':True,'direct_io':False,'end_ns':150,'bytes':262144},
              {'source':'s','allowed_lower':True,'direct_io':False,'end_ns':250,'bytes':262144},
              {'source':'s','allowed_lower':False,'direct_io':False,'end_ns':150,'bytes':4096}]
        class Work:
            def __truediv__(self,key):return types.SimpleNamespace(open=lambda **kw:io.StringIO('\n'.join(json.dumps(r) for r in rows)))
        result=p.TIMESERIES.read_size_profile(Work(),{'bindings':[{'source':'s','sandbox_id':'a'}],
            'trajectory_windows_monotonic_ns':{'a':[100,200]}},[{'observer_status':{'records_written':3}}])
        self.assertTrue(result['available']);self.assertEqual(result['calls_total'],1);self.assertEqual(result['calls_exactly_256k'],1)
        self.assertFalse(result['physical_disk_IO_or_folio_size_inferred'])
    def root_context(self):
        root.require=p.ENGINE.need;root.time=types.SimpleNamespace(monotonic_ns=Mock(return_value=200*10**9),time=Mock(return_value=1))
        root.subprocess=types.SimpleNamespace(run=Mock())
        root.root_cache_counts=Mock(return_value={'Cached':123,'Dirty':0})
        root.other_units=Mock(return_value={'other':'same'})
        root.unit_state=Mock(return_value={'MainPID':'1'});root.find_firecrackers=Mock(return_value=list(range(10,18)))
        root.identity=Mock(return_value=(1,'ticks'))
        root.api_get=Mock(return_value=(200,{'metadata':{'cow55_run':'run'}}))
        return {'operator_declared_quiet_window':True,'run_id':'run'},[{'pid':10+i,'start_ticks':'ticks','sandbox_id':str(i)} for i in range(8)],{'other':'same'}
    def test_two_ordered_drops_only_fixed_value_one(self):
        plan,bound,others=self.root_context();report={}
        stream=Mock();stream.write.return_value=2
        opening=Mock();opening.return_value.__enter__=Mock(return_value=stream);opening.return_value.__exit__=Mock(return_value=False)
        with patch.object(builtins,'open',opening):
            first=root.global_drop_once({'phase':'idle_control'},report,plan,bound,others)
            root.time.monotonic_ns.return_value+=61*10**9
            second=root.global_drop_once({'phase':'replay'},report,plan,bound,others)
            with self.assertRaisesRegex(RuntimeError,'Unexpected/repeated'):root.global_drop_once({'phase':'replay'},report,plan,bound,others)
        self.assertTrue(first['drop_write_completed'] and second['drop_write_completed'])
        self.assertEqual(stream.write.call_count,2);stream.write.assert_called_with('1\n')
        self.assertEqual(opening.call_count,2)
        opening.assert_called_with('/proc/sys/vm/drop_caches','w',encoding='ascii')
    def test_no_drop_without_declared_quiet_window(self):
        plan,bound,others=self.root_context();plan['operator_declared_quiet_window']=False
        with patch.object(builtins,'open') as opening:
            with self.assertRaisesRegex(RuntimeError,'Quiet-window'):root.global_drop_once({'phase':'idle_control'},{},plan,bound,others)
            opening.assert_not_called();root.subprocess.run.assert_not_called()
    def test_changed_other_service_blocks_global_sync(self):
        plan,bound,others=self.root_context();root.other_units.return_value={}
        with self.assertRaisesRegex(RuntimeError,'Other service'):root.global_drop_once({'phase':'idle_control'},{},plan,bound,others)
        root.subprocess.run.assert_not_called()
    def test_extra_original_guest_blocks_global_sync(self):
        plan,bound,others=self.root_context();root.find_firecrackers.return_value=list(range(10,19))
        with self.assertRaisesRegex(RuntimeError,'Unexpected Guest'):root.global_drop_once({'phase':'idle_control'},{},plan,bound,others)
        root.subprocess.run.assert_not_called()
    def test_sync_failure_records_intent_but_never_drops(self):
        plan,bound,others=self.root_context();report={};root.subprocess.run.side_effect=TimeoutError('test')
        with patch.object(builtins,'open') as opening:
            with self.assertRaises(TimeoutError):root.global_drop_once({'phase':'idle_control'},report,plan,bound,others)
            opening.assert_not_called()
        self.assertFalse(report['global_pagecache_drops'][0]['drop_requested'])
    def test_second_drop_requires_full_idle_interval(self):
        plan,bound,others=self.root_context();r={'global_pagecache_drops':[{'finished_monotonic_ns':199*10**9}]}
        with self.assertRaisesRegex(RuntimeError,'Idle control'):root.global_drop_once({'phase':'replay'},r,plan,bound,others)
        root.subprocess.run.assert_not_called()
    def test_host_delta_and_residual_use_own_phase_baseline(self):
        result=p.TIMESERIES.reduce([{'phase':'replay','monotonic_ns':2*10**9,'Cached':11000}],
            [frame()],{'replay':baseline()},{});row=result['file_rows'][0]
        self.assertEqual(row['seconds_since_phase_baseline'],2)
        self.assertEqual(row['known_other_file_delta_bytes'],900)
        self.assertEqual(row['unexplained_delta_bytes'],10000-8192-900)
        self.assertEqual(result['host_rows'][0]['cached_delta_bytes'],10000)
    def test_missing_auxiliary_sample_does_not_become_zero(self):
        f=frame();f['known_other_file_cache']['complete_for_listed_prefixes']=False
        r=p.TIMESERIES.reduce([], [f], {'replay':baseline()}, {})['file_rows'][0]
        self.assertIsNone(r['known_other_file_delta_bytes']);self.assertIsNone(r['unexplained_delta_bytes'])
    def test_invalid_shared_set_inclusion_rejected(self):
        f=frame();f['global_same_template_shared_accessed_resident_bytes']=8192
        with self.assertRaisesRegex(ValueError,'set inclusion'):p.TIMESERIES.reduce([], [f], {'replay':baseline()}, {})
    def test_packet_uses_new_lifecycle_but_same_binary(self):
        code=(HERE/'cow4_global_cache_once.py').read_text(encoding='utf-8')
        self.assertIs(p.FourRun,p.GlobalFourRun)
        self.assertIn('cow4-global-cache-v2-node-a.pending.json',code)
        self.assertIn('--accept-nonzero-baseline',code)
        self.assertIn('--quiet-window-confirmed',code)
        self.assertIn("'operator_declared_quiet_window':args.quiet_window_confirmed",code)
        self.assertEqual(p.CANDIDATE_SHA,'eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf')
        self.assertEqual(p.ROOT_SOURCE.count("elif op=='drop_pagecache'"),1)
    def test_host_sampler_failure_is_visible(self):
        with directory() as d:
            timeline=p.HostTimeline(d);timeline.path=d/'host.jsonl'
            with patch.object(p,'global_host_row',side_effect=OSError('fixture')):
                timeline.start();timeline.thread.join(timeout=2)
            with self.assertRaisesRegex(RuntimeError,'Host timeline failed'):timeline.stop()
    def test_root_program_is_syntax_valid_and_fixed_unit_only(self):
        tree=ast.parse(p.ROOT_SOURCE)
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.List) and len(n.elts)>=2 and isinstance(n.elts[0],ast.Constant) and n.elts[0].value=='/usr/bin/systemctl']
        for call in calls:
            if isinstance(call.elts[1],ast.Constant) and call.elts[1].value=='restart':
                self.assertIsInstance(call.elts[2],ast.Name);self.assertEqual(call.elts[2].id,'UNIT')
        self.assertEqual(p.ROOT_SOURCE.count("f.write('1\\n')"),1)
    def test_owner_sequence_eight_guests_idle_then_second_drop_then_replay(self):
        clock=types.SimpleNamespace(now=1.)
        fake_time=types.SimpleNamespace(monotonic=lambda:clock.now,monotonic_ns=lambda:int(clock.now*1e9),
            sleep=lambda seconds:setattr(clock,'now',clock.now+seconds))
        jobs=[{'sandbox_id':str(i),'template_id':str(i//2)} for i in range(8)]
        cohort=types.SimpleNamespace(work=HERE/'nonexistent-fixture-work',jobs=jobs,max_guests=8,report={},
            create=Mock(),guard=Mock(),persist=Mock(),stop=Mock())
        plan={'template_lowers':{str(i):[] for i in range(4)}}
        runner=p.GlobalFourRun(cohort,plan,{},None)
        runner.timeline=types.SimpleNamespace(start=Mock(),check=Mock(),stop=Mock(),phase='',rows=100,error=None,path=Path('host.jsonl'))
        bindings=[dict(j,source='source'+j['sandbox_id'],lowers=[],uppers=[]) for j in jobs]
        runner.rpc=Mock(return_value={'bindings':bindings,'observer_identity':[123,'ticks']})
        events=[]
        def drop(phase):
            events.append((phase,clock.now));runner.start=int(clock.now*1e9);runner.experiment_phase=phase
        runner.global_cold=drop
        runner.metrics=Mock();runner.cache=Mock()
        def replay(job):events.append(('action',clock.now));runner.ends[job['sandbox_id']]=int(clock.now*1e9)
        runner.replay=replay
        class ImmediatePool:
            def __init__(self,**kw):pass
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def submit(self,fn,*args):fn(*args);return types.SimpleNamespace(done=lambda:True,result=lambda:None)
        with patch.object(p,'time',fake_time),patch.object(p.COLD,'environment',return_value={}),patch.object(p.COLD,'calibrate',return_value={}),patch.object(p.COLD,'independent_check',return_value={}),patch.object(p.concurrent.futures,'ThreadPoolExecutor',ImmediatePool):
            runner.run()
        self.assertEqual(cohort.create.call_count,8)
        self.assertEqual([e[0] for e in events[:2]],['idle_control','replay'])
        self.assertGreaterEqual(events[1][1]-events[0][1],60)
        self.assertEqual(len([e for e in events if e[0]=='action']),8)
        runner.timeline.stop.assert_called_once()


if __name__=='__main__':unittest.main()
