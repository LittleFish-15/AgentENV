import ast,base64,copy,hashlib,importlib.util,json,shutil,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('packet17',HERE/'cow17_access_once.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec=importlib.util.spec_from_file_location('maker17',HERE/'rootfs-access/make_seventeen_packet.py');maker=importlib.util.module_from_spec(spec);spec.loader.exec_module(maker)


class SeventeenTests(unittest.TestCase):
    def jobs(self):return [{'template_id':str(i),'index':i*2+s} for i in range(17) for s in range(2)]
    def test_device_budget_uses_51_plus_reserve_then_tracks_admission(self):
        jobs=self.jobs();r=m.device_budget(jobs,{'limit':64,'registered':11})
        self.assertTrue(r['fits']);self.assertEqual(r['remaining_business_devices_estimate'],51)
        self.assertFalse(m.device_budget(jobs,{'limit':64,'registered':12})['fits'])
        jobs[0]['sandbox_id']='first'
        self.assertEqual(m.device_budget(jobs,{'limit':64,'registered':13})['remaining_business_devices_estimate'],49)
        self.assertTrue(m.device_budget(jobs,{'limit':64,'registered':13})['fits'])
        jobs[1]['sandbox_id']='second';self.assertEqual(m.device_budget(jobs,{'limit':64,'registered':14})['remaining_business_devices_estimate'],48)
    def test_exact_17_selection_and_catalog_match(self):
        languages=['go']*9+['ts']*5+['java']*3
        cases=[{'instance_id':str(i),'language':lang} for i,lang in enumerate(languages)]
        ready=[{'instance_id':str(i),'template_id':'t'+str(i),'state':'READY'} for i in range(17)]
        old={'run_id':'083604f2f76045c0beb8de4cf92c0758','all_cohort_guests_released':True,
             'jobs':[{'index':2*i+s,'instance_id':str(i),'template_id':'t'+str(i),'catalog_sha256':str(i),'state':'REPLAY_COMPLETED'} for i in range(17) for s in range(2)]}
        def verify(b):b['catalog_sha256']=b['instance_id']
        with patch.object(m.ENGINE,'B',types.SimpleNamespace(verify_ready=verify)):
            selected,built=m.select17({'cohort':{'cases':cases}},{'cases':ready},old)
        self.assertEqual(len(selected),17);self.assertEqual(len(built),17)
    def test_compiler_delta_only_changes_byte_bound_and_calibration_spec(self):
        manifest,changes,fingerprint,old=maker.compiler_inputs()
        self.assertEqual(manifest,m.INPUTS);self.assertEqual(fingerprint,m.BUDGET_PATCH_SHA)
        self.assertEqual(len(changes),2)
        observer='storage/overlaybd/src/rootfs_access_trace.rs';cal='storage/overlaybd/examples/rootfs_access_calibration.rs'
        self.assertEqual(base64.b64decode(changes[observer]['base64']),old[observer].replace(b'1048576..=268435456',b'1048576..=536870912'))
        self.assertEqual(base64.b64decode(changes[cal]['base64']),old[cal].replace(b'max_bytes=1048576',b'max_bytes=536870912'))
        self.assertIn(b'1..=1000000',base64.b64decode(changes[observer]['base64']))
    def test_stage_verifies_every_input_and_preserves_original(self):
        manifest,changes,_,files=maker.compiler_inputs()
        directory=Path.cwd()/('.cow17-stage-'+uuid.uuid4().hex);directory.mkdir(mode=0o755)
        try:
            old=directory/'old';new=directory/'new';old.mkdir();new.mkdir()
            for name,raw in files.items():
                p=old/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
            result=m.BUILD.stage(new,old)
            self.assertEqual(result['files'],804);self.assertFalse(result['previous_source_modified'])
            for name,item in manifest.items():
                self.assertEqual(hashlib.sha256((old/name).read_bytes()).hexdigest(),item['sha256'])
                expected=changes.get(name,item)['sha256'];self.assertEqual(hashlib.sha256((new/name).read_bytes()).hexdigest(),expected)
            first=next(iter(sorted(manifest)));(old/first).write_bytes(b'tamper');second=directory/'second';second.mkdir()
            with self.assertRaises(RuntimeError):m.BUILD.stage(second,old)
        finally:
            self.assertEqual(directory.resolve().parent,Path.cwd().resolve());self.assertTrue(directory.name.startswith('.cow17-stage-'));shutil.rmtree(directory)
    def test_root_has_34_binding_and_only_original_restart(self):
        source=m.ROOT_SOURCE;ast.parse(source)
        self.assertIn('len(jobs)==34',source);self.assertIn('len(pids)==34',source);self.assertIn("endpoint.name=='c17-'",source)
        self.assertIn(m.BUDGET_PATCH_SHA,source);self.assertIn("'cleanup_complete'",source);self.assertIn('scoped_file_path(p)',source)
        self.assertNotIn('len(pids)==8',source)
        for node in ast.walk(ast.parse(source)):
            if isinstance(node,ast.List) and len(node.elts)>=2 and isinstance(node.elts[0],ast.Constant) and node.elts[0].value=='/usr/bin/systemctl':
                action=node.elts[1].value;self.assertIn(action,('show','list-units','restart'))
                if action=='restart':self.assertEqual(node.elts[2].id,'UNIT')
    def test_core_loops_use_actual_guest_budget(self):
        source=m._source('core')
        self.assertNotIn('range(0,8,2)',source);self.assertNotIn('max_workers=8',source)
        self.assertIn('max_workers=c.max_guests',source);self.assertIn('global_same_template_shared_accessed_resident_bytes',source)
        self.assertIn('global_access_cache_sweeps',source);self.assertIn('rootfs_storage_details',source)
    def test_thin_packet_contains_no_original_source_archive(self):
        raw=(HERE/'cow17_access_once.py').read_bytes()
        self.assertLess(len(raw),400000);self.assertNotIn(b'BASE_ARCHIVE=',raw)
        self.assertIn(b'readonly', (HERE/'cow17_access_preflight.py').read_bytes())
    def test_root_command_roundtrips_only_json_scope_data(self):
        plan={'run_id':'fixture','path':'/owned/with space','literal':"not code: print('never executed')"}
        with patch.object(m,'ROOT_SOURCE',''):
            command=m.root_command('',plan)
        body=command.split("\n",1)[1].rsplit('\nCOW17_ACCESS_ROOT',1)[0]
        captured=[]
        ns={'base64':base64,'hashlib':hashlib,'json':json,'require':m.ENGINE.need,'root_session':captured.append}
        exec(compile(body,'literal-scope-test','exec'),ns)
        self.assertEqual(captured,[plan]);self.assertNotIn("print('never executed')",body)
    def test_17_summary_preserves_denominators_upper_and_global_dedup(self):
        directory=Path.cwd()/('.cow17-summary-'+uuid.uuid4().hex);directory.mkdir(mode=0o755);(directory/'measurements').mkdir()
        try:
            jobs=[];layers={};rows=[];process=[]
            for t in range(17):
                tid=str(t);sids=[tid+'a',tid+'b'];layers[tid]=[{'dev':1,'inode':100+t,'file_bytes':8192}]
                jobs.extend({'template_id':tid,'instance_id':tid,'sandbox_id':sid} for sid in sids)
                upper=[{'sandbox_id':sid,'files':[{'available':True,'dev':2,'inode':t*4+s*2+k,'logical_file_or_device_bytes':8192,
                       'allocated_file_bytes':4096,'resident_page_bytes':4096} for k in (1,2)]} for s,sid in enumerate(sids)]
                rows.append({'template_id':tid,'phase':'both_replaying','sandbox_ids':sids,'lower_file_bytes':8192,'lower_layer_count':1,
                    'sandbox1_accessed_lower_bytes':4096,'sandbox2_accessed_lower_bytes':4096,
                    'sandbox1_accessed_and_resident_bytes':4096,'sandbox2_accessed_and_resident_bytes':4096,
                    'shared_accessed_host_pagecache_bytes':4096,'accessed_resident_union_bytes':4096,
                    'shared_pool_fraction':1.0,'duplicate_avoidance_fraction':0.5,'upper_observations':upper})
                for sid in sids:
                    p={'template_id':tid,'sandbox_id':sid,'phase':'both_replaying','sandbox_valid_samples':1,'template_valid_paired_samples':1}
                    for f in ('sandbox_min_rss_bytes','sandbox_max_rss_bytes','sandbox_min_pss_bytes','sandbox_max_pss_bytes','template_min_shared_bytes','template_max_shared_bytes'):p[f]=8192
                    process.append(p)
            frame={'sample_id':0,'unix':1,'templates':rows,'global_accessed_resident_union_bytes':4096,
                   'global_same_template_shared_accessed_resident_bytes':4096,'reference_union_avoided_bytes':33*4096}
            report={'run_id':'fixture','status':'COW17_TRAJECTORIES_COMPLETED','jobs':jobs,'template_lowers':layers,'root_plan':{'boot_id':'fixture'},
                    'all_cohort_guests_released':True,'replay_completed_guests':34,'root_session':{k:True for k in
                    ('original_configuration_restored','original_service_healthy','other_services_unchanged','observer_exit_confirmed','bound_guest_processes_exited')}}
            def save(path,value):path.write_text(json.dumps(value))
            with patch.object(m.ENGINE,'H',types.SimpleNamespace(save=save)):
                for missing_upper in (False,True):
                    if missing_upper:frame['templates'][0]['upper_observations'][0]['files'][0]['available']=False
                    (directory/'measurements/access-cache.jsonl').write_text(json.dumps(frame)+'\n')
                    c=types.SimpleNamespace(work=directory,report=copy.deepcopy(report));runner=types.SimpleNamespace(process=types.SimpleNamespace(result=lambda:{'rows':process}))
                    m.summary_finish(c,runner)
                    result=json.loads((directory/'combined-summary.json').read_text())
                    if missing_upper:self.assertNotEqual(c.report['status'],'COW17_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED')
                    else:
                        self.assertEqual(c.report['status'],'COW17_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED')
                        metric=result['rootfs_storage_details']['rows'][0]['metrics']['access_resident_coverage_fraction']
                        self.assertEqual(metric['min'],.5)
                        self.assertEqual(result['global_access_cache_sweeps'][0]['global_same_template_shared_accessed_resident_bytes'],4096)
                        text=(directory/'combined-summary.md').read_text(encoding='utf-8');self.assertIn('17模板',text);self.assertIn('S1 upper分配',text)
        finally:
            self.assertEqual(directory.resolve().parent,Path.cwd().resolve());self.assertTrue(directory.name.startswith('.cow17-summary-'));shutil.rmtree(directory)


if __name__=='__main__':unittest.main()
