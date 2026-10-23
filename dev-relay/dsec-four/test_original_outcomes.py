import copy, hashlib, importlib.util, json, types, unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('original',HERE/'export_original_outcomes.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    root=HERE/'fixture';work=root/'relay/reports/node-a-memory-256-fixture';files={};jobs=[]
    repository=root/'deployments/agentenv-ae9c626-baseline/state/snapshot-store/repository'
    for index in range(8):
        template='00000000-0000-0000-0000-'+str(index//2).zfill(12)
        record={'id':template,'resources':{'cpu_count':2,'memory_mib':4096}}
        data=json.dumps(record).encode();files[repository/'catalog/records'/(template+'.json')]=data
        jobs.append({'index':index,'instance_id':'case'+str(index//2),'slot':index%2,'sandbox_id':'sandbox'+str(index),
            'template_id':template,'parent_snapshot_id':template,'catalog_sha256':hashlib.sha256(data).hexdigest(),
            'replay_sha256':'a'*64,'state':'REPLAY_COMPLETED','steps_completed':2,'failed_commands':1})
        events=[{'step':i,'return_code':i,'started_unix':float(i),'finished_unix':i+.5,
                 'requested_delay_seconds':0,'stdout_file':'not-read','stderr_file':'not-read'} for i in range(2)]
        files[work/'commands'/('%03d-events.jsonl'%index)]=b'\n'.join(json.dumps(row).encode() for row in events)
    report={'run_id':'a'*32,'experiment_comparison':{'base_commit':m.ORIGINAL,'io64_core_changes_used':False},
        'validation':{'all_cohort_guests_released':True,'replay_completed_guests':8},'jobs':jobs}
    path=work/'combined-summary.json';raw=json.dumps(report).encode();files[path]=raw
    sha=hashlib.sha256(raw).hexdigest()
    rt=types.SimpleNamespace(read=lambda path,limit=None:files[path])
    wrapped={'groups':[{'run_id':report['run_id'],'cache':report,'full_cache_evidence':{'sha256':sha}}]}
    return root,path,sha,rt,files,wrapped


class Original(unittest.TestCase):
    def test_read_existing_events_and_pinned_catalog_without_stdout(self):
        root,path,sha,rt,files,wrapped=fixture()
        before=copy.deepcopy(files);result=m.export(rt,root,path,sha)
        self.assertTrue(result['complete']);self.assertEqual(files,before)
        self.assertEqual(result['jobs'][0]['resources']['memory_mib'],4096)
        self.assertNotIn('stdout_file',result['jobs'][0]['events'][0])

    def test_report_hash_mismatch_rejected(self):
        root,path,sha,rt,files,wrapped=fixture()
        with self.assertRaisesRegex(RuntimeError,'content changed'):m.export(rt,root,path,'b'*64)

    def test_event_missing_preserves_other_rows_and_na(self):
        root,path,sha,rt,files,wrapped=fixture()
        del files[path.parent/'commands/000-events.jsonl']
        oldread=rt.read
        def read(path,limit=None):
            try:return oldread(path,limit)
            except KeyError:raise FileNotFoundError()
        rt.read=read;result=m.export(rt,root,path,sha)
        self.assertFalse(result['complete']);self.assertIsNone(result['jobs'][0]['events'])
        self.assertIsNotNone(result['jobs'][1]['events'])

    def test_changed_catalog_does_not_fill_resources_with_defaults(self):
        root,path,sha,rt,files,wrapped=fixture()
        catalog=next(p for p in files if p.name.startswith('00000000'))
        files[catalog]=b'{}'
        result=m.export(rt,root,path,sha)
        self.assertFalse(result['complete']);self.assertIsNone(result['jobs'][0]['resources'])

    def test_events_nonzero_count_must_match_original(self):
        root,path,sha,rt,files,wrapped=fixture();job=wrapped['groups'][0]['cache']['jobs'][0]
        job['failed_commands']=0
        with self.assertRaisesRegex(RuntimeError,'nonzero count'):
            m.normalize_events(files[path.parent/'commands/000-events.jsonl'],job)

    def test_supplement_merges_only_identical_original_without_rewriting(self):
        root,path,sha,rt,files,wrapped=fixture();before=copy.deepcopy(wrapped)
        result=m.export(rt,root,path,sha);merged,events=m.apply_supplement(wrapped,result)
        self.assertEqual(wrapped,before);self.assertEqual(len(events),8)
        self.assertEqual(merged['groups'][0]['cache']['jobs'][0]['resources']['cpu_count'],2)

    def test_wrong_run_or_per_job_receipt_cannot_be_merged(self):
        root,path,sha,rt,files,wrapped=fixture();result=m.export(rt,root,path,sha)
        other=copy.deepcopy(result);other['runId']='b'*32
        with self.assertRaisesRegex(RuntimeError,'bound'):m.apply_supplement(wrapped,other)
        result['jobs'][0]['catalogSha256']='b'*64
        with self.assertRaisesRegex(RuntimeError,'per-job'):m.apply_supplement(wrapped,result)


if __name__=='__main__':unittest.main()
