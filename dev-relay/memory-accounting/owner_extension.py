"""Owner extensions; bindings ENGINE, MODE, MASTER, PAIR_ID are injected."""
import collections


def reconcile_memory(m,identity,api):
    if MODE==256:
        previous=m.B.read_json(m.ROOT/'relay/cow4-original-256-recheck-node-a.pending.json')
        m.need(previous['run_id']=='fdebc7fb00bd4388828a1cbd248ff16b' and previous['status']=='COW4_ORIGINAL_256_RECHECK_MEASURED_GUESTS_RELEASED_RESTORED','Latest original comparison is not complete')
    else:
        previous=m.B.read_json(m.ROOT/'relay/cow4-memory-256-node-a.pending.json')
        m.need(previous.get('memory_pair_id')==PAIR_ID and previous.get('status')=='COW4_ORIGINAL_256_RECHECK_MEASURED_GUESTS_RELEASED_RESTORED','First group lifecycle not complete')
    root=previous['root_session']
    m.need(previous['all_cohort_guests_released'] and not previous['restore_outcome_uncertain'],'Prior release uncertain')
    m.need(all(root.get(k) for k in ('original_configuration_restored','original_service_healthy','other_services_unchanged','observer_exit_confirmed','bound_guest_processes_exited')),'Prior service restoration incomplete')
    m.need(root.get('original_server_unchanged') is True,'Prior original server identity not confirmed')
    m.need(hashlib.sha256(m.H.read(m.BASE/'bin/server',256*1024**2)).hexdigest()=='0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff','Current server is not original')
    m.need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Original inventory not empty')
    for j in previous['jobs']:m.need(api.call('GET','/sandboxes/'+j['sandbox_id'])[0]==404,'Previous Guest still exists')
    for pid,ticks in [previous['observer_identity']]+[[b['pid'],b['start_ticks']] for b in previous['bindings']]:
        try:alive=m.R.identity(pid)[1]==ticks
        except (FileNotFoundError,ProcessLookupError):alive=False
        m.need(not alive,'Previous experiment process remains')
    return {'previous_run_id':previous['run_id'],'previous_report_directory':previous['report_directory'],'prior_receipt_preserved':True,
        'previous_guests_http404':True,'original_process_changed_since_prior':list(identity)!=root['restored_identity'],
        'baseline_template_ids':sorted({j['template_id'] for j in previous['jobs']})}


def announce_memory_group(plan,cohort):
    plan.update(rootfs_io_kib=MODE,pair_id=PAIR_ID)
    if MODE==256:plan['core_commit']='ae9c62693839ce7effa2b45df31c0039ae4f9fbc'
    if MODE==64:
        prior=ENGINE.B.read_json(ENGINE.ROOT/'relay/cow4-memory-256-node-a.pending.json')
        for key in ('template_lowers','template_memory_lowers','boot_id'):
            ENGINE.need(plan[key]==prior['root_plan'][key],'Paired input changed: '+key)
        fields=('template_id','parent_snapshot_id','catalog_sha256','slot','instance_id','replay_sha256','terminal_action')
        signature=lambda jobs:sorted(tuple(j[k] for k in fields) for j in jobs)
        ENGINE.need(signature(cohort.jobs)==signature(prior['jobs']),'Paired templates/replays differ')
        cohort.report['paired_input_equivalence_verified']=True
        cohort.report['paired_256_run_id']=prior['run_id']
    cohort.report.update(memory_pair_id=PAIR_ID,memory_collection_revision='memory-accounting-v1',root_plan=plan)
    cohort.persist();ENGINE.H.save(cohort.work/'memory-root-plan.json',plan)
    ENGINE.send(MASTER,{'op':'start_group','plan':plan})
    print('GROUP_START rootfs_io_kib='+str(MODE)+' report='+str(cohort.work),flush=True)


class MemoryRun(FourRun):
    def record_memory(self,row):
        row=dict(row,experiment_phase=getattr(self,'experiment_phase','preparation'),run_id=self.c.run_id,rootfs_io_kib=MODE)
        path=self.c.work/'measurements/memory-accounting.jsonl'
        with path.open('a',encoding='utf-8') as f:f.write(json.dumps(row,separators=(',',':'))+'\n');f.flush()
        ENGINE.need(path.stat().st_size<=64*1024**2,'Memory measurement log budget exceeded')
    def rpc(self,op,**values):
        result=super().rpc(op,**values)
        if result.get('memory_snapshot') is not None:self.record_memory({'kind':'periodic','snapshot':result['memory_snapshot']})
        if op=='bind' and result.get('memory_baseline') is not None:self.record_memory({'kind':'checkpoint','snapshot':result['memory_baseline'],'pfn':result.get('pfn')})
        return result
    def global_cold(self,phase):
        baseline=super().global_cold(phase)
        if phase=='replay':
            checkpoint=self.rpc('memory_checkpoint',phase='B2_replay_baseline',pfn=False)
            self.record_memory({'kind':'checkpoint',**checkpoint})
        return baseline
    def run(self):
        super().run()
        checkpoint=self.rpc('memory_checkpoint',phase='T2_replay_finished_before_cleanup',pfn=True)
        self.record_memory({'kind':'checkpoint',**checkpoint})


def memory_summary(work,report):
    raw=work/'measurements/memory-accounting.jsonl';snapshots=[];pfns=[]
    if raw.exists():
        with raw.open(encoding='utf-8') as f:
            for line in f:
                row=json.loads(line)
                if row.get('snapshot'):snapshots.append(row)
                if row.get('pfn'):pfns.append(row['pfn'])
    per_guest={};per_device={};samples=[]
    for row in snapshots:
        s=row['snapshot'];phase=row['experiment_phase'];samples.append({'phase':phase,'monotonic_ns':s['started_monotonic_ns'],'duration_seconds':s['duration_seconds'],'complete':s['complete'],
            'host_before':s['host_before'],'host_after':s['host_after'],'memory_devices':s['memory_devices'],'memory_lower_files':s['memory_lower_files'],'rootfs_lower_files':s.get('rootfs_lower_files'),'services':s['services'],'measurement_helpers':s['measurement_helpers'],'guests':s['guests']})
        if phase!='replay' or not s['complete']:continue
        for g in s['guests']:
            if g.get('available') and g.get('exact_vma_partition'):
                per_guest[g['sandbox_id']]=per_guest.get(g['sandbox_id'],0)+1
        for d in s['memory_devices']['devices']:
            if d.get('available'):per_device[d['device']]=per_device.get(d['device'],0)+1
    process_file=work/'measurements/process.jsonl';pair={};batch={};process_details={}
    if process_file.exists():
        with process_file.open(encoding='utf-8') as f:
            for line in f:
                row=json.loads(line);ps=row['processes'];valid=len(ps)==2 and all(p.get('available') for p in ps)
                entry={'sample_id':row['sample_id'],'template_id':row['template_id'],'phase':row['phase'],'started_unix':row['started_unix'],'finished_unix':row['finished_unix'],'valid':valid,
                    'sum_pss_bytes':sum(p['pss_bytes'] for p in ps) if valid else None,'sum_rss_bytes_not_unique':sum(p['rss_bytes'] for p in ps) if valid else None,'processes':ps}
                pair.setdefault(row['template_id'],[]).append(entry);batch.setdefault(row['sample_id'],[]).append(entry)
                for p in ps:process_details.setdefault(p['sandbox_id'],[]).append(p)
    batch_rows=[]
    for sid,entries in batch.items():
        valid=len(entries)==4 and len({x['template_id'] for x in entries})==4 and all(x['valid'] for x in entries)
        batch_rows.append({'sample_id':sid,'valid':valid,'sum_fc_pss_bytes':sum(x['sum_pss_bytes'] for x in entries) if valid else None,
            'sum_fc_rss_bytes_not_unique':sum(x['sum_rss_bytes_not_unique'] for x in entries) if valid else None,
            'started_unix':min(x['started_unix'] for x in entries),'finished_unix':max(x['finished_unix'] for x in entries),'phases':[x['phase'] for x in entries]})
    process_complete=len(process_details)==8 and all(sum(p.get('available') and p.get('pss_categories_complete') for p in rows)>=2 for rows in process_details.values())
    coverage={'replay_guest_complete_samples':per_guest,'replay_device_complete_samples':per_device,'process_pss_category_coverage':process_complete,
              'required_accounting_complete':len(per_guest)==8 and min(per_guest.values(),default=0)>=2 and len(per_device)==4 and min(per_device.values(),default=0)>=2 and process_complete,
              'PFN_checkpoints_valid':sum(p.get('available',False) for p in pfns),'PFN_checkpoints_requested':len(pfns),
              'PFN_diagnostic_complete':len(pfns)==2 and all(p.get('available',False) for p in pfns)}
    result={'revision':'memory-accounting-v1','run_id':report['run_id'],'rootfs_io_kib':MODE,'coverage':coverage,'snapshots':samples,'pfn_checkpoints':pfns,
        'root_baselines_and_cleanup':report.get('root_session',{}).get('memory_baselines',{}),'per_template_process_timeseries':pair,'all_fc_same_cycle':batch_rows,
        'scope':'Cached file accounting, memory-device residency and process mapping accounting are separate views. Do not sum Cached + RSS/PSS or device cache + mapped Guest RAM.',
        'Guest_memory_accesses_inferred_from_residency':False,'rootfs_read_observer_changed':False,'B_accessed':False,'SDK_called':False}
    report['physical_guest_ram_resampled']=coverage['PFN_checkpoints_valid']>0
    ENGINE.H.save(work/'memory-accounting-summary.json',result)
    return {'file':str(work/'memory-accounting-summary.json'),'coverage':coverage,'samples':len(samples),'process_cycles':len(batch_rows)}


FourRun=MemoryRun
