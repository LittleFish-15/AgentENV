"""Host-wide page-cache time series with idle control and bounded replay.

Injected into the reviewed four-template lifecycle packet. Only the literal
root supervisor may issue the two fixed page-cache drop requests.
"""
import threading


def global_host_row(phase):
    row={'phase':phase,'monotonic_ns':time.monotonic_ns(),'unix':time.time()}
    row.update({k:int(v.split()[0])*1024 for k,v in
                (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
                if k in ('Cached','Buffers','Shmem','Dirty','Writeback','SReclaimable','MemAvailable','SwapCached')})
    row['finished_monotonic_ns']=time.monotonic_ns()
    return row


class HostTimeline:
    def __init__(self,work):
        self.path=work/'measurements/host-cache.jsonl';self.phase='preparation'
        self.stopped=threading.Event();self.thread=None;self.error=None;self.rows=0
    def start(self):
        self.thread=threading.Thread(target=self._loop,name='host-cache-timeline',daemon=True);self.thread.start()
    def _loop(self):
        try:
            with self.path.open('x',encoding='utf-8') as f:
                while not self.stopped.is_set():
                    row=global_host_row(self.phase);f.write(json.dumps(row,separators=(',',':'))+'\n');f.flush();self.rows+=1
                    ENGINE.need(f.tell()<=16*1024**2,'Host timeline budget exceeded')
                    self.stopped.wait(1)
        except BaseException as e:self.error={'type':type(e).__name__,'reason':str(e)}
    def check(self):ENGINE.need(self.error is None,'Host timeline failed: '+str(self.error))
    def stop(self):
        self.stopped.set()
        if self.thread:self.thread.join(timeout=10)
        ENGINE.need(not self.thread or not self.thread.is_alive(),'Host sampler did not exit')
        self.check()


def auxiliary_cache(runner,frame):
    """Known ordinary-file cache, deduplicated; not complete host attribution."""
    rows=[];seen=set(runner.files);errors=[]
    for template in frame.get('templates',[]):
        for observation in template['upper_observations']:
            for f in observation['files']:
                if not f.get('available'):errors.append({'kind':'rootfs_upper','file':f});continue
                key=(f['dev'],f['inode'])
                if key not in seen:
                    seen.add(key);rows.append({'kind':'rootfs_upper',**f})
    targets=[]
    for f in runner.plan['memory_lowers']:targets.append(('memory_lower',Path(f['path']),f))
    work=runner.c.work
    for name in ('observer/trace.jsonl','observer/trace.status.json','measurements/process.jsonl',
                 'measurements/access-cache.jsonl','measurements/host-cache.jsonl'):
        if (work/name).exists():targets.append(('experiment_files',work/name,None))
    command_files=list((work/'commands').glob('*.stdout'))+list((work/'commands').glob('*.stderr'))
    ENGINE.need(len(command_files)<=2048,'Command log observation file-count budget exceeded')
    targets += [('experiment_files',p,None) for p in command_files]
    total=0
    for kind,path,expected in targets:
        fd=None
        try:
            ENGINE.need(path.resolve(strict=True)==path,'Redirected auxiliary cache input')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);before=os.fstat(fd)
            ENGINE.need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid(),'Auxiliary file owner differs')
            key=(before.st_dev,before.st_ino)
            if key in seen:continue
            seen.add(key);total+=before.st_size
            ENGINE.need(total<=8*1024**3,'Auxiliary file cache observation exceeds budget')
            if expected:ENGINE.need(key==(expected['dev'],expected['inode']) and before.st_size==expected['file_bytes'],'Memory lower differs')
            bits=COLD.vector(fd,before.st_size);after=os.fstat(fd)
            ENGINE.need(after.st_size>=before.st_size,'Auxiliary file shrank during observation')
            rows.append({'kind':kind,'path':str(path),'dev':key[0],'inode':key[1],
                         'observed_file_prefix_bytes':before.st_size,'file_bytes_after':after.st_size,
                         'grew_during_scan':after.st_size!=before.st_size,
                         'resident_page_bytes':sum(bits)*4096,'available':True})
        except Exception as e:errors.append({'kind':kind,'path':str(path),'type':type(e).__name__,'reason':str(e)})
        finally:
            if fd is not None:os.close(fd)
    totals={kind:sum(r['resident_page_bytes'] for r in rows if r['kind']==kind)
            for kind in ('memory_lower','rootfs_upper','experiment_files')}
    return {'files':rows,'errors':errors,'observed_resident_bytes':sum(totals.values()),
            'complete_for_listed_prefixes':not errors,'category_bytes':totals,
            'total_host_attribution_claimed':False,'atomic_snapshot':False,
            'memory_device_cache_included':False,'regular_file_cache_must_not_be_added_to_guest_RSS':True}


class GlobalFourRun(FourRun):
    def __init__(self,*args):
        super().__init__(*args);self.timeline=HostTimeline(self.c.work)
        self.experiment_phase='preparation';self.extra_samples=[];self.cache_baselines={}
    def phase(self,sids):
        return 'idle_control' if self.experiment_phase=='idle_control' else super().phase(sids)
    def before_frame_write(self,frame):
        frame['experiment_phase']=self.experiment_phase
        BASELINE.enrich(frame,self.cache_baselines[self.experiment_phase]['lower_probe'],COLD.TEMPLATE_KEYS)
        frame['known_other_file_cache']=auxiliary_cache(self,frame)
        frame['host_after_auxiliary_scan']=global_host_row(self.experiment_phase)
        self.timeline.check()
    def global_cold(self,phase):
        self.experiment_phase='clear_'+phase;self.timeline.phase=self.experiment_phase
        _,before=COLD.scan(self.files,set())
        event=self.rpc('drop_pagecache',phase=phase)['event']
        _,after=COLD.scan(self.files,set())
        result={'phase':phase,'before':before,'root_drop':event,'after':after,
                'zero_resident_at_each_file_observation':after['whole_lower_resident_bytes']==0,
                'globally_atomic_cold_state_claimed':False}
        output=self.c.work/('global-cold-'+phase+'.json');ENGINE.H.save(output,result)
        self.c.report.setdefault('global_cold_checkpoints',[]).append({'phase':phase,'file':str(output),
            'resident_bytes_after':after['whole_lower_resident_bytes'],'root_drop':event})
        self.c.persist()
        result['baseline_classification']='ZERO_OBSERVED_POST_DROP_BASELINE' if result['zero_resident_at_each_file_observation'] else 'NONZERO_MEASURED_POST_DROP_BASELINE'
        result['all_zero_cold_start_claimed']=False
        ENGINE.H.save(output,result)
        print('POST_DROP_BASELINE phase='+phase+' resident_bytes='+str(after['whole_lower_resident_bytes']),flush=True)
        # Baseline is observed after the full sequential lower sweep, not a
        # fictional instantaneous all-zero host state.
        self.start=time.monotonic_ns();self.experiment_phase=phase;self.timeline.phase=phase
        baseline={'phase':phase,'monotonic_ns':self.start,'unix':time.time(),
                  'host':global_host_row(phase),'lower_resident_bytes':after['whole_lower_resident_bytes'],
                  'lower_probe':after,'known_other_file_cache':None,
                  'classification':result['baseline_classification'],'all_zero_cold_start_claimed':False}
        # Collect upper and other files consistently for delta reconciliation.
        upper_rows=[]
        for b in self.bound:
            upper_rows.append({'upper_observations':[{'files':[ENGINE.R.resident(Path(f['path']),64*1024**3) for f in b['uppers']]}]})
        baseline['known_other_file_cache']=auxiliary_cache(self,{'templates':upper_rows})
        baseline['finished_monotonic_ns']=time.monotonic_ns()
        self.cache_baselines[phase]=baseline
        ENGINE.H.save(self.c.work/'cache-baselines.json',self.cache_baselines)
        return baseline
    def run(self):
        c=self.c;COLD.TEMPLATE_KEYS={tid:{(f['dev'],f['inode']) for f in rows} for tid,rows in self.plan['template_lowers'].items()}
        c.report['cold_scope']='Two host-wide page-cache drop requests with measured residual baselines. No all-zero cold-start claim. Guest and daemon userspace caches are not flushed.'
        c.report['cache_geometry']=COLD.environment(self.files)
        print('PHASE=owned_cold_cache_calibration',flush=True)
        c.report['cold_calibration']=COLD.calibrate(c.work)
        self.timeline.start()
        try:
            for j in c.jobs:c.create(j);self.rpc('heartbeat')
            until=time.monotonic()+10
            while not (c.work/'observer/trace.status.json').exists() and time.monotonic()<until:time.sleep(.25)
            r=self.rpc('bind',jobs=[{k:j[k] for k in ('sandbox_id','template_id')} for j in c.jobs])
            self.bound=r['bindings'];self.observer_pid=r['observer_identity'][0]
            for b in self.bound:
                self.bindings[b['source']]={'sandbox_id':b['sandbox_id'],'template_id':b['template_id'],
                    'lower_keys':{(f['dev'],f['inode']) for f in b['lowers']},'upper_keys':{(f['dev'],f['inode']) for f in b['uppers']}}
            c.report['bindings']=self.bound;c.report['observer_identity']=r['observer_identity'];c.persist()
            self.global_cold('idle_control')
            print('PHASE=idle_control_60_seconds',flush=True)
            until=time.monotonic()+60;next_cache=time.monotonic()+2
            while time.monotonic()<until:
                c.guard();self.timeline.check();self.metrics()
                if time.monotonic()>=next_cache:self.cache();next_cache=time.monotonic()+15
                time.sleep(1)
            self.cache();c.report['idle_control_end_monotonic_ns']=time.monotonic_ns()
            self.global_cold('replay');c.report['replay_start_monotonic_ns']=self.start;c.persist()
            print('PHASE=continuous_replay_8_guests',flush=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=c.max_guests) as pool:
                futures=[pool.submit(self.replay,j) for j in c.jobs];next_cache=time.monotonic()+2
                try:
                    while not all(f.done() for f in futures):
                        c.guard();self.timeline.check();self.metrics()
                        if time.monotonic()>=next_cache:self.cache();next_cache=time.monotonic()+15
                        time.sleep(1)
                    for f in futures:f.result()
                    time.sleep(2);self.metrics();self.cache()
                except BaseException:c.stop.set();raise
            c.report['trajectory_windows_monotonic_ns']={sid:[self.start,end] for sid,end in self.ends.items()}
            self.experiment_phase='post_replay';self.timeline.phase=self.experiment_phase
            print('PHASE=independent_fincore_crosscheck',flush=True)
            c.report['independent_cache_crosscheck']=COLD.independent_check(self.files,c.work/'independent-cache-crosscheck.json')
        finally:
            try:self.timeline.stop()
            finally:
                c.report['host_timeline']={'file':str(self.timeline.path),'samples':self.timeline.rows,'error':self.timeline.error}
                c.report['cache_baselines_file']=str(c.work/'cache-baselines.json');c.persist()


_base_summarize=summarize


def summarize(work,report,process):
    result=_base_summarize(work,report,process)
    result['revision']='cow4-global-cache-v2'
    result['cold_cache_validation']={'method':'two ordered sync plus drop_caches=1 operations',
        'scope':report.get('cold_scope'),'checkpoints':report.get('global_cold_checkpoints',[]),
        'calibration':report.get('cold_calibration'),'cache_geometry':report.get('cache_geometry'),
        'independent_cache_crosscheck':report.get('independent_cache_crosscheck')}
    timeline=TIMESERIES.build(work,report,result)
    result['cache_timeseries']=timeline
    ENGINE.H.save(work/'combined-summary.json',result)
    with (work/'combined-summary.md').open('a',encoding='utf-8') as f:f.write(TIMESERIES.markdown(timeline))
    return result


FourRun=GlobalFourRun
