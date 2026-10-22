"""Final held-Guest access/residency evidence. No target mutations or net-saving claim."""
import json,os,stat,time
from pathlib import Path

def need(ok,message):
    if not ok:raise ValueError(message)

def read_owned(path,limit):
    path=Path(path);need(path.resolve(strict=True)==path,'Redirected observation file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        m=os.fstat(stream.fileno());need(stat.S_ISREG(m.st_mode) and m.st_uid==os.geteuid() and m.st_size<=limit,'Invalid observation file')
        return stream.read(limit+1)

def drain_proof(status,cutoff):
    """Only proves completion of the instrumented context-aware leaf reads."""
    result={'accepted':False,'throughMonotonicNs':None,'scope':'instrumented-context-read-completion-only'}
    if 'read_tracking_version' not in status:
        return dict(result,reason='This observer build has no in-flight tracking')
    need(type(status['read_tracking_version']) is int and status['read_tracking_version']==1,'Unknown read tracking protocol')
    for key in ('active_reads','completed_reads','failed_or_cancelled_reads','mono_ns'):
        need(type(status.get(key)) is int and status[key]>=0,'Invalid in-flight read counter')
    through=status.get('drained_through_ns')
    need(through is None or type(through) is int and through>0,'Invalid drain timestamp')
    accepted=(status['active_reads']==0 and status['failed_or_cancelled_reads']==0
              and type(through) is int and through==status['mono_ns'] and through>=cutoff
              and all(status.get(k)==0 for k in ('errors','dropped_records','unsupported_context_calls','repository_fallback_reads')))
    return dict(result,accepted=accepted,throughMonotonicNs=through if accepted else None,
                guardedReadsCompleted=status['completed_reads'],activeReads=status['active_reads'],
                reason='Guarded leaf reads and record writes completed' if accepted else 'No error-free drain after all task ends')

def await_status(fetch,expected_pid,cutoff,clock=time.monotonic,sleep=time.sleep):
    started=clock();last=None
    while True:
        last=fetch()
        need(last.get('version')==2 and last.get('pid')==expected_pid,'Observer changed while awaiting drain')
        proof=drain_proof(last,cutoff)
        if proof['accepted'] or 'read_tracking_version' not in last or any(last.get(k)!=0 for k in
            ('errors','dropped_records','unsupported_context_calls','repository_fallback_reads')) or clock()-started>=10:
            proof['waitSeconds']=max(0,clock()-started)
            return last,proof
        sleep(.1)

def parse_prefix(trace,status,expected_pid,expected_build,bindings,lowers,jobs,mode,algebra):
    need(status.get('version')==2 and status.get('pid')==expected_pid,'Observer status identity differs')
    for key in ('dropped_records','errors','unsupported_context_calls','repository_fallback_reads'):
        need(type(status.get(key)) is int and status[key]==0,'Incomplete/error/fallback observer status: '+key)
    count=status.get('records_written');need(type(count) is int and 0<=count<=1000000,'Invalid trace count')
    lines=iter(trace)
    header_line=next(lines);header=json.loads(header_line);prefix_bytes=len(header_line.encode('utf-8'))
    need(header.get('kind')=='header' and header.get('version')==2 and header.get('pid')==expected_pid
         and header.get('build_patch_sha256')==expected_build and header.get('clock')=='CLOCK_MONOTONIC','Trace header/build differs')
    by_source={v['imageConfigPath']:dict(v,guest=sid) for sid,v in bindings.items()}
    by_guest={j['sandboxId']:j for j in jobs}
    need(set(by_guest)==set(bindings) and len(by_source)==len(bindings),'Guest/source mapping is incomplete')
    local={(v['dev'],v['inode'],v['size']):v['digest'] for v in lowers}
    access={sid:{} for sid in by_guest};excluded=0;accepted=0
    for seq in range(count):
        line=next(lines);prefix_bytes+=len(line.encode('utf-8'));row=json.loads(line);need(row.get('seq')==seq,'Missing/reordered trace record')
        need(row.get('source') in by_source,'Trace includes unbound rootfs source')
        binding=by_source[row['source']];sid=binding['guest'];job=by_guest[sid]
        layers={x['digest']:x['fileBytes'] for x in binding['layers']}
        if row.get('kind')=='read':
            need(mode=='off','Local read encountered in required UB path')
            key=local.get((row.get('dev'),row.get('inode'),row.get('file_bytes')))
            if key is None:
                need(row.get('allowed_lower') is False,'Allowed lower is missing its binding')
                excluded+=1;continue
        else:
            need(row.get('kind')=='content_read' and mode=='lazy' and row.get('from_ub') is True,'Unexpected content backend')
            key=row.get('digest')
        need(key in layers and layers[key]==row.get('file_bytes') and row.get('allowed_lower') is True,'Actual lower identity differs')
        for field in ('start_ns','end_ns','offset','bytes'):need(type(row.get(field)) is int,'Missing read field')
        need(0<row['start_ns']<=row['end_ns'] and 0<=row['offset']<row['offset']+row['bytes']<=layers[key],'Invalid read range/time')
        start=job.get('replayStartedMonotonicNs');end=job.get('replayFinishedMonotonicNs')
        need(type(start) is int and type(end) is int and 0<start<=end,'Task monotonic bounds missing')
        if row['start_ns']<start or row['end_ns']>end:continue
        lo=row['offset']//4096*4096;hi=min((row['offset']+row['bytes']+4095)//4096*4096,layers[key])
        access[sid].setdefault(key,[]).append([lo,hi]);accepted+=1
    access={sid:{key:algebra.merge(ranges) for key,ranges in by_key.items()} for sid,by_key in access.items()}
    need(type(status.get('bytes_written')) is int and status['bytes_written']==prefix_bytes,'Status does not cover exact trace prefix bytes')
    cutoff=max(j['replayFinishedMonotonicNs'] for j in jobs)
    proof=drain_proof(status,cutoff)
    return {'access':access,'prefixRecords':count,'acceptedTaskReadRecords':accepted,'excludedNonLowerReads':excluded,
            'prefixBytes':prefix_bytes,'instrumentedReadDrain':proof,
            'coverage':'validated-status-bounded-observed-prefix','fullAccessCoverageAccepted':False,
            'coverageReason':'Instrumented leaf completion is separate from exhaustive Guest filesystem/other-backend coverage',
            'observerStatusMonotonicNs':status['mono_ns']}

def collect(io,algebra,rt,root,jobs,mode,base,expected_build,window_id,ready_fetch=None):
    began=time.time_ns();result={'available':False,'windowId':window_id,'node':rt.NODE,'mode':mode,
        'physicalNetSavingBytes':None,'atomicSnapshot':False,'fullAccessCoverageAccepted':False}
    try:
        daemon=root['readObserver'];need(daemon.get('available') is True,'Observed daemon identity missing')
        directory=base/'libexec/observed-v3/observations'
        trace_path=directory/('trace-'+str(daemon['pid'])+'.jsonl')
        cutoff=max(j['replayFinishedMonotonicNs'] for j in jobs)
        need(type(cutoff) is int and cutoff>0,'Completed task bounds required for final collection')
        status,proof=await_status(lambda:json.loads(read_owned(trace_path.with_suffix('.status.json'),65536)),daemon['pid'],cutoff)
        result['instrumentedDrainWaitSeconds']=proof['waitSeconds']
        # Rust with_extension("status.json") preserves the trace basename.
        fd=os.open(trace_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        with os.fdopen(fd,'r',encoding='utf-8') as stream:
            meta=os.fstat(stream.fileno());need(stat.S_ISREG(meta.st_mode) and meta.st_uid==os.geteuid() and meta.st_size<=268435456,'Invalid trace file')
            def lines():
                while True:
                    line=stream.readline(16385)
                    need(line and len(line)<=16384 and line.endswith('\n'),'Incomplete/oversized trace line')
                    yield line
            parsed=parse_prefix(lines(),status,daemon['pid'],expected_build,root['bindingEvidence']['guests'],rt.LOWERS,jobs,mode,algebra)
            try:
                resident_pages=rt.OBSERVER.resident_pages(stream.fileno(),meta.st_size,4096)
                result['traceOverhead']={'sampledFileBytes':meta.st_size,'allocatedDiskBytes':meta.st_blocks*512,
                    'sampledFileResidentPageBytes':resident_pages*4096,
                    'scope':'observer log prefix cache including collector reads; overlaps Host/cache charges; not additive'}
            except Exception as error:result['traceOverhead']={'available':False,'errorType':type(error).__name__}
            try:
                result['collectorWholeProcess']=rt.OBSERVER.whole_process_metrics(os.getpid(),rt.ticks(os.getpid()))
                result['collectorWholeProcess']['scope']='whole_cohort_collector_including_replay_control_not_firecracker'
            except Exception as error:result['collectorWholeProcess']={'available':False,'errorType':type(error).__name__}
        result.update(parsed,daemon=daemon)
        if mode=='off':
            rows=[io.resident_ranges(row) for row in rt.LOWERS]
            resident={row['digest']:row['residentContentRanges'] for row in rows}
            result['residentFileScans']=rows
            result['residentPageBytes']=sum(row['residentPageBytes'] for row in rows)
            result['residentContentBytes']=sum(row['residentContentBytes'] for row in rows)
            result['residentTailPagePaddingBytes']=result['residentPageBytes']-result['residentContentBytes']
            result['overlap']=algebra.summarize(parsed['access'],resident,window_id=window_id,sets_validated=True)
        elif rt.NODE=='node-a':
            need(ready_fetch is not None,'Owner ready-set reader is missing')
            ready=ready_fetch();result['ownerReadySnapshot']=ready
            result['overlap']=algebra.summarize(parsed['access'],algebra.ready_ranges(ready),window_id=window_id,sets_validated=True)
        else:
            result['overlap']=None;result['awaitsOwnerSnapshot']=True
        # Set validation covers the supplied mathematical sets only, never exhaustive IO.
        result.update(available=True,startUnixNs=began,endUnixNs=time.time_ns(),
            setSemantics='task reads observed in a validated prefix intersected with measured held-Guest final residency')
    except Exception as error:
        result.update(errorType=type(error).__name__,reason=str(error)[:400],startUnixNs=began,endUnixNs=time.time_ns())
    return result
