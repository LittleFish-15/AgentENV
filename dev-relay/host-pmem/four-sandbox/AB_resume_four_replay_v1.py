"""Resume only the four already-created, acknowledged v3 Guests."""
import hashlib,json,os,sys,time,types
from pathlib import Path
PIN='3265dfad8b0abc73df7c656edca4c6811e4989496b19ff9d0d17940c3d876778'
RUN='hpd4-replay-20261030-r1'

def normalized_job(template,sid,slot,steps,bind):
    resources=template['resources']
    if resources!={'cpu_count':2,'memory_mib':4096,'disk_size_mib':65536}:
        raise RuntimeError('Expected catalog resources 2 CPU / 4096MiB / 65536MiB disk; got '+repr(resources))
    root=[d for d in bind['devices'] if d['path']==bind['rootfsDevice']]
    if len(root)!=1 or root[0]['bytes']!=resources['disk_size_mib']*1024**2:raise RuntimeError('Actual rootfs disk capacity differs from catalog')
    return {'sandboxId':sid,'slot':slot,'templateId':template['templateId'],'replaySha256':template['replaySha256'],
        'catalogSha256':template['catalogSha256'],'resources':{k:resources[k] for k in ('cpu_count','memory_mib')},
        'snapshotResources':dict(resources),'steps':steps}

def main():
    entry=Path('/var/lib/agentenv-hpd4-full-v3/entry.py');raw=entry.read_bytes()
    if os.geteuid()!=0 or entry.stat().st_uid!=0 or hashlib.sha256(raw).hexdigest()!=PIN:raise RuntimeError('Expected acknowledged root v3 entry')
    m=types.ModuleType('retained_four');m.__file__=str(entry);sys.modules[m.__name__]=m
    exec(compile(raw,str(entry),'exec'),m.__dict__)
    from aenv_ub_provider import fsdax
    m.FSDAX=fsdax;ctx=m.Context();old=ctx.work
    status,approval_raw,_=ctx.control.contents(m.CONTROL,'approvals/'+RUN+'.json','main')
    m.need(status==200,'Resume approval missing');approval=json.loads(approval_raw)
    pin=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    m.need(approval['humanApproved'] and approval['entrySha256']==pin and approval['nodes'][ctx.node]['identity']==ctx.expected['identity'], 'Resume binding differs')
    expected=approval['nodes'][ctx.node]
    state_raw=m.read(old/'cohort.json');bindings_raw=m.read(old/'bindings.json')
    m.need(m.digest(state_raw)==expected['cohortSha256'] and m.digest(bindings_raw)==expected['bindingsSha256'],'Retained Guest state changed')
    state=json.loads(state_raw);saved=json.loads(bindings_raw)
    m.need(not state['openRequests'] and len(state['sandboxIds'])==2 and len(state['operations'])==2
        and all(r['kind']=='create' and r['httpStatus']==201 for r in state['operations']),'Not exactly two acknowledged creations')
    m.need(not (old/'replay.json').exists() and not (old/'commands').exists(),'Prior workload may have run; do not repeat')
    ctx.work=old/'resume-r1';ctx.work.mkdir(mode=0o700,exist_ok=True)
    m.need(not (ctx.work/'started.json').exists(),'Resume already started; no automatic rerun')
    m.RUN=RUN;ctx.pin=pin
    try:
        ctx.setup_inputs()
        ctx.case=m.ENGINE.Cohort.recovery(ctx.api,state,lambda value:m.atomic(ctx.work/'cohort.json',value))
        ctx.jobs=[]
        for slot,sid in enumerate(state['sandboxIds']):
            m.need(ctx.case.owned(sid) is not None,'Previously confirmed Guest no longer exists')
            job=normalized_job(ctx.template,sid,slot,ctx.steps,saved[sid])
            job['lowerContentSha256']=m.BIND.content_signature(ctx.template['rootfsLayers']);ctx.jobs.append(job)
        # Construct the actual replay engine before the start barrier: verifies
        # catalog/lower hashes, resource contract, all 32 steps, IDs and slots.
        engine=m.GROUP.NativeGroupReplay(ctx.work,ctx.active/'aenv-host-dax',ctx.env,ctx.jobs,m.REPLAY.shell_command,ctx.case.owned,
            ctx.collect,lambda value:m.atomic(ctx.work/'replay.json',value),launcher=ctx.launcher)
        ctx.bindings=ctx.observe();devices={}
        for sid,b in ctx.bindings.items():
            for key in ('process','configSha256','cwd','rootfsDevice','devices'):
                m.need(b[key]==saved[sid][key],'Existing Guest binding changed: '+key)
            ctx.processes.append(b['process']);ctx.files.extend(b['upper'])
            for d in b['devices']:devices[(d['major'],d['minor'])]=d
        ctx.devices=list(devices.values());ctx.permissions=json.loads(m.read(old/'device-acls.json'))
        cg=Path('/proc',str(ctx.pid),'cgroup').read_text();daemon=Path(ctx.app.plan['binaries']['bin/uvm-ublk-daemon']['path']).stat()
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:
                st=(proc/'exe').stat()
                if (st.st_dev,st.st_ino)==(daemon.st_dev,daemon.st_ino) and (proc/'cgroup').read_text()==cg:ctx.processes.append(ctx.process_row(int(proc.name),'daemon'))
            except (FileNotFoundError,ProcessLookupError):continue
        m.need(any(p['role']=='daemon' for p in ctx.processes),'Missing bound daemon')
        m.atomic(ctx.work/'bindings.json',ctx.bindings)
        m.atomic(ctx.work/'snapshot-resources.json',{'catalogSha256':ctx.template['catalogSha256'],'fullResources':ctx.template['resources'],
            'replayResources':ctx.jobs[0]['resources'],'diskBytesVerified':65536*1024**2})
        m.atomic(ctx.work/'started.json',{'unixNs':time.time_ns(),'entrySha256':pin,'existingGuestIds':state['sandboxIds'],'newGuestsCreated':False})
        ctx.event('resume-ready',{'unixNs':time.time_ns(),'sandboxIds':state['sandboxIds'],'sdkObject':ctx.expected['sharedObjectName']})
        peer=ctx.peer_event('resume-ready');local=json.loads(m.read(ctx.work/'resume-ready.json'))['data']
        m.need(peer['sdkObject']==ctx.expected['sharedObjectName'],'Peer source differs')
        start=max(peer['unixNs'],local['unixNs'])/1e9+45;m.need(time.time()<start,'Missed synchronized start window')
        while time.time()<start:ctx.guard();time.sleep(max(0,min(.5,start-time.time())))
        report=engine.run()
        m.need(report['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED' and report['pendingCommands']==0,'Replay failed; preserve Guest journal')
        ctx.event('replay-complete',{'completedCommands':report['completedCommands'],'nonzeroCommands':report['nonzeroCommands'],'unixNs':time.time_ns()})
        ctx.peer_event('replay-complete',1800);ctx.performance();ctx.release()
        ctx.event('completed',{'status':'FOUR_RETAINED_GUESTS_REPLAYED_LOCAL_RELEASED_BACKING_HELD','newGuestsCreated':False,
            'completedCommands':report['completedCommands'],'nonzeroCommands':report['nonzeroCommands'],'netSavingsBytes':None})
    except BaseException as error:
        value={'status':'RETAINED_FOUR_REPLAY_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,
            'reason':str(error)[:700] if isinstance(error,RuntimeError) else type(error).__name__,'newGuestsCreated':False}
        m.atomic(ctx.work/'failure-local.json',value)
        try:ctx.failure_details();ctx.event('failed',value)
        except Exception:pass
        print(json.dumps(value),flush=True);raise
    finally:
        try:ctx.upload()
        except Exception as error:print('PRIVATE_REPORT_UPLOAD_PENDING='+type(error).__name__,flush=True)

if __name__=='__main__':main()
