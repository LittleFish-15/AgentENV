"""Reconcile the sole proven pre-create failure, initialize empty catalog dirs,
then continue the same approved experiment in a fresh run; backing untouched.
"""
import ast,base64,hashlib,http.client,json,os,re,socket,stat,sys,time,types,zlib
from pathlib import Path
OLD_RUN='titanic-full-20261102-v1';NEW_RUN='titanic-full-20261102-r2'
PIN='99373712325cd0ff93e0670d27e36f24b7275a3cea07c9bb2c7152fc9b60cf1f'
RELATIVE=('catalog','catalog/aliases','catalog/records','volumes','volumes/aliases','volumes/records','snapshots')

def need(ok,why):
    if not ok:raise RuntimeError(why)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def snapshot_failure_evidence(diag,state,node):
    """Require the observed pre-create failure, not merely an empty inventory."""
    requests=state['openRequests']
    need(len(requests)==1 and requests[0]==diag['request'] and requests[0]['kind']=='create'
         and requests[0]['route']=='/v2/sandboxes' and not state['sandboxIds'] and not state['operations'],
         'Previous request is not the single diagnosed failure')
    journal=diag['runtimeJournal'];need(journal['exitCode']==0,'Runtime log unavailable')
    text=journal['stdout'];path='/home/jwk/agent/r/hpt-'+node[-1]+'-v1/seed/repository/catalog/aliases'
    need(text.count('failed to load runnable snapshot')==1 and path in text and 'Read-only file system (os error 30)' in text
         and "load committed snapshot '01a19b76-130a-75c2-bf0a-76b49acc1943'" in text,'Different or ambiguous snapshot failure')
    times=re.findall(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z).*failed to load runnable snapshot',text)
    import datetime
    need(len(times)==1,'Missing exact Runtime error time')
    delta=datetime.datetime.fromisoformat(times[0].replace('Z','+00:00')).timestamp()-requests[0]['startedNs']/1e9
    need(0<=delta<=2,'Runtime error not in this request window')
    metrics=diag['httpMetrics'];need(metrics['status']==200,'Request counters unavailable')
    def value(prefix,labels):
        rows=[]
        for line in metrics['lines']:
            if line.startswith(prefix+'{') and all(k in line.split('}',1)[0] for k in labels):rows.append(float(line.rsplit(' ',1)[1]))
        return rows
    need(value('agentenv_http_request_duration_seconds_count',('method="POST"','route="/v2/sandboxes"'))==[1.0], 'Unexpected prior POST count')
    need(value('agentenv_http_request_duration_seconds_count',('method="POST"','route="/v2/sandboxes"','status="5xx"'))==[1.0], 'Prior POST not a server failure')
    need(value('agentenv_sandbox_stage_duration_seconds_count',('operation="create_warm"','stage="load_snapshot"','status="error"'))==[1.0], 'Snapshot failure count differs')
    need(value('agentenv_sandbox_stage_inflight',('operation="create_warm"','stage="load_snapshot"'))==[0.0], 'Snapshot load remains active')
    need(diag['devices']==[] and diag['recentFirecrackerLogs']==[] and diag['inventory']['httpStatus']==200
         and diag['inventory']['items']==[], 'Additional runtime resources need separate reconciliation')
    return {'outcome':'request_failed_during_snapshot_load_before_orchestrator_create','request':requests[0],
            'evidence':'Runtime error within request window plus sole failed POST, failed completed load_snapshot, and resource checks',
            'errorAfterRequestSeconds':delta,'emptyInventoryAloneUsed':False,'previousJournalPreserved':True}


def main():
    need(os.getuid()==os.geteuid()==0 and len(sys.argv)==2 and re.fullmatch('[0-9a-f]{64}',sys.argv[1]),'Use approved exact-contract root job')
    node={'server1':'node-a','agent1':'node-b'}.get(socket.gethostname());need(node,'Only A/B')
    old_entry=Path('/home/jwk/root/relay/jobs')/('titanic-business-perf-20261102-015-'+node)/'task.py';raw=old_entry.read_bytes()
    need(old_entry.resolve()==old_entry and old_entry.stat().st_uid==0 and digest(raw)==PIN,'Original measurement source differs')
    root_report=json.loads((old_entry.parent/'report.json').read_text());need(root_report['state']=='completed' and root_report['exitCode']==1,'Previous task not a completed failure')
    m=types.ModuleType('titanic_measure_original');m.__file__=str(old_entry);sys.modules[m.__name__]=m;exec(compile(raw,str(old_entry),'exec'),m.__dict__)
    for name,item in m.BUNDLED.items():
        data=zlib.decompress(base64.b64decode(item['z64']));need(digest(data)==item['sha256'],'Reused module differs');m.__dict__[name]=m.load_module(name,data)
    m.RUN=NEW_RUN;m.HOME=Path('/home/jwk/root/titanic-measure-r2');m.SPEC='titanic-experiments/'+m.SESSION+'/'+NEW_RUN+'/contract.json';m.CONTRACT_SHA=sys.argv[1]
    ctx=None
    try:
        ctx=m.Context();need(ctx.approval['executionWrapperSha256']==digest(Path(__file__).read_bytes()),'Repair wrapper contract differs');PREVIOUS=ctx.approval['previousFailure'];need(root_report['jobSha256']==PREVIOUS[node]['jobSha256'],'Previous root receipt binding differs')
        old=Path('/home/jwk/root/titanic-measure-v1')/node;state_raw=m.read(old/'cohort.json');need(digest(state_raw)==PREVIOUS[node]['cohortSha256'],'Original pending request journal changed; preserve')
        state=json.loads(state_raw);need(state['openRequests']==[PREVIOUS[node]['request']],'Old request changed')
        outcomes=[json.loads(line) for line in m.read(old/'http-outcomes.jsonl',1024**2).decode().splitlines()]
        need(len(outcomes)==1 and outcomes[0]['method']=='POST' and outcomes[0]['route']=='/v2/sandboxes' and outcomes[0]['httpStatus']==500,'Prior HTTP outcome not sole confirmed500')
        oldroot=json.loads(next(line for line in root_report['logs']['stdout.log']['text'].splitlines() if line.startswith('{"status": "TITANIC_MEASUREMENT_FAILED')))
        need(oldroot['cohort']==state,'Original root receipt/cohort mismatch')
        diag={'request':state['openRequests'][0],'runtimeJournal':{'exitCode':oldroot['diagnosis']['exitCode'],'stdout':oldroot['diagnosis']['runtimeJournal']},'devices':[],'recentFirecrackerLogs':[],'inventory':{}}
        code,inventory=ctx.api.call('GET','/v2/sandboxes?limit=1');diag['inventory']={'httpStatus':code,'items':inventory}
        c=m.UnixHTTP(ctx.active/'api.sock',10)
        try:
            c.request('GET','/metrics',headers={'X-API-Key':ctx.key});r=c.getresponse();data=r.read(2*1024**2+1);need(len(data)<=2*1024**2,'Metrics too large');diag['httpMetrics']={'status':r.status,'lines':data.decode().splitlines()}
        finally:c.close()
        cg=Path('/proc',str(ctx.pid),'cgroup').read_text();fc=Path(ctx.app.plan['binaries']['deps/firecracker/1.15.1-patch-v3/firecracker']['path']).stat()
        for p in Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:
                if (p/'cgroup').read_text()!=cg:continue
                exe=(p/'exe').stat()
                if (exe.st_dev,exe.st_ino)==(fc.st_dev,fc.st_ino):diag['recentFirecrackerLogs'].append({'pid':int(p.name),'reason':'FC still in own Runtime'})
                for fd in (p/'fd').iterdir():
                    try:
                        target=os.readlink(fd)
                        if re.fullmatch('/dev/ublk[bc][0-9]+',target):diag['devices'].append({'pid':int(p.name),'device':target})
                    except FileNotFoundError:continue
            except (FileNotFoundError,ProcessLookupError):continue
        need(not list((ctx.active/'fc').glob('agentenv-fc-*')),'Existing FC work dirs need inspection')
        acl=old/'device-acls.json';need(not acl.exists() or json.loads(m.read(acl))==[],'Previous device grant needs reconciliation')
        resolution=snapshot_failure_evidence(diag,state,node);resolution.update(priorCohortSha256=digest(state_raw),previousJobSha256=PREVIOUS[node]['jobSha256'],runtime=ctx.runtime)
        m.atomic(ctx.work/'prior-request-resolution.json',resolution);m.atomic(ctx.work/'prior-request-diagnosis.json',diag)
        root=ctx.app.work/'seed/repository';need(root.resolve()==root and root.stat().st_uid==1204,'Seed directory differs')
        record=root/'catalog/records'/(ctx.template['templateId']+'.json');before=digest(m.read(record));created=[]
        for rel in RELATIVE:
            path=root/rel;need(path.parent.resolve()==path.parent,'Seed parent redirected')
            if not path.exists():
                m.run(['/usr/bin/setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs','/usr/bin/mkdir','-m','700','--',str(path)]);created.append(str(path))
            need(path.resolve()==path and path.is_dir() and path.stat().st_uid==1204,'Seed layout owner/type differs')
        need(digest(m.read(record))==before==ctx.template['catalogSha256'],'Captured record changed')
        identities={rel:[(root/rel).stat().st_dev,(root/rel).stat().st_ino] for rel in RELATIVE}
        check="import json,os,sys;from pathlib import Path;root=Path(sys.argv[1]);names=json.loads(sys.argv[2]);ids=json.loads(sys.argv[3]);assert os.getuid()==1204;out=[]\nfor name in names:\n p=root/name;assert p.is_dir() and p.stat().st_uid==1204 and [p.stat().st_dev,p.stat().st_ino]==ids[name];os.makedirs(p,exist_ok=True);out.append({'path':str(p),'readonly':bool(os.statvfs(p).f_flag & os.ST_RDONLY)})\nassert all(x['readonly'] for x in out if '/catalog' in x['path'] or x['path'].endswith('/snapshots'));print(json.dumps(out))"
        visible=json.loads(m.run(['nsenter','-t',str(ctx.pid),'-m','--','/usr/bin/setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs','/usr/bin/python3','-I','-B','-c',check,str(root),json.dumps(RELATIVE),json.dumps(identities)]))
        need(m.read(old/'cohort.json')==state_raw,'Original cohort changed')
        marker=ctx.active/'external-mutation-observed';marker_raw=m.read(marker);need(json.loads(marker_raw)=={'runId':OLD_RUN,'work':str(old),'pendingBeforeCreate':True},'Prior mutation marker differs')
        os.rename(marker,ctx.work/'prior-external-mutation-marker.json');need(m.read(ctx.work/'prior-external-mutation-marker.json')==marker_raw,'Mutation marker archive differs')
        ctx.event('catalog-layout-repaired',{'createdEmptyDirectories':created,'runtimeVisible':visible,'previousRequestResolution':resolution,'servicesRestarted':False,'SDKCalled':False,'readOnlyBindsPreserved':True})
        ctx.execute()
    except Exception as error:
        if ctx is not None:
            try:ctx.failure_details();ctx.event('failed',{'errorType':type(error).__name__,'reason':str(error)[:500],'backingHeld':True,'oldJournalUnchanged':True})
            except Exception:pass
            print(json.dumps({'status':'TITANIC_REPAIR_RESUME_FAILED_PRESERVE_STATE','errorType':type(error).__name__,'reason':str(error)[:500],'work':str(ctx.work),'cohort':json.loads(m.read(ctx.work/'cohort.json')) if (ctx.work/'cohort.json').exists() else None,'diagnosis':json.loads(m.read(ctx.work/'runtime-failure-details.json')) if (ctx.work/'runtime-failure-details.json').exists() else None}),flush=True)
        raise
if __name__=='__main__':main()
