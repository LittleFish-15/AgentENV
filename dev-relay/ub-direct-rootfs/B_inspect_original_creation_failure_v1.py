"""Read one retained original creation failure; no POST/DELETE or state repair."""
import datetime,hashlib,http.client,json,os,re,stat,time,tomllib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
WORK=ROOT/'deployments/agentenv-direct-ub-deletefix-v1/comparison/deletefix-full-v1'

def redact(text):
    text=re.sub(r'\x1b\[[0-9;]*m','',text)
    text=re.sub(r'e2b_[A-Za-z0-9._~\-]+','[REDACTED_KEY]',text)
    text=re.sub(r'(?i)(bearer\s+)[^\s,;"\']+',r'\1[REDACTED]',text)
    text=re.sub(r'(?i)((?:api[_-]?key|access[_-]?token|password|authorization)\s*[=:]\s*)[^\s,;]+',r'\1[REDACTED]',text)
    return text[:2500]

def read_json(path):
    assert path.resolve(strict=True)==path
    with path.open('rb') as f:
        before=os.fstat(f.fileno());assert stat.S_ISREG(before.st_mode) and before.st_uid in (0,1204) and before.st_size<=8*1024**2
        raw=f.read(8*1024**2+1);after=os.fstat(f.fileno())
    assert (before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns)
    return json.loads(raw),hashlib.sha256(raw).hexdigest()

def selected_log(raw,begin,end):
    selected=[];continuation=0
    for line in raw.decode(errors='replace').splitlines():
        clean=redact(line)
        stamp=re.search(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)',clean)
        if not stamp:
            if continuation>0:selected.append(clean);continuation-=1
            continue
        continuation=0
        try:ts=datetime.datetime.fromisoformat(stamp[0].replace('Z','+00:00')).timestamp()
        except ValueError:continue
        if begin<=ts<=end and re.search(r'(?i)error|warn|fail|panic|restore|snapshot|ublk',clean):
            selected.append(clean);continuation=12
    return selected[-60:]

def main():
    assert os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','B root required'
    state,sha=read_json(WORK/'run.json');assert state['runId']=='9c8f00d962c848c4b07e089bd69c5476'
    group=state['groups']['original'];context=group['context'];assert context['unit']=='jwk-aenv-ae9c626-node-b.service'
    cases=group['cases'];requests=[]
    report={'status':'ORIGINAL_CREATION_FAILURE_READ_ONLY','runId':state['runId'],'runJournalSha256':sha,'phase':group['phase'],
            'experimentStateChanged':False,'POSTSent':False,'DELETESent':False,'automaticRetry':False,'cases':{},'logs':{}}
    for index,case in cases.items():
        report['cases'][index]={k:case.get(k) for k in ('phase','sandboxIds','outcomeUncertain','openRequests','operations')}
        requests.extend(case.get('openRequests',[]));requests.extend(case.get('operations',[]))
    starts=[r['startedNs']/1e9 for r in requests if r.get('kind')=='create' and isinstance(r.get('startedNs'),int)]
    assert starts,'No durable creation intent; preserve'
    begin=min(starts)-20
    failure_path=WORK/'failure-original.json'
    failure,failure_sha=read_json(failure_path);report['failure']=failure;report['failureSha256']=failure_sha
    end=max(max(starts)+20,failure_path.stat().st_mtime)+20
    assert end-begin<=900,'Failure log window unexpectedly large'
    report['failureWindowUTC']=[datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat() for t in (begin,end)]
    out=WORK/('creation-inspection-'+str(time.time_ns()));out.mkdir(mode=0o700)
    for name in ('server.log','ublk-daemon.log'):
        path=BASE/'logs'/name
        try:
            assert path.resolve(strict=True)==path
            with path.open('rb') as f:
                meta=os.fstat(f.fileno());assert stat.S_ISREG(meta.st_mode) and meta.st_uid==1204
                f.seek(max(0,meta.st_size-4*1024**2));raw=f.read(4*1024**2)
            # Private tail stays on B. Only selected, redacted failure-window
            # lines are printed; no whole configuration or workload export.
            target=out/(name+'.private-tail');fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as f:f.write(raw)
            report['logs'][name]={'sourceBytes':meta.st_size,'tailBytes':len(raw),'windowLines':selected_log(raw,begin,end),'privateTail':str(target)}
        except Exception as e:report['logs'][name]={'errorType':type(e).__name__,'reason':redact(str(e))}
    pid=context['pid'];proc=Path('/proc')/str(pid)
    try:
        ticks=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
        assert ticks==str(context['startTicks']) and os.readlink(proc/'exe')==str(BASE/'bin/server'),'Original process changed'
        report['originalRuntimeIdentityStable']=True
        credential=tomllib.loads((BASE/'cli/config/aenv/credentials').read_text());match=re.fullmatch(r'http://127\.0\.0\.1:(180[0-9]{2})',credential['url']);assert match
        connection=http.client.HTTPConnection('127.0.0.1',int(match[1]),timeout=15)
        try:
            connection.request('GET','/v2/sandboxes?limit=100',headers={'X-API-Key':credential['api_key']})
            response=connection.getresponse();raw=response.read(2*1024**2+1)
            assert len(raw)<=2*1024**2
            report['inventoryHttpStatus']=response.status;report['inventoryPaginated']=bool(response.getheader('X-Next-Token'))
            value=json.loads(raw) if raw else None
            if response.status==200 and isinstance(value,list):
                report['inventory']=[{k:item[k] for k in ('sandboxID','templateID','state','startedAt','endAt') if k in item} for item in value]
            else:report['inventoryError']=redact(str(value))
        finally:connection.close()
        report['originalRuntimeIdentityStable']=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]==ticks
    except Exception as e:report['runtimeReadError']={'type':type(e).__name__,'reason':redact(str(e))}
    report['resourceReleaseConfirmed']=False
    report['scope']='Existing intent, failure-window logs and current GET inventory only; no success/release inferred from empty inventory'
    report['outputDirectory']=str(out)
    data=(json.dumps(report,indent=2)+'\n').encode();fd=os.open(out/'report.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data)
    print('BEGIN_ORIGINAL_CREATION_FAILURE_READ_ONLY');print(data.decode());print('END_ORIGINAL_CREATION_FAILURE_READ_ONLY')

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'status':'STOPPED_CREATION_INSPECTION_PRESERVE_STATE','errorType':type(e).__name__,'reason':redact(str(e)),'POSTSent':False,'DELETESent':False}))
        raise SystemExit(1)
