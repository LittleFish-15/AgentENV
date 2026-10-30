"""Read-only diagnosis of the already-failed four-Guest request; never retry it."""
import hashlib,json,os,re,subprocess,sys,time,types
from pathlib import Path

PIN='8a266e114c4b5fd52463d3cec72069b87e9e1c6edf90bdb7fe6f5054ed8ec4cf'
ENTRY=Path('/var/lib/agentenv-hpd4-full-v1/entry.py')

def need(ok,why):
    if not ok:raise RuntimeError(why)

def main():
    need(os.geteuid()==0 and ENTRY.resolve(strict=True)==ENTRY,'Expected installed root entry')
    meta=ENTRY.stat();need(meta.st_uid==0 and not meta.st_mode&0o022 and meta.st_size==88117,'Installed entry owner/size differs')
    raw=ENTRY.read_bytes();need(hashlib.sha256(raw).hexdigest()==PIN,'Installed entry digest differs')
    module=types.ModuleType('full_four_diagnosis_source');module.__file__=str(ENTRY);sys.modules[module.__name__]=module
    exec(compile(raw,str(ENTRY),'exec'),module.__dict__)
    ctx=module.Context();path=ctx.work/'creation-diagnosis-v1.json'
    if path.exists():
        value=json.loads(module.read(path));need(value['identity']==ctx.expected['identity'],'Prior diagnosis boot differs')
    else:
        state_raw=module.read(ctx.work/'cohort.json');state=json.loads(state_raw)
        need(len(state['openRequests'])==1 and state['openRequests'][0]['kind']=='create' and
             state['openRequests'][0]['route']=='/v2/sandboxes','Not the reported first-create failure')
        began=state['openRequests'][0]['startedNs']/1e9
        tokens=json.loads(module.read(Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json'),8192))
        secrets=[ctx.key,*tokens.values()]
        def clean(raw):
            value=ctx.transport.redact(raw,secrets)
            # Existing relay redact returns (bytes, changed).
            return (value[0] if isinstance(value,tuple) else value).decode(errors='replace')
        def command(argv):
            p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
            need(len(p.stdout)<=2*1024**2 and len(p.stderr)<=16384,'Diagnostic output exceeds bound')
            return {'exitCode':p.returncode,'stdout':clean(p.stdout),'stderr':clean(p.stderr)}
        value={'status':'FULL_FOUR_CREATE_DIAGNOSIS_READ_ONLY','identity':ctx.expected['identity'],
            'request':state['openRequests'][0],'cohortSha256':module.digest(state_raw),'runtime':ctx.runtime,
            'createRetried':False,'pendingRequestsCleared':False,'servicesChanged':False,'SDKCalled':False,'GuestDeleted':False}
        value['runtimeJournal']=command(['journalctl','--no-pager','-q','-u',ctx.runtime['name'],
            '--since','@'+str(int(began)-15),'--until','@'+str(min(int(time.time()),int(began)+1800)),
            '-n','1500','-o','short-precise'])
        status,body=ctx.api.call('GET','/v2/sandboxes?limit=1')
        value['inventory']={'httpStatus':status,'limitedToOne':True,'items':[
            {k:row.get(k) for k in ('sandboxID','templateID','state','startedAt')} for row in body
            if isinstance(row,dict)] if isinstance(body,list) else None,
            'emptyDoesNotReconcileCreate':True}
        c=module.UnixHTTP(ctx.active/'api.sock',10)
        try:
            c.request('GET','/metrics',headers={'X-API-Key':ctx.key});r=c.getresponse();raw=r.read(2*1024**2+1)
            need(len(raw)<=2*1024**2,'Metrics output exceeds bound')
            value['httpMetrics']={'status':r.status,'lines':[line for line in clean(raw).splitlines()
                if '/v2/sandboxes' in line or 'create_warm' in line][:160]}
        finally:c.close()
        value['devices']=[{'name':p.name,'uid':p.lstat().st_uid,'gid':p.lstat().st_gid,
            'mode':oct(p.lstat().st_mode&0o777),'inode':p.lstat().st_ino,'rdev':p.lstat().st_rdev}
            for p in Path('/dev').glob('ublk[bc]*') if re.fullmatch('ublk[bc][0-9]+',p.name)]
        value['obmmReferenceCount']=Path('/sys/module/obmm/refcnt').read_text().strip()
        value['recentFirecrackerLogs']=[]
        logs=ctx.active/'logs'
        for p in sorted(logs.glob('*/*')):
            if p.name not in ('firecracker.log','firecracker-stderr.log') or not p.is_file() or p.is_symlink():continue
            if p.stat().st_mtime<began-15:continue
            need(p.resolve()==p and p.is_relative_to(logs),'Log escaped runtime scope')
            with p.open('rb') as f:f.seek(max(0,p.stat().st_size-32768));tail=f.read(32768)
            value['recentFirecrackerLogs'].append({'path':str(p),'tail':clean(tail)})
            if len(value['recentFirecrackerLogs'])>=8:break
        need(module.read(ctx.work/'cohort.json')==state_raw,'Cohort changed during read-only diagnosis')
        need(len(module.wire(value))<=800*1024,'Diagnosis exceeds private event limit')
        module.atomic(path,value)
    ctx.event('creation-diagnosis-v1',value)
    print(json.dumps({'status':'FULL_FOUR_CREATE_DIAGNOSIS_UPLOADED_NO_RETRY','node':ctx.node,
        'pendingRequestsCleared':False,'servicesChanged':False,'SDKCalled':False}),flush=True)

if __name__=='__main__':main()
