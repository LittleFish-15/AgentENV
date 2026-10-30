"""Upload the frozen completed report in small immutable pieces. No workload."""
import base64,hashlib,json,os,sys,time,types,urllib.error
from pathlib import Path
PIN='3265dfad8b0abc73df7c656edca4c6811e4989496b19ff9d0d17940c3d876778'

def main():
    entry=Path('/var/lib/agentenv-hpd4-full-v3/entry.py');raw=entry.read_bytes()
    if os.geteuid()!=0 or entry.stat().st_uid!=0 or hashlib.sha256(raw).hexdigest()!=PIN:raise RuntimeError('Expected installed root entry')
    m=types.ModuleType('small_report_upload');m.__file__=str(entry);sys.modules[m.__name__]=m
    exec(compile(raw,str(entry),'exec'),m.__dict__)
    # Historical archive transfer must survive reboot and not depend on SDK,
    # namespace, module, view, Runtime or old process identities being alive.
    service_raw=m.read(m.BASE/'entry.py',256*1024)
    m.need(m.digest(service_raw)==m.ENTRY_PIN,'Service source changed')
    service=m.load_module('historical_services',service_raw);api=service.module('api')
    node={'server1':'node-a','agent1':'node-b'}.get(__import__('socket').gethostname())
    m.need(node is not None,'Unexpected node')
    work=Path('/var/lib/agentenv-hpd4-full-v3')/node/'resume-r1'
    completed_raw=m.read(work/'completed.json');completed=json.loads(completed_raw)
    m.RUN='hpd4-replay-20261030-r1'
    pin='012e7c6305ce0c0d5984372dd6319e95965f5222a23bccfcf5345b5108e48084'
    m.need(completed['node']==node and completed['runId']==m.RUN and completed['entrySha256']==pin and
        completed['data']['status']=='FOUR_RETAINED_GUESTS_REPLAYED_LOCAL_RELEASED_BACKING_HELD','Historical completion differs')
    current=service.identity();old=completed['identity']
    m.need(all(current[k]==old[k] for k in ('machineId','hostname','uid','gid','architecture')),'Different physical node/user')
    tokens=json.loads(m.read(Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json'),8192))
    results=api.GitHub(tokens['resultToken']);results.private_repo(m.RESULTS,1438089386)
    key=f'four-guest/{m.SESSION}/{m.RUN}/{node}/completed.json'
    status,known,_=results.contents(m.RESULTS,key,'main')
    m.need(status==200 and known==completed_raw,'Historical receipt not acknowledged in private repository')
    ctx=object.__new__(m.Context);ctx.work=work;ctx.node=node;ctx.pin=pin;ctx.results=results;ctx.key=''
    ctx.transport=api;ctx.expected={'identity':old}
    archive=work/'report.tar.gz';raw=m.read(archive,24*1024**2);full=m.digest(raw)
    print('HISTORICAL_REPORT_UPLOAD bootChanged='+str(current['bootId']!=old['bootId']),flush=True)
    target=Path('/var/lib/agentenv-hpab-services-v1/upload-reports.py')
    data=Path(__file__).read_bytes()
    if target.exists():m.need(m.read(target)==data,'Different fixed report uploader installed')
    else:
        with target.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    starter=target.with_suffix('.sh')
    script=b'#!/bin/bash\nset -eu\numask 077\nexec /usr/bin/python3 -I -B /var/lib/agentenv-hpab-services-v1/upload-reports.py\n'
    if starter.exists():m.need(m.read(starter)==script,'Different upload entry exists')
    else:
        with starter.open('xb') as f:f.write(script);f.flush();os.fsync(f.fileno())
        os.chmod(starter,0o700)
    diagnostics=[];original_open=ctx.results.opener.open
    def capture(*args,**kwargs):
        try:return original_open(*args,**kwargs)
        except urllib.error.HTTPError as error:
            preview=error.read(8192)
            try:
                value=json.loads(preview);body={k:value[k] for k in ('message','documentation_url','status') if k in value}
            except (ValueError,TypeError):body={'text':preview.decode(errors='replace')[:2048]}
            safe=ctx.transport.redact(m.wire(body),[ctx.results.token,ctx.key]).decode(errors='replace')
            diagnostics.append({'httpStatus':error.code,'body':safe,'headers':{k:error.headers.get(k) for k in
                ('Content-Type','Server','X-GitHub-Request-Id','X-RateLimit-Remaining','X-RateLimit-Reset','Retry-After')}})
            raise
    ctx.results.opener.open=capture
    def put(path,payload):
        for attempt in range(5):
            try:ctx.results.immutable_result(m.RESULTS,1438089386,'main',path,payload);return
            except ctx.transport.Network as error:
                if error.status not in (0,409,422) or attempt==4:raise
                time.sleep(2+attempt)
    try:
        chunks=[]
        for index,start in enumerate(range(0,len(raw),16384)):
            piece=raw[start:start+16384]
            path=f'four-guest/{m.SESSION}/{m.RUN}/{ctx.node}/artifacts-small/{full}/{index}.json'
            payload=m.wire({'sha256':m.digest(piece),'dataBase64':base64.b64encode(piece).decode()})
            m.need(len(payload)<24*1024,'Small upload bound exceeded');put(path,payload)
            chunks.append({'path':path,'sha256':m.digest(piece),'bytes':len(piece)})
            print(f'REPORT_CHUNK_UPLOADED={index+1}/{(len(raw)+16383)//16384}',flush=True)
            time.sleep(1)
        m.need(m.digest(m.read(archive,24*1024**2))==full,'Frozen archive changed during upload')
        manifest={'sha256':full,'bytes':len(raw),'chunks':chunks}
        # Preserve the existing event schema, so the already-shipped collector
        # validates both the file and its source experiment identity.
        event={'runId':m.RUN,'node':ctx.node,'identity':ctx.expected['identity'],'entrySha256':ctx.pin,'kind':'archive','data':manifest}
        path=f'four-guest/{m.SESSION}/{m.RUN}/{ctx.node}/archive.json';put(path,m.wire(event))
        m.atomic(ctx.work/'small-upload-receipt.json',{'archiveSha256':full,'bytes':len(raw),'chunks':len(chunks),'newExperimentExecuted':False})
        print('EXISTING_REPORT_ARCHIVE_UPLOADED_VERIFIED',flush=True)
    except Exception as error:
        value={'errorType':type(error).__name__,'httpResponses':diagnostics[-4:],'archiveSha256':full,
            'archiveBytes':len(raw),'reason':str(error)[:500],'newExperimentExecuted':False}
        m.atomic(ctx.work/'small-upload-error.json',value)
        try:ctx.event('upload-small-error',value)
        except Exception:pass
        print('SMALL_REPORT_UPLOAD_FAILED_DETAILS_PRESERVED',flush=True);raise

if __name__=='__main__':main()
