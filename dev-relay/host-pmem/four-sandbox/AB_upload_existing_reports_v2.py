"""Upload the frozen completed report in small immutable pieces. No workload."""
import base64,hashlib,json,os,sys,time,types,urllib.error
from pathlib import Path
PIN='3265dfad8b0abc73df7c656edca4c6811e4989496b19ff9d0d17940c3d876778'

def main():
    entry=Path('/var/lib/agentenv-hpd4-full-v3/entry.py');raw=entry.read_bytes()
    if os.geteuid()!=0 or entry.stat().st_uid!=0 or hashlib.sha256(raw).hexdigest()!=PIN:raise RuntimeError('Expected installed root entry')
    m=types.ModuleType('small_report_upload');m.__file__=str(entry);sys.modules[m.__name__]=m
    exec(compile(raw,str(entry),'exec'),m.__dict__)
    ctx=m.Context();ctx.work=ctx.work/'resume-r1';m.RUN='hpd4-replay-20261030-r1'
    ctx.pin='012e7c6305ce0c0d5984372dd6319e95965f5222a23bccfcf5345b5108e48084'
    archive=ctx.work/'report.tar.gz';raw=m.read(archive,24*1024**2);full=m.digest(raw)
    ctx.results.private_repo(m.RESULTS,1438089386)
    completed=json.loads(m.read(ctx.work/'completed.json'))
    m.need(completed['node']==ctx.node and completed['entrySha256']==ctx.pin and
        completed['data']['status']=='FOUR_RETAINED_GUESTS_REPLAYED_LOCAL_RELEASED_BACKING_HELD','Completion receipt differs')
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
