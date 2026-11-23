"""Manual M/N root task entry. New tasks arrive only through the private queue."""
import argparse,base64,fcntl,hashlib,json,os,platform,re,stat,subprocess,sys,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/root');STATE=ROOT/'relay'
SESSION='rust-demand-20261123-01'
CONTROL='LittleFish-15/AgentENV-relay-control';RESULTS='LittleFish-15/AgentENV-relay-results'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def identity():
    return {'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'architecture':platform.machine()}
def child_environment(parent):
    result={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    # Preserve transport configuration, never copy PATs/API keys into the child
    # environment. Approved tasks continue reading existing credential files.
    for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy',
                'SSL_CERT_FILE','SSL_CERT_DIR','REQUESTS_CA_BUNDLE'):
        if key in parent:result[key]=parent[key]
    return result
def read(path,limit=512*1024,owner=0):
    need(path.resolve()==path and not path.is_symlink(),'Redirected local input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid==owner and st.st_size<=limit,'Local file owner/type/size differs')
        data=f.read(limit+1);need(len(data)<=limit,'Input exceeds bound');return data
def save(path,value):
    raw=wire(value);tmp=path.with_name(path.name+'.next')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def mkdir(path,mode=0o700):
    need(path.parent.resolve()==path.parent and not path.is_symlink(),'Redirected state directory')
    if not path.exists():path.mkdir(mode=mode)
    st=path.stat();need(st.st_uid==0 and stat.S_ISDIR(st.st_mode) and not st.st_mode&0o022,'Untrusted root state directory')
def fetch(client,path):
    code,raw,_=client.contents(CONTROL,path,'main');need(code==200,'Private task document unavailable');return json.loads(raw)
def put(client,path,raw):
    for attempt in range(5):
        try:client.immutable_result(RESULTS,1438089386,'main',path,raw);return
        except API.Network as error:
            if error.status not in (0,409,422) or attempt==4:raise
            time.sleep(2+attempt)
def validate(job,current,node,pin):
    need(job['schema']==1 and job['sessionId']==SESSION and job['node']==node and job['identity']==current,'Task node/boot differs')
    need(re.fullmatch('[a-z0-9-]{1,96}',job['jobId']) and job['rootEntrySha256']==pin,'Task entry binding differs')
    need(job['humanApproved'] is True and job['scope'] in ('read-only-diagnosis','approved-root-operation'),'Task has no explicit authorization')
    need(API.timestamp(job['notBefore'])<=time.time()<API.timestamp(job['expiresAt']),'Task authorization expired')
    entry=job['entry'];need(entry['repo']=='LittleFish-15/AgentENV' and re.fullmatch('dev-relay/host-pmem/[A-Za-z0-9_./-]+\\.py',entry['path'])
        and '..' not in Path(entry['path']).parts,'Task source path outside reviewed experiment source')
    need(all(re.fullmatch('[0-9a-f]{40}',entry[k]) for k in ('commit','blob')) and re.fullmatch('[0-9a-f]{64}',entry['sha256'])
        and type(entry['bytes']) is int and 0<entry['bytes']<=256*1024,'Invalid task source descriptor')
    need(type(job['seconds']) is int and 1<=job['seconds']<=10800 and isinstance(job['argv'],list) and len(job['argv'])<=16
        and all(isinstance(x,str) and len(x)<=512 for x in job['argv']),'Invalid bounded Python invocation')
def publish_report(client,node,job,report):
    raw=wire(report);compressed=zlib.compress(raw,9);chunks=[];digest=sha(compressed)
    need(len(raw)<=2*1024**2 and len(compressed)<=2*1024**2,'Task report exceeds bound')
    for i,start in enumerate(range(0,len(compressed),16384)):
        piece=compressed[start:start+16384];path=f'root-results-v1/{SESSION}/{node}/{job["jobId"]}/chunks/{digest}/{i}.json'
        put(client,path,wire({'sha256':sha(piece),'dataBase64':base64.b64encode(piece).decode()}));chunks.append({'path':path,'sha256':sha(piece),'bytes':len(piece)})
    manifest={'schema':1,'node':node,'sessionId':SESSION,'jobId':job['jobId'],'identity':report['identity'],
        'jobSha256':sha(wire(job)),'entrySha256':job['entry']['sha256'],'exitCode':report.get('exitCode'),
        'state':report['state'],'compressedSha256':digest,'rawSha256':sha(raw),'rawBytes':len(raw),'chunks':chunks}
    put(client,f'root-results-v1/{SESSION}/{node}/{job["jobId"]}/result.json',wire(manifest))
def run_task(control,results,node,current,pin):
    queue=fetch(control,f'root-entry-v1/{SESSION}/queues/{node}.json')
    need(queue['node']==node and queue['sessionId']==SESSION and queue['mode']=='manual','Queue identity/mode differs')
    if queue.get('stop') or not queue.get('jobIds'):print('ROOT_QUEUE_EMPTY_NO_ACTION');return
    need(len(queue['jobIds'])<=4 and len(set(queue['jobIds']))==len(queue['jobIds']),'Invalid queue bounds')
    for job_id in queue['jobIds']:
        need(re.fullmatch('[a-z0-9-]{1,96}',job_id),'Invalid queued task name')
        job=fetch(control,f'root-entry-v1/{SESSION}/jobs/{job_id}.json')
        need(job['jobId']==job_id,'Queue/task differs')
        directory=STATE/'jobs'/job_id;mkdir(directory)
        result_path=directory/'report.json';state_path=directory/'state.json'
        if result_path.exists():
            report=json.loads(read(result_path,2*1024**2));need(report['jobSha256']==sha(wire(job)),'Completed task descriptor changed')
            publish_report(results,node,job,report);print('ROOT_TASK_ALREADY_DONE_REPORT_RESENT='+job_id);continue
        validate(job,current,node,pin)
        if state_path.exists():
            report={'state':'unknown_after_interruption_no_retry','identity':current,'jobSha256':sha(wire(job)),
                'previousState':json.loads(read(state_path)),'exitCode':None}
            publish_report(results,node,job,report);print('ROOT_TASK_UNKNOWN_NO_RETRY='+job_id);return
        for previous in (STATE/'jobs').glob('*/state.json'):
            if previous==state_path:continue
            prior_report=previous.parent/'report.json'
            unresolved=not prior_report.exists() or json.loads(read(prior_report,2*1024**2)).get('state')!='completed'
            if unresolved and job['scope']!='read-only-diagnosis':
                raise RuntimeError('Unconfirmed earlier root task; only approved diagnosis may proceed')
        entry=job['entry'];code,raw,_=control.contents(entry['repo'],entry['path'],entry['commit'])
        need(code==200 and len(raw)==entry['bytes'] and sha(raw)==entry['sha256']
            and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==entry['blob'],'Pinned Python source differs')
        path=directory/'task.py'
        if path.exists():need(read(path)==raw,'Prior downloaded source differs; preserved')
        else:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        save(state_path,{'state':'running','jobSha256':sha(wire(job)),'identity':current,'startedUnixNs':time.time_ns()})
        print('ROOT_APPROVED_TASK_STARTED='+job_id,flush=True)
        start=time.monotonic();timed_out=False
        with (directory/'stdout.log').open('xb') as out,(directory/'stderr.log').open('xb') as err:
            p=subprocess.Popen(['/usr/bin/python3','-I','-B',str(path),*job['argv']],stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                env=child_environment(os.environ),cwd=directory)
            while p.poll() is None:
                if time.monotonic()-start>job['seconds'] or sum((directory/n).stat().st_size for n in ('stdout.log','stderr.log'))>1024**2:
                    timed_out=True;p.terminate()
                    try:p.wait(timeout=5)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
                    break
                time.sleep(.25)
        logs={}
        for name in ('stdout.log','stderr.log'):
            raw=(directory/name).read_bytes();need(len(raw)<=1024**2,'Local output exceeded safety bound')
            redacted=API.redact(raw,[control.token,results.token]);logs[name]={'text':redacted.decode(errors='replace'),
                'sha256':sha(redacted),'bytes':len(redacted),'redacted':redacted!=raw}
        report={'schema':1,'jobId':job_id,'jobSha256':sha(wire(job)),'identity':current,'exitCode':p.returncode,
            'state':'interrupted_outcome_requires_reconciliation' if timed_out else 'completed','logs':logs,'elapsedSeconds':time.monotonic()-start}
        save(result_path,report);save(state_path,{'state':'executed_upload_pending','exitCode':p.returncode})
        publish_report(results,node,job,report);save(state_path,{'state':'result_uploaded','exitCode':p.returncode})
        print('ROOT_TASK_RESULT_UPLOADED_EXIT='+str(p.returncode),flush=True)
        if p.returncode!=0:return


ADMISSION_SHA256='70b67f83f3e95ce4f090ed0e988097bc9700ef06636c09ef2d99100ffb783081'
ADMISSION_B64='eNq1PGl34zaS3/0rOMzuhkx02G630603yowPdcevfa3tziSr0fJRJCQxpkgtj7aVHv/3rQMgAYqync3bfjMxCRYKQKFQN/TNX/plnvWnUdIXyRdrtS4WafJmx7btsyRfiaCwzqOkfLRWmcjE/5RRHhUit2ZpZhULYV30L62bMi+sUCz9JLSyMulYDxHgKAtrkcKHYOEnc5H3AOHOTrRcpVlh+dl85We5UO/z36OVel74+SKOpuo1WvlhmIk8Vw2/5WmintN8Z5alS2vlF9jHks3X8KpAsmqQfFEWUVy9FX5RPZfTVZYG2iD5Ot/Z2bk4O7aG1t7u/oH1Hf3Zuf319m504V0f3f0EX2yiXA6kGygaDuRr1RangR9rMPwOr/bO6PLj2eXIO/71bnQL2N57P+weeLtvD9WH25+OcJD9/UD8EO7PDt7svv/h8G24904chLODPf+dv/8e/vhBuLv/JvCDg8Pw3WzvzVtfiN0gPPD3xd778OCtvXN3dXWOIzg7Fvyz51Fhdyw7gF1I8SGD/Quohf/7/ff4Z85vcYj/Xfr3gr7xA+NZ3c+7QZrMojl9imGf8QFIWaTUN12JJM9jahQZ/V2mYZTMeNjVUmFa3ov9WY6NoZiWc36EPSjEMiioX7SipmDFE07KXGTUAtvI06xnkgk/FPEMkLs7ny/P7rSll9Nc9KDrlyig9cD7MtQbfDgDxvtcJIXRxohUe7ecdvPwvq0LfgoFtmqd3Z1PJ1eXH84+1nPid+/TzxfYW74dn3/yTkc/e5/hQWs+PfpFe/twyw0GntEvdwfwRQO7Or7QUV9cnX4+H92aLT+Pbm7Pri5vG8gY1rvFwa5uTkZap8+3oxuPOrhwVEIxs5DuXiEeCwfPY8eKo2VUDA923x+6A8JaZGt+wH8oJCzkEAltZ1PbtfzcytMyC0QNiP9Cv/CBYvyphwM5hN363tpzK8hMFGWWEHAvFEEaCscui1n3HXPFKvZhD9xeXmTRynGtaGbFMDyCu9ZfhzxfS8S5sC7TRBBa8RiIVWFd3Y6yLM0GzaEIjlc/i2LhzfygyI3lI0THkuLFE48iKAt/GovhBx8GaiMM9oa1ohAjTPX6vrFuYOUkd+EIJFEyV4i/zS0YufRjqx7BEl9EgouMihyQBvfAmIz8AagsyRH2tCXlafxFhDA2QUHPzWkzefB7T8I7SM6gGN5lpdC3Ii/jAlB9tRHYHoCspn2Lo+Sel/XcAIDTUfNxnyqsKDoAp/rSw9PvNAftlSvYUuFM16CohtgF4Lw8+h32oYzCqgWeO9Zca4DnjsF19T8QW2I4s7/igL1b7wzOxchR/fCjO9g9SJ/sei6wOAV8e/LTjQlsgfasvsIJb6AyJmEuaun/lmZDoCU9VP0yEDRux1pGifyKD42vW5aG/0BHZ8A/IjsleTXcPnNjgXxgotxK0oKOgoUmQNX5ZvSxsWz8rG9IderMJc9if57DPsNCrryb06vL81+tf/Hb5dXl8fnVySf1fnJ+NfpldGJ2D7kvCRfFKx2J9RmmY4BqoA9X5+dX/3AN1Cy08t4sJOSz8AW5RcQtsww0As9pRiwr5RiKjCR1XHejTxRCj6hYo5ZQBINN7FTUg/3tWCZvV6QuoqXwkrxuCWRLyzgz2jtjy+R8DWat5vMXpbZa2ajuSZPV3mm+2jtN+TWI6tVojdWCBq0odOHc/BZGYIziZkg7s5cv/P23h84mbTKwaCMSskOD0huADwvYxxq8fU7BokzuGyoMTqkDNman7tvCCto2EY7BVqo9t+x66UqSEDJ3C/3UyrtDUpFbYP0ZiIw/xtczk5UIQ8Uv1RtxS/X2PK8YkzE5pmr6E/zC4ndsM5vYE1iupONCPPKTs2GBcCfdgHCkBdEBbynB2dCb+5xBUaBdLsCiStPYSfylUgzfWMoxS5N4bbGZbCFU3rOOLPJNgMTZ2gKTuMjSOAadPl1bvz3ck6wGsyBD+wFlVpamBVsAAcjmCBkDeZQ8pR7wdbCgkTuk8Yea98NLVnyp+rYvZ8PCyUUM0ydLg6ycqr/bZowo6OcNDnRI2WxJoEfhaIL/u8peAKcTKAOc8V2FVDa5DdaQlgYZOg0rQ/FxbUaQhNQUnfUf1m66u78/2HkNp8m2igh/km2CdImeuNy378DJK5e8aDZI3+z/cPhO2Z3ANLDKTU7TdxdbX7mxldVXe9Q94DRTY4wRoT6zSQcUELiFQ60X+D6Xn8/P6UtaFvqn67PrkSkOAEZkWWt3pBn2PwD9sRDBPZvdZnfw1YZfbeRqMFM1Hgfdfn50+REa7RP0IM5PvKPz8+r1p6uLEb708RDZTzXOLeKgx0t5xjNRHokB/5JrUrOItv47XvbocRVlYEE/xy/qJHggFvIoBXcsS+eZv5SddLlg8IkCkzJpRMYU6gzfQrByBWIkWlpLf23NRBEsoH0Z5TlCwLA+8gniAdMzSnrWFYoyIASFfMhfgYPXKmPwsDWkRiUZ3B5yrzUcclCjXNnbGRfIsyqRV9WBkQuCDel2JS1sdWje7b3f55VKNNy7l6/iqACXRuSOO96djAd7h7sTnLLEjgZvC6i2k7wJFA3z/Czz1+yPtviFX/y4FGgWYwSsF6d+mDNsc4kSEGUUkBukVxIIhxtxPXkhxx9PDD66W6+E5KSfEXiLqIFePOdEFA9pdu+IxxUxECgJIVQHdPNyEqD1whShZTCn+xtFSzi6R7GcRfpQUXxv/50MukkzggJn6FD6vTnId5ve4cyg4MfRUPDzqNjiq1cGxlE8GXgaT6RHmcHOiFdNkiApKCYw2oTeKa3VZScWHg2KEjj6qTTAmDlCjkZwX590XvpakdhWtDySVBnQWKqVRlMvNQ/VkoeJIjtf+HDqBOJwGkgSJubL6OTmnCVfQE6n2froix/F6DAB0ikKASK4S/E9kZmTJgKZ5Glgxw83RNmB9dXmUBk8EqF426DNRuxsV5rfVpmY5RnGGbVGbHC3urp2ASxuYqEWHALcgY8gSx78Ncr0uXxEWhH0U7WFrUspgtVJmiRAyegL2LZ3AuUkINK0zZM8NkR6zw+CFDS6I4+LfEVmdOowmt0Hwdlf+Xn+gFFYcBXIGbMxhqVJE8Iwh8mtWvvTl5e6o3E4hCP9iJZT+sAAjj2QBwyakBTVNIkYD2gZZUWOTrFjA4YB0p5Io83pFWjl3F+HdPPQACfkwJ+KJ6EPbijYZdACL+N9On+4QhTHqGARxPpxaP3QupnzquebP9hzkS6F7Pr2D3bNFyKOZd/DPzphpN9HmjU9yhUz+RUKeiMkb1qRAL329ncProKgXEUiPF5fFQuRAUo/WePeoRgDlw23xCak2AYDobLFjvaLHlptqMt9X/orJ/aX09BnnTXgPxqXdCqWq42j9IFX4ZpbBnN4+3+d/Nv/p8kzYz8/9TQD09fP1ieUjgFhrQWS7T5yVB9m3e9RuobSdJy4cRWPVJvpmoImzb0MbDs/F0rK3Is1SQj77BSVmYz5e/x2fTO6u/vVuzwCq9ZVOly0SpQ070rM0JFMo61ypY4Ds8qT2lpI9Szy2r6A2XUsr8NktIb0Gd2zIirQLLWHZnQVwBEJrqktYDqGD+isy02hkP+39j+//dZlI21n011nst2LLBGxx+kkR66zY03LKA6bNjFRh4xRu4+md5979ea/4+7LD1N0D1yrD3Tnz13b+t6SiF2JGT7bPZnCcneaDm09YL1UwzaUNGF3tZzNokdibZzIphNKQUxMufaM9AtaNiIJMEE3H1beiUArMB9qTsozoU6aF/BJI86FeVQjUaPHkGEG2AUOBmqoLcGzFJzfpDSjM8j3m+By+GYuCpXfTktIDUFaQrbN8TZ8rdHVh6Z93NpRhbK/PhmRCnJTYGNlMtBEskTDjdbQy4WfBQsnm9nO35bufzt/G3zFrk9DZ7xeJhP3X99Y3KCi8Lko3H+DbSOSbgbVxwiMx8KhQcZ7Ezq5CUsTHtj0MnWVW9thZOBhEgcYhxBDG/01Ddu6A6fBKtivT0/mcWN5pw4F02OZhmVMZ0yepDia9mUjHSgJTsB8ioZVJzhP1MSSPc2iOUjZuF0Q1Ua/lp5Op8tl7Y0cvnl30CrlXi+/Bq3yy7EpWgrbgoOC37n05xFlz8GWrd1QO4/mCae8QwGnNsxlo4dxbD9GhWBykVpymyAEGfhmV8pAJlhN5HydSyL3iQTbrC6lAQZWJSPtlT8Xx5h243wfoEKR5ti3J9710UfMI/8XKBdN+fEWDfTkKQtaLhWASdyul0iFFhjc4guCgYEYqGNRqQYe9uYgN9p0lWio0ERJEJehkOK7zzzZUys0DA0Bu+Cjh1YWKYKjxt7AU0H1fQnWWwDfRLmHi3B0hFLmD57XO7q9gJsy0HZCOn5+SB4HUw2HCqPMcU0+0hcv971vADRcJ9jkGZlfW3riZ/jY7LVI45D3DOYAPhF4juB8Sx9S667gOlI87B1izopI6OGJyDnG28C+Wool5sEx+r1lXnDqoHsBuPsI7WWpB0cM/dY2ZKdUuvSPLCrEK/FxsZP3gF22YabIC8bemUfxRMgTWfF2fhrl2Dc0hpWmBJ5D5gkl82BHJXhzLBQOPhxQMQLhBQK3iVA70/KPtiIUIoL7bSAGZ/U+TB+SFnxybrkISiDDul+BajieTIu0jRtYPaMzHz0qabv/doMRtlZLzIA9Ue7L0IuepM3JbJKKCs0WzIpEomEuoiLgdAlI41YIZVzRHFHRUqpbdaOQo+60MtyWVBNNt+evUIQ7df+taT80j6gP2kctqXL93xS26L61AqNykPE8Ya2WPNOYgKxHkORHmVFkZRL4HMPYnMLTjpEH0fap1RK36ROlzvI0A6SMbjwgZJNXZM+2ld/oS+NQS7223cYy6PtTFfSmgiypTuRe1RTDCaORYthqVErGS4dznT5QcuqrfUYFcucgf28Ln6OERxgGEtXrbTmtni/8KLlmh+uzLGH7KOMz9ofMn2NCBBWx/dQepDar4mTE1O52k7SLyjfjNxAgK5EV6yF6GnbH7v2Wwk5L4svJY1TlO1pT7W9grPh3Cp06cmRl8bDZoJzbfyb/THR7g8hImdGgcMjukYBDmM+eaxhbPIYZDgc2AlDlExpmEqHmWB1QmoKXvE+trEbQY4ScTOqNJNNnPNh/uzupdlTZaYCPhwBRvpRzUTsuKfW01VdUlSQGGxG3k5uN1YayyrArEpD9dc0hPXxZdstpfN8NfbFkK0+vHQTkehPtN7At7LHbyq7jicGuNA2eOgrChNh1d6dNQLLGsdtl5MvyUbpSmjSM8lAE0dKPHfcVzpU+xe+H1l4Tufr2o0Vm+CZGU/CpPTC8QDJueYasDvooKcjCPzzY9AwlDSWJVQhNMhn5UK71V2uvNcNbwyg5HyWFLutNi5o3T57NVRTmrsaj+F5PROdR/FJJM1Q+XhEF9zlikDRXfkhNhJk0Lb4C0FOfSmelT8MSIBJxmFeuQqb5Lq7tjvcn8lQb8+dO4733k0pdUQsqi733G4kuPgbywEgpnFf1kUJVaGD9CaX+GWBsFu5OWB5osnRXngkjMjNGuiMmd8LebZTonCmr0SSIkcCp0fSAboKTgzxBHlqe7PHEdV/doRYBVbfqCMtxKeYT4axIlPawuB0DXHWuMx8P3k60Q0WbjpRqsMBOM86BX16KVUgprjlaJseIR5z9m312sVqrWs2iDDk4I2b9YswSY7KvmVlerlZ0QFCsahpBFuW4GOzSiuZxY6UmoCJQe6IBULl9uw2l9cPsAfXardhEfsECD3vSsd65qsyDwDaqUOXZBxOFAvMrrDa1iQB3uGJoopVjo1rd8fo6Qkl3naVfopDi19U3UNbf0Qye3K3qKA/vTVW0wEr4LDejHtJgIy0vfX68mCCbtcCl1tovp40PfI+h6uQOWuNbxPgeuEzg/7Lq89h/mtUNUiRUQHE0RR+XX+hWQTfonyWheOQmeaugD/9Hr9pkHVk8rdbYp5mY9v4ml28PEdL3TSEv6TquwmBobBDsTqN4SdI98IMFvVd2nH5hobuqAk1v9/ZV2luXzJr9xKi2xKDIkPrRplMnrakXjlYsZkXHAs90UaiYlbLdfiTjbaehU7FDZQ9qKsKysQKiWcVOiBX4zkaoWkv19W2WyE13ykGGQJvJo3sWqWSR6roJPCMn1B+y9apI8d3drKSWZeOikCUoWnVbbQVXbmrziAD2w4PmOYimfR+DtIcH3RgvSnXnSdl6VgDymXPSusgtC9MoQOvcMMecegl8ArTYU6vJsoUuyN8bqFRyaJr5aAvWBujGiVKaQplUxn43FqzVxLQ4w5pFpGr82GCq5i5NIxfM/P3J06YhjmInSoBX/Tj6vbLDoXGGIRmzKV/gf9H6D6TbZnxY+iu7UWJgAsRpes8undFcJtSz0RqKaiBeOBCkypmzDdfis1Tkb/otz9MYDxjhMFLq+Xo5TeNcF0/VHSp0J8N10gWYnN8eQDVhEUx4P+a7HRMtblMJr4jU0UbJGiozsleEsiONQLyaybOB9spO1aSVeS9Bt0KH1jtW7Gyo7k56GD1n+gwkSeS3Q04Sf748bWTN5Lx7fhhKxOMflDVs/53EJCCW6xEUiWvmTTFkNi1zUKTwP08CYc/9d9uzp0akaxoR5RbikRwKiQLG7YD1QQRXQ7fWCdY1XRsoK9AqrCIVHBgg8olFDrMcxoTUc62Pr+/nJzKWbdCuTq6Y9wW7XbCktARHfVmwKgBzG+EHfDWrFjj6Gd7fMt98wLgSTI/cr01vWHft5JZOXkr8Ix9LptQvurRUUEg58IE34RhIixUp8GcD5LjM+aLNthC5wS6hBO3oSX4tQj8HAr4GncTTl4ktSiSgDOIiq+Ycy2zpv4QVe3YU8AaO+yR9SI6ptuGW7fSBZqR3DACVNNJt9Aa629NPJxRP12J9H/xpFgWjR5EFUb4Z5Quj/H5biK+2hzP/gVVwHxdDFRfVA5Ze0EuxXOl6Vr+jB/03PB6ybsRjlBe581KKeDORz7XnGKABF/3LLG9cA2QZGAtZ+a8HB+Vt2C4Lbkoj/vsdnzYslPMfNFHttgXQAIQCZ7avSv3U1lCB+8yb0gcQ8/J9lvHtI3uWCXGWgHOkAc8I+Nm7G3a9Epnj4xf9lqa22OrcPTVz8xsx4g1ib4ngTYXjZ3MVeaA760gAfKC0LKUyS3zE+mJYIKtiG40+UL4BCXIDaAkmerQhGmTrWTM5gxU18ls3Cjkg1eiKJSRnL2WJMmCBdEnlJl6FB455Xqc+9ZIgFdWkV2Y3NX89ry5LQMmQUhW/SK6eKhz1JETHomYs6lRNzGEPWZrMPUlXhzvL9cI8Sf/ix7FGINLDDcC2FAmcXsYnF60hkySrMUmQZ9E010T4KgqMW8trJ0ovUOijujlRr7ola4HntMRzYo9+uR6d3I1Ovcur0xH8586jipCbixHFtZDdsIoNJ4fPHhxJ0XKgiFtRW8Mf7MYbhT3V5J861j4bezKmVofXlIikz1XcCuuizfA2WxPkrePXF0N5suYMmRPAWws9CEQqJjx1KOg2HAnXqIVivdO//0JKjJ4piC4vO1WNQIN+USbVO6k7zN7akvXpxlTtvWxegjEMCPoNhSe9WBcNULOWVzPftVAMc0Sec/G+jPQBhzCfGlKE7U/pTmp2FPdWISU78TG/JH+X4+jm4vDAop/myPiiF94PX1EgyaoiScaNHt6KcaPCgkqBnvncCLkBsAI0CixoDXJ/t66Ae+LPIwBvFKA56KSZ1RxcjoT3RYoFHDF1410yFN0JQWMyW2JCXF8e1nyyAq4M/X4dhjK5ibwYZe3qgdXGhD8fW2CAWCtgtSiQRjHHNin/DJgivpQHRJeqSsWgcKh8c4Z/wFlrcwBp4rVJPqkc4JeWwH3WL0xeQW2ZPJ/98TOhy4lMHM2layflxvbpVbutNvrz8e1I/zmDZ3ZcSpBxLRoqZm75xIzcuPNub59Zklqffr6oL8lLnPQzCumUcnKgJQqrGmHj+hwMz0W7Ew5xIRVZaIwb9b+TrbOg7+au4UHf2DnaMVw91gbf8E2synyXU5MXsTwlAjf9JUf9Sszc+FEY89dgTIdO/u6Lay6cEmGVzDMG3rpUrqfiyak7Y/Q7PxuLxWt6oEUpy23JNLcxRq2QN6yTeitqBV9fSdm+EXSfha+CwBbGjGMqalYgrRCvG5VzmtK/GR2devirBt71zehm9J+fz27PwOEB1X9+TtbAa1X/y2of7dRAlUTIJ3S9SIhWVWcNrGHt9wmp1W2iJiYt8G8DXnrxVNgp05nNS4WbCtV56QeIFD89Nd19aWpgdqSyOuzK7MBci3qGdil3oFU+dShggJ3D+wbm2s9gn7f2HvEXiIgL0LehBzwa8Kc4AZN8467Ps06rmvQJ/TCW/oU3o9EOhtuudFYwUancSbqzhpfv1W9p9Y7kfdpr+uKAIxaAB4XB+aHnhWngea7WE2NZnrqC61AFSSi6xGM23pVNcYpDh9iwu1QM2U1s91ksyoLu1vf68IrVsPoZr160Mt2DLYjwlP1pJJpb9Swc+gY1EB45dSsw66nLgfPWoByFh0CuxH4BzL0k+43SADaK4JTylGUUOpTq3K3bRN3YVsjSAcUXFR5eFCZnVJMdV+AjnJ9dfv7FI8lxA9Kisu3by+LbUGp+78v3zY0LoVQk0qzGemHOlbw7u7xFfwdvnXw4OjtnSUfY7vhqHu6zQw1uz6OaMs974bcfsH+CN2eArH6BNx15zrJdhs2ARnvSwcHoKd2hDcvlKneq2Sc52OCenwdRNORCOUwyeJiAV+8C6yYLvBDh2B2cO99Om8VlvtBy31LmV/SA8wuMotZDVzM8D0+z50krP/Mj8MJvSfiMoJvDZ93d+V+W1zAl'

"""Entry main and first enrollment, assembled with the existing private relay."""
import getpass
import grp
import ipaddress
import pwd
import warnings

ALIASES = ('node-m', 'node-n')
HOST_HOME = ROOT.parent
ENTRY = STATE / 'entry.py'
CREDENTIALS = STATE / 'credentials.json'
ENROLLED = STATE / 'enrollment.json'
INTENT = STATE / 'enrollment-intent.json'
BOOT_LAUNCHER = ROOT / 'root-start.sh'
LAUNCHER = (b'#!/bin/bash\nset -eu\numask 077\n'
            b'exec /usr/bin/python3 -I -B /home/jwk/root/relay/entry.py\n')
HOST_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
JWK_UID = 1204
JWK_GID = 1205


def lexists(path):
    return os.path.lexists(path)


def directory(path, owner=0, group=None):
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and path.resolve() == path,
         'Redirected or non-directory path: ' + str(path))
    need(st.st_uid == owner and (group is None or st.st_gid == group)
         and not st.st_mode & 0o022, 'Directory ownership/writability differs: ' + str(path))


def binary(name):
    for folder in HOST_PATH.split(':'):
        path = Path(folder) / name
        if path.is_file() and os.access(path, os.X_OK):
            resolved = path.resolve(strict=True)
            need(resolved.stat().st_uid == 0 and not resolved.stat().st_mode & 0o022,
                 'Untrusted platform command: ' + name)
            return str(resolved)
    raise RuntimeError('Required platform command absent: ' + name)


def local_address(expected, peer):
    expected = str(ipaddress.IPv4Address(expected))
    peer = str(ipaddress.IPv4Address(peer))
    reply = subprocess.run([binary('ip'), '-j', '-4', 'address', 'show'],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=8, check=True, env={'PATH': HOST_PATH, 'LC_ALL': 'C'})
    need(len(reply.stdout) <= 1024 * 1024, 'Local network identity exceeds limits')
    rows = json.loads(reply.stdout)
    addresses = {addr['local'] for row in rows for addr in row.get('addr_info', ())
                 if addr.get('family') == 'inet' and addr.get('local')}
    need(expected in addresses and peer != expected and peer not in addresses,
         'Expected local IPv4 absent or the peer IPv4 is also configured locally')
    return expected, peer


def fresh_file(path, data, mode):
    if lexists(path):
        need(read(path, max(len(data), 1)) == data
             and stat.S_IMODE(path.stat().st_mode) == mode,
             'Existing installation differs and was preserved: ' + str(path))
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_file(path, limit):
    raw = read(path, limit)
    need(stat.S_IMODE(path.stat().st_mode) == 0o600,
         'Root-only file has unexpected permissions: ' + str(path))
    return raw


def named(lookup, key):
    try:
        return lookup(key)
    except KeyError:
        return None


def check_account():
    user = named(pwd.getpwnam, 'jwk')
    same_uid = named(pwd.getpwuid, JWK_UID)
    group = named(grp.getgrnam, 'jwk')
    same_gid = named(grp.getgrgid, JWK_GID)
    if user:
        need((user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell)
             == (JWK_UID, JWK_GID, str(HOST_HOME), '/bin/bash')
             and same_uid is not None and same_uid.pw_name == 'jwk',
             'Existing jwk account differs; preserved')
    else:
        need(same_uid is None, 'UID 1204 is already occupied; no account changed')
    if group:
        need(group.gr_gid == JWK_GID and same_gid is not None and same_gid.gr_name == 'jwk',
             'Existing jwk group differs; preserved')
    else:
        need(same_gid is None, 'GID 1205 is already occupied; no account changed')
    for path in (Path('/'), HOST_HOME.parent):
        directory(path)
    # A user-owned parent would let that user replace root-start.sh by renaming
    # its directory. Preserve existing homes and stop on incompatible ownership.
    for path in (HOST_HOME, ROOT, STATE):
        if lexists(path):
            directory(path)
    for path in (HOST_HOME / 'agent', HOST_HOME / '.ssh'):
        if lexists(path):
            directory(path, JWK_UID, JWK_GID)
    return user, group


def create_account():
    user, group = check_account()
    call = lambda *args: subprocess.run([binary(args[0]), *args[1:]],
                                        stdin=subprocess.DEVNULL, check=True, timeout=20,
                                        env={'PATH': HOST_PATH, 'LC_ALL': 'C'})
    if not group:
        call('groupadd', '--gid', str(JWK_GID), 'jwk')
    if not user:
        call('useradd', '--no-create-home', '--uid', str(JWK_UID), '--gid',
             str(JWK_GID), '--home-dir', str(HOST_HOME), '--shell', '/bin/bash', 'jwk')
    for folder in (HOST_HOME / 'agent', HOST_HOME / '.ssh'):
        if not lexists(folder):
            call('install', '-d', '-m', '0700', '-o', str(JWK_UID), '-g', str(JWK_GID), str(folder))
    user, group = check_account()
    need(user is not None and group is not None, 'Account creation not confirmed')


def credentials(enroll=False):
    if lexists(CREDENTIALS):
        result = json.loads(private_file(CREDENTIALS, 8192))
    else:
        need(enroll and sys.stdin.isatty() and sys.stderr.isatty(),
             'First enrollment needs a root terminal with hidden token input')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            result = {
                'controlToken': getpass.getpass('Private control repository read token: '),
                'resultToken': getpass.getpass('Private results repository write token: '),
            }
    need(set(result) == {'controlToken', 'resultToken'}
         and all(isinstance(token, str) and re.fullmatch('[A-Za-z0-9_-]{16,512}', token)
                 for token in result.values())
         and result['controlToken'] != result['resultToken'],
         'Expected separate control-read and result-write tokens')
    return result


def verified_clients(tokens):
    control = API.GitHub(tokens['controlToken'])
    results = API.GitHub(tokens['resultToken'])
    control.private_repo(CONTROL, 1438089258)
    results.private_repo(RESULTS, 1438089386)
    return control, results


def advisory_lock():
    directory(STATE)
    fd = os.open(STATE / 'operation.lock',
                 os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600,
             'Untrusted operation lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def admission(node, expected, peer):
    raw = zlib.decompress(base64.b64decode(ADMISSION_B64, validate=True))
    need(len(raw) <= 64 * 1024 and sha(raw) == ADMISSION_SHA256, 'Embedded admission source differs')
    probe = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', raw.decode('utf-8'),
                            '--expected-address', expected, '--peer-address', peer,
                            '--node-label', node],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=90, env=child_environment(os.environ))
    need(probe.returncode == 0 and 0 < len(probe.stdout) <= 128 * 1024,
         'Read-only admission probe failed or exceeded its output bound')
    obj = json.loads(probe.stdout)
    need(isinstance(obj, dict), 'Read-only admission returned an invalid report')
    return obj


def enroll(args, current, pin):
    need(args.node in ALIASES and args.expected_ip and args.peer_ip,
         'Use --enroll with --node, --expected-ip and --peer-ip')
    expected, peer = local_address(args.expected_ip, args.peer_ip)
    need(re.fullmatch('[0-9a-f]{32}', current['machineId'])
         and current['machineId'] != '0' * 32
         and re.fullmatch('[0-9a-f-]{36}', current['bootId'])
         and bool(current['hostname']), 'Target machine identity is incomplete')
    user, _ = check_account()
    had_home = lexists(HOST_HOME)
    if had_home and user is None:
        need(lexists(INTENT), 'Existing home without a matching account or enrollment intent; preserved')
    binding = {'schema': 1, 'sessionId': SESSION, 'node': args.node, 'identity': current,
               'entrySha256': pin, 'expectedAddress': expected, 'peerAddress': peer}
    remote_path = f'root-entry-v1/{SESSION}/enrollments/{args.node}.json'
    tokens = credentials(enroll=True)
    _, results = verified_clients(tokens)
    code, existing, _ = results.contents(RESULTS, remote_path, 'main')
    need(code in (200, 404), 'Enrollment repository unavailable')
    cached = private_file(ENROLLED, 192 * 1024) if lexists(ENROLLED) else None
    if code == 200 or cached is not None:
        if code == 200 and cached is not None:
            need(existing == cached, 'Local and remote enrollment differ')
        report = json.loads(cached if cached is not None else existing)
        need(set(report) == set(binding) | {'admission'}
             and all(report[k] == v for k, v in binding.items())
             and isinstance(report['admission'], dict), 'Enrollment identity already fixed; preserved')
    else:
        report = {**binding, 'admission': admission(args.node, expected, peer)}

    if not had_home:
        HOST_HOME.mkdir(mode=0o700)
        directory(HOST_HOME)
        # The account can traverse its home and own its worktree without being
        # able to rename the protected root launcher directory.
        HOST_HOME.chmod(0o755)
    directory(HOST_HOME)
    mkdir(ROOT)
    mkdir(STATE)
    fd = advisory_lock()
    try:
        fresh_file(INTENT, wire(binding), 0o600)
        create_account()
        mkdir(STATE / 'jobs')
        fresh_file(CREDENTIALS, wire(tokens), 0o600)
        fresh_file(ENROLLED, wire(report), 0o600)
        fresh_file(ENTRY, Path(__file__).read_bytes(), 0o600)
        fresh_file(BOOT_LAUNCHER, LAUNCHER, 0o700)
        put(results, remote_path, wire(report))
        print('ROOT_RELAY_ENROLLED=' + args.node, flush=True)
        print('ROOT_FIXED_ENTRY_READY=bash /home/jwk/root/root-start.sh', flush=True)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--enroll', action='store_true')
    parser.add_argument('--node', choices=ALIASES)
    parser.add_argument('--expected-ip')
    parser.add_argument('--peer-ip')
    args = parser.parse_args()
    need(os.getuid() == os.geteuid() == 0 and platform.system() == 'Linux',
         'Use the designated node root terminal')
    os.umask(0o077)
    pin = sha(Path(__file__).read_bytes())
    current = identity()
    if args.enroll:
        enroll(args, current, pin)
        return
    need(not any((args.node, args.expected_ip, args.peer_ip)) and Path(__file__).resolve() == ENTRY,
         'Use the installed unified entry')
    for path in (Path('/'), HOST_HOME.parent, HOST_HOME, ROOT, STATE):
        directory(path)
    local = json.loads(private_file(ENROLLED, 192 * 1024))
    node = local['node']
    need(local['schema'] == 1 and node in ALIASES and local['sessionId'] == SESSION
         and local['entrySha256'] == pin, 'Local enrollment differs')
    local_address(local['expectedAddress'], local['peerAddress'])
    control, results = verified_clients(credentials())
    profile = fetch(control, f'root-entry-v1/{SESSION}/profiles/{node}.json')
    need(profile['schema'] == 1 and profile['node'] == node and profile['sessionId'] == SESSION
         and profile['mode'] == 'manual' and profile['entrySha256'] == pin
         and profile['rootArtifactDirectory'] == str(ROOT)
         and profile['expectedAddress'] == local['expectedAddress'], 'Pinned root profile differs')
    need(all(current[k] == profile['identity'][k] == local['identity'][k]
             for k in ('machineId', 'hostname', 'kernel', 'architecture')),
         'Different machine, kernel, or architecture')
    fd = advisory_lock()
    try:
        boot = {'node': node, 'identity': current, 'entrySha256': pin}
        save(STATE / 'current-boot.json', boot)
        put(results, f'root-entry-v1/{SESSION}/{node}/boots/{current["bootId"]}/{pin}.json', wire(boot))
        run_task(control, results, node, current, pin)
    finally:
        os.close(fd)



raw=zlib.decompress(base64.b64decode('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'))
need(sha(raw)=='b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd','Pinned transport differs')
API=types.ModuleType('root_transport');exec(compile(raw,'<root-transport>','exec'),API.__dict__)

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'ROOT_UNIFIED_ENTRY_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,
            'reason':str(error)[:400] if isinstance(error,RuntimeError) else type(error).__name__}),flush=True)
        raise SystemExit(1)
