"""Provision one native amd64 template and run the existing namespace benchmark."""
import base64,fcntl,hashlib,http.client,io,json,os,pathlib,re,socket,ssl,subprocess,tarfile,time,urllib.error,urllib.parse,urllib.request,zlib
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');WORK=BASE/'wikidata017'
REG='swr.cn-north-4.myhuaweicloud.com';REPO='kunpeng-ai/swerebench-x86-wikidata-wikidata-toolkit';TAG='717-e99f196'
NAME='swb-wikidata-wikidata-toolkit-717-retry017';STATE={};KEY=None;TOKEN=None
def save(phase,**values):
    STATE.update(phase=phase,updatedUnix=time.time(),**values)
    temp=WORK/'state.next';temp.write_text(json.dumps(STATE,indent=2)+'\n');temp.replace(WORK/'state.json')
    print('WIKIDATA_PHASE='+phase,flush=True)
def api(method,path,body=None):
    conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=90)
    try:
        conn.request(method,path,body=json.dumps(body) if body is not None else None,headers={'X-API-Key':KEY,'Content-Type':'application/json'})
        response=conn.getresponse();raw=response.read(2*1024**2)
        assert 200<=response.status<300,'API '+method+' '+path+' HTTP '+str(response.status)+' '+raw[:1500].decode(errors='replace')
        return json.loads(raw) if raw else None
    finally:conn.close()
def registry(path,accept=None):
    global TOKEN
    headers={'Accept':accept} if accept else {}
    if TOKEN:headers['Authorization']='Bearer '+TOKEN
    request=urllib.request.Request('https://'+REG+path,headers=headers)
    try:
        with urllib.request.urlopen(request,timeout=120) as r:return r.read(8*1024**2),dict(r.headers)
    except urllib.error.HTTPError as error:
        if error.code!=401:raise RuntimeError('Registry HTTP '+str(error.code)) from None
        challenge=error.headers.get('WWW-Authenticate','')
        assert challenge.lower().startswith('bearer '),'Unsupported anonymous registry challenge'
        fields=dict(re.findall(r'(\w+)="([^"]*)"',challenge))
        realm=urllib.parse.urlsplit(fields['realm']);assert realm.scheme=='https' and realm.hostname==REG
        scope='repository:'+REPO+':pull';assert fields.get('scope',scope)==scope
        query=urllib.parse.parse_qsl(realm.query)+[('service',fields.get('service',REG)),('scope',scope)]
        url=urllib.parse.urlunsplit(realm._replace(query=urllib.parse.urlencode(query)))
        with urllib.request.urlopen(url,timeout=90) as r:token=json.load(r)
        TOKEN=token.get('token') or token.get('access_token');assert TOKEN
        headers['Authorization']='Bearer '+TOKEN
        with urllib.request.urlopen(urllib.request.Request(request.full_url,headers=headers),timeout=120) as r:return r.read(8*1024**2),dict(r.headers)
def pinned_image():
    accept=','.join(['application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json','application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'])
    raw,_=registry('/v2/'+REPO+'/manifests/sha256:a28574d78c51af2b341f769b484aed023406015cb2a249e985a0bbdcd022775b',accept);doc=json.loads(raw)
    if 'manifests' in doc:
        selected=[x for x in doc['manifests'] if x.get('platform',{}).get('architecture')=='amd64' and x.get('platform',{}).get('os')=='linux']
        assert len(selected)==1,'Ambiguous native amd64 image'
        expected=selected[0]['digest'];raw,_=registry('/v2/'+REPO+'/manifests/'+expected,accept)
        assert 'sha256:'+hashlib.sha256(raw).hexdigest()==expected
        doc=json.loads(raw)
    digest='sha256:'+hashlib.sha256(raw).hexdigest();config_digest=doc['config']['digest']
    config_raw,_=registry('/v2/'+REPO+'/blobs/'+config_digest)
    assert 'sha256:'+hashlib.sha256(config_raw).hexdigest()==config_digest
    config=json.loads(config_raw);assert config['architecture']=='amd64' and config['os']=='linux'
    (WORK/'oci-manifest.json').write_bytes(raw);(WORK/'oci-config.json').write_bytes(config_raw)
    assert digest=='sha256:a28574d78c51af2b341f769b484aed023406015cb2a249e985a0bbdcd022775b'
    return REG+'/'+REPO+'@'+digest,{'tag':REG+'/'+REPO+':'+TAG,'digest':digest,'architecture':'amd64','os':'linux','configDigest':config_digest,'layerCount':len(doc['layers'])}
def main():
    global KEY
    assert os.getuid()==os.geteuid()==1002
    status=P('/proc/self/status').read_text();caps={a:int(b.strip(),16) for line in status.splitlines() if ':' in line for a,b in [line.split(':',1)] if a.startswith('Cap')}
    assert all(caps[n]==0 for n in ('CapEff','CapPrm','CapInh','CapAmb'))
    lock=(BASE/'r/wikidata017.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    assert not WORK.exists(),'Existing experiment preserved; reconcile before retry'
    WORK.mkdir(mode=0o700);KEY=(BASE/'config/api-key').read_text().strip()
    try:
        save('admitted',uid=os.getuid(),caps=caps,netns=os.stat('/proc/self/ns/net').st_ino,benchmarkRun=False)
        conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=10);conn.request('GET','/health');assert conn.getresponse().status==204;conn.close()
        assert api('GET','/v2/sandboxes?limit=100')==[],'Runtime is not empty'
        assert not [row for row in api('GET','/templates') if NAME in row.get('names',[]) or NAME in row.get('aliases',[])],'Existing template must be reconciled'
        assert not (BASE/'config/bench_image_map.json').exists(),'Existing image map preserved'
        save('image_resolution');image,proof=pinned_image();save('image_verified',image=image,imageProof=proof)
        save('template_create_intent')
        allocated=api('POST','/v3/templates',{'name':NAME,'cpuCount':2,'memoryMB':4096})
        sid=allocated['templateID'];bid=allocated['buildID']
        assert re.fullmatch(r'[0-9a-f-]{36}',sid) and re.fullmatch(r'[0-9a-f-]{36}',bid)
        save('template_registered',templateId=sid,buildId=bid)
        save('template_build_intent')
        api('POST','/v2/templates/'+sid+'/builds/'+bid,{'fromImage':image,'steps':[]})
        deadline=time.monotonic()+3600
        while True:
            build=api('GET','/templates/'+sid+'/builds/'+bid+'/status');save('template_building',buildStatus=build)
            if build['status']=='ready':break
            assert build['status'] in ('waiting','building'),'Native template build failed'
            assert time.monotonic()<deadline,'Build deadline exceeded; preserve pending build'
            time.sleep(5)
        row=next(r for r in api('GET','/templates') if r['templateID']==sid)
        assert row['cpuCount']==2 and row['memoryMB']==4096 and row.get('buildStatus','ready')=='ready'
        with (BASE/'config/bench_image_map.json').open('x') as f:json.dump({NAME:sid},f)
        save('template_ready',template=row)
        assert api('GET','/v2/sandboxes?limit=100')==[]
        available=next(int(line.split()[1])*1024 for line in P('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
        assert available>128*2**30,'Insufficient memory reserve'
        result=BASE/'results/wikidata017';result.mkdir(mode=0o700)
        environment=dict(os.environ)
        for name in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','PYTHONPATH','PYTHONHOME'):environment.pop(name,None)
        environment.update(E2B_API_KEY=KEY,E2B_ACCESS_TOKEN='dummy',NO_PROXY='localhost,127.0.0.1',no_proxy='localhost,127.0.0.1',PYTHONNOUSERSITE='1',PYTHONUNBUFFERED='1')
        transport={'uid':os.getuid(),'caps':caps,'netns':os.stat('/proc/self/ns/net').st_ino,'api':'direct Rust 127.0.0.1:18080'}
        (result/'transport.json').write_text(json.dumps(transport)+'\n')
        for label,rounds in [('prewarm100',1),('formal',5)]:
            pool=[]
            for proc in P('/proc').iterdir():
                if not proc.name.isdigit():continue
                try:
                    if proc.stat().st_uid==1002 and (proc/'comm').read_text().strip()=='firecracker' and P(os.readlink(proc/'cwd')).is_relative_to(BASE/'fc'):pool.append(int(proc.name))
                except OSError:pass
            save(label+'_running',rounds=rounds,total=100,batchSize=100,benchmarkRun=True,resultDir=str(result),**{label+'InitialFCCount':len(pool)})
            command=[str(BASE/'sdk/g4-e2b246/bin/python'),'-B',str(BASE/'g4-benchmark_sandbox_lifecycle.py'),
                '--api-url','http://127.0.0.1:18080','--total','100','--batch-size','100','--rounds',str(rounds),
                '--image-map',str(BASE/'config/bench_image_map.json'),'--output-dir',str(result/label)]
            with (result/(label+'.log')).open('xb') as log:
                process=subprocess.run(command,env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=6900)
            assert process.returncode==0,label+' benchmark failed, inspect persisted log'
            summary=json.loads((result/label/'summary.json').read_text());assert summary.get('valid'),label+' summary invalid'
        finished=True
        summaries={label:json.loads((result/label/'summary.json').read_text()) for label in ('prewarm100','formal')}
        inventory=api('GET','/v2/sandboxes?limit=100')
        save('benchmark_finished',benchmarkExitZero=finished,summaries=summaries,finalInventoryCount=len(inventory))
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w:gz') as tar:
            for path in sorted(result.rglob('*')):
                if path.is_file() and path.suffix in ('.json','.jsonl','.csv','.log'):
                    assert path.stat().st_size<8*1024**2
                    tar.add(path,arcname=str(path.relative_to(result)),recursive=False)
        blob=archive.getvalue();assert len(blob)<1200000,'Benchmark archive too large; preserve full local results'
        STATE['archive']={'sha256':hashlib.sha256(blob).hexdigest(),'bytes':len(blob),'base64':base64.b64encode(blob).decode()}
        assert finished and all(s.get('valid') for s in summaries.values()) and not inventory,'Benchmark invalid or cleanup incomplete'
        STATE['success']=True
    except BaseException as error:
        STATE.update(success=False,errorType=type(error).__name__,error=str(error)[:2000]);raise
    finally:
        (WORK/'result.json').write_text(json.dumps(STATE,indent=2)+'\n')
        print('WIKIDATA_RESULT='+json.dumps(STATE,separators=(',',':')),flush=True)
if __name__=='__main__':main()
