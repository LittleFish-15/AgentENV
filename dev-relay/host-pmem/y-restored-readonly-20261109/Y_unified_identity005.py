"""Read-only identity reporting before task validation; never weakens task execution checks."""
import ast,hashlib,importlib.util,json,os,pathlib,time
P=pathlib.Path;ROOT=P('/home/jwk/y-aenv-control');STATE=ROOT/'relay-restored-20261109'
SESSION='y-restored-readonly-20261109-v1';PREFIX='root-entry-v1/'+SESSION
PIN='0a9012252418249dd44c034db362294bff1c5070412d1887a5e3020634794897'
def need(ok,msg):
    if not ok:raise RuntimeError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    need(os.geteuid()==0,'Use the root unified entry');os.umask(0o077)
    entry=STATE/'entry.py';need(entry.resolve()==entry and entry.stat().st_uid==0 and sha(entry.read_bytes())==PIN,'Known installed entry missing or changed')
    spec=importlib.util.spec_from_file_location('trusted_transport',entry);e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
    tokens=json.loads(e.read(STATE/'credentials.json',8192));control=e.API.GitHub(tokens['controlToken']);results=e.API.GitHub(tokens['resultToken'])
    control.private_repo(e.CONTROL,1438089258);results.private_repo(e.RESULTS,1438089386)
    current=e.identity()
    code,head,_=control.request('GET','/repos/'+e.CONTROL+'/git/ref/heads/main?verify='+str(time.time_ns()));need(code==200,'Control revision unavailable')
    revision=head['object']['sha']
    def fetch(path):
        code,raw,_=control.contents(e.CONTROL,path,revision);need(code==200,'Diagnostic control document unavailable');return json.loads(raw)
    plan=fetch(PREFIX+'/entry-diagnostics/005.json')
    need(plan['sessionId']==SESSION and plan['sourceSha256']==sha(P(__file__).read_bytes()),'Diagnostic source pin differs')
    profile=fetch(PREFIX+'/profiles/node-y.json');queue=fetch(PREFIX+'/queues/node-y.json')
    ids=plan['inspectJobIds'];need(isinstance(ids,list) and len(ids)<=8,'Diagnostic job bound differs')
    jobs=[]
    for jobid in ids:
        job=fetch(PREFIX+'/jobs/'+jobid+'.json')
        expected={'schema':1,'sessionId':SESSION,'node':'node-y','identity':current,'rootEntrySha256':PIN}
        differences={k:{'task':job.get(k),'actual':v} for k,v in expected.items() if job.get(k)!=v}
        jobs.append({'jobId':jobid,'jobSha256':sha(e.wire(job)),'differences':differences,
          'authorization_time':{'notBefore':job['notBefore'],'expiresAt':job['expiresAt'],'currentUnix':time.time()},
          'local_state_exists':(STATE/'jobs'/jobid/'state.json').exists(),
          'local_report_exists':(STATE/'jobs'/jobid/'report.json').exists()})
    files=[]
    for file in (ROOT/'root-start.sh',ROOT/'root-start.before-identity005.sh',STATE/'entry.py',ROOT/'relay/entry.py'):
        row={'path':str(file),'exists':file.exists()}
        if file.is_file():
            raw=file.read_bytes();row.update(sha256=sha(raw),uid=file.stat().st_uid)
            if file.suffix=='.py':
                try:
                    tree=ast.parse(raw);row['SESSION']=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='SESSION' for x in n.targets))
                except (SyntaxError,StopIteration,ValueError):row['SESSION']='unavailable'
            else:
                row['entry_path_lines']=[line for line in raw.decode(errors='replace').splitlines() if line.startswith('exec /usr/bin/python3 -I -B /home/jwk/y-aenv-control/')]
        files.append(row)
    report={'schema':1,'diagnostic':'unified-entry-identity005','sessionId':SESSION,'identity':current,
      'entrySha256':PIN,'controlRevision':revision,'profile':profile,'queue':queue,'jobs':jobs,'entry_files':files,
      'capturedUnixNs':time.time_ns(),'serviceActions':[],'taskExecuted':False}
    raw=e.wire(report);path='root-entry-diagnostics-v1/'+SESSION+'/node-y/identity005/'+current['bootId']+'/'+sha(raw)+'.json'
    e.put(results,path,raw)
    print(json.dumps({'status':'IDENTITY_DIAGNOSTIC_UPLOADED','reportPath':path,'differences':{x['jobId']:list(x['differences']) for x in jobs}}),flush=True)
    if plan.get('mode')=='resume':
        need(not any(x['differences'] for x in jobs),'Task binding still differs; diagnostic only')
        need(profile['entrySha256']==PIN and all(profile['identity'][k]==current[k] for k in ('hostname','machineId','kernel','architecture')),'Profile binding differs')
        os.execv('/usr/bin/python3',['python3','-I','-B',str(entry)])
    need(plan.get('mode')=='diagnose','Unknown diagnostic mode')
if __name__=='__main__':main()
