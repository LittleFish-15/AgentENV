"""Bounded read-only G7 prerequisites and exact orphan receipt state. No mutation."""
import hashlib,http.client,json,os,pathlib,pwd,shutil,subprocess,tomllib
P=pathlib.Path
B=P('/home/jwk/aenv-y-clean-20261111')
S=B.parent/'y-aenv-control/relay-debian-clean-20261111'
U='jwk-aenv-y-clean-20261111.service'
OLD='y-debian-anchor-memory-ab-20261112-026-node-y'
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 assert os.getuid()==os.geteuid()==0
 props=dict(x.split('=',1) for x in subprocess.check_output(['systemctl','show',U,'-p','MainPID','-p','ActiveState','-p','FragmentPath','-p','DropInPaths','-p','ControlGroup'],text=True).splitlines())
 pid=int(props['MainPID']);assert props['ActiveState']=='active' and pid>1
 proc=P('/proc',str(pid));env=dict(x.split('=',1) for x in (proc/'environ').read_text().split('\0') if '=' in x)
 report={'group':'G7','action':'READ_ONLY_PREFLIGHT','benchmarkExecuted':False,'service':props,
  'bootId':P('/proc/sys/kernel/random/boot_id').read_text().strip(),'uid':pwd.getpwnam('jwk').pw_uid,
  'serverSha256':digest(proc/'exe'),'configSha256':digest(B/'config/runtime005.toml'),
  'logging':{k:env.get(k) for k in ('AENV_LOG_FORMAT','AENV_LOG_SPAN_EVENTS','RUST_LOG')},
  'thresholds':{str(i):P('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)).read_text().strip() for i in (1,2,3)},
  'entrySha256':digest(S/'entry.py'),'rootStartSha256':digest(S.parent/'root-start.sh')}
 # Return only configuration keys relevant to the pool/resources, never arbitrary values.
 cfg=tomllib.loads((B/'config/runtime005.toml').read_text());selected={}
 def walk(x,prefix=''):
  for k,v in x.items():
   name=prefix+k
   if isinstance(v,dict):walk(v,name+'.')
   elif any(s in k.lower() for s in ('water','pool','vcpu','memory','poll')):selected[name]=v
 walk(cfg);report['poolResourceConfiguration']=selected
 files={}
 for name in ('state.json','report.json','task.py','stdout.log','stderr.log'):
  p=S/'jobs'/OLD/name
  if p.is_file():
   files[name]={'bytes':p.stat().st_size,'sha256':digest(p)}
   if name in ('state.json','report.json'):files[name]['value']=json.loads(p.read_text())
 report['old026']=files
 result=json.loads((B/'diagnostic026/result.json').read_text());worker=json.loads((B/'anchor026/result.json').read_text())
 report['saved026']={'success':result['success'],'workerExitCode':result['workerExitCode'],
  'archiveSha256':result['archive']['sha256'],'workerSuccess':worker['success'],'finalInventoryCount':worker['finalInventoryCount']}
 report['relatedOldProcesses']=[];fc=[];bench=[]
 for p in P('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   args=(p/'cmdline').read_bytes().decode(errors='replace').split('\0');comm=(p/'comm').read_text().strip()
   if any(a in (str(S/'jobs'/OLD/'task.py'),str(B/'diagnostic026/anchor026_worker.py')) for a in args):report['relatedOldProcesses'].append(int(p.name))
   if p.stat().st_uid==1002 and comm=='firecracker' and P(os.readlink(p/'cwd')).is_relative_to(B/'fc'):fc.append(int(p.name))
   if p.stat().st_uid==1002 and any(P(a).name in ('benchmark_sandbox_lifecycle.py','g4-benchmark_sandbox_lifecycle.py','benchmark_hook026.py','lifecycle-go') for a in args if a):bench.append(int(p.name))
  except OSError:pass
 report['fcCount']=len(fc);report['activeBenchmarkPids']=bench
 report['goCandidates']=[]
 for path in dict.fromkeys(filter(None,[shutil.which('go'),'/usr/local/go/bin/go','/home/jwk/go/bin/go',str(B/'sdk/go/bin/go')])):
  p=P(path)
  if p.is_file():
   r=subprocess.run([str(p),'version'],capture_output=True,text=True,timeout=15,env={'PATH':'/usr/bin:/bin','GOTOOLCHAIN':'local'})
   report['goCandidates'].append({'path':str(p),'sha256':digest(p),'version':r.stdout.strip(),'exitCode':r.returncode})
 report['perfPath']=shutil.which('perf');report['inventory']={}
 key=(B/'config/api-key').read_text().strip()
 for state in ('running','paused'):
  c=http.client.HTTPConnection('127.0.0.1',18080,timeout=20)
  try:
   c.request('GET','/v2/sandboxes?limit=100&state='+state,headers={'X-API-Key':key});r=c.getresponse();raw=r.read(1024**2)
   assert r.status==200
   report['inventory'][state]=len(json.loads(raw))
  finally:c.close()
 text=json.dumps(report,separators=(',',':'));assert len(text.encode())<64000 and key not in text
 print(text,flush=True)
if __name__=='__main__':main()
