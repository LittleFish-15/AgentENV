"""Align runtime ARP thresholds to live X and repeat identical five-round test."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
worker=(H/'wikidata018_worker.py').read_text(encoding='utf-8').replace("BASE/'wikidata018'","BASE/'wikidata023'").replace('wikidata018.lock','wikidata023.lock').replace("BASE/'results/wikidata018'","BASE/'results/wikidata023'")
(H/'wikidata023_worker.py').write_bytes(worker.encode())
s=(H/'Y_retry018.py').read_text(encoding='utf-8')
s=s.replace('import base64,hashlib,io,json,os,pathlib,pwd,signal,subprocess,tarfile,time','import base64,fcntl,hashlib,http.client,io,json,os,pathlib,pwd,re,signal,stat,subprocess,tarfile,time')
s=s.replace('WORKER=None;WORKER_SHA=None','WORKER=None;WORKER_SHA=None\nTARGET=None')
s=s.replace("BASE/'deployment018'","BASE/'deployment023'").replace('wikidata018_worker.py','wikidata023_worker.py').replace('worker018','worker023').replace("BASE/'results/wikidata018'","BASE/'results/wikidata023'").replace('RETRY018_RESULT=','NEIGHBOR023_RESULT=')
s=s.replace("outcome={'parameterChanges':False,'serviceRestarted':False,'templateRebuilt':False,'serverPid':pid}","outcome={'parameterChanges':True,'serviceRestarted':False,'templateRebuilt':False,'serverPid':pid,'persistentFilesModified':False,'comparisonReference':'unchanged low-threshold run018'}")
needle=" def sample():"
helpers=''' def arp_stats():
  raw=read('/proc/net/stat/arp_cache',200000)
  if not raw:return {'available':False}
  lines=raw.splitlines();names=lines[0].split();rows=[[int(x,16) for x in line.split()] for line in lines[1:] if line.strip()]
  assert rows and all(len(row)==len(names) for row in rows)
  return {'available':True,'entries':rows[0][names.index('entries')],'cpuRows':len(rows),
   'counters':{name:sum(row[i] for row in rows) for i,name in enumerate(names) if name!='entries'}}
 def threshold_values():return {str(i):P('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)).read_text().strip() for i in (1,2,3)}
 def empty_inventory():
  for state in ('running','paused'):
   conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=20)
   try:
    conn.request('GET','/v2/sandboxes?limit=1&state='+state,headers={'X-API-Key':key});response=conn.getresponse()
    assert response.status==200 and json.loads(response.read())==[],'Runtime has existing '+state+' sandboxes'
   finally:conn.close()
'''
assert needle in s;s=s.replace(needle,helpers+needle)
s=s.replace("   'sockstat':read(proc/'net/sockstat',2000),'netdev':read(proc/'net/dev',4000)}", "   'sockstat':read(proc/'net/sockstat',2000),'netdev':read(proc/'net/dev',4000),'arp':arp_stats()}")
needle=" try:\n  with (directory/'worker.log')"
preflight=''' try:
  empty_inventory()
  lock_path=BASE/'scripts/.run.lock'
  if lock_path.exists():
   st=lock_path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==1002
  lockfd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
  os.fchown(lockfd,1002,1002);fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  for proc in P('/proc').iterdir():
   if not proc.name.isdigit():continue
   try:
    if proc.stat().st_uid!=1002:continue
    args=(proc/'cmdline').read_bytes().split(b'\\0')
    assert not any(P(a.decode(errors='replace')).name in ('benchmark_sandbox_lifecycle.py','g4-benchmark_sandbox_lifecycle.py') for a in args if a),'Another jwk benchmark is active'
   except (FileNotFoundError,PermissionError,ProcessLookupError):continue
  before=threshold_values();assert before in ({'1':'128','2':'512','3':'1024'},TARGET),'Thresholds changed since reviewed inventory'
  outcome.update(thresholdsBefore=before,thresholdsTarget=TARGET,arpBefore=arp_stats(),startUnix=time.time())
  record=directory/'threshold-change.json';record.write_text(json.dumps({'before':before,'target':TARGET,'persistentFilesModified':False,'applied':False},indent=2)+'\\n');os.chown(record,1002,1002)
  try:
   for i in (3,2,1):P('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)).write_text(TARGET[str(i)]+'\\n')
   assert threshold_values()==TARGET
  except BaseException:
   for i in (1,2,3):P('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)).write_text(before[str(i)]+'\\n')
   raise
  record.write_text(json.dumps({'before':before,'target':TARGET,'persistentFilesModified':False,'applied':True,'restoredAfterBenchmark':False},indent=2)+'\\n')
  probe=subprocess.run(['nsenter','--target',str(pid),'--net','--','ip','-j','-s','ntable','show'],env=env,capture_output=True,text=True,timeout=30)
  assert probe.returncode==0,'Cannot verify threshold visibility in service netns'
  tables=json.loads(probe.stdout);rows=[r for r in tables if r.get('name')=='arp_cache' and 'thresh1' in r]
  assert rows and all([r['thresh1'],r['thresh2'],r['thresh3']]==[int(TARGET[str(i)]) for i in (1,2,3)] for r in rows)
  outcome['runtimeThresholdVerification']={k:rows[0].get(k) for k in ('thresh1','thresh2','thresh3','table_fulls','forced_gc_runs','res_failed','entries')}
  with (directory/'worker.log')'''
assert needle in s;s=s.replace(needle,preflight)
s=s.replace(" finally:\n  archive=io.BytesIO()",''' finally:
  outcome['thresholdsAfter']=threshold_values();outcome['arpAfter']=arp_stats()
  outcome['newThresholdsRetained']=outcome['thresholdsAfter']==TARGET
  kernel=subprocess.run(['journalctl','-k','--since','@'+str(int(outcome.get('startUnix',time.time()))),'--no-pager','-o','short-iso'],env=env,capture_output=True,text=True,timeout=30)
  outcome['neighborKernelLogs']=[line for line in kernel.stdout.splitlines() if re.search(r'(arp_cache|ndisc_cache).*overflow|net_ratelimit',line,re.I)][-100:]
  archive=io.BytesIO()''')
s=s.replace("for name in ('samples.jsonl','worker.log'):","for name in ('samples.jsonl','worker.log','threshold-change.json'):")
s=s.replace("  (directory/'result.json').write_text(json.dumps(outcome,indent=2)+'\\n')", "  (directory/'result.json').write_text(json.dumps(outcome,indent=2)+'\\n');os.chown(directory/'result.json',1002,1002)")
for name,body in [('wikidata023_worker.py',worker),('Y_neigh023.py',s)]:ast.parse(body,feature_version=(3,11));(H/name).write_bytes(body.encode())
print('023 prepared: live-X ARP target only, retained after five-round identical test, ARP/TCP evidence returned')
