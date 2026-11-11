"""Read-only ARP/neighbor inventory in host, aenv and sampled slot namespaces."""
import hashlib,http.client,json,os,pathlib,re,subprocess
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');UNIT='jwk-aenv-y-clean-20261111.service'
COLLECT=r'''
import collections,json,os,pathlib,subprocess
P=pathlib.Path
def read(path):
 try:return {'text':P(path).read_text()[:100000]}
 except OSError as error:return {'error':type(error).__name__,'errno':error.errno}
def command(args):
 try:
  r=subprocess.run(args,capture_output=True,text=True,timeout=20)
  if r.returncode:return {'code':r.returncode,'stderr':r.stderr[-2000:]}
  return {'code':0,'data':json.loads(r.stdout)}
 except Exception as error:return {'error':type(error).__name__}
result={'netns':os.stat('/proc/self/ns/net').st_ino,'mntns':os.stat('/proc/self/ns/mnt').st_ino,
 'thresholds':{str(i):read('/proc/sys/net/ipv4/neigh/default/gc_thresh'+str(i)) for i in (1,2,3)},
 'arpStats':read('/proc/net/stat/arp_cache'),'ndiscStats':read('/proc/net/stat/ndisc_cache'),
 'netstat':read('/proc/net/netstat'),'snmp':read('/proc/net/snmp')}
tables=command(['ip','-j','-s','ntable','show'])
if tables.get('code')==0:
 rows=tables['data'];main=[r for r in rows if any(k in r for k in ('thresh1','thresh2','thresh3','gc_thresh1','gc_thresh2','gc_thresh3'))]
 result['neighborTables']={'rowCount':len(rows),'thresholdRows':main[:6],'sampleRows':rows[:6]}
else:result['neighborTables']=tables
neighbors=command(['ip','-j','-s','-4','neigh','show'])
if neighbors.get('code')==0:
 rows=neighbors['data'];counts=collections.Counter()
 for row in rows:
  states=row.get('state',[]);states=[states] if isinstance(states,str) else states
  for state in states:counts[state]+=1
 result['neighbors']={'count':len(rows),'states':dict(counts),'failedOrIncompleteSample':[r for r in rows if any(s in ('FAILED','INCOMPLETE') for s in (r.get('state',[]) if isinstance(r.get('state',[]),list) else [r.get('state')]))][:15]}
else:result['neighbors']=neighbors
links=command(['ip','-j','link','show'])
if links.get('code')==0:
 rows=links['data'];result['interfaces']={'count':len(rows),'aenvCount':sum(r['ifname'].startswith('aenv-') for r in rows),'sampleNames':[r['ifname'] for r in rows[:12]]}
else:result['interfaces']=links
slots=P('/home/jwk/aenv-y-clean-20261111/r/netns')
try:
 paths=sorted(slots.iterdir());result['slotNamespaces']={'count':len(paths),'samplePaths':[str(p) for p in paths[:2]]}
except OSError as error:result['slotNamespaces']={'error':type(error).__name__}
print(json.dumps(result))
'''
def main():
 assert os.getuid()==os.geteuid()==0
 previous=json.loads((BASE/'deployment014/result.json').read_text());pid=previous['serverPid']
 props=dict(line.split('=',1) for line in subprocess.check_output(['systemctl','show',UNIT,'-p','MainPID','-p','ActiveState'],text=True).splitlines())
 assert props['ActiveState']=='active' and int(props['MainPID'])==pid
 inputs=json.loads((BASE/'runtime-prep005/result.json').read_text())
 with P('/proc',str(pid),'exe').open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==inputs['native_inputs']['server']['sha256']
 env={'PATH':'/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin','LANG':'C.UTF-8'}
 def collect(prefix):
  r=subprocess.run([*prefix,'/usr/bin/python3','-I','-B','-c',COLLECT],env=env,capture_output=True,text=True,timeout=90)
  assert r.returncode==0,r.stderr[-2000:];return json.loads(r.stdout)
 result={'action':'READ_ONLY_NEIGHBOR_DIAGNOSIS','mutations':False,'serverPid':pid,'host':collect([])}
 result['service']=collect(['nsenter','--target',str(pid),'--mount','--net','--'])
 result['slots']=[]
 for path in result['service'].get('slotNamespaces',{}).get('samplePaths',[]):
  assert path.startswith(str(BASE/'r/netns')+'/')
  r=subprocess.run(['nsenter','--target',str(pid),'--mount','--net=/proc/'+str(pid)+'/root'+path,'--','/usr/bin/python3','-I','-B','-c',COLLECT],env=env,capture_output=True,text=True,timeout=90)
  result['slots'].append({'path':path,'result':json.loads(r.stdout) if r.returncode==0 else {'code':r.returncode,'stderr':r.stderr[-2000:]}})
 kernel=subprocess.run(['journalctl','-k','--since','2 hours ago','--no-pager','-o','short-iso'],env=env,capture_output=True,text=True,timeout=30)
 result['neighborKernelLogs']={'journalExitCode':kernel.returncode,'matches':[line for line in kernel.stdout.splitlines() if re.search(r'(arp_cache|ndisc_cache).*overflow|neigh.*(overflow|table.*full)|net_ratelimit',line,re.I)][-100:]}
 key=(BASE/'config/api-key').read_text().strip();result['inventory']={}
 for state in ('running','paused'):
  conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=20)
  try:
   conn.request('GET','/v2/sandboxes?limit=1&state='+state,headers={'X-API-Key':key});response=conn.getresponse()
   result['inventory'][state]={'status':response.status,'hasEntries':bool(json.loads(response.read())) if response.status==200 else None}
  finally:conn.close()
 print(json.dumps(result,ensure_ascii=False),flush=True)
if __name__=='__main__':main()
