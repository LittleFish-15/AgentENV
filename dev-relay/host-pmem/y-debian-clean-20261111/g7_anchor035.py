"""One independently tagged running anchor, with ownership-checked cleanup."""
class G7Anchor:
 def __init__(self,directory,template,key,mode):
  self.directory=directory;self.template=template;self.key=key;self.mode=mode;self.id=None;self.intent=False;self.fc=None
  self.metadata={'g7_anchor_run':'g7-anchor035-'+uuid.uuid4().hex,'g7_anchor_role':'template-memory-holder'}
  self.checkpoints=[];self.heartbeats=0;self.cleaned=False;self.persist()
 def persist(self):
  save(self.directory/'anchor-state.json',{'id':self.id,'intent':self.intent,'metadata':self.metadata,'fc':self.fc,'checkpoints':self.checkpoints,'heartbeats':self.heartbeats,'cleaned':self.cleaned})
 def request(self,method,path,body=None,allow404=False):
  conn=http.client.HTTPConnection('127.0.0.1',18080,timeout=120)
  try:
   conn.request(method,path,body=json.dumps(body) if body is not None else None,headers={'X-API-Key':self.key,'Content-Type':'application/json'})
   r=conn.getresponse();raw=r.read(4*1024**2)
   if allow404 and r.status==404:return None
   assert 200<=r.status<300,'Anchor '+method+' '+path+' HTTP '+str(r.status)
   return json.loads(raw) if raw else None
  finally:conn.close()
 def inventory(self):
  return sum((self.request('GET','/v2/sandboxes?limit=100&state='+s) for s in ('running','paused')),[])
 def inventory_ok(self):
  rows=self.inventory();assert len(rows)==1 and self.id is not None,'Expected only the known running anchor'
  row=rows[0];assert (row.get('sandboxID') or row.get('sandboxId'))==self.id and row['metadata']==self.metadata and row['state']=='running'
  return True
 def mappings(self,pid):
  proc=P('/proc',str(pid));text=(proc/'maps').read_text();devices=sorted(set(re.findall(r'/dev/ublkb\d+',text)));assert devices,'Anchor memory has no ublk mapping'
  return [{'path':d,'rdev':(proc/'root'/d.lstrip('/')).stat().st_rdev,'inode':(proc/'root'/d.lstrip('/')).stat().st_ino} for d in devices]
 def create(self):
  assert self.inventory()==[];self.intent=True;self.persist()
  row=self.request('POST','/sandboxes',{'templateID':self.template,'timeout':86400,'secure':True,'allow_internet_access':True,'envVars':{},'metadata':self.metadata})
  self.id=row.get('sandboxID') or row.get('sandboxId');assert self.id;self.persist();self.inventory_ok()
  import socket
  running=[]
  for p in P('/proc').iterdir():
   if not p.name.isdigit():continue
   try:
    if p.stat().st_uid!=1002 or (p/'comm').read_text().strip()!='firecracker' or not P(os.readlink(p/'cwd')).is_relative_to(B/'fc'):continue
    args=(p/'cmdline').read_bytes().decode().strip('\0').split('\0');name=args[args.index('--api-sock')+1];path=name if name.startswith('/') else str(p/'cwd'/name)
    sock=socket.socket(socket.AF_UNIX);sock.settimeout(.3);conn=http.client.HTTPConnection('localhost',timeout=.3);conn.sock=sock
    try:
     sock.connect(path);conn.request('GET','/');response=conn.getresponse();state=json.loads(response.read())['state']
     if state=='Running':running.append(int(p.name))
    finally:conn.close()
   except (OSError,ValueError,IndexError,KeyError):continue
  assert len(running)==1,'Cannot identify exactly one anchor FC'
  pid=running[0];start=P('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]
  self.fc={'pid':pid,'startTicks':start,'memoryDevices':self.mappings(pid)};self.checkpoint('created')
 def verify(self):
  assert self.fc is not None
  pid=self.fc['pid'];assert P('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]==self.fc['startTicks'],'Anchor PID changed'
  assert self.mappings(pid)==self.fc['memoryDevices'],'Anchor template memory device changed'
  self.heartbeats+=1
 def checkpoint(self,name):
  self.inventory_ok();self.verify();self.checkpoints.append({'name':name,'monotonicNs':time.monotonic_ns()});self.persist()
 def cleanup(self):
  if self.cleaned:return
  if self.intent and not self.id:
   matches=[r for r in self.inventory() if r.get('metadata')==self.metadata];assert len(matches)<=1,'Ambiguous lost anchor response'
   if matches:self.id=matches[0].get('sandboxID') or matches[0].get('sandboxId');self.persist()
  if self.id:
   info=self.request('GET','/sandboxes/'+self.id,allow404=True)
   if info is not None:
    assert info['metadata']==self.metadata and info['templateID']==self.template,'Anchor cleanup ownership mismatch'
    self.request('DELETE','/sandboxes/'+self.id,allow404=True)
   assert self.request('GET','/sandboxes/'+self.id,allow404=True) is None,'Anchor deletion unconfirmed'
  self.cleaned=True;self.persist()
 def cleanup_benchmark_runs(self,tags):
  deleted=[]
  for _ in range(6):
   rows=[r for r in self.inventory() if r.get('metadata',{}).get('lifecycle_benchmark_run') in tags]
   if not rows:return deleted
   for row in rows:
    sid=row.get('sandboxID') or row.get('sandboxId');assert sid and sid!=self.id
    current=self.request('GET','/sandboxes/'+sid,allow404=True)
    if current is None:continue
    assert current.get('metadata',{}).get('lifecycle_benchmark_run') in tags and current['templateID']==self.template,'Benchmark cleanup ownership differs'
    self.request('DELETE','/sandboxes/'+sid,allow404=True);deleted.append(sid)
  raise RuntimeError('Owned benchmark cleanup exceeded bounded passes')

def g7_anchor_poll_gate(logs,operations):
 roots={'create_sandbox':'create','resume_sandbox':'resume'}
 selected={(r['sandbox_id'],r['phase']) for r in operations if r['round']==1 and r['status']=='ok' and r['phase'] in ('create','resume')}
 values={'create':[],'resume':[]}
 def milliseconds(value):
  match=re.fullmatch(r'([\d.]+)(ns|µs|μs|us|ms|s)',value);assert match,value
  return float(match[1])*{'ns':1e-6,'µs':.001,'μs':.001,'us':.001,'ms':1,'s':1000}[match[2]]
 for line in logs.splitlines():
  row=json.loads(line);fields=row.get('fields') or {};span=row.get('span') or {};context=(row.get('spans') or [])+[span]
  root=next((s for s in context if s.get('name') in roots and s.get('sandbox_id')),None)
  if root is None:continue
  phase=roots[root['name']]
  if (root['sandbox_id'],phase) not in selected:continue
  if row.get('target')=='agentenv::sandbox::envd' and span.get('name')=='wait_for_ready' and fields.get('message')=='close':values[phase].append(milliseconds(fields['time.busy'])+milliseconds(fields['time.idle']))
 assert all(len(values[p])==100 for p in values),'Incomplete target envd poll coverage'
 result={p:{'n':len(v),'meanMs':sum(v)/len(v),'maxMs':max(v)} for p,v in values.items()}
 result['createMeanLimitMs']=20;result['passed']=result['create']['meanMs']<=20
 return result
