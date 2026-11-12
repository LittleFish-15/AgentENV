"""A released-template control, then B running-anchor retention, same benchmark."""
import fcntl,http.client,json,os,pathlib,pwd,signal,socket,subprocess,time,uuid
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');WORK=BASE/'anchor026';CONTROL=WORK/'control';STATE={};KEY=None;STOP=False
def interrupt(signum,frame):
 global STOP
 STOP=True;STATE['interruptRequested']=True
def save(phase,**values):
 STATE.update(phase=phase,unixNs=time.time_ns(),**values);temp=WORK/'state.tmp';temp.write_text(json.dumps(STATE,indent=2)+'\n');temp.replace(WORK/'state.json');print('ANCHOR_PHASE='+phase,flush=True)
def api(method,path,body=None,allow404=False):
 c=http.client.HTTPConnection('127.0.0.1',18080,timeout=120)
 try:
  c.request(method,path,body=json.dumps(body) if body is not None else None,headers={'X-API-Key':KEY,'Content-Type':'application/json'})
  r=c.getresponse();raw=r.read(4*1024**2)
  if allow404 and r.status==404:return None
  assert 200<=r.status<300,'API '+method+' '+path+' HTTP '+str(r.status)
  return json.loads(raw) if raw else None
 finally:c.close()
def inventory():
 rows=[]
 for state in ('running','paused'):rows+=api('GET','/v2/sandboxes?limit=100&state='+state)
 return rows
def rid(row):return row.get('sandboxID') or row.get('sandboxId') or row.get('sandbox_id')
def group_event(group,edge):
 name=group+'-'+('0000' if edge=='before' else '9999');path=CONTROL/(name+'.json')
 path.write_text(json.dumps({'group':group,'phase':'group','edge':edge,'anchorId':STATE.get('anchorId'),'unixNs':time.time_ns(),'monotonicNs':time.monotonic_ns()})+'\n')
 deadline=time.monotonic()+120
 while not path.with_suffix('.ack').exists():assert not STOP and time.monotonic()<deadline,'Group observer interrupted/timed out';time.sleep(.05)
 assert json.loads(path.with_suffix('.ack').read_text())['ok']
def stable_pool(anchor):
 last=set();stable=0;deadline=time.monotonic()+180
 while time.monotonic()<deadline:
  assert not STOP,'Pool wait interrupted'
  current=set()
  for path in P('/proc').iterdir():
   if not path.name.isdigit():continue
   try:
    if path.stat().st_uid==1002 and (path/'comm').read_text().strip()=='firecracker' and P(os.readlink(path/'cwd')).is_relative_to(BASE/'fc'):current.add(int(path.name))
   except OSError:pass
  stable=stable+1 if current==last and len(current)>=512 else 0;last=current
  if stable>=5:break
  time.sleep(1)
 assert stable>=5,'Warm pool failed stability; no forcing of configured pool'
 counts={}
 for pid in sorted(last):
  proc=P('/proc',str(pid));args=(proc/'cmdline').read_bytes().decode().strip('\0').split('\0');name=args[args.index('--api-sock')+1]
  path=name if name.startswith('/') else str(proc/'cwd'/name)
  s=socket.socket(socket.AF_UNIX);s.settimeout(.5);c=http.client.HTTPConnection('localhost',timeout=.5);c.sock=s
  try:s.connect(path);c.request('GET','/');r=c.getresponse();assert r.status==200;state=json.loads(r.read())['state'];counts[state]=counts.get(state,0)+1
  finally:c.close()
 assert counts.get('Not started',0)>=512 and counts.get('Running',0)==(1 if anchor else 0) and sum(counts.values())==len(last)
 return {'processCount':len(last),'states':counts,'stableSecondsAtLeast':5}
def main():
 global KEY
 signal.signal(signal.SIGTERM,interrupt);signal.signal(signal.SIGINT,interrupt)
 assert os.getuid()==os.geteuid()==1002;assert not WORK.exists();WORK.mkdir(mode=0o700);CONTROL.mkdir(mode=0o700)
 KEY=(BASE/'config/api-key').read_text().strip();experiment='anchor026-'+uuid.uuid4().hex
 token={'anchor_experiment_run':experiment,'anchor_role':'template-mem-holder'};anchor_id=None;intent=False
 result=BASE/'results/anchor026';result.mkdir(mode=0o700)
 env=dict(os.environ)
 for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','PYTHONPATH','PYTHONHOME'):env.pop(k,None)
 env.update(E2B_API_KEY=KEY,E2B_ACCESS_TOKEN='dummy',NO_PROXY='localhost,127.0.0.1',no_proxy='localhost,127.0.0.1',PYTHONNOUSERSITE='1',PYTHONUNBUFFERED='1')
 try:
  assert inventory()==[]
  sid=json.loads((BASE/'wikidata017/result.json').read_text())['templateId'];STATE.update(experiment=experiment,templateId=sid,anchorMetadata=token,groups={})
  row=next(x for x in api('GET','/templates') if x['templateID']==sid);assert row['buildStatus']=='ready' and row['cpuCount']==2 and row['memoryMB']==4096
  for group in ('A_released','B_anchor'):
   assert not STOP,'Experiment interrupted'
   if group=='B_anchor':
    save('anchor_create_intent');intent=True
    created=api('POST','/sandboxes',{'templateID':sid,'timeout':86400,'secure':True,'allow_internet_access':True,'envVars':{},'metadata':token})
    anchor_id=rid(created);assert anchor_id;STATE['anchorId']=anchor_id;save('anchor_created')
    info=api('GET','/sandboxes/'+anchor_id);assert info['metadata']==token and info['templateID']==sid
    STATE['anchorInfo']={k:info.get(k) for k in ('sandboxID','templateID','state','cpuCount','memoryMB','metadata')}
   rows=inventory();assert len(rows)==(1 if anchor_id else 0) and (not anchor_id or rid(rows[0])==anchor_id and rows[0]['state']=='running')
   pool=stable_pool(bool(anchor_id));STATE['groups'][group]={'poolBefore':pool};save(group+'_ready')
   group_event(group,'before');env['ANCHOR_GROUP026']=group
   args=[str(BASE/'sdk/g4-e2b246/bin/python'),'-B',str(BASE/'diagnostic026/benchmark_hook026.py'),'--api-url','http://127.0.0.1:18080','--total','100','--batch-size','100','--rounds','1','--image-map',str(BASE/'config/bench_image_map.json'),'--output-dir',str(result/group)]
   with (result/(group+'.log')).open('xb') as log:run=subprocess.run(args,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=3600)
   summary=json.loads((result/group/'summary.json').read_text());STATE['groups'][group].update(exitCode=run.returncode,summary=summary);save(group+'_finished')
   group_event(group,'after')
   assert run.returncode==0 and summary['valid'] and not summary['remaining_sandboxes'],'Comparison group failed; preserve state'
  STATE['success']=True
 except BaseException as error:STATE.update(success=False,errorType=type(error).__name__,error=str(error)[:2000]);raise
 finally:
  try:
   if intent and not anchor_id:
    matches=[x for x in inventory() if x.get('metadata')==token];assert len(matches)<=1,'Ambiguous anchor creation; preserve for review'
    if matches:anchor_id=rid(matches[0]);STATE['anchorId']=anchor_id
   if anchor_id:
    info=api('GET','/sandboxes/'+anchor_id,allow404=True)
    if info is not None:
     assert info['metadata']==token,'Anchor ownership differs; preserve'
     api('DELETE','/sandboxes/'+anchor_id,allow404=True)
    STATE['anchorCleaned']=True
   STATE['finalInventoryCount']=len(inventory())
  except BaseException as error:STATE.update(success=False,cleanupError=type(error).__name__+': '+str(error)[:1000])
  (WORK/'result.json').write_text(json.dumps(STATE,indent=2)+'\n');print('ANCHOR026_RESULT='+json.dumps(STATE,separators=(',',':')),flush=True)
  assert STATE.get('success') and STATE.get('finalInventoryCount')==0,'Experiment or cleanup incomplete'
if __name__=='__main__':main()
