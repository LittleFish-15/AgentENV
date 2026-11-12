"""Scoped fault/block/cgroup snapshots and optional kernel profiling for anchor A/B."""
import collections,ctypes,fcntl,hashlib,json,os,pathlib,re,shutil,signal,stat,struct,subprocess,time
P=pathlib.Path;BASE=P('/home/jwk/aenv-y-clean-20261111');UNIT='jwk-aenv-y-clean-20261111.service'
def procstat(raw):
 a=raw.rsplit(')',1)[1].split()
 return {'state':a[0],'minflt':int(a[7]),'majflt':int(a[9]),'utime':int(a[11]),'stime':int(a[12]),'starttime':int(a[19]),'guest_ticks':int(a[40]) if len(a)>40 else None}
class Observer:
 def __init__(self,directory,pid):
  self.directory=P(directory);self.pid=pid;self.cgroup=P('/sys/fs/cgroup/system.slice')/UNIT;self.offset=(BASE/'logs/server.log').stat().st_size;self.start_offset=self.offset
  self.paths={};self.devices={};self.group=None;self.perf=None;self.perf_log=None;self.current_event=None;self.anchor_device=None;self.anchor_pid=None;self.phase_before=None;self.profile={};self.tick=0
  self.samples=(self.directory/'samples.jsonl').open('x');self.stacks=(self.directory/'proc-stacks.jsonl').open('x');self.snapshot_last={};self.block_last={};self.sample_last={}
 def read(self,path,limit=50000):
  try:return P(path).read_text()[:limit]
  except OSError:return None
 def scan(self):
  out={}
  for pid in (self.cgroup/'cgroup.procs').read_text().split():
   path=P('/proc',pid)
   try:
    if path.stat().st_uid!=1002 or (path/'comm').read_text().strip()!='firecracker':continue
    cwd=os.readlink(path/'cwd')
    if not P(cwd).is_relative_to(BASE/'fc'):continue
    out[pid]={'pid':int(pid),'cwd':cwd,**procstat((path/'stat').read_text())}
   except OSError:continue
  return out
 def tail(self):
  path=BASE/'logs/server.log'
  with path.open('rb') as f:f.seek(self.offset);raw=f.read(16*1024**2)
  boundary=raw.rfind(b'\n')
  if boundary<0:return
  self.offset+=boundary+1
  for line in raw[:boundary].splitlines():
   try:d=json.loads(line)
   except ValueError:continue
   fields=d.get('fields') or {};context=(d.get('spans') or [])+[d.get('span') or {}]
   root=next((x for x in context if x.get('sandbox_id')),None)
   if root and fields.get('message')=='using warm firecracker from pool':self.paths[root['sandbox_id']]=fields['pool_work_dir']
   if fields.get('message')=='created or acquired shared read-only ublk device' and re.fullmatch(r'/dev/ublkb\d+',fields.get('path','')):
    self.devices[fields['path']]={'key':fields['key'],'eventTimestamp':d['timestamp'],'dev_id':fields['dev_id']}
 def block(self,names=None):
  out={}
  paths=P('/sys/class/block').glob('ublkb*') if names is None else [P('/sys/class/block')/n for n in names]
  for p in paths:
   try:out[p.name]={'dev':(p/'dev').read_text().strip(),'stat':[int(x) for x in (p/'stat').read_text().split()]}
   except OSError:pass
  return out
 def mapped(self,ids,fc):
  out={};bycwd={r['cwd']:r for r in fc.values()}
  for sid in ids:
   row=bycwd.get(self.paths.get(sid))
   if not row:out[sid]={'available':False};continue
   text=self.read(P('/proc',str(row['pid']),'maps'),2*1024**2) or ''
   devices=sorted(set(re.findall(r'/dev/ublkb\d+',text)))
   out[sid]={'available':True,'pid':row['pid'],'starttime':row['starttime'],'devices':devices,'deviceKeys':{dev:self.devices.get(dev) for dev in devices}}
  return out
 def residency(self,device):
  assert re.fullmatch(r'/dev/ublkb\d+',device)
  node=P(device).stat();assert stat.S_ISBLK(node.st_mode) and node.st_uid==1002
  fd=os.open(device,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW);libc=ctypes.CDLL(None,use_errno=True);address=None
  try:
   size=struct.unpack('Q',fcntl.ioctl(fd,0x80081272,b'\0'*8))[0];assert 0<size<=8*1024**3
   libc.mmap.restype=ctypes.c_void_p;libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_longlong]
   address=libc.mmap(None,size,1,1,fd,0);assert address!=ctypes.c_void_p(-1).value,ctypes.get_errno()
   pages=(size+os.sysconf('SC_PAGE_SIZE')-1)//os.sysconf('SC_PAGE_SIZE');vector=ctypes.create_string_buffer(pages)
   libc.mincore.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
   assert libc.mincore(address,size,vector)==0,ctypes.get_errno()
   return {'bytes':size,'pages':pages,'residentPages':sum(x&1 for x in vector.raw),'rdev':node.st_rdev,'inode':node.st_ino,'method':'read-only mmap+mincore; no page touching'}
  except (OSError,AssertionError) as error:return {'error':type(error).__name__,'detail':str(error)}
  finally:
   if address and address!=ctypes.c_void_p(-1).value:
    libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap(address,size)
   os.close(fd)
 def start_profile(self,group):
  perf=shutil.which('perf');self.profile[group]={'method':'proc-stack-snapshots','perfAvailable':bool(perf)}
  if not perf:return
  self.perf_log=(self.directory/(group+'.perf.log')).open('xb')
  args=[perf,'record','-a','-e','cpu-clock:kH','-G','system.slice/'+UNIT,'-F','49','-g','--call-graph','fp','--clockid','mono','-m','32','-o',str(self.directory/(group+'.perf.data')),'--','sleep','300']
  self.perf=subprocess.Popen(args,stdout=self.perf_log,stderr=subprocess.STDOUT,start_new_session=True)
  time.sleep(.25)
  if self.perf.poll() is None:self.profile[group].update(method='perf-cgroup-kernel-cpu-clock',frequencyHz=49,clock='monotonic')
  else:self.profile[group]['perfStartupExit']=self.perf.returncode;self.perf=None;self.perf_log.close();self.perf_log=None
 def stop_profile(self):
  if self.perf is not None:
   if self.perf.poll() is None:os.killpg(self.perf.pid,signal.SIGINT)
   try:self.perf.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(self.perf.pid,signal.SIGTERM);self.perf.wait(timeout=5)
   self.profile[self.group]['perfExit']=self.perf.returncode;self.perf=None
   self.perf_log.close();self.perf_log=None
   data=self.directory/(self.group+'.perf.data')
   if data.exists():
    with (self.directory/(self.group+'.kernel-stacks.txt')).open('xb') as f:
     r=subprocess.run([shutil.which('perf'),'script','--ns','-i',str(data)],stdout=f,stderr=subprocess.PIPE,timeout=45)
    self.profile[self.group].update(decodeExit=r.returncode,decodeError=r.stderr.decode(errors='replace')[-1000:],rawPerfBytes=data.stat().st_size,rawPerfSha256=hashlib.sha256(data.read_bytes()).hexdigest(),rawPerfPath=str(data))
 def snapshot(self,event):
  self.tail();fc=self.scan();ids=list(event.get('sandboxIds') or [])
  anchor=event.get('anchorId')
  if not anchor and (BASE/'anchor026/state.json').exists():anchor=json.loads((BASE/'anchor026/state.json').read_text()).get('anchorId')
  if anchor:ids.append(anchor)
  mappings=self.mapped(ids,fc)
  blocks=self.block();full=event['phase']=='group' and event['edge']=='before'
  result={'event':event,'unixNs':time.time_ns(),'monotonicNs':time.monotonic_ns(),'snapshotEncoding':'full' if full else 'changed rows plus complete presence lists',
   'fc':{k:v for k,v in fc.items() if full or self.snapshot_last.get(k)!=v},'fcPresent':list(fc),
   'blockDevices':{k:v for k,v in blocks.items() if full or self.block_last.get(k)!=v},'blockPresent':list(blocks),
   'cgroupCpu':self.read(self.cgroup/'cpu.stat'),'mappings':mappings,'resident':{},'clockTicksPerSecond':os.sysconf('SC_CLK_TCK')}
  self.snapshot_last=fc;self.block_last=blocks
  if anchor and event['group']=='B_anchor':
   m=mappings.get(anchor,{});assert m.get('available') and len(m['devices'])==1,'Anchor memory mapping unavailable'
   device=m['devices'][0];expected=str(BASE/'state/snapshot-local-cache/runtime/01a1ca98-128f-7463-b163-78dd06a167d0/memory/image.json')
   assert self.devices.get(device,{}).get('key')==expected,'Anchor mapping is not the shared template memory'
   if self.anchor_device is None:self.anchor_device=device;self.anchor_pid=(m['pid'],m['starttime'])
   assert device==self.anchor_device and (m['pid'],m['starttime'])==self.anchor_pid,'Anchor device/process changed'
   result['anchorRetentionVerified']={'id':anchor,'device':device,'pid':m['pid'],'starttime':m['starttime']}
  if event['phase']=='create':
   # Only query mappings held by active VMs at the barrier; never retain an opener across phases.
   devs={dev for m in mappings.values() if m.get('available') for dev in m['devices']}
   for dev in devs:
    if self.devices.get(dev,{}).get('key','').endswith('/memory/image.json'):result['resident'][dev]=self.residency(dev)
  return result
 def event(self,path):
  event=json.loads(path.read_text());assert event['group'] in ('A_released','B_anchor') and event['phase'] in ('group','create','pause','resume','delete') and event['edge'] in ('before','after')
  self.group=event['group'];self.current_event=event
  if event['phase']=='group' and event['edge']=='before':self.start_profile(self.group)
  value=self.snapshot(event)
  (self.directory/(path.stem+'.snapshot.json')).write_text(json.dumps(value)+'\n')
  if event['phase']=='group' and event['edge']=='after':self.stop_profile();self.current_event=None
 def periodic(self):
  if not self.current_event:return
  self.tick+=1;self.tail();fc=self.scan()
  previous=self.sample_last;changed={k:v for k,v in fc.items() if previous.get(k)!=v};self.sample_last=fc
  self.samples.write(json.dumps({'unixNs':time.time_ns(),'monotonicNs':time.monotonic_ns(),'event':self.current_event,'fcChanged':changed,'fcPresent':list(fc),'trackedBlockStats':self.block([P(k).name for k in self.devices]),'cgroupCpu':self.read(self.cgroup/'cpu.stat')})+'\n');self.samples.flush()
  if self.profile.get(self.group,{}).get('method')!='perf-cgroup-kernel-cpu-clock':
   active=[r for k,r in fc.items() if r['state']=='R' or k in previous and r['starttime']==previous[k]['starttime'] and r['stime']+r['utime']>previous[k]['stime']+previous[k]['utime']]
   for row in active[self.tick%max(1,len(active))::max(1,len(active)//4)][:4]:
    try:
     tids=list(P('/proc',str(row['pid']),'task').iterdir());tids.sort(key=lambda p:('vcpu' not in (self.read(p/'comm') or '').lower(),int(p.name)))
     for task in tids[:3]:
      stack=self.read(task/'stack',8000)
      if stack:self.stacks.write(json.dumps({'unixNs':time.time_ns(),'monotonicNs':time.monotonic_ns(),'pid':row['pid'],'tid':int(task.name),'event':self.current_event,'stack':stack})+'\n')
    except OSError:pass
   self.stacks.flush()
 def close(self):
  self.stop_profile();self.samples.close();self.stacks.close()
  (self.directory/'profile-status.json').write_text(json.dumps(self.profile,indent=2)+'\n')
