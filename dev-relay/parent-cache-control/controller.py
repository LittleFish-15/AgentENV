"""Four groups of parent snapshot -> two private children. No target auto-access."""
import argparse,base64,concurrent.futures,ctypes,hashlib,http.client,json,os,re,select,shutil,signal,socket,stat,struct,subprocess,sys,time,types,uuid,zlib
from pathlib import Path

ROOT=Path('/home/jwk/agent')
STAGE=ROOT/'r/pcc-parent-v1'
UNIT='jwk-pcc-node-a-v1.service'
RAM=256*1024**2
LOWER=64*1024**2
GROUPS=[('B0','block',False),('D0','pmem',False),('B1','block',True),('D1','pmem',True)]
PINS={'lower':('a13c02fc90b1719c07e58f6266190b30f2d084664bf9a704c0a11523c3808f52',67108864),
 'kernel':('04b12a7409b60c63bc807148826969d30ecb4d93a88ffc7690c22bcc06676752',17123840),
 'tools':('21ecf473cb91f0168005c701e89fd1500f54221024d5159f9a44bb5eb4f0a711',67108864),
 'upper':('8dd9f581dd05523ee444a81eb396a21c48008b8cc8d4b191a4cf76052981e81b',67108864),
 'firecracker':('4954397edf0b849b87ef114d86897f41f475b2a98a0338bcb6c4abdef74197e7',7695920)}
PAYLOAD={}
MODULES={}
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def unpack(name):
 r=PAYLOAD[name];b=zlib.decompress(base64.b85decode(r['z85']));need(len(b)==r['bytes'] and hashlib.sha256(b).hexdigest()==r['sha256'],'Payload mismatch');return b
def helper(name):
 if name not in MODULES:
  m=types.ModuleType(name);m.__file__=str(STAGE/(name+'.py'));exec(compile(unpack(name),m.__file__,'exec'),m.__dict__);MODULES[name]=m
 return MODULES[name]
def sha_file(p):
 p=Path(p);s=owned(p);h=hashlib.sha256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1024**2),b''):h.update(chunk)
 need(stamp(s)==stamp(p.stat()),'File changed during hash');return h.hexdigest()
def stamp(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def owned(p,limit=512*1024**2):
 p=Path(p);need(p.is_absolute() and p.is_relative_to(ROOT) and p.resolve(strict=True)==p,'Path outside namespace or redirected')
 s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_uid==1204 and 0<=s.st_size<=limit,'Unexpected file metadata');return s
def read_json(p):
 s=owned(p,32*1024**2);b=Path(p).read_bytes();need(stamp(s)==stamp(Path(p).stat()),'JSON changed');return json.loads(b)
def write_json(p,value):
 p=Path(p);need(p.parent.resolve(strict=True)==p.parent and p.is_relative_to(STAGE),'Output path differs')
 if p.exists():owned(p)
 tmp=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
 with tmp.open('xb') as f:f.write((json.dumps(value,indent=2)+'\n').encode());f.flush();os.fsync(f.fileno())
 os.chmod(tmp,0o600);os.replace(tmp,p)
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def ticks(pid):return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]
def phase(text):print('PHASE='+text,flush=True)
def check_cache(event,mode,reads,hot):
 facts=event['facts'];need(facts['readCount']==reads,'Unexpected target read before barrier')
 for name in ('lower','visible'):
  r=facts[name];need(r['bytes']==8*1024**2 and r['dax']==(mode=='pmem') and r['fileDataReadByCheck'] is False,'Target/DAX/check contract differs')
  if mode=='block':
   need(r['ordinaryPageCacheApplicable'] is True and r['totalPages']*r['pageSize']==8*1024**2,'Invalid mincore coverage')
   need(r['residentPages']==(r['totalPages'] if hot else 0),'Parent/child cache condition is not exact '+('hot' if hot else 'cold'))
  else:need(r['ordinaryPageCacheApplicable'] is False and 'residentPages' not in r,'DAX mincore is not ordinary cache evidence')
 return True
def check_read(event,expected,count):
 r=event.get('read',{});need(event.get('command')=='READ' and r and r['bytes']==8*1024**2 and r['sha256']==expected and r['readCount']==count,'Read result differs')
def check_ram_maps(text,path,info):
 lines=[line.split() for line in text.splitlines() if line.endswith(' '+str(path))]
 need(lines and all(int(f[4])==info.st_ino and f[1].endswith('p') and
      tuple(int(x,16) for x in f[3].split(':'))==(os.major(info.st_dev),os.minor(info.st_dev)) for f in lines),
      'RAM base device/inode/private view mismatch')
def file_state(p):
 obs=helper('observer');p=Path(p);s=owned(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:resident=obs.resident_pages(fd,s.st_size,os.sysconf('SC_PAGE_SIZE'))
 finally:os.close(fd)
 need(stamp(s)==stamp(p.stat()),'Observed file changed')
 return {'path':str(p),'device':s.st_dev,'inode':s.st_ino,'logicalBytes':s.st_size,'allocatedBytes':s.st_blocks*512,'residentBytes':resident,'contentReadBySampling':False}
def sum_fields(maps):
 keys=['Rss','Pss','Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty','Anonymous','Swap']
 return {k:sum(m['bytes'][k] for m in maps) if maps and all(k in m['bytes'] for m in maps) else None for k in keys}
def pmem_maps(text,lower):
 s=owned(lower);out=[];current=None
 for line in text.splitlines():
  m=re.match(r'^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+):([0-9a-f]+)\s+(\d+)\s*(.*)$',line)
  if m:
   current=None
   if m[8]==str(lower):
    need(int(m[7])==s.st_ino and int(m[5],16)==os.major(s.st_dev) and int(m[6],16)==os.minor(s.st_dev),'PMEM inode identity differs')
    need(m[3]=='r--s' and int(m[4],16)==0,'PMEM not readonly/shared offset0')
    current={'start':int(m[1],16),'end':int(m[2],16),'inode':s.st_ino,'device':s.st_dev,'offset':0,'permissions':m[3],'bytes':{}};out.append(current)
  elif current:
   kv=re.fullmatch(r'(\w+):\s+(\d+) kB',line)
   if kv:current['bytes'][kv[1]]=int(kv[2])*1024
 return out

class Machine:
 def __init__(self,run,folder,role,mode,ram=None):
  self.run=run;self.folder=folder;self.role=role;self.mode=mode;self.ram=ram
  folder.mkdir(mode=0o700);self.pid=None;self.pidfd=None;self.stdin=None;self.log_cursor=0;self.exit=None
  self.record={'role':role,'mode':mode,'directory':str(folder),'phase':'spawn_intent','pid':None,'ticks':None,'exitConfirmed':False}
  run.state['machines'].append(self.record);run.persist()
 def api(self,method,route,body=None,timeout=45):
  need(self.pid is not None and ticks(self.pid)==self.record['ticks'],'FC identity changed')
  sock=socket.socket(socket.AF_UNIX);sock.settimeout(timeout);sock.connect(str(self.folder/'fc.sock'))
  pid,uid,_=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(pid==self.pid and uid==1204,'FC API peer mismatch')
  conn=http.client.HTTPConnection('localhost',timeout=timeout);conn.sock=sock
  intent={'method':method,'route':route,'phase':'intent','timeNs':time.time_ns()}
  self.record.setdefault('api',[]).append(intent);self.run.persist()
  if route in ('/snapshot/create','/snapshot/load'):phase(self.role+':'+route+':begin')
  try:
   conn.request(method,route,json.dumps(body) if body is not None else None,{'Content-Type':'application/json'})
   res=conn.getresponse();raw=res.read(2*1024**2);intent.update(status=res.status,phase='acknowledged');self.run.persist()
   if route in ('/snapshot/create','/snapshot/load'):phase(self.role+':'+route+':http'+str(res.status))
   need(res.status in (200,204),'FC API '+route+' failed '+str(res.status)+': '+raw.decode(errors='replace')[:400])
   return json.loads(raw) if raw else None
  finally:conn.close()
 def start(self):
  lower=Path(self.run.cfg['inputs']['lower']['path']);fd=os.open(lower,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  ls=os.fstat(fd);self.record['freshLowerFDIdentity']={'device':ls.st_dev,'inode':ls.st_ino,'bytes':ls.st_size}
  readfd,writefd=os.pipe();out=os.open(self.folder/'serial.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);err=os.open(self.folder/'stderr.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  descriptor='aenv-pmem-fd:v5:'+PINS['lower'][0]+':'+str(LOWER)+':hostfile:64'
  if self.mode=='pmem':write_json(self.folder/'aenv-pmem-restore.json',{'version':1,'paths':[descriptor]})
  args=[self.run.cfg['inputs']['firecracker']['path'],'--api-sock','fc.sock','--id','pcc_'+uuid.uuid4().hex[:12]]
  env=dict(os.environ)
  for key in ('LD_PRELOAD','LD_AUDIT','GLIBC_TUNABLES'):env.pop(key,None)
  env['GLIBC_TUNABLES']='glibc.pthread.rseq=0'
  # cwd is provided by a tiny exec-only helper; the inherited data FD is freshly
  # opened per FC. Slot64 is not borrowed from an exited parent process.
  launch=['/usr/bin/python3','-I','-B','-c','import os,sys; os.chdir(sys.argv[1]); os.execve(sys.argv[2],sys.argv[2:],os.environ)',str(self.folder),*args]
  actions=[(os.POSIX_SPAWN_DUP2,fd,64),(os.POSIX_SPAWN_DUP2,readfd,0),(os.POSIX_SPAWN_DUP2,out,1),(os.POSIX_SPAWN_DUP2,err,2)]
  try:self.pid=os.posix_spawn(launch[0],launch,env,file_actions=actions,setsid=True)
  finally:
   for f in (fd,readfd,out,err):os.close(f)
  self.stdin=writefd;self.record.update(pid=self.pid,ticks=ticks(self.pid),phase='spawned');self.run.persist()
  self.pidfd=os.pidfd_open(self.pid)
  deadline=time.monotonic()+20
  while not (self.folder/'fc.sock').exists():
   need(not self.poll() and time.monotonic()<deadline,'FC API did not appear');time.sleep(.1)
  if self.ram:
   self.api('PUT','/snapshot/load',{'snapshot_path':str(self.ram.parent/'state.bin'),'mem_backend':{'backend_type':'File','backend_path':str(self.ram)},'resume_vm':False},120)
   self.api('PATCH','/drives/upper',{'drive_id':'upper','path_on_host':str(self.folder/'upper.ext4')})
   self.record['restoredFrom']=self.run.identity(self.ram)
   self.verify_mapping()
   self.api('PATCH','/vm',{'state':'Resumed'})
  else:
   cfg=self.run.cfg
   self.api('PUT','/machine-config',{'vcpu_count':1,'mem_size_mib':256,'smt':False,'track_dirty_pages':False})
   self.api('PUT','/boot-source',{'kernel_image_path':cfg['inputs']['kernel']['path'],'boot_args':'console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/agentenv/parent-init.sh pcc_mode='+self.mode+' pcc_sha='+cfg['expectedCommonSha256']})
   for id,path,root,ro in [('tools',STAGE/'tools.ext4',True,True),('upper',self.folder/'upper.ext4',False,False)]:
    self.api('PUT','/drives/'+id,{'drive_id':id,'path_on_host':str(path),'is_root_device':root,'is_read_only':ro,'io_engine':'Sync'})
   if self.mode=='pmem':self.api('PUT','/pmem/base0',{'id':'base0','path_on_host':descriptor,'root_device':False,'read_only':True})
   else:self.api('PUT','/drives/lower',{'drive_id':'lower','path_on_host':str(lower),'is_root_device':False,'is_read_only':True,'io_engine':'Sync'})
   self.api('PUT','/actions',{'action_type':'InstanceStart'})
   self.wait_event(None,'boot_ready',90)
  self.record['phase']='running';self.run.persist()
  local=Path('/proc',str(self.pid),'fd/64').stat()
  need((local.st_dev,local.st_ino,local.st_size)==(ls.st_dev,ls.st_ino,LOWER),'Fresh inherited lower FD identity differs')
  upper=owned(self.folder/'upper.ext4');fds=[]
  for fp in Path('/proc',str(self.pid),'fd').iterdir():
   try:fs=fp.stat();fds.append((fs.st_dev,fs.st_ino))
   except FileNotFoundError:pass
  need((upper.st_dev,upper.st_ino) in fds,'FC did not open its private upper')
  if self.ram:
   parent_upper=owned(self.ram.parent/'p/upper.ext4')
   need((parent_upper.st_dev,parent_upper.st_ino) not in fds,'Child retains parent upper device FD')
 def poll(self):
  if self.exit is not None:return True
  if self.pid is None:return False
  pid,status=os.waitpid(self.pid,os.WNOHANG)
  if pid:
   self.exit=os.waitstatus_to_exitcode(status);self.record.update(exitCode=self.exit,exitConfirmed=True,phase='exited');self.run.persist();return True
  return False
 def wait_event(self,token,event='reply',seconds=40):
  deadline=time.monotonic()+seconds;last_print=0
  while time.monotonic()<deadline:
   p=self.folder/'serial.log';need(p.stat().st_size<4*1024**2,'Serial log budget exhausted')
   with p.open('rb') as f:f.seek(self.log_cursor);data=f.read()
   complete=data.rfind(b'\n')
   if complete>=0:
    self.log_cursor+=complete+1
    for line in data[:complete+1].decode(errors='replace').splitlines():
     if not line.startswith('PCC_EVENT '):continue
     value=json.loads(line[10:])
     if value.get('event')=='error':raise RuntimeError('Guest rejected control: '+str(value.get('error')))
     if value.get('event')==event and (token is None or value.get('token')==token):return value
   need(not self.poll(),'FC exited before barrier response')
   if time.monotonic()-last_print>10:print('WAIT role='+self.role+' event='+event,flush=True);last_print=time.monotonic()
   time.sleep(.05)
  raise TimeoutError('Guest barrier timed out; no automatic retry')
 def send(self,command):
  token=uuid.uuid4().hex;os.write(self.stdin,(command+' '+token+'\n').encode());return token
 def command(self,command):
  token=self.send(command);v=self.wait_event(token);need(v['command']==command,'Guest command acknowledgment mismatch');return v
 def verify_mapping(self):
  regions=self.api('GET','/vm/guest-memory-regions');maps=helper('observer').parse_guest_smaps(Path('/proc',str(self.pid),'smaps').read_text(),str(self.ram),RAM,regions)
  named=[m for m in maps if m['mapping_kind']=='snapshot_file_vma'];need(named,'No RAM snapshot file mapping')
  info=owned(self.ram)
  fd_id=[]
  for p in Path('/proc',str(self.pid),'fd').iterdir():
   try:
    z=p.stat()
    if (z.st_dev,z.st_ino)==(info.st_dev,info.st_ino):fd_id.append(p.name)
   except FileNotFoundError:pass
  # A mapped file need not retain an open fd; maps path and inode are checked too.
  text=Path('/proc',str(self.pid),'maps').read_text()
  check_ram_maps(text,self.ram,info)
  self.record['ramView']={'base':self.run.identity(self.ram),'private':True,'regions':regions,'offsetChecked':True,'fileVmas':len(named)};self.run.persist()
  return maps
 def stop(self,guest_exit=False):
  if self.pid is None:return False
  if self.poll():
   if self.stdin is not None:os.close(self.stdin);self.stdin=None
   if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None
   return True
  if guest_exit:
   try:self.command('EXIT')
   except Exception:pass
   until=time.monotonic()+5
   while not self.poll() and time.monotonic()<until:time.sleep(.05)
  if not self.poll():
   need(ticks(self.pid)==self.record['ticks'],'Stop refused reused PID')
   try:signal.pidfd_send_signal(self.pidfd,signal.SIGTERM)
   except ProcessLookupError:pass
   until=time.monotonic()+10
   while not self.poll() and time.monotonic()<until:time.sleep(.05)
  if not self.poll():
   try:signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)
   except ProcessLookupError:pass
  until=time.monotonic()+5
  while not self.poll() and time.monotonic()<until:time.sleep(.05)
  if self.exit is not None:
   if self.stdin is not None:os.close(self.stdin);self.stdin=None
   if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None
   return True
  return False

class Run:
 def __init__(self,cfg):
  self.cfg=cfg;self.state={'revision':'pcc-parent-v1','runId':uuid.uuid4().hex,'status':'RUNNING','machines':[],'groups':[],'samples':[],
   'globalPhysicalSavingBytes':None,'physicalPageAttributionAccepted':False,'SDK_called':False,'existingServicesChanged':False}
  self.files={str(STAGE/'tools.ext4'),*[v['path'] for v in cfg['inputs'].values()]};self.machines=[]
 def persist(self):write_json(STAGE/'journal.json',self.state)
 def identity(self,p):
  s=owned(p);return {'path':str(p),'device':s.st_dev,'inode':s.st_ino,'bytes':s.st_size,'mtimeNs':s.st_mtime_ns}
 def sample(self,phase_name,vms):
  obs=helper('observer');sample={'phase':phase_name,'startNs':time.time_ns(),'host':obs.host_observation(),'ownUnitCharge':helper('cgroup').sample(UNIT),
   'controller':obs.whole_process_metrics(os.getpid(),ticks(os.getpid())),'files':[],'guests':[],'physicalNetBytes':None,'columnsAreAdditive':False}
  unique=set()
  for p in sorted(self.files):
   if not Path(p).exists():continue
   try:
    f=file_state(p);key=f['device'],f['inode']
    if key not in unique:sample['files'].append(f);unique.add(key)
   except Exception as e:sample['files'].append({'path':p,'available':False,'error':type(e).__name__})
  for vm in vms:
   need(not vm.poll(),'FC exited during measurement')
   text=Path('/proc',str(vm.pid),'smaps').read_text();regions=vm.api('GET','/vm/guest-memory-regions')
   maps=obs.parse_guest_smaps(text,str(vm.ram) if vm.ram else '__fresh_anonymous__',RAM,regions)
   pm=pmem_maps(text,Path(self.cfg['inputs']['lower']['path'])) if vm.mode=='pmem' else []
   if vm.mode=='pmem':need(sum(m['end']-m['start'] for m in pm)==LOWER,'PMEM virtual extent differs')
   sample['guests'].append({'role':vm.role,'pid':vm.pid,'ticks':vm.record['ticks'],'wholeFC':obs.whole_process_metrics(vm.pid,vm.record['ticks']),
    'guestRam':{'virtualBytes':RAM,'bytes':sum_fields(maps),'source':'FC_API_INTERSECT_SMAPS'},'pmem':{'mappings':pm,'bytes':sum_fields(pm),'overlapsHostLower':True},'ramBase':vm.record.get('ramView')})
  sample['endNs']=time.time_ns();self.state['samples'].append(sample);self.persist()
  need(sample['ownUnitCharge']['available'],'Own-unit charge unavailable; measurement not accepted')
  need(all(g['wholeFC'].get('pss_bytes') is not None and g['guestRam']['bytes']['Pss'] is not None for g in sample['guests']),
       'Required FC/Guest RAM PSS missing; preserve partial data')
  return sample
 def machine(self,folder,role,mode,upper,ram=None):
  vm=Machine(self,folder,role,mode,ram);self.machines.append(vm)
  shutil.copyfile(upper,folder/'upper.ext4');self.files.add(str(folder/'upper.ext4'))
  need(sha_file(folder/'upper.ext4')==sha_file(upper),'Private upper copy content mismatch')
  vm.start();return vm
 def group(self,gid,mode,warm):
  phase(gid+'-prepare');folder=STAGE/gid;folder.mkdir(mode=0o700)
  record={'id':gid,'mode':mode,'parentPreRead':warm,'accepted':False,'reads':[]};self.state['groups'].append(record);self.persist()
  self.sample(gid+':before_prepare',[])
  need(sha_file(Path(self.cfg['inputs']['lower']['path']))==PINS['lower'][0],'Lower content changed')
  warmed=file_state(self.cfg['inputs']['lower']['path']);need(warmed['residentBytes']==LOWER,'Host warm lower condition not established')
  record['hostLowerWarm']=warmed
  parent=self.machine(folder/'p',gid+'_parent',mode,Path(self.cfg['inputs']['upper']['path']))
  initial=parent.command('CHECK');check_cache(initial,mode,0,False);record['parentInitial']=initial
  self.sample(gid+':parent_before_read',[parent])
  if warm:
   value=parent.command('READ');check_read(value,self.cfg['expectedCommonSha256'],1);record['reads'].append(value)
  barrier=parent.command('BARRIER');check_cache(barrier,mode,int(warm),warm);record['parentCaptureBarrier']=barrier
  self.sample(gid+':parent_before_capture',[parent])
  parent.api('PATCH','/vm',{'state':'Paused'})
  # No snapshot outcome is inferred from files alone or retried after timeout.
  parent.api('PUT','/snapshot/create',{'snapshot_type':'Full','snapshot_path':str(folder/'state.bin'),'mem_file_path':str(folder/'memory.bin')},120)
  self.files.update([str(folder/'state.bin'),str(folder/'memory.bin')]);record['snapshotAcknowledged']=True;self.persist()
  need(parent.stop(),'Parent exit unconfirmed; children forbidden')
  record['parentExitedBeforeChildren']=True
  ram=folder/'memory.bin';need(owned(ram).st_size==RAM,'Unexpected RAM snapshot extent')
  os.chmod(ram,0o400);os.chmod(folder/'state.bin',0o400)
  record['ramSha256']=sha_file(ram);record['stateSha256']=sha_file(folder/'state.bin');record['ramBase']=self.identity(ram)
  record['capturedUpperSha256']=sha_file(folder/'p/upper.ext4')
  if mode=='pmem':
   state=(folder/'state.bin').read_bytes();ref=('aenv-pmem-content:v1:'+PINS['lower'][0]+':'+str(LOWER)).encode()
   need(ref in state and b'aenv-pmem-fd:v5:' not in state,'Snapshot lacks portable pmem content reference')
  self.sample(gid+':parent_captured_and_exited',[])
  kids=[self.machine(folder/('c'+str(i)),gid+'_child'+str(i),mode,folder/'p/upper.ext4',ram) for i in range(2)]
  views=[k.record['ramView'] for k in kids]
  need(all(v['private'] and v['base']==record['ramBase'] for v in views),'Children do not share same private RAM base')
  need(len({(owned(k.folder/'upper.ext4').st_dev,owned(k.folder/'upper.ext4').st_ino) for k in kids})==2,'Upper files alias')
  record['childrenBefore']=[k.command('CHECK') for k in kids]
  for event in record['childrenBefore']:check_cache(event,mode,int(warm),warm)
  self.sample(gid+':children_before_read',kids)
  phase(gid+'-release-two-readers')
  record['releaseStartNs']=time.time_ns();tokens=[k.send('READ') for k in kids];record['releaseSentNs']=time.time_ns()
  need(record['releaseSentNs']-record['releaseStartNs']<=100_000_000,'Two-reader release window exceeded 100ms')
  record['childrenAfter']=[k.wait_event(token) for k,token in zip(kids,tokens)]
  for event in record['childrenAfter']:
   check_read(event,self.cfg['expectedCommonSha256'],int(warm)+1);check_cache(event,mode,int(warm)+1,True)
  for i in range(3):self.sample(gid+':children_after_read_'+str(i),kids);time.sleep(1)
  time.sleep(5)
  for k in kids:need(k.stop(guest_exit=True) and k.exit==0,'Child did not exit normally')
  need(sha_file(ram)==record['ramSha256'] and sha_file(folder/'state.bin')==record['stateSha256'],'Snapshot base modified by children')
  need(sha_file(folder/'p/upper.ext4')==record['capturedUpperSha256'],'Captured parent disk base modified')
  need(sha_file(self.cfg['inputs']['lower']['path'])==PINS['lower'][0],'Shared lower changed during group')
  self.sample(gid+':children_exited',[])
  record.update(accepted=True,allProcessesExited=True,ramBaseUnchanged=True,baseFilesRetained=True,physicalNetBytes=None)
  self.persist();phase(gid+'-passed')
 def execute(self):
  need(not (STAGE/'journal.json').exists(),'Existing journal preserved; do not rerun')
  self.persist()
  try:
   for gid,mode,warm in GROUPS:self.group(gid,mode,warm)
   self.state['status']='PCC_FOUR_GROUPS_PASSED_OWNED_GUESTS_RELEASED_NOT_PHYSICAL_NET_ACCEPTANCE'
  except BaseException as error:
   self.state.update(status='STOPPED_PCC_PRESERVE_ALL_ARTIFACTS',errorType=type(error).__name__,reason=str(error)[:700])
  finally:
   cleanup=[]
   for vm in reversed(self.machines):
    try:cleanup.append({'role':vm.role,'exitConfirmed':vm.stop()})
    except BaseException as e:cleanup.append({'role':vm.role,'exitConfirmed':False,'errorType':type(e).__name__})
   self.state['cleanup']=cleanup;self.state['allOwnedProcessesExited']=all(v['exitConfirmed'] for v in cleanup) and all(m.get('exitConfirmed') for m in self.state['machines'])
   if not self.state['allOwnedProcessesExited']:self.state['status']='STOPPED_PCC_UNKNOWN_PROCESS_STATE'
   self.persist();write_json(STAGE/'return.json',self.state)
  print('BEGIN_PCC_RESULT');print(json.dumps({k:v for k,v in self.state.items() if k not in ('samples','machines')},indent=2));print('END_PCC_RESULT',flush=True)
  return 0 if self.state['status'].startswith('PCC_FOUR_GROUPS_PASSED') else 1

def root_block(plan_sha):
 entry=Path(__file__).resolve();entry_sha=sha_file(entry)
 return """/usr/bin/python3 -I -B - <<'PCC_REVIEWED_ROOT'
import hashlib,json,os,socket,stat,subprocess
from pathlib import Path
assert os.geteuid()==0 and socket.gethostname()=='server1'
entry=Path(__ENTRY__); stage=Path(__STAGE__)
assert entry.resolve(strict=True)==entry and entry.is_relative_to(Path('/home/jwk/agent'))
assert entry.stat().st_uid==1204 and entry.stat().st_size<4*1024**2
assert hashlib.sha256(entry.read_bytes()).hexdigest()==__ENTRY_SHA__
plan=stage/'plan.json';assert plan.resolve(strict=True)==plan and plan.stat().st_uid==1204
assert hashlib.sha256(plan.read_bytes()).hexdigest()==__PLAN_SHA__
assert subprocess.check_output(['/usr/bin/id','-u','jwk'],text=True).strip()=='1204'
assert subprocess.check_output(['/usr/bin/id','-g','jwk'],text=True).strip()=='1205'
assert subprocess.check_output(['/usr/bin/systemctl','show',__UNIT__,'--property=LoadState','--value'],text=True).strip()=='not-found'
cmd=['/usr/bin/systemd-run','--unit='+__UNIT__,'--collect','--wait','--pipe',
 '--property=User=jwk','--property=Group=jwk','--property=SupplementaryGroups=kvm',
 '--property=CapabilityBoundingSet=','--property=AmbientCapabilities=',
 '--property=NoNewPrivileges=yes','--property=PrivateNetwork=yes','--property=PrivateTmp=yes',
 '--property=Type=exec','--property=Restart=no','--property=KillMode=control-group',
 '--property=RuntimeMaxSec=1800s','--property=TimeoutStopSec=20s',
 '--property=MemoryMax=4096M','--property=LimitNOFILE=4096','--property=UMask=0077',
 '/usr/bin/python3','-I','-B',str(entry),'run','--plan-sha',__PLAN_SHA__]
code=subprocess.run(cmd).returncode
print('PCC_UNIT_EXIT='+str(code),flush=True)
raise SystemExit(code)
PCC_REVIEWED_ROOT
""".replace('__ENTRY_SHA__',repr(entry_sha)).replace('__PLAN_SHA__',repr(plan_sha)).replace('__ENTRY__',repr(str(entry))).replace('__STAGE__',repr(str(STAGE))).replace('__UNIT__',repr(UNIT))

def prepare():
 need(not STAGE.exists() and not STAGE.is_symlink(),'Existing stage retained; use status')
 STAGE.mkdir(mode=0o700)
 prep={'startedNs':time.time_ns(),'hostBefore':helper('observer').host_observation(),'controllerBefore':helper('observer').whole_process_metrics(os.getpid(),ticks(os.getpid()))}
 write_json(STAGE/'preparation.json',prep)
 cfg=read_json(ROOT/'r/dsec-host-pagecache-node-a-v1/compare.json')
 prior=read_json(ROOT/'r/dsec-host-pagecache-node-a-v1/results/return.json')
 need(prior['status']=='DSEC_HOST_PAGECACHE_COMPONENT_COMPLETED_NOT_CROSS_NODE_COW' and prior['unresolvedFCPids']==[],'Prior component not complete')
 sources={k:dict(cfg['guest'][k]) for k in ('kernel','tools','upper')};sources['lower']=dict(cfg['lower'])
 sources['firecracker']={'path':str(ROOT/'builds/dsec-hostfile-release-v2/artifacts/firecracker')}
 prep['inputsBeforeVerification']=[file_state(v['path']) for v in sources.values()]
 for k,v in sources.items():
  need(sha_file(v['path'])==PINS[k][0] and owned(v['path']).st_size==PINS[k][1],'Pinned input differs: '+k)
  v.update(sha256=PINS[k][0],bytes=PINS[k][1])
 target=cfg['expectedCommonSha256'];need(re.fullmatch('[0-9a-f]{64}',target),'Expected target digest invalid')
 for name in ('pcc-helper-arm64','parent-init.sh'):
  (STAGE/name).write_bytes(unpack(name));os.chmod(STAGE/name,0o700)
 shutil.copyfile(sources['tools']['path'],STAGE/'tools.ext4')
 debugfs=shutil.which('debugfs');need(debugfs is not None,'Existing debugfs required; no automatic installation')
 for name in ('pcc-helper-arm64','parent-init.sh'):
  dest='/agentenv/'+('pcc-helper' if name=='pcc-helper-arm64' else name)
  for cmd in [f'write {STAGE/name} {dest}',f'set_inode_field {dest} mode 0100755',f'set_inode_field {dest} uid 0',f'set_inode_field {dest} gid 0']:
   r=subprocess.run([debugfs,'-w','-R',cmd,str(STAGE/'tools.ext4')],capture_output=True,text=True,timeout=60);need(r.returncode==0,'Tools image preparation failed')
  check=STAGE/(name+'.roundtrip')
  r=subprocess.run([debugfs,'-R',f'dump {dest} {check}',str(STAGE/'tools.ext4')],capture_output=True,text=True,timeout=60)
  need(r.returncode==0 and check.read_bytes()==unpack(name),'Injected Guest program roundtrip differs')
 plan={'revision':'pcc-parent-v1','inputs':sources,'toolsSha256':sha_file(STAGE/'tools.ext4'),'expectedCommonSha256':target,
  'groups':GROUPS,'entrySha256':sha_file(Path(__file__).resolve()),'memoryMiB':256,'vcpu':1,'children':2,'holdSeconds':5,
  'maxRuntimeSeconds':1800,'specificationSha256':SPEC_SHA,'matrixSha256':MATRIX_SHA,'globalDropCaches':False,'SDK_called':False}
 prep.update(finishedNs=time.time_ns(),hostAfter=helper('observer').host_observation(),filesAfter=[file_state(STAGE/'tools.ext4'),*[file_state(v['path']) for v in sources.values()]],
  controllerAfter=helper('observer').whole_process_metrics(os.getpid(),ticks(os.getpid())),targetGuestCreated=False)
 write_json(STAGE/'preparation.json',prep);write_json(STAGE/'plan.json',plan)
 command=root_block(sha_file(STAGE/'plan.json'))
 with (STAGE/'run-root.sh').open('x') as f:f.write(command)
 print(json.dumps({'status':'PCC_PREPARED_NO_GUEST','stage':str(STAGE),'newToolsSha256':plan['toolsSha256'],'existingImagesModified':False,'existingServicesChanged':False},indent=2),flush=True)
 print('BEGIN_PCC_ROOT');print(command);print('END_PCC_ROOT',flush=True)
 return 0
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['prepare','run','status','recover']);parser.add_argument('--plan-sha');args=parser.parse_args()
 need(sys.platform=='linux' and os.uname().machine=='aarch64' and socket.gethostname()=='server1','Use A ARM64')
 need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use jwk only; root runs the printed supervisor')
 os.umask(0o077)
 if args.mode=='status':
  print(json.dumps({'stage':str(STAGE),'plan':(STAGE/'plan.json').exists(),'journal':read_json(STAGE/'journal.json') if (STAGE/'journal.json').exists() else None},indent=2));return 0
 if args.mode=='prepare':return prepare()
 if args.mode=='recover':return recover()
 need(args.plan_sha and sha_file(STAGE/'plan.json')==args.plan_sha,'Plan changed')
 plan=read_json(STAGE/'plan.json');need(plan['entrySha256']==sha_file(Path(__file__).resolve()),'Entry differs')
 caps=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
 need(all(int(caps[x],16)==0 for x in ('CapInh','CapPrm','CapEff','CapAmb')),'Capability-free runner required')
 charge=helper('cgroup').sample(UNIT);need(charge['available'],'Run only in the printed isolated comparison unit')
 import fcntl
 fd=os.open(STAGE/'run.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  need(not (STAGE/'journal.json').exists() and not (STAGE/'admission.json').exists(),'Existing run preserved; no automatic restart')
  admission={'startedNs':time.time_ns(),'cpuStartedSeconds':time.process_time(),'hostBefore':helper('observer').host_observation(),'chargeBefore':helper('cgroup').sample(UNIT)}
  write_json(STAGE/'admission.json',admission)
  need(sha_file(STAGE/'tools.ext4')==plan['toolsSha256'],'Prepared tools changed')
  for k,v in plan['inputs'].items():need(sha_file(v['path'])==PINS[k][0],'Input changed before run')
  admission.update(finishedNs=time.time_ns(),cpuFinishedSeconds=time.process_time(),hostAfter=helper('observer').host_observation(),chargeAfter=helper('cgroup').sample(UNIT))
  write_json(STAGE/'admission.json',admission)
  def interrupted(*_):raise InterruptedError('Operator/supervisor interrupted this run')
  for sig in (signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
  return Run(plan).execute()
 finally:os.close(fd)

def recover():
 import fcntl
 fd=os.open(STAGE/'run.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  plan=read_json(STAGE/'plan.json');state=read_json(STAGE/'journal.json');results=[]
  for m in state['machines']:
   if m.get('pid') is None:
    results.append({'role':m['role'],'resolved':False,'reason':'No acknowledged PID; retain unknown intent'});continue
   pid=m['pid'];need(type(pid) is int and pid>1,'Invalid recorded PID')
   try:
    current=ticks(pid)
   except FileNotFoundError:
    results.append({'role':m['role'],'resolved':True,'reason':'Recorded process absent'});continue
   need(current==m['ticks'],'PID reused; do not signal it')
   folder=Path(m['directory']);need(folder.is_relative_to(STAGE) and folder.resolve(strict=True)==folder,'Recorded process directory differs')
   need(Path('/proc',str(pid),'cwd').resolve()==folder,'Process cwd differs')
   need(Path('/proc',str(pid),'exe').resolve()==Path(plan['inputs']['firecracker']['path']).resolve(),'Process executable differs')
   pf=os.pidfd_open(pid)
   try:
    need(ticks(pid)==m['ticks'],'PID changed during recovery')
    try:signal.pidfd_send_signal(pf,signal.SIGTERM)
    except ProcessLookupError:pass
    poll=select.poll();poll.register(pf,select.POLLIN);done=bool(poll.poll(10000))
    results.append({'role':m['role'],'resolved':done,'reason':'Scoped signal and pidfd exit observation'})
   finally:os.close(pf)
  result={'status':'PCC_RECOVERY_OBSERVATION','results':results,'allKnownProcessesExited':all(x['resolved'] for x in results),'filesDeleted':False,'automaticRetry':False}
  write_json(STAGE/'recovery.json',result);print(json.dumps(result,indent=2));return 0 if result['allKnownProcessesExited'] else 1
 finally:os.close(fd)

if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as error:
  print(json.dumps({'status':'STOPPED_PCC_ENTRY_PRESERVE_STATE','errorType':type(error).__name__,'reason':str(error)[:700],'stage':str(STAGE)}),flush=True);raise SystemExit(1)
