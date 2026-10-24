import ast,copy,importlib.util,json,types,unittest,uuid,shutil
from pathlib import Path
from unittest.mock import patch
H=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('pcc',H/'A_parent_cache_control_v1.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def event(mode,reads,hot):
 r={'bytes':8*1024**2,'dax':mode=='pmem','fileDataReadByCheck':False,'ordinaryPageCacheApplicable':mode=='block'}
 if mode=='block':r.update(residentPages=2048 if hot else 0,totalPages=2048,pageSize=4096)
 return {'facts':{'readCount':reads,'lower':dict(r),'visible':dict(r)}}
class Contracts(unittest.TestCase):
 def test_cold_partial_warm_refused(self):
  for count in (1,2047,2048):
   e=event('block',0,False);e['facts']['visible']['residentPages']=count
   with self.assertRaisesRegex(RuntimeError,'cache condition'):m.check_cache(e,'block',0,False)
 def test_hot_partial_refused(self):
  e=event('block',1,True);e['facts']['lower']['residentPages']=2047
  with self.assertRaisesRegex(RuntimeError,'cache condition'):m.check_cache(e,'block',1,True)
 def test_hidden_read_in_cold_refused(self):
  with self.assertRaisesRegex(RuntimeError,'Unexpected target read'):m.check_cache(event('block',1,False),'block',0,False)
 def test_cold_checks_cannot_claim_content_read(self):
  e=event('block',0,False);e['facts']['lower']['fileDataReadByCheck']=True
  with self.assertRaisesRegex(RuntimeError,'contract'):m.check_cache(e,'block',0,False)
 def test_dax_does_not_accept_fake_mincore(self):
  e=event('pmem',0,False);e['facts']['lower']['residentPages']=2048
  with self.assertRaisesRegex(RuntimeError,'DAX mincore'):m.check_cache(e,'pmem',0,False)
 def test_four_required_cache_conditions(self):
  for _,mode,warm in m.GROUPS:self.assertTrue(m.check_cache(event(mode,int(warm),warm),mode,int(warm),warm))
 def test_incorrect_read_length_digest_count_rejected(self):
  good={'command':'READ','read':{'bytes':8*1024**2,'sha256':'a'*64,'readCount':1}}
  for key,bad in [('bytes',1),('sha256','b'*64),('readCount',2)]:
   v=copy.deepcopy(good);v['read'][key]=bad
   with self.assertRaises(RuntimeError):m.check_read(v,'a'*64,1)
 def test_bootstrap_is_exact_scoped_python(self):
  with patch.object(m,'sha_file',return_value='a'*64):src=m.root_block('b'*64)
  code=src.split("<<'PCC_REVIEWED_ROOT'\n",1)[1].rsplit('PCC_REVIEWED_ROOT',1)[0]
  ast.parse(code,feature_version=(3,11));self.assertIn('PCC_UNIT_EXIT=',code)
  self.assertNotIn('__UNIT__',code);self.assertNotIn('drop_caches',code)
  self.assertIn('jwk-pcc-node-a-v1.service',code);self.assertIn('MemoryMax=4096M',code)
 def test_embedded_helpers_import_without_actions(self):
  for n in ['observer','cgroup']:self.assertIsNotNone(m.helper(n))
  self.assertEqual(m.helper('cgroup').UNIT_RE.fullmatch(m.UNIT).group(0),m.UNIT)
  self.assertIsNone(m.helper('cgroup').UNIT_RE.fullmatch('jwk-aenv-ae9c626-node-a.service'))
 def test_real_maps_contract_device_inode_private(self):
  info=types.SimpleNamespace(st_ino=42,st_dev=999)
  with patch.object(m.os,'major',return_value=8,create=True),patch.object(m.os,'minor',return_value=0,create=True):
   m.check_ram_maps('1000-2000 rw-p 00000000 08:00 42 mem.bin',Path('mem.bin'),info)
   for text in ['1000-2000 rw-s 00000000 08:00 42 mem.bin','1000-2000 rw-p 00000000 08:01 42 mem.bin','1000-2000 rw-p 00000000 08:00 43 mem.bin']:
    with self.assertRaises(RuntimeError):m.check_ram_maps(text,Path('mem.bin'),info)
 def test_first_group_failure_stops_matrix_and_keeps_unknown(self):
  r=object.__new__(m.Run);r.state={'machines':[{'exitConfirmed':False}],'samples':[]};r.machines=[];seen=[]
  r.persist=lambda:None
  def group(*args):seen.append(args[0]);raise TimeoutError('unknown creation')
  r.group=group
  with patch.object(m,'write_json'),patch.object(Path,'exists',return_value=False):
   self.assertEqual(r.execute(),1)
  self.assertEqual(seen,['B0']);self.assertFalse(r.state['allOwnedProcessesExited'])
 def test_guest_cold_inspection_has_no_payload_read(self):
  text=(H/'guest_linux.go').read_text()
  inspect=text.split('func inspect(',1)[1].split('func facts(',1)[0]
  self.assertIn('syscall.PROT_NONE',inspect);self.assertIn('syscall.SYS_MINCORE',inspect)
  self.assertIn('st.Uid!=uint32(os.Geteuid())',inspect)
  self.assertNotIn('.Read(',inspect);self.assertIn('os.ReadFile("/proc/self/status")',inspect)
  self.assertNotIn('ReadFile(path)',inspect);self.assertIn('caps&(1<<3)',inspect)
  main=text.split('func main()',1)[1]
  self.assertLess(main.index('facts()'),main.index('for scanner.Scan()'))
  self.assertNotIn('readTarget()',main.split('for scanner.Scan()',1)[0])

class SimulatedGroup(unittest.TestCase):
 def setUp(self):
  self.dir=H/('test-'+uuid.uuid4().hex);self.dir.mkdir();self.calls=[]
 def tearDown(self):
  self.assertTrue(self.dir.resolve().is_relative_to(H.resolve()));shutil.rmtree(self.dir)
 def run_group(self,gid='B0',mode='block',warm=False,fault=None):
  calls=self.calls;cfg={'inputs':{'lower':{'path':str(self.dir/'lower')},'upper':{'path':str(self.dir/'upper')}},'expectedCommonSha256':'a'*64}
  class VM:
   def __init__(self,role,folder,ram=None):
    self.role=role;self.folder=folder;folder.mkdir();(folder/'upper.ext4').write_bytes(role.encode());self.exit=0;self.reads=int(warm) if ram else 0
    self.record={'ramView':{'private':fault!='shared_view','base':identity(ram) if ram else None}}
    if fault=='wrong_base' and ram:self.record['ramView']['base']={'wrong':True}
   def command(self,cmd):
    calls.append((self.role,cmd))
    if cmd=='READ':self.reads+=1
    v=event(mode,self.reads,self.reads>0);v['command']=cmd
    if fault=='cold_polluted' and gid=='B0':v['facts']['visible']['residentPages']=1
    if cmd=='READ':v['read']={'bytes':8*1024**2,'sha256':'a'*64,'readCount':self.reads}
    return v
   def api(self,method,path,body):
    calls.append((self.role,path))
    if path=='/snapshot/create':
     if fault=='snapshot_unknown':raise TimeoutError('unknown snapshot response')
     Path(body['snapshot_path']).write_bytes(('aenv-pmem-content:v1:'+m.PINS['lower'][0]+':'+str(m.LOWER)).encode())
     Path(body['mem_file_path']).write_bytes(b'ram')
   def stop(self,guest_exit=False):calls.append((self.role,'stop'));return not(fault=='parent_stop' and self.role.endswith('parent'))
   def send(self,cmd):calls.append((self.role,'send'));return 'nonce'
   def wait_event(self,token):return self.command('READ')
  def identity(p):return {'path':str(p),'inode':1,'bytes':m.RAM}
  r=object.__new__(m.Run);r.cfg=cfg;r.files=set();r.state={'groups':[]};r.persist=lambda:None;r.identity=identity
  r.sample=lambda phase,vms:calls.append(('sample',phase))
  def machine(folder,role,mode,upper,ram=None):calls.append(('create',role));return VM(role,folder,ram)
  r.machine=machine
  def metadata(p):
   if str(p).endswith('memory.bin'):return types.SimpleNamespace(st_size=m.RAM)
   return Path(p).stat()
  real_mkdir=Path.mkdir
  def local_mkdir(path,mode=0o777,parents=False,exist_ok=False):
   self.assertTrue(path.resolve().is_relative_to(self.dir.resolve()))
   return real_mkdir(path,mode=0o777,parents=parents,exist_ok=exist_ok)
  with patch.object(m,'STAGE',self.dir),patch.object(m,'owned',side_effect=metadata),patch.object(m,'sha_file',return_value=m.PINS['lower'][0]),patch.object(m,'file_state',return_value={'residentBytes':m.LOWER}),patch.object(m.time,'sleep',return_value=None),patch.object(Path,'mkdir',local_mkdir),patch.object(m.os,'chmod',return_value=None):
   # fake api accepts the production timeout keyword/argument
   original=VM.api;VM.api=lambda self,method,path,body,*a,**kw:original(self,method,path,body)
   return r.group(gid,mode,warm)
 def test_each_group_captures_parent_before_children_and_releases(self):
  for gid,mode,warm in m.GROUPS:
   self.run_group(gid,mode,warm)
   seq=self.calls;cap=seq.index((gid+'_parent','/snapshot/create'));stop=seq.index((gid+'_parent','stop'))
   child=seq.index(('create',gid+'_child0'));self.assertLess(cap,stop);self.assertLess(stop,child)
   self.assertEqual(sum(role==gid+'_parent' and cmd=='READ' for role,cmd in seq),int(warm))
 def test_cold_polluted_never_snapshots(self):
  with self.assertRaises(RuntimeError):self.run_group(fault='cold_polluted')
  self.assertFalse(any(v=='/snapshot/create' for _,v in self.calls))
 def test_unknown_snapshot_does_not_start_children_or_retry(self):
  with self.assertRaises(TimeoutError):self.run_group(fault='snapshot_unknown')
  self.assertEqual(sum(v=='/snapshot/create' for _,v in self.calls),1)
  self.assertFalse(any('child' in v for k,v in self.calls if k=='create'))
 def test_parent_stop_failure_does_not_start_children(self):
  with self.assertRaises(RuntimeError):self.run_group(fault='parent_stop')
  self.assertFalse(any('child' in v for k,v in self.calls if k=='create'))
 def test_shared_view_or_wrong_base_refused(self):
  for fault in ['shared_view','wrong_base']:
   with self.assertRaises(RuntimeError):self.run_group(gid=fault,fault=fault)

if __name__=='__main__':unittest.main()
