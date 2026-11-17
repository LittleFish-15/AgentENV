"""Short native X/Y study, reusing verified binaries, with external-load records."""
import argparse,base64,csv,hashlib,importlib.util,json,math,os,pathlib,platform,re,signal,subprocess,sys,tarfile,time
P=pathlib.Path
PROTOCOL={'status': 'prepared_not_published_or_executed', 'purpose': 'Short paired X/Y memory screening; not frequency causality proof', 'host_window_minutes_target': 10, 'host_window_minutes_budget': 12, 'physical_cores': 16, 'cpu_node': 0, 'memory_nodes': [0], 'page_bytes': 4096, 'working_set_mib': 1024, 'bandwidth_budget': 'total', 'bandwidth_threads': [1, 4, 16], 'loaded_total_threads': [4, 16], 'patterns': ['stream-sum', 'stream-copy'], 'repetitions': 3, 'samples_per_run': 3, 'matrix': [{'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 1, 'load_threads': 1, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 1, 'order': 1}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 4, 'load_threads': 4, 'per_worker_bytes': 268435456, 'target_bytes': 1073741824, 'repetition': 1, 'order': 2}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 1, 'load_threads': 1, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 1, 'order': 3}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 16, 'load_threads': 16, 'per_worker_bytes': 67108864, 'target_bytes': 1073741824, 'repetition': 1, 'order': 4}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-sum', 'threads': 16, 'load_threads': 15, 'per_worker_bytes': 1073741824, 'target_bytes': 17179869184, 'repetition': 1, 'order': 5}, {'memory_node': 0, 'mode': 'latency', 'pattern': 'simple', 'threads': 1, 'load_threads': 0, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 1, 'order': 6}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-sum', 'threads': 4, 'load_threads': 3, 'per_worker_bytes': 1073741824, 'target_bytes': 4294967296, 'repetition': 1, 'order': 7}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 16, 'load_threads': 16, 'per_worker_bytes': 67108864, 'target_bytes': 1073741824, 'repetition': 1, 'order': 8}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 4, 'load_threads': 4, 'per_worker_bytes': 268435456, 'target_bytes': 1073741824, 'repetition': 1, 'order': 9}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-copy', 'threads': 4, 'load_threads': 3, 'per_worker_bytes': 1073741824, 'target_bytes': 4294967296, 'repetition': 1, 'order': 10}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-copy', 'threads': 16, 'load_threads': 15, 'per_worker_bytes': 1073741824, 'target_bytes': 17179869184, 'repetition': 1, 'order': 11}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 1, 'load_threads': 1, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 2, 'order': 12}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 1, 'load_threads': 1, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 2, 'order': 13}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-sum', 'threads': 16, 'load_threads': 15, 'per_worker_bytes': 1073741824, 'target_bytes': 17179869184, 'repetition': 2, 'order': 14}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 4, 'load_threads': 4, 'per_worker_bytes': 268435456, 'target_bytes': 1073741824, 'repetition': 2, 'order': 15}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-copy', 'threads': 4, 'load_threads': 3, 'per_worker_bytes': 1073741824, 'target_bytes': 4294967296, 'repetition': 2, 'order': 16}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-sum', 'threads': 4, 'load_threads': 3, 'per_worker_bytes': 1073741824, 'target_bytes': 4294967296, 'repetition': 2, 'order': 17}, {'memory_node': 0, 'mode': 'latency', 'pattern': 'simple', 'threads': 1, 'load_threads': 0, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 2, 'order': 18}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 16, 'load_threads': 16, 'per_worker_bytes': 67108864, 'target_bytes': 1073741824, 'repetition': 2, 'order': 19}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 4, 'load_threads': 4, 'per_worker_bytes': 268435456, 'target_bytes': 1073741824, 'repetition': 2, 'order': 20}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 16, 'load_threads': 16, 'per_worker_bytes': 67108864, 'target_bytes': 1073741824, 'repetition': 2, 'order': 21}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-copy', 'threads': 16, 'load_threads': 15, 'per_worker_bytes': 1073741824, 'target_bytes': 17179869184, 'repetition': 2, 'order': 22}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-sum', 'threads': 4, 'load_threads': 3, 'per_worker_bytes': 1073741824, 'target_bytes': 4294967296, 'repetition': 3, 'order': 23}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 1, 'load_threads': 1, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 3, 'order': 24}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 16, 'load_threads': 16, 'per_worker_bytes': 67108864, 'target_bytes': 1073741824, 'repetition': 3, 'order': 25}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 4, 'load_threads': 4, 'per_worker_bytes': 268435456, 'target_bytes': 1073741824, 'repetition': 3, 'order': 26}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-copy', 'threads': 4, 'load_threads': 3, 'per_worker_bytes': 1073741824, 'target_bytes': 4294967296, 'repetition': 3, 'order': 27}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-copy', 'threads': 1, 'load_threads': 1, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 3, 'order': 28}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-copy', 'threads': 16, 'load_threads': 15, 'per_worker_bytes': 1073741824, 'target_bytes': 17179869184, 'repetition': 3, 'order': 29}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 16, 'load_threads': 16, 'per_worker_bytes': 67108864, 'target_bytes': 1073741824, 'repetition': 3, 'order': 30}, {'memory_node': 0, 'mode': 'loaded_latency', 'pattern': 'stream-sum', 'threads': 16, 'load_threads': 15, 'per_worker_bytes': 1073741824, 'target_bytes': 17179869184, 'repetition': 3, 'order': 31}, {'memory_node': 0, 'mode': 'latency', 'pattern': 'simple', 'threads': 1, 'load_threads': 0, 'per_worker_bytes': 1073741824, 'target_bytes': 1073741824, 'repetition': 3, 'order': 32}, {'memory_node': 0, 'mode': 'bandwidth_total', 'pattern': 'stream-sum', 'threads': 4, 'load_threads': 4, 'per_worker_bytes': 268435456, 'target_bytes': 1073741824, 'repetition': 3, 'order': 33}], 'page_path': {'working_set_mib': 1024, 'workers': [1, 100], 'pairs': 3}, 'estimates_from_046': {'X': {'previous_ram_seconds': 1610.5073087572237, 'projected_short_ram_seconds': 429.31411664349724}, 'Y': {'previous_ram_seconds': 1623.6915794218658, 'projected_short_ram_seconds': 433.38316461957874}}, 'binary_policy': 'Reuse each host previously verified native binary; verify SHA256. No cross-architecture binary copying.', 'environment_policy': 'Human-confirmed exclusive window; preflight and ongoing external-process activity evidence. Preserve and reject the full affected study if interference is detected; no selective retries or fast-sample selection.', 'transport': {'X': 'existing direct connection', 'Y': 'existing unified root-start.sh entry'}, 'exclusions': ['No aenv lifecycle run bundled into this timing estimate', 'No global configuration or frequency change', 'No automatic stop of unrelated processes'], 'limitations': ['Sparse curve cannot locate the exact bandwidth/latency knee', 'Three repeats are screening evidence, not a long-term stability claim', 'Cross-host rate differences alone do not establish frequency causality'], 'implementation_note': 'Declarative protocol only. Existing 046 runner does not consume this file; prepare a new bounded worker and verify environment monitor before publication.'}
HASHES={'X': {'memory_study.py': '000231d53f2c6f424cb18f01b3ea5f79c7efb6833981f019e73ec47ac3bee345', 'page_path_probe.py': '629be3d8deb8332c5eb757000ee965342bb642cbed17e7694e8a3fab407e598a', 'build/aarch64/source/multiload': '298428c6f0724d20110820bf86340669cbab08c93d79fee55b1d2f1a327e7332', 'private-bin/numactl': '82c32127948534efe40a2d3da80c89aa61b69bfb03a13e05a6715faa362992bf', 'numa_exec.c': 'ed00e08cbe5bb881e0064bd79f177cc828a6cc616aed9afd026d88f4180877e4'}, 'Y': {'memory_study.py': '000231d53f2c6f424cb18f01b3ea5f79c7efb6833981f019e73ec47ac3bee345', 'page_path_probe.py': '629be3d8deb8332c5eb757000ee965342bb642cbed17e7694e8a3fab407e598a', 'build/x86_64/source/multiload': '6cf1c79bf79d95438fde34a64bbe7d47c4783b7477447dc823ac708f56922a35', 'numa_exec.c': 'ed00e08cbe5bb881e0064bd79f177cc828a6cc616aed9afd026d88f4180877e4'}}
def sha(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
def save(p,value):
 tmp=p.with_name(p.name+'.next');tmp.write_text(json.dumps(value,indent=2)+'\n');os.replace(tmp,p)
def process_snapshot():
 rows={};now=time.monotonic()
 for p in P('/proc').glob('[0-9]*'):
  try:
   raw=(p/'stat').read_text();end=raw.rfind(')');v=raw[end+2:].split()
   if int(v[6])&0x200000:continue
   anon=next((int(x.split()[1]) for x in (p/'status').read_text().splitlines() if x.startswith('RssAnon:')),0)
   rows[int(p.name)]={'comm':raw[raw.find('(')+1:end],'ppid':int(v[1]),'start':int(v[19]),'ticks':int(v[11])+int(v[12]),'anonKiB':anon}
  except (OSError,ValueError,IndexError):pass
 own={os.getpid()}
 while True:
  new=own|{pid for pid,r in rows.items() if r['ppid'] in own}
  if new==own:break
  own=new
 return now,{pid:r for pid,r in rows.items() if pid not in own}

KNOWN_MONITOR_HASHES={'spotbox_monitor.py': '85a14499460acdad1a7e3293f6370dc122a2d82450e0eeb1e660aa3ee46c2fe4', 'hcollect.py': '5226af919c8999d09aaa545f3d27f19a040be63e1c33a1174274768dcc4a8ac5'}
def recognized_monitors(initial):
 found={}
 for pid,row in initial.items():
  if not row['comm'].startswith('python'):continue
  p=P('/proc')/str(pid)
  try:
   for raw in (p/'cmdline').read_bytes().split(b'\0')[1:]:
    if len(raw)>300 or b'\n' in raw:continue
    name=raw.decode(errors='replace');basename=P(name).name
    if basename not in KNOWN_MONITOR_HASHES:continue
    path=P(name) if name.startswith('/') else (p/'cwd').resolve()/name
    if path.stat().st_size<=100000 and sha(path)==KNOWN_MONITOR_HASHES[basename]:found[pid]={'start':row['start'],'basename':basename,'sha256':KNOWN_MONITOR_HASHES[basename]}
  except (OSError,ValueError):pass
 return found

class EnvironmentGuard:
 def __init__(self,root,study):
  self.root=root;self.study=study;self.previous=process_snapshot();self.initial=self.previous[1];self.baseline_anon=sum(x['anonKiB'] for x in self.initial.values());self.baseline_cpu=0.;self.high=0;self.new_high=0;self.maximum_cpu=0.;self.count=0;self.baseline=False;self.failure=None;self.recognized_monitors=recognized_monitors(self.initial)
 def sample(self,stage,enforce=True):
  if time.monotonic()-self.previous[0]<1.5:return getattr(self,'last_record',None)
  now,rows=process_snapshot();then,old=self.previous;dt=now-then;hz=os.sysconf('SC_CLK_TCK');activity=[];new_cpu=0
  for pid,r in rows.items():
   prev=old.get(pid);same=prev and prev['start']==r['start'];ticks=max(0,r['ticks']-prev['ticks']) if same else r['ticks'];cores=ticks/hz/dt
   is_new=pid not in self.initial or self.initial[pid]['start']!=r['start']
   if is_new:new_cpu+=cores
   if cores>0:activity.append({'pid':pid,'comm':r['comm'],'cpuCores':cores,'newSinceBaseline':is_new,'recognizedBaselineMonitor':pid in self.recognized_monitors and self.recognized_monitors[pid]['start']==r['start']})
  activity.sort(key=lambda r:r['cpuCores'],reverse=True);cpu=sum(r['cpuCores'] for r in activity);anon=sum(r['anonKiB'] for r in rows.values());new_anon=sum(r['anonKiB'] for pid,r in rows.items() if pid not in self.initial or self.initial[pid]['start']!=r['start'])
  host=self.study.snapshot();record={'recognizedMonitoringCpuCores':sum(r['cpuCores'] for r in activity if r['recognizedBaselineMonitor']),'unix_ns':time.time_ns(),'stage':stage,'interval_s':dt,'externalCpuCores':cpu,'newExternalCpuCores':new_cpu,'externalAnonKiB':anon,'newExternalAnonKiB':new_anon,'topExternalCpu':activity[:8],'host':host}
  self.previous=(now,rows);self.maximum_cpu=max(self.maximum_cpu,cpu);self.count+=1;self.last_record=record
  with (self.root/'environment.jsonl').open('a') as f:f.write(json.dumps(record,separators=(',',':'))+'\n')
  return record
 def admit(self):
  samples=[]
  for _ in range(3):time.sleep(2);samples.append(self.sample('preflight',False))
  self.baseline_cpu=sum(x['externalCpuCores'] for x in samples)/len(samples)
  self.baseline_nonmonitor_cpu=sum(x['externalCpuCores']-x['recognizedMonitoringCpuCores'] for x in samples)/len(samples)
  self.baseline=True
  save(self.root/'environment-policy.json',{'mode':'record_only','loadAbortEnabled':False,'baselineExternalCpuCores':self.baseline_cpu,'baselineNonMonitorCpuCores':self.baseline_nonmonitor_cpu,'baselineExternalAnonKiB':self.baseline_anon,'recognizedExistingMonitors':self.recognized_monitors,'intervalSeconds':2,'scope':'Record existing and new external activity, PSI and memory without rejecting or selectively retrying samples. Identity, native binary, NUMA, memory headroom, command result and timeout checks remain enforced.','limitations':'Measurements describe the observed host environment. Background activity may affect results; these data alone do not establish memory-frequency causality.'})

def main():
 parser=argparse.ArgumentParser();parser.add_argument('machine',choices=['X','Y']);machine=parser.parse_args().machine
 root=P('/home/jwk')/('xy-memory-study-20261117-'+machine+'-053');old=P('/home/jwk')/('xy-memory-study-20261117-'+machine+'-046');child=None;guard=None;created=False;result={'experiment':'XY_MEMORY053','machine':machine,'success':False,'stage':'preflight','frequencyChanged':False,'aenvChanged':False};started=time.monotonic()
 def stop_child():
  nonlocal child
  if child is not None and child.poll() is None:
   try:os.killpg(child.pid,signal.SIGINT);child.wait(timeout=15)
   except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
   except ProcessLookupError:pass
 def run(argv,tag,limit):
  nonlocal child
  result['stage']=tag;save(root/'progress.json',result)
  out=root/(tag+'.stdout.log');err=root/(tag+'.stderr.log');cmdtime=time.monotonic();stdout=b'';stderr=b''
  save(root/(tag+'.command.json'),argv)
  guard.sample(tag)
  try:
   child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
   while True:
    try:stdout,stderr=child.communicate(timeout=2);guard.sample(tag);break
    except subprocess.TimeoutExpired:
     guard.sample(tag)
     if time.monotonic()-cmdtime>limit or time.monotonic()-started>720:raise TimeoutError('Bounded study deadline')
   if child.returncode:raise RuntimeError('Tool exit '+str(child.returncode)+' in '+tag)
  finally:
   stop_child()
   if child is not None:
    stdout,stderr=child.communicate();out.write_bytes(stdout);err.write_bytes(stderr);child=None
  return stdout,time.monotonic()-cmdtime
 try:
  assert os.getuid()==os.geteuid()==0 and sys.version_info>=(3,11);os.umask(0o077)
  assert platform.machine()==('aarch64' if machine=='X' else 'x86_64') and platform.node()==('debian188' if machine=='X' else 'debian')
  assert not root.exists() and root.parent.resolve()==root.parent;root.mkdir(mode=0o700);created=True
  expected=HASHES[machine]
  for relative,value in expected.items():assert sha(old/relative)==value,'Previously verified source/binary changed: '+relative
  save(root/'source-proof.json',{'priorRoot':str(old),'hashes':expected,'workerSha256':sha(__file__),'protocol':PROTOCOL})
  spec=importlib.util.spec_from_file_location('study',old/'memory_study.py');study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)
  inventory=study.inventory();save(root/'inventory-root.json',inventory);assert inventory['page_bytes']==4096 and len(inventory['nodes'][0]['physical_cpu_choices'])>=16
  selected=inventory['nodes'][0]['physical_cpu_choices'][:16];cpus=','.join(map(str,selected));matrix=PROTOCOL['matrix'];assert len(matrix)==33
  env={'PATH':str(old/'private-bin')+':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
  mem=inventory['snapshot']['memory_kib']['MemAvailable']*1024;assert mem>40*(1<<30),'Insufficient memory headroom'
  quota=None;cg=next((x.split(':',2)[2] for x in P('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::')),None)
  if cg is not None:
   group=P('/sys/fs/cgroup')/cg.lstrip('/');assert group.resolve().is_relative_to(P('/sys/fs/cgroup').resolve());quota=(group/'cpu.max').read_text().split();assert quota[0]=='max' or int(quota[0])/int(quota[1])>=16
  result.update(arch=inventory['machine_arch'],kernel=inventory['kernel'],configuredMtS=inventory['configured_mt_s'],selectedPhysicalCpus=selected,cpuMax=quota,boot=P('/proc/sys/kernel/random/boot_id').read_text().strip(),binarySha256=expected['build/'+platform.machine()+'/source/multiload'])
  guard=EnvironmentGuard(root,study);guard.admit()
  run([str(old/'private-bin/numactl'),'--physcpubind='+cpus,'--membind=0','/usr/bin/python3','-I','-B','-c','import os; assert len(os.sched_getaffinity(0))==16; print("AFFINITY_READBACK_OK")'],'binding_smoke',20)
  folder=root/'ram-local';folder.mkdir();(folder/'raw').mkdir();binary=old/'build'/platform.machine()/'source/multiload'
  manifest={'machine':machine,'frequency_label':'current-short','configured_mt_s':inventory['configured_mt_s'],'frequency_source':inventory['configured_mt_s_source'],'topology':inventory,'selected_physical_cpus':selected,'cpu_node':0,'matrix':matrix,'args':{'cores':16,'repetitions':3,'samples':3,'cpu_node':0,'memory_nodes':'0','working_set_mib':1024,'bandwidth_budget':'total'},'binary_sha256':sha(binary),'source':json.loads((old/'vendor/manifest.json').read_text()),'sampling':'ChasAVG arithmetic mean, per-case three internal samples; all three independent repetitions retained','bandwidth':'tool effective traffic, not measured memory-controller traffic','environment':'background activity is recorded without load-triggered abort; no perf or active extra memory probe started'};save(folder/'manifest.json',manifest)
  with (folder/'results.csv').open('w',newline='') as f:
   writer=csv.DictWriter(f,fieldnames=study.FIELDS);writer.writeheader()
   for case in matrix:
    tag='raw/%04d'%case['order'];base=folder/tag;before=study.snapshot();save(base.with_suffix('.before.json'),before)
    cmd=[str(old/'private-bin/numactl'),'--physcpubind='+cpus,'--membind=0',str(binary),'-a','-v','-n','3','-t',str(case['threads']),'-m',str(case['per_worker_bytes']),'-s','128','-p','4096']
    if case['mode']=='latency':cmd+=['-c','simple']
    elif case['mode']=='loaded_latency':cmd+=['-c','chaseload','-l',case['pattern']]
    else:cmd+=['-l',case['pattern']]
    record={**case,'machine':machine,'frequency_label':'current-short','configured_mt_s':inventory['configured_mt_s'],'frequency_source':inventory['configured_mt_s_source'],'cpu_node':0,'numa_distance':inventory['nodes'][0]['distance'][0],'status':'error','raw_log':tag+'.stdout.txt'}
    case_start=time.monotonic()
    try:
     stdout,elapsed=run(cmd,'ram_%04d'%case['order'],50);base.with_suffix('.stdout.txt').write_bytes(stdout);base.with_suffix('.stderr.txt').write_bytes((root/('ram_%04d.stderr.log'%case['order'])).read_bytes());save(base.with_suffix('.command.json'),cmd)
     record.update(study.parse_output(stdout.decode(),case));record['status']='ok'
    except BaseException as e:record['error']=type(e).__name__+': '+str(e)[:700];raise
    finally:
     after=study.snapshot();save(base.with_suffix('.after.json'),after);record['elapsed_s']=time.monotonic()-case_start
     for key,label in [('pswpin','swap_in_delta'),('pswpout','swap_out_delta')]:record[label]=after['vmstat'].get(key,0)-before['vmstat'].get(key,0)
     writer.writerow(record);f.flush()
    result['ramCasesFinished']=case['order'];save(root/'progress.json',result)
  save(folder/'complete.json',{'success':True,'cases':33,'results_csv_sha256':sha(folder/'results.csv'),'finish':study.snapshot()})
  result['pageCases']=[]
  result['fileAuxiliaryNotScheduled']=True
  guard.sample('complete');result.update(success=True,stage='complete',environmentObservationComplete=True,loadAbortEnabled=False)
 except BaseException as e:result['error']=type(e).__name__+': '+str(e)[:1200];result['environmentObservationComplete']=False
 finally:
  stop_child();result['elapsedSeconds']=time.monotonic()-started
  if guard is not None:result['environmentSummary']={'baselineExternalCpuCores':guard.baseline_cpu,'maximumExternalCpuCores':guard.maximum_cpu,'samples':guard.count,'policy':'record_only','loadAbortEnabled':False}
  if created:
   save(root/'result.json',result);save(root/'progress.json',result);archive=root/'results.tar.gz'
   with tarfile.open(archive,'w:gz',compresslevel=9) as tar:
    for p in sorted(root.rglob('*')):
     if p.is_file() and not p.is_symlink() and p!=archive:tar.add(p,arcname=p.relative_to(root).as_posix(),recursive=False)
   raw=archive.read_bytes();result.update(archiveBytes=len(raw),archiveSha256=hashlib.sha256(raw).hexdigest(),archivePath=str(archive))
   if len(raw)<=450000:result['archiveBase64']=base64.b64encode(raw).decode()
   else:result['archiveRetainedOnly']=True
  result['root']=str(root);text=json.dumps(result,separators=(',',':'));assert len(text.encode())<800000;print(text,flush=True)
if __name__=='__main__':main()
