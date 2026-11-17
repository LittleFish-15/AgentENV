"""Read-only process ancestry observation; no benchmark or service operation."""
import hashlib,json,os,pathlib,platform,time
P=pathlib.Path
def describe(pid):
 p=P('/proc')/str(pid)
 try:
  raw=(p/'stat').read_text();end=raw.rfind(')');v=raw[end+2:].split();args=(p/'cmdline').read_bytes().split(b'\0');status={k:x.strip() for line in (p/'status').read_text().splitlines() for k,_,x in [line.partition(':')] if k in ('Uid','NSpid','RssAnon','VmRSS','Threads','Cpus_allowed_list')}
  scripts=[]
  for arg in args[1:]:
   if len(arg)<300 and b'\n' not in arg and arg.endswith((b'.py',b'.sh')):
    name=arg.decode(errors='replace');q=P(name) if name.startswith('/') else (p/'cwd').resolve()/name;item={'basename':q.name,'path':str(q)}
    try:
     if q.is_file() and q.stat().st_size<=128000:item['sha256']=hashlib.sha256(q.read_bytes()).hexdigest()
    except OSError:pass
    scripts.append(item)
  return {'pid':pid,'ppid':int(v[1]),'comm':raw[raw.find('(')+1:end],'state':v[0],'startTicks':int(v[19]),'cpuTicks':int(v[11])+int(v[12]),'exe':os.readlink(p/'exe'),'cwd':os.readlink(p/'cwd'),'argv0Basename':P(args[0].decode(errors='replace')).name if args else None,'scriptArguments':scripts,'commandSha256':hashlib.sha256((p/'cmdline').read_bytes()).hexdigest(),'status':status}
 except (OSError,ValueError,IndexError):return {'pid':pid,'unavailable':True}
def main():
 assert os.getuid()==os.geteuid()==0 and platform.node()=='debian' and platform.machine()=='x86_64';os.umask(0o077)
 root=P('/home/jwk/xy-memory-diagnosis-20261117-Y-051');assert not root.exists();root.mkdir(mode=0o700)
 records={};samples=[];names={'lat_probe','bw_probe','perf','multiload','multichase','mlc','stress-ng','stream'}
 for index in range(32):
  found=[]
  for p in P('/proc').glob('[0-9]*'):
   try:comm=(p/'comm').read_text().strip()
   except OSError:continue
   if comm not in names and not comm.startswith(('lat_probe','bw_probe','stress-ng')):continue
   if len(found)>=24:break
   pid=int(p.name);chain=[];current=pid
   for _ in range(7):
    if current<=0 or current in chain:break
    chain.append(current);row=describe(current);key=str(current)+':'+str(row.get('startTicks','gone'))
    if len(records)<160:records.setdefault(key,row)
    if row.get('unavailable'):break
    current=row['ppid']
   detail=describe(pid);found.append({'pid':pid,'comm':comm,'cpuTicks':detail.get('cpuTicks'),'rssAnon':detail.get('status',{}).get('RssAnon'),'ancestryPids':chain})
  samples.append({'unix_ns':time.time_ns(),'targets':found,'loadavg':P('/proc/loadavg').read_text().strip()})
  if index<31:time.sleep(1)
 result={'experiment':'Y_MEMORY_PROCESS_DIAG051','success':True,'readOnly':True,'benchmarkStarted':False,'servicesChanged':False,'frequencyChanged':False,'node':platform.node(),'kernel':platform.release(),'boot':P('/proc/sys/kernel/random/boot_id').read_text().strip(),'observerPid':os.getpid(),'processRecords':list(records.values()),'samples':samples,'privacy':'No environment or full arbitrary argv is returned; scripts, executable paths, cwd, parent identities and command hashes only.'}
 raw=json.dumps(result,separators=(',',':'));assert len(raw.encode())<500000;(root/'result.json').write_text(raw+'\n');print(raw,flush=True)
if __name__=='__main__':main()
