"""Prepare exact logging-only change and stable-pool measurement handshake."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'runtime_supervisor024.py').read_text(encoding='utf-8')
old="agentenv::sandbox::firecracker::sandbox=debug'";assert s.count(old)==1
s=s.replace(old,"agentenv::sandbox::firecracker::sandbox=debug,agentenv::sandbox::envd=trace'")
(H/'runtime_supervisor025.py').write_bytes(s.encode())
w=(H/'wikidata024_worker.py').read_text(encoding='utf-8').replace("BASE/'wikidata024'","BASE/'wikidata025'").replace('wikidata024.lock','wikidata025.lock').replace("BASE/'results/wikidata024'","BASE/'results/wikidata025'")
needle="            if label=='formal':STATE['formalServerLogOffset']=(BASE/'logs/server.log').stat().st_size"
replacement='''            if label=='formal':
                def fc_pids():
                    found=set()
                    for proc in P('/proc').iterdir():
                        if not proc.name.isdigit():continue
                        try:
                            if proc.stat().st_uid==1002 and (proc/'comm').read_text().strip()=='firecracker' and P(os.readlink(proc/'cwd')).is_relative_to(BASE/'fc'):found.add(int(proc.name))
                        except OSError:pass
                    return found
                stable=0;last=set();deadline=time.monotonic()+180
                while time.monotonic()<deadline:
                    current=fc_pids();stable=stable+1 if current==last and len(current)>=600 else 0;last=current
                    if stable>=5:break
                    time.sleep(1)
                assert stable>=5,'FC pool did not stabilize at >=600; no parameter forcing'
                states={}
                for pid in sorted(last):
                    proc=P('/proc',str(pid));args=(proc/'cmdline').read_bytes().decode().strip('\\0').split('\\0')
                    path=args[args.index('--api-sock')+1];path=path if path.startswith('/') else str(proc/'cwd'/path)
                    channel=socket.socket(socket.AF_UNIX);channel.settimeout(.5);conn=http.client.HTTPConnection('localhost',timeout=.5);conn.sock=channel
                    try:
                        channel.connect(path);conn.request('GET','/');response=conn.getresponse();assert response.status==200
                        state=json.loads(response.read())['state'];states[state]=states.get(state,0)+1
                    finally:conn.close()
                assert states=={'Not started':len(last)} and fc_pids()==last,'Pool has active/changing instances'
                assert api('GET','/v2/sandboxes?limit=100')==[]
                pool=sorted(last)
                STATE['stablePoolBeforeFormal']={'count':len(last),'states':states,'stableSecondsAtLeast':5}
                with (WORK/'formal-ready.json').open('x') as f:json.dump(STATE['stablePoolBeforeFormal'],f)
                deadline=time.monotonic()+45
                while not (WORK/'capture-go.json').exists():
                    assert time.monotonic()<deadline,'Capture observer did not become ready'
                    time.sleep(.05)
                assert fc_pids()==last,'FC pool changed while admitting observers'
                STATE['formalServerLogOffset']=(BASE/'logs/server.log').stat().st_size
                STATE['formalInvocationUnixNs']=time.time_ns()
'''
assert needle in w;w=w.replace(needle,replacement)
(H/'wikidata025_worker.py').write_bytes(w.encode())
root=(H/'Y_detail024.py').read_text(encoding='utf-8')
root=root.replace('import base64,collections,fcntl,hashlib,http.client,io,json,os,pathlib,pwd,signal,stat,subprocess,tarfile,time','import base64,collections,fcntl,hashlib,http.client,io,json,os,pathlib,pwd,signal,stat,subprocess,tarfile,time')
root=root.replace("old=json.loads((BASE/'deployment014/result.json').read_text())","old=json.loads((BASE/'diagnostic024/result.json').read_text())")
root=root.replace("pid==old['serverPid']","pid==old['newServerPid']")
root=root.replace("BASE/'runtime-code014/runtime_supervisor014.py'","BASE/'diagnostic024/runtime_supervisor024.py'")
root=root.replace("old['runtime_attestation']['boot_id']","json.loads((BASE/'diagnostic024/runtime-identity.json').read_text())['boot_id']")
root=root.replace("'runtime-code014/runtime_supervisor014.py'","'diagnostic024/runtime_supervisor024.py'")
root=root.replace("BASE/'diagnostic024'","BASE/'diagnostic025'").replace('runtime_supervisor024.py\',source','runtime_supervisor025.py\',source').replace("source['runtime_supervisor024.py']","source['runtime_supervisor025.py']")
# Only new launch/write paths use025; earlier exact024 guard remains unchanged.
root=root.replace("directory/'runtime_supervisor024.py'","directory/'runtime_supervisor025.py'")
root=root.replace('wikidata024_worker.py','wikidata025_worker.py').replace('24-detailed-logging.conf','25-envd-health-trace.conf')
root=root.replace("BASE/'wikidata024/result.json'","BASE/'wikidata025/result.json'").replace("BASE/'results/wikidata024","BASE/'results/wikidata025").replace('DETAIL024_RESULT=','PROBE025_RESULT=')
root=root.replace("assert logging['AENV_LOG_FORMAT']=='json' and logging['AENV_LOG_SPAN_EVENTS']=='close'","assert logging['AENV_LOG_FORMAT']=='json' and logging['AENV_LOG_SPAN_EVENTS']=='close' and 'agentenv::sandbox::envd=trace' in logging['RUST_LOG']")
needle="  with (directory/'worker.log').open('xb') as log:r=subprocess.run(args,env=worker_env,stdout=log,stderr=subprocess.STDOUT,timeout=7200)"
replacement='''  capture_dir=P('/run/jwk-aenv-y-clean-20261111/capture-code025');assert not capture_dir.exists();capture_dir.mkdir(mode=0o755);capture_dir.chmod(0o755)
  capture_script=capture_dir/'packet025.py';capture_script.write_bytes(source['packet025.py']);capture_script.chmod(0o444)
  def arp():
   lines=P('/proc/net/stat/arp_cache').read_text().splitlines();keys=lines[0].split();values=[[int(x,16) for x in line.split()] for line in lines[1:]]
   return {'entries':values[0][keys.index('entries')],**{k:sum(v[i] for v in values) for i,k in enumerate(keys) if k!='entries'}}
  def sample():
   return {'unixNs':time.time_ns(),'monotonicNs':time.monotonic_ns(),'arp':arp(),
    'netstat':P('/proc',str(newpid),'net/netstat').read_text(),'snmp':P('/proc',str(newpid),'net/snmp').read_text(),
    'cpuPressure':P('/proc/pressure/cpu').read_text(),'ioPressure':P('/proc/pressure/io').read_text(),
    'serviceCpuStat':P('/sys/fs/cgroup/system.slice',UNIT,'cpu.stat').read_text()}
  capture=None;launched=False;measurement_started=None
  with (directory/'worker.log').open('xb') as log,(directory/'samples.jsonl').open('x') as samples,(directory/'capture.log').open('xb') as capture_log:
   process=subprocess.Popen(args,env=worker_env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);deadline=time.monotonic()+7200
   try:
    while process.poll() is None:
     if (BASE/'wikidata025/formal-ready.json').exists() and not launched:
      capture_args=['nsenter','--target',str(newpid),'--net','--','setpriv','--reuid=1002','--regid=1002','--clear-groups','--bounding-set=-all,+net_raw','--inh-caps=-all,+net_raw','--ambient-caps=-all,+net_raw','--no-new-privs','/usr/bin/python3','-I','-B',str(capture_script)]
      capture=subprocess.Popen(capture_args,env=worker_env,stdout=capture_log,stderr=subprocess.STDOUT,start_new_session=True)
      ready_deadline=time.monotonic()+10
      while not (directory/'capture-ready.json').exists():
       assert capture.poll() is None and time.monotonic()<ready_deadline,'Packet capture failed before measurement'
       time.sleep(.05)
      proof=json.loads((directory/'capture-ready.json').read_text());assert proof['netns']==outcome['netns'] and proof['kernelTimestamps'] and not proof['payloadStored']
      outcome['arpBefore']=arp();measurement_started=time.time_ns();outcome['observerStartUnixNs']=measurement_started
      userfile(BASE/'wikidata025/capture-go.json',json.dumps({'captureReady':True,'unixNs':measurement_started})+'\\n')
      launched=True
     if launched:samples.write(json.dumps(sample())+'\\n');samples.flush()
     if time.monotonic()>deadline:os.killpg(process.pid,signal.SIGTERM);raise TimeoutError('Own diagnostic deadline')
     time.sleep(.2)
    r=process
   finally:
    if process.poll() is None:
     os.killpg(process.pid,signal.SIGTERM)
     try:process.wait(timeout=15)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
    if capture is not None:
     userfile(directory/'capture-stop',b'')
     try:capture.wait(timeout=10)
     except subprocess.TimeoutExpired:os.killpg(capture.pid,signal.SIGTERM);capture.wait(timeout=5)
   if launched:
    outcome['arpAfter']=arp();outcome['capture']=json.loads((directory/'capture-result.json').read_text())
'''
assert needle in root;root=root.replace(needle,replacement)
root=root.replace("('server-formal.jsonl','worker.log','runtime-identity.json','dropin-applied.conf')","('server-formal.jsonl','worker.log','runtime-identity.json','dropin-applied.conf','packet-metadata.jsonl','capture-ready.json','capture-result.json','capture.log','samples.jsonl')")
for name,body in [('runtime_supervisor025.py',s),('wikidata025_worker.py',w),('Y_probe025.py',root)]:
 ast.parse(body,feature_version=(3,11));(H/name).write_bytes(body.encode())
print('025 prepared: envd TRACE, stable >=600 all-Not-started FC pool, receive-only kernel-timestamped packet metadata, ARP/TCP counters')
