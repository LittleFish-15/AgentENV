"""Read-only eligibility and service inventory. No benchmark/service mutation."""
import hashlib,http.client,json,os,platform,re,subprocess,sys,time
from pathlib import Path
P=Path

def command(args,seconds=10):
    try:
        r=subprocess.run(args,capture_output=True,text=True,timeout=seconds)
        return {'code':r.returncode,'stdout':r.stdout[:24000],'stderr':r.stderr[:1200]}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error':type(e).__name__}

def scan():
    out={}
    for p in P('/proc').glob('[0-9]*'):
        try:
            s=(p/'stat').read_text();v=s[s.rfind(')')+2:].split();name=s[s.find('(')+1:s.rfind(')')]
            args=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
            relevant=name in ('server','agentenv','firecracker','lat_probe','bw_probe','multiload','multichase','lat_mem_rd','stream','stress-ng','perf') or any(t in args for t in ('agent_replay.runner','spotbox_monitor.py','hcollect.py','collect_metrics.sh','start_aenv.sh'))
            out[int(p.name)]={'name':name,'state':v[0],'ppid':int(v[1]),'ticks':int(v[11])+int(v[12]),'start':int(v[19]),'uid':p.stat().st_uid,'relevant':relevant,'fingerprint':hashlib.sha256((p/'cmdline').read_bytes()).hexdigest()}
        except (OSError,ValueError,IndexError):pass
    return out

def main():
    m=sys.argv[1];assert m in ('X','Y') and os.geteuid()==0
    result={'machine':m,'hostname':platform.node(),'arch':platform.machine(),'kernel':platform.release(),'boot':P('/proc/sys/kernel/random/boot_id').read_text().strip(),'readOnly':True,'benchmarksStarted':False,'observedUnix':time.time(),'services':[]}
    snap=scan();start=time.monotonic();time.sleep(4);after=scan();dt=time.monotonic()-start;hz=os.sysconf('SC_CLK_TCK')
    active=[]
    for pid,r in after.items():
        old=snap.get(pid)
        if not old or old['start']!=r['start']:continue
        cores=max(0,r['ticks']-old['ticks'])/hz/dt
        if r['relevant'] or cores>=.05:
            item={**r,'pid':pid,'cpuCores':round(cores,4)}
            if r['name'] in ('server','agentenv'):
                p=P('/proc')/str(pid)
                try:
                    item['exe']=os.readlink(p/'exe');item['cwd']=os.readlink(p/'cwd');item['cgroup']=(p/'cgroup').read_text()
                    allowed={'AENV_HOME_PATH','AENV_RUNTIME_PATH','AENV_LOG_FORMAT','AENV_LOG_SPAN_EVENTS','RUST_LOG','API_ADDR'}
                    item['settings']={k:v for x in (p/'environ').read_bytes().split(b'\0') if b'=' in x for k,v in [x.decode(errors='replace').split('=',1)] if k in allowed}
                except OSError:pass
            active.append(item)
    result['processes']=sorted(active,key=lambda r:r['cpuCores'],reverse=True)
    result['sampleSeconds']=dt
    result['host']={x:P('/proc',x).read_text() for x in ('loadavg','meminfo','pressure/cpu','pressure/io','pressure/memory')}
    units=command(['systemctl','list-units','--all','--type=service','--plain','--no-legend'])
    for line in units.get('stdout','').splitlines():
        parts=line.split();name=next((x for x in parts if x.endswith('.service')),'')
        if name and any(x in name.lower() for x in ('aenv','agentenv','cxd')):
            result['services'].append(command(['systemctl','show',name,'-p','Id,ActiveState,MainPID,ControlGroup,FragmentPath,ExecStart']))
    home=P('/data/jwk/aenv-baseline-20261103') if m=='X' else P('/home/jwk/aenv-y-clean-20261111')
    unit='jwk-aenv-baseline-1103.service' if m=='X' else 'jwk-aenv-y-clean-20261111.service'
    result['target']={'home':str(home),'unit':unit,'homeExists':home.is_dir(),'unitInfo':command(['systemctl','show',unit,'-p','Id,ActiveState,MainPID,ControlGroup,ExecStart'])}
    for folder in ('build/target/release/server','config/runtime.toml','runtime-code-v1/runtime_supervisor.py'):
        p=home/folder
        if p.is_file() and p.stat().st_size<200000000:
            result['target'].setdefault('files',{})[folder]={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    for name in ('/sys/devices/system/node/online','/sys/kernel/mm/transparent_hugepage/enabled','/proc/sys/kernel/numa_balancing'):
        p=P(name)
        if p.is_file():result[name]=p.read_text().strip()
    result['tools']={x:command(['sh','-c','command -v '+x]) for x in ('gcc','cc','go','nsenter','setpriv','perf','udevadm')}
    result['tracefs']={}
    for root in (P('/sys/kernel/tracing'),P('/sys/kernel/debug/tracing')):
        p=root/'available_events'
        if p.is_file():
            result['tracefs']={'path':str(root),'events':[x for x in p.read_text().splitlines() if any(t in x for t in ('block_rq_issue','block_rq_complete','sched_process_exit','mm_filemap'))]};break
    result['old055']={}
    for name in ('progress.json','result.json'):
        p=P('/home/jwk/lifecycle-counters-20261117-'+m+'-055')/name
        if p.is_file():
            d=json.loads(p.read_text());result['old055'][name]={k:d.get(k) for k in ('stage','success','error','loggingRestored','restoreError','finalInventoryCount')}
    print(json.dumps(result,separators=(',',':')),flush=True)

if __name__=='__main__':main()
