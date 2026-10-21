"""Read-only A/original inventory for a 55-template, 110-Guest continuous run.

No Guest creation, template download, SDK call, service change or elevation.
Records capacity without treating configured RAM as measured resident usage.
"""
import http.client,json,os,re,stat,subprocess,tempfile
from pathlib import Path
ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
UNIT='jwk-aenv-ae9c626-node-a.service'
LIMIT=2*1024**2

def need(ok,why):
    if not ok:raise RuntimeError(why)

def owned(path,limit=LIMIT):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Unexpected/redirected project file')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        m=os.fstat(f.fileno());need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size<=limit,'Unexpected input metadata')
        raw=f.read(limit+1);need(len(raw)==m.st_size,'Input changed');return raw

def service():
    p=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--property=LoadState,ActiveState,SubState,MainPID,User,Group,ControlGroup,MemoryMax,MemoryHigh,TasksMax'],capture_output=True,text=True,timeout=10,check=True)
    data=dict(s.split('=',1) for s in p.stdout.splitlines() if '=' in s)
    pid=int(data.get('MainPID') or 0)
    if pid:
        try:data['start_ticks']=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
        except OSError:data['start_ticks']=None
    return data

def projection(rows,kind):
    need(isinstance(rows,list) and len(rows)<=1000,'Unexpected API inventory')
    allowed={'templates':('templateID','buildID','buildStatus','cpuCount','memoryMB','diskSizeMB'),
             'snapshots':('snapshotID',),'sandboxes':('sandboxID','templateID','state','cpuCount','memoryMB','diskSizeMB')}[kind]
    result=[]
    for row in rows:
        need(isinstance(row,dict),'Unexpected API item')
        value={k:row[k] for k in allowed if k in row and isinstance(row[k],(str,int,bool,type(None)))}
        if kind=='templates':
            for name in ('aliases','names'):
                if isinstance(row.get(name),list):value[name]=[s for s in row[name] if isinstance(s,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,200}',s)]
        result.append(value)
    return result

def api(key,path,kind=None):
    need(path in ('/health','/v2/templates','/snapshots?limit=100','/v2/sandboxes?limit=100'),'Unexpected route')
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=10)
    try:
        c.request('GET',path,headers={'X-API-Key':key});r=c.getresponse();raw=r.read(LIMIT+1)
        need(len(raw)<=LIMIT,'API response exceeds limit')
        result={'http_status':r.status,'complete':not bool(r.getheader('x-next-token'))}
        if kind and r.status==200:result['items']=projection(json.loads(raw),kind)
        return result
    except (OSError,http.client.HTTPException,ValueError) as e:return {'error_type':type(e).__name__}
    finally:c.close()

def memory_info(text):
    values={}
    for line in text.splitlines():
        match=re.fullmatch(r'(MemTotal|MemAvailable|SwapTotal|SwapFree|Cached|SReclaimable|Dirty|Writeback):\s+(\d+) kB',line)
        if match:values[match[1]+'_bytes']=int(match[2])*1024
    return values

def cgroups(control_group):
    # Read only this unit and its ancestors; no discovery of other units.
    if not control_group:return {'available':False,'reason':'NO_ACTIVE_CONTROL_GROUP'}
    need(control_group.startswith('/') and '..' not in control_group.split('/'),'Invalid control group')
    root=Path('/sys/fs/cgroup');current=root/control_group.lstrip('/');rows=[]
    need(current.is_relative_to(root),'Cgroup outside hierarchy')
    for _ in range(16):
        row={'path':str(current)}
        for name in ('memory.max','memory.high','memory.current','pids.max','pids.current','cpuset.cpus.effective'):
            try:
                raw=(current/name).read_text()[:4096].strip()
                row[name]=int(raw) if raw.isdecimal() else raw if raw=='max' or name=='cpuset.cpus.effective' else 'UNRECOGNIZED'
            except OSError:row[name]=None
        rows.append(row)
        if current==root:break
        current=current.parent
    return {'available':any(r['memory.max'] is not None for r in rows),'ancestors':rows}

def main():
    need(os.getuid()==os.geteuid()==1204 and os.uname().nodename=='server1','A/server1 ordinary jwk required')
    caps=dict(s.split(':',1) for s in Path('/proc/self/status').read_text().splitlines() if ':' in s)
    need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free preflight required')
    os.umask(0o077);reports=ROOT/'relay/reports';need(reports.resolve(strict=True)==reports,'Reports directory differs')
    work=Path(tempfile.mkdtemp(prefix='node-a-cow55-preflight-',dir=reports))
    r={'revision':'cow55-original-preflight-v1','report_directory':str(work),'mode':'continuous','implementation':'original',
       'requested_templates':55,'sandboxes_per_template':2,'requested_simultaneous_sandboxes':110,
       'memory_mib_per_template_from_colleague_script':4096,'configured_total_guest_ram_bytes':110*4096*1024**2,
       'configured_RAM_is_resident_measurement':False,'template_selection_confirmed':False,
       'Guest_created':False,'SDK_called':False,'services_modified':False,'images_downloaded':False,'B_accessed':False,
       'ready_for_110_Guest_launch':False,'status':'STOPPED_COW55_PREFLIGHT'}
    try:
        before=service();r['original_service']=before
        key=owned(BASE/'config/api-key',1024).decode().strip();need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',key),'Unexpected key format; value withheld')
        for name,path in [('health','/health'),('templates','/v2/templates'),('snapshots','/snapshots?limit=100'),('sandboxes','/v2/sandboxes?limit=100')]:
            r[name]=api(key,path,None if name=='health' else name)
        r['host_memory']=memory_info(Path('/proc/meminfo').read_text())
        r['online_cpus']=os.cpu_count()
        fs=os.statvfs(ROOT);r['filesystem']={'available_bytes':fs.f_bavail*fs.f_frsize,'readonly':bool(fs.f_flag&os.ST_RDONLY)}
        r['unit_cgroups']=cgroups(before.get('ControlGroup',''))
        r['machine']=os.uname().machine
        text=owned(BASE/'config/runtime.toml',65536).decode()
        match=re.search(r'(?ms)^\[firecracker\]\s*\n(.*?)(?=^\[|\Z)',text)
        r['firecracker_settings']={} if not match else {k:json.loads(v) for k,v in re.findall(r'(?m)^(work_dir|serial_dir|log_level)\s*=\s*("[^"\n]*")\s*$',match[1])}
        r['regctl_available']=(BASE/'deps/regctl/v0.11.5/regctl').is_file()
        r['original_process_unchanged']=service()==before;need(r['original_process_unchanged'],'Original unit changed during read')
        r['status']='COW55_ORIGINAL_CAPACITY_AND_INPUTS_OBSERVED_NO_GUEST'
        r['remaining_gates']=['Exact verified-135 selection and ARM64 image digests','Template build/CPU settings alignment',
                              'Capacity and disk budget review before launch','Scoped collector and bounded lifecycle controller']
    except Exception as e:r.update(error_type=type(e).__name__,reason=str(e))
    (work/'return.json').write_text(json.dumps(r,indent=2)+'\n')
    print('BEGIN_RETURN_REPORT');print(json.dumps(r,indent=2));print('END_RETURN_REPORT')
    return 0 if r['status'].startswith('COW55_ORIGINAL_CAPACITY') else 1

if __name__=='__main__':raise SystemExit(main())
