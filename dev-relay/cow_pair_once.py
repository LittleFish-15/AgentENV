"""A original: two restores, private-file isolation, layer/cache observations.

This is a preparatory observation, not the full physical sharing experiment.
Uses the already delivered, SHA-pinned v4 parent helper; no downloads at runtime.
"""
import ctypes
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
import time
import uuid

ROOT = Path('/home/jwk/agent')
BASE = ROOT/'deployments/agentenv-ae9c626-baseline'
PENDING = ROOT/'relay/cow-pair-node-a.pending.json'
H = None


def load_helper():
    path = ROOT/'cow_parent_424b012.py'
    if path.resolve(strict=True) != path:
        raise RuntimeError('Redirected helper')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != 'edc6ea585021c585fee41ea09d623f64d4df189dfa54c9af08bdab2765b16e11':
        raise RuntimeError('Existing v4 helper hash mismatch; no execution')
    spec = importlib.util.spec_from_file_location('reviewed_parent_v4', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unavailable(e):
    return {'available':False, 'error_type':type(e).__name__, 'errno':getattr(e, 'errno', None)}


def cache_file(path):
    """mincore without reading/faulting file data. Counts only this inode's cache."""
    fd = None
    try:
        H.safe(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        m = os.fstat(fd)
        H.need(stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and m.st_size <= 2*1024**3,
               'Unsupported layer type, owner or sampling size')
        page = os.sysconf('SC_PAGESIZE')
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.argtypes = [ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        libc.mmap.restype = ctypes.c_void_p
        libc.mincore.argtypes = [ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        libc.munmap.argtypes = [ctypes.c_void_p,ctypes.c_size_t]
        resident = 0
        for offset in range(0, m.st_size, 128*1024**2):
            size = min(128*1024**2, m.st_size-offset)
            address = libc.mmap(None,size,1,1,fd,offset)
            H.need(address not in (None,ctypes.c_void_p(-1).value), 'mincore mmap failed')
            try:
                vector = (ctypes.c_ubyte*((size+page-1)//page))()
                H.need(libc.mincore(address,size,vector)==0, 'mincore failed')
                resident += sum(bool(x & 1) for x in vector)
            finally:
                H.need(libc.munmap(address,size)==0, 'mincore munmap failed')
        after = os.fstat(fd)
        H.need((m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns)==
               (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns), 'Layer changed during sample')
        return {'available':True, 'path':str(path), 'dev':m.st_dev, 'inode':m.st_ino,
                'file_bytes':m.st_size, 'allocated_file_bytes':m.st_blocks*512,
                'page_bytes':page, 'resident_pages':resident, 'resident_page_bytes':resident*page,
                'scope':'stored_regular_file_pagecache_only', 'file_data_read':False,
                'atomic_snapshot':False, 'exclusive_physical_bytes_verified':False}
    except Exception as e:
        return dict(unavailable(e), path=str(path))
    finally:
        if fd is not None:
            os.close(fd)


def layer_inventory(snapshot):
    repo = BASE/'state/snapshot-store/repository'
    path = repo/'catalog/records'/(snapshot+'.json')
    record = json.loads(H.read(path))
    H.need(record.get('id')==snapshot and isinstance(record.get('committed'),dict), 'Snapshot is not committed')
    resources = record.get('resources',{})
    H.need(resources.get('cpu_count')==1 and resources.get('memory_mib')==512, 'Parent resource budget differs')
    rows = []
    for kind in ('memory','rootfs'):
        layers = record['committed'].get(kind+'_layers')
        H.need(isinstance(layers,list) and 0 < len(layers) <= 64, 'Missing or excessive snapshot layers')
        for layer in layers:
            origin = 'Managed' if kind=='memory' else next(iter(layer),'')
            value = layer if kind=='memory' else layer.get(origin,{})
            digest = value.get('digest','')
            H.need(re.fullmatch(r'sha256:[0-9a-f]{64}',digest), 'Unexpected layer digest')
            row = {'kind':kind,'origin':origin,'digest':digest,'stored_bytes_declared':value.get('size')}
            if origin=='Managed':
                row['path'] = str(repo/'managed-layers'/(digest.replace(':','_')+'.overlaybd.commit'))
            else:
                row['placement'] = 'EXTERNAL_LOCAL_CACHE_UNRESOLVED'
            rows.append(row)
    return {'snapshot_id':snapshot,'catalog_path':str(path),'resources':resources,'layers':rows,
            'record_sha256':hashlib.sha256(H.read(path)).hexdigest(),
            'content_hashes_verified':False}


def descendant_firecrackers(main_pid, proc_root=Path('/proc')):
    """Walk this service's process tree; no assumption about cgroup v1/v2 mounts."""
    queue=[main_pid];seen=set();found=[]
    while queue:
        pid=queue.pop()
        if pid in seen: continue
        seen.add(pid)
        H.need(len(seen)<=128,'Service process tree exceeds bound')
        proc=proc_root/str(pid)
        try:
            fields=(proc/'stat').read_text().rsplit(')',1)[1].split()
            ticks=fields[19]
            status=(proc/'status').read_text()
            uids=re.search(r'^Uid:\s+(.+)$',status,re.M)
            H.need(uids and list(map(int,uids[1].split()))==[1204]*4,'Unexpected descendant UID')
            if (proc/'comm').read_text().strip()=='firecracker': found.append(pid)
            tasks=list((proc/'task').iterdir())
            H.need(len(tasks)<=512,'Thread enumeration exceeds bound')
            for task in tasks:
                try: children=(task/'children').read_text().split()
                except FileNotFoundError: continue
                H.need(len(children)<=128,'Child enumeration exceeds bound')
                for child in children:
                    H.need(child.isdecimal(),'Invalid child PID')
                    try:
                        parent=(proc_root/child/'stat').read_text().rsplit(')',1)[1].split()[1]
                    except FileNotFoundError: continue
                    if int(parent)==pid: queue.append(int(child))
            H.need((proc/'stat').read_text().rsplit(')',1)[1].split()[19]==ticks,'Process changed during tree walk')
        except FileNotFoundError:
            continue
    return sorted(found)


def process_observations():
    """Only the approved original unit; no cmdline, environment or memory reads."""
    result = {'scope':'original_unit_firecracker_processes', 'processes':[]}
    try:
        identity=H.runtime_pid()
        pids = descendant_firecrackers(identity[0])
        result['discovery']='bounded_service_descendant_tree_no_cgroup_mount_assumption'
        for pid in pids:
            value=str(pid)
            proc = Path('/proc')/value
            try:
                if proc.joinpath('comm').read_text().strip() != 'firecracker':
                    continue
                status = proc.joinpath('status').read_text()
                uids = re.search(r'^Uid:\s+(.+)$',status,re.M)
                H.need(uids and list(map(int,uids[1].split()))==[1204]*4, 'Unexpected Firecracker UID')
                ticks = proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]
                item = {'pid':int(value),'start_ticks':ticks,'guest_ram_attribution':'NOT_CONFIRMED'}
                try:
                    with proc.joinpath('smaps').open() as f:
                        raw = f.read(4*1024**2+1)
                    H.need(len(raw)<=4*1024**2, 'smaps limit exceeded')
                    # Preserve VMA identity and accounting, never process memory contents.
                    selected = [x for x in raw.splitlines() if re.match(r'^[0-9a-f]+-[0-9a-f]+\s',x)
                                or re.match(r'^(Size|Rss|Pss|Shared_Clean|Shared_Dirty|Private_Clean|Private_Dirty|Anonymous|Swap|KernelPageSize|MMUPageSize|VmFlags):',x)]
                    item['smaps'] = {'available':True,'selected_lines':selected,'scope':'VMAs_not_yet_classified_as_Guest_RAM'}
                except Exception as e:
                    item['smaps'] = unavailable(e)
                H.need(proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]==ticks, 'PID changed during sample')
                result['processes'].append(item)
            except FileNotFoundError:
                result.setdefault('exited_during_sample',[]).append(int(value))
        result['available'] = True
        H.need(H.runtime_pid()==identity,'Service changed during process observation')
    except Exception as e:
        result.update(unavailable(e))
    return result


def summarize_sample(files, layers, processes):
    def totals(rows):
        unique={(x['dev'],x['inode']):x for x in rows if x.get('available')}
        missing=sum(not x.get('available') for x in rows)
        def total(key): return None if missing and not unique else sum(x[key] for x in unique.values())
        return {'resident_regular_file_page_bytes':total('resident_page_bytes'),
                'stored_file_bytes':total('file_bytes'),
                'allocated_file_bytes':total('allocated_file_bytes'),
                'sampled_unique_inodes':len(unique),
                'unavailable_files':missing,'complete_for_listed_regular_files':missing==0,
                'totals_cover_observed_files_only':True}
    summary=totals(files.values())
    summary['by_kind']={}
    for kind in ('memory','rootfs'):
        paths={r['path'] for r in layers if r['kind']==kind and 'path' in r}
        summary['by_kind'][kind]=totals([files[p] for p in paths])
        summary['by_kind'][kind]['unresolved_external_layers']=sum(r['kind']==kind and 'path' not in r for r in layers)
    summary['processes']=dict(processes,processes=[])
    for process in processes.get('processes',[]):
        item={k:v for k,v in process.items() if k!='smaps'}
        smaps=process.get('smaps',{})
        item['smaps']={k:v for k,v in smaps.items() if k!='selected_lines'}
        if smaps.get('available'):
            sums={}
            for line in smaps['selected_lines']:
                match=re.fullmatch(r'(Rss|Pss|Shared_Clean|Shared_Dirty|Private_Clean|Private_Dirty):\s+(\d+) kB',line)
                if match: sums[match[1]]=sums.get(match[1],0)+int(match[2])*1024
            item['smaps'].update(whole_process_bytes=sums,guest_ram_attribution=False)
        summary['processes']['processes'].append(item)
    return summary


class Api:
    def __init__(self):
        self.original = H.Api()
        self.key = self.original.key
        self.identity = self.original.identity

    def call(self, method, path, data=None, timeout=20):
        if (method,path) not in (('POST','/sandboxes'),('GET','/v2/sandboxes?limit=3')):
            return self.original.call(method,path,data,timeout)
        H.need(H.runtime_pid()==self.identity,'Original service changed; no request sent')
        c = http.client.HTTPConnection('127.0.0.1',18080,timeout=timeout)
        try:
            c.request(method,path,body=json.dumps(data).encode() if data else None,
                      headers={'X-API-Key':self.key,'Content-Type':'application/json'})
            r = c.getresponse(); raw = r.read(1024**2+1)
            H.need(len(raw)<=1024**2 and not r.getheader('x-next-token'),'Response too large or inventory incomplete')
            return r.status,json.loads(raw) if raw else None
        finally:
            c.close()


GUEST = '''import hashlib,importlib,json,os,sys
from pathlib import Path
os.chdir('/pypika');importlib.import_module('pypika')
mode,name,token=sys.argv[1:]
p=Path('/pypika')/name
if mode=='absent':
    assert not p.exists(),'Unexpected private file visible'
elif mode=='write':
    block=hashlib.sha256(token.encode()).digest()*2048
    with p.open('xb') as f:
        for i in range(64): f.write(block)
        f.flush();os.fsync(f.fileno())
elif mode=='check':
    block=hashlib.sha256(token.encode()).digest()*2048
    assert p.stat().st_size==4194304
    with p.open('rb') as f:
        for i in range(64): assert f.read(len(block))==block
        assert f.read(1)==b''
else: raise ValueError('Unexpected mode')
print('COW_PAIR_GUEST_OK')
'''


def run(api, work, report):
    layers = report['parent_layers']['layers']
    env = {'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
           'PATH':str(BASE/'native/bin')+':/usr/bin:/bin',
           'LD_LIBRARY_PATH':str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib'),
           'TMPDIR':str(work/'tmp'),'XDG_CONFIG_HOME':str(work/'config')}
    (work/'tmp').mkdir(); (work/'config/aenv').mkdir(parents=True)
    credential = work/'config/aenv/credentials'
    credential.write_text('url = "http://127.0.0.1:18080"\napi_key = '+json.dumps(api.key)+'\n')
    def persist(): H.save(PENDING,report)
    def sample(phase):
        print('PHASE='+phase,flush=True)
        samples=[]
        for _ in range(3):
            files={}
            for row in layers:
                if 'path' in row and row['path'] not in files:
                    files[row['path']]=cache_file(Path(row['path']))
            samples.append({'unix':time.time(),'stored_layer_files':list(files.values()),
                            'processes':process_observations()})
            time.sleep(1)
        H.save(work/(phase+'.json'),samples)
        # File bytes can be deduplicated by dev/inode, but do not add this
        # number to Guest RSS: mappings and device cache may overlap.
        summary=[]
        for s in samples:
            summary.append(summarize_sample({f['path']:f for f in s['stored_layer_files']},layers,s['processes']))
        report['samples'][phase]={'file':str(work/(phase+'.json')),'samples':summary,
                                 'scope':'managed_stored_layer_files_not_total_host_cache'}
        persist()
    def guest(sid,mode,token):
        log=work/('guest-'+sid+'-'+mode+'-'+uuid.uuid4().hex[:6]+'.log')
        H.checked_process([BASE/'bin/aenv','exec',sid,'python','-c',GUEST,mode,
                           '.cow-pair-'+report['run_id'],token],env,log,60)
        H.need(b'COW_PAIR_GUEST_OK' in H.read(log),'Guest check did not confirm')
    try:
        status,rows=api.call('GET','/v2/sandboxes?limit=3')
        H.need(status==200 and rows==[],'Original Runtime not empty; no experiment started')
        sample('T0_parent_only')
        for number in (1,2):
            report['create_calls']+=1;report['create_outcome_uncertain']=True;persist()
            status,body=api.call('POST','/sandboxes',{
                'templateID':report['snapshot_id'],'timeout':900,'autoPause':False,'secure':True,
                'allow_internet_access':False,'metadata':{'cow_pair_run':report['run_id'],'cow_pair_child':str(number)}},timeout=300)
            if status!=201:
                report['create_error']=H.error_summary(body,api.key)
            H.need(status==201 and isinstance(body,dict),'Restore failed; no retry')
            sid=body.get('sandboxID')
            H.need(isinstance(sid,str) and H.ID.fullmatch(sid),'Restore ID missing; keep uncertain receipt')
            report['children'].append(sid);report['create_outcome_uncertain']=False;persist()
            guest(sid,'absent','unused')
            sample('T'+str(number)+'_restored')
        a,b=report['children']
        guest(a,'write','A-'+report['run_id']);guest(a,'check','A-'+report['run_id']);guest(b,'absent','unused')
        sample('T3_child1_private_file')
        guest(b,'write','B-'+report['run_id']);guest(b,'check','B-'+report['run_id']);guest(a,'check','A-'+report['run_id'])
        report['private_file_isolation_verified']=True
        sample('T4_both_private_files')
    finally:
        for sid in reversed(report['children']):
            try:
                logs=H.collect_fc_logs(sid,env,api.key)
                H.save(work/('firecracker-'+sid+'.json'),logs)
                report.setdefault('firecracker_logs',{})[sid]={
                    'file':str(work/('firecracker-'+sid+'.json')),
                    'files':{name:{k:v for k,v in item.items() if k!='tail'} for name,item in logs['files'].items()}}
            except Exception as e:
                report.setdefault('log_errors',[]).append(dict(unavailable(e),sandbox_id=sid))
            try:
                status,detail=api.call('GET','/sandboxes/'+sid)
                if status!=404:
                    H.need(status==200 and detail.get('metadata',{}).get('cow_pair_run')==report['run_id'],
                           'Ownership marker differs; no delete')
                    H.need(api.call('DELETE','/sandboxes/'+sid,timeout=90)[0] in (200,204,404),'Delete not acknowledged')
                    H.need(api.call('GET','/sandboxes/'+sid)[0]==404,'Child still visible')
                report['released_children'].append(sid)
            except Exception as e:
                report.setdefault('cleanup_errors',[]).append(dict(unavailable(e),sandbox_id=sid))
            try: persist()
            except Exception as e: report.setdefault('receipt_errors',[]).append(unavailable(e))
        credential.unlink()
        report['temporary_cli_credentials_removed']=not credential.exists()
        sample('T5_after_cleanup')


def main():
    global H
    if not (socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204
            and os.getgid()==os.getegid()==1205):
        raise RuntimeError('A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    if len(caps)!=4 or any(int(v,16) for v in caps): raise RuntimeError('Capability-free collector required')
    H=load_helper();os.umask(0o077)
    import fcntl
    with open(H.safe(ROOT/'relay/cow-pair-node-a.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        H.need(not PENDING.exists(),'Pair receipt exists; preserve it, do not repeat this experiment')
        work=Path(tempfile.mkdtemp(prefix='node-a-cow-pair-',dir=H.safe(ROOT/'relay/reports')))
        report={'revision':'cow-pair-prepare-v1','report_directory':str(work),'run_id':uuid.uuid4().hex,
                'node':'node-a','SDK_called':False,'services_modified':False,'B_accessed':False,
                'children':[],'released_children':[],'create_calls':0,'create_calls_limit':2,
                'create_outcome_uncertain':False,'private_file_isolation_verified':False,'samples':{},
                'physical_shared_ram_bytes':None,'physical_shared_ram_ratio':None,
                'rootfs_device_pagecache_bytes':None,'memory_device_pagecache_bytes':None,
                'full_cow_acceptance':'PENDING_SCOPED_RAM_DEVICE_CACHE_AND_WRITE_MEASUREMENTS',
                'colleague_full_replay_executed':False}
        try:
            prior=json.loads(H.read(H.PENDING))
            H.need(prior.get('status')=='ORIGINAL_PARENT_SNAPSHOT_READY_PARENT_RELEASED'
                   and prior.get('parent_deleted') is True and not prior.get('create_outcome_uncertain'), 'Parent not ready')
            snapshot=prior.get('snapshot_id')
            H.need(isinstance(snapshot,str) and H.ID.fullmatch(snapshot),'Parent snapshot identity missing')
            report['snapshot_id']=snapshot
            report['parent_layers']=layer_inventory(snapshot)
            api=Api();H.need(api.call('GET','/health')[0]==204,'Original health failed')
            run(api,work,report)
            H.need(report['private_file_isolation_verified'] and len(report['released_children'])==2,
                   'Pair isolation or cleanup not completed')
            report['status']='ORIGINAL_PAIR_RESTORE_FILE_ISOLATION_COMPLETED_FULL_MEASUREMENT_PENDING'
        except Exception as e:
            report.update(status='STOPPED_PAIR_PREPARATION_REVIEW_RECEIPT',error_type=type(e).__name__,
                          error=str(e) if type(e) is RuntimeError else 'Inspect bounded report diagnostics')
            if isinstance(e,H.ChildFailure): report['child_diagnostics']=e.diagnostics
        H.save(work/'return.json',report)
        if report['create_calls']: H.save(PENDING,report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 1 if report['status'].startswith('STOPPED') else 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_PAIR_ENTRY','error_type':type(e).__name__,
              'error':str(e) if type(e) is RuntimeError else 'Entry check failed'}));print('END_RETURN_REPORT')
        raise SystemExit(1)
