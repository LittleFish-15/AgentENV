"""Read-only config/tool discovery and offline 128/256KiB footprint modelling.

Does not execute an unknown CLI, instantiate a cache backend, query a service,
change configuration, touch lower payloads, or create Guests. Metadata checkpoint
counters are not live request hit rates or kernel page-cache hit rates.
"""
import hashlib, importlib.util, json, os, re, shutil, stat, struct, sys, time
from pathlib import Path

ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
RUN=ROOT/'relay/reports/node-a-cow4-global-_0s927uo'
PIN='4dc486145378f945df9a285e9bee0fe7368c147a67699b3343ce47bc8200ceb1'


def need(ok,why):
    if not ok:raise RuntimeError(why)


def read_owned(path,limit):
    need(path.resolve(strict=True)==path,'Redirected diagnostic input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_size<=limit,'Input owner/type/size differs')
        raw=f.read(limit+1);after=os.fstat(f.fileno())
        need(len(raw)<=limit and (before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns),'Input changed while reading')
        return raw


def crc32c(raw):
    table=[]
    for n in range(256):
        v=n
        for _ in range(8):v=(v>>1)^0x82f63b78 if v&1 else v>>1
        table.append(v)
    c=0xffffffff
    for b in raw:c=table[(c^b)&255]^(c>>8)
    return c^0xffffffff


def metadata_header(raw):
    need(len(raw)>=64,'Metadata too short')
    magic,version,size,block,last,hits,misses,refills=struct.unpack_from('<II6Q',raw)
    need(magic==0x4f424348 and version==1,'Not this Rust cache metadata format')
    need(crc32c(raw[:-4])==struct.unpack_from('<I',raw,len(raw)-4)[0],'Metadata checksum differs')
    need(size>0 and block>=4096 and block&(block-1)==0,'Invalid cache geometry')
    keylen=struct.unpack_from('<I',raw,56)[0];need(60+keylen<=len(raw)-4,'Invalid cache key length')
    return {'source_bytes':size,'block_bytes':block,'last_access_unix_ns':last,
            'hits':hits,'misses':misses,'refills':refills,'crc32c_verified':True,
            'cache_key_output':False,'bitmap_cardinality_decoded':False}


def inspect_cache(path):
    result={'path':str(path),'metadata_only':True,'live_hit_rate':None,'kernel_pagecache_hit_rate':None}
    try:
        need(path.resolve(strict=True)==path and path.is_relative_to(BASE),'Cache path outside scoped deployment')
        children=list(path.iterdir());result['children_count']=len(children)
        entries=[p for p in children if re.fullmatch('[0-9a-f]{64}',p.name) and not p.is_symlink() and p.is_dir()]
        result['rust_entry_directories']=len(entries);result['sample_truncated']=len(entries)>128;rows=[]
        for entry in sorted(entries)[:128]:
            p=entry/'meta.bin'
            try:rows.append(dict(entry_id=entry.name,checkpoint_file_mtime_ns=p.stat().st_mtime_ns,**metadata_header(read_owned(p,1024**2))))
            except Exception as e:rows.append({'entry_id':entry.name,'error_type':type(e).__name__,'reason':str(e)})
        result['entries']=rows;result['scope']='Persisted historical checkpoints; no live cache attach and no experiment attribution'
    except Exception as e:result.update(error_type=type(e).__name__,reason=str(e))
    return result


def config_inventory():
    import tomllib
    cfg=tomllib.loads(read_owned(BASE/'config/runtime.toml',65536).decode())
    home=Path(cfg['home_path']);need(home.is_absolute() and home.is_relative_to(BASE),'Unexpected home path')
    rawpath=cfg.get('ublk',{}).get('overlaybd',{}).get('global_config_path','$AENV_HOME/overlaybd/overlaybd-global.json')
    path=Path(rawpath.replace('$AENV_HOME',str(home)))
    if not path.is_absolute():path=BASE/'config'/path
    path=Path(os.path.abspath(path));need(path.is_relative_to(BASE),'Global config outside deployment')
    obj=json.loads(read_owned(path,1024**2));cache=obj.get('cacheConfig',{})
    result={'global_config_path':str(path),'cacheConfig':{k:cache.get(k) for k in ('cacheType','cacheDir','cacheSizeGB','refillSize','blockSize')},
            'ioEngine':obj.get('ioEngine'),'download_enable':obj.get('download',{}).get('enable'),
            'credential_fields_output':False}
    if isinstance(cache.get('cacheDir'),str):result['cache_metadata']=inspect_cache(Path(cache['cacheDir']))
    return result


def footprint(pages,files,cell_bytes):
    need(cell_bytes in (131072,262144),'Unexpected model cell')
    cells={(d,i,n//(cell_bytes//4096)) for d,i,n in pages}
    capacity=sum(min(cell_bytes//4096,(files[(d,i)]['file_bytes']+4095)//4096-b*(cell_bytes//4096))*4096 for d,i,b in cells)
    requested=len(pages)*4096
    need(0<=requested<=capacity,'Invalid model footprint')
    return {'cell_bytes':cell_bytes,'distinct_cells_touched':len(cells),'rounded_request_page_bytes':requested,
            'touched_cell_capacity_bytes':capacity,'request_page_coverage_of_model_cells':requested/capacity if capacity else None,
            'actual_refill_bytes':None,'actual_prefetch_efficiency':None,'actual_hit_rate':None}


def trace_model():
    owner=json.loads(read_owned(RUN/'return.json',8*1024**2))
    need(owner['run_id']=='de320ed9ad9b4b8b9aa037ee9d4dcc8e' and owner['all_cohort_guests_released'] and owner['root_session']['observer_exit_confirmed'],'Completed owned run required')
    path=ROOT/'cow4_global_cache_12323ca.py';raw=read_owned(path,4*1024**2)
    need(hashlib.sha256(raw).hexdigest()==PIN,'Pinned accounting module differs')
    spec=importlib.util.spec_from_file_location('cache_inspect_pinned',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    bindings={};files={};saved_image_configs=[]
    for b in owner['bindings']:
        bindings[b['source']]={'sandbox_id':b['sandbox_id'],'template_id':b['template_id'],
            'lower_keys':{(f['dev'],f['inode']) for f in b['lowers']},'upper_keys':{(f['dev'],f['inode']) for f in b['uppers']}}
        for f in b['lowers']:files[(f['dev'],f['inode'])]=f
        try:
            image_path=Path(b['source']);need(image_path.is_relative_to(ROOT/'r/fc-a-base'),'Image config outside historical runtime scope')
            image=json.loads(read_owned(image_path,2*1024**2))
            saved_image_configs.append({'sandbox_id':b['sandbox_id'],'available':True,
                'acceleration_layer':image.get('accelerationLayer',False),
                'record_trace_path_configured':bool(image.get('recordTracePath')),
                'local_lower_descriptors':sum(bool(x.get('file')) for x in image.get('lowers',[]))})
        except Exception as e:saved_image_configs.append({'sandbox_id':b['sandbox_id'],'available':False,'error_type':type(e).__name__})
    need(len(bindings)==8 and len(files)==46 and sum(f['file_bytes'] for f in files.values())<16*1024**3,'Unexpected trace scope')
    status=json.loads(read_owned(RUN/'observer/trace.status.json',65536))
    need(status['pid']==owner['observer_identity'][0],'Observer status PID differs')
    path=RUN/'observer/trace.jsonl'
    need(path.resolve(strict=True)==path,'Redirected trace')
    before=path.stat();need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_size<=256*1024**2,'Trace size/owner differs')
    with path.open(encoding='utf-8') as stream:
        sets,audit=m.ACCOUNTING.read_sets(stream,status,bindings,owner['trajectory_windows_monotonic_ns'],files,
            'c553d631d18a01ce5511dec12e50a1a58817c92181d20f1443f17561f87a67ce',window_semantics='completion')
    after=path.stat();need((before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns),'Trace changed')
    need(audit['direct_lower_reads']==0,'Direct lower reads excluded from this model')
    rows=[]
    for tid in owner['template_lowers']:
        jobs=[j for j in owner['jobs'] if j['template_id']==tid];need(len(jobs)==2,'Pair differs')
        pages=sets[jobs[0]['sandbox_id']]|sets[jobs[1]['sandbox_id']]
        rows.append({'template_id':tid,'trajectory':jobs[0]['instance_id'],'sandbox_ids':[j['sandbox_id'] for j in jobs],
                     'models':[footprint(pages,files,n) for n in (131072,262144)]})
    union=set().union(*sets.values())
    return {'run_id':owner['run_id'],'audit':audit,'templates':rows,'historical_image_configs':saved_image_configs,
            'global_models':[footprint(union,files,n) for n in (131072,262144)],
            'scope':'Cumulative successful host backing-request pages over replay; includes any format/read coalescing already below the probe',
            'loaded_chunks_not_observed':True,'kernel_read_ahead_not_measured':True,
            'finite_cache_eviction_not_simulated':True,'model_is_not_a_128k_runtime_test':True}


def main():
    need(os.name=='posix' and os.getuid()==os.geteuid()==1204 and os.uname().nodename=='server1','A ordinary jwk only')
    result={'revision':'cache-prefetch-inspect-v1','hostname':os.uname().nodename,'runtime_modified':False,
            'services_modified':False,'SDK_called':False,'Guest_created':False,'lower_payload_read':False,
            'unknown_cli_executed':False,'started_unix':time.time()}
    paths=[shutil.which('overlaybd-tools')]
    paths += [str(d/'overlaybd-tools') for d in (BASE/'bin',BASE/'deps/overlaybd/bin',Path('/usr/bin'),Path('/usr/local/bin')) if (d/'overlaybd-tools').exists()]
    result['overlaybd_tools_candidates']=sorted(set(p for p in paths if p))
    for key,fn in [('configuration',config_inventory),('historical_trace_models',trace_model)]:
        try:result[key]=fn()
        except Exception as e:result[key]={'error_type':type(e).__name__,'reason':str(e)}
    result['finished_unix']=time.time();result['status']='READONLY_CACHE_PATH_AND_MODEL_INSPECTION_RETURNED'
    print('BEGIN_RETURN_REPORT');print(json.dumps(result,indent=2));print('END_RETURN_REPORT')


if __name__=='__main__':main()
