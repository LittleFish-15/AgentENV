"""Single ordinary-user entry and one literal root supervisor for two runs.
Public helpers are embedded by make_packet.py; old executable packets are reused
only after their exact hashes match. No automatic root execution or SSH.
"""
import argparse,base64,hashlib,importlib.util,json,os,pprint,re,socket,stat,struct,sys,tempfile,time,types,uuid
from pathlib import Path
ROOT=Path('/home/jwk/agent');STATE=ROOT/'relay/cow4-memory-pair-node-a.pending.json'
PACKETS={256:('cow4_original_256_recheck_13c6b72.py','7fc663e28faddcab982e26f144a084afaccb730344125abde00c668e037c6679'),
         64:('cow4_original_io64_once_d4aae57.py','44c707e7bed85c5458d32f08cf763c3201ee0dda617e794f752752d3f8839d00')}


def need(ok,why):
    if not ok:raise RuntimeError(why)


def read_owned(path,limit):
    need(path.resolve(strict=True)==path,'Redirected input: '+path.name)
    with path.open('rb') as f:
        s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_uid==1204 and s.st_size<=limit,'Unexpected input metadata: '+path.name)
        raw=f.read(limit+1);need(len(raw)<=limit,'Input grew');return raw


def dump(path,value):
    temp=path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    with temp.open('xb') as f:f.write((json.dumps(value,indent=2)+'\n').encode());f.flush();os.fsync(f.fileno())
    os.replace(temp,path)


def module(name,source,bindings=None):
    m=types.ModuleType(name);m.__file__=__file__+'#'+name;m.__dict__.update(bindings or {});sys.modules[name]=m
    exec(compile(source,m.__file__,'exec'),m.__dict__);return m


def pinned_packet(mode):
    name,sha=PACKETS[mode];raw=read_owned(ROOT/name,1024**2);need(hashlib.sha256(raw).hexdigest()==sha,'Previous pinned packet differs: '+name)
    m=module('memory_base_'+str(mode),raw.decode());return m,raw.decode()


def pair_summary(directory,groups):
    combined={'revision':'memory-pair-v1','group_order':[256,64],'groups':[],
              'Host_cache_and_process_PSS_are_not_disjoint_accounts':True,'UB_used':False,'B_accessed':False}
    for group in groups:
        work=Path(group['report_directory']);memory=work/'memory-accounting-summary.json';cache=work/'combined-summary.json'
        entry={'rootfs_io_kib':group['rootfs_io_kib'],'run_id':group['run_id'],'report_directory':str(work),'lifecycle_status':group['status']}
        if memory.exists():entry['memory']=json.loads(read_owned(memory,64*1024**2))
        if cache.exists():
            data=json.loads(read_owned(cache,32*1024**2))
            entry['cache']={k:data[k] for k in ('run_id','jobs','boot_id','process_rows','rootfs_layer_inventory','rootfs_storage_details','cache_timeseries','validation','experiment_comparison')}
            entry['full_cache_evidence']={'path':str(cache),'sha256':hashlib.sha256(cache.read_bytes()).hexdigest(),'full_residency_bitmaps_retained_here':True}
        combined['groups'].append(entry)
    dump(directory/'memory-comparison.json',combined)
    lines=['# 256 KiB / 64 KiB 内存占用增强采集','',
        '这是现场采集索引与完整统计，最终物理归因仍需分析；Cached、Buffers、设备驻留、进程PSS不可直接相加。','',
        '|组|run ID|原生命周期状态|新增占用采样完整|有效PFN检查点|报告目录|','|---|---|---|---|---|---|']
    for g in combined['groups']:
        v=g.get('memory',{}).get('coverage',{});lines.append('|'+ '|'.join(map(str,[g['rootfs_io_kib'],g['run_id'],g['lifecycle_status'],v.get('required_accounting_complete',False),str(v.get('PFN_checkpoints_valid',0))+'/'+str(v.get('PFN_checkpoints_requested',0)),g['report_directory']]))+'|')
    lines+=['','文件memory-comparison.json含两组Host时序、模板同点PSS、每Guest分类、memory设备驻留、公共服务、测量器开销与关键PFN汇总。',
            'PFN未稳定/不可见/超预算的项是NA，不用RSS-PSS替代。完整lower位图及原始JSONL仍在各组报告目录，路径与哈希见JSON。',
            'B0是空服务基线；B1是Guest就绪；B2为回放前；T2为清理前；T3为Guest退出但观测服务仍在；T4为原服务恢复。后续不得把缺少活绑定设备记成缓存归零。','']
    (directory/'memory-comparison.md').write_text('\n'.join(lines),encoding='utf-8');return combined


def main():
    ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['run','status']);ap.add_argument('--quiet-window-confirmed',action='store_true');ap.add_argument('--accept-nonzero-baseline',action='store_true');a=ap.parse_args()
    need(sys.platform=='linux' and os.uname().nodename=='server1' and os.getuid()==os.geteuid()==1204,'A/server1 ordinary jwk only');os.umask(0o077)
    if a.mode=='status':print('BEGIN_RETURN_REPORT');print(read_owned(STATE,4*1024**2).decode());print('END_RETURN_REPORT');return 0
    need(a.quiet_window_confirmed and a.accept_nonzero_baseline,'Explicit quiet window and measured-baseline flags required')
    caps=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
    need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free owner required')
    import fcntl
    lock=os.open(ROOT/'relay/cow4-memory-pair-node-a.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    need(not STATE.exists(),'Pair receipt exists; use status, no implicit repeat')
    for mode in (256,64):need(not (ROOT/f'relay/cow4-memory-{mode}-node-a.pending.json').exists(),'Group receipt already exists; preserve it')
    packets={mode:pinned_packet(mode) for mode in (256,64)}
    patcher=module('memory_patcher',payload('patch_sources'))
    root_text=patcher.root_source(packets[64][0].ROOT_SOURCE,payload('root256_extra'),payload('root_measure'),payload('root_pair'))
    engine=packets[256][0].ENGINE;collector=read_owned(ROOT/'cow_ram_readonly.py',128*1024).decode();need(hashlib.sha256(collector.encode()).hexdigest()==engine.COLLECTOR_SHA,'Collector source changed')
    for mode,(_,raw) in packets.items():compile(patcher.stage_source(raw,mode,payload('owner_extension')),'stage-preflight','exec')
    pair_id=uuid.uuid4().hex;work=Path(tempfile.mkdtemp(prefix='node-a-memory-pair-',dir=ROOT/'relay/reports'))
    report={'revision':'memory-pair-owner-v1','pair_id':pair_id,'status':'WAITING_FOR_ROOT','report_directory':str(work),'groups':[],
            'group_order':[256,64],'maximum_simultaneous_Guests':8,'maximum_restore_calls':16,'SDK_called':False,'B_accessed':False,'new_compilation':False}
    endpoint=ROOT/'r'/('cm-'+pair_id[:12]+'.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(endpoint));os.chmod(endpoint,0o600);listener.listen(1);listener.settimeout(600);socket_meta=endpoint.lstat()
    ticks=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
    master={'pair_id':pair_id,'owner_pid':os.getpid(),'owner_ticks':ticks,'endpoint':str(endpoint)}
    command="/usr/bin/python3 -I -B - <<'COW4_MEMORY_PAIR_ROOT'\n"+collector+'\n'+root_text+'\nmemory_root_driver('+pprint.pformat(master,width=100)+')\nCOW4_MEMORY_PAIR_ROOT'
    (work/'root-session-review.txt').write_text(command,encoding='utf-8');report['root_review_file']=str(work/'root-session-review.txt');report['root_body_sha256']=hashlib.sha256(command.encode()).hexdigest();dump(STATE,report)
    print('BEGIN_REVIEWED_ROOT_BODY_ONLY');print(command);print('END_REVIEWED_ROOT_BODY_ONLY',flush=True)
    print('Keep this terminal open. Paste the literal body ONCE in A/root within 600 seconds. Two groups run sequentially; four ordered host cache drops total; original service restored after each. No done input.',flush=True)
    sock=None;root_closed=False
    try:
        sock,_=listener.accept();sock.settimeout(1200);peer=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(peer[1]==0,'Expected root peer')
        need(engine.receive(sock)=={'op':'pair_ready'},'Root pair handshake differs')
        for mode in (256,64):
            report['status']='RUNNING_'+str(mode);dump(STATE,report)
            source=patcher.stage_source(packets[mode][1],mode,payload('owner_extension'))
            stage=module('memory_group_'+str(mode),source,{'MODE':mode,'MASTER':sock,'PAIR_ID':pair_id})
            previous_argv=sys.argv[:];sys.argv=[__file__,'run','--quiet-window-confirmed','--accept-nonzero-baseline']
            try:code=stage.main()
            finally:sys.argv=previous_argv
            original=json.loads(read_owned(stage.ENGINE.PENDING,8*1024**2))
            root_ack=engine.receive(sock);need(root_ack.get('op')=='group_root_finished' and root_ack['rootfs_io_kib']==mode,'Root group acknowledgement differs')
            root=original.get('root_session',{});lifecycle=code==0 and original.get('all_cohort_guests_released') and root.get('original_configuration_restored') and root.get('original_service_healthy') and root_ack.get('restored')
            entry={'rootfs_io_kib':mode,'run_id':original['run_id'],'status':original['status'],'report_directory':original['report_directory'],'lifecycle_complete':bool(lifecycle),'paired_input_equivalence_verified':original.get('paired_input_equivalence_verified'),'memory_accounting':original.get('memory_accounting'),'memory_summary_error':original.get('memory_summary_error')}
            report['groups'].append(entry);dump(STATE,report)
            engine.send(sock,{'op':'group_complete','rootfs_io_kib':mode,'lifecycle_complete':bool(lifecycle)})
            if not lifecycle:break
            if mode==256:
                print('PHASE=original_restored_between_groups_wait_30_seconds',flush=True);time.sleep(30)
        final=engine.receive(sock);need(final.get('op')=='pair_root_finished','Missing final root receipt');root_closed=True;report['root_session']=final['report']
        complete=len(report['groups'])==2 and all(g['lifecycle_complete'] for g in report['groups']) and final['report']['status']=='MEMORY_PAIR_ROOT_BOTH_GROUPS_RESTORED'
        measurement=complete and all(g.get('memory_accounting',{}).get('coverage',{}).get('required_accounting_complete') for g in report['groups'])
        report['PFN_diagnostic_complete']=complete and all(g.get('memory_accounting',{}).get('coverage',{}).get('PFN_diagnostic_complete') for g in report['groups'])
        report['physical_sharing_claim']='Review stable PFN checkpoints; completion of occupancy accounting alone is not exact physical-sharing acceptance'
        report['status']='MEMORY_PAIR_BOTH_GROUPS_RELEASED_ACCOUNTING_COLLECTED' if measurement else 'MEMORY_PAIR_RELEASED_WITH_MEASUREMENT_GAPS' if complete else 'STOPPED_MEMORY_PAIR_REVIEW_RECEIPT'
    except BaseException as e:
        report.update(status='STOPPED_MEMORY_PAIR_ENTRY',error_type=type(e).__name__,reason=str(e))
        if sock and not root_closed:
            try:engine.send(sock,{'op':'pair_stop'});report['root_session']=engine.receive(sock).get('report')
            except Exception as ee:report['root_coordination_error']=type(ee).__name__
    finally:
        if sock:sock.close()
        listener.close()
        try:
            if endpoint.is_socket() and (endpoint.lstat().st_dev,endpoint.lstat().st_ino)==(socket_meta.st_dev,socket_meta.st_ino):endpoint.unlink()
        except OSError:pass
        try:
            pair_summary(work,report['groups']);report['comparison_json']=str(work/'memory-comparison.json');report['comparison_markdown']=str(work/'memory-comparison.md')
        except Exception as e:report['summary_error']={'type':type(e).__name__,'reason':str(e)}
        dump(STATE,report);dump(work/'return.json',report);os.close(lock)
    print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
    return 0 if report['status']=='MEMORY_PAIR_BOTH_GROUPS_RELEASED_ACCOUNTING_COLLECTED' else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_MEMORY_PAIR_PRECONDITION','error_type':type(e).__name__,'reason':str(e)},indent=2));print('END_RETURN_REPORT');raise SystemExit(1)
