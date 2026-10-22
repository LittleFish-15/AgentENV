"""One operator entry: reuse inputs, build bounded observer, run 17 x 2, restore.

ENGINE/CORE/BUILD/ACCOUNTING/PROCESS/DETAILS/ROOT_SOURCE are embedded and pinned.
"""
import argparse,base64,collections,copy,hashlib,json,os,re,socket,stat,struct,tempfile,time,zlib
from pathlib import Path


def select17(inputs,build,old):
    ENGINE.need(old['run_id']=='083604f2f76045c0beb8de4cf92c0758' and old['all_cohort_guests_released'],'Prior 17-template receipt differs')
    ENGINE.need(len(old['jobs'])==34 and all(j['state']=='REPLAY_COMPLETED' for j in old['jobs']),'Prior 17-template cohort incomplete')
    names=[]
    for j in sorted(old['jobs'],key=lambda j:j['index']):
        if j['instance_id'] not in names:names.append(j['instance_id'])
    ENGINE.need(len(names)==17,'Expected the exact prior 17 templates')
    cases={c['instance_id']:c for c in inputs['cohort']['cases']};built={c['instance_id']:c for c in build['cases']}
    selected=[cases[n] for n in names];ready=[copy.deepcopy(built[n]) for n in names]
    ENGINE.need(collections.Counter(c['language'] for c in selected)=={'go':9,'ts':5,'java':3},'Representative languages changed')
    ENGINE.need(len({b['template_id'] for b in ready})==17 and all(b['state']=='READY' for b in ready),'Selected templates not ready')
    for b in ready:
        prior=next(j for j in old['jobs'] if j['instance_id']==b['instance_id'])
        ENGINE.need(b['template_id']==prior['template_id'],'Template identity changed')
        ENGINE.B.verify_ready(b)
        ENGINE.need(b['catalog_sha256']==prior['catalog_sha256'],'Template catalog changed')
    return selected,ready


def device_budget(jobs,observed):
    per_template=collections.Counter(j['template_id'] for j in jobs if j.get('sandbox_id'))
    templates={j['template_id'] for j in jobs}
    ENGINE.need(len(templates)==17 and len(jobs)==34 and all(n in (1,2) for n in per_template.values()),'Invalid device planning scope')
    remaining=sum({0:3,1:1,2:0}[per_template[t]] for t in templates)
    return {'limit':observed['limit'],'registered':observed['registered'],'free':observed['limit']-observed['registered'],
        'remaining_business_devices_estimate':remaining,'reserve_devices':2,
        'fits':observed['limit']==64 and observed['limit']-observed['registered']>=remaining+2}


def root_command(collector,plan):
    # Compress only structured scope data, not executable supervisor source.
    raw=json.dumps(plan,separators=(',',':')).encode();ENGINE.need(len(raw)<=262144,'Root scope exceeds reviewed data limit')
    encoded=base64.b64encode(zlib.compress(raw,9)).decode()
    chunks='\n'.join('    '+repr(encoded[i:i+100]) for i in range(0,len(encoded),100))
    tail="\nimport zlib\nscope_bytes=zlib.decompress(base64.b64decode(\n"+chunks+"\n))\n"
    tail+="require(len(scope_bytes)<=262144 and hashlib.sha256(scope_bytes).hexdigest()=="+repr(hashlib.sha256(raw).hexdigest())+",'Scope data differs')\nroot_session(json.loads(scope_bytes))\n"
    return "/usr/bin/python3 -I -B - <<'COW17_ACCESS_ROOT'\n"+collector+'\n'+ROOT_SOURCE+tail+'COW17_ACCESS_ROOT'


def prepare_inputs():
    m=ENGINE
    m.B.inputs(m.ROOT/'cow55_inputs.json');inputs=m.B.read_json(m.ROOT/'cow55_inputs.json');build=m.B.read_json(m.B.STATE)
    old=m.B.read_json(m.ROOT/'relay/cow33-batch1-node-a.pending.json')
    four=m.B.read_json(m.ROOT/'relay/cow4-access-node-a.pending.json')
    m.need(four['run_id']=='2606e4f482b44f4fb072792215ac9793' and four['status']=='COW4_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','Four-template success receipt changed')
    m.need(four['all_cohort_guests_released'] and not four['restore_outcome_uncertain'],'Previous Guest cleanup uncertain')
    for k in ('original_configuration_restored','original_service_healthy','observer_exit_confirmed','other_services_unchanged'):
        m.need(four['root_session'].get(k) is True,'Previous restoration incomplete')
    m.need(build.get('status')=='COW55_ALL_TEMPLATES_READY_NO_REPLAY_STARTED' and build.get('final_merge_verified') and build.get('worker_finished'),'Prepared template inventory incomplete')
    m.need(m.B.read_json(m.BASE/'installation.json').get('commit')=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc','Original installation differs')
    selected,ready=select17(inputs,build,old)
    identity=m.H.runtime_pid();api=m.Api(identity)
    m.need(api.call('GET','/health')[0]==204 and api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Original service not healthy and empty')
    m.need(not m.R.find_firecrackers(identity[0]),'Original Guest process exists')
    for j in four['jobs']:m.need(api.call('GET','/sandboxes/'+j['sandbox_id'])[0]==404,'Previous Guest remains')
    cfg=m.H.read(m.BASE/'config/runtime.toml',65536);m.need(CORE.digest(cfg)==CORE.CONFIG_SHA,'Original config differs')
    return inputs,build,selected,ready,identity,cfg


def summary_finish(c,runner):
    m=ENGINE
    result=CORE.summarize(c.work,c.report,runner.process)
    coverage={r['template_id'] for r in result['rootfs_access_rows'] if r['phase']=='both_replaying' and
        r['metrics'].get('sandbox1_accessed_lower_bytes',{}).get('max',0)>0 and r['metrics'].get('sandbox2_accessed_lower_bytes',{}).get('max',0)>0}
    process_coverage={r['template_id'] for r in result['process_rows'] if r['phase']=='both_replaying' and r['template_valid_paired_samples']>0}
    upper_coverage={r['template_id'] for r in result['rootfs_storage_details']['rows'] if r['phase']=='both_replaying' and
        all(r['metrics'].get(f'sandbox{i}_upper_{field}',{}).get('valid_samples',0)>0 for i in (1,2) for field in ('file_bytes','allocated_bytes','resident_bytes'))}
    c.report.update(access_coverage_templates=len(coverage),process_coverage_templates=len(process_coverage),upper_coverage_templates=len(upper_coverage))
    restored=c.report.get('root_session',{})
    passed=(c.report['status']=='COW17_TRAJECTORIES_COMPLETED' and len(coverage)==len(process_coverage)==len(upper_coverage)==17 and
        c.report['replay_completed_guests']==34 and c.report['all_cohort_guests_released'] and
        all(restored.get(k) for k in ('original_configuration_restored','original_service_healthy','other_services_unchanged','observer_exit_confirmed','bound_guest_processes_exited')))
    if passed:c.report['status']='COW17_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED'
    else:c.report['full_acceptance']='NOT_COMPLETE_REVIEW_COVERAGE_AND_RESTORATION'
    result['validation']={'status':c.report['status'],'access_coverage_templates':len(coverage),'process_coverage_templates':len(process_coverage),
        'upper_coverage_templates':len(upper_coverage),'replay_completed_guests':c.report['replay_completed_guests'],
        'all_cohort_guests_released':c.report['all_cohort_guests_released'],'root_session':restored}
    m.H.save(c.work/'combined-summary.json',result)
    with (c.work/'combined-summary.md').open('a',encoding='utf-8') as f:
        f.write('\n最终状态：'+c.report['status']+f"；访问/进程/upper回放期覆盖分别为{len(coverage)}/{len(process_coverage)}/{len(upper_coverage)}（目标各17）。\n")
    c.report.update(combined_summary=str(c.work/'combined-summary.json'),combined_markdown=str(c.work/'combined-summary.md'))


def main():
    m=ENGINE;p=argparse.ArgumentParser();p.add_argument('mode',choices=('run','status'));a=p.parse_args()
    m.need(os.name=='posix' and os.uname().nodename=='server1' and os.getuid()==os.geteuid()==1204,'A ordinary jwk only')
    m.need(os.uname().machine=='aarch64','Expected ARM64 node');os.umask(0o077)
    m.PENDING=m.ROOT/'relay/cow17-access-node-a.pending.json'
    if a.mode=='status':print('BEGIN_RETURN_REPORT');print(m.PENDING.read_text());print('END_RETURN_REPORT');return 0
    caps=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    m.need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free owner required')
    import fcntl
    locks=[]
    for path in (m.LOCK,m.ROOT/'relay/cow4-rootfs-access-build.lock'):
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(fd)
    m.need(not m.PENDING.exists(),'This 17-template receipt exists; return status, no blind repeat')
    m.B,_=m.load(m.ROOT/'cow55_build_edf502d.py',m.BUILDER_SHA,'seventeen_builder');m.B.load_helper();m.H=m.B.H
    m.R,collector=m.load(m.ROOT/'cow_ram_readonly.py',m.COLLECTOR_SHA,'seventeen_collector')
    inputs,build,selected,ready,identity,old=prepare_inputs()
    work=Path(tempfile.mkdtemp(prefix='node-a-cow17-access-',dir=m.ROOT/'relay/reports'))
    c=m.Cohort(work,dict(build,original_identity=list(identity),cases=ready),dict(inputs,cohort=dict(inputs['cohort'],cases=selected)),template_count=17,admission_workers=1)
    c.control=lambda _:None;c.report.update(revision='cow17-attributed-v1',variant='original_with_diagnostic_observer',status='PREPARING_COW17_ACCESS',
        configured_guest_ram_bytes=34*4096*1024**2,physical_guest_ram_resampled=False,cache_target_interval_seconds=15,
        observer_log_byte_limit=536870912,observer_record_limit=1000000,previous_four_run_preserved=True,
        selected_templates=[{k:x[k] for k in ('instance_id','language','recorded_wait_seconds')} for x in selected])
    config=m.BASE/'config/runtime.toml';meta=config.stat();sock=listener=runner=endpoint=None;changed=False;socket_identity=None
    files={};template_lowers={}
    for b in ready:
        layers=[{k:r[k] for k in ('path','dev','inode','file_bytes')} for r in b['parent_layer_inventory']['rootfs']]
        template_lowers[b['template_id']]=layers
        for f in layers:files[(f['dev'],f['inode'])]=f
    m.need(len(files)<=256,'Observer whitelist limit exceeded');c.report['template_lowers']=template_lowers
    c.persist()
    try:
        initial=device_budget(c.jobs,CORE.inventory());c.report['initial_device_budget']=initial;c.persist()
        m.need(initial['fits'],'Need 51 business device slots plus 2 spare; no existing device reclaim assumed')
        c.guard(initial=True)
        def save_build(value):c.report['observer_build']=value;c.persist()
        candidate_result=BUILD.build(work,save_build)
        candidate=Path(candidate_result['candidate']);CORE.CANDIDATE_SHA=candidate_result['candidate_sha256'];CORE.PATCH_SHA=BUILD.PATCH_SHA
        c.deadline=time.monotonic()+5400
        observer=work/'observer'
        spec='output='+str(observer/'trace.jsonl')+'\nmax_bytes=536870912\nmax_records=1000000\n'+''.join('allow=%d:%d:%d\n'%(k[0],k[1],v['file_bytes']) for k,v in sorted(files.items()))
        candidate.with_suffix('.access-spec').write_text(spec)
        new=CORE.replace_daemon(old,candidate)
        (work/'runtime.original.toml').write_bytes(old);(work/'runtime.observer.toml').write_bytes(new)
        endpoint=m.ROOT/'r'/('c17-'+c.run_id[:12]+'.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind(str(endpoint));os.chmod(endpoint,0o600);listener.listen(1);listener.settimeout(600)
        sm=endpoint.lstat();socket_identity=(sm.st_dev,sm.st_ino)
        plan={'run_id':c.run_id,'owner_pid':os.getpid(),'owner_ticks':m.R.identity(os.getpid())[1],'endpoint':str(endpoint),'work':str(work),
            'candidate':str(candidate),'candidate_sha256':CORE.CANDIDATE_SHA,'original_identity':list(identity),
            'original_config_base64':base64.b64encode(old).decode(),'original_config_sha256':CORE.CONFIG_SHA,'new_config_sha256':CORE.digest(new),
            'spec_sha256':CORE.digest(spec.encode()),'original_config_metadata':{'uid':meta.st_uid,'gid':meta.st_gid,'mode':stat.S_IMODE(meta.st_mode)},
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'template_lowers':template_lowers}
        c.report.update(root_plan=plan,status='AWAITING_COW17_ROOT_SUPERVISOR');c.persist()
        m.H.save(work/'root-plan.json',plan);command=root_command(collector,plan)
        (work/'root-session-review.txt').write_text(command)
        print('BEGIN_REVIEWED_ROOT_BODY_ONLY');print(command);print('END_REVIEWED_ROOT_BODY_ONLY',flush=True)
        print('Keep this jwk terminal open. Paste the body once into A/root within 600 seconds. It supervises only the empty original service, then restores it after owned Guest cleanup. No done input.',flush=True)
        sock,_=listener.accept();sock.settimeout(600)
        peer=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));m.need(peer[1]==0,'Expected root supervisor')
        m.need(m.receive(sock)=={'op':'ready'},'Root supervisor not ready')
        m.need(m.H.runtime_pid()==identity and c.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Original service changed during preparation')
        m.need(m.H.read(config,65536)==old,'Original config changed')
        temp=config.with_name('runtime.toml.cow17-'+c.run_id)
        with temp.open('xb') as f:f.write(new);f.flush();os.fsync(f.fileno())
        os.chmod(temp,stat.S_IMODE(meta.st_mode));os.chown(temp,-1,meta.st_gid);os.replace(temp,config);changed=True
        runner=CORE.FourRun(c,plan,files,sock);r=runner.rpc('activate');c.api=m.Api(r['identity'])
        c.report.update(active_runtime_identity=r['identity'],services_modified=True,modified_services=['jwk-aenv-ae9c626-node-a.service'])
        before=CORE.inventory();budget=device_budget(c.jobs,before);c.report['ublk_before']=before;c.persist();m.need(budget['fits'],'Post-restart device capacity insufficient')
        create=c.create
        def guarded_create(job):
            current=device_budget(c.jobs,CORE.inventory());c.report.setdefault('device_admission_checks',[]).append(current);c.persist()
            m.need(current['fits'],'Device reserve changed before next owned Guest; no blind allocation')
            return create(job)
        c.create=guarded_create
        c.guard(initial=True);c.credential.write_text('url = "http://127.0.0.1:18080"\napi_key = '+json.dumps(c.api.key)+'\n')
        c.report['status']='COW17_ADMISSION_AND_REPLAY';c.persist();runner.run();c.report['status']='COW17_TRAJECTORIES_COMPLETED'
    except BaseException as e:
        c.stop.set();c.report.update(status='STOPPED_COW17_ACCESS',error_type=type(e).__name__,reason=str(e).replace(c.api.key,'[REDACTED]'))
    finally:
        c.cleanup();c.report['all_cohort_guests_released']=set(c.created)==set(c.report['released_sandboxes']) and not c.report['restore_outcome_uncertain']
        if c.credential.exists():c.credential.unlink()
        c.report['temporary_cli_credentials_removed']=not c.credential.exists()
        if sock and runner:
            try:
                m.need(c.report['all_cohort_guests_released'],'Uncertain Guest cleanup; no restoration request')
                c.report['root_session']=runner.root_final if runner.root_final is not None else runner.rpc('restore')['report']
            except Exception as e:c.report['root_restore_error']={'type':type(e).__name__,'reason':str(e)}
        if sock:sock.close()
        if listener:listener.close()
        if endpoint and endpoint.is_socket():
            sm=endpoint.lstat()
            if (sm.st_dev,sm.st_ino)==socket_identity:endpoint.unlink()
        c.report.update(configuration_changed_this_run=changed,services_modified=changed,
            replay_completed_guests=sum(j['state']=='REPLAY_COMPLETED' for j in c.jobs))
        c.persist()
        if runner:
            try:summary_finish(c,runner)
            except Exception as e:c.report['summary_error']={'type':type(e).__name__,'reason':str(e)}
        try:c.report['ublk_after']=CORE.inventory()
        except Exception as e:c.report['ublk_after_error']=type(e).__name__
        c.persist();m.H.save(work/'return.json',c.report)
        for fd in locks:os.close(fd)
    print('BEGIN_RETURN_REPORT');print(json.dumps(c.report,indent=2));print('END_RETURN_REPORT')
    return 0 if c.report['status']=='COW17_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED' else 1
