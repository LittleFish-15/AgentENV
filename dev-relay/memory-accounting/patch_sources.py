"""Deterministic extension of the already executed pinned lifecycle packets."""
import ast


def once(s,a,b):
    if s.count(a)!=1:raise RuntimeError('Pinned patch anchor differs: '+a[:100])
    return s.replace(a,b)


def stage_source(raw,mode,extension):
    body=raw.rsplit("if __name__=='__main__':",1)[0]
    tree=ast.parse(body);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main');before=ast.get_source_segment(body,node);main=before
    previous='cow4-original-256-recheck-node-a.pending.json' if mode==256 else 'cow4-original-io64-node-a.pending.json'
    main=once(main,previous,'cow4-memory-'+str(mode)+'-node-a.pending.json')
    main=once(main,'physical_guest_ram_resampled=False','physical_guest_ram_resampled=None,physical_guest_ram_checkpoint_requested=True')
    main=once(main,'RECHECK.reconcile(m,identity,api)' if mode==256 else 'IO64.reconcile(m,identity,api)','reconcile_memory(m,identity,api)')
    main=once(main,"prefix='node-a-cow4-256-recheck-'" if mode==256 else "prefix='node-a-cow4-io64-'","prefix='node-a-memory-"+str(mode)+"-'")
    anchor='    cohort.report.update(root_plan=plan,template_lowers=template_lowers,'
    main=once(main,anchor,"    plan['template_memory_lowers']={b['template_id']:[{k:f[k] for k in ('path','dev','inode','file_bytes')} for f in b['parent_layer_inventory']['memory']] for b in built}\n"+anchor)
    start=main.index('    command="/usr/bin/python3 -I -B - <<\'COW4_');end=main.index('    sock=None;runner=None;changed=False',start)
    main=main[:start]+'    announce_memory_group(plan,cohort)\n'+main[end:]
    anchor="        cohort.report['configuration_changed_this_run']=changed"
    main=once(main,anchor,"        try:cohort.report['memory_accounting']=memory_summary(work,cohort.report)\n        except Exception as e:cohort.report['memory_summary_error']={'type':type(e).__name__,'reason':str(e)}\n"+anchor)
    body=once(body,before,main)
    # Include added measurement logs in the unchanged file-cache bookkeeping.
    body=once(body,"'measurements/access-cache.jsonl','measurements/host-cache.jsonl'):","'measurements/access-cache.jsonl','measurements/host-cache.jsonl','measurements/memory-accounting.jsonl'):")
    body=once(body,"('Cached','Buffers','Shmem','Dirty','Writeback','SReclaimable','MemAvailable','SwapCached')}","('Cached','Buffers','Shmem','Dirty','Writeback','SReclaimable','MemAvailable','SwapCached','AnonPages','Mapped','Slab','SUnreclaim','PageTables','KernelStack','Unevictable','Mlocked','AnonHugePages','SwapTotal','SwapFree')}")
    result=body+'\n'+extension+'\n';compile(result,'extended-owner-stage','exec');return result


def root_source(base64_source,root256_extra,measure,pair):
    s=base64_source
    s=once(s,'io64_server_preflight(plan,before)','memory_runtime_preflight(plan,before)')
    s=once(s,"report.update(original_server_sha256=plan['original_server_sha256'],candidate_server_sha256=IO64_SERVER_SHA,core_commit=plan['core_commit'])","report.update(original_server_sha256=plan['original_server_sha256'],rootfs_io_kib=memory_mode(plan),core_commit=plan['core_commit'])")
    s=once(s,'expected_new=io64_config(raw,candidate)','expected_new=memory_runtime_config(plan,raw,candidate)')
    s=once(s,"==plan['candidate_sha256']==IO64_DAEMON_SHA","==plan['candidate_sha256']==memory_expected_daemon(plan)")
    s=once(s,'io64_install_server(plan,report)','memory_install_server(plan,report)')
    s=once(s,'io64_active_server(plan,active)','memory_active_server(plan,active)')
    # Only the call sites are replaced; the fixed IO64 implementation stays intact.
    if s.count('                io64_restore_server(plan,report)')!=2:raise RuntimeError('Restore call-site count differs')
    s=s.replace('                io64_restore_server(plan,report)','                memory_restore_server(plan,report)')
    s=once(s,'def bind_guests(plan, active, jobs):','def bind_guests(plan, active, jobs):')
    s=once(s,'        limits=io64_bound_devices(b)',"        limits=memory_bound_limits(plan,b)\n        mm=Path(b['memory_device']).stat()")
    s=once(s,"bound.append({'effective_device_limits':limits,","bound.append({'guest_regions':b['guest_regions'],'memory_device':b['memory_device'],'memory_device_identity':[mm.st_dev,mm.st_ino,mm.st_rdev],'effective_device_limits':limits,")
    s=once(s,"        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(600);sock.connect(str(endpoint));check_peer(plan,sock)","        report['memory_baselines']={'B0_empty_original_service':memory_snapshot(plan,before,[],'B0_empty_original_service')}\n        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(600);sock.connect(str(endpoint));check_peer(plan,sock)")
    s=once(s,'        until=time.monotonic()+5400;last_progress=time.monotonic()', '        until=time.monotonic()+5400;last_progress=time.monotonic();next_memory=0;memory_checkpoints=set()')
    s=once(s,"                report['rootfs64_memory256_verified']=len(bound)==8","                report['rootfs64_memory256_verified']=memory_mode(plan)==64 and len(bound)==8\n                report['rootfs256_memory256_verified']=memory_mode(plan)==256 and len(bound)==8")
    s=once(s,"                print('ROOT_PHASE=rootfs64_memory256_verified_8_of_8',flush=True)","                print('ROOT_PHASE=rootfs'+str(memory_mode(plan))+'_memory256_verified_8_of_8',flush=True)\n                baseline=memory_snapshot(plan,active,bound,'B1_all_Guests_ready_before_idle')\n                report['memory_baselines']['B1_all_Guests_ready']=baseline\n                require(baseline['complete'],'Memory sampler admission incomplete; no replay')\n                print('ROOT_PHASE=memory_sampler_admission_passed',flush=True)\n                pfn=pfn_checkpoint(bound,'B1_all_Guests_ready_before_idle')\n                next_memory=time.monotonic()+15")
    s=once(s,"wire_send(sock,{'op':'bound','bindings':bound,'observer_identity':[pid,ticks]})","wire_send(sock,{'op':'bound','bindings':bound,'observer_identity':[pid,ticks],'memory_baseline':baseline,'pfn':pfn})")
    s=once(s,"                wire_send(sock,{'op':'sample','unix':time.time(),'processes':rows})","                extended=None\n                if time.monotonic()>=next_memory:\n                    extended=memory_snapshot(plan,active,bound,'periodic_live')\n                    next_memory=time.monotonic()+15\n                wire_send(sock,{'op':'sample','unix':time.time(),'processes':rows,'memory_snapshot':extended})")
    anchor="            elif op=='heartbeat':wire_send(sock,{'op':'heartbeat'})"
    extra="""            elif op=='memory_checkpoint':
                phase=request.get('phase');require(phase in ('B2_replay_baseline','T2_replay_finished_before_cleanup') and phase not in memory_checkpoints,'Unexpected/repeated memory checkpoint')
                require(len(bound)==8,'Guests not bound');memory_checkpoints.add(phase)
                require(request.get('pfn') is (phase=='T2_replay_finished_before_cleanup'),'PFN phase policy differs')
                snap=memory_snapshot(plan,active,bound,phase)
                phys=pfn_checkpoint(bound,phase) if request['pfn'] else None
                report['memory_baselines'][phase]=snap
                wire_send(sock,{'op':'memory_checkpoint','snapshot':snap,'pfn':phys})
"""
    s=once(s,anchor,extra+anchor)
    s=once(s,"            elif op=='restore':break","            elif op=='restore':\n                report['memory_baselines']['T3_after_Guest_exit']=memory_after_guest_exit(plan,active,bound)\n                break")
    s=once(s,"                report['original_service_healthy']=True","                report['original_service_healthy']=True\n                if memory_mode(plan)==256:report['original_server_unchanged']=True\n                report['memory_baselines']['T4_original_service_restored']=memory_snapshot(plan,restored,[],'T4_original_service_restored')")
    s=once(s,"        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT',flush=True)","        print('ROOT_GROUP_FINISHED io_kib='+str(memory_mode(plan))+' status='+report['status'],flush=True)\n    return report")
    result=s+'\n'+root256_extra+'\n'+measure+'\n'+pair
    compile(result,'literal-memory-pair-root','exec');return result
