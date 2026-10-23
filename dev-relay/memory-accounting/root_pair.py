"""Literal mode selection and two-stage root driver. Plans are data only."""
ORIGINAL_OBSERVER_SHA='eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf'


def memory_mode(plan):
    value=plan.get('rootfs_io_kib');require(type(value) is int and value in (256,64),'Unexpected experimental mode');return value


def memory_expected_daemon(plan):
    return IO64_DAEMON_SHA if memory_mode(plan)==64 else ORIGINAL_OBSERVER_SHA


def memory_runtime_preflight(plan,before):
    require(plan['candidate_sha256']==memory_expected_daemon(plan),'Observer mode/hash differs')
    if memory_mode(plan)==64:io64_server_preflight(plan,before)
    else:verify_original_server(plan,before)


def memory_runtime_config(plan,raw,candidate):
    if memory_mode(plan)==64:return io64_config(raw,candidate)
    pattern=r'(?m)^daemon_binary_path\s*=\s*"([^"]+)"\s*$';matches=list(re.finditer(pattern,raw.decode()))
    require(len(matches)==1 and matches[0][1]==str(BASE/'bin/uvm-ublk-daemon'),'Original daemon field differs')
    require(b'rootfs_max_io_kib' not in raw,'Original configuration has an I/O override')
    return re.sub(pattern,lambda _: 'daemon_binary_path = '+json.dumps(str(candidate)),raw.decode()).encode()


def memory_install_server(plan,report):
    if memory_mode(plan)==64:io64_install_server(plan,report)
    else:report['server_binary_replaced']=False


def memory_active_server(plan,active):
    if memory_mode(plan)==64:io64_active_server(plan,active)
    else:verify_original_server(plan,active)


def memory_restore_server(plan,report):
    if memory_mode(plan)==64:io64_restore_server(plan,report)
    else:
        verify_original_server(plan,unit_state());report['original_server_unchanged']=True


def memory_bound_limits(plan,b):
    return io64_bound_devices(b) if memory_mode(plan)==64 else original_bound_limits(b)


def memory_after_guest_exit(plan,active,bound):
    require(api_get('/v2/sandboxes?limit=1')==(200,[]),'Guests remain; no post-exit observation')
    for b in bound:
        try:alive=identity(b['pid'])[1]==b['start_ticks']
        except (FileNotFoundError,ProcessLookupError):alive=False
        require(not alive,'Bound Guest PID still alive')
    rows=[]
    for index in range(3):
        if index:time.sleep(5)
        rows.append(memory_snapshot(plan,active,[],'T3_Guests_exited_observer_service_alive'))
    return {'samples':rows,'old_device_cache_not_read':'Device paths may have been released/reused; no post-exit name-only attribution.'}


def memory_root_driver(master):
    result={'revision':'memory-pair-root-v1','pair_id':master['pair_id'],'status':'STARTING_MEMORY_PAIR_ROOT','groups':[],'SDK_called':False}
    sock=None
    try:
        require(os.geteuid()==0 and os.uname().nodename=='server1','A/root only')
        endpoint=Path(master['endpoint']);require(endpoint.parent==ROOT/'r' and endpoint.name=='cm-'+master['pair_id'][:12]+'.sock','Master endpoint outside scope')
        m=endpoint.lstat();require(stat.S_ISSOCK(m.st_mode) and m.st_uid==1204 and stat.S_IMODE(m.st_mode)==0o600,'Master socket metadata differs')
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(900);sock.connect(str(endpoint));check_peer(master,sock)
        wire_send(sock,{'op':'pair_ready'})
        for mode in (256,64):
            request=wire_recv(sock)
            if request.get('op')=='pair_stop':result['status']='MEMORY_PAIR_STOPPED_BY_OWNER';return result
            require(request.get('op')=='start_group','Unexpected master request');plan=request['plan']
            require(plan['pair_id']==master['pair_id'] and plan['owner_pid']==master['owner_pid'] and plan['owner_ticks']==master['owner_ticks'],'Stage owner differs')
            require(memory_mode(plan)==mode,'Group order differs')
            require(Path(plan['work']).parent==ROOT/'relay/reports' and Path(plan['work']).name.startswith('node-a-memory-'+str(mode)+'-'),'Group report directory outside scope')
            print('ROOT_GROUP_START io_kib='+str(mode),flush=True)
            report=root_session(plan);result['groups'].append({'rootfs_io_kib':mode,'run_id':plan['run_id'],'report':report})
            good=report.get('status')=='COW4_ROOT_SESSION_RESTORED' and report.get('original_configuration_restored') and report.get('original_service_healthy') and report.get('other_services_unchanged')
            wire_send(sock,{'op':'group_root_finished','rootfs_io_kib':mode,'restored':bool(good)})
            require(good,'Group restoration not confirmed; second group prohibited')
            ack=wire_recv(sock);require(ack.get('op')=='group_complete' and ack.get('rootfs_io_kib')==mode,'Owner completion acknowledgement differs')
            if not ack.get('lifecycle_complete'):
                result['status']='MEMORY_PAIR_STOPPED_AFTER_GROUP_FAILURE';return result
        result['status']='MEMORY_PAIR_ROOT_BOTH_GROUPS_RESTORED'
    except BaseException as e:result.update(status='STOPPED_MEMORY_PAIR_ROOT',error_type=type(e).__name__,reason=str(e))
    finally:
        if sock:
            try:wire_send(sock,{'op':'pair_root_finished','report':result})
            except OSError:pass
            sock.close()
        print('BEGIN_RETURN_REPORT');print(json.dumps(result,indent=2));print('END_RETURN_REPORT',flush=True)
    return result
