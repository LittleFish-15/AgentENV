"""Inline root supervisor; fixed original service, scoped proc reads, restore.

Printed as literal code, never imports/executes a user-writable Python file.
COLLECTOR_SOURCE is prepended by the public single-file packet.
"""
import base64, json, hashlib, http.client, os, re, socket, stat, struct, subprocess, time
from pathlib import Path


def wire_send(sock, value):
    raw = json.dumps(value).encode(); require(len(raw) <= 4*1024**2, 'Oversized frame')
    sock.sendall(struct.pack('!I', len(raw)) + raw)


def wire_recv(sock):
    def exact(n):
        out = bytearray()
        while len(out) < n:
            part = sock.recv(n-len(out)); require(part, 'Owner disconnected'); out.extend(part)
        return bytes(out)
    n = struct.unpack('!I', exact(4))[0]; require(n <= 4*1024**2, 'Oversized frame')
    return json.loads(exact(n))


def unit_state(name=UNIT):
    r = subprocess.run(['/usr/bin/systemctl', 'show', name,
        '--property=MainPID,ActiveState,User,Group,PrivateNetwork,PrivateMounts,LimitMEMLOCK,LimitMEMLOCKSoft'],
        check=True, capture_output=True, text=True, timeout=10)
    s = dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
    pid = int(s.get('MainPID','0'))
    s['ticks'] = identity(pid)[1] if pid > 1 else None
    return s


def other_units():
    r = subprocess.run(['/usr/bin/systemctl','list-units','--all','--plain','--no-legend','--no-pager','jwk-aenv-*.service'],
                       check=True,capture_output=True,text=True,timeout=10)
    names = [line.split()[0] for line in r.stdout.splitlines() if line.strip()]
    return {n:unit_state(n) for n in names if n != UNIT}


def scoped_read(path, limit=65536):
    require(path.resolve(strict=True)==path, 'Redirected supervised input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno()); require(stat.S_ISREG(s.st_mode) and s.st_uid==1204 and s.st_size<=limit,'Unexpected supervised input')
        raw=f.read(limit+1); require(len(raw)<=limit,'Input grew'); return raw


def api_get(path):
    key=scoped_read(BASE/'config/api-key',1024).decode().strip()
    require(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',key),'Credential format differs')
    c=http.client.HTTPConnection('127.0.0.1',18080,timeout=5)
    try:
        c.request('GET',path,headers={'X-API-Key':key});r=c.getresponse();data=r.read(65537)
        require(len(data)<=65536 and not r.getheader('x-next-token'),'Uncertain API inventory')
        return r.status,json.loads(data) if data else None
    finally:c.close()


def wait_health():
    until=time.monotonic()+60
    while time.monotonic()<until:
        try:
            s=unit_state()
            if s['ActiveState']=='active' and api_get('/health')[0]==204:return s
        except (OSError,RuntimeError,http.client.HTTPException):pass
        time.sleep(1)
    raise RuntimeError('Original service health did not recover')


def assert_unit(s):
    require(s['ActiveState']=='active' and int(s['MainPID'])>1 and s['User']==s['Group']=='jwk','Original unit differs')
    require(s['PrivateNetwork']==s['PrivateMounts']=='yes','Original isolation differs')
    require(s['LimitMEMLOCK']==s['LimitMEMLOCKSoft']=='2147483648','Original memlock differs')
    limits=Path('/proc')/s['MainPID']/'limits'
    require(re.search(r'Max locked memory\s+2147483648\s+2147483648\s+bytes',limits.read_text()),'Runtime process memlock differs')


def check_peer(plan, sock):
    peer=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    require(peer[0]==plan['owner_pid'] and peer[1]==1204 and identity(peer[0])[1]==plan['owner_ticks'],'Owner identity differs')


def bind_guests(plan, active, jobs):
    require(len(jobs)==8 and len({j['sandbox_id'] for j in jobs})==8,'Expected eight unique Guests')
    require({j['template_id'] for j in jobs}==set(plan['template_lowers']),'Template scope differs')
    s=unit_state();require((s['MainPID'],s['ticks'])==(active['MainPID'],active['ticks']),'Runtime changed')
    pids=find_firecrackers(int(s['MainPID']));require(len(pids)==8,'Unexpected Firecracker descendants')
    scope={'main_pid':int(s['MainPID']),'sandbox_ids':[j['sandbox_id'] for j in jobs],'memory_bytes':4096*1024**2}
    bound=[]
    for pid in pids:
        b=bind(scope,{'pid':pid,'start_ticks':identity(pid)[1]})
        job=next(j for j in jobs if j['sandbox_id']==b['sandbox_id'])
        code,body=api_get('/sandboxes/'+b['sandbox_id'])
        require(code==200 and body.get('metadata',{}).get('cow55_run')==plan['run_id'],'Guest ownership differs')
        cfg_path=b['cwd']/'overlaybd/image.json';cfg=json.loads(scoped_read(cfg_path,2*1024**2))
        lowers=[]
        for layer in cfg['lowers']:
            require(set(layer).issuperset({'file'}) and not layer.get('ub'),'Expected local original lower')
            p=Path(layer['file']);p=p if p.is_absolute() else cfg_path.parent/p
            require(p.resolve(strict=True)==p and p.parent==BASE/'state/snapshot-store/repository/managed-layers','Unexpected lower placement')
            meta=p.stat();require(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204,'Unexpected lower inode')
            lowers.append({'path':str(p),'dev':meta.st_dev,'inode':meta.st_ino,'file_bytes':meta.st_size})
        require(sorted(lowers,key=lambda x:x['path'])==sorted(plan['template_lowers'][job['template_id']],key=lambda x:x['path']),'Runtime lower binding differs')
        upper=[]
        for name in ('data','index'):
            p=Path(cfg['upper'][name]);p=p if p.is_absolute() else cfg_path.parent/p
            require(p.resolve(strict=True)==p and p.is_relative_to(b['cwd']),'Unexpected upper path')
            meta=p.stat();require(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204,'Unexpected upper inode')
            upper.append({'path':str(p),'dev':meta.st_dev,'inode':meta.st_ino})
        bound.append({'sandbox_id':b['sandbox_id'],'template_id':job['template_id'],'pid':pid,'start_ticks':b['start_ticks'],
                      'source':str(cfg_path),'lowers':lowers,'uppers':upper})
    upper_ids=[(f['dev'],f['inode']) for b in bound for f in b['uppers']]
    lower_ids={(f['dev'],f['inode']) for b in bound for f in b['lowers']}
    require(len(set(upper_ids))==len(upper_ids) and not(set(upper_ids)&lower_ids),'Upper is aliased or overlaps lower')
    return bound


def root_session(plan):
    report={'status':'STARTING_COW4_ROOT_SESSION','run_id':plan['run_id'],'unit':UNIT,'SDK_called':False,'restart_calls':0,'restart_requests':0}
    sock=None;active=None;bound=[];changed=False;armed=False
    config=BASE/'config/runtime.toml'
    raw=base64.b64decode(plan['original_config_base64'],validate=True)
    try:
        require(os.geteuid()==0 and os.uname().nodename=='server1','A/root only')
        require(hashlib.sha256(raw).hexdigest()==plan['original_config_sha256']=='f2a1abe6542c3230bfe3cd81b884cf080dc4a3b2f2c371b40092940c686d01bd','Original bytes differ')
        before=unit_state();assert_unit(before)
        require((int(before['MainPID']),before['ticks'])==tuple(plan['original_identity']),'Original service changed before activation')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['boot_id'],'Boot identity changed')
        others=other_units();report['other_services_before']=others
        require(hashlib.sha256(scoped_read(config)).hexdigest()==plan['original_config_sha256'],'Original configuration changed')
        cfg_meta=config.stat();expected_meta=plan['original_config_metadata']
        require({'uid':cfg_meta.st_uid,'gid':cfg_meta.st_gid,'mode':stat.S_IMODE(cfg_meta.st_mode)}==expected_meta,'Original config metadata differs')
        require(api_get('/v2/sandboxes?limit=1')==(200,[]),'Original service not empty')
        candidate=Path(plan['candidate']);require(candidate.parent==Path(plan['work'])/'observer','Unexpected candidate scope')
        pattern=r'(?m)^daemon_binary_path\s*=\s*"([^"]+)"\s*$'
        matches=list(re.finditer(pattern,raw.decode()))
        require(len(matches)==1 and matches[0][1]==str(BASE/'bin/uvm-ublk-daemon'),'Unexpected original daemon field')
        expected_new=re.sub(pattern,lambda _: 'daemon_binary_path = '+json.dumps(str(candidate)),raw.decode()).encode()
        require(hashlib.sha256(expected_new).hexdigest()==plan['new_config_sha256'],'Configuration delta exceeds daemon path only')
        require(hashlib.sha256(scoped_read(candidate,128*1024**2)).hexdigest()==plan['candidate_sha256']=='eed36d01de13f83a8abdc13e93c21883a3a48273da83fa1c813e65e4655babcf','Candidate differs')
        require(hashlib.sha256(scoped_read(candidate.with_suffix('.access-spec'))).hexdigest()==plan['spec_sha256'],'Observer spec differs')
        endpoint=Path(plan['endpoint']);require(endpoint.parent==ROOT/'r' and endpoint.name=='c4-'+plan['run_id'][:12]+'.sock','Endpoint outside scope')
        meta=endpoint.lstat();require(stat.S_ISSOCK(meta.st_mode) and meta.st_uid==1204 and stat.S_IMODE(meta.st_mode)==0o600,'Endpoint metadata differs')
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(600);sock.connect(str(endpoint));check_peer(plan,sock)
        armed=True
        wire_send(sock,{'op':'ready'})
        require(wire_recv(sock)=={'op':'activate'},'Unexpected activation request')
        require(unit_state()==before and other_units()==others,'Service identities changed')
        require(api_get('/v2/sandboxes?limit=1')==(200,[]),'Guest appeared before restart')
        require(hashlib.sha256(scoped_read(config)).hexdigest()==plan['new_config_sha256'],'Candidate config differs')
        # Only this existing original unit is restarted, never stopped/unloaded.
        changed=True;report['restart_requests']+=1;subprocess.run(['/usr/bin/systemctl','restart',UNIT],check=True,timeout=90);report['restart_calls']+=1
        active=wait_health();assert_unit(active)
        require(other_units()==others,'Other services changed during activation')
        wire_send(sock,{'op':'activated','identity':[int(active['MainPID']),active['ticks']]})
        until=time.monotonic()+5400
        while time.monotonic()<until:
            request=wire_recv(sock);op=request.get('op')
            current=unit_state();require((current['MainPID'],current['ticks'])==(active['MainPID'],active['ticks']),'Active Runtime changed')
            if op=='bind':
                require(not bound,'Duplicate binding request');bound=bind_guests(plan,active,request['jobs'])
                observer=json.loads(scoped_read(Path(plan['work'])/'observer/trace.status.json'))
                pid=observer['pid'];ticks=identity(pid)[1]
                require(Path(os.readlink(Path('/proc')/str(pid)/'exe'))==candidate,'Observer executable differs')
                parent=pid
                for _ in range(16):
                    parent=identity(parent)[0]
                    if parent==int(active['MainPID']):break
                    require(parent>1,'Observer outside original service')
                require(parent==int(active['MainPID']),'Observer ancestry unavailable')
                report['observer_identity']=[pid,ticks]
                wire_send(sock,{'op':'bound','bindings':bound,'observer_identity':[pid,ticks]})
            elif op=='sample':
                rows=[]
                for b in bound:
                    m=whole_process_metrics(b['pid'],b['start_ticks'])
                    rows.append(dict(m,sandbox_id=b['sandbox_id'],template_id=b['template_id'],identity_verified=m.get('available',False)))
                wire_send(sock,{'op':'sample','unix':time.time(),'processes':rows})
            elif op=='heartbeat':wire_send(sock,{'op':'heartbeat'})
            elif op=='restore':break
            else:raise RuntimeError('Unexpected supervisor request')
        else:raise RuntimeError('Root session deadline exceeded')
        report['status']='COW4_ROOT_SESSION_ENDING'
    except BaseException as e:
        report.update(status='STOPPED_COW4_ROOT_SESSION',error_type=type(e).__name__,reason=str(e))
    finally:
        try:
            require(armed,'Supervisor never armed; no restoration action')
            current_hash=hashlib.sha256(scoped_read(config)).hexdigest()
            if current_hash==plan['new_config_sha256']:
                # Recovery is limited to exact original bytes and an empty service.
                require(api_get('/v2/sandboxes?limit=1')==(200,[]),'Guests remain; retain candidate configuration for recovery')
                if active:
                    s=unit_state();require((s['MainPID'],s['ticks'])==(active['MainPID'],active['ticks']),'Runtime changed before restoration')
                temporary=config.with_name('runtime.toml.cow4-restore-'+plan['run_id'])
                fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,expected_meta['mode'])
                with os.fdopen(fd,'wb') as f:
                    f.write(raw);f.flush();os.fsync(f.fileno());os.fchown(f.fileno(),expected_meta['uid'],expected_meta['gid']);os.fchmod(f.fileno(),expected_meta['mode'])
                require(hashlib.sha256(scoped_read(config)).hexdigest()==plan['new_config_sha256'],'Config changed during restore')
                os.replace(temporary,config)
                report['restart_requests']+=1;subprocess.run(['/usr/bin/systemctl','restart',UNIT],check=True,timeout=90);report['restart_calls']+=1
                restored=wait_health();require(api_get('/v2/sandboxes?limit=1')==(200,[]),'Restored service not empty')
                report['restored_identity']=[int(restored['MainPID']),restored['ticks']]
                report['original_configuration_restored']=True
                report['original_service_healthy']=True
                if report.get('observer_identity'):
                    pid,ticks=report['observer_identity']
                    try:alive=identity(pid)[1]==ticks
                    except (FileNotFoundError,ProcessLookupError):alive=False
                    require(not alive,'Observer still alive after original service restart')
                    report['observer_exit_confirmed']=True
                for b in bound:
                    try:alive=identity(b['pid'])[1]==b['start_ticks']
                    except (FileNotFoundError,ProcessLookupError):alive=False
                    require(not alive,'A bound Guest still exists after service restoration')
                report['bound_guest_processes_exited']=True
            elif current_hash==plan['original_config_sha256'] and not changed:
                report['original_configuration_restored']=True
            else:raise RuntimeError('Unrecognized configuration/runtime state; no blind restore')
            report['other_services_unchanged']=other_units()==report.get('other_services_before')
            require(report['other_services_unchanged'],'Other service identity differs')
            if report['status']=='COW4_ROOT_SESSION_ENDING':report['status']='COW4_ROOT_SESSION_RESTORED'
        except BaseException as e:report['restoration_error']={'type':type(e).__name__,'reason':str(e)}
        if sock:
            try:wire_send(sock,{'op':'restored','report':report})
            except OSError:pass
            sock.close()
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT',flush=True)
