"""Pasted inline only: two exact modified-unit restarts and scoped measurements.

Requires the previously reviewed collector and framing functions in this namespace.
Never execute this user-writable file as root.
"""
def root_ub_session(review,endpoint):
    import hashlib,http.client,json,os,re,socket,stat,struct,subprocess,time
    from pathlib import Path
    receipt={'revision':'ub-guest-root-v1','run_id':review['run_id'],'actions':[],
             'SDK_called':False,'Guest_commands_executed':False}
    started=False;activated=None;sample_number=0
    phases=('baseline','a_first','a_repeat','b_disjoint')
    def props():
        p=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--property=LoadState,ActiveState,MainPID,User,Group,PrivateNetwork,PrivateMounts'],
                         capture_output=True,text=True,timeout=10,check=True)
        return dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
    def current():
        p=props()
        if p.get('MainPID')=='0' and p.get('ActiveState') in ('inactive','failed'):return None
        require(p.get('ActiveState')=='active' and p.get('User')==p.get('Group')=='jwk'
                and p.get('PrivateNetwork')==p.get('PrivateMounts')=='yes','Modified unit identity/isolation differs')
        pid=int(p['MainPID']);require(pid>1,'Invalid main PID')
        return [pid,identity(pid)[1]]
    def original():
        p=subprocess.run(['/usr/bin/systemctl','show','jwk-aenv-ae9c626-node-a.service','--property=ActiveState,MainPID'],
                         capture_output=True,text=True,timeout=10,check=True)
        values=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
        require(values.get('ActiveState')=='active' and int(values['MainPID'])==review['original'][0]
                and identity(review['original'][0])[1]==review['original'][1],'Original Runtime changed')
    def hashes(expected):
        require(set(expected)=={'config/runtime.toml','libexec/deploy_a_ub.py','installation.json'},'Unexpected file selectors')
        for rel,digest in expected.items():
            require(hashlib.sha256(owned(BASE/rel)).hexdigest()==digest,'Reviewed file changed: '+rel)
    def request(path,key):
        c=http.client.HTTPConnection('127.0.0.1',18081,timeout=5)
        try:
            c.request('GET',path,headers={'X-API-Key':key});r=c.getresponse();raw=r.read(1024**2+1)
            require(len(raw)<=1024**2 and not r.getheader('x-next-token'),'Unexpected API reply')
            return r.status,raw
        finally:c.close()
    def empty(key):
        code,raw=request('/v2/sandboxes?limit=1',key)
        require(code==200 and json.loads(raw)==[],'Modified Runtime has sandboxes; no restart')
    def restart(key):
        subprocess.run(['/usr/bin/systemctl','restart',UNIT],check=True,timeout=90)
        until=time.monotonic()+45
        while time.monotonic()<until:
            who=current()
            if who is None:return None,False
            try:
                if request('/health',key)==(204,b''):return who,True
            except (OSError,http.client.HTTPException):pass
            time.sleep(1)
        raise RuntimeError('Modified API not ready after bounded restart')
    def verify_rootfs(scope,index):
        expected={r['layerDigest']:r for r in index['replicas']}
        observed=[]
        for child in scope['children']:
            bound=bind(scope,child)
            cfg=json.loads(owned(bound['cwd']/'overlaybd/image.json'))
            lowers=cfg.get('lowers',[])
            require(len(lowers)==14 and {x.get('digest') for x in lowers}==set(review['rootfs_digests']),
                    'Guest rootfs lower set differs')
            for layer in lowers:
                if layer.get('ub')!=expected[layer['digest']] or layer['ub']['allowRepositoryFallback'] is not False:
                    raise BindingError('Guest rootfs is not bound to the reviewed UB replicas',
                                       {'sandbox_id':bound['sandbox_id'],'digest':layer['digest'],'observed_ub':layer.get('ub')})
            observed.append({'sandbox_id':bound['sandbox_id'],'ub_lowers':14,'fallback_allowed':False})
        return observed
    try:
        require(os.geteuid()==0 and os.uname().nodename=='server1','A existing root only')
        require(UNIT=='jwk-aenv-ub-b019f27-node-a.service','Unexpected unit scope')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==review['boot_id'],'Boot changed')
        path=Path(endpoint['path'])
        require(path.parent==ROOT/'r' and re.fullmatch(r'ub-control-[0-9a-f]{16}\.sock',path.name)
                and path.resolve(strict=True)==path,'Unexpected coordinator path')
        m=path.lstat()
        require(stat.S_ISSOCK(m.st_mode) and m.st_uid==1204 and stat.S_IMODE(m.st_mode)==0o600
                and [m.st_dev,m.st_ino]==endpoint['identity'],'Coordinator socket changed')
        key=owned(BASE/'config/api-key',1024).decode().strip()
        require(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',key),'Unexpected credential format')
        index_raw=owned(Path(review['index_path']))
        require(hashlib.sha256(index_raw).hexdigest()==review['index_sha256'],'Replica index changed')
        index=json.loads(index_raw)
        require(index.get('state')=='ready' and len(index.get('replicas',[]))==16
                and all(r.get('allowRepositoryFallback') is False for r in index['replicas']),'Incomplete/unsafe replica index')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(900);client.connect(str(path))
            pid,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(uid==1204 and pid==endpoint['pid'] and identity(pid)[1]==endpoint['ticks'],'Coordinator peer changed')
            wire_send(client,{'hello':review['run_id']})
            for _ in range(8):
                message=wire_receive(client);op=message.get('op')
                try:
                    original()
                    if op=='activate':
                        require(not started and current()==review['before'],'Activation identity changed')
                        hashes(review['enabled_hashes']);empty(key);started=True
                        activated,healthy=restart(key)
                        require(activated is not None and activated!=review['before'] and healthy,'UB activation did not become healthy')
                        reply={'ok':True,'op':op,'identity':activated,'health':204}
                    elif op=='sample':
                        require(activated is not None and sample_number<4 and message.get('phase')==phases[sample_number],'Unexpected sample sequence')
                        scope=message['scope']
                        require(scope['run_id']==review['run_id'] and scope['snapshot_id']==review['snapshot_id']
                                and scope['catalog_sha256']==review['catalog_sha256'] and scope['boot_id']==review['boot_id']
                                and scope['memory_bytes']==512*1024**2
                                and [scope['main_pid'],scope['main_start_ticks']]==activated==current(),'Guest scope differs')
                        import contextlib,io
                        with contextlib.redirect_stdout(io.StringIO()):
                            result=collect_scope(dict(scope,marker_targets=message['marker_targets']))
                        result['UB_rootfs_bindings']=verify_rootfs(scope,index)
                        reply={'ok':True,'op':op,'phase':phases[sample_number],'report':result,
                               'sha256':hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()}
                        sample_number+=1
                    elif op=='deactivate':
                        hashes(review['baseline_hashes']);who=current()
                        if who is None:
                            reply={'ok':True,'op':op,'safe_off':True,'healthy':False,'identity':None}
                        elif not started and who==review['before']:
                            reply={'ok':True,'op':op,'safe_off':True,'healthy':True,'identity':who}
                        else:
                            require(activated is None or who==activated,'Modified identity changed unexpectedly')
                            empty(key);after,healthy=restart(key)
                            require(after is None or after!=who,'Old UB-enabled process remains')
                            reply={'ok':True,'op':op,'safe_off':True,'healthy':healthy,'identity':after}
                    else:raise RuntimeError('Unsupported supervisor operation')
                    original()
                except Exception as error:
                    reply={'ok':False,'op':op,'error_type':type(error).__name__,
                           'reason':str(error) if isinstance(error,RuntimeError) else 'Bounded operation failed'}
                    if isinstance(error,BindingError):reply['binding_diagnostics']=error.diagnostics
                receipt['actions'].append({k:v for k,v in reply.items() if k!='report'})
                wire_send(client,reply)
                if op=='deactivate':break
        receipt['samples_completed']=sample_number
        receipt['status']='UB_ROOT_SESSION_FINISHED' if receipt['actions'] and receipt['actions'][-1].get('safe_off') else 'STOPPED_UB_ROOT_SESSION'
    except Exception as error:
        receipt.update(status='STOPPED_UB_ROOT_SESSION',error_type=type(error).__name__,
                       reason=str(error) if isinstance(error,RuntimeError) else 'Supervisor transport/read failure')
    print('BEGIN_RETURN_REPORT');print(json.dumps(receipt,indent=2));print('END_RETURN_REPORT')
