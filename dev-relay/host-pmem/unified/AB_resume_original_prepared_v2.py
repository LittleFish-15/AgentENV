"""Reuse the prepared original experiment; remove manager EnvironmentFile reads."""
import base64,hashlib,json,os,socket,subprocess,sys,threading,time,types
from pathlib import Path
PIN='78dc13208bda586473d01416426b8023d75a5a080c12623efb15fc07f883f61b'
RUN='original-t1-20261030-r2'

def make_wrapper(server,config,environment):
    # The file is read by the existing service UID, not by systemd's manager.
    return ('import json,os\nfrom pathlib import Path\n'
        'env=dict(os.environ);env.update(json.loads(Path('+repr(str(environment))+').read_bytes()))\n'
        'os.execve('+repr(str(server))+','+repr([str(server),'--config',str(config)])+',env)\n').encode()

def main():
    entry=Path('/home/jwk/root/original-t1/original-entry.py');raw=entry.read_bytes()
    if os.geteuid()!=0 or entry.resolve()!=entry or entry.stat().st_uid!=0 or hashlib.sha256(raw).hexdigest()!=PIN:
        raise RuntimeError('Expected prepared original entry')
    m=types.ModuleType('prepared_original');m.__file__=str(entry);sys.modules[m.__name__]=m
    exec(compile(raw,str(entry),'exec'),m.__dict__)
    class Prepared(m.OriginalContext):
        def __init__(self):
            os.umask(0o077);self.node={'server1':'node-a','agent1':'node-b'}.get(socket.gethostname());m.need(self.node,'Only A/B')
            self.n=self.node[-1];self.peer='node-b' if self.n=='a' else 'node-a';old=m.BASE/self.node
            started=json.loads(m.read(old/'started.json'));m.need(started['identity']==m.identity() and started['sourceSha256']==PIN,'Prepared node/boot differs')
            m.need(not (old/'cohort.json').exists(),'Old Guest phase must be reconciled, not restarted')
            self.lockfd=os.open(old/'operation.lock',os.O_RDWR|os.O_NOFOLLOW);m.fcntl.flock(self.lockfd,m.fcntl.LOCK_EX|m.fcntl.LOCK_NB)
            units=json.loads(m.read(old/'units.json'));m.need(set(units)=={'runtime'},'Unexpected previous units')
            previous=units['runtime'];status=m.props(previous['name'])
            m.need(previous['state']=='launch_intent' and status['Description']==previous['description'] and status['MainPID']=='0'
                and status['ActiveState']=='failed','Failed prepared Runtime is not quiescent')
            self.work=old/'resume-r2';m.mkdir(self.work);m.need(not (self.work/'started.json').exists(),'Resume already started; do not repeat')
            self.public=m.BASE/'public';self.active=m.ROOT/('orig-'+self.n);self.pin=m.digest(m.read(Path(__file__),256*1024))
            api=m.load_module('prepared_transport',m.decode(m.BUNDLED['API']));self.transport=api
            tokens=json.loads(m.read(Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json'),8192))
            self.control=api.GitHub(tokens['controlToken']);self.results=api.GitHub(tokens['resultToken'])
            self.control.private_repo(m.CONTROL,1438089258);self.results.private_repo(m.RESULTS,1438089386)
            code,auth,_=self.control.contents(m.CONTROL,'approvals/'+RUN+'.json','main');m.need(code==200,'Prepared original approval missing')
            self.approval=json.loads(auth);m.need(self.approval['humanApproved'] and self.approval['entrySha256']==self.pin,'Prepared original code differs')
            self.expected=dict(self.approval['nodes'][self.node],identity=m.identity())
            m.need(self.expected['identity']==self.approval['nodes'][self.node]['identity'],'Prepared experiment boot differs from approval')
            m.need(api.timestamp(self.approval['notBefore'])<=time.time()<api.timestamp(self.approval['expiresAt']),'Resume approval expired')
            self.case=None;self.jobs=[];self.processes=[];self.files=[];self.devices=[];self.bindings={}
            self.runtime=None;self.proxy=None;self.original_units={};self.permissions=[];self.permission_error=None
            self.stop=threading.Event();self.lock=threading.RLock();self.background_daemons={}
            for proc in Path('/proc').iterdir():
                if not proc.name.isdigit():continue
                try:
                    if 'uvm-ublk' in (proc/'comm').read_text() and m.MEM.identity(int(proc.name))['uids']==[1204]*4:
                        self.background_daemons[int(proc.name)]=m.MEM.identity(int(proc.name))
                except (FileNotFoundError,ProcessLookupError):continue
            self.before_devices={p.name:(p.lstat().st_ino,p.lstat().st_rdev) for p in Path('/dev').glob('ublk[bc]*')}
            m.atomic(self.work/'started.json',{'identity':m.identity(),'sourceSha256':self.pin,'preparedInputsReused':True,
                'oldUnitsPreserved':units,'SDKCalled':False})
        def launch(self,label,argv,extra):
            name='aenv-original-t1-'+self.n+'-'+label+'-1030r2.service'
            m.need(m.props(name)['LoadState']=='not-found','Resume unit already exists')
            row={'name':name,'description':RUN+' '+self.node+' '+label,'state':'launch_intent'}
            self.original_units[label]=row;m.atomic(self.work/'units.json',self.original_units)
            properties=['Type=exec','Restart=no','UMask=0077','KillMode=control-group','TimeoutStopSec=90','LimitNOFILE=65536',
                'LimitCORE=0','StandardOutput=journal','StandardError=journal','WorkingDirectory=/','Description='+row['description'],*extra]
            try:
                m.run(['systemd-run','--unit='+name,*['--property='+p for p in properties],'--',*argv],30)
                p=m.props(name);m.need(p['ActiveState']=='active' and int(p['MainPID'])>0,'Resume service not active')
                row.update(pid=int(p['MainPID']),ticks=m.MEM.identity(int(p['MainPID']))['startTicks'],state='active')
                m.atomic(self.work/'units.json',self.original_units);return row
            except BaseException:
                details={'unit':row,'commands':[]}
                for command in (['systemctl','show',name,'--no-pager','--property=MainPID,ActiveState,LoadState,Result,ExecMainCode,ExecMainStatus,ExecStartPre,User,Group,SupplementaryGroups'],
                    ['journalctl','-b','-u',name,'--no-pager','-n','50','-o','short-precise']):
                    p=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
                    details['commands'].append({'exitCode':p.returncode,'stdout':self.transport.redact(p.stdout[-65536:],[self.key]).decode(errors='replace'),
                        'stderr':self.transport.redact(p.stderr[-8192:],[self.key]).decode(errors='replace')})
                m.atomic(self.work/(label+'-launch-failure.json'),details);raise
        def prepare(self):
            old=m.BASE/self.node;configuration=json.loads(m.read(old/'configuration.json'))
            m.need(configuration['identity']==m.identity(),'Prepared configuration boot differs')
            for relative,expected in self.approval['binaries'].items():
                item=configuration['binaries'][relative];m.need(item['path']==str(m.ORIGINAL/relative),'Prepared binary path differs')
                body=m.read(Path(item['path']),128*1024**2)
                m.need(m.digest(body)==expected['sha256'] and len(body)==expected['bytes'],'Prepared original binary differs')
            self.app=types.SimpleNamespace(plan={'binaries':configuration['binaries'],'sourceDeployment':str(m.ORIGINAL)})
            templates,steps=m.INPUT.load_inputs(m.SOURCE,self.n,1,m.read,m.REPLAY.steps_from)
            self.template=templates[0];self.steps=steps[0];m.INPUT.check_catalogs(m.SOURCE,templates,m.read)
            m.need(self.template['resources']=={'cpu_count':2,'memory_mib':4096,'disk_size_mib':65536} and len(self.steps)==32,'Prepared workload/resources differ')
            repository=m.SOURCE/'state/snapshot-store/repository';record=m.read(repository/'catalog/records'/(self.template['templateId']+'.json'))
            m.need(m.read(self.active/'seed/repository/catalog/records'/(self.template['templateId']+'.json'))==record,'Prepared seed record differs')
            for kind,layers in [('rootfs',self.template['rootfsLayers']),('memory',json.loads(record)['committed']['memory_layers'])]:
                for layer in layers:
                    name=layer['digest'].replace(':','_')+'.overlaybd.commit';p=repository/'managed-layers'/name;target=self.active/'seed/repository/managed-layers'/name
                    st=p.stat();other=target.stat();m.need(p.resolve()==p and st.st_uid==1204 and st.st_size==layer['size']
                        and (st.st_dev,st.st_ino)==(other.st_dev,other.st_ino),'Prepared lower link differs')
                    self.files.append({'path':str(p),'category':kind+'-lower-source','identity':m.MEM.immutable_identity(st),'immutable':True})
            if self.n=='a':
                p=Path('/home/jwk/agent/r/hpd4-a-v1/rootfs-lowers.ext4')
                if p.exists():self.files.append({'path':str(p),'category':'full-source-image','identity':m.MEM.immutable_identity(p.stat()),'immutable':True})
            self.helper=self.public/('owner-'+self.n)
            m.need(m.digest(m.read(self.helper,1024**2))==self.expected['ownerHelper']['sha256'],'Prepared owner query tool differs')
            env=dict(line.split('=',1) for line in m.read(old/'runtime.env',16384).decode().splitlines() if '=' in line)
            m.need(env['AENV_CONFIG_PATH']==str(self.public/('runtime-'+self.n+'.toml')) and env['API_ADDR']=='127.0.0.1:18231','Prepared environment differs')
            config=m.tomllib.loads(m.read(Path(env['AENV_CONFIG_PATH'])).decode());m.need(config==configuration['config'],'Prepared TOML differs')
            self.key=env['AENV_API_KEY'];self.env={'HOME':'/home/jwk','PATH':env['PATH'],'LANG':'C.UTF-8',
                'XDG_CONFIG_HOME':str(self.active/'cli'),'LD_LIBRARY_PATH':env['LD_LIBRARY_PATH']}
            private=self.active/'private';m.mkdir(private,1204)
            env_path=private/'runtime-env.json';m.put(env_path,m.wire(env),1204,1205,0o600)
            m.need(not env_path.stat().st_mode&0o077 and env_path.stat().st_uid==1204,'Private service environment permissions differ')
            wrapper=self.public/('exec-private-env-'+self.n+'.py')
            m.put(wrapper,make_wrapper(configuration['binaries']['bin/server']['path'],env['AENV_CONFIG_PATH'],env_path))
            # Root prestart code stays in argv, not in a home file read by PID1.
            pre='import os;assert os.stat("/proc/self/ns/net").st_ino!='+str(os.stat('/proc/self/ns/net').st_ino)+';open("/proc/sys/net/ipv4/ip_forward","w").write("1\\n")'
            command="import base64;exec(base64.b64decode('"+base64.b64encode(pre.encode()).decode()+"'))"
            device=Path('/dev/ublk-control').stat();m.need(device.st_gid!=0 and device.st_mode&0o060==0o060,'Original control group unavailable')
            self.runtime=self.launch('runtime',['/usr/bin/python3','-I','-B',str(wrapper)],
                ['User=1204','Group=1205','SupplementaryGroups=ubsmd kvm '+str(device.st_gid),'AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN',
                 'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN','PrivateNetwork=yes','PrivateMounts=yes',
                 'ExecStartPre=+/usr/bin/python3 -I -B -c "'+command+'"']);self.pid=self.runtime['pid']
            proxy=m.decode(m.BUNDLED['PROXY']).decode().replace("assert re.fullmatch('/home/jwk/agent/r/hpab-[ab]-v1/active/api.sock',cfg['socket'])", "assert re.fullmatch('/home/jwk/root/orig-[ab]/api.sock',cfg['socket'])")
            m.put(self.public/'proxy.py',proxy.encode());m.put(self.public/('proxy-'+self.n+'.json'),m.wire({'port':18231,'socket':str(self.active/'api.sock')}))
            self.proxy=self.launch('inside-proxy',['/usr/bin/python3','-I','-B',str(self.public/'proxy.py'),'inside',str(self.public/('proxy-'+self.n+'.json'))],
                ['User=1204','Group=1205','PrivateNetwork=yes','JoinsNamespaceOf='+self.runtime['name'],'NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities='])
            deadline=time.monotonic()+60
            while not (self.active/'api.sock').exists():self.guard();m.need(time.monotonic()<deadline,'Prepared proxy socket not ready');time.sleep(.3)
            self.api=m.Api(self)
            while True:
                self.guard()
                try:
                    if self.api.call('GET','/v2/sandboxes?limit=1')==(200,[]):break
                except (OSError,ValueError):pass
                m.need(time.monotonic()<deadline,'Prepared original API not healthy');time.sleep(.5)
            self.processes=[self.process_row(self.pid,'runtime'),self.process_row(os.getpid(),'collector')]
            m.atomic(self.work/'configuration.json',{'identity':m.identity(),'config':config,'binaries':configuration['binaries'],
                'startupFix':'private environment read by scoped jwk wrapper; no EnvironmentFile','EnvironmentFileUsed':False})
    m.RUN=RUN;ctx=Prepared()
    try:ctx.execute()
    except BaseException as error:
        value={'status':'ORIGINAL_RESUME_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,
            'reason':str(error)[:700] if isinstance(error,RuntimeError) else type(error).__name__}
        m.atomic(ctx.work/'failure-local.json',value)
        try:
            if ctx.runtime:ctx.failure_details()
            ctx.event('failed',value)
        except Exception:pass
        print(json.dumps(value),flush=True);raise
    finally:
        try:m.upload_small(ctx)
        except Exception as error:
            m.atomic(ctx.work/'upload-error-local.json',{'errorType':type(error).__name__,'reason':str(error)[:500]})
            print('PRIVATE_REPORT_UPLOAD_PENDING='+type(error).__name__,flush=True)

if __name__=='__main__':main()
