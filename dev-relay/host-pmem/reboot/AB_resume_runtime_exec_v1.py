"""Retry only an attributable failed 203/EXEC Runtime; keep SDK/DAX intact."""
import hashlib,json,os,platform,sys,types,fcntl,time
from pathlib import Path
B=Path('/var/lib/agentenv-hpab-services-v1')
PIN='1f388bb505c655bfd0b494f20f4ab13ad7e2b3ab57f34cbf525e72b350e89358'
def main():
    assert os.getuid()==os.geteuid()==0
    p=B/'entry.py';raw=p.read_bytes();assert p.resolve()==p and p.stat().st_uid==0 and hashlib.sha256(raw).hexdigest()==PIN
    m=types.ModuleType('approved');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
    api=m.module('api');auth=json.loads(m.read(B/'private/approval.json'))
    node={'server1':'node-a','agent1':'node-b'}[platform.node()];assert auth['nodes'][node]['identity']==m.identity()
    tokens=json.loads(m.read(m.CREDS,8192,owners=(1204,)))
    control,result=api.GitHub(tokens['controlToken']),api.GitHub(tokens['resultToken'])
    control.private_repo(m.CONTROL,1438089258);result.private_repo(m.RESULTS,1438089386)
    fd=os.open(B/'private/operation.lock',os.O_RDWR|os.O_NOFOLLOW)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        app=m.Start(api,auth,control,result,node)
        assert app.state['steps']['runtime']['state']=='intent' and 'proxies' not in app.state['steps']
        assert not app.state.get('runtimeExecRepairAttempted')
        app.bound('sdk');app.bound('view');app.candidate_live()
        old=app.state['units']['runtime'];status=m.props(old['name'])
        assert status['ActiveState']=='failed' and status['MainPID']=='0' and status['ExecMainStatus']=='203'
        assert status['Description']==old['description'] and status['ControlGroup']==''
        server=app.plan['binaries']['bin/server']['path']
        assert m.digest(server)==app.plan['binaries']['bin/server']['sha256']
        assert m.digest(B/'public/rootfs-index.json')==app.state['steps']['view']['result']['indexSha256']
        error=app.active/'logs/runtime-exec-error.json'
        wrapper=('import json,os\nfrom pathlib import Path\n'
            'try:\n os.execve('+repr(server)+','+repr([server,'--config',str(B/'public/runtime.toml')])+',dict(os.environ))\n'
            'except OSError as e:\n Path('+repr(str(error))+').write_text(json.dumps({"errno":e.errno,"reason":e.strerror,"path":'+repr(server)+'}))\n raise SystemExit(126)\n')
        m.put(B/'public/runtime-exec-wrapper.py',wrapper.encode())
        app.state['failedRuntimeBeforeExecRepair']=old
        app.state['runtimeExecRepairAttempted']=True;app.mark('runtime_exec_repair_intent')
        report={'node':node,'identity':m.identity(),'runId':auth['runId'],'SDKReallocated':False,'viewRecreated':False}
        try:
            row=app.launch('runtime-exec-repair',['/usr/bin/python3','-I','-B',str(B/'public/runtime-exec-wrapper.py')],
                ['User=1204','Group=1205','SupplementaryGroups=ubsmd kvm',
                'AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN',
                'PrivateNetwork=yes','PrivateMounts=yes','EnvironmentFile='+str(B/'private/runtime.env'),
                'ExecStartPre=+/usr/bin/python3 -I -B '+str(B/'public/runtime-prestart.py'),
                'BindReadOnlyPaths='+app.plan['sourceManagedLayers']+':'+app.plan['privateReadonlyBindTarget']+' '+
                    str(app.work/'seed/repository/catalog')+' '+str(app.work/'seed/repository/snapshots')])
            app.state['units']['runtime']=row;app.state['units'].pop('runtime-exec-repair')
            end=time.monotonic()+90
            while time.monotonic()<end:
                app.bound('runtime')
                r=m.cmd([m.tool('nsenter'),'-t',str(row['pid']),'-n','--',m.tool('curl'),'-sS','--max-time','3',
                    '-o','/dev/null','-w','%{http_code}','http://127.0.0.1:18231/health'],10,check=False)
                if r.returncode==0 and r.stdout==b'204':break
                time.sleep(1)
            else:raise RuntimeError('Runtime health not confirmed')
            app.state['steps']['runtime']={'state':'done','result':{'unit':row,'health':204,
                'configSha256':m.digest(B/'public/runtime.toml'),'binarySha256':app.plan['binaries']['bin/server']['sha256'],
                'privateNetwork':True,'HostForwardingChanged':False,'execRepair':'Python execve plus explicit --config'}}
            app.mark('runtime_exec_repair_confirmed')
            app.start();report['status']='RUNTIME_EXEC_REPAIRED_SERVICES_HELD'
        except Exception as e:
            report.update(status='RUNTIME_EXEC_REPAIR_STOPPED_PRESERVE_BACKING',errorType=type(e).__name__)
            if error.exists():report['execError']=json.loads(m.read(error))
            label='runtime-exec-repair' if 'runtime-exec-repair' in app.state['units'] else 'runtime'
            name=app.state['units'][label]['name'];report['unit']=m.props(name)
            r=m.cmd([m.tool('journalctl'),'-b','-u',name,'--no-pager','-n','50'],check=False)
            import tomllib
            secret=tomllib.loads(m.read(app.active/'cli/aenv/credentials').decode())['api_key']
            report['journal']=api.redact(r.stdout[:65536],[secret]).decode(errors='replace')
            app.mark('runtime_exec_repair_stopped_preserve_state')
        finally:
            api.atomic(B/'private/runtime-exec-repair-report.json',report)
            app.event('runtime-exec-repair',report)
            print(json.dumps(report,indent=2))
if __name__=='__main__':main()
