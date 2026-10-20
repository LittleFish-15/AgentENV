"""A modified-runtime UB-off comparison, reusing the measured immutable template.

prepare is read-only unless --apply-reviewed is supplied. That explicit mode
copies selected immutable inputs and changes only three FC settings, with backup.
Only the operator-pasted inline root block restarts the exact modified unit.
"""
import argparse
import ast
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time

ROOT=Path('/home/jwk/agent')
OLD=ROOT/'deployments/agentenv-ae9c626-baseline'
MOD=ROOT/'deployments/agentenv-ub-b019f27'
UNIT='jwk-aenv-ub-b019f27-node-a.service'
OLD_UNIT='jwk-aenv-ae9c626-node-a.service'
SHORT=ROOT/'r/fc-a-ub'
PREP=ROOT/'relay/cow-modified-prepare-node-a.json'
PENDING=ROOT/'relay/cow-modified-controlled-node-a.pending.json'
ENGINE_SHA='3244818005e93d1e67140d090d7d3a15cde0ae12cc7da2f3701e0a308a5d61a7'
ORIGINAL_CONFIG_SHA='1b2ced8d4ff429837ff8fb153ee1b28da52434e7193b6d2c6d52b0dc84b8a421'
BINARIES={'server':'e8ea6c30704ec511f0b2a479313bb4cd4f71d25adc5acb6548adafe5f980b231',
          'aenv':'be2c3b339bf077e66d6646c1ecafdf38392a4c2ca327cd6a26ab5433afc66546',
          'uvm-ublk-daemon':'6d73405d4d30777355c43df68361616c9ff2639cbc0347fd8dec4c56b93e5879'}
C=H=P=R=None

def state(unit):
    r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState,MainPID,User,Group'],
                     capture_output=True,text=True,check=True,timeout=10)
    fields=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
    H.need(fields.get('ActiveState')=='active' and fields.get('User')==fields.get('Group')=='jwk','Expected unit not active')
    pid=int(fields.get('MainPID',0));H.need(pid>1,'Missing main process')
    return [pid,R.identity(pid)[1]]

class Api:
    def __init__(self,base=MOD,unit=UNIT,port=18081):
        self.base=base;self.unit=unit;self.port=port;self.identity=state(unit)
        self.key=H.read(base/'config/api-key',1024).decode().strip()
        H.need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',self.key),'Unexpected credential format; value withheld')
    def call(self,method,path,data=None,timeout=20):
        H.need(state(self.unit)==self.identity,'Runtime changed')
        allowed=path in ('/health','/sandboxes','/v2/sandboxes?limit=1') or re.fullmatch(r'/sandboxes/[A-Za-z0-9_-]+(?:/snapshots)?',path)
        H.need(allowed and method in ('GET','POST','DELETE'),'Route outside experiment')
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=timeout)
        try:
            conn.request(method,path,body=json.dumps(data).encode() if data is not None else None,
                         headers={'X-API-Key':self.key,'Content-Type':'application/json'})
            r=conn.getresponse();raw=r.read(1024**2+1)
            H.need(len(raw)<=1024**2 and not r.getheader('x-next-token'),'Oversized/paginated reply')
            return r.status,json.loads(raw) if raw else None
        finally:conn.close()

def empty(api):
    code,body=api.call('GET','/v2/sandboxes?limit=1')
    H.need(code==200 and body==[],'Runtime inventory not empty')
    H.need(R.find_firecrackers(api.identity[0])==[],'Existing Firecracker descendants')

def restore(api,snapshot,run,role):
    code,body=api.call('POST','/sandboxes',{'templateID':snapshot,'timeout':900,'autoPause':False,'secure':True,
            'allow_internet_access':False,'metadata':{'cow_marker_run':run,'cow_marker_role':role}},timeout=300)
    H.need(code==201 and isinstance(body,dict),'Restore unconfirmed: '+json.dumps(H.error_summary(body,api.key)))
    sid=body.get('sandboxID');H.need(isinstance(sid,str) and H.ID.fullmatch(sid),'Missing restored ID');return sid

def digest_file(path,limit=2*1024**3):
    H.safe(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno())
        H.need(stat.S_ISREG(a.st_mode) and a.st_uid==1204 and 0<=a.st_size<=limit,'Unexpected input metadata')
        h=hashlib.sha256()
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
        z=os.fstat(f.fileno())
        H.need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns),'Input changed')
    return h.hexdigest(),a.st_size

def config_candidate(raw):
    text=raw.decode()
    insert=''.join(k+' = '+json.dumps(v)+'\n' for k,v in
                   [('work_dir',str(SHORT)),('serial_dir',str(MOD/'logs/firecracker')),('log_level','Info')])
    H.need(hashlib.sha256(raw).hexdigest()==ORIGINAL_CONFIG_SHA,'Unknown/custom modified config; preserve it')
    H.need(text.count('[firecracker]\n')==1,'Unexpected firecracker section')
    return text.replace('[firecracker]\n','[firecracker]\n'+insert,1).encode()

def launcher_candidate(raw):
    text=raw.decode()
    anchor='[firecracker]\nbinary_path = "{D}/deps/firecracker/1.15.1-patch-v3/firecracker"'
    H.need(text.count(anchor)==1,'Unexpected installed launcher config generator')
    replacement='[firecracker]\nwork_dir = "{ROOT}/r/fc-a-ub"\nserial_dir = "{D}/logs/firecracker"\nlog_level = "Info"\nbinary_path = "{D}/deps/firecracker/1.15.1-patch-v3/firecracker"'
    result=text.replace(anchor,replacement,1);ast.parse(result);return result.encode()

def selected_inputs(marker):
    snapshot=marker['measurement_snapshot_id']
    H.need(re.fullmatch(r'[0-9a-f-]{36}',snapshot),'Invalid source snapshot')
    repo=OLD/'state/snapshot-store/repository'
    raw=H.read(repo/'catalog/records'/(snapshot+'.json'));record=json.loads(raw)
    H.need(record['id']==snapshot and record['resources']['memory_mib']==512 and record['resources']['cpu_count']==1,'Wrong template budget')
    committed=record['committed']
    H.need(not committed.get('attached_drives') and not committed.get('volume_snapshots') and not committed.get('memory_startup'),
           'Additional snapshot dependencies require explicit import support')
    layers=list(committed['memory_layers'])
    for item in committed['rootfs_layers']:
        H.need(isinstance(item,dict) and set(item)=={'Managed'},'External layer not supported in this bounded import')
        layers.append(item['Managed'])
    H.need(len(committed['memory_layers'])==2 and len(committed['rootfs_layers'])==14,'Measured layer inventory differs')
    files={}
    for layer in layers:
        digest=layer.get('digest');H.need(isinstance(digest,str) and re.fullmatch(r'sha256:[0-9a-f]{64}',digest),'Invalid layer digest')
        files['managed-layers/'+digest.replace(':','_')+'.overlaybd.commit']=digest.split(':')[1]
    H.need(H.read(repo/'snapshots'/snapshot/'commit')==b'committed','Source snapshot not committed')
    for name in ('vm_state.bin','firecracker-manifest.json'):
        files['snapshots/'+snapshot+'/'+name]=None
    return snapshot,raw,files

def copy_new(source,target,expected=None):
    """No source hardlinks: independent destination inode/cache and lifecycle."""
    H.safe(source);H.safe(target)
    if target.exists():
        actual,size=digest_file(source);other,other_size=digest_file(target)
        H.need(actual==other and size==other_size and (expected is None or actual==expected),'Existing destination conflict; preserve')
        H.need((source.stat().st_dev,source.stat().st_ino)!=(target.stat().st_dev,target.stat().st_ino),'Cross-deployment hardlink rejected')
        return {'bytes':size,'sha256':actual,'reused':True}
    H.safe(target.parent);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temp=target.with_name(target.name+'.'+os.urandom(8).hex()+'.part')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        with os.fdopen(fd,'rb') as src, temp.open('xb') as dst:
            a=os.fstat(src.fileno());H.need(stat.S_ISREG(a.st_mode) and a.st_uid==1204 and a.st_size<=2*1024**3,'Source metadata differs')
            h=hashlib.sha256();total=0
            for chunk in iter(lambda:src.read(1024**2),b''):
                total+=len(chunk);H.need(total<=a.st_size,'Source grew');h.update(chunk);dst.write(chunk)
            dst.flush();os.fsync(dst.fileno());z=os.fstat(src.fileno())
            H.need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns) and total==a.st_size,'Source changed')
            H.need(expected is None or h.hexdigest()==expected,'Layer content digest differs')
        # link+unlink publishes exclusively, without replacing a concurrent file.
        os.link(temp,target);temp.unlink()
        return {'bytes':total,'sha256':h.hexdigest(),'reused':False}
    except BaseException:
        if temp.exists():temp.unlink()
        raise

def put_new(path,raw):
    H.safe(path);H.safe(path.parent);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

ROOT_RESTART=r'''
import hashlib,http.client,json,os,pathlib,re,stat,subprocess
def need(ok,why):
    if not ok:raise SystemExit('STOP: '+why)
need(os.geteuid()==0 and os.uname().nodename=='server1','A existing root only')
base=pathlib.Path('/home/jwk/agent/deployments/agentenv-ub-b019f27')
def owned(rel):
    path=base/rel
    need(path.resolve(strict=True)==path,'Redirected input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        m=os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size<65536,'Unexpected input')
        return f.read(65536)
def state(unit):
    r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState,MainPID,User,Group,PrivateNetwork,PrivateMounts'],capture_output=True,text=True,check=True,timeout=10)
    s=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
    need(s.get('ActiveState')=='active' and s.get('User')==s.get('Group')=='jwk'
         and s.get('PrivateNetwork')==s.get('PrivateMounts')=='yes','Unexpected unit')
    pid=int(s['MainPID'])
    return [pid,pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]]
need(hashlib.sha256(owned('config/runtime.toml')).hexdigest()==scope['config_sha256'],'Config changed')
need(hashlib.sha256(owned('libexec/deploy_a_ub.py')).hexdigest()==scope['launcher_sha256'],'Launcher changed')
need(hashlib.sha256(owned('installation.json')).hexdigest()==scope['installation_sha256'],'Installation receipt changed')
need(state(scope['unit'])==scope['before'],'Modified Runtime changed; no repeat restart')
need(state('jwk-aenv-ae9c626-node-a.service')==scope['original'],'Original Runtime changed')
key=owned('config/api-key').decode().strip()
need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',key),'Unexpected key')
c=http.client.HTTPConnection('127.0.0.1',18081,timeout=10)
try:
    c.request('GET','/v2/sandboxes?limit=1',headers={'X-API-Key':key});r=c.getresponse();raw=r.read(65537)
    need(r.status==200 and len(raw)<=65536 and json.loads(raw)==[] and not r.getheader('x-next-token'),'Modified Runtime not empty')
finally:c.close()
subprocess.run(['/usr/bin/systemctl','restart',scope['unit']],check=True,timeout=60)
need(state('jwk-aenv-ae9c626-node-a.service')==scope['original'],'Original process changed')
print('MODIFIED_ONLY_RESTART_SUBMITTED_RUN_JWK_COMPARISON')
'''

def prepare(work,apply):
    H.need(not PREP.exists(),'Preparation receipt exists; use run, do not repeat preparation/restart')
    a=Api(OLD,OLD_UNIT,18080);b=Api()
    for api in (a,b):H.need(api.call('GET','/health')[0]==204,'Service unhealthy');empty(api)
    marker=json.loads(H.read(P.PENDING))
    H.need(marker['status']=='INSTRUMENTED_SNAPSHOT_READY_MARKER_RESTORE_VERIFIED_GUESTS_RELEASED','Marker template not ready')
    snapshot,record,files=selected_inputs(marker)
    raw=H.read(MOD/'config/runtime.toml');candidate=config_candidate(raw)
    installed_raw=H.read(MOD/'installation.json');installed=json.loads(installed_raw)
    H.need(installed.get('source_commit',installed.get('commit'))=='b019f270a6c4359db0ad65ef669dd0e479056603','Modified installation differs')
    for name,digest in BINARIES.items():H.need(digest_file(MOD/'bin'/name)[0]==digest,'Modified binary differs: '+name)
    launcher=H.read(MOD/'libexec/deploy_a_ub.py')
    H.need(hashlib.sha256(launcher).hexdigest()==installed['launcher_sha256'],'Installed launcher changed')
    new_launcher=launcher_candidate(launcher)
    new_installed=dict(installed,launcher_sha256=hashlib.sha256(new_launcher).hexdigest())
    new_installed_raw=(json.dumps(new_installed,indent=2)+'\n').encode()
    source=OLD/'state/snapshot-store/repository';dest=MOD/'state/snapshot-store/repository'
    H.need(not (dest/'catalog/records'/(snapshot+'.json')).exists(),'Target snapshot already exists; preserve it')
    sizes=[H.safe(source/rel).stat().st_size for rel in files]
    H.need(sum(sizes)<=2*1024**3,'Selected input copy budget exceeds 2GiB')
    report={'revision':'cow-modified-prepare-v1','status':'PREPARED_NO_CHANGE','report_directory':str(work),
            'snapshot_id':snapshot,'catalog_sha256':hashlib.sha256(record).hexdigest(),'unit':UNIT,
            'original_process':a.identity,'modified_process_before':b.identity,'config_before_sha256':hashlib.sha256(raw).hexdigest(),
            'config_after_sha256':hashlib.sha256(candidate).hexdigest(),'files':{},'planned_copy_bytes':sum(sizes),
            'launcher_before_sha256':installed['launcher_sha256'],'launcher_after_sha256':new_installed['launcher_sha256'],
            'installation_after_sha256':hashlib.sha256(new_installed_raw).hexdigest(),
            'configuration_modified':False,'SDK_called':False,'B_accessed':False,'services_restarted':False,
            'cache_preparation':'Selected immutable files copied and hashed before measurement; warm destination cache, no cache eviction. Not a cold-cache comparison.'}
    (work/'runtime-before.toml').write_bytes(raw);(work/'runtime-proposed.toml').write_bytes(candidate)
    (work/'launcher-before.py').write_bytes(launcher);(work/'launcher-proposed.py').write_bytes(new_launcher)
    (work/'installation-before.json').write_bytes(installed_raw);(work/'installation-proposed.json').write_bytes(new_installed_raw)
    if apply:
        fs=os.statvfs(ROOT);H.need(fs.f_bavail*fs.f_frsize>=sum(sizes)+2*1024**3,'Insufficient free space; no cleanup')
        report['status']='PREPARATION_IN_PROGRESS';H.save(PREP,report)
        for rel,digest in files.items():
            print('PHASE=copy_verified_immutable_input '+str(len(report['files'])+1)+'/'+str(len(files)),flush=True)
            report['files'][rel]=copy_new(source/rel,dest/rel,digest);H.save(PREP,report)
        H.need(H.read(source/'catalog/records'/(snapshot+'.json'))==record,'Source record changed')
        # All data first, marker second, record last: no half-import visible to direct get.
        put_new(dest/'snapshots'/snapshot/'commit',b'committed')
        put_new(dest/'catalog/records'/(snapshot+'.json'),record)
        for api in (a,b):H.need(state(api.unit)==api.identity,'Service changed');empty(api)
        H.need(H.read(MOD/'config/runtime.toml')==raw,'Configuration changed during preparation')
        H.need(H.read(MOD/'libexec/deploy_a_ub.py')==launcher and H.read(MOD/'installation.json')==installed_raw,'Launcher/receipt changed')
        for path in (SHORT,MOD/'logs/firecracker'):H.safe(path);path.mkdir(parents=True,exist_ok=True,mode=0o700)
        for rel,new in [('config/runtime.toml',candidate),('libexec/deploy_a_ub.py',new_launcher),('installation.json',new_installed_raw)]:
            path=MOD/rel;temp=path.with_name(path.name+'.'+work.name+'.tmp');put_new(temp,new);os.replace(temp,path)
        report['configuration_modified']=True;report['status']='MODIFIED_TEMPLATE_READY_CONFIG_APPLIED_RESTART_REQUIRED'
        H.save(PREP,report)
        scope={'unit':UNIT,'before':b.identity,'original':a.identity,'config_sha256':report['config_after_sha256'],
               'launcher_sha256':report['launcher_after_sha256'],'installation_sha256':report['installation_after_sha256']}
        command="/usr/bin/python3 -I -B - <<'COW_MODIFIED_ONLY_RESTART'\nscope="+repr(scope)+'\n'+ROOT_RESTART+'\nCOW_MODIFIED_ONLY_RESTART'
        (work/'root-restart-review.txt').write_text(command)
        print('BEGIN_REVIEWED_MODIFIED_RESTART_COPY_BODY_ONLY');print(command);print('END_REVIEWED_MODIFIED_RESTART_COPY_BODY_ONLY',flush=True)
    return report

def configure_engine():
    C.BASE=MOD;C.PORT=18081;C.PENDING=PENDING;C.H=H;C.P=P;C.R=R
    P.restore=restore;P.inventory_empty=empty
    R.BASE=MOD;R.UNIT=UNIT;R.SHORT=SHORT
    source=H.read(ROOT/'cow_ram_readonly.py').decode()
    return source+"\nBASE=Path("+repr(str(MOD))+")\nUNIT="+repr(UNIT)+"\nSHORT=Path("+repr(str(SHORT))+")\n"

def run(work):
    prior=json.loads(H.read(PREP))
    H.need(prior['status']=='MODIFIED_TEMPLATE_READY_CONFIG_APPLIED_RESTART_REQUIRED','Preparation incomplete')
    H.need(hashlib.sha256(H.read(MOD/'config/runtime.toml')).hexdigest()==prior['config_after_sha256'],'Config changed')
    H.need(hashlib.sha256(H.read(MOD/'libexec/deploy_a_ub.py')).hexdigest()==prior['launcher_after_sha256'],'Launcher changed')
    H.need(hashlib.sha256(H.read(MOD/'installation.json')).hexdigest()==prior['installation_after_sha256'],'Installation receipt changed')
    H.need(state(OLD_UNIT)==prior['original_process'],'Original Runtime changed')
    api=Api();H.need(api.identity!=prior['modified_process_before'],'Modified service restart not yet verified')
    deadline=time.monotonic()+45
    while True:
        try:
            H.need(api.call('GET','/health')[0]==204,'Modified API not healthy');break
        except (OSError,http.client.HTTPException):
            H.need(time.monotonic()<deadline,'Modified health timeout');time.sleep(1)
    empty(api);H.need(not PENDING.exists(),'Comparison pending exists; no repeat')
    marker=json.loads(H.read(P.PENDING));snapshot=prior['snapshot_id']
    catalog=H.read(MOD/'state/snapshot-store/repository/catalog/records'/(snapshot+'.json'))
    H.need(hashlib.sha256(catalog).hexdigest()==prior['catalog_sha256'],'Imported catalog changed')
    for rel,e in prior['files'].items():
        # Metadata only here; hashes were verified during the bounded import.
        path=H.safe(MOD/'state/snapshot-store/repository'/rel)
        H.need(path.is_file() and path.stat().st_size==e['bytes'],'Imported artifact missing/size changed')
    source=configure_engine()
    report={'revision':'cow-modified-controlled-v1','run_id':C.uuid.uuid4().hex,'report_directory':str(work),
            'snapshot_id':snapshot,'marker_seed':marker['run_id'],'catalog_sha256':prior['catalog_sha256'],
            'source_commit':'b019f270a6c4359db0ad65ef669dd0e479056603',
            'scenario':'Modified A, UB disabled, same instrumented PyPika template and four stages',
            'restore_calls':0,'restore_calls_limit':4,'restore_outcome_uncertain':False,'snapshot_capture_calls':0,
            'snapshot_capture_calls_limit':1,'snapshot_outcome_uncertain':False,'max_simultaneous_sandboxes':2,
            'known_sandboxes':[],'cleanup_attempted':[],'released_sandboxes':[],'SDK_called':False,'UB_enabled':False,
            'services_modified':False,'B_accessed':False,'measurements':{},'root_reader_finished':False,
            'generation_and_base_content_verified':False,'original_process_before':prior['original_process'],
            'preparation_report':prior['report_directory'],'cache_preparation':prior['cache_preparation']}
    try:
        C.Experiment(api,work,report,marker).run(source)
        H.need(len(report['released_sandboxes'])==4,'Guest cleanup incomplete')
        H.need(state(OLD_UNIT)==prior['original_process'],'Original Runtime changed during comparison')
        report['original_main_process_unchanged']=True
        report['marker_physical_expectations_matched']=all(report['measurements'][p]['matches_expected'] for p in C.PHASES)
        report['status']='MODIFIED_UB_OFF_CONTROLLED_COMPLETED_REVIEW_COMPARABILITY'
    except (Exception,KeyboardInterrupt) as e:
        report.update(status='STOPPED_MODIFIED_CONTROLLED_REVIEW_RECEIPT',error_type=type(e).__name__,
                      reason=str(e) if isinstance(e,RuntimeError) else 'Inspect bounded diagnostics; no retry')
        if isinstance(e,H.ChildFailure):report['child_diagnostics']=e.diagnostics
    if report['restore_calls']:H.save(PENDING,report)
    return report

def main():
    global C,H,P,R
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['prepare','run'])
    parser.add_argument('--apply-reviewed',action='store_true');args=parser.parse_args()
    if not(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205):raise RuntimeError('A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    if len(caps)!=4 or any(int(v,16) for v in caps):raise RuntimeError('Capability-free launcher required')
    raw=(ROOT/'cow_controlled_engine.py').read_bytes()
    if (ROOT/'cow_controlled_engine.py').resolve(strict=True)!=ROOT/'cow_controlled_engine.py' or hashlib.sha256(raw).hexdigest()!=ENGINE_SHA:raise RuntimeError('Engine differs')
    import importlib.util
    spec=importlib.util.spec_from_file_location('controlled_engine',ROOT/'cow_controlled_engine.py')
    C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
    P,_=C.load(ROOT/'cow_marker_prepare_e5b9050.py',C.PREPARE_SHA,'marker_prepare');H=P.load_parent();P.H=H;C.H=H
    R,_=C.load(ROOT/'cow_ram_readonly.py',C.COLLECTOR_SHA,'scoped_reader')
    os.umask(0o077);import fcntl
    with open(H.safe(ROOT/'relay/cow-modified-node-a.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        work=Path(tempfile.mkdtemp(prefix='node-a-cow-modified-',dir=H.safe(ROOT/'relay/reports')))
        try:report=prepare(work,args.apply_reviewed) if args.mode=='prepare' else run(work)
        except (Exception,KeyboardInterrupt) as e:
            report={'status':'STOPPED_MODIFIED_'+args.mode.upper(),'report_directory':str(work),'error_type':type(e).__name__,
                    'reason':str(e) if isinstance(e,RuntimeError) else 'Preserve receipts/files; no automatic retry'}
        H.save(work/'return.json',report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 1 if report['status'].startswith('STOPPED') else 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_MODIFIED_ENTRY','error_type':type(e).__name__,
              'reason':str(e) if isinstance(e,RuntimeError) else 'Entry failure'}));print('END_RETURN_REPORT');raise SystemExit(1)
