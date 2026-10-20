"""Stage one measured template for a strict-UB peer, without copying its layers.

export-a writes one private JSON input for operator SCP/SFTP to B. stage-b
validates and stages it outside the live repository, and reports deployment
prerequisites. Neither mode loads SDK, executes imported code or changes units.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

ROOT=Path('/home/jwk/agent')
MOD=ROOT/'deployments/agentenv-ub-b019f27'
OLD=ROOT/'deployments/agentenv-ae9c626-baseline'
SNAPSHOT='01a15804-9c11-7c82-89c9-9384f7223607'
CATALOG_SHA='39c7335c34f3620b8007a78be638e93517502ff2e6484af091ddb629e4ce04e5'
SEED='2cff88de7f864cf2a8d683a1f7a4c9ce'
RUNTIME_COMMIT='b019f270a6c4359db0ad65ef669dd0e479056603'
MAX_INPUT=48*1024**2
MAX_METADATA=32*1024**2
BINARIES={'server':'e8ea6c30704ec511f0b2a479313bb4cd4f71d25adc5acb6548adafe5f980b231',
          'aenv':'be2c3b339bf077e66d6646c1ecafdf38392a4c2ca327cd6a26ab5433afc66546',
          'uvm-ublk-daemon':'6d73405d4d30777355c43df68361616c9ff2639cbc0347fd8dec4c56b93e5879'}
DEPS=('deps/firecracker/1.15.1-patch-v3/firecracker',
      'deps/kernel/vmlinux-6.1.175/vmlinux.bin','deps/tools/0.1.1/tools.ext4')
FILES=('catalog/records/'+SNAPSHOT+'.json','snapshots/'+SNAPSHOT+'/vm_state.bin',
       'snapshots/'+SNAPSHOT+'/firecracker-manifest.json','snapshots/'+SNAPSHOT+'/commit')

def need(ok,why):
    if not ok:raise RuntimeError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def safe(path,exists=False):
    path=Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT),'Path outside project')
    need(path.resolve(strict=exists)==path,'Redirected project path')
    return path

def read(path,limit=MAX_INPUT):
    safe(path,True)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_uid==1204 and a.st_size<=limit,'Unexpected input type/owner/size: '+path.name)
        raw=f.read(limit+1);b=os.fstat(f.fileno())
        need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns)
             and len(raw)==a.st_size,'Input changed: '+path.name)
        return raw

def fingerprint(path,limit=512*1024**2):
    safe(path,True)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_uid==1204 and a.st_size<=limit,'Unexpected artifact')
        h=hashlib.sha256();total=0
        for chunk in iter(lambda:f.read(1024**2),b''):
            total+=len(chunk);need(total<=a.st_size,'Artifact grew');h.update(chunk)
        b=os.fstat(f.fileno());need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns) and total==a.st_size,'Artifact changed')
        return {'sha256':h.hexdigest(),'bytes':total}

def put(path,raw):
    safe(path);safe(path.parent)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.exists():
        need(read(path)==raw,'Existing different file preserved: '+path.name);return
    tmp=path.with_name(path.name+'.'+os.urandom(8).hex()+'.part')
    try:
        with tmp.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.link(tmp,path)  # exclusive publication, never overwrite
    finally:
        if tmp.exists():tmp.unlink()

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def units(node):
    rows={}
    for kind,unit in [('original','jwk-aenv-ae9c626-'+node+'.service'),('modified','jwk-aenv-ub-b019f27-'+node+'.service')]:
        p=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,SubState,MainPID,User,Group,PrivateNetwork,PrivateMounts'],
                         capture_output=True,text=True,check=True,timeout=10)
        d=dict(s.split('=',1) for s in p.stdout.splitlines() if '=' in s)
        pid=int(d.get('MainPID') or 0)
        if pid:
            try:d['start_ticks']=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
            except OSError:d['start_ticks']=None
        rows[kind]=d
    return rows

def api_observation(port,base):
    key=read(base/'config/api-key',1024).decode().strip()
    need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',key),'Unexpected credential format; value withheld')
    result={}
    for name,path in [('health','/health'),('inventory','/v2/sandboxes?limit=1')]:
        c=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
        try:
            c.request('GET',path,headers={'X-API-Key':key});r=c.getresponse();raw=r.read(1024**2+1)
            need(len(raw)<=1024**2,'Oversized API response')
            result[name+'_http']=r.status
            if name=='inventory':result['empty']=r.status==200 and not r.getheader('x-next-token') and json.loads(raw)==[]
        except (OSError,http.client.HTTPException,ValueError) as e:
            result[name+'_error_type']=type(e).__name__
        finally:c.close()
    return result

def layer_inventory(raw):
    need(sha(raw)==CATALOG_SHA,'Catalog differs from measured template')
    record=json.loads(raw);need(record['id']==SNAPSHOT,'Snapshot identity differs')
    need(record['resources']['memory_mib']==512 and record['resources']['cpu_count']==1,'Guest budget differs')
    c=record['committed']
    need(not any(c.get(k) for k in ('attached_drives','volume_snapshots','memory_startup')),'Additional dependencies unsupported')
    result=[]
    for kind,count in [('memory',2),('rootfs',14)]:
        rows=c[kind+'_layers'];need(len(rows)==count,'Layer count differs')
        for v in rows:
            if kind=='rootfs':need(set(v)=={'Managed'},'External layer unsupported');v=v['Managed']
            digest,size=v['digest'],v['size']
            need(re.fullmatch(r'sha256:[0-9a-f]{64}',digest) and type(size) is int and 0<size<2*1024**3,'Layer descriptor differs')
            result.append({'kind':kind,'digest':digest,'stored_bytes':size})
    need(len({v['digest'] for v in result})==16 and sum(v['stored_bytes'] for v in result)==1526478848,'Measured payload differs')
    return result

def validate_package(package):
    need(package.get('revision')=='ub-cross-template-input-v1' and package.get('snapshot_id')==SNAPSHOT
         and package.get('catalog_sha256')==CATALOG_SHA and package.get('marker_seed')==SEED,'Unexpected package')
    need(set(package['files'])==set(FILES),'Unexpected file selector')
    decoded={};total=0
    for name,item in package['files'].items():
        need(set(item)=={'base64','sha256','bytes'} and type(item['bytes']) is int and 0<=item['bytes']<=MAX_METADATA,'Invalid file descriptor')
        raw=base64.b64decode(item['base64'],validate=True);total+=len(raw)
        need(total<=MAX_METADATA and len(raw)==item['bytes'] and sha(raw)==item['sha256'],'Metadata checksum/size mismatch')
        decoded[name]=raw
    need(decoded[FILES[3]]==b'committed','Snapshot commit marker missing')
    layers=layer_inventory(decoded[FILES[0]])
    need(layers==package['layers'],'Layer list differs')
    need(set(package['dependencies'])==set(DEPS),'Dependency selector differs')
    for v in package['dependencies'].values():
        need(re.fullmatch(r'[0-9a-f]{64}',v['sha256']) and type(v['bytes']) is int and 0<v['bytes']<=512*1024**2,'Dependency fingerprint malformed')
    need(isinstance(json.loads(decoded[FILES[2]]),dict),'Manifest is not an object')
    return decoded,layers

def sdk_evidence(node):
    # Read receipts only. No SDK import, lock modification, or cleanup here.
    rows=[]
    for name in ('ub-layer-sdk-'+node+'.pending.json','ub-guest-'+node+'.pending.json','native-fd-'+node+'.pending.json'):
        p=ROOT/'relay'/name
        if p.exists():
            v=json.loads(read(p));rows.append({'file':name,'status':v.get('status'),'state':v.get('state'),
              'SDK_resources_released':v.get('SDK_resources_released'),'mappings_released':v.get('mappings_released'),
              'delete_acknowledged':v.get('delete_acknowledged'),'report_directory':v.get('report_directory')})
    return rows

def deployment(node):
    before=units(node);result={'units':before,'api':{},'fingerprints':{},'issues':[]}
    for kind,base,port in [('original',OLD,18080),('modified',MOD,18081)]:
        try:result['api'][kind]=api_observation(port,base)
        except (OSError,RuntimeError) as e:result['api'][kind]={'error_type':type(e).__name__}
        u=before[kind]
        if not (u.get('ActiveState')=='active' and u.get('User')==u.get('Group')=='jwk' and u.get('start_ticks')):result['issues'].append(kind+'_unit_not_verified')
        if result['api'][kind].get('health_http')!=204:result['issues'].append(kind+'_API_not_healthy')
    if not result['api']['modified'].get('empty'):result['issues'].append('modified_inventory_not_empty')
    receipt=json.loads(read(MOD/'installation.json',65536))
    wrapper='deploy_a_ub.py' if node=='node-a' else 'deploy_b_ub.py'
    rels=['config/runtime.toml','installation.json','libexec/'+wrapper]
    rels+=['libexec/'+name for name in receipt.get('launcher_dependencies',{})]
    need(all(re.fullmatch(r'deploy_[ab]_ub\.py',n) for n in receipt.get('launcher_dependencies',{})),'Unexpected launcher dependency')
    for rel in rels:result['fingerprints'][rel]=fingerprint(MOD/rel,256*1024)
    need(result['fingerprints']['libexec/'+wrapper]['sha256']==receipt['launcher_sha256'],'Launcher receipt mismatch')
    for name,digest in receipt.get('launcher_dependencies',{}).items():need(result['fingerprints']['libexec/'+name]['sha256']==digest,'Library receipt mismatch')
    for name,digest in BINARIES.items():
        value=fingerprint(MOD/'bin'/name);need(value['sha256']==digest,'Modified binary differs: '+name)
        result['fingerprints']['bin/'+name]=value
    need(receipt.get('commit')==RUNTIME_COMMIT,'Runtime source differs')
    result['installation_boot_matches']=receipt.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not result['installation_boot_matches']:result['issues'].append('installation_boot_context_differs')
    lib=read(MOD/'libexec/deploy_a_ub.py',256*1024).decode()
    result['restart_guards']={'refused_proxy_socket_guard':'def prepare_inside_socket(' in lib,
                             'stale_runtime_attestation_guard':'def publish_runtime_attestation(' in lib}
    config=read(MOD/'config/runtime.toml',65536).decode()
    section=re.search(r'(?ms)^\[firecracker\]\s*\n(.*?)(?=^\[|\Z)',config)
    need(section is not None,'Missing Firecracker section')
    fc={k:json.loads(v) for k,v in re.findall(r'(?m)^(work_dir|serial_dir|log_level)\s*=\s*("[^"\n]*")\s*$',section[1])}
    result['firecracker_settings']=fc
    result['short_work_dir_expected']=str(ROOT/('r/fc-a-ub' if node=='node-a' else 'r/fc-b-ub'))
    result['UB_environment_present']=('AENV_UB_MEMORY_REPLICAS' in lib or 'AENV_UB_ROOTFS_REPLICAS' in lib)
    result['SDK_receipts']=sdk_evidence(node)
    sources=ROOT/'src/agentenv-ub-0118ebb/tools/ub-snapshot'
    result['SDK_build_inputs']={}
    for name in ('sdk_smoke.py','ub_layer_broker.py','bridge.cpp'):
        path=sources/name
        result['SDK_build_inputs'][name]=fingerprint(path,512*1024) if path.exists() else {'available':False}
    result['compiler_available']=shutil.which('g++') is not None
    try:
        with Path('/sys/bus/ub/ub_feature').open() as f:result['ub_feature_first_line']=f.readline(513).strip()
    except OSError as e:result['ub_feature_error_type']=type(e).__name__
    after=units(node);need(after==before,'Runtime changed during preparation')
    return result

def export_a(work,report):
    previous=json.loads(read(ROOT/'relay/ub-guest-node-a.pending.json'))
    need(previous.get('status')=='A_UB_ALL_LAYERS_GUEST_CONTROLLED_COMPLETED' and previous.get('SDK_resources_released')
         and previous.get('modified_service_restored_healthy') and previous.get('all_UB_payloads_verified_after_Guest_exit'),'Previous A batch not released')
    need(set(previous['Guest']['known_sandboxes'])==set(previous['Guest']['released_sandboxes']),'Previous Guest cleanup incomplete')
    repo=MOD/'state/snapshot-store/repository'
    files={};total=0
    for name in FILES:
        raw=read(repo/name,MAX_METADATA);total+=len(raw);need(total<=MAX_METADATA,'Metadata copy budget exceeded')
        files[name]={'base64':base64.b64encode(raw).decode(),'sha256':sha(raw),'bytes':len(raw)}
    package={'revision':'ub-cross-template-input-v1','snapshot_id':SNAPSHOT,'catalog_sha256':CATALOG_SHA,'marker_seed':SEED,
      'files':files,'layers':layer_inventory(base64.b64decode(files[FILES[0]]['base64'])),
      'dependencies':{rel:fingerprint(MOD/rel) for rel in DEPS},'source_run_id':previous['run_id']}
    validate_package(package);raw=encoded(package);need(len(raw)<=MAX_INPUT,'Input package too large')
    target=ROOT/'ub_cross_template.json';put(target,raw)
    report.update(status='A_CROSS_TEMPLATE_EXPORTED_NO_SDK',input_file=str(target),input_sha256=sha(raw),input_bytes=len(raw),
                  metadata_bytes=total,layer_payload_bytes_copied=0,dependency_fingerprints=package['dependencies'])

def stage_b(work,report,input_path):
    raw=read(input_path,MAX_INPUT);package=json.loads(raw);files,layers=validate_package(package)
    report.update(input_sha256=sha(raw),input_bytes=len(raw))
    report['deployment']=deployment('node-b')
    report['dependency_comparison']={}
    for rel,expected in package['dependencies'].items():
        observed=fingerprint(MOD/rel);report['dependency_comparison'][rel]={'expected':expected,'observed':observed,'matches':expected==observed}
        need(expected==observed,'Native dependency mismatch: '+rel)
    staged=ROOT/'relay/ub-cross-input'/SNAPSHOT
    for rel,data in files.items():put(staged/rel,data)
    put(staged/'input.json',raw)
    # Stage only; registering a template without its active UB index would make
    # it visible but unrestorable while the normal service is still UB-off.
    repo=MOD/'state/snapshot-store/repository';present=[]
    for a in layers:
        p=repo/'managed-layers'/(a['digest'].replace(':','_')+'.overlaybd.commit');safe(p)
        if p.exists():present.append(a['digest'])
    report.update(status='B_CROSS_METADATA_STAGED_REVIEW_RUNTIME_PREREQUISITES',staged_directory=str(staged),
      metadata_bytes=sum(map(len,files.values())),layer_payload_bytes_copied=0,
      existing_local_layer_count=len(present),existing_local_layer_digests=present,
      live_catalog_exists=(repo/FILES[0]).exists(),registered_in_live_repository=False)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('export-a','stage-b'))
    parser.add_argument('--input',type=Path,default=ROOT/'ub_cross_template.json')
    args=parser.parse_args();node='node-a' if args.mode=='export-a' else 'node-b'
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Ordinary jwk identity required')
    need(os.uname().nodename==('server1' if node=='node-a' else 'agent1'),'Wrong node')
    caps=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(caps[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapAmb')),'Capability-free preparation required')
    os.umask(0o077);safe(ROOT,True);safe(ROOT/'relay/reports',True)
    work=Path(tempfile.mkdtemp(prefix=node+'-ub-cross-prepare-',dir=ROOT/'relay/reports'))
    report={'revision':'ub-cross-prepare-v1','mode':args.mode,'node':node,'report_directory':str(work),
       'snapshot_id':SNAPSHOT,'SDK_called':False,'services_modified':False,'Guest_created':False,
       'live_repository_modified':False,'host_API_credentials_transferred':False,'status':'STOPPED_CROSS_PREPARATION'}
    try:
        if args.mode=='export-a':export_a(work,report)
        else:stage_b(work,report,args.input)
    except Exception as error:
        report.update(status='STOPPED_CROSS_PREPARATION',error_type=type(error).__name__,reason=str(error))
    put(work/'return.json',encoded(report))
    print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
    return 1 if report['status'].startswith('STOPPED') else 0

if __name__=='__main__':raise SystemExit(main())
