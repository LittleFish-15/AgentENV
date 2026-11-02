"""Verify an already committed Titanic snapshot; never recreate or restart it."""
import base64,hashlib,json,os,re,stat,subprocess,sys,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/root/titanic-candidate-capture-20261102')
ACTIVE=Path('/home/jwk/agent/dsbench-20261102/candidate-a')
SID='01a19b76-130a-75c2-bf0a-76b49acc1943'
OLD=Path('/home/jwk/root/relay/jobs/titanic-candidate-capture-20261102-007-node-a/task.py')
OLD_SHA='37fcd05752773b227cb5b35d3644b0553175eb6a3204d570af0dd771cff52cb1'
REPORT_SHA='8b37460ab6051ca574bc7204ee9a9c19db5d0704bf09a2aea12afefb5dfc5d81'
WORKER_SHA='9cac55deb8c1e3d79f6004f71654dd59bb1f6690960b94d33cef5b05f98c01dc';WORKER_Z64='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'

def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def read(path,limit=4*1024**2):
    need(path.resolve()==path and path.is_file() and path.stat().st_size<=limit,'Input path/size differs')
    return path.read_bytes()
def normalize_layers(record):
    committed=record['committed'];roots=[]
    for row in committed['rootfs_layers']:
        need(isinstance(row,dict) and set(row)=={'Managed'},'External/unknown rootfs reference requires explicit support')
        roots.append(row['Managed'])
    memory=committed['memory_layers']
    need(0<len(roots)<=64 and 0<len(memory)<=16,'Unexpected snapshot layer count')
    for row in roots+memory:
        need(isinstance(row,dict) and set(row)<={'digest','size','uuid'} and {'digest','size'}<=set(row)
             and re.fullmatch('sha256:[0-9a-f]{64}',row['digest']) and type(row['size']) is int and 0<row['size']<=8*1024**3,
             'Invalid managed layer descriptor')
    return roots,memory

def main():
    need(os.getuid()==os.geteuid()==0,'Root metadata verification only')
    previous=json.loads(read(OLD.parent/'report.json'))
    need(sha(wire(previous))==REPORT_SHA and previous['state']=='completed' and previous['exitCode']==1,'Previous root failure receipt differs')
    raw=read(OLD);need(sha(raw)==OLD_SHA,'Frozen capture driver differs')
    m=types.ModuleType('verified_capture_driver');m.__file__=str(OLD);sys.modules[m.__name__]=m;exec(compile(raw,str(OLD),'exec'),m.__dict__)
    state_raw=read(ROOT/'state.json');state=json.loads(state_raw)
    need(state['phase']=='template_build_requested' and state['templateId']==SID and state.get('pending') is None
         and state.get('failure')=={'type':'KeyError','reason':"'digest'"},'Not the post-publication layer-decoding failure')
    need(state['identity']['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Snapshot owner boot changed')
    m.STATE.update(state);m.KEY=json.loads(read(ACTIVE/'private/runtime-env.json'))['AENV_API_KEY']
    live=m.props();need(live.get('ActiveState')=='active' and int(live['MainPID'])==state['runtime']['pid']
        and m.ticks(state['runtime']['pid'])==state['runtime']['ticks'],'Existing capture Runtime is not the same process')
    need(m.api('GET','/health')['status']==204,'Existing Runtime unhealthy; do not restart')
    result=m.api('GET',f'/templates/{SID}/builds/{SID}/status')
    need(result['status']==200 and result['body']['status']=='ready','Published template is not ready')
    repo=ACTIVE/'seed/repository';directory=repo/'snapshots'/SID
    need(read(directory/'commit')==b'committed','Commit marker missing')
    record_path=repo/'catalog/records'/(SID+'.json')
    # The optional startup-recording continuation may finish after API ready.
    fc=ACTIVE/'deps/firecracker/1.15.1-patch-v3/firecracker';fm=fc.stat();pid=state['runtime']['pid']
    deadline=time.monotonic()+60
    while True:
        cg=Path('/proc',str(pid),'cgroup').read_text();remaining=[]
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:
                st=(proc/'exe').stat()
                if (st.st_dev,st.st_ino)==(fm.st_dev,fm.st_ino) and (proc/'cgroup').read_text()==cg:remaining.append(int(proc.name))
            except (FileNotFoundError,ProcessLookupError):continue
        if not remaining:break
        need(time.monotonic()<deadline,'Startup-recording Guest remains active; preserve without restart');time.sleep(1)
    record_raw=read(record_path);record=json.loads(record_raw)
    need(record['id']==SID and record['resources']=={'cpu_count':2,'memory_mib':4096,'disk_size_mib':65536},'Captured resource or ID differs')
    committed=record['committed'];need(not committed.get('attached_drives') and not committed.get('volume_snapshots'),'Unexpected additional snapshot dependency')
    roots,memory=normalize_layers(record)
    need(committed['runtime_versions']['tools_drive_version']=='0.1.1','Unexpected tools version')
    artifacts=[];resolved_roots=[]
    for kind,layers in (('rootfs',roots),('memory',memory)):
        for row in layers:
            path=repo/'managed-layers'/(row['digest'].replace(':','_')+'.overlaybd.commit')
            need(path.stat().st_uid==1204 and path.stat().st_size==row['size'] and 'sha256:'+m.file_sha(path)==row['digest'],'Captured layer bytes differ')
            item={**row,'file':str(path),'kind':kind};artifacts.append(item)
            if kind=='rootfs':resolved_roots.append({k:item[k] for k in ('file','digest','size')})
    manifest=json.loads(read(directory/'firecracker-manifest.json'))
    need(not manifest.get('nativeRootfs') and not manifest.get('attachedDrives') and manifest['memory']['virtualSize']==4096*1024**2,'Unexpected manifest payload geometry')
    for name in ('vm_state.bin','firecracker-manifest.json','commit'):
        path=directory/name;need(path.stat().st_size>0,'Snapshot artifact empty');artifacts.append({'kind':name,'file':str(path),'bytes':path.stat().st_size,'sha256':m.file_sha(path)})
    startup=committed.get('memory_startup')
    if startup:
        path=directory/'memory-startup.pack'
        need(startup['mem_virtual_size']==4096*1024**2 and path.stat().st_size==startup['pack_size'] and m.file_sha(path)==startup['index_sha256'],'Startup descriptor/payload mismatch')
        artifacts.append({'kind':'memory-startup.pack','file':str(path),'bytes':path.stat().st_size,'sha256':startup['index_sha256']})
    source=json.loads(read(m.INPUT));need(sha(wire(source))==m.CONVERSION_RECORD_SHA,'Converted-source provenance changed')
    expected={r['digest'] for r in source['images'][0]['rootfsLowers']}
    need(expected<={r['digest'] for r in roots},'Snapshot omits converted Titanic base')
    need(read(record_path)==record_raw,'Catalog changed while verifying artifacts')
    m.put(ROOT/'post-capture007-state.json',state_raw,0,0o600)
    verification={'status':'TITANIC_EXISTING_TEMPLATE_VERIFIED_NO_RECAPTURE','templateId':SID,'catalogSha256':sha(record_raw),
        'repository':str(repo),'resources':record['resources'],'runtimeVersions':committed['runtime_versions'],
        'rootfsLayers':resolved_roots,'memoryLayers':memory,'artifacts':artifacts,'startupPackPresent':bool(startup),
        'rootfsLogicalPayloadBytes':sum({r['digest']:r['size'] for r in roots}.values()),
        'dependencyBuildReady':True,'businessTrainingExecuted':False,'temporaryFcExited':True,
        'RuntimeRestarted':False,'GuestCreatedByThisTask':False,'UBAllocated':False}
    m.put(ROOT/'snapshot-verified.json',wire(verification),0,0o600)
    # Keep an exact private copy of the small catalog for later node transfer.
    m.put(ROOT/'verified-catalog.json',record_raw,0,0o600)
    m.STATE['previousVerificationFailure']=m.STATE.pop('failure');m.STATE.update(phase='committed_template_verified',verification=verification);m.checkpoint()
    print('BEGIN_TITANIC_SNAPSHOT_VERIFICATION');print(json.dumps(verification,indent=2));print('END_TITANIC_SNAPSHOT_VERIFICATION',flush=True)
    worker=zlib.decompress(base64.b64decode(WORKER_Z64));need(sha(worker)==WORKER_SHA,'Pinned image worker differs')
    worker_path=ROOT/'public/prepare-image.py';m.put(worker_path,worker,0,0o644)
    result=subprocess.run(['setpriv','--reuid=1204','--regid=1205','--clear-groups','--inh-caps=-all','--ambient-caps=-all',
        '--bounding-set=-all','--no-new-privs','/usr/bin/python3','-I','-B',str(worker_path)],
        input=wire({'templateId':SID,'catalogSha256':sha(record_raw),'rootfsLayers':resolved_roots}),
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=2400,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/jwk','LANG':'C','LC_ALL':'C'})
    need(len(result.stdout)<=256*1024,'Image preparation log exceeds bound')
    print(result.stdout.decode(errors='replace'),flush=True)
    need(result.returncode==0,'Snapshot verified but image preparation failed; do not recapture')
    m.STATE.update(phase='template_verified_and_host_image_prepared_no_UB');m.checkpoint()

if __name__=='__main__':main()
