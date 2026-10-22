"""Stage isolated observed Runtime binaries and launchers on an inactive retained deployment.

No service start, SDK call, Guest creation, installed-binary replacement or image copy.
This is a component of the coordinated entry, not a complete field retry.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import types

ROOT=Path('/home/jwk/agent')
D=ROOT/'deployments/agentenv-lazy-four-32ce41c'
OLD_PREPARE_PIN='5015655787a4600fdd83c3b6db4fa47a417be6be36dd6dad920c23e68351d7f6'
CANDIDATE_PIN='dd6ba06fdb6cd36e9bdf8069aec8891d4ae9e7a18f18d4b89c17eca0af260dd5'
CANDIDATE_CORE='6ab53dd2e1f33cb63cbad63eb62a3388494e382c'
CORE='32ce41c0ac6436198860f888e07ef9793e58dc40'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def library(raw,path,pin):
    need(sha(raw)==pin,'Unexpected preparation library')
    ast.parse(raw)
    m=types.ModuleType('reviewed_reuse_library');m.__file__=str(path)
    exec(compile(raw,str(path),'exec'),m.__dict__)
    return m

def validate_build(report):
    need(report.get('status')=='CONTENT_OBSERVER_BINARIES_BUILT_TESTED_NOT_DEPLOYED'
         and report.get('release',{}).get('coreCommit')==CANDIDATE_CORE
         and report.get('release',{}).get('published') is True
         and report.get('SDK_called') is False and report.get('Guest_created') is False
         and report.get('servicesChanged') is False,'Candidate build identity or completion differs')
    required={'native-archive-file-lifecycle-tests','provider-protocol-and-archive-tests',
              'content-observer-source-tests','build-content-observer-binaries'}
    need(set(report.get('phases',{}))==required and all(v.get('exitCode')==0 for v in report['phases'].values()),'Candidate build/test phases incomplete')
    need(set(report.get('artifacts',{}))=={'server','uvm-ublk-daemon'},'Unexpected candidate artifact set')
    need(report.get('observerSourceSha256')==report['release'].get('observerSourceSha256')
         and isinstance(report['observerSourceSha256'],str) and len(report['observerSourceSha256'])==64,
         'Missing observer build identity')
    return report


def build_payload(candidate,definition_raw,installation_raw,node,build):
    validate_build(build)
    m=library(candidate,D/'libexec/observed-v3/native_prepare.py',CANDIDATE_PIN)
    m.select_node(node)
    definition=json.loads(definition_raw);receipt=json.loads(installation_raw)
    need(definition.get('node')==node and definition.get('rootfsBinding') is None,'Ordinary node definition required')
    need(receipt.get('node')==node and receipt.get('commit')==CORE and receipt.get('unit')==m.UNIT
         and receipt.get('runtime')==str(m.RUNTIME) and receipt.get('binaries')==definition['binaries'],
         'Retained installation provenance differs')
    config=definition['config']
    old='daemon_binary_path = "'+str(D/'bin/uvm-ublk-daemon')+'"'
    new='daemon_binary_path = "'+str(D/'libexec/observed-v3/bin/uvm-ublk-daemon')+'"'
    need(config.count(old)==1,'Exactly one retained daemon configuration required')
    definition['config']=config.replace(old,new)
    definition['retainedDefinitionSha256']=sha(definition_raw)
    definition['coreCommit']=CANDIDATE_CORE
    definition['observerSourceSha256']=build['observerSourceSha256']
    for name,item in build['artifacts'].items():definition['binaries'][name]=item['sha256']
    public_definition=(json.dumps(definition,indent=2,sort_keys=True)+'\n').encode()
    definition['definitionSha256']=sha(public_definition)
    definition['prepareSourceSha256']=sha(candidate)
    base=base64.b64decode(m.BASE_SOURCE_B64,validate=True)
    need(sha(base)==m.BASE_SOURCE_SHA,'Embedded base differs')
    launcher=m.adapter(definition)
    receipt.update(commit=CANDIDATE_CORE,binaries=definition['binaries'],
                   launcher=str(D/'libexec/observed-v3/native_service.py'),launcher_sha256=sha(launcher),
                   launcher_dependencies={'native_base.py':sha(base),'native_prepare.py':sha(candidate)})
    files={'native_prepare.py':candidate,'native_base.py':base,'native_service.py':launcher,
           'installation.json':(json.dumps(receipt,indent=2)+'\n').encode(),
           'definition.json':public_definition,'runtime.toml':definition['config'].encode()}
    for name,raw in files.items():
        if name.endswith('.py'):ast.parse(raw)
    return files


def observation_spec(seed, output):
    repository=Path(seed['repository'])
    need(repository.is_absolute() and repository.resolve(strict=True)==repository,'Unexpected retained snapshot repository')
    rows={}
    for template in seed['templates']:
        for layer in template['rootfsLayers']:
            digest=layer['digest'];size=layer['size']
            need(isinstance(digest,str) and len(digest)==71 and digest.startswith('sha256:')
                 and all(c in '0123456789abcdef' for c in digest[7:]) and type(size) is int and size>0,
                 'Malformed retained content identity')
            path=repository/'managed-layers'/(digest.replace(':','_')+'.overlaybd.commit')
            meta=path.lstat()
            need(path.resolve(strict=True)==path and stat.S_ISREG(meta.st_mode) and meta.st_uid==1204
                 and meta.st_size==size,'Retained lower metadata changed')
            item=(meta.st_dev,meta.st_ino,size)
            need(digest not in rows or rows[digest]==item,'Content identity maps to inconsistent node files')
            rows[digest]=item
    need(1<=len(rows)<=64,'Unexpected lower inventory')
    lines=['output='+str(output),'max_bytes=268435456','max_records=1000000']
    for digest,(dev,ino,size) in sorted(rows.items()):
        lines.extend(['allow='+str(dev)+':'+str(ino)+':'+str(size),'allow_content='+digest+':'+str(size)])
    raw=('\n'.join(lines)+'\n').encode()
    need(len(raw)<=65536,'Observer spec exceeds limit')
    return raw


def unit_inactive(unit):
    p=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID'],capture_output=True,text=True,timeout=15)
    fields=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
    need(p.returncode==0 or fields.get('LoadState')=='not-found','Cannot inspect exact experiment unit')
    need(fields.get('MainPID')=='0' and fields.get('ActiveState')=='inactive','Experiment service still active; no launcher stage')
    return fields

def validate_quiescent(journal,provider,node):
    need(journal.get('phase')=='quiesced' and journal.get('sandboxIds')==[]
         and journal.get('openRequests')==[] and journal.get('outcomeUncertain') is False,'Retained Guest lifecycle not quiescent')
    need(provider.get('state')=='released' and provider.get('finalizeAcknowledged') is True
         and (node=='node-b' or provider.get('deleteAcknowledged') is True),'Prior UB generation not explicitly released')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--node',choices=('node-a','node-b'),required=True);p.add_argument('--run',action='store_true');p.add_argument('--artifacts',type=Path)
    args=p.parse_args()
    if not args.run:print('STAGE_ONLY_PLAN_NO_SERVICES_OR_SDK');return
    import fcntl
    need(args.artifacts is not None,'Explicit candidate artifact directory required')
    need(os.getuid()==os.geteuid()==1204 and socket.gethostname()==('server1' if args.node=='node-a' else 'agent1'),'Use declared ordinary node')
    os.umask(0o077)
    old_path=D/'libexec/native_prepare.py'
    need(old_path.resolve(strict=True)==old_path and old_path.stat().st_uid==1204 and old_path.stat().st_size<=512*1024,'Unexpected old library file')
    old=library(old_path.read_bytes(),old_path,OLD_PREPARE_PIN);old.select_node(args.node)
    fd=os.open(D/'cohort.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1,'Unexpected retained cohort lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        units=[old.UNIT,'jwk-ub-lazy-four-'+args.node+'-v1.service','jwk-ub-lazy-four-'+args.node+'-v2.service','jwk-ub-lazy-four-'+args.node+'-v3.service']
        before={u:unit_inactive(u) for u in units}
        session=ROOT/('r/lazy4-a-v1' if args.node=='node-a' else 'r/lazy4-b-v1')
        validate_quiescent(old.read_json(D/'cohort-state.json'),old.read_json(session/'provider/owner.json'),args.node)
        definition_raw=old.own(D/'definition-native.json',1024**2)
        definition=json.loads(definition_raw)
        definition.update(definitionSha256=sha(definition_raw),prepareSourceSha256=OLD_PREPARE_PIN)
        checked=old.make_module(definition);checked.identity();checked.no_caps();checked.installed()
        installation_raw=old.own(D/'installation.json',1024**2)
        candidate_path=ROOT/'lazy-four-v3/prepare_observed_service_v3.py'
        candidate=old.own(candidate_path,512*1024)
        artifacts=args.artifacts
        need(artifacts.is_absolute() and artifacts.resolve(strict=True)==artifacts
             and artifacts.is_relative_to(ROOT/'builds'),'Candidate artifacts must be in the existing owned build workspace')
        build=validate_build(old.read_json(artifacts.parent/'return.json'))
        binaries={}
        for name,item in build['artifacts'].items():
            raw=old.own(artifacts/name,256*1024**2)
            need(sha(raw)==item['sha256'] and len(raw)==item['bytes'] and raw[:6]==b'\x7fELF\x02\x01'
                 and int.from_bytes(raw[18:20],'little')==183,'Candidate ELF or digest differs')
            binaries[name]=raw
        files=build_payload(candidate,definition_raw,installation_raw,args.node,build)
        spec=observation_spec(old.read_json(D/'rootfs-inputs.json'),D/'libexec/observed-v3/observations/trace-{pid}.jsonl')
        files['bin/uvm-ublk-daemon.access-spec']=spec
        destination=D/'libexec/observed-v3'
        need(destination.parent.resolve(strict=True)==destination.parent and destination.parent.stat().st_uid==1204,'Unexpected launcher parent')
        need(not destination.exists() and not destination.is_symlink(),'Existing or partial stage preserved; do not restage blindly')
        need({u:unit_inactive(u) for u in units}==before,'Unit state changed during stage validation')
        destination.mkdir(mode=0o700)
        report={'status':'OBSERVED_V3_STAGED_NOT_ACTIVATED','node':args.node,'files':{},'SDK_called':False,
                'Guest_created':False,'servicesChanged':False,'installedBinariesChanged':False,'candidateBinariesStaged':True,'oldLaunchersOverwritten':False,'coreCommit':CANDIDATE_CORE,
                'oldInstallationSha256':sha(installation_raw),'definitionSha256':sha(definition_raw)}
        (destination/'bin').mkdir(mode=0o700)
        (destination/'observations').mkdir(mode=0o700)
        for name,raw in binaries.items():
            with (destination/'bin'/name).open('xb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            (destination/'bin'/name).chmod(0o700)
            report['files']['bin/'+name]=sha(raw)
        for name,raw in files.items():
            with (destination/name).open('xb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            report['files'][name]=sha(raw)
        fresh=library(candidate,destination/'native_prepare.py',CANDIDATE_PIN);fresh.select_node(args.node)
        candidate_definition=json.loads(files['definition.json'])
        candidate_definition['definitionSha256']=sha(files['definition.json'])
        candidate_definition['prepareSourceSha256']=sha(candidate)
        fresh.make_module(candidate_definition).installed()
        need(old.own(D/'installation.json')==installation_raw and old.own(D/'definition-native.json')==definition_raw,'Retained source metadata changed')
        need({u:unit_inactive(u) for u in units}==before,'Unit state changed while staging; no activation accepted')
        with (destination/'stage.json').open('x') as stream:
            json.dump(report,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        directory_fd=os.open(destination,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
        print(json.dumps(report,indent=2))
    finally:os.close(fd)

if __name__=='__main__':main()
