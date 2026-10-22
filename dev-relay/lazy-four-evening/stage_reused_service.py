"""Stage isolated v2 launchers on a confirmed inactive retained deployment.

No service start, SDK call, Guest creation, binary replacement or image copy.
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
CANDIDATE_PIN='400caf60d3da96b27a65dcdba7330eec11905bbecd6d537cf160d23125b022b9'
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

def build_payload(candidate,definition_raw,installation_raw,node):
    m=library(candidate,D/'libexec/lazy-v2/native_prepare.py',CANDIDATE_PIN)
    m.select_node(node)
    definition=json.loads(definition_raw);receipt=json.loads(installation_raw)
    need(definition.get('node')==node and definition.get('rootfsBinding') is None,'Ordinary node definition required')
    need(receipt.get('node')==node and receipt.get('commit')==CORE and receipt.get('unit')==m.UNIT
         and receipt.get('runtime')==str(m.RUNTIME) and receipt.get('binaries')==definition['binaries'],
         'Retained installation provenance differs')
    definition['definitionSha256']=sha(definition_raw)
    definition['prepareSourceSha256']=sha(candidate)
    base=base64.b64decode(m.BASE_SOURCE_B64,validate=True)
    need(sha(base)==m.BASE_SOURCE_SHA,'Embedded base differs')
    launcher=m.adapter(definition)
    receipt.update(launcher=str(D/'libexec/lazy-v2/native_service.py'),launcher_sha256=sha(launcher),
                   launcher_dependencies={'native_base.py':sha(base),'native_prepare.py':sha(candidate)})
    files={'native_prepare.py':candidate,'native_base.py':base,'native_service.py':launcher,
           'installation.json':(json.dumps(receipt,indent=2)+'\n').encode()}
    for name,raw in files.items():
        if name.endswith('.py'):ast.parse(raw)
    return files

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
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--node',choices=('node-a','node-b'),required=True);p.add_argument('--run',action='store_true')
    args=p.parse_args()
    if not args.run:print('STAGE_ONLY_PLAN_NO_SERVICES_OR_SDK');return
    import fcntl
    need(os.getuid()==os.geteuid()==1204 and socket.gethostname()==('server1' if args.node=='node-a' else 'agent1'),'Use declared ordinary node')
    os.umask(0o077)
    old_path=D/'libexec/native_prepare.py'
    need(old_path.resolve(strict=True)==old_path and old_path.stat().st_uid==1204 and old_path.stat().st_size<=512*1024,'Unexpected old library file')
    old=library(old_path.read_bytes(),old_path,OLD_PREPARE_PIN);old.select_node(args.node)
    fd=os.open(D/'cohort.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1,'Unexpected retained cohort lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        units=[old.UNIT,'jwk-ub-lazy-four-'+args.node+'-v1.service','jwk-ub-lazy-four-'+args.node+'-v2.service']
        before={u:unit_inactive(u) for u in units}
        session=ROOT/('r/lazy4-a-v1' if args.node=='node-a' else 'r/lazy4-b-v1')
        validate_quiescent(old.read_json(D/'cohort-state.json'),old.read_json(session/'provider/owner.json'),args.node)
        definition_raw=old.own(D/'definition-native.json',1024**2)
        definition=json.loads(definition_raw)
        definition.update(definitionSha256=sha(definition_raw),prepareSourceSha256=OLD_PREPARE_PIN)
        checked=old.make_module(definition);checked.identity();checked.no_caps();checked.installed()
        installation_raw=old.own(D/'installation.json',1024**2)
        candidate_path=ROOT/'lazy-four-v2/prepare_lazy_four_reuse_v2.py'
        candidate=old.own(candidate_path,512*1024)
        files=build_payload(candidate,definition_raw,installation_raw,args.node)
        destination=D/'libexec/lazy-v2'
        need(destination.parent.resolve(strict=True)==destination.parent and destination.parent.stat().st_uid==1204,'Unexpected launcher parent')
        need(not destination.exists() and not destination.is_symlink(),'Existing or partial stage preserved; do not restage blindly')
        need({u:unit_inactive(u) for u in units}==before,'Unit state changed during stage validation')
        destination.mkdir(mode=0o700)
        report={'status':'V2_LAUNCHERS_STAGED_NOT_ACTIVATED','node':args.node,'files':{},'SDK_called':False,
                'Guest_created':False,'servicesChanged':False,'binariesChanged':False,'oldLaunchersOverwritten':False,
                'oldInstallationSha256':sha(installation_raw),'definitionSha256':sha(definition_raw)}
        for name,raw in files.items():
            with (destination/name).open('xb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            report['files'][name]=sha(raw)
        fresh=library(candidate,destination/'native_prepare.py',CANDIDATE_PIN);fresh.select_node(args.node)
        fresh.make_module(definition).installed()
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
