"""One largest measured stored layer through SDK publish, broker read and cleanup.

Default is plan only. --run-reviewed requires the exact explicit logical budget.
No Guest, Rust format probe, service configuration or other UB object is changed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT=Path('/home/jwk/agent')
HELPERS=ROOT/'src/agentenv-ub-0118ebb/tools/ub-snapshot'
REPO=ROOT/'deployments/agentenv-ub-b019f27/state/snapshot-store/repository'
PENDING=ROOT/'relay/ub-real-layer-canary-node-a.pending.json'
DIGEST='sha256:c161b9691ab6551a7b10cba283c2e525003378be3fc9193a12cac85c783d47d2'
STORED=564057088
REQUEST=540*1024**2
COVERAGE_LIMIT=1024*1024**2
HASHES={'sdk_smoke.py':'e16f672f6a0dbfc83a4b013aed76adb14904f5322fcded305c0614d095f8967f',
        'ub_layer_broker.py':'d111bf915fea62e6d6cbf450734a5c4e256346b3c7f820f7e69b3384ed1b5dfb',
        'bridge.cpp':'503a5f64d93568e7b536410a4c89bbefa637fc38fbab781bcc138bf89cedba84'}

def need(ok,why):
    if not ok:raise RuntimeError(why)

def safe(path):
    need(path.is_relative_to(ROOT) and path.resolve()==path,'Outside or redirected path')
    if path.exists():need(path.lstat().st_uid==1204,'Unexpected owner')
    return path

def read(path,limit=1024**2):
    safe(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        m=os.fstat(f.fileno());need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size<=limit,'Unexpected input metadata')
        raw=f.read(limit+1);need(len(raw)==m.st_size,'Input changed/grew');return raw

def units():
    result={}
    for unit in ('jwk-aenv-ae9c626-node-a.service','jwk-aenv-ub-b019f27-node-a.service'):
        p=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState,MainPID,User,Group'],
                         capture_output=True,text=True,timeout=10,check=True)
        s=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
        need(s.get('ActiveState')=='active' and s.get('User')==s.get('Group')=='jwk','Expected runtime not active: '+unit)
        pid=int(s['MainPID']);need(pid>1,'Invalid service identity')
        ticks=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
        result[unit]=[pid,ticks]
    return result

def source_layer():
    done=json.loads(read(ROOT/'relay/cow-modified-controlled-node-a.pending.json'))
    need(done.get('status')=='MODIFIED_UB_OFF_CONTROLLED_COMPLETED_REVIEW_COMPARABILITY'
         and done.get('restore_outcome_uncertain') is False and done.get('snapshot_outcome_uncertain') is False
         and len(done.get('known_sandboxes',[]))==4
         and set(done['known_sandboxes'])==set(done.get('released_sandboxes',[])),'Completed comparison/cleanup required')
    sid=done['snapshot_id'];need(isinstance(sid,str) and re.fullmatch(r'[0-9a-f-]{36}',sid),'Invalid template')
    raw=read(REPO/'catalog/records'/(sid+'.json'))
    need(hashlib.sha256(raw).hexdigest()==done['catalog_sha256'],'Measured catalog changed')
    layers=json.loads(raw)['committed']['rootfs_layers']
    matching=[x.get('Managed') for x in layers if isinstance(x,dict) and x.get('Managed',{}).get('digest')==DIGEST]
    need(len(matching)==1 and matching[0]['size']==STORED,'Largest measured layer differs')
    path=safe(REPO/'managed-layers'/(DIGEST.replace(':','_')+'.overlaybd.commit'));m=path.lstat()
    need(stat.S_ISREG(m.st_mode) and m.st_size==STORED,'Stored source size/type differs')
    return path,sid

def load_helpers():
    for name,digest in HASHES.items():need(hashlib.sha256(read(HELPERS/name)).hexdigest()==digest,'Reviewed UB helper differs: '+name)
    spec=importlib.util.spec_from_file_location('reviewed_real_layer_smoke',HELPERS/'sdk_smoke.py')
    s=importlib.util.module_from_spec(spec);sys.modules[spec.name]=s;spec.loader.exec_module(s)
    need(s.b.ALIGN==4*1024**2 and s.b.HEADER_BYTES==4096,'Broker layout differs')
    need(((STORED+s.b.HEADER_BYTES+s.b.ALIGN-1)//s.b.ALIGN)*s.b.ALIGN==REQUEST,'Logical request differs')
    return s

def exercise(s,source,library,work,report,backend_factory):
    b=s.b;backend=publisher=broker=None;passed=False
    try:
        backend=backend_factory(library,COVERAGE_LIMIT)
        publisher=b.Publisher(backend,work/'owner-receipt.json')
        report['SDK_runtime_started']=True;report['state']='INTENT_BEFORE_SDK';b.atomic_json(PENDING,report)
        print('PHASE=publish_one_real_layer logical_mib=540',flush=True)
        replicas,mappings=publisher.publish({DIGEST:(source,STORED)},work/'broker.sock',REQUEST)
        need(len(replicas)==len(mappings)==1 and replicas[0].mappingBytes==REQUEST,'Unexpected publication shape')
        report.update(object_name=replicas[0].objectName,generation=replicas[0].generation,
                      published_stored_bytes_verified=True,backing_coverage_bytes=getattr(mappings[0],'backing_coverage',None))
        broker=b.Broker(replicas,mappings);broker.start(replicas[0].brokerSocket)
        print('PHASE=read_entire_real_layer_through_readonly_broker',flush=True)
        s.probe(replicas[0],broker)
        report['broker_full_payload_sha256_verified']=True
        passed=True
    except BaseException as error:
        report.update(error_type=type(error).__name__,reason=str(error) if isinstance(error,(RuntimeError,ValueError)) else 'Probe interrupted/failed; inspect receipt')
    finally:
        if hasattr(signal,'SIGALRM'):signal.alarm(0)
        safe_to_release=broker is None
        if broker is not None:
            try:
                with broker.condition:
                    need(broker.condition.wait_for(lambda: broker.active==0,timeout=10),
                         'Reader did not exit; preserve owner')
                report['broker_statistics']=broker.stop();safe_to_release=True
            except BaseException as e:
                report['reader_release_error']=type(e).__name__;report['state']='OWNERSHIP_OR_IMPORT_UNRESOLVED'
        if publisher is not None:
            if safe_to_release:
                try:
                    publisher.cleanup()
                    report.update(state='COMPLETE_NO_OWNED_OBJECT',
                                  delete_acknowledged=bool(publisher.state['objects']) and all(x['delete_acknowledged'] for x in publisher.state['objects']),
                                  mappings_released=True,finalize_acknowledged=True)
                except BaseException as e:
                    report.update(state='OWNERSHIP_OR_IMPORT_UNRESOLVED',cleanup_error=type(e).__name__+': '+str(e))
            report['owned_objects']=publisher.state['objects']
        if backend is not None:
            report['allocation_calls_observed']=backend.allocation_calls
            report['mapping_coverage_observations']=[getattr(m,'backing_coverage',None) for m in backend.mappings]
        report['status']=('ONE_REAL_LARGE_LAYER_PUBLISHED_READ_VERIFIED_AND_RELEASED'
                          if passed and report.get('state')=='COMPLETE_NO_OWNED_OBJECT'
                          and report.get('allocation_calls_observed')==1 else 'STOPPED_REAL_LAYER_CANARY_PRESERVE_RECEIPT')
        b.atomic_json(work/'return.json',report);b.atomic_json(PENDING,report)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-reviewed',action='store_true')
    parser.add_argument('--logical-budget-mib',type=int)
    parser.add_argument('--max-backing-coverage-mib',type=int)
    args=parser.parse_args()
    need(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    need(len(caps)==4 and all(int(x,16)==0 for x in caps),'Capability-free session required')
    source,sid=source_layer()
    report={'revision':'ub-real-largest-layer-v1','snapshot_id':sid,'digest':DIGEST,'stored_bytes':STORED,
            'logical_request_bytes':REQUEST,'allocation_calls_limit':1,'allocation_calls_observed':0,
            'max_backing_coverage_inspection_bytes':COVERAGE_LIMIT,'physical_hard_quota':False,
            'physical_limit_note':'Coverage is checked after creation/mapping; this is not a pre-allocation physical cap or a physical-increment measurement.',
            'physical_increment_measured':False,'UB_pool_free_bytes':None,'SDK_runtime_started':False,
            'SDK_backing_placement_verified':False,
            'deadline_policy':'600-second soft transfer deadline; cleanup is attempted without forced termination. A blocking SDK call may overrun the deadline.',
            'Guest_created':False,'services_modified':False,'B_accessed':False,
            'OverlayBD_logical_format_validation':False,'cross_node_validation':False,
            'scope':'One actual stored rootfs layer via SDK and local read-only broker, no published service index',
            'state':'NO_OBJECT_CREATED','status':'PLAN_ONLY_NO_SDK_CALLS'}
    if not args.run_reviewed:
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT');return 0
    need(args.logical_budget_mib==540 and args.max_backing_coverage_mib==1024,'Explicit reviewed 540MiB logical / 1024MiB post-map inspection values required')
    os.umask(0o077);import fcntl
    fd=os.open(safe(ROOT/'relay/ub-layer-sdk-node-a.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        m=os.fstat(fd);need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_nlink==1,'SDK lock metadata differs')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(not PENDING.exists(),'Canary pending exists; preserve it, no repeat allocation')
        s=load_helpers();s.previous_guard(ROOT/'relay/ub-layer-sdk-node-a.pending.json','node-a')
        with Path('/sys/bus/ub/ub_feature').open() as stream:feature=stream.readline(513).strip()
        need(int(feature,0)&4,'NC sharing not advertised')
        before=units()
        work=Path(tempfile.mkdtemp(prefix='node-a-ub-real-layer-',dir=safe(ROOT/'relay/reports')))
        report.update(report_directory=str(work),ub_feature=feature,services_before=before,started_unix=time.time())
        class LimitedBackend(s.b.NativeBackend):
            def __init__(self,*a):
                super().__init__(*a);self.transferred={'read':0,'write':0}
            def allocate(self,replica):
                need(self.allocation_calls==0 and replica.mappingBytes==REQUEST,'One exact allocation only')
                return super().allocate(replica)
            def call(self,operation,*arguments):
                result=super().call(operation,*arguments)
                if operation in self.transferred:
                    old=self.transferred[operation];self.transferred[operation]+=int(arguments[-1])
                    if old//(64*1024**2)!=self.transferred[operation]//(64*1024**2):
                        print('PHASE=UB_transfer direction='+operation+' completed_bytes='+str(self.transferred[operation]),flush=True)
                return result
        try:
            print('PHASE=compile_small_SDK_bridge_only',flush=True)
            s.build(work);report['bridge_compiled']=True
            report['bridge_sha256']=hashlib.sha256((work/'libaenv_ub_bridge.so').read_bytes()).hexdigest()
            def deadline(*_):raise RuntimeError('Soft transfer deadline exceeded; attempt own cleanup')
            signal.signal(signal.SIGALRM,deadline);signal.alarm(600)
            exercise(s,source,work/'libaenv_ub_bridge.so',work,report,LimitedBackend)
            report['services_unchanged']=units()==before
            if not report['services_unchanged']:report['status']='STOPPED_SERVICE_IDENTITY_CHANGED_REVIEW_RECEIPT'
        except (Exception,KeyboardInterrupt) as e:
            report.update(status='STOPPED_REAL_LAYER_CANARY_PRESERVE_RECEIPT',error_type=type(e).__name__,
                          reason=str(e) if isinstance(e,(RuntimeError,ValueError)) else 'See bounded build/SDK logs')
        finally:
            signal.alarm(0);report['finished_unix']=time.time()
            s.b.atomic_json(work/'return.json',report)
            if report['SDK_runtime_started']:s.b.atomic_json(PENDING,report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 0 if report['status']=='ONE_REAL_LARGE_LAYER_PUBLISHED_READ_VERIFIED_AND_RELEASED' else 1
    finally:os.close(fd)

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_REAL_LAYER_ENTRY','error_type':type(e).__name__,
              'reason':str(e) if isinstance(e,(RuntimeError,ValueError)) else 'Entry failed; preserve existing receipts'},indent=2))
        print('END_RETURN_REPORT');raise SystemExit(1)
