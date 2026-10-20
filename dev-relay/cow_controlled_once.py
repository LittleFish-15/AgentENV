"""A original controlled CoW experiment; ordinary user owns all Guest mutations.

The printed inline root reader only observes two fixed VMs, returning measurements
over a one-use private local socket. No root execution of user-writable files.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import tempfile
import time
import uuid

ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-ae9c626-baseline'
PENDING=ROOT/'relay/cow-controlled-node-a.pending.json'
COLLECTOR_SHA='3ccf6de2e9bcafcff7d00cff62a5c82e3ae1d48804c41fbf881be626d9d6fdf5'
PREPARE_SHA='6569c107c75e833bdb12a54c0f368ba252fff9d6a8eb4bd07f4802a6cc002984'
PHASES=('baseline','a_first','a_repeat','b_disjoint')
H=P=R=None

# This same bounded framing implementation is pasted into the reviewed reader.
WIRE_SOURCE='''
def wire_send(client,value):
    raw=json.dumps(value,separators=(',',':')).encode()
    if len(raw)>4*1024**2:raise RuntimeError('Frame too large')
    client.sendall(struct.pack('!I',len(raw))+raw)
def wire_receive(client):
    def exact(n):
        result=bytearray()
        while len(result)<n:
            block=client.recv(min(n-len(result),65536))
            if not block:raise RuntimeError('Measurement peer disconnected')
            result.extend(block)
        return bytes(result)
    n=struct.unpack('!I',exact(4))[0]
    if not 0<n<=4*1024**2:raise RuntimeError('Frame size outside limit')
    value=json.loads(exact(n))
    if not isinstance(value,dict):raise RuntimeError('Frame must be an object')
    return value
'''
exec(WIRE_SOURCE)

ROOT_DRIVER='''
def controlled_reader(scope,endpoint):
    import contextlib,io
    receipt={'revision':'cow-controlled-root-v1','run_id':scope['run_id'],
             'read_only':True,'Guest_commands_executed':False,'phases':[]}
    try:
        require(os.geteuid()==0 and os.uname().nodename=='server1','A root only')
        path=Path(endpoint['path'])
        require(path.parent==ROOT/'r' and re.fullmatch(r'cow-control-[0-9a-f]{16}\\.sock',path.name), 'Unexpected coordinator socket')
        require(path.resolve(strict=True)==path,'Redirected coordinator socket')
        m=path.lstat()
        require(stat.S_ISSOCK(m.st_mode) and m.st_uid==1204 and stat.S_IMODE(m.st_mode)==0o600
                and [m.st_dev,m.st_ino]==endpoint['identity'],'Coordinator socket changed')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(150);client.connect(str(path))
            pid,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(uid==1204 and pid==endpoint['pid'] and identity(pid)[1]==endpoint['ticks'],'Coordinator peer changed')
            wire_send(client,{'hello':scope['run_id']})
            for phase in ('baseline','a_first','a_repeat','b_disjoint'):
                message=wire_receive(client)
                require(set(message)=={'run_id','phase','marker_targets'} and message['run_id']==scope['run_id']
                        and message['phase']==phase,'Unexpected phase request')
                current=dict(scope,marker_targets=message['marker_targets'])
                with contextlib.redirect_stdout(io.StringIO()):result=collect_scope(current)
                digest=hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()
                wire_send(client,{'phase':phase,'report':result,'sha256':digest})
                receipt['phases'].append({'phase':phase,'sha256':digest,'status':result['status']})
            # No more proc reads after this message; owner may release the pair.
            wire_send(client,{'finished':scope['run_id']})
            require(wire_receive(client)=={'ack':scope['run_id']},'Final acknowledgement missing')
        receipt['status']='ROOT_FOUR_PHASE_REPORTS_RETURNED'
    except Exception as e:
        receipt.update(status='STOPPED_CONTROLLED_ROOT_READER',error_type=type(e).__name__,
                       reason=str(e) if isinstance(e,RuntimeError) else 'Scoped read or transport failed')
    print('BEGIN_RETURN_REPORT');print(json.dumps(receipt,indent=2));print('END_RETURN_REPORT')
'''


def load(path,digest,name):
    raw=H.read(path) if H else path.read_bytes()
    if path.resolve(strict=True)!=path or hashlib.sha256(raw).hexdigest()!=digest:
        raise RuntimeError('Pinned helper differs: '+path.name)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module,raw.decode()


def expected_tags(phase,which):
    tags=['ram-base']*4;file_tag='rootfs-base'
    if which==0 and phase!='baseline':tags[0]='ram-a';file_tag='rootfs-a'
    if which==1 and phase=='b_disjoint':tags[1]='ram-b';file_tag='rootfs-b'
    return tags,file_tag


def validate_state(response,seed,reference,tags,file_tag):
    H.need(response.get('ok') is True and isinstance(response.get('status'),dict),'Marker response failed')
    state=response['status'];mapping=state.get('guest_page_mapping',{});gpas=mapping.get('guest_physical_addresses')
    H.need(state.get('seed')==seed and state.get('arena_bytes')==16*1024**2
           and state.get('segment_bytes')==state.get('rootfs_file_bytes')==4*1024**2
           and state.get('guest_page_bytes')==4096,'Marker identity/budget differs')
    H.need(state.get('server_pid')==reference['server_pid']
           and state.get('arena_guest_virtual_address')==reference['arena_guest_virtual_address'],'Marker process or address differs')
    H.need(state.get('content_verified') is True and state.get('ram_tags')==tags
           and state.get('ram_hashes')==[P.expected_hash(seed,t,i*4*1024**2,4*1024**2) for i,t in enumerate(tags)]
           and state.get('rootfs_tag')==file_tag
           and state.get('rootfs_hash')==P.expected_hash(seed,file_tag,0,4*1024**2),'Guest content/write isolation differs')
    H.need(mapping.get('available') is True and mapping.get('masked_pages')==mapping.get('swapped_pages')==0
           and isinstance(gpas,list) and len(gpas)==4096 and all(type(g) is int and g>0 and g%4096==0 for g in gpas)
           and len(set(gpas))==4096,'Guest marker GPA metadata unavailable/aliased')
    return state


def assess_measurement(result,phase,scope):
    H.need(result.get('scope')==scope,'Measurement scope differs')
    H.need(result.get('status')=='SCOPED_RAM_PAGE_AND_CACHE_OBSERVATIONS_COMPLETED'
           and len(result.get('samples',[]))==3,'Incomplete root observation')
    expected=[4*1024**2]*4
    if phase!='baseline':expected[0]=0
    if phase=='b_disjoint':expected[1]=0
    observed=[]
    for sample in result['samples']:
        segments=sample.get('marker_segments',[])
        H.need(len(segments)==4,'Marker segment measurement missing')
        values=[]
        for i,s in enumerate(segments):
            H.need(s['segment']==i and s['stable'],'Marker sample unstable')
            categories=s['physical']['categories']
            H.need(all(categories[k]['unique_bytes']==0 for k in ('zero','ksm','compound_or_huge','unclassified_nonanon')),
                   'Special/unknown marker pages require separate attribution')
            values.append(s['physical']['all_selected_guest_ram']['shared_unique_bytes'])
        observed.append(values)
    return {'expected_segment_shared_bytes':expected,'observed_segment_shared_bytes':observed,
            'matches_expected':all(v==expected for v in observed)}


def repeat_identity(first,second,sid):
    def values(report):
        return {(g['pagemap']['identity_hash'],g['segment_gpa_sha256'])
                for sample in report['samples'] for g in sample['marker_segments'][0]['guests'] if g['sandbox_id']==sid}
    a,b=values(first),values(second)
    return {'segment':0,'sandbox_id':sid,'stable_pfn_and_gpa_identity_between_windows':len(a)==len(b)==1 and a==b,
            'interpretation':'Equal observed page identities support no additional replacement at sample times; not an allocation event trace'}


def measurement_summary(result):
    """Keep the return receipt useful without dumping raw addresses or VM maps."""
    def cache(r):
        return {k:r[k] for k in ('available','resident_page_bytes','logical_file_or_device_bytes','rdev','reason') if k in r}
    def files(rows,expected_count=None):
        rows=list(rows)
        good={};missing=0
        for r in rows:
            if r.get('available'):good[(r['dev'],r['inode'])]=r
            else:missing+=1
        complete=missing==0 and bool(rows) and (expected_count is None or len(rows)==expected_count)
        return {'unique_inodes':len(good),'unavailable_files':missing,'complete_for_listed_files':complete,
                'stored_bytes':sum(r['logical_file_or_device_bytes'] for r in good.values()) if complete else None,
                'allocated_bytes':sum(r['allocated_file_bytes'] for r in good.values()) if complete else None,
                'resident_page_bytes':sum(r['resident_page_bytes'] for r in good.values()) if complete else None}
    rows=[]
    for s in result.get('samples',[]):
        lowers=s['stored_layer_cache'];rootfs=[]
        for r in s['rootfs']:
            if r.get('available') is False:rootfs.append(r);continue
            identities=sorted({str(x['local_file']['dev'])+':'+str(x['local_file']['inode'])
                               for x in r['runtime_lowers'] if x['local_file'].get('available')})
            rootfs.append({'sandbox_id':r['sandbox_id'],'fd_flags':r['fd_flags'],
                           'device_cache':cache(r['device_cache']),'upper':files(r['upper_files'].values(),2),
                           'upper_identities':{k:[v['dev'],v['inode']] for k,v in r['upper_files'].items() if v.get('available')},
                           'lower':files(x['local_file'] for x in r['runtime_lowers']),
                           'lower_identity_set_sha256':hashlib.sha256(json.dumps(identities).encode()).hexdigest()})
        rows.append({'started_unix':s['started_unix'],'finished_unix':s['finished_unix'],
                     'guest_ram_pagemap_stable':s['pagemap_stable_during_flags'],
                     'guest_ram':s['physical_page_observation']['all_selected_guest_ram'],
                     'marker_segment_shared_bytes':[x['physical']['all_selected_guest_ram']['shared_unique_bytes'] for x in s.get('marker_segments',[])],
                     'memory_lower':files(r for r in lowers if 'memory' in r['kinds']),
                     'rootfs_lower':files(r for r in lowers if 'rootfs' in r['kinds']),
                     'memory_device_cache':{k:cache(v) for k,v in s['memory_device_cache'].items()},'rootfs':rootfs})
    return rows


class Experiment:
    def __init__(self,api,work,report,prepare):
        self.api=api;self.work=work;self.report=report;self.prepare=prepare
        self.seed=prepare['run_id'];self.reference=prepare['restored_marker_status'];self.started=time.monotonic()
        self.env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
                  'PATH':str(BASE/'native/bin')+':/usr/bin:/bin',
                  'LD_LIBRARY_PATH':str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib'),
                  'TMPDIR':str(work/'tmp'),'XDG_CONFIG_HOME':str(work/'config')}
        self.credential=work/'config/aenv/credentials';self.socket_path=None;self.socket_identity=None

    def persist(self):H.save(PENDING,self.report)

    def make(self,snapshot,role):
        H.need(self.report['restore_calls']<4,'Restore budget exhausted')
        live=set(self.report['known_sandboxes'])-set(self.report['released_sandboxes'])
        H.need(len(live)<2 and time.monotonic()-self.started<700,'Live/time budget exhausted')
        self.report['restore_calls']+=1;self.report['restore_outcome_uncertain']=True;self.persist()
        sid=P.restore(self.api,snapshot,self.report['run_id'],role)
        H.need(sid not in self.report['known_sandboxes'],'Duplicate sandbox identity')
        self.report['known_sandboxes'].append(sid);self.report['restore_outcome_uncertain']=False;self.persist();return sid

    def release(self,sid):
        if sid in self.report['cleanup_attempted']:return sid in self.report['released_sandboxes']
        self.report['cleanup_attempted'].append(sid)
        try:
            code,body=self.api.call('GET','/sandboxes/'+sid)
            if code!=404:
                H.need(code==200 and body.get('metadata',{}).get('cow_marker_run')==self.report['run_id'],'Foreign sandbox; no deletion')
                H.need(self.api.call('DELETE','/sandboxes/'+sid,timeout=90)[0] in (200,204,404),'Delete not acknowledged')
                H.need(self.api.call('GET','/sandboxes/'+sid)[0]==404,'Sandbox still visible')
            self.report['released_sandboxes'].append(sid);return True
        except Exception as e:
            self.report.setdefault('cleanup_errors',[]).append({'sandbox_id':sid,'error_type':type(e).__name__});return False

    def guest(self,sid,operation,label):
        H.need(operation in ('status','ram_a','ram_b','rootfs_a','rootfs_b'),'Unexpected Guest operation')
        log=self.work/(label+'.log');script='/pypika/.aenv-cow-'+self.seed+'/marker.py'
        H.checked_process([BASE/'bin/aenv','exec',sid,'python',script,'request',self.seed,operation],self.env,log,60)
        text=H.read(log).decode()
        H.need(text.count('BEGIN_COW_MARKER_STATUS')==text.count('END_COW_MARKER_STATUS')==1,'Marker framing differs')
        response=json.loads(text.split('BEGIN_COW_MARKER_STATUS')[1].split('END_COW_MARKER_STATUS')[0])
        H.save(self.work/(label+'.json'),response);return response

    def check(self,sid,label,tags,file_tag):
        state=validate_state(self.guest(sid,'status',label),self.seed,self.reference,tags,file_tag)
        summary=P.summarize_status(state)
        self.report.setdefault('content_checks',{})[label]={
            'sandbox_id':sid,'content_verified':True,'ram_tags':state['ram_tags'],'ram_hashes':state['ram_hashes'],
            'rootfs_tag':state['rootfs_tag'],'rootfs_hash':state['rootfs_hash'],
            'gpa_list_sha256':summary['guest_page_mapping']['gpa_list_sha256']}
        return state

    def measure(self,source,scope,pair):
        self.socket_path=ROOT/'r'/('cow-control-'+self.report['run_id'][:16]+'.sock')
        H.safe(self.socket_path);H.need(not self.socket_path.exists(),'Coordinator path exists')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            server.bind(str(self.socket_path));os.chmod(self.socket_path,0o600)
            meta=self.socket_path.lstat();self.socket_identity=(meta.st_dev,meta.st_ino)
            server.listen(1);server.settimeout(240)
            endpoint={'path':str(self.socket_path),'identity':list(self.socket_identity),
                      'pid':os.getpid(),'ticks':R.identity(os.getpid())[1]}
            command="/usr/bin/python3 -I -B - <<'COW_CONTROLLED_READONLY'\n"+source+WIRE_SOURCE+ROOT_DRIVER+"\ncontrolled_reader("+repr(scope)+','+repr(endpoint)+")\nCOW_CONTROLLED_READONLY"
            (self.work/'root-readonly-review.txt').write_text(command)
            print('BEGIN_REVIEWED_READONLY_ROOT_COMMAND_COPY_BODY_ONLY',flush=True);print(command,flush=True)
            print('END_REVIEWED_READONLY_ROOT_COMMAND_COPY_BODY_ONLY',flush=True)
            print('Keep this jwk terminal open. Paste the block into A root within 240 seconds. Four stages run automatically; no done input. Return both reports.',flush=True)
            client,_=server.accept()
            with client:
                client.settimeout(150)
                _,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                H.need(uid==0,'Measurement peer must be existing root')
                H.need(wire_receive(client)=={'hello':self.report['run_id']},'Measurement run differs')
                reports={}
                for phase in PHASES:
                    H.need(time.monotonic()-self.started<650,'Controlled phase time budget exhausted')
                    print('PHASE='+phase,flush=True)
                    if phase!='baseline':
                        which=1 if phase=='b_disjoint' else 0;suffix='b' if which else 'a'
                        for operation in ('ram_'+suffix,'rootfs_'+suffix):
                            self.guest(pair[which],operation,phase+'-'+operation)
                    states=[self.check(sid,phase+'-'+str(i),*expected_tags(phase,i)) for i,sid in enumerate(pair)]
                    targets={sid:{'guest_page_bytes':s['guest_page_bytes'],'gpas':s['guest_page_mapping']['guest_physical_addresses']}
                             for sid,s in zip(pair,states)}
                    wire_send(client,{'run_id':self.report['run_id'],'phase':phase,'marker_targets':targets})
                    message=wire_receive(client)
                    H.need(message.get('phase')==phase and isinstance(message.get('report'),dict),'Unexpected root result')
                    result=message['report'];digest=hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()
                    H.need(message.get('sha256')==digest,'Root result digest differs')
                    H.save(self.work/(phase+'-root.json'),result);reports[phase]=result
                    self.report['measurements'][phase]={'file':str(self.work/(phase+'-root.json')),'sha256':digest,
                                                       'root_status':result.get('status')}
                    self.persist()
                    assessment=assess_measurement(result,phase,scope)
                    self.report['measurements'][phase].update(assessment,whole_process_comparison=result.get('whole_process_comparison'),
                                                              samples=measurement_summary(result))
                    self.persist()
                    for i,sid in enumerate(pair):
                        after=self.check(sid,phase+'-after-'+str(i),*expected_tags(phase,i))
                        H.need(after['guest_page_mapping']['guest_physical_addresses']==states[i]['guest_page_mapping']['guest_physical_addresses'],
                               'Guest marker GPA layout changed during observation; cannot attribute these pages')
                    self.report['measurements'][phase]['guest_gpa_layout_stable_before_after']=True
                    if phase=='baseline':H.need(assessment['matches_expected'],'Initial markers not all shared; preserve measurements for review')
                H.need(wire_receive(client)=={'finished':self.report['run_id']},'Root completion missing')
                wire_send(client,{'ack':self.report['run_id']})
                self.report['root_reader_finished']=True
                self.report['repeat_write_observation']=repeat_identity(reports['a_first'],reports['a_repeat'],pair[0])

    def run(self,source):
        (self.work/'tmp').mkdir();(self.work/'config/aenv').mkdir(parents=True)
        try:
            self.credential.write_text('url = "http://127.0.0.1:18080"\napi_key = '+json.dumps(self.api.key)+'\n')
            P.inventory_empty(self.api);H.need(R.find_firecrackers(self.api.identity[0])==[],'Existing Guest processes')
            H.need(not PENDING.exists(),'Existing controlled receipt; no repeat')
            pair=[self.make(self.report['snapshot_id'],role) for role in ('pair-a','pair-b')]
            pids=R.find_firecrackers(self.api.identity[0]);H.need(len(pids)==2,'Expected exactly two Guest processes')
            scope={'run_id':self.report['run_id'],'main_pid':self.api.identity[0],'main_start_ticks':self.api.identity[1],
                   'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   'snapshot_id':self.report['snapshot_id'],'catalog_sha256':self.report['catalog_sha256'],
                   'memory_bytes':512*1024**2,'sandbox_ids':pair,
                   'children':[{'pid':pid,'start_ticks':R.identity(pid)[1]} for pid in pids]}
            self.report['scope']=scope;self.persist();self.measure(source,scope,pair)
            print('PHASE=capture_written_generation_once',flush=True)
            H.need(time.monotonic()-self.started<650,'Insufficient bounded lifetime for capture')
            self.report['snapshot_capture_calls']=1;self.report['snapshot_outcome_uncertain']=True;self.persist()
            code,body=self.api.call('POST','/sandboxes/'+pair[0]+'/snapshots',{'name':'jwk-cow-written-'+self.report['run_id']},timeout=120)
            sid=body.get('snapshotID') if isinstance(body,dict) else None
            H.need(code in (200,201) and isinstance(sid,str) and H.ID.fullmatch(sid),'Written generation capture uncertain')
            self.report['written_snapshot_id']=sid;self.report['snapshot_outcome_uncertain']=False;self.persist()
            H.need(self.release(pair[0]),'First child not released')
            self.check(pair[1],'peer_after_first_exit',*expected_tags('b_disjoint',1))
            H.need(self.release(pair[1]),'Second child not released');self.persist()
            print('PHASE=verify_written_generation',flush=True)
            descendant=self.make(sid,'written-generation-verifier')
            self.check(descendant,'written_generation',*expected_tags('a_first',0))
            H.need(self.release(descendant),'Written generation verifier not released');self.persist()
            print('PHASE=verify_original_measurement_base_unchanged',flush=True)
            base=self.make(self.report['snapshot_id'],'base-verifier')
            self.check(base,'unchanged_base',*expected_tags('baseline',0))
            self.report['generation_and_base_content_verified']=True
        finally:
            for sid in reversed(self.report['known_sandboxes']):self.release(sid)
            if self.credential.exists():self.credential.unlink()
            self.report['temporary_cli_credentials_removed']=not self.credential.exists()
            if self.socket_identity and self.socket_path.exists():
                m=self.socket_path.lstat()
                if stat.S_ISSOCK(m.st_mode) and (m.st_dev,m.st_ino)==self.socket_identity:self.socket_path.unlink()
            self.report['coordinator_socket_removed']=not self.socket_path or not self.socket_path.exists()


def main():
    global H,P,R
    if not(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205):
        raise RuntimeError('A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    if len(caps)!=4 or any(int(v,16) for v in caps):raise RuntimeError('Capability-free launcher required')
    P,_=load(ROOT/'cow_marker_prepare_e5b9050.py',PREPARE_SHA,'marker_prepare_pinned');H=P.load_parent();P.H=H
    R,source=load(ROOT/'cow_ram_readonly.py',COLLECTOR_SHA,'controlled_reader_pinned')
    os.umask(0o077)
    import fcntl
    with open(H.safe(ROOT/'relay/cow-controlled-node-a.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        H.need(not PENDING.exists(),'Controlled receipt exists; preserve it, no automatic rerun')
        prepare=json.loads(H.read(P.PENDING))
        H.need(isinstance(prepare.get('run_id'),str) and re.fullmatch(r'[0-9a-f]{32}',prepare['run_id']),'Invalid marker seed')
        H.need(prepare.get('status')=='INSTRUMENTED_SNAPSHOT_READY_MARKER_RESTORE_VERIFIED_GUESTS_RELEASED'
               and prepare.get('marker_survived_snapshot_restore') is True
               and prepare.get('restore_outcome_uncertain') is False and prepare.get('snapshot_outcome_uncertain') is False
               and len(prepare.get('known_sandboxes',[]))==2
               and set(prepare['known_sandboxes'])==set(prepare.get('released_sandboxes',[])),'Instrumented parent not ready/released')
        snapshot=prepare.get('measurement_snapshot_id');H.need(isinstance(snapshot,str) and H.ID.fullmatch(snapshot),'Invalid measurement snapshot')
        raw=H.read(BASE/'state/snapshot-store/repository/catalog/records'/(snapshot+'.json'));record=json.loads(raw)
        H.need(record.get('id')==snapshot and record.get('resources',{}).get('memory_mib')==512
               and record['resources'].get('cpu_count')==1,'Snapshot resource budget differs')
        work=Path(tempfile.mkdtemp(prefix='node-a-cow-controlled-',dir=H.safe(ROOT/'relay/reports')))
        report={'revision':'cow-controlled-once-v1','run_id':uuid.uuid4().hex,'report_directory':str(work),
                'snapshot_id':snapshot,'marker_seed':prepare['run_id'],'catalog_sha256':hashlib.sha256(raw).hexdigest(),
                'scenario':'Instrumented PyPika original single-node; four controlled stages, not full agent_replay',
                'restore_calls':0,'restore_calls_limit':4,'restore_outcome_uncertain':False,
                'snapshot_capture_calls':0,'snapshot_capture_calls_limit':1,'snapshot_outcome_uncertain':False,
                'max_simultaneous_sandboxes':2,'known_sandboxes':[],'cleanup_attempted':[],'released_sandboxes':[],
                'SDK_called':False,'services_modified':False,'B_accessed':False,'measurements':{},
                'root_reader_finished':False,'generation_and_base_content_verified':False}
        try:
            fs=os.statvfs(ROOT);H.need(fs.f_bavail*fs.f_frsize>=2*1024**3,'Need 2GiB free workspace space; no cleanup')
            installed=json.loads(H.read(BASE/'installation.json'))
            H.need(installed.get('node')=='node-a' and installed.get('commit')=='ae9c62693839ce7effa2b45df31c0039ae4f9fbc',
                   'Original installation identity differs')
            report['source_commit']=installed['commit']
            api=H.Api();H.need(api.call('GET','/health')[0]==204,'Original API unhealthy')
            for sid in prepare['known_sandboxes']:H.need(api.call('GET','/sandboxes/'+sid)[0]==404,'Preparation Guest remains')
            Experiment(api,work,report,prepare).run(source)
            H.need(len(report['released_sandboxes'])==4,'Own Guest cleanup incomplete')
            report['marker_physical_expectations_matched']=all(report['measurements'][p]['matches_expected'] for p in PHASES)
            report['full_cow_acceptance']='PENDING_ANALYSIS_OF_RAM_ROOTFS_AND_CACHE_EVIDENCE'
            report['status']='CONTROLLED_OBSERVATIONS_AND_GENERATION_CHECKS_COMPLETED_REVIEW_MEASUREMENTS'
        except (Exception,KeyboardInterrupt) as e:
            report.update(status='STOPPED_CONTROLLED_EXPERIMENT_REVIEW_RECEIPT',error_type=type(e).__name__,
                          reason=str(e) if isinstance(e,RuntimeError) else 'See bounded diagnostics; no automatic retry')
            if isinstance(e,H.ChildFailure):report['child_diagnostics']=e.diagnostics
        H.save(work/'return.json',report)
        if report['restore_calls']:H.save(PENDING,report)
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 1 if report['status'].startswith('STOPPED') else 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_CONTROLLED_ENTRY','error_type':type(e).__name__,
              'reason':str(e) if isinstance(e,RuntimeError) else 'Entry failed'}));print('END_RETURN_REPORT');raise SystemExit(1)
