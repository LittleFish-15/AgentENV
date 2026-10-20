"""A full immutable-layer UB publication + three bounded Guest restores.

One manually pasted root supervisor enables the reviewed indexes, measures four
stages, and restarts the modified unit back to its exact UB-off launcher.
SDK ownership stays in this ordinary-user process until readers have exited.
"""
import argparse,ast,hashlib,importlib.util,json,os,re,signal,socket,stat,struct,sys,tempfile,threading,time,uuid
from pathlib import Path
ROOT=Path('/home/jwk/agent')
MOD=ROOT/'deployments/agentenv-ub-b019f27'
UNIT='jwk-aenv-ub-b019f27-node-a.service'
OLD_UNIT='jwk-aenv-ae9c626-node-a.service'
PENDING=ROOT/'relay/ub-guest-node-a.pending.json'
ROOT_DRIVER_SHA='122d45e901851153f5c59d929f122c97fd0c8d48b88ae6a70cd48baf8fbd42ad'
COMPARE_SHA='0b16daa0ae68cb10c378af2752481f1503c7efa6deb33dab9875d536e4527029'
CANARY_SHA='e7d0b8fa584f83688ae9daee5b7f7e8bc14693178586a92ca1b4a19713ba8e4a'
LOGICAL=1504*1024**2
TOTAL_COVERAGE=4096*1024**2
OBJECT_COVERAGE=1024*1024**2
H=S=C=P=R=K=None

def load(path,digest,name):
    raw=path.read_bytes()
    if path.resolve(strict=True)!=path or hashlib.sha256(raw).hexdigest()!=digest:raise RuntimeError('Pinned helper differs: '+path.name)
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m

def sources():
    done=json.loads(H.read(ROOT/'relay/cow-modified-controlled-node-a.pending.json'))
    H.need(done.get('status')=='MODIFIED_UB_OFF_CONTROLLED_COMPLETED_REVIEW_COMPARABILITY'
           and len(done.get('known_sandboxes',[]))==4 and set(done['known_sandboxes'])==set(done.get('released_sandboxes',[]))
           and not done.get('restore_outcome_uncertain') and not done.get('snapshot_outcome_uncertain'),'UB-off comparison not released')
    sid=done['snapshot_id'];H.need(re.fullmatch(r'[0-9a-f-]{36}',sid),'Invalid snapshot')
    repo=MOD/'state/snapshot-store/repository';raw=H.read(repo/'catalog/records'/(sid+'.json'))
    H.need(hashlib.sha256(raw).hexdigest()==done['catalog_sha256'],'Catalog changed')
    record=json.loads(raw)['committed'];selected={};kinds={}
    for kind in ('memory','rootfs'):
        rows=record[kind+'_layers'];H.need(len(rows)==(2 if kind=='memory' else 14),'Layer count differs')
        kinds[kind]=[]
        for entry in rows:
            layer=entry if kind=='memory' else entry.get('Managed')
            H.need(isinstance(layer,dict) and re.fullmatch(r'sha256:[0-9a-f]{64}',layer['digest']),'Unresolved layer')
            digest,size=layer['digest'],layer['size'];path=H.safe(repo/'managed-layers'/(digest.replace(':','_')+'.overlaybd.commit'))
            meta=path.stat();H.need(stat.S_ISREG(meta.st_mode) and meta.st_size==size and 0<size<2*1024**3,'Layer size/type differs')
            selected[digest]=(path,size);kinds[kind].append(digest)
    H.need(len(selected)==16 and sum(((n+4096+4194304-1)//4194304)*4194304 for _,n in selected.values())==LOGICAL,'Reviewed budget differs')
    return done,selected,kinds

def enable_launcher(raw,index):
    text=raw.decode();anchor="'API_ADDR': '127.0.0.1:' + str(PORT)}"
    H.need(text.count(anchor)==1 and 'AENV_UB_MEMORY_REPLICAS' not in text and 'AENV_UB_ROOTFS_REPLICAS' not in text,
           'Unknown/already enabled launcher')
    replacement="'AENV_UB_MEMORY_REPLICAS': "+repr(str(index))+",\n            'AENV_UB_ROOTFS_REPLICAS': "+repr(str(index))+",\n            "+anchor
    changed=text.replace(anchor,replacement,1);ast.parse(changed);return changed.encode()

class Meter:
    """Only broker-driven SDK reads count here; publisher hash reads bypass it."""
    def __init__(self,replicas):
        self.lock=threading.Lock()
        self.rows={r.objectName:{'digest':r.layerDigest,'read_calls':0,'SDK_bytes_returned_to_broker':0} for r in replicas}
    def snapshot(self):
        with self.lock:return {k:dict(v) for k,v in self.rows.items()}
    def wrap(self,name,mapping):
        parent=self
        class ReadOnly:
            def read(self,offset,count):
                data=mapping.read(offset,count)
                with parent.lock:
                    parent.rows[name]['read_calls']+=1
                    parent.rows[name]['SDK_bytes_returned_to_broker']+=len(data)
                return data
        return ReadOnly()

def write_changed(path,expected,replacement):
    H.need(H.read(path)==expected,'Concurrent file change: '+path.name)
    temporary=path.with_name(path.name+'.ub-'+uuid.uuid4().hex+'.tmp')
    try:
        with temporary.open('xb') as f:f.write(replacement);f.flush();os.fsync(f.fileno())
        H.need(H.read(path)==expected,'File changed before replacement')
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()

def rpc(client,message):
    C.wire_send(client,message);reply=C.wire_receive(client)
    H.need(reply.get('op')==message['op'],'Unexpected supervisor response')
    H.need(reply.get('ok') is True,'Root supervisor stopped: '+json.dumps(reply))
    return reply

def experiment_class(client,meter):
    class UBExperiment(C.Experiment):
        def make(self,snapshot,role):
            H.need(self.report['restore_calls']<3,'UB Guest restore limit reached')
            return super().make(snapshot,role)
        def measure(self,source,scope,pair):
            results={}
            for phase in C.PHASES:
                print('PHASE=UB_Guest_'+phase,flush=True)
                if phase!='baseline':
                    i=1 if phase=='b_disjoint' else 0;suffix='b' if i else 'a'
                    for op in ('ram_'+suffix,'rootfs_'+suffix):self.guest(pair[i],op,phase+'-'+op)
                states=[self.check(sid,phase+'-'+str(i),*C.expected_tags(phase,i)) for i,sid in enumerate(pair)]
                targets={sid:{'guest_page_bytes':s['guest_page_bytes'],'gpas':s['guest_page_mapping']['guest_physical_addresses']}
                         for sid,s in zip(pair,states)}
                reply=rpc(client,{'op':'sample','phase':phase,'scope':scope,'marker_targets':targets})
                result=reply['report'];digest=hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()
                H.need(reply.get('sha256')==digest,'Root result digest differs')
                H.save(self.work/(phase+'-root.json'),result);results[phase]=result
                entry={'sha256':digest,'file':str(self.work/(phase+'-root.json')),'root_status':result['status'],
                       'broker_by_object':meter.snapshot(),'owner_process':R.whole_process_metrics(os.getpid(),R.identity(os.getpid())[1])}
                self.report['measurements'][phase]=entry;self.persist()
                entry.update(C.assess_measurement(result,phase,scope),
                             whole_process_comparison=result.get('whole_process_comparison'),
                             samples=C.measurement_summary(result),UB_rootfs_bindings=result.get('UB_rootfs_bindings'))
                for i,sid in enumerate(pair):
                    after=self.check(sid,phase+'-after-'+str(i),*C.expected_tags(phase,i))
                    H.need(after['guest_page_mapping']['guest_physical_addresses']==states[i]['guest_page_mapping']['guest_physical_addresses'],
                           'Guest GPA changed during measurement')
                entry['guest_gpa_layout_stable_before_after']=True;self.persist()
                if phase=='baseline':H.need(entry['matches_expected'],'Initial marker sharing differs')
            self.report['root_measurement_finished']=True
            self.report['repeat_write_observation']=C.repeat_identity(results['a_first'],results['a_repeat'],pair[0])
        def run(self,source):
            (self.work/'tmp').mkdir();(self.work/'config/aenv').mkdir(parents=True)
            try:
                self.credential.write_text('url = "http://127.0.0.1:18081"\napi_key = '+json.dumps(self.api.key)+'\n')
                S.empty(self.api)
                pair=[self.make(self.report['snapshot_id'],role) for role in ('pair-a','pair-b')]
                pids=R.find_firecrackers(self.api.identity[0]);H.need(len(pids)==2,'Expected exactly two Guest processes')
                scope={'run_id':self.report['run_id'],'main_pid':self.api.identity[0],'main_start_ticks':self.api.identity[1],
                       'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                       'snapshot_id':self.report['snapshot_id'],'catalog_sha256':self.report['catalog_sha256'],
                       'memory_bytes':512*1024**2,'sandbox_ids':pair,
                       'children':[{'pid':p,'start_ticks':R.identity(p)[1]} for p in pids]}
                self.report['scope']=scope;self.persist();self.measure(source,scope,pair)
                H.need(self.release(pair[0]),'First Guest cleanup incomplete')
                self.check(pair[1],'peer_after_first_exit',*C.expected_tags('b_disjoint',1))
                H.need(self.release(pair[1]),'Second Guest cleanup incomplete')
                base=self.make(self.report['snapshot_id'],'base-verifier')
                self.check(base,'unchanged_base',*C.expected_tags('baseline',0))
                self.report['base_marker_verified']=True
            finally:
                for sid in reversed(self.report['known_sandboxes']):self.release(sid)
                if self.credential.exists():self.credential.unlink()
                self.report['temporary_cli_credentials_removed']=not self.credential.exists()
                self.persist()
    return UBExperiment

def session(s,library,selected,kinds,done,work,report,driver):
    b=s.b;backend=publisher=broker=client=server=None;baseline=enabled=None;applied=[];off=False;meter=None
    before=S.state(UNIT);original=S.state(OLD_UNIT)
    control=ROOT/'r'/('ub-control-'+report['run_id'][:16]+'.sock');control_identity=None
    class Backend(b.NativeBackend):
        def __init__(self,*a):super().__init__(*a);self.coverage={};self.progress={'read':0,'write':0}
        def allocate(self,r):
            H.need(self.allocation_calls<16 and r.layerDigest in selected and r.fileBytes==selected[r.layerDigest][1]
                   and r.mappingBytes==((r.fileBytes+4096+4194304-1)//4194304)*4194304,'Allocation budget/identity differs')
            H.need(sum(self.coverage.values())+OBJECT_COVERAGE<=TOTAL_COVERAGE,'Conservative next-object coverage reserve exceeded')
            return super().allocate(r)
        def map(self,r,writable=False):
            m=super().map(r,writable);self.coverage[r.objectName]=max(self.coverage.get(r.objectName,0),m.backing_coverage)
            H.need(sum(self.coverage.values())<=TOTAL_COVERAGE,'Observed aggregate coverage exceeds limit')
            return m
        def call(self,op,*a):
            result=super().call(op,*a)
            if op in self.progress:
                old=self.progress[op];self.progress[op]+=int(a[-1])
                if old//(128*1024**2)!=self.progress[op]//(128*1024**2):
                    print('PHASE=UB_transfer direction='+op+' bytes='+str(self.progress[op]),flush=True)
            return result
    try:
        S.empty(S.Api());S.empty(S.Api(S.OLD,OLD_UNIT,18080))
        report.update(original_process=original,modified_process_before=before,
                      owner_receipt=str(work/'owner-receipt.json'),SDK_runtime_started=True,started_unix=time.time(),
                      owner_process_before_publication=R.whole_process_metrics(os.getpid(),R.identity(os.getpid())[1]))
        H.save(PENDING,report)
        backend=Backend(library,OBJECT_COVERAGE);publisher=b.Publisher(backend,work/'owner-receipt.json')
        print('PHASE=publish_all_16_layers logical_mib=1504',flush=True)
        if hasattr(signal,'SIGALRM'):
            signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(RuntimeError('Soft SDK publication deadline exceeded')))
            signal.alarm(600)
        try:replicas,mappings=publisher.publish(selected,work/'broker.sock',LOGICAL)
        finally:
            if hasattr(signal,'SIGALRM'):signal.alarm(0)
        meter=Meter(replicas)
        broker=b.Broker(replicas,[meter.wrap(r.objectName,m) for r,m in zip(replicas,mappings)])
        broker.start(work/'broker.sock')
        index=work/'replicas.json';b.atomic_json(index,b.index_for(replicas))
        report.update(publication_ready=True,observed_unique_object_coverage_bytes=sum(backend.coverage.values()),
                      replicas=b.index_for(replicas)['replicas'],index=str(index),layer_kinds=kinds,
                      coverage_sum_is_physical_increment_measurement=False)
        baseline={p:H.read(MOD/p) for p in ('config/runtime.toml','libexec/deploy_a_ub.py','installation.json')}
        prior=json.loads(H.read(S.PREP))
        for rel,key in [('config/runtime.toml','config_after_sha256'),('libexec/deploy_a_ub.py','launcher_after_sha256'),('installation.json','installation_after_sha256')]:
            H.need(hashlib.sha256(baseline[rel]).hexdigest()==prior[key],'UB-off preparation hash differs: '+rel)
        enabled=dict(baseline);enabled['libexec/deploy_a_ub.py']=enable_launcher(baseline['libexec/deploy_a_ub.py'],index)
        installation=json.loads(baseline['installation.json']);installation['launcher_sha256']=hashlib.sha256(enabled['libexec/deploy_a_ub.py']).hexdigest()
        enabled['installation.json']=(json.dumps(installation,indent=2)+'\n').encode()
        for rel,raw in baseline.items():
            backup=work/'baseline'/rel;backup.parent.mkdir(parents=True,exist_ok=True);backup.write_bytes(raw)
        report['baseline_hashes']={p:hashlib.sha256(v).hexdigest() for p,v in baseline.items()}
        report['enabled_hashes']={p:hashlib.sha256(v).hexdigest() for p,v in enabled.items()};H.save(PENDING,report)
        for rel in ('libexec/deploy_a_ub.py','installation.json'):
            write_changed(MOD/rel,baseline[rel],enabled[rel]);applied.append(rel)
        H.safe(control);H.need(not control.exists(),'Control endpoint exists')
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(control));os.chmod(control,0o600)
        meta=control.stat();control_identity=(meta.st_dev,meta.st_ino);server.listen(1);server.settimeout(240)
        review={'run_id':report['run_id'],'snapshot_id':done['snapshot_id'],'catalog_sha256':done['catalog_sha256'],
                'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'original':original,'before':before,
                'baseline_hashes':report['baseline_hashes'],'enabled_hashes':report['enabled_hashes'],
                'index_path':str(index),'index_sha256':hashlib.sha256(H.read(index)).hexdigest(),'rootfs_digests':kinds['rootfs']}
        endpoint={'path':str(control),'identity':list(control_identity),'pid':os.getpid(),'ticks':R.identity(os.getpid())[1]}
        source=S.configure_engine()
        C.PENDING=work/'guest-receipt.json'
        command="/usr/bin/python3 -I -B - <<'UB_GUEST_REVIEWED_ROOT'\n"+source+C.WIRE_SOURCE+driver+"\nroot_ub_session("+repr(review)+','+repr(endpoint)+")\nUB_GUEST_REVIEWED_ROOT"
        (work/'root-review.txt').write_text(command)
        print('BEGIN_REVIEWED_UB_ROOT_SUPERVISOR_COPY_BODY_ONLY',flush=True);print(command,flush=True)
        print('END_REVIEWED_UB_ROOT_SUPERVISOR_COPY_BODY_ONLY',flush=True)
        print('Keep jwk open. Paste once into A root within 240 seconds. It performs two exact modified-unit restarts and four scoped samples. No done input.',flush=True)
        client,_=server.accept();client.settimeout(180)
        _,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        H.need(uid==0 and C.wire_receive(client)=={'hello':report['run_id']},'Root supervisor identity differs')
        activated=rpc(client,{'op':'activate'});report['activation']=activated;H.save(PENDING,report)
        api=S.Api();H.need(api.identity==activated['identity'],'Activated process differs')
        guest={'revision':'ub-guest-controlled-v1','run_id':report['run_id'],'report_directory':str(work),
               'snapshot_id':done['snapshot_id'],'catalog_sha256':done['catalog_sha256'],'marker_seed':done['marker_seed'],
               'restore_calls':0,'restore_calls_limit':3,'restore_outcome_uncertain':False,
               'snapshot_capture_calls':0,'snapshot_capture_calls_limit':0,'snapshot_outcome_uncertain':False,
               'max_simultaneous_sandboxes':2,'known_sandboxes':[],'cleanup_attempted':[],'released_sandboxes':[],
               'measurements':{},'UB_enabled':True,'new_generation_UB_validation':'PENDING_SEPARATE_LAYER_PUBLICATION'}
        report['Guest']=guest;H.save(PENDING,report)
        prepare=json.loads(H.read(P.PENDING))
        experiment_class(client,meter)(api,work,guest,prepare).run(source)
        S.empty(api)
        H.need(len(guest['released_sandboxes'])==3 and not guest['restore_outcome_uncertain'],'Guest cleanup incomplete')
        H.need(guest.get('base_marker_verified') is True,'Base marker not verified')
        report['Guest_validation_completed']=True
        report['marker_physical_expectations_matched']=all(guest['measurements'][p]['matches_expected'] for p in C.PHASES)
        report['repeat_target_identity_stable']=guest['repeat_write_observation']['stable_pfn_and_gpa_identity_between_windows']
        report['broker_after_Guests']=meter.snapshot()
        report['all_16_layers_read_by_Guest_workflow']=all(r['read_calls']>0 for r in meter.snapshot().values())
    except (Exception,KeyboardInterrupt) as error:
        report.update(error_type=type(error).__name__,reason=str(error) if isinstance(error,RuntimeError) else 'Inspect scoped SDK/Guest receipt')
        if isinstance(error,H.ChildFailure):report['child_diagnostics']=error.diagnostics
    finally:
        # Disk rollback precedes root deactivation; SDK objects remain alive meanwhile.
        try:
            for rel in reversed(applied):write_changed(MOD/rel,enabled[rel],baseline[rel])
            report['launcher_files_restored']=True
            if client is not None:
                reply=rpc(client,{'op':'deactivate'});report['deactivation']=reply;off=reply.get('safe_off') is True
                report['modified_service_restored_healthy']=reply.get('healthy') is True
            else:
                off=S.state(UNIT)==before
                report['modified_service_restored_healthy']=off
        except Exception as error:
            report['restore_error']=str(error) if isinstance(error,RuntimeError) else type(error).__name__
        if client is not None:client.close()
        if server is not None:server.close()
        if control_identity and control.exists():
            m=control.lstat()
            if stat.S_ISSOCK(m.st_mode) and (m.st_dev,m.st_ino)==control_identity:control.unlink()
        safe_release=off
        if broker is not None:
            if off:
                try:
                    with broker.condition:H.need(broker.condition.wait_for(lambda:broker.active==0,timeout=15),'UB readers remain after restart')
                    report['broker_statistics']=broker.stop()
                except Exception as e:safe_release=False;report['broker_retirement_error']=str(e)
            else:safe_release=False
        if publisher is not None:
            try:
                if safe_release:
                    if report.get('publication_ready'):
                        b.atomic_json(work/'replicas.json',b.index_for(replicas,'retired'))
                        try:
                            for replica,mapping in zip(replicas,mappings):b.verify_mapping(replica,mapping)
                            report['all_UB_payloads_verified_after_Guest_exit']=True
                        except Exception as error:
                            report['all_UB_payloads_verified_after_Guest_exit']=False
                            report['post_Guest_payload_error']=str(error)
                    publisher.cleanup();report['SDK_resources_released']=True
                else:report['SDK_resources_released']=False
            except Exception as e:report.update(SDK_resources_released=False,SDK_cleanup_error=str(e))
            report['owned_objects']=publisher.state['objects']
        if backend is not None:
            report['allocation_calls_observed']=backend.allocation_calls
            report['object_coverage_observations']=backend.coverage
        try:report['original_process_unchanged']=S.state(OLD_UNIT)==original
        except Exception:report['original_process_unchanged']=False
        passed=all(report.get(k) is True for k in ('Guest_validation_completed','all_16_layers_read_by_Guest_workflow',
                   'SDK_resources_released','modified_service_restored_healthy','original_process_unchanged',
                   'all_UB_payloads_verified_after_Guest_exit','marker_physical_expectations_matched','repeat_target_identity_stable'))
        report['status']='A_UB_ALL_LAYERS_GUEST_CONTROLLED_COMPLETED' if passed else 'STOPPED_UB_GUEST_REVIEW_RECEIPTS'
        report['finished_unix']=time.time()
        H.save(work/'return.json',report);H.save(PENDING,report)

def main():
    global H,S,C,P,R,K
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-reviewed',action='store_true')
    parser.add_argument('--logical-budget-mib',type=int);parser.add_argument('--max-total-coverage-mib',type=int)
    args=parser.parse_args()
    if not(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205):raise RuntimeError('A ordinary jwk only')
    caps=re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    if len(caps)!=4 or any(int(v,16) for v in caps):raise RuntimeError('Capability-free owner required')
    S=load(ROOT/'cow_modified_d2285fe.py',COMPARE_SHA,'ub_comparison')
    C=load(ROOT/'cow_controlled_engine.py',S.ENGINE_SHA,'ub_engine')
    P=C.load(ROOT/'cow_marker_prepare_e5b9050.py',C.PREPARE_SHA,'ub_marker')[0];H=P.load_parent();P.H=H;C.H=H;S.H=H
    R=C.load(ROOT/'cow_ram_readonly.py',C.COLLECTOR_SHA,'ub_reader')[0];S.C=C;S.P=P;S.R=R
    K=load(ROOT/'ub_real_layer_canary_51f4ac9.py',CANARY_SHA,'ub_canary')
    driver=H.read(ROOT/'ub_guest_root.py');H.need(hashlib.sha256(driver).hexdigest()==ROOT_DRIVER_SHA,'Root driver differs')
    done,selected,kinds=sources()
    if not args.run_reviewed:
        print(json.dumps({'status':'UB_GUEST_PLAN_ONLY','logical_mib':1504,'objects':16,'max_object_coverage_mib':1024,
                          'max_total_coverage_mib':4096,'physical_hard_quota':False,'Guest_restores_limit':3,'modified_unit_restarts':2}));return 0
    H.need(args.logical_budget_mib==1504 and args.max_total_coverage_mib==4096,'Exact reviewed budgets required')
    os.umask(0o077);import fcntl,contextlib
    with contextlib.ExitStack() as stack:
        for name in ('cow-modified-node-a.lock','ub-layer-sdk-node-a.lock'):
            lock=stack.enter_context(open(H.safe(ROOT/'relay'/name),'a'));fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        H.need(not PENDING.exists(),'UB Guest receipt exists; no repeat')
        canary=json.loads(H.read(K.PENDING))
        H.need(canary['status']=='ONE_REAL_LARGE_LAYER_PUBLISHED_READ_VERIFIED_AND_RELEASED'
               and canary['delete_acknowledged'] and canary['mappings_released'] and canary['finalize_acknowledged'],'Large-layer canary not released')
        directory=Path(canary['report_directory'])
        H.need(directory.parent==ROOT/'relay/reports' and directory.name.startswith('node-a-ub-real-layer-'),'Unexpected bridge directory')
        library=directory/'libaenv_ub_bridge.so'
        H.need(hashlib.sha256(H.read(library)).hexdigest()==canary['bridge_sha256'],'Verified canary bridge changed')
        s=K.load_helpers();s.previous_guard(ROOT/'relay/ub-layer-sdk-node-a.pending.json','node-a')
        with Path('/sys/bus/ub/ub_feature').open() as f:feature=f.readline(513).strip()
        H.need(int(feature,0)&4,'NC sharing not advertised')
        work=Path(tempfile.mkdtemp(prefix='node-a-ub-guest-',dir=H.safe(ROOT/'relay/reports')))
        report={'revision':'ub-guest-owner-v1','run_id':uuid.uuid4().hex,'report_directory':str(work),
                'snapshot_id':done['snapshot_id'],'catalog_sha256':done['catalog_sha256'],
                'runtime_source_commit':'b019f270a6c4359db0ad65ef669dd0e479056603',
                'bridge_sha256':canary['bridge_sha256'],
                'status':'PREPARING','SDK_runtime_started':False,'logical_request_bytes':LOGICAL,'allocation_calls_limit':16,
                'max_object_coverage_inspection_bytes':OBJECT_COVERAGE,'max_total_coverage_inspection_bytes':TOTAL_COVERAGE,
                'physical_hard_quota':False,'physical_increment_measured':False,'SDK_backing_placement_verified':False,
                'independent_global_absence_query':False,
                'deadline_policy':'600s soft publication deadline; root handoff 240s; blocking SDK calls are not forcibly terminated.',
                'B_accessed':False,'cross_node_validation':False,'new_generation_UB_validation':False,
                'bridge_reused_from_verified_canary':True,'ub_feature':feature}
        session(s,library,selected,kinds,done,work,report,driver.decode())
        print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')
        return 0 if report['status']=='A_UB_ALL_LAYERS_GUEST_CONTROLLED_COMPLETED' else 1
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_UB_GUEST_ENTRY','error_type':type(error).__name__,
              'reason':str(error) if isinstance(error,RuntimeError) else 'Preserve receipts; entry failed'}));print('END_RETURN_REPORT');raise SystemExit(1)
