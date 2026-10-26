"""Explicit local phase of original/full aenv comparison; no peer transport.

Each original phase runs after the complete two-node Guest evidence gate.
Each full phase additionally requires both original phases to have released
their Guests. Starts are not synchronized; no simultaneous-window claim.
"""
import argparse,base64,hashlib,json,os,platform,re,shutil,stat,sys,time,tomllib,types,uuid,zlib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
FULL=ROOT/'deployments/agentenv-direct-ub-guest-v1'
SOURCE=ROOT/'deployments/agentenv-lazy-four-32ce41c'
WORK=FULL/'comparison/full-v1'
PAIR_SHA='6c01a15e36a056b29a400e52f33f38981ff0abf3ca939185e6a4074dd9fda1fa'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def module(name):
    row=MODULES[name];raw=zlib.decompress(base64.b64decode(row['z64'],validate=True))
    need(hashlib.sha256(raw).hexdigest()==row['sha256'],'Embedded component differs')
    result=types.ModuleType('comparison_'+name);result.__file__=str(WORK/(name+'.py'))
    exec(compile(raw,result.__file__,'exec'),result.__dict__)
    return result

def save(path,value):
    need(path.parent.resolve(strict=True)==path.parent and path.is_relative_to(WORK), 'Output outside fixed comparison directory')
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write((json.dumps(value,indent=2)+'\n').encode());stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def mkdir(path):
    need(path.is_relative_to(FULL) and path.parent.resolve(strict=True)==path.parent,'Unexpected output parent')
    path.mkdir(mode=0o700,exist_ok=True)
    meta=path.stat()
    need(path.resolve(strict=True)==path and meta.st_uid==0 and not meta.st_mode&0o077,'Expected private root-owned output directory')

class Comparison:
    def __init__(self,args):
        need(sys.platform=='linux' and os.getuid()==os.geteuid()==0,'Run explicitly as root on the declared node')
        self.args=args;self.node={'server1':'a','agent1':'b'}[platform.node()]
        need(args.node==self.node,'Node differs')
        self.ready=module('ready');self.runtime=self.ready.ReadyRun()
        self.rt=self.runtime.rt;self.continue_pair=module('continue_pair')
        self.gates=module('admission');self.inputs=module('inputs');self.sampler=module('sampler')
        self.replay=module('native_replay');self.adapter=module('cohort');self.ram=module('ram')
        self.journals=module('journal')
        self.bundle,self.bundle_file_sha=self.continue_pair.document(args.pair_bundle,16*1024**2)
        self.accepted=module('pair_verify').verify(self.bundle,PAIR_SHA)
        self.templates,self.steps=self.inputs.load_inputs(SOURCE,self.node,args.templates,self.rt.read,self.runtime.replay.steps_from)
        self.gates.matching_inputs(self.templates,self.templates,{
            'guestTimeoutSeconds':300,'cliTimeoutSeconds':330,'terminalActionPolicy':'stop_before_submit_finish_done',
            'nonzeroPolicy':'record_each_and_compare','globalCacheEviction':False})
        self.contexts={variant:self.gates.inspect_runtime(self.node,variant) for variant in ('original','full')}
        ready_report=self.bundle['readyReports'][self.node]
        # Pair acceptance is tied to the same running full Runtime, not just its disk binary.
        need(ready_report['serverIdentity']==self.runtime.server,'Full Runtime changed since pair acceptance')
        self.apis={'full':self.runtime.api}
        for variant in ('original','full'):
            base=self.gates.VERSIONS[variant]['root'];context=self.contexts[variant]
            self.inputs.check_catalogs(base,self.templates,self.rt.read)
            credential=tomllib.loads(self.rt.read(base/'cli/config/aenv/credentials').decode())
            match=re.fullmatch(r'http://127\.0\.0\.1:([0-9]+)',credential['url'])
            need(match is not None,'CLI endpoint must be retained local Runtime')
            port=int(match[1]);need(18000<=port<18100,'Unexpected retained API port')
            if variant not in self.apis:self.apis[variant]=self.rt.Api(base,context['unit'],port)
            api=self.apis[variant]
            need(api.port==port and api.key==credential['api_key'] and api.pid==context['pid']
                 and api.ticks==context['startTicks'],'CLI/API/inspected Runtime differ')
            env=dict(item.split(b'=',1) for item in (Path('/proc')/str(api.pid)/'environ').read_bytes().split(b'\0') if b'=' in item)
            need(env.get(b'API_ADDR')==('127.0.0.1:'+str(port)).encode(),'Running Runtime endpoint differs')
            need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Both Runtime inventories must be empty')
            config=tomllib.loads(self.rt.read(base/'config/runtime.toml').decode())
            context['fcWorkDir']=config['firecracker']['work_dir']
            work=Path(context['fcWorkDir'])
            need(work.is_relative_to(ROOT) and work.resolve(strict=True)==work,'FC working directory outside admitted deployment')
            fc=base/'deps/firecracker/1.15.1-patch-v3/firecracker'
            need(config['firecracker']['binary_path']==str(fc), 'Configured FC path differs')
            fc_sha=self.rt.digest_file(fc)
            need(fc_sha==self.runtime.binaries['firecracker']['sha256'], 'Original/full FC binary differs')
            context['firecrackerSha256']=fc_sha
        self.ledger,self.ledger_sha=self.continue_pair.document(args.allocation_ledger,2*1024**2)
        need(self.ledger['ownerId']==self.runtime.deploy.OWNER and self.ledger['manifestSha256']==self.runtime.deploy.MANIFEST,
             'Retained allocation ledger has different owner/content')
        need({r['objectName'] for r in self.ledger['objects']}=={r['objectName'] for r in self.runtime.index['replicas']},
             'Allocation ledger omits or adds shared objects')
        cost=self.sampler.ub_reservation(self.ledger)
        need(cost['uniqueExportRegions']==19 and cost['reportedReservationBytesCountedOnce']==19*128*1024**2,
             'Fixed retained first-template allocation evidence differs')
        # Existing approval covers the first-template experiment only. No new allocation here.
        self.gates.full_coverage(self.templates,self.runtime.index,{
            'reportedBackingReservationAvailable':True,'uniqueReportedReservationBytes':cost['reportedReservationBytesCountedOnce'],
            'retainedDuringOriginal':True,'originalBackgroundAccountingIncluded':True},4*1024**3)
        self.files=self.inputs.lower_file_scope(self.gates.ORIGINAL,SOURCE,self.templates,self.sampler.immutable_identity)
        self.files+=self.inputs.memory_file_scope(self.gates.ORIGINAL,SOURCE,self.templates,self.rt.read,self.sampler.immutable_identity)
        self.plan={'node':self.node,'variants':['original','full'],'templates':self.templates,
                   'pairAcceptanceSha256':self.accepted['bundleSha256'],'allocationLedgerSha256':self.ledger_sha,
                   'runId':args.run_id,'scope':'first-template-fallback' if args.templates==1 else 'four-template',
                   'crossNodeSynchronizationVerified':False,'retainedUBBackgroundIncluded':True}
        self.status=self.continue_pair.provider_status(self.runtime)
        need(self.status['activeLeases']==self.status['activePayloadResponses']==self.status['payloadFailures']==0,
             'Provider is busy or has failed reads; preserve state')

    def guard(self):
        self.runtime.guard()
        for api in self.apis.values():api.stable()

    def capacity(self,kind,count):
        self.guard()
        memory=self.sampler.kib_fields(Path('/proc/meminfo').read_text())
        need(memory['MemAvailable']>=(count*4+4)*1024**3,'Insufficient available memory for bounded Guest batch')
        need(shutil.disk_usage(ROOT).free>=max(8,count*4)*1024**3,'Insufficient free disk; no automatic cleanup')
        limit=int(Path('/sys/module/ublk_drv/parameters/ublks_max').read_text())
        used=sum(bool(re.fullmatch('ublkc[0-9]+',p.name)) for p in Path('/sys/class/ublk-char').iterdir())
        need(limit-used>=count*4,'Insufficient free ublk slots')

    def peer_original(self):
        need(self.args.peer_original is not None,'Full phase needs explicit peer original completion receipt')
        peer,_=self.continue_pair.document(self.args.peer_original,4*1024**2)
        need(peer['status']=='LOCAL_COMPARISON_PHASE_RELEASED' and peer['variant']=='original'
             and peer['node']==('b' if self.node=='a' else 'a') and peer['runId']==self.args.run_id
             and peer['pairBundleSha256']==self.accepted['bundleSha256'],'Peer original completion differs')
        need(json.dumps(peer['templateSignature'],sort_keys=True)==json.dumps(self.gates.input_signature(self.templates),sort_keys=True)
             and peer['cleanup']['ownedGuestsReleased'] is True,'Peer scope or release incomplete')
        need(peer['controllerSha256']==hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'Peer ran a different comparison controller')
        cases=peer['lifecycleJournals']
        need(len(cases)==len(self.templates) and all(c['phase']=='quiesced' and not c['openRequests']
             and not c['sandboxIds'] and not c['outcomeUncertain'] for c in cases),'Peer lifecycle incomplete')
        created=[sid for c in cases for op in c['operations'] if op['kind']=='create' and op['httpStatus']==201
                 for sid in op['ack']['sandboxIds']]
        released=[row['sandboxId'] for row in peer['cleanup']['released']]
        need(len(created)==len(set(created))==len(released)==len(set(released))==len(self.templates)*2
             and set(created)==set(released) and all(row['fcExitConfirmed'] for row in peer['cleanup']['released']),
             'Peer release does not match acknowledged original Guests')
        return peer

    def idle_sample(self,group):
        processes=[]
        for variant,api in self.apis.items():
            processes.append(group.process_scope(api.pid,api.ticks,'runtime'))
            for daemon in self.ready.find_processes(self.gates.VERSIONS[variant]['root']/'bin/uvm-ublk-daemon',api.cgroup):
                processes.append(group.process_scope(daemon['pid'],daemon['startTicks'],'daemon'))
        provider=self.runtime.provider['providerProcess']
        processes.append(group.process_scope(provider['pid'],provider['startTicks'],'provider'))
        processes.append(group.process_scope(os.getpid(),self.sampler.identity(os.getpid())['startTicks'],'collector',0))
        return self.sampler.sample({'version':1,'root':str(ROOT),'node':self.node,'group':'before-'+self.args.phase,
            'bootId':self.contexts[self.args.phase]['bootId'],'processes':processes,'files':self.files,
            'devices':[],'ubReservation':self.ledger},include_files=True)

    def run(self):
        mkdir(FULL/'comparison');mkdir(WORK)
        registry=self.journals.RunJournal(WORK)
        phase=self.args.phase;receipt=None
        try:
            if phase=='original':registry.begin(self.args.run_id,self.plan)
            else:
                need(registry.state and registry.state['plan']==self.plan,'Existing local comparison inputs differ')
                self.peer_original()
            permit=registry.start_group(phase,self.contexts[phase])
            out=WORK/phase;need(not out.exists(),'Prior phase directory retained');mkdir(out)
            base=self.gates.VERSIONS[phase]['root'];api=self.apis[phase]
            group=self.adapter.ActualComparisonCohort(api,self.runtime.engine,self.ready,self.ram,self.sampler,
                base,phase,self.templates,self.contexts[phase],lambda index,state:save(out/('case-'+str(index)+'.json'),state),
                self.capacity,index=self.runtime.index if phase=='full' else None,permit=permit)
            save(out/'before-guest-create.json',self.idle_sample(group))
            started=time.monotonic();jobs=group.restore(self.args.run_id)
            restore_seconds=time.monotonic()-started
            for job in jobs:job['steps']=self.steps[job['templateIndex']]
            env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
                 'PATH':'/usr/local/bin:/usr/bin:/bin','NO_PROXY':'127.0.0.1,localhost,::1',
                 'no_proxy':'127.0.0.1,localhost,::1','XDG_CONFIG_HOME':str(base/'cli/config'),
                 'XDG_CACHE_HOME':str(base/'cli/cache'),'TMPDIR':str(base/'cli/tmp'),
                 'LD_LIBRARY_PATH':str(base/'native/lib')+':'+str(base/'native/fallback/lib')}
            provider=self.runtime.provider['providerProcess']
            runner=self.replay.NativeGroupReplay(out,base/'bin/aenv',env,jobs,self.runtime.replay.shell_command,
                group.owned,lambda **kw:group.collect(self.node,self.files,provider,self.ledger,**kw),
                lambda value:save(out/'replay.json',value))
            report=runner.run();save(out/'bindings.json',group.bindings)
            need(report['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED','Replay failed; Guests/state retained')
            actual_reads={}
            if phase=='full':
                through=time.monotonic_ns();daemon=group.daemon
                trace=FULL/'logs/rootfs-access'/('uvm-ublk-daemon-'+str(daemon['pid'])+'.jsonl')
                trace_status=trace.with_suffix('.status.json')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    if trace_status.exists() and json.loads(trace_status.read_bytes()).get('drained_through_ns',0)>=through:break
                    time.sleep(.2)
                for sid,binding in group.bindings.items():
                    actual_reads[sid]=self.ready.trace_summary(trace,trace_status,daemon['pid'],Path(binding['imageConfigPath']),self.runtime.refs,through)
                save(out/'actual-ub-reads.json',actual_reads)
            cleanup=group.release_after_completed_replay(report)
            status=self.continue_pair.provider_status(self.runtime)
            need(status['activeLeases']==status['activePayloadResponses']==status['payloadFailures']==0,'Provider drain/failure gate did not pass')
            permit.finish(cleanup,status if phase=='full' else None)
            receipt={'status':'LOCAL_COMPARISON_PHASE_RELEASED','node':self.node,'runId':self.args.run_id,'variant':phase,
                     'pairBundleSha256':self.accepted['bundleSha256'],'templateSignature':self.gates.input_signature(self.templates),
                     'context':self.contexts[phase],'cleanup':cleanup,'providerStatus':status,
                     'completedCommands':report['completedCommands'],'nonzeroCommands':report['nonzeroCommands'],
                     'elapsedSeconds':report['elapsedSeconds'],'restoreSeconds':restore_seconds,
                     'guests':len(jobs),'actualUBReads':actual_reads,
                     'controllerSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     'lifecycleJournals':[case.state for case in group.cases.values()],
                     'crossNodeSynchronizationVerified':False,'netSavingsBytes':None,'sharedObjectsRetired':False}
            save(out/'receipt.json',receipt)
            if phase=='full':
                original=json.loads((WORK/'original/replay.json').read_bytes())
                save(WORK/'local-comparison.json',self.replay.compare_completed(original,report))
            return receipt
        except Exception as error:
            save(WORK/('failure-'+phase+'.json'),{'status':'STOPPED_COMPARISON_PRESERVE_STATE',
                 'errorType':type(error).__name__,'reason':str(error)[:1000],'automaticCleanup':False})
            raise
        finally:registry.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--node',choices=('a','b'))
    parser.add_argument('--phase',choices=('original','full'));parser.add_argument('--run-id')
    parser.add_argument('--templates',type=int,choices=(1,4),default=1)
    parser.add_argument('--pair-bundle',type=Path);parser.add_argument('--allocation-ledger',type=Path)
    parser.add_argument('--peer-original',type=Path);args=parser.parse_args()
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY','scope':'explicit local original/full phase after real pair acceptance',
                          'defaultLocalGuests':2,'crossNodeTransportProvided':False,'fourTemplateCoverageReady':False}));return 0
    need(args.node and args.phase and args.pair_bundle and args.allocation_ledger
         and re.fullmatch('[0-9a-f]{32}',args.run_id or ''),'Missing fixed phase inputs')
    result=Comparison(args).run();print(json.dumps(result,indent=2));return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_LOCAL_COMPARISON_PRESERVE_STATE','errorType':type(error).__name__,
                          'reason':str(error)[:1000],'automaticCleanup':False}));raise SystemExit(1)
