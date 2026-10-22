LEGACY_BUILD=ROOT/'builds/native-four-release-v1/return.json'
RAW_PREPARATION=ROOT/'builds/native-four-inputs-v1/return.json'
TOOLS_REPORT=ROOT/'r/pm-a-v1/tools-runtime/return.json'
NEW_BUILD=ROOT/'builds/content-observer-release-v2/return.json'

def packet_module(name):
    row=PAYLOAD['common'][name+'.py'];data=zlib.decompress(base64.b64decode(row['data'],validate=True))
    need(len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'Input library payload differs')
    module=type(sys)('native_round_packet_'+name);module.__file__='<pinned-packet/'+name+'.py>'
    exec(compile(data,module.__file__,'exec'),module.__dict__);return module

def unit_state(unit):
    need(re.fullmatch(r'jwk-(?:aenv-native-archive(?:-single)?-v1-node-[ab]|native-retained-node-[ab]-[0-9a-f]{12})\.service',unit),
         'Unit outside this native round')
    r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,MainPID'],capture_output=True,text=True,timeout=15)
    value=dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
    need(r.returncode==0 or value.get('LoadState')=='not-found','Cannot inspect exact native unit')
    return value

def print_root(node,title,block):
    need(block.startswith('/usr/bin/python3 -I -B - <<') and len(block)<=256*1024,'Unexpected generated root block')
    print('\nCOPY_ON_'+node.upper().replace('-','_')+'_ROOT '+title+'\n'+block+'\nKEEP_THE_A_COORDINATOR_OPEN\n',flush=True)

def wait_until(label,predicate,timeout=1200):
    start=last=time.monotonic()
    while time.monotonic()-start<timeout:
        result=predicate()
        if result:return result
        if time.monotonic()-last>=30:print('WAITING='+label+' elapsed_s='+str(int(time.monotonic()-start)),flush=True);last=time.monotonic()
        time.sleep(2)
    raise RuntimeError('Deadline waiting for '+label+'; no automatic restart or release')

def provider_state(node):
    path=WORK/('generation-'+node)/'provider/owner.json'
    if not path.exists():return {'state':'not-ready'}
    value=load(path)
    need(value.get('state') not in ('unresolved_preserved','unresolved_create','released'),'Provider stopped or unresolved; preserve its journal')
    if value.get('state')!='serving':return {'state':value.get('state','not-ready')}
    plan=load(PROVIDER_PLAN/'plan.json');fields=unit_state(plan['unit'])
    need(fields.get('ActiveState')=='active' and int(fields.get('MainPID','0'))>1,'Serving journal without its active unit')
    return value

def rpc(mode,**values):
    args=[mode]
    for key,value in values.items():
        if value is not None:args+=['--'+key.replace('_','-'),str(value)]
    result=subprocess.run(remote_command(args),capture_output=True,timeout=60)
    need(result.returncode==0 and len(result.stdout)<=8*1024**2,'B control failed; remote action may be uncertain')
    return json.loads(result.stdout)

def fetch_file(name):
    result=rpc('b-fetch',file=name);raw=base64.b64decode(result['data'],validate=True)
    need(result['name']==name and len(raw)<=8*1024**2 and hashlib.sha256(raw).hexdigest()==result['sha256'],'B file framing differs')
    return raw

def bootstrap_b():
    need(SCENARIO=='dual-ab','Single-node round cannot initialize B')
    code="""import os,socket
from pathlib import Path
assert os.getuid()==os.geteuid()==1204 and socket.gethostname()=='agent1'
p=Path(WORK);assert p.parent.resolve(strict=True)==p.parent and p.parent.stat().st_uid==1204
assert not p.exists() and not p.is_symlink(),'Existing B round preserved'
os.umask(0o077);p.mkdir(mode=0o700)
(p/'new-build').mkdir(mode=0o700);(p/'new-build/artifacts').mkdir(mode=0o700)
print('B_PRIVATE_ROUND_DIRECTORY_READY')
"""
    code='WORK='+repr(str(WORK))+'\n'+code
    r=subprocess.run(SSH+[shlex.join([PYTHON,'-I','-B','-c',code])],capture_output=True,timeout=30)
    need(r.returncode==0 and r.stdout.strip()==b'B_PRIVATE_ROUND_DIRECTORY_READY','B round initialization failed; preserve any partial')
    transfer(SELF,SELF)

def install_components(steps):
    steps.local('install-provider-source','native_retained_install.py',['--directory',PROVIDER_SOURCE,'--install'])
    steps.local('install-native-cohort','native_archive_cohort_install.py',['--install'])

def local_provider_prepare(steps,node,selection,logical,coverage,legacy):
    inputs=checked_module('native_round_inputs');layout=inputs.paths(node,SCENARIO)
    need(layout['deployment']==DEPLOYMENT and layout['work']==WORK,'Scenario layout differs')
    adapter=ROOT/('r/lazy4-a-v1/libaenv-ub.so' if node=='node-a' else 'r/lazy4-b-v1/libaenv-ub.so')
    runtime={'verifier':str(DEPLOYMENT/'bin/aenv-native-fd-verify'),
             'verifierSha256':'sha256:'+legacy['artifacts']['aenv-native-fd-verify']['sha256'],
             'firecrackerSha256':'sha256:'+legacy['artifacts']['firecracker']['sha256'],'verificationTimeoutSecs':300}
    save(WORK/'device-runtime.json',runtime)
    request=inputs.provider_request(node,SCENARIO,selection,sha(adapter),logical,coverage)
    save(WORK/'provider-request.json',request)
    steps.local('prepare-provider','native_retained_service.py',['prepare','--node',node,'--request',WORK/'provider-request.json',
                '--directory',PROVIDER_PLAN,'--detached','--run'],1800)

def prepare_runtime(steps,node,legacy_report,runtime_report,tools_report,tools_image=None,snapshots=None):
    selection={'version':1,'legacyReport':str(legacy_report),'legacyReportSha256':sha(legacy_report),
               'runtimeReport':str(runtime_report),'runtimeReportSha256':sha(runtime_report)}
    save(WORK/'runtime-builds.json',selection)
    binding=WORK/('generation-'+node)/'binding.json'
    args=['prepare','--node',node,'--core-report',WORK/'runtime-builds.json','--tools-report',tools_report,
          '--rootfs-binding',binding,'--binding-sha256',sha(binding)]
    if tools_image:args+=['--tools-image',tools_image]
    steps.local('prepare-runtime','prepare_native_archive_runtime.py',args,1800)
    steps.local('seed-original-inputs','native_archive_inputs.py',['seed','--node',node,'--directory',WORK/'sources','--run'],7200)
    if snapshots:
        steps.local('seed-a-native-snapshots','native_snapshot_transport.py',['seed','--node',node,'--directory',snapshots,'--run'],7200)

def runtime_ready(node):
    definition=load(DEPLOYMENT/'definition-native.json');unit='jwk-aenv-'+('native-archive-single' if SCENARIO=='single-a' else 'native-archive')+'-v1-'+node+'.service'
    fields=unit_state(unit)
    if fields.get('LoadState')=='not-found' or fields.get('ActiveState')=='activating':return False
    need(fields.get('ActiveState')=='active' and int(fields.get('MainPID','0'))>1,'Native Runtime failed; preserve launcher logs')
    return {'unit':unit,'pid':int(fields['MainPID']),'apiPort':definition['apiPort']}

def check_cohort_sources():
    installer=checked_module('native_archive_cohort_install')
    for name,row in installer.FILES.items():need(sha(COHORT/name)==row['sha256'],'Native cohort helper changed')

def worker(node,mode,replica_mode='restore-pair',admission=None,completed=None):
    check_cohort_sources()
    need(mode in ('parents','replay','cleanup') and replica_mode in ('restore-pair','restore-fork','restore-fork-parallel'),'Invalid cohort mode')
    args=[PYTHON,'-I','-B',str(COHORT/'native_archive_cohort.py'),mode,'--node',node,'--replica-mode',replica_mode,'--run']
    if mode!='cleanup':args+=['--provider-plan',str(PROVIDER_PLAN/'plan.json')]
    if mode!='parents':args+=['--scenario',SCENARIO]
    if admission or completed:
        need(admission and completed,'Both native pair gates required');args+=['--admission-epoch',admission,'--completed-epoch',completed]
    name=mode+'-'+node+'-'+replica_mode
    log=WORK/'logs'/(name+'.log')
    need(not log.exists(),'Existing cohort phase log preserved')
    print('PHASE='+name,flush=True)
    with log.open('xb') as stream:
        child=subprocess.Popen(args,stdout=stream,stderr=subprocess.STDOUT)
        began=last=time.monotonic()
        try:
            while child.poll() is None:
                need(time.monotonic()-began<9000,'Native worker budget exceeded')
                if time.monotonic()-last>=30:print('COHORT_PROGRESS='+name+' elapsed_s='+str(int(time.monotonic()-began)),flush=True);last=time.monotonic()
                time.sleep(1)
        finally:
            if child.poll() is None:
                child.terminate()
                try:child.wait(360)
                except subprocess.TimeoutExpired:
                    child.kill();child.wait(10) # Unknown API effects remain in the case journal.
    if mode=='parents':path=DEPLOYMENT/'native-cohort/templates.json'
    else:path=DEPLOYMENT/'native-cohort'/(SCENARIO+'-'+replica_mode)/'report.json'
    report=load(path) if path.exists() else {'status':'WORKER_STOPPED_BEFORE_REPORT','ownedGuestsReleased':False,'outcomeUncertain':True,'fullLog':str(log)}
    report['workerExitCode']=child.returncode
    save(WORK/(name+'.json'),report)
    return report

def sync_module():
    check_cohort_sources();spec=importlib.util.spec_from_file_location('native_round_sync',COHORT/'four_sync.py')
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

def pair(stage,epoch,operation,payload=None):
    return rpc('b-pair',variant=stage,pair_epoch=epoch,operation=operation,payload=json.dumps(payload) if payload else None)

def dual_replay(steps,replica_mode):
    sync=sync_module();epochs={stage:uuid.uuid4().hex for stage in ('admission','completed')}
    for stage,epoch in epochs.items():sync.prepare('node-a',stage,epoch);pair(stage,epoch,'prepare')
    released=False;state={'epochs':epochs,'status':'DUAL_NATIVE_STARTING'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(worker,'node-a','replay',replica_mode,epochs['admission'],epochs['completed'])
        b=pool.submit(steps.call,'dual-worker-b',remote_command(['b-worker','--replica-mode',replica_mode,
            '--admission-epoch',epochs['admission'],'--completed-epoch',epochs['completed']]),9300,True)
        try:
            for stage,epoch in epochs.items():
                start=time.monotonic();readies=None
                while time.monotonic()-start<8100:
                    need(not a.done() and not b.done(),'Worker ended before the native completion gate')
                    observed={'node-a':sync.control('node-a',stage,epoch,'status'),'node-b':pair(stage,epoch,'status')}
                    need(not any(v.get('failed') or v.get('abort') for v in observed.values()),'Native pair gate failed')
                    if readies is None and all(v.get('ready') for v in observed.values()):
                        readies={n:v['ready'] for n,v in observed.items()};message=sync.control_message('measure',stage,epoch,readies)
                        pair(stage,epoch,'measure',message);sync.control('node-a',stage,epoch,'measure',message)
                    if readies is not None and all(v.get('measured') for v in observed.values()):
                        measured={n:v['measured'] for n,v in observed.items()};message=sync.control_message('release',stage,epoch,readies,measured)
                        pair(stage,epoch,'release',message);sync.control('node-a',stage,epoch,'release',message)
                        state[stage]={'ready':readies,'measured':measured};break
                    time.sleep(2)
                else:raise RuntimeError('Native pair gate deadline exceeded')
            released=True
        finally:
            if not released:
                for stage,epoch in epochs.items():
                    for node in ('node-a','node-b'):
                        try:
                            if node=='node-a':sync.control(node,stage,epoch,'abort')
                            else:pair(stage,epoch,'abort')
                        except Exception as error:state.setdefault('abortErrors',[]).append([node,stage,type(error).__name__])
            state['bothGatesReleased']=released;save(WORK/'dual-gates.json',state)
        result_a=a.result();b.result()
    result_b=json.loads(fetch_file('replay-node-b-'+replica_mode+'.json'))
    need(released,'Native replay barriers not completed')
    return [result_a,result_b]

def pid_gone(identity):
    if identity is None:return True
    path=Path('/proc')/str(identity['pid'])/'stat'
    try:ticks=path.read_text().rsplit(')',1)[1].split()[19]
    except FileNotFoundError:return True
    return ticks!=identity['startTicks']

def quiesce_local(node,replica_mode):
    if not DEPLOYMENT.exists():return {'quiescent':True,'runtimePrepared':False}
    state=load(DEPLOYMENT/'cohort-state.json')
    if state.get('phase') not in ('prepared','quiesced') or state.get('openRequests') or state.get('sandboxIds'):
        phase=state.get('fourPhase');need(phase in ('parents',SCENARIO+'-'+replica_mode),'Unknown native cohort phase preserved')
        check_cohort_sources();log=WORK/'logs'/('cleanup-'+node+'-'+uuid.uuid4().hex+'.log')
        with log.open('xb') as stream:
            result=subprocess.run([PYTHON,'-I','-B',str(COHORT/'native_archive_cohort.py'),'cleanup','--node',node,
                 '--scenario','parents' if phase=='parents' else SCENARIO,'--replica-mode',replica_mode,'--run'],
                 stdout=stream,stderr=subprocess.STDOUT,timeout=900)
        need(result.returncode==0,'Native cohort reconciliation failed; no service stop or SDK retire')
        state=load(DEPLOYMENT/'cohort-state.json')
    need(state.get('phase') in ('prepared','quiesced') and state.get('openRequests')==[]
         and state.get('sandboxIds')==[] and state.get('outcomeUncertain') is False,'Native Guest lifecycle is uncertain')
    return {'quiescent':True,'runtimePrepared':True}

def stop_plan_local(node,replica_mode):
    quiesce_local(node,replica_mode)
    if not DEPLOYMENT.exists():return {'stopped':True,'neverPrepared':True}
    installation=load(DEPLOYMENT/'installation.json');unit=installation['unit'];fields=unit_state(unit)
    proxy_path=Path(installation['runtime'])/'host-proxy.json'
    proxy=load(proxy_path) if proxy_path.exists() else None
    proxy_identity={'pid':proxy['pid'],'startTicks':proxy['start_ticks']} if proxy else None
    if fields.get('LoadState')=='not-found' or fields.get('ActiveState')=='inactive':
        need(int(fields.get('MainPID','0'))==0 and pid_gone(proxy_identity),'Runtime stopped but its proxy remains unconfirmed')
        return {'stopped':True,'alreadyInactive':True}
    need(fields.get('ActiveState')=='active' and int(fields.get('MainPID','0'))>1,'Unknown Runtime state preserved')
    path=WORK/('runtime-stop-'+node+'.json');need(not path.exists(),'Prior Runtime stop attempt preserved; do not submit again')
    pid=int(fields['MainPID']);ticks=Path('/proc')/str(pid)/'stat'
    proof={'unit':unit,'main':{'pid':pid,'startTicks':ticks.read_text().rsplit(')',1)[1].split()[19]},'proxy':proxy_identity}
    result=subprocess.run([PYTHON,'-I','-B',str(HELPERS/'prepare_native_archive_runtime.py'),'rollback-plan','--node',node],
                          capture_output=True,text=True,timeout=120)
    need(result.returncode==0,'Could not produce a scoped Runtime rollback; preserve it')
    begin,end='BEGIN_NATIVE_CONTROL_PLAN','END_NATIVE_CONTROL_PLAN'
    need(result.stdout.count(begin)==result.stdout.count(end)==1,'Rollback framing differs')
    proof['block']=result.stdout.split(begin,1)[1].split(end,1)[0].strip()+'\n';save(path,proof)
    return proof

def stop_complete_local(node):
    proof=load(WORK/('runtime-stop-'+node+'.json'));fields=unit_state(proof['unit'])
    return {'stopped':int(fields.get('MainPID','0'))==0 and pid_gone(proof['main']) and pid_gone(proof['proxy'])}

def retire_local(node):
    work=WORK/('generation-'+node)/'provider'
    if not work.exists():
        # A submitted provider may still initialize. A mere absent directory
        # cannot prove non-execution once a root activation plan was emitted.
        need(not (PROVIDER_PLAN/'plan.json').exists(),'Provider activation status unknown; no release inferred')
        return {'state':'not-created','noActivationPlan':True}
    owner=load(work/'owner.json')
    if owner.get('state')=='released':return wait_until('released-provider-exit-'+node,lambda:released_local(node,allow_pending=True),120)
    need(owner.get('state')=='serving','Provider is not in a reconciled serving state')
    intent=WORK/('retire-'+node+'.json');need(not intent.exists(),'Prior retire outcome preserved; never resend')
    command=[PYTHON,'-I','-B',str(PROVIDER_SOURCE/'provider_entry.py'),'retire',str(work)]
    if node=='node-a' and SCENARIO=='dual-ab':
        receipt=WORK/'peer-release.json';need(receipt.exists(),'Exact B release receipt required');command+=['--peer-receipt',str(receipt)]
    save(intent,{'state':'intent_before_retire','ownerId':owner['ownerId'],'manifestSha256':owner['manifestSha256']})
    log=WORK/'logs'/('retire-'+node+'.log')
    with log.open('xb') as output:
        try:result=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT,timeout=660)
        except subprocess.TimeoutExpired:result=None
    if result is not None and result.returncode!=0 and log.stat().st_size<=65536:
        try:reply=json.loads(log.read_bytes())
        except (ValueError,UnicodeDecodeError):reply=None
        if isinstance(reply,dict) and reply.get('state')=='refused':
            raise RuntimeError('Provider explicitly refused retirement; preserve the exact reply and do not resend')
    # A lost control reply does not warrant a second request. Observe journals.
    value=wait_until('provider-release-'+node,lambda:released_local(node,allow_pending=True),1800)
    value['retireCommandExit']=result.returncode if result else None;return value

def released_local(node,allow_pending=False):
    work=WORK/('generation-'+node)/'provider';owner=load(work/'owner.json')
    if allow_pending and owner.get('state') in ('serving','retiring_readers_released'):return False
    manifest=load(work/'replicas.json')
    pin='sha256:'+hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    need(owner.get('state')=='released' and owner.get('mode')=='pmem' and owner.get('format')=='native-raw-v1'
         and owner.get('role')==('publish' if node=='node-a' else 'import') and owner.get('finalize_acknowledged') is True
         and owner.get('ownerId')==manifest.get('ownerId') and owner.get('manifestSha256')==pin,'Native provider release not proved')
    if node=='node-a':
        need(owner.get('objects') and all(r.get('creation_confirmed') is True and r.get('delete_acknowledged') is True for r in owner['objects']),
             'Owner allocation deletion not fully acknowledged')
    else:
        need(load(work/'release.json')=={'version':1,'ownerId':manifest['ownerId'],'readerId':'node-b-native-retained',
             'manifestSha256':pin,'state':'released'},'Importer release receipt differs')
    plan=load(PROVIDER_PLAN/'plan.json');fields=unit_state(plan['unit'])
    if int(fields.get('MainPID','0'))!=0:
        if allow_pending:return False
        raise RuntimeError('SDK release acknowledged but provider process has not exited')
    return {'state':'released','ownerId':owner['ownerId'],'manifestSha256':pin,'finalizeAcknowledged':True}

def cleanup_round(nodes,replica_mode):
    result={'status':'NATIVE_CLEANUP_CHECKING','nodes':{},'unknownPreserved':False}
    try:
        for node in reversed(nodes):
            value=stop_plan_local(node,replica_mode) if node=='node-a' else rpc('b-stop-plan',replica_mode=replica_mode)
            if not value.get('stopped'):
                print_root(node,'STOP_ONLY_CONFIRMED_EMPTY_RUNTIME',value['block'])
                wait_until('runtime-stopped-'+node,lambda:(stop_complete_local(node) if node=='node-a' else rpc('b-stop-state')).get('stopped'))
            result['nodes'][node]={'runtimeStoppedOrAbsent':True}
        if 'node-b' in nodes:
            result['nodes']['node-b']['provider']=rpc_long('b-retire',timeout=2500)
            release=fetch_file('peer-release.json')
            with (WORK/'peer-release.json').open('xb') as output:output.write(release)
        result['nodes']['node-a']['provider']=retire_local('node-a')
        result['status']='OWN_NATIVE_ROUND_QUIESCED_AND_UB_RELEASED'
    except BaseException as error:
        result.update(status='NATIVE_CLEANUP_STOPPED_PRESERVE_UNKNOWN',unknownPreserved=True,errorType=type(error).__name__,reason=str(error)[:500])
    save(WORK/'cleanup.json',result);return result

def rpc_long(mode,timeout=7200,**values):
    args=[mode]
    for key,value in values.items():
        if value is not None:args+=['--'+key.replace('_','-'),str(value)]
    log=WORK/'logs'/(mode+'-'+uuid.uuid4().hex+'.log')
    with log.open('xb') as output:
        result=subprocess.run(remote_command(args),stdout=output,stderr=subprocess.STDOUT,timeout=timeout)
    need(result.returncode==0,'B phase failed; inspect '+str(log))
    # Phase operations write a bounded response as the final line; full logs stay local.
    with log.open('rb') as stream:stream.seek(0,2);stream.seek(max(0,stream.tell()-8*1024**2));tail=stream.read().decode()
    return json.loads(tail.strip().splitlines()[-1])

def validate_reports(reports,error=None):
    expected={'node-a'} if SCENARIO=='single-a' else {'node-a','node-b'}
    issues=[];vectors={};identities={}
    if error is not None:issues.append('coordinator_error')
    if len(reports)!=len(expected) or {r.get('node') for r in reports}!=expected:issues.append('missing_or_duplicate_node_report')
    for report in reports:
        node=report.get('node')
        if (report.get('scenario')!=SCENARIO or report.get('status')!='NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED'
                or report.get('workerExitCode')!=0 or report.get('replicaFormation') not in ('restore-pair','restore-fork','restore-fork-parallel')):
            issues.append(str(node)+':worker_incomplete')
        jobs=report.get('jobs',[])
        if len(jobs)!=8 or len({j.get('sandboxId') for j in jobs})!=8 or { (j.get('templateIndex'),j.get('slot')) for j in jobs }!={(i,s) for i in range(4) for s in (0,1)}:
            issues.append(str(node)+':guest_inventory_incomplete');continue
        vectors[node]={};identities[node]={}
        for job in jobs:
            key=(job['templateIndex'],job['slot']);results=job.get('commandResults',[]);count=job.get('expectedSteps')
            valid=type(count) is int and count>0 and job.get('state')=='REPLAY_COMPLETED' and job.get('stepsCompleted')==count and len(results)==count
            valid=valid and all(row.get('step')==i and type(row.get('returnCode')) is int and row['returnCode'] not in (124,137) for i,row in enumerate(results))
            valid=valid and job.get('failedCommands')==sum(row['returnCode']!=0 for row in results)
            valid=valid and isinstance(job.get('instanceId'),str) and bool(job['instanceId']) and isinstance(job.get('replaySha256'),str) and re.fullmatch('[0-9a-f]{64}',job['replaySha256']) is not None
            if not valid:issues.append(str(node)+':commands_incomplete:'+str(key));continue
            vectors[node][key]=[row['returnCode'] for row in results]
            identities[node][key]=(job.get('instanceId'),job.get('replaySha256'),report.get('replicaFormation'))
    peer_match=None
    if SCENARIO=='dual-ab':
        peer_match=(set(vectors)==expected and all(len(v)==8 for v in vectors.values())
                    and vectors['node-a']==vectors['node-b'] and identities['node-a']==identities['node-b'])
        if not peer_match:issues.append('native_peer_command_results_or_inputs_differ')
    return {'complete':not issues,'issues':issues,'nativePeerCommandResultsMatch':peer_match}

def emit_report(reports,cleanup,error=None):
    validation=validate_reports(reports,error)
    complete=validation['complete'] and cleanup.get('status')=='OWN_NATIVE_ROUND_QUIESCED_AND_UB_RELEASED'
    pools={}
    for report in reports:
        provider=report.get('completedSample',{}).get('provider',{})
        if provider.get('available') is not True:continue
        key=provider.get('ownerId')
        if not isinstance(key,str):continue
        pool=pools.setdefault(key,{'ownerId':key,'observationsByNode':{},'ownerReportedCoverageBytes':None,'physicalIncrementBytes':None})
        node=report.get('node');pool['observationsByNode'][node]={k:provider.get(k) for k in
            ('manifestSha256','sdkReportedBackingCoverageBytes','logicalRequestBudgetBytes')}
        if node=='node-a':pool['ownerReportedCoverageBytes']=provider.get('sdkReportedBackingCoverageBytes')
    for pool in pools.values():
        identities={row['manifestSha256'] for row in pool['observationsByNode'].values()}
        pool['manifestIdentityConsistent']=len(identities)==1 and None not in identities
        if not pool['manifestIdentityConsistent']:pool['ownerReportedCoverageBytes']=None
    result={'status':'NATIVE_ROUND_MEASURED_AND_RELEASED' if complete and not cleanup['unknownPreserved'] else 'NATIVE_ROUND_PARTIAL_PRESERVED',
            'scenario':SCENARIO,'reports':reports,'cleanup':cleanup,'error':error,'completionValidation':validation,
            'originalComparison':'historical reference only; no original Runtime replay in this native round',
            'memfileCrossNodeCowImplemented':False,'completeCounterfactualAccepted':False,
            'globalPhysicalNetSavingBytes':None,'rootfsCompleteAccessResidency':None,'SDKCoverageIsPhysicalIncrement':False,
            'guestFileCacheDecomposition':None,'completeAuxiliaryCost':False,'ubGenerations':list(pools.values()),
            'accountingLimits':['Guest file cache is included in Guest RAM and not separately attributed',
                                'auxiliary process PSS overlaps Host accounting; SSH/kernel/driver costs are incomplete']}
    save(WORK/'comparison.json',result)
    lines=['# Native round result','',result['status'],'','Scenario: '+SCENARIO,
           '', 'This round measures the native candidate only. Original-version causal comparison and global physical net savings remain NA.',
           'Guest RAM cross-node private CoW is not implemented. SDK mapping coverage is not physical incremental memory.','',
           '| Node | Template | Slot | Completed actions | Nonzero actions | State |','|---|---|---:|---:|---:|---|']
    for report in reports:
        for job in report.get('jobs',[]):lines.append('| '+' | '.join(str(x) for x in [report.get('node'),job.get('templateIndex'),job.get('slot'),job.get('stepsCompleted'),job.get('failedCommands'),job.get('state')])+' |')
    lines+=['','Cleanup: '+cleanup['status'],'','Full per-command results, measurement summaries and preserved diagnostics: comparison.json and logs/.']
    with (WORK/'comparison.md').open('x') as output:output.write('\n'.join(lines)+'\n')
    return result

def run_a(replica_mode):
    ordinary('node-a');need(Path(__file__).resolve()==SELF,'Use the pinned native round entry path')
    need(not WORK.exists() and not DEPLOYMENT.exists() and not COHORT.exists() and not PROVIDER_SOURCE.exists(),
         'Existing/partial native scenario preserved; do not restart blindly')
    inputs=packet_module('native_round_inputs');prepared=load(RAW_PREPARATION)
    need(prepared.get('status')=='FOUR_NATIVE_IMAGES_AND_BINARIES_PREPARED_NOT_DEPLOYED','Native raw preparation not complete; no automatic export or compaction')
    print('PHASE=verify-retained-native-raw-images',flush=True)
    images,logical,coverage=inputs.image_selection(prepared)
    load(LEGACY_BUILD);load(TOOLS_REPORT)
    if SCENARIO=='dual-ab':transport_readiness()
    steps=Steps('node-a');install_tools();nodes=['node-a'];reports=[];failure=None
    try:
        if not NEW_BUILD.exists():
            need(not NEW_BUILD.parent.exists(),'Partial new Runtime build preserved')
            steps.local('build-runtime-once','A_build_content_observer_v1.py',['--run'],10800)
        prepared,legacy,_,_=inputs.preflight_a(RAW_PREPARATION,LEGACY_BUILD,NEW_BUILD,TOOLS_REPORT)
        install_components(steps);save(WORK/'images.json',images)
        save(WORK/'budgets.json',{'logical':logical,'coverage':coverage})
        steps.local('pack-verified-source-inputs','native_archive_inputs.py',['pack','--report',RAW_PREPARATION,'--archive',WORK/'sources.tar','--run'],7200)
        steps.local('receive-source-inputs-a','native_archive_inputs.py',['receive','--archive',WORK/'sources.tar','--sha256',sha(WORK/'sources.tar'),'--directory',WORK/'sources','--run'],7200)
        local_provider_prepare(steps,'node-a',{'images':WORK/'images.json'},logical,coverage,legacy)
        print_root('node-a','START_NATIVE_PROVIDER',read(PROVIDER_PLAN/'activate-root.sh').decode())
        wait_until('A-provider-serving',lambda:provider_state('node-a').get('state')=='serving',1800)
        if SCENARIO=='dual-ab':
            bootstrap_b();nodes.append('node-b')
            steps.local('pack-retained-binaries','four_release_bundle.py',['pack','--build-report',LEGACY_BUILD,'--tools-report',TOOLS_REPORT,'--archive',WORK/'old-release.tar','--run'],1800)
            for source,target in [(WORK/'old-release.tar',WORK/'old-release.tar'),(WORK/'sources.tar',WORK/'sources.tar'),
                                  (WORK/'budgets.json',WORK/'budgets.json'),(NEW_BUILD,WORK/'new-build/return.json'),
                                  (WORK/'generation-node-a/binding.json',WORK/'owner-binding.json'),
                                  (WORK/'generation-node-a/provider/replicas.json',WORK/'owner-manifest.json')]:transfer(source,target)
            for name in ('server','uvm-ublk-daemon'):transfer(NEW_BUILD.parent/'artifacts'/name,WORK/'new-build/artifacts'/name)
            rpc_long('b-prepare-provider',bundle_sha=sha(WORK/'old-release.tar'),inputs_sha=sha(WORK/'sources.tar'),timeout=10800)
            print_root('node-b','START_NATIVE_PROVIDER',fetch_file('provider-root.txt').decode())
            wait_until('B-provider-serving',lambda:rpc('b-provider-state').get('state')=='serving',1800)
        prepare_runtime(steps,'node-a',LEGACY_BUILD,NEW_BUILD,TOOLS_REPORT)
        print_root('node-a','START_NATIVE_RUNTIME',read(DEPLOYMENT/'review-new-unit-root.txt').decode())
        wait_until('A-runtime-active',lambda:runtime_ready('node-a'))
        steps.call('health-a',[PYTHON,'-I','-B',str(DEPLOYMENT/'libexec/native_service.py'),'health'],180)
        parents=worker('node-a','parents')
        need(parents.get('status')=='FOUR_NATIVE_PARENTS_CAPTURED_OWNED_GUESTS_RELEASED' and parents['workerExitCode']==0,'A native capture/cleanup failed')
        if SCENARIO=='single-a':reports=[worker('node-a','replay',replica_mode)]
        else:
            steps.local('pack-a-native-snapshots','native_snapshot_transport.py',['pack','--repository',DEPLOYMENT/'state/snapshot-store/repository',
                '--selection',WORK/'sources/selection.private.json','--history',WORK/'sources/historical-reference.private.json',
                '--captures',DEPLOYMENT/'native-cohort/templates.json','--archive',WORK/'snapshots.tar','--run'],7200)
            pin=transfer(WORK/'snapshots.tar',WORK/'snapshots.tar')
            rpc_long('b-prepare-runtime',snapshots_sha=pin,timeout=10800)
            print_root('node-b','START_NATIVE_RUNTIME',fetch_file('runtime-root.txt').decode())
            wait_until('B-runtime-active',lambda:rpc('b-runtime-state').get('active'))
            rpc_long('b-health',timeout=180)
            reports=dual_replay(steps,replica_mode)
    except BaseException as error:failure={'type':type(error).__name__,'reason':re.sub(r'e2b_[A-Za-z0-9._~-]+','[REDACTED]',str(error))[:1000]}
    finally:
        if not reports:
            for node in nodes:
                name='replay-'+node+'-'+replica_mode+'.json'
                try:
                    if node=='node-b':
                        raw=fetch_file(name)
                        if not (WORK/name).exists():
                            with (WORK/name).open('xb') as output:output.write(raw)
                    if (WORK/name).exists():reports.append(load(WORK/name))
                except Exception:pass # Missing failed-run evidence remains absent, not zero or success.
        cleanup=cleanup_round(nodes,replica_mode)
        report=emit_report(reports,cleanup,failure);print(json.dumps(report,indent=2))
    return 0 if report['status']=='NATIVE_ROUND_MEASURED_AND_RELEASED' else 1

def continued_steps(node):
    steps=Steps.__new__(Steps);steps.node=node;steps.path=WORK/('steps-'+node+'.json');steps.state=load(steps.path)
    need(steps.state.get('revision')=='native-archive-round-v1' and steps.state.get('scenario')==SCENARIO
         and steps.state.get('bootId')==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and all(r.get('state')=='completed' and r.get('exitCode')==0 for r in steps.state['steps']),
         'Earlier B phase is incomplete; no automatic retry')
    return steps

def b_prepare_provider(args):
    steps=Steps('node-b');install_tools();install_components(steps)
    steps.local('receive-retained-binaries','four_release_bundle.py',['receive','--archive',WORK/'old-release.tar',
        '--sha256',args.bundle_sha,'--destination',WORK/'old-release','--run'],1800)
    steps.local('receive-original-inputs','native_archive_inputs.py',['receive','--archive',WORK/'sources.tar',
        '--sha256',args.inputs_sha,'--directory',WORK/'sources','--run'],7200)
    budgets=load(WORK/'budgets.json');legacy=load(WORK/'old-release/build-receipt.json')
    selected={'binding':WORK/'owner-binding.json','bindingSha256':sha(WORK/'owner-binding.json'),
              'manifest':WORK/'owner-manifest.json','manifestSha256':sha(WORK/'owner-manifest.json')}
    local_provider_prepare(steps,'node-b',selected,budgets['logical'],budgets['coverage'],legacy)
    return {'status':'B_NATIVE_PROVIDER_PREPARED_NOT_STARTED'}

def b_prepare_runtime(args):
    steps=continued_steps('node-b')
    steps.local('receive-a-snapshots','native_snapshot_transport.py',['receive','--archive',WORK/'snapshots.tar',
        '--sha256',args.snapshots_sha,'--directory',WORK/'received-snapshots','--run'],7200)
    prepare_runtime(steps,'node-b',WORK/'old-release/build-receipt.json',WORK/'new-build/return.json',
                    WORK/'old-release/tools-receipt.json',WORK/'old-release/tools.ext4',WORK/'received-snapshots')
    return {'status':'B_NATIVE_RUNTIME_AND_A_SNAPSHOTS_PREPARED_NOT_STARTED'}

def b_fetch(name):
    paths={'provider-root.txt':PROVIDER_PLAN/'activate-root.sh','runtime-root.txt':DEPLOYMENT/'review-new-unit-root.txt',
           'peer-release.json':WORK/'generation-node-b/provider/release.json',
           **{'replay-node-b-'+mode+'.json':WORK/('replay-node-b-'+mode+'.json') for mode in ('restore-pair','restore-fork','restore-fork-parallel')}}
    need(name in paths,'Unexpected private response file')
    raw=read(paths[name],8*1024**2)
    return {'name':name,'data':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}

def main():
    parser=argparse.ArgumentParser(description='Coordinated native archive candidate; no cross-node RAM private CoW claim.')
    parser.add_argument('mode',choices=('run-a','b-prepare-provider','b-provider-state','b-prepare-runtime','b-runtime-state',
        'b-health','b-worker','b-fetch','b-pair','b-stop-plan','b-stop-state','b-retire'))
    parser.add_argument('--scenario',choices=('single-a','dual-ab'),required=True)
    parser.add_argument('--replica-mode',choices=('restore-pair','restore-fork','restore-fork-parallel'),default='restore-pair')
    for name in ('bundle-sha','inputs-sha','snapshots-sha','admission-epoch','completed-epoch','pair-epoch','variant','operation','payload','file'):
        parser.add_argument('--'+name)
    parser.add_argument('--run',action='store_true');args=parser.parse_args();scenario_paths(args.scenario)
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY_NO_HOST_ACCESS_OR_CHANGES','scenario':SCENARIO,
            'guestCount':8 if SCENARIO=='single-a' else 16,'replicaFormation':args.replica_mode,
            'memfilePrivateCowImplemented':False,'originalReplayIncluded':False}));return 0
    if args.mode=='run-a':
        import fcntl
        ordinary('node-a');lock=ROOT/'relay/native-archive-coordinator.lock'
        fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            metadata=os.fstat(fd);need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==1204 and metadata.st_nlink==1,'Coordinator lock differs')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return run_a(args.replica_mode)
        finally:os.close(fd)
    need(SCENARIO=='dual-ab','Single-node mode has no B operations')
    ordinary('node-b');need(Path(__file__).resolve()==SELF,'Unexpected B coordinator path')
    if args.mode!='b-prepare-provider':hydrate_tools()
    for key in ('bundle_sha','inputs_sha','snapshots_sha'):
        value=getattr(args,key);need(value is None or re.fullmatch('[0-9a-f]{64}',value),'Invalid file digest')
    if args.mode=='b-prepare-provider':
        need(args.bundle_sha and args.inputs_sha,'B transferred file identities missing');result=b_prepare_provider(args)
    elif args.mode=='b-prepare-runtime':
        need(args.snapshots_sha,'A snapshot archive identity missing');result=b_prepare_runtime(args)
    elif args.mode=='b-provider-state':result=provider_state('node-b')
    elif args.mode=='b-runtime-state':result={'active':bool(runtime_ready('node-b'))}
    elif args.mode=='b-health':
        r=subprocess.run([PYTHON,'-I','-B',str(DEPLOYMENT/'libexec/native_service.py'),'health'],timeout=180)
        need(r.returncode==0,'B Runtime health failed');result={'healthy':True}
    elif args.mode=='b-worker':result=worker('node-b','replay',args.replica_mode,args.admission_epoch,args.completed_epoch)
    elif args.mode=='b-fetch':result=b_fetch(args.file)
    elif args.mode=='b-stop-plan':result=stop_plan_local('node-b',args.replica_mode)
    elif args.mode=='b-stop-state':result=stop_complete_local('node-b')
    elif args.mode=='b-retire':result=retire_local('node-b')
    else:
        need(args.variant in ('admission','completed') and re.fullmatch('[0-9a-f]{32}',args.pair_epoch or '')
             and args.operation in ('prepare','status','measure','release','abort'),'Invalid native barrier scope')
        sync=sync_module()
        if args.operation=='prepare':sync.prepare('node-b',args.variant,args.pair_epoch);result={'prepared':True}
        else:
            need(args.payload is None or len(args.payload)<=65536,'Barrier payload too large')
            result=sync.control('node-b',args.variant,args.pair_epoch,args.operation,json.loads(args.payload) if args.payload else None)
    print(json.dumps(result,separators=(',',':')));return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED_NATIVE_ROUND_PRESERVE_JOURNALS','errorType':type(error).__name__,
                          'reason':re.sub(r'e2b_[A-Za-z0-9._~-]+','[REDACTED]',str(error))[:1000],
                          'memfilePrivateCowImplemented':False,'physicalNetSavingBytes':None}));raise SystemExit(1)
