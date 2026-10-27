"""Local identity, workload and coverage gates before original/full replay.

Read-only inspection only. This does not start a cohort or allocate UB. A
complete cross-node lifecycle gate and explicit allocation approval are also
required by the eventual executor.
"""
import argparse,hashlib,json,os,platform,re,stat,subprocess,tomllib
from pathlib import Path
ROOT=Path('/home/jwk/agent')
ORIGINAL=ROOT/'deployments/agentenv-ae9c626-baseline'
FULL=ROOT/'deployments/agentenv-direct-ub-deletefix-v1'
VERSIONS={
 'original':{'commit':'ae9c62693839ce7effa2b45df31c0039ae4f9fbc','root':ORIGINAL,
    'server':'0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff',
    'uvm-ublk-daemon':'13bd2ac381cf877348a39c0b198e2061479ae237c0f54cbcbeae0ab14e700172',
    'aenv':'ac2cf76020ce2ed0cf06f1105e06c34534a35ed8247fca0cb57e2d53269771e1'},
 'full':{'commit':'d97d2388e6985e7d28faa3746b91fe54c18aaf60','serverBuildCommit':'ff1efdd9a2598e19b84cc09b91c8bc1e10ab6254','root':FULL,
    'server':'759423e634e25bc2e74067bfaccc16e40720907fc0e717269261dd573f0097df',
    'uvm-ublk-daemon':'5291c267777cd91c4b853c6d40720e8d87200b2a0162024782534c4126cba726',
    'aenv':'b07e0ad826a6080a4481cb42278023732f21d090edf813f5bedd4438a486e1f2'}}

def need(ok,why):
    if not ok:raise ValueError(why)

def read(path,limit):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Input path redirected/outside root')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and before.st_size<=limit,'Input owner/type/size differs')
        data=stream.read(limit+1);after=os.fstat(stream.fileno())
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Input changed during read')
    return data,before

def validate_policy(variant,hashes,config,environment_keys):
    expected=VERSIONS[variant]
    need(all(hashes.get(name)==expected[name] for name in ('server','uvm-ublk-daemon','aenv')),
         'Runtime is not the exact declared build; disabling UB does not make it original')
    need(config['ublk']['daemon_binary_path']==str(expected['root']/'bin/uvm-ublk-daemon'),'Unexpected storage daemon configuration')
    forbidden={'AENV_UB_MEMORY_REPLICAS','AENV_DIRECT_ROOTFS_BINDING','AENV_UB_ROOTFS_REPLICAS'}
    need(not forbidden.intersection(environment_keys),'Unexpected legacy/native UB environment binding')
    snapshot=config.get('snapshot',{})
    if variant=='original':
        need(not any(snapshot.get(k) for k in ('ub_rootfs_index','ub_rootfs_index_sha256','ub_rootfs_demand_manifest')),
             'Original has a UB binding')
    else:
        need(snapshot.get('ub_rootfs_index') and snapshot.get('ub_rootfs_index_sha256')
             and not snapshot.get('ub_rootfs_demand_manifest'),'Full mode requires strict index and no demand pool')

def inspect_runtime(node,variant):
    need(os.geteuid()==0 and platform.node()=={'a':'server1','b':'agent1'}[node],'Inspect on declared node as root')
    expected=VERSIONS[variant];base=expected['root']
    unit=('jwk-aenv-ae9c626-node-' if variant=='original' else 'jwk-aenv-direct-ub-deletefix-v1-node-')+node+'.service'
    def fields():
        result=subprocess.run(['/usr/bin/systemctl','show',unit,'--no-pager',
            '--property=LoadState,ActiveState,MainPID,User,Group,ControlGroup'],capture_output=True,text=True,timeout=15,check=True)
        return dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    before=fields();pid=int(before['MainPID'])
    need(before['ActiveState']=='active' and before['User']==before['Group']=='jwk' and pid>1,'Expected running Runtime missing')
    proc=Path('/proc')/str(pid);ticks=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
    hashes={};identities={}
    for name in ('server','uvm-ublk-daemon','aenv'):
        data,meta=read(base/'bin'/name,128*1024**2)
        hashes[name]=hashlib.sha256(data).hexdigest();identities[name]={'dev':meta.st_dev,'inode':meta.st_ino,'bytes':meta.st_size}
    need(os.readlink(proc/'exe')==str(base/'bin/server'),'Actual Runtime executable path differs')
    meta=os.stat(proc/'exe');need((meta.st_dev,meta.st_ino)==(identities['server']['dev'],identities['server']['inode']), 'Actual running binary inode differs')
    raw,_=read(base/'config/runtime.toml',1024**2);config=tomllib.loads(raw.decode())
    env=(proc/'environ').read_bytes();keys={item.split(b'=',1)[0].decode('ascii','replace') for item in env.split(b'\0') if item}
    validate_policy(variant,hashes,config,keys)
    need(fields()==before and (proc/'stat').read_text().rsplit(')',1)[1].split()[19]==ticks,'Runtime changed during inspection')
    return {'node':node,'variant':variant,'verifiedCommit':expected['commit'],'unit':unit,'pid':pid,'startTicks':ticks,
            'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'serverBuildCommit':expected.get('serverBuildCommit',expected['commit']),'daemonBuildCommit':expected['commit'],'binaries':hashes,'binaryFileIdentities':identities,'configSha256':hashlib.sha256(raw).hexdigest(),
            'cgroup':before['ControlGroup'],'daemonProcessIdentity':None,
            'hashingBinariesMayWarmCodeFileCache':True,'lowerPayloadRead':False,
            'scope':'identity/config only; empty inventory, Guest binding and device queue checks required before replay'}

def input_signature(templates):
    need(len(templates) in (1,4),'Only explicit one-template fallback or complete four-template scope')
    need(len({r['templateId'] for r in templates})==len(templates),'Duplicate templates')
    for row in templates:
        need(all(re.fullmatch('[0-9a-f]{64}',row[k]) for k in ('catalogSha256','replaySha256')),'Missing catalog/replay digest')
        need(row['resources']=={'cpu_count':2,'memory_mib':4096} and row['rootfsLayers'],'Template resources/layers differ')
        for layer in row['rootfsLayers']:
            need(re.fullmatch('sha256:[0-9a-f]{64}',layer['digest']) and type(layer['size']) is int and layer['size']>0,'Invalid lower content identity')
    return [(r['templateId'],r['catalogSha256'],r['replaySha256'],r['resources'],r['rootfsLayers']) for r in templates]

def matching_inputs(original,full,semantics):
    need(input_signature(original)==input_signature(full),'Template/catalog/replay/resource/lower inputs differ')
    need(semantics=={'guestTimeoutSeconds':300,'cliTimeoutSeconds':330,'terminalActionPolicy':'stop_before_submit_finish_done',
                     'nonzeroPolicy':'record_each_and_compare','globalCacheEviction':False},'Replay/timeout/cache semantics differ')
    return {'templates':len(original),'guestsPerNode':len(original)*2,'guestsAcrossTwoNodes':len(original)*4,
            'scope':'four-template' if len(original)==4 else 'one-template-fallback','conditionsMatched':True}

def full_coverage(templates,index,reservation,approved_coverage_bytes):
    need(index['version']==1 and index['state']=='ready','Full index not ready')
    expected={}
    for template in templates:
        for layer in template['rootfsLayers']:
            digest,size=layer['digest'],layer['size']
            need(digest not in expected or expected[digest]==size,'Same digest has different sizes')
            expected[digest]=size
    refs=index['replicas'];actual={r['layerDigest']:r['fileBytes'] for r in refs}
    need(len(actual)==len(refs) and actual==expected,'Shared objects do not exactly cover requested templates')
    need(all(r['allowRepositoryFallback'] is False for r in refs),'Required full mode cannot fall back')
    need(reservation['reportedBackingReservationAvailable'] is True and type(reservation['uniqueReportedReservationBytes']) is int,
         'Actual reported backing reservation missing; payload/mapping size cannot substitute')
    need(type(approved_coverage_bytes) is int and approved_coverage_bytes>0
         and 0<reservation['uniqueReportedReservationBytes']<=approved_coverage_bytes,'Reservation exceeds explicit approved bound')
    need(reservation['retainedDuringOriginal'] is True and reservation['originalBackgroundAccountingIncluded'] is True,
         'Retained UB pool omitted from original background accounting')
    return {'uniqueLayers':len(expected),'payloadBytes':sum(expected.values()),
            'reportedReservationBytes':reservation['uniqueReportedReservationBytes'],'newAllocationAuthorized':False,
            'scope':'coverage and retained-budget check only; caller must hold explicit launch authorization'}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--node',choices=('a','b'),required=True)
    parser.add_argument('--inspect',action='store_true');args=parser.parse_args()
    if not args.inspect:print(json.dumps({'status':'PLAN_ONLY','mutations':False}));return
    reports=[inspect_runtime(args.node,variant) for variant in ('original','full')]
    print(json.dumps({'status':'ORIGINAL_AND_FULL_IDENTITIES_INSPECTED_NOT_RUN','reports':reports,
                      'cohortStarted':False,'SDKCalled':False},indent=2))

if __name__=='__main__':main()
