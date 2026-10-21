"""Two user-started standalone Guests sharing one UB lower, with causal overlap proof.
Prepare on each node, paste its root block, then observe from A using ordinary SSH.
No existing services, active UB owner, old evidence or host permissions are changed.
"""
import argparse,copy,hashlib,json,os,runpy,shlex,socket,stat,subprocess,sys,time,uuid
from pathlib import Path
ROOT=Path('/home/jwk/agent')
SELF=ROOT/'native_pair_v1.py'
PINS={'node-a':('A_futex265_policy_guest_v5.py','d88bdc1f2578bb5f367030e1ca7352c098016a223f6259aff2399168d067563b'),
      'node-b':('B_native_dax_guest_v4.py','ddbe0102021c03cc71c74aa6dec263928c8cc4021f9c931886d8e713216a1ef5')}
INIT=r'''#!/agentenv/bin/busybox sh
BB=/agentenv/bin/busybox
die() { echo "AENV_PAIR_FAIL $1"; $BB poweroff -f; while :; do $BB sleep 30; done; }
$BB mkdir -p /proc /sys /dev /mnt/ro0 /mnt/write /mnt/user || die mkdir
$BB mount -n -t proc proc /proc || die proc
$BB mount -n -t sysfs sysfs /sys || die sys
if ! $BB awk '$2=="/dev" && $3=="devtmpfs" {f=1} END {exit !f}' /proc/mounts; then
 $BB mount -n -t devtmpfs devtmpfs /dev || die dev
fi
NODE=
for arg in $($BB cat /proc/cmdline); do
 case "$arg" in aenv_pair_node=*) [ -z "$NODE" ] || die duplicate_node; NODE="${arg#aenv_pair_node=}";; esac
done
case "$NODE" in node-a|node-b) ;; *) die node;; esac
PMEM_COUNT=1
PMEM_FSTYPE=ext4
. /agentenv/pmem-rootfs
BASE_SHA=6ed4c221615a18a3f586110b10493d1889ef75f760f8eb939b69e44d20f49158
COMMON_SHA=52e5e039997ae5162da02a824fdd3839d16fdb9293ceccb5e6ce784fd9fc3bfd
/agentenv/dax-check /mnt/user/common-data.bin || die common_dax
BEFORE=$($BB sha256sum /mnt/ro0/.aenv-dax-probe)
[ "${BEFORE%% *}" = "$BASE_SHA" ] || die original_base
printf '%s\n' "$NODE-private" > /mnt/user/.aenv-dax-probe || die private_write
check() {
 [ "$($BB cat /mnt/user/.aenv-dax-probe)" = "$NODE-private" ] || die private_changed
 BASE=$($BB sha256sum /mnt/ro0/.aenv-dax-probe)
 [ "${BASE%% *}" = "$BASE_SHA" ] || die lower_changed
 COMMON=$($BB sha256sum /mnt/user/common-data.bin)
 [ "${COMMON%% *}" = "$COMMON_SHA" ] || die common_changed
}
check
echo "AENV_PAIR_READY $NODE"
COUNT=0
while [ "$COUNT" -lt 60 ]; do
 check
 echo "AENV_PAIR_ALIVE $NODE $COUNT"
 $BB sleep 5
 COUNT=$((COUNT+1))
done
check
echo "AENV_DAX_SELFTEST_BASE $BASE_SHA  /mnt/ro0/.aenv-dax-probe"
echo 'AENV_DAX_SELFTEST_PASS pmem_count=1 lower_unchanged=1 private_copyup=1'
echo "AENV_PAIR_DONE $NODE"
$BB sync
$BB poweroff -f
while :; do $BB sleep 30; done
'''

def need(value,reason):
    if not value:raise RuntimeError(reason)

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda:stream.read(1024**2),b''):h.update(part)
    return h.hexdigest()

def read(path,limit=2*1024**2):
    path=Path(path);need(path.resolve(strict=True)==path,'Redirected input')
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode) and before.st_uid==1204 and before.st_size<=limit,'Input identity/size differs')
        data=stream.read(limit+1);after=os.fstat(stream.fileno())
    need((before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns) and len(data)==before.st_size,'Input changed')
    return data

def save(path,value):
    path=Path(path);temp=path.with_name(path.name+'.new')
    with temp.open('x') as stream:json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
    os.replace(temp,path)

def paths(node):
    base=ROOT/('r/pm-a-v1' if node=='node-a' else 'r/pm-b-v1')
    return base,base/'pair-v1'

def account(node):
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary jwk process')
    need(os.uname().nodename==('server1' if node=='node-a' else 'agent1') and os.uname().machine=='aarch64','Wrong node')

def dependency(node):
    name,pin=PINS[node];path=ROOT/name
    need(hashlib.sha256(read(path,256*1024)).hexdigest()==pin,'Prior reviewed runner changed')
    return runpy.run_path(str(path))

def launcher_text(source,node):
    source=source.replace('native-pmem-guest-futex-v5','native-pmem-pair-'+node).replace('native-pmem-guest-node-b-v1','native-pmem-pair-'+node)
    old='init=/init aenv_pmem_rootfs=1 aenv_pmem_fstype=ext4 aenv_dax_selftest=1'
    need(source.count(old)==1,'Expected reviewed Guest command line')
    source=source.replace(old,'init=/agentenv/pair-init.sh aenv_pmem_rootfs=1 aenv_pmem_fstype=ext4 aenv_pair_node='+node)
    source=source.replace("<= 120, 'Timeout exceeds 120s'","<= 400, 'Timeout exceeds 400s'")
    # Keep the exact lifecycle and lease handling; only permit the longer hold.
    need("<= 400, 'Timeout exceeds 400s'" in source,'Timeout patch differs')
    return source

def prepare(node):
    account(node);base,stage=paths(node)
    need(not stage.exists() and not stage.is_symlink(),'Existing pair stage preserved; do not prepare again')
    dep=dependency(node)
    if node=='node-a':
        gate=json.loads(read(base/'guest-futex-v5/return.json'))
        config=json.loads(read(base/'native-session/futex-v5/guest-config.json'))
        need(gate.get('guestDaxSelftestPassed') is True and gate.get('firecrackerExit')==0 and gate.get('safeToRetireThisLease') is True,'A completed pass required')
        text=dep['PAYLOAD']['native_pmem_guest_policy_trace.py']
        config.pop('traceRunner',None)
    else:
        gate=json.loads(read(base/'native-guest-v4/return.json'))
        need(gate.get('status')=='B_SHARED_BASE_DAX_GUEST_PASSED_AND_RELEASED' and gate.get('mappingsReleased') is True and gate.get('guestDaxSelftestPassed') is True,'B completed pass/release required')
        config=dep['guest_config'](dep['manifest']())
        config['providerSpec']['socket']=str(stage/'provider/data.sock')
        text=dep['GUEST_LAUNCHER']
    need(gate.get('guest',gate)['providerSpec']['sha256']==config['providerSpec']['sha256'],'Prior tested content differs')
    for key in ('firecracker','kernel','tools','upper','seccompFilter'):
        need(sha(config[key]['path'])==config[key]['sha256'],'Pinned input changed: '+key)
    debug=ROOT/'deployments/agentenv-ub-b019f27/native/bin/debugfs'
    need(sha(debug)=='bc53991ef4ee2d20a8c27b7aeed2e2c59cb40d5291292d1742ee01bd4ca50707','debugfs changed')
    import shutil
    need(shutil.disk_usage(base).free>=2*1024**3,'Need 2GiB free disk')
    os.umask(0o077);stage.mkdir(mode=0o700)
    with (stage/'pair-init.sh').open('x') as stream:stream.write(INIT)
    tools=stage/'tools-pair.ext4';shutil.copyfile(config['tools']['path'],tools)
    need(sha(tools)==config['tools']['sha256'],'Private tools copy differs')
    env=dict(os.environ);env.pop('LD_PRELOAD',None);env.pop('LD_AUDIT',None)
    native=ROOT/'deployments/agentenv-ub-b019f27/native'
    env['LD_LIBRARY_PATH']=str(native/'lib')+os.pathsep+str(native/'fallback/lib')
    commands=['write '+str(stage/'pair-init.sh')+' /agentenv/pair-init.sh',
              'set_inode_field /agentenv/pair-init.sh mode 0100755',
              'set_inode_field /agentenv/pair-init.sh uid 0','set_inode_field /agentenv/pair-init.sh gid 0',
              'dump /agentenv/pair-init.sh '+str(stage/'verified-init.sh')]
    for i,command in enumerate(commands):
        with (stage/('debugfs-'+str(i)+'.log')).open('xb') as log:
            result=subprocess.run([str(debug),'-w','-R',command,str(tools)],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=30)
        need(result.returncode==0,'Private tools preparation failed; preserve logs')
    need(sha(stage/'verified-init.sh')==sha(stage/'pair-init.sh'),'Guest init extraction differs')
    config['tools']={'path':str(tools),'sha256':sha(tools),'bytes':tools.stat().st_size};config['timeoutSecs']=360
    (stage/'launcher.py').write_text(launcher_text(text,node))
    save(stage/'guest-config.json',config)
    receipt={'node':node,'configSha256':sha(stage/'guest-config.json'),'launcherSha256':sha(stage/'launcher.py'),
             'selfSha256':sha(SELF),'providerIdentity':config['providerSpec'],'holdSeconds':300,'SDK_called':False,'Guest_created':False}
    save(stage/'prepared.json',receipt)
    block=root_block(node,receipt)
    (stage/'root-review.txt').write_text(block)
    print('BEGIN_PAIR_REVIEWED_ROOT\n'+block+'END_PAIR_REVIEWED_ROOT',flush=True)

def root_block(node,receipt):
    _,stage=paths(node)
    values={'HOST':'server1' if node=='node-a' else 'agent1','NODE':node,'UNIT':'jwk-native-pair-'+node+'-v1.service',
        'SCRIPT':str(SELF),'SCRIPT_SHA':receipt['selfSha256'],'STAGE':str(stage),
        'PINS':{'guest-config.json':receipt['configSha256'],'launcher.py':receipt['launcherSha256']}}
    body=r'''import hashlib,os,socket,stat,subprocess
from pathlib import Path
assert os.geteuid()==0 and socket.gethostname()==HOST
assert subprocess.check_output(['/usr/bin/id','-u','jwk'],text=True).strip()=='1204'
assert subprocess.check_output(['/usr/bin/id','-g','jwk'],text=True).strip()=='1205'
assert subprocess.check_output(['/usr/bin/getent','group','kvm'],text=True).split(':')[2]=='36'
if NODE=='node-b':assert subprocess.check_output(['/usr/bin/getent','group','ubsmd'],text=True).split(':')[2]=='984'
assert subprocess.check_output(['/usr/bin/systemctl','show',UNIT,'--property=LoadState','--value'],text=True).strip()=='not-found'
items={SCRIPT:SCRIPT_SHA,**{str(Path(STAGE)/name):pin for name,pin in PINS.items()}}
for name,pin in items.items():
 p=Path(name);assert p.resolve(strict=True)==p and p.is_relative_to(Path('/home/jwk/agent'))
 with p.open('rb') as stream:
  a=os.fstat(stream.fileno());assert stat.S_ISREG(a.st_mode) and a.st_uid==1204 and a.st_size<256*1024
  data=stream.read(256*1024+1);b=os.fstat(stream.fileno())
 assert (a.st_ino,a.st_size,a.st_mtime_ns)==(b.st_ino,b.st_size,b.st_mtime_ns) and hashlib.sha256(data).hexdigest()==pin
assert not (Path(STAGE)/'guest-result').exists() and not (Path(STAGE)/'provider').exists()
assert Path('/dev/kvm').is_char_device()
command=['/usr/bin/systemd-run','--unit='+UNIT,'--collect','--wait','--pipe',
 '--property=User=jwk','--property=Group=jwk','--property=SupplementaryGroups='+('kvm' if NODE=='node-a' else 'ubsmd kvm'),
 '--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=NoNewPrivileges=yes',
 '--property=Type=exec','--property=Restart=no','--property=KillMode=control-group',
 '--property=TimeoutStopSec=90s','--property=LimitNOFILE=4096','--property=MemoryMax=768M','--property=UMask=0077',
 '/usr/bin/python3','-I','-B',SCRIPT,'--worker',NODE]
result=subprocess.run(command)
print('PAIR_UNIT_EXIT='+str(result.returncode),flush=True)
raise SystemExit(result.returncode)
'''
    return "/usr/bin/python3 -I -B - <<'NATIVE_PAIR_REVIEWED_ROOT'\n"+''.join(k+'='+repr(v)+'\n' for k,v in values.items())+body+'NATIVE_PAIR_REVIEWED_ROOT\n'

def worker(node):
    account(node);base,stage=paths(node);receipt=json.loads(read(stage/'prepared.json'))
    need(sha(SELF)==receipt['selfSha256'] and sha(stage/'launcher.py')==receipt['launcherSha256'] and sha(stage/'guest-config.json')==receipt['configSha256'],'Prepared inputs changed')
    need(not (stage/'guest-result').exists(),'Guest output already exists')
    if node=='node-a':
        return subprocess.run([sys.executable,'-I','-B',str(stage/'launcher.py'),'--config',str(stage/'guest-config.json'),
            '--output',str(stage/'guest-result'),'--run']).returncode
    dep=dependency(node);g=dep['main'].__globals__
    initial=g['previous_failure_proof']
    def prior():
        proof=initial()
        import fcntl
        old=base/'native-guest-v4';report=g['read'](old/'return.json');state=g['read'](old/'provider/owner.json')
        need(report.get('status')=='B_SHARED_BASE_DAX_GUEST_PASSED_AND_RELEASED' and report.get('mappingsReleased') is True
             and report.get('finalizeAcknowledged') is True and state.get('state')=='released','Previous B Guest release incomplete')
        need(report['ownerId']==g['manifest']()['ownerId'] and report['manifestSha256']==g['MANIFEST_SHA'],'Previous B generation differs')
        lock=old/'provider/generation.lock';need(lock.resolve(strict=True)==lock,'Old Guest generation lock redirected')
        fd=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:os.close(fd);raise
        g['OLD_GENERATION_LOCKS'].append(fd)
        proof['priorBGuestEndpoints']=g['check_retired_endpoints'](old/'provider')
        proof['priorBGuestReleased']=True
        return proof
    # The importer requires its session not to exist. Keep its SDK session
    # separate from this already prepared launcher/tools directory.
    session=stage/'import-session'
    g.update(SESSION=session,WORK=stage/'provider',PENDING=ROOT/'relay/native-pmem-node-b-pair-v1.pending.json',previous_failure_proof=prior)
    def prepared(owner):
        config=json.loads(read(stage/'guest-config.json'))
        need({k:v for k,v in config['providerSpec'].items() if k!='socket'}==owner['replicas'][0]['identity'],'Prepared Guest generation differs')
        need(config['providerSpec']['socket']==str(stage/'provider/data.sock'),'Prepared provider path differs')
        need(os.access('/dev/kvm',os.R_OK|os.W_OK),'KVM access missing')
    def run_guest():
        with (stage/'launcher.log').open('xb') as log:
            process=subprocess.Popen([sys.executable,'-I','-B',str(stage/'launcher.py'),'--config',str(stage/'guest-config.json'),
                '--output',str(stage/'guest-result'),'--run'],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=process.wait(timeout=390)
            except subprocess.TimeoutExpired:return {'safeToRetireThisLease':False,'launcherPid':process.pid,'reason':'Keep provider: Guest unresolved'}
        result=stage/'guest-result/return.json'
        if not result.exists():return {'safeToRetireThisLease':False,'launcherExit':code,'reason':'Keep provider: Guest report absent'}
        value=json.loads(read(result));value['launcherExit']=code
        return value
    g.update(prepare_guest=prepared,run_guest_after_import=run_guest)
    sys.argv=['reviewed-importer','--run']
    return dep['main']()

def proc_ticks(pid):return Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]

def sample(node,nonce):
    account(node);_,stage=paths(node);path=stage/'guest-result/return.json'
    result={'node':node,'nonce':nonce,'live':False}
    if not path.exists():return result
    state=json.loads(read(path));config=json.loads(read(stage/'guest-config.json'));pid=state.get('firecrackerPid')
    result['providerSpec']=state.get('providerSpec');result['pid']=pid
    if state.get('state')!='owned_firecracker_running' or type(pid) is not int:return result
    try:
        ticks=proc_ticks(pid);proc=Path('/proc')/str(pid)
        need(proc.stat().st_uid==1204 and (proc/'exe').resolve(strict=True)==Path(config['firecracker']['path']),'Selected process identity differs')
        argv=(proc/'cmdline').read_bytes().split(b'\0')
        need(str(stage/'guest-result/firecracker.json').encode() in argv,'Selected process uses another configuration')
        log=stage/'guest-result/serial.stdout.log'
        meta=log.stat();need(meta.st_size<=16*1024**2,'Oversized Guest log')
        with log.open('rb') as stream:stream.seek(max(0,meta.st_size-32768));text=stream.read(32768).decode(errors='replace')
        need('AENV_PAIR_FAIL' not in text and 'AENV_PAIR_DONE' not in text,'Guest reported failure/completion')
        lines=[line.strip() for line in text.splitlines() if line.startswith('AENV_PAIR_ALIVE '+node+' ')]
        need(lines and time.time_ns()-meta.st_mtime_ns<20*10**9,'No recent Guest heartbeat')
        need(proc_ticks(pid)==ticks,'FC identity changed during observation')
        result.update(live=True,startTicks=ticks,heartbeat=int(lines[-1].split()[-1]),guestPrivateMarker=node+'-private')
    except (OSError,RuntimeError,ValueError) as error:result['reason']=str(error)[:200]
    return result

def collect(node):
    account(node);_,stage=paths(node);path=stage/'guest-result/return.json'
    if not path.exists():return {'node':node,'complete':False}
    guest=json.loads(read(path));passed=guest.get('guestDaxSelftestPassed') is True and guest.get('firecrackerExit')==0 and guest.get('safeToRetireThisLease') is True
    result={'node':node,'complete':guest.get('firecrackerReaped') is True,'passed':passed,'guest':guest}
    if node=='node-b':
        receipt=stage/'import-session/return.json'
        if not receipt.exists():result.update(complete=False,passed=False);return result
        outer=json.loads(read(receipt));result['importRelease']={k:outer.get(k) for k in ('status','ownerId','manifestSha256','mappingsReleased','finalizeAcknowledged','allocationCalls','deallocationCalls')}
        result['passed']=passed and outer.get('status')=='B_SHARED_BASE_DAX_GUEST_PASSED_AND_RELEASED'
    return result

def remote(action,nonce=''):
    args=['python3','-I','-B',str(SELF),action,'node-b']
    if nonce:args+=['--nonce',nonce]
    result=subprocess.run(['ssh','-T','-o','ConnectTimeout=10','jwk@agent1',shlex.join(args)],capture_output=True,text=True,timeout=25)
    need(result.returncode==0,'B SSH observation failed: '+result.stderr[-500:])
    need(len(result.stdout)<=128*1024,'Oversized B observation')
    return json.loads(result.stdout)

def overlap(a,b,after,nonce):
    need(all(x.get('live') is True for x in (a,b,after)),'Both Guest windows must be live')
    need(b.get('nonce')==nonce,'B observation challenge differs')
    need(a.get('pid')==after.get('pid') and a.get('startTicks')==after.get('startTicks'),'A process changed around B observation')
    identity=lambda x:{k:v for k,v in x['providerSpec'].items() if k!='socket'}
    need(identity(a)==identity(b)==identity(after),'Different base/generation in overlap')
    need(a['guestPrivateMarker']=='node-a-private' and b['guestPrivateMarker']=='node-b-private','Private markers differ')
    return {'accepted':True,'method':'A live before -> fresh B live response -> same A process still live; no cross-node clock comparison',
        'A_before':a,'B_between':b,'A_after':after}

def observe():
    account('node-a');_,stage=paths('node-a');out=stage/'paired-observation.json'
    need(not out.exists(),'Existing paired observation preserved')
    report={'status':'OBSERVING','simultaneousRootfsMechanismAccepted':False,'memfilePrivateCowAccepted':False,'globalNetPhysicalSavingsAccepted':False}
    try:
        ready_deadline=time.monotonic()+90
        while True:
            nonce=uuid.uuid4().hex;a=sample('node-a',nonce)
            if a.get('live'):
                b=remote('--sample',nonce);after=sample('node-a',nonce)
                if b.get('live') and after.get('live'):break
            need(time.monotonic()<ready_deadline,'No simultaneous live window within 90 seconds')
            time.sleep(3)
        report['overlap']=overlap(a,b,after,nonce);save(out,report)
        print('PAIR_OVERLAP_OBSERVED_WAITING_FOR_NORMAL_EXIT',flush=True)
        deadline=time.monotonic()+420
        while time.monotonic()<deadline:
            ar=collect('node-a')
            if ar.get('complete'):
                br=remote('--collect')
                if br.get('complete'):break
            time.sleep(10)
        else:raise RuntimeError('Completion not yet confirmed; preserve both providers and evidence')
        need(ar.get('passed') and br.get('passed'),'One Guest or B release failed')
        for row,observed in ((ar,a),(br,b)):
            need(row['guest']['firecrackerPid']==observed['pid'],'Completed Guest differs from observed Guest')
        report.update(status='TWO_NODE_ROOTFS_OVERLAP_AND_PRIVATE_COPYUP_PASSED',simultaneousRootfsMechanismAccepted=True,A=ar,B=br)
    except Exception as error:report.update(status='PAIR_NOT_ACCEPTED_REVIEW_EVIDENCE',reason=str(error)[:1000])
    save(out,report);print('BEGIN_TWO_NODE_ROOTFS_REPORT\n'+json.dumps(report,indent=2)+'\nEND_TWO_NODE_ROOTFS_REPORT',flush=True)
    return 0 if report['simultaneousRootfsMechanismAccepted'] else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group(required=True)
    for action in ('prepare','worker','sample','collect'):group.add_argument('--'+action,choices=('node-a','node-b'))
    group.add_argument('--observe',action='store_true');parser.add_argument('--nonce',default='')
    args=parser.parse_args()
    if args.prepare:prepare(args.prepare);return 0
    if args.worker:return worker(args.worker)
    if args.sample:print(json.dumps(sample(args.sample,args.nonce)));return 0
    if args.collect:print(json.dumps(collect(args.collect)));return 0
    return observe()

if __name__=='__main__':raise SystemExit(main())
