import argparse,base64,concurrent.futures,hashlib,importlib.util,json,os,re,shlex,signal,socket,stat,subprocess,sys,time,uuid,zlib
from pathlib import Path


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def safe(path, existing=True):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve(strict=existing) == path,
         'Redirected or out-of-workspace path')
    if path.exists():
        need(path.stat().st_uid == 1204, 'Unexpected path owner')
    return path

def read(path, limit=2 * 1024**2):
    path = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204 and 0 <= meta.st_size <= limit, 'Unexpected input file')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    need(len(data) == meta.st_size and (meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Input changed')
    return data

def load(path):
    return json.loads(read(path))

def sha(path):
    path = safe(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 64 * 1024**3 + 128 * 1024**2, 'File exceeds transfer budget')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    need((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Transfer source changed')
    return digest

def save(path, value):
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('xb') as stream:
        stream.write((json.dumps(value, indent=2) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)

def ordinary(node):
    need(sys.version_info >= (3, 11) and os.name == 'posix' and os.getuid() == os.geteuid() == 1204
         and os.getgid() == os.getegid() == 1205 and os.uname().machine == 'aarch64'
         and socket.gethostname() == ('server1' if node == 'node-a' else 'agent1'),
         'Use the declared ordinary ARM64 node user')
    caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(caps[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), 'Capability-free coordinator required')
    os.umask(0o077)

def remote_command(arguments):
    need(SCENARIO=='dual-ab','Single-node entry never contacts B')
    return SSH + [shlex.join([PYTHON, '-I', '-B', str(SELF), *arguments, '--scenario', SCENARIO, '--run'])]

def transport_readiness():
    need(SCENARIO=='dual-ab','Single-node entry never contacts B')
    # This is executed only by the user-run A entry, before any build/journal or
    # B filesystem preparation. No connectivity was established during authoring.
    code = ("import os,socket,sys; assert sys.version_info>=(3,11) and sys.platform=='linux'; "
            "assert os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205; "
            "assert socket.gethostname()=='agent1' and os.uname().machine=='aarch64'; "
            "print('B_COORDINATOR_TRANSPORT_READY')")
    result = subprocess.run(SSH + [shlex.join([PYTHON, '-I', '-B', '-c', code])],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    need(result.returncode == 0 and result.stdout.strip() == b'B_COORDINATOR_TRANSPORT_READY',
         'Existing authenticated A-to-B SSH/Python prerequisite unavailable; no build, SDK or service change attempted')

def transfer(path, destination):
    need(SCENARIO=='dual-ab','Single-node entry never contacts B')
    """Create one pinned B file via SSH stdin; no shell data interpolation."""
    path, destination = safe(path), Path(destination)
    need(destination.parent in (ROOT, WORK, HELPERS, WORK/'new-build', WORK/'new-build/artifacts') and destination.name not in ('', '.', '..'), 'Transfer destination outside rollout')
    size, digest = path.stat().st_size, sha(path)
    script = r'''import hashlib,os,socket,stat,sys
from pathlib import Path
p=Path(DEST)
assert os.getuid()==os.geteuid()==1204 and socket.gethostname()=='agent1'
assert p.parent in [Path(x) for x in PARENTS]
assert p.parent.resolve(strict=True)==p.parent and p.parent.stat().st_uid==1204
assert not p.is_symlink(),'Redirected transfer destination preserved'
if p.exists():
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as old:
  meta=os.fstat(old.fileno());assert stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1 and meta.st_size==SIZE
  assert hashlib.file_digest(old,'sha256').hexdigest()==SHA,'Existing transfer destination differs'
 h=hashlib.sha256();remaining=SIZE
 while remaining:
  part=sys.stdin.buffer.read(min(1048576,remaining));assert part
  h.update(part);remaining-=len(part)
 assert not sys.stdin.buffer.read(1) and h.hexdigest()==SHA
 print('PINNED_TRANSFER_COMPLETE');raise SystemExit(0)
os.umask(0o077)
partial=p.with_name(p.name+'.partial')
h=hashlib.sha256();remaining=SIZE
with partial.open('xb') as out:
 while remaining:
  block=sys.stdin.buffer.read(min(1048576,remaining));assert block,'Truncated transfer'
  h.update(block);out.write(block);remaining-=len(block)
 assert not sys.stdin.buffer.read(1),'Excess transfer input'
 out.flush();os.fsync(out.fileno())
assert h.hexdigest()==SHA,'Transferred hash differs; partial retained'
assert not p.exists() and not p.is_symlink()
os.link(partial,p)
partial.unlink()
print('PINNED_TRANSFER_COMPLETE')
'''
    source = 'PARENTS='+repr([str(p) for p in (ROOT,WORK,HELPERS,WORK/'new-build',WORK/'new-build/artifacts')])+'\nDEST=' + repr(str(destination)) + '\nSIZE=' + str(size) + '\nSHA=' + repr(digest) + '\n' + script
    # Remote code is literal and arguments are shell-quoted. File bytes travel
    # solely through stdin and are never evaluated as command text.
    with path.open('rb') as stream:
        result = subprocess.run(SSH + [shlex.join([PYTHON, '-I', '-B', '-c', source])],
                                stdin=stream, capture_output=True, timeout=1800)
    need(result.returncode == 0 and b'PINNED_TRANSFER_COMPLETE' in result.stdout,
         'Pinned transfer failed; preserve target partial and stage journal')
    return digest

class Steps:
    def __init__(self, node):
        self.node = node
        WORK.mkdir(mode=0o700, exist_ok=True)
        safe(WORK)
        (WORK / 'logs').mkdir(mode=0o700, exist_ok=True)
        self.path = WORK / ('steps-' + node + '.json')
        need(not self.path.exists(), 'Existing rollout journal preserved; do not restart from the beginning')
        self.state = {'revision': 'native-archive-round-v1', 'scenario':SCENARIO, 'node': node, 'steps': [], 'status': 'PREPARING',
                      'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        save(self.path, self.state)

    def call(self, name, command, timeout=600, allow_failure=False):
        need(re.fullmatch('[a-z0-9-]+', name), 'Invalid phase name')
        need(not any(row['name']==name for row in self.state['steps']),'Prior phase preserved; no implicit replay')
        row = {'name': name, 'state': 'running', 'startNs': time.time_ns()}
        self.state['steps'].append(row)
        save(self.path, self.state)
        log = WORK / 'logs' / (name + '.log')
        print('PHASE=' + name, flush=True)
        with log.open('xb') as stream:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT)
            start = last = time.monotonic()
            try:
                while child.poll() is None:
                    now = time.monotonic()
                    if now - last >= 30:
                        print('PROGRESS phase=' + name + ' elapsed_s=' + str(int(now - start)), flush=True)
                        last = now
                    if now - start > timeout:
                        child.terminate()
                        try:
                            child.wait(20)
                        except subprocess.TimeoutExpired:
                            # Only this owned launcher is reaped; remote/API
                            # side effects remain explicitly uncertain.
                            child.kill()
                            child.wait()
                        raise RuntimeError('Phase timed out; remote/API outcome may remain pending: ' + name)
                    time.sleep(1)
            except BaseException:
                if child.poll() is None:
                    child.terminate()
                try: child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=10)
                row.update(state='interrupted_outcome_uncertain',finishNs=time.time_ns(),log=str(log))
                save(self.path,self.state)
                raise
        row.update(state='completed', exitCode=child.returncode, finishNs=time.time_ns(), log=str(log))
        save(self.path, self.state)
        need(child.returncode == 0 or allow_failure, 'Phase failed; inspect full log and preserved journal: ' + name)
        return log, child.returncode

    def local(self, name, file, args=(), timeout=600, allow_failure=False):
        need(file in PINS and sha(HELPERS / file) == PINS[file], 'Public executable changed')
        return self.call(name, [PYTHON, '-I', '-B', str(HELPERS / file), *map(str, args)], timeout, allow_failure)

SSH = ['/usr/bin/ssh', '-F', '/dev/null', '-i', '/home/jwk/.ssh/agentenv-native-four/id_ed25519',
       '-oIdentitiesOnly=yes', '-oIdentityAgent=none', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
       '-oUserKnownHostsFile=/home/jwk/.ssh/agentenv-native-four/known_hosts',
       '-oGlobalKnownHostsFile=/dev/null', '-oUpdateHostKeys=no', '-oHostKeyAlgorithms=ssh-ed25519',
       '-oForwardAgent=no', '-oClearAllForwardings=yes', '-oRequestTTY=no',
       '-oConnectTimeout=10', '-oServerAliveInterval=15', '-oServerAliveCountMax=4', 'jwk@agent1']


ROOT=Path('/home/jwk/agent')
PYTHON='/usr/bin/python3'
SELF=ROOT/'native_archive_round.py'
PAYLOAD={}
PINS={}

def scenario_paths(scenario):
    global SCENARIO,WORK,DEPLOYMENT,HELPERS,PROVIDER_SOURCE,COHORT,PROVIDER_PLAN
    need(scenario in ('single-a','dual-ab'),'Explicit native scenario required')
    SCENARIO=scenario
    prefix='native-archive-single' if scenario=='single-a' else 'native-archive'
    WORK=ROOT/'r'/(prefix+'-rollout-v1')
    DEPLOYMENT=ROOT/'deployments'/(prefix+'-v1')
    HELPERS=WORK/'tools'
    PROVIDER_SOURCE=ROOT/(prefix+'-provider-source')
    COHORT=ROOT/(prefix+'-cohort')
    PROVIDER_PLAN=WORK/'provider-plan'

def install_tools():
    global PINS
    rows={**PAYLOAD['common'],**PAYLOAD['variants'][SCENARIO]}
    need(not HELPERS.exists() and HELPERS.parent.resolve(strict=True)==WORK,'Existing helper stage preserved')
    values={}
    for name,row in rows.items():
        need(re.fullmatch(r'[A-Za-z0-9_]+\.py',name),'Invalid bundled helper name')
        data=zlib.decompress(base64.b64decode(row['data'],validate=True))
        need(len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'Bundled source differs')
        values[name]=data
    HELPERS.mkdir(mode=0o700)
    for name,data in values.items():
        with (HELPERS/name).open('xb') as out:out.write(data);out.flush();os.fsync(out.fileno())
    PINS={name:row['sha256'] for name,row in rows.items()}
    save(HELPERS/'manifest.json',{'scenario':SCENARIO,'files':PINS})

def checked_module(name):
    path=HELPERS/(name+'.py');need(sha(path)==PINS[path.name],'Helper changed')
    spec=importlib.util.spec_from_file_location('native_round_'+name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def hydrate_tools():
    global PINS
    rows={**PAYLOAD['common'],**PAYLOAD['variants'][SCENARIO]}
    PINS={name:row['sha256'] for name,row in rows.items()}
    need(load(HELPERS/'manifest.json')=={'scenario':SCENARIO,'files':PINS},'Helper manifest differs')
    for name,pin in PINS.items():need(sha(HELPERS/name)==pin,'Existing helper differs')
