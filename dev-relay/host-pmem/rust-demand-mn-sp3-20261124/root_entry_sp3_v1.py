"""Manual M/N root task entry. New tasks arrive only through the private queue."""
import argparse,base64,fcntl,hashlib,json,os,platform,re,stat,subprocess,sys,time,types,zlib
from pathlib import Path
ROOT=Path('/home/jwk/root');STATE=ROOT/'relay-sp3-20261124'
SESSION='rust-demand-mn-sp3-20261124-01'
CONTROL='LittleFish-15/AgentENV-relay-control';RESULTS='LittleFish-15/AgentENV-relay-results'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def identity():
    return {'hostname':platform.node(),'machineId':Path('/etc/machine-id').read_text().strip(),
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'architecture':platform.machine()}
def child_environment(parent):
    result={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    # Preserve transport configuration, never copy PATs/API keys into the child
    # environment. Approved tasks continue reading existing credential files.
    for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy',
                'SSL_CERT_FILE','SSL_CERT_DIR','REQUESTS_CA_BUNDLE'):
        if key in parent:result[key]=parent[key]
    return result
def read(path,limit=512*1024,owner=0):
    need(path.resolve()==path and not path.is_symlink(),'Redirected local input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid==owner and st.st_size<=limit,'Local file owner/type/size differs')
        data=f.read(limit+1);need(len(data)<=limit,'Input exceeds bound');return data
def save(path,value):
    raw=wire(value);tmp=path.with_name(path.name+'.next')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def mkdir(path,mode=0o700):
    need(path.parent.resolve()==path.parent and not path.is_symlink(),'Redirected state directory')
    if not path.exists():path.mkdir(mode=mode)
    st=path.stat();need(st.st_uid==0 and stat.S_ISDIR(st.st_mode) and not st.st_mode&0o022,'Untrusted root state directory')
def fetch(client,path):
    code,raw,_=client.contents(CONTROL,path,'main');need(code==200,'Private task document unavailable');return json.loads(raw)
def put(client,path,raw):
    for attempt in range(5):
        try:client.immutable_result(RESULTS,1438089386,'main',path,raw);return
        except API.Network as error:
            if error.status not in (0,409,422) or attempt==4:raise
            time.sleep(2+attempt)
def validate(job,current,node,pin):
    need(job['schema']==1 and job['sessionId']==SESSION and job['node']==node and job['identity']==current,'Task node/boot differs')
    need(re.fullmatch('[a-z0-9-]{1,96}',job['jobId']) and job['rootEntrySha256']==pin,'Task entry binding differs')
    need(job['humanApproved'] is True and job['scope'] in ('read-only-diagnosis','approved-root-operation'),'Task has no explicit authorization')
    need(API.timestamp(job['notBefore'])<=time.time()<API.timestamp(job['expiresAt']),'Task authorization expired')
    entry=job['entry'];worker_address(entry)
    need(all(re.fullmatch('[0-9a-f]{40}',entry[k]) for k in ('commit','blob')) and re.fullmatch('[0-9a-f]{64}',entry['sha256'])
        and type(entry['bytes']) is int and 0<entry['bytes']<=256*1024,'Invalid task source descriptor')
    need(type(job['seconds']) is int and 1<=job['seconds']<=10800 and isinstance(job['argv'],list) and len(job['argv'])<=16
        and all(isinstance(x,str) and len(x)<=512 for x in job['argv']),'Invalid bounded Python invocation')
def publish_report(client,node,job,report):
    raw=wire(report);compressed=zlib.compress(raw,9);chunks=[];digest=sha(compressed)
    need(len(raw)<=2*1024**2 and len(compressed)<=2*1024**2,'Task report exceeds bound')
    for i,start in enumerate(range(0,len(compressed),16384)):
        piece=compressed[start:start+16384];path=f'root-results-v1/{SESSION}/{node}/{job["jobId"]}/chunks/{digest}/{i}.json'
        put(client,path,wire({'sha256':sha(piece),'dataBase64':base64.b64encode(piece).decode()}));chunks.append({'path':path,'sha256':sha(piece),'bytes':len(piece)})
    manifest={'schema':1,'node':node,'sessionId':SESSION,'jobId':job['jobId'],'identity':report['identity'],
        'jobSha256':sha(wire(job)),'entrySha256':job['entry']['sha256'],'exitCode':report.get('exitCode'),
        'state':report['state'],'compressedSha256':digest,'rawSha256':sha(raw),'rawBytes':len(raw),'chunks':chunks}
    put(client,f'root-results-v1/{SESSION}/{node}/{job["jobId"]}/result.json',wire(manifest))
def run_task(control,results,node,current,pin):
    queue=fetch(control,f'root-entry-v1/{SESSION}/queues/{node}.json')
    need(queue['node']==node and queue['sessionId']==SESSION and queue['mode']=='manual','Queue identity/mode differs')
    if queue.get('stop') or not queue.get('jobIds'):print('ROOT_QUEUE_EMPTY_NO_ACTION');return
    need(len(queue['jobIds'])<=4 and len(set(queue['jobIds']))==len(queue['jobIds']),'Invalid queue bounds')
    for job_id in queue['jobIds']:
        need(re.fullmatch('[a-z0-9-]{1,96}',job_id),'Invalid queued task name')
        job=fetch(control,f'root-entry-v1/{SESSION}/jobs/{job_id}.json')
        need(job['jobId']==job_id,'Queue/task differs')
        directory=STATE/'jobs'/job_id;mkdir(directory)
        result_path=directory/'report.json';state_path=directory/'state.json'
        if result_path.exists():
            report=json.loads(read(result_path,2*1024**2));need(report['jobSha256']==sha(wire(job)),'Completed task descriptor changed')
            publish_report(results,node,job,report);print('ROOT_TASK_ALREADY_DONE_REPORT_RESENT='+job_id);continue
        validate(job,current,node,pin)
        if state_path.exists():
            report={'state':'unknown_after_interruption_no_retry','identity':current,'jobSha256':sha(wire(job)),
                'previousState':json.loads(read(state_path)),'exitCode':None}
            publish_report(results,node,job,report);print('ROOT_TASK_UNKNOWN_NO_RETRY='+job_id);return
        for previous in (STATE/'jobs').glob('*/state.json'):
            if previous==state_path:continue
            prior_report=previous.parent/'report.json'
            unresolved=not prior_report.exists() or json.loads(read(prior_report,2*1024**2)).get('state')!='completed'
            if unresolved and job['scope']!='read-only-diagnosis':
                raise RuntimeError('Unconfirmed earlier root task; only approved diagnosis may proceed')
        entry=job['entry'];raw=fetch_worker(entry)
        need(len(raw)==entry['bytes'] and sha(raw)==entry['sha256']
            and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==entry['blob'],'Pinned Python source differs')
        path=directory/'task.py'
        if path.exists():need(read(path)==raw,'Prior downloaded source differs; preserved')
        else:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        save(state_path,{'state':'running','jobSha256':sha(wire(job)),'identity':current,'startedUnixNs':time.time_ns()})
        print('ROOT_APPROVED_TASK_STARTED='+job_id,flush=True)
        start=time.monotonic();timed_out=False
        with (directory/'stdout.log').open('xb') as out,(directory/'stderr.log').open('xb') as err:
            p=subprocess.Popen(['/usr/bin/python3','-I','-B',str(path),*job['argv']],stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                env=child_environment(os.environ),cwd=directory)
            while p.poll() is None:
                if time.monotonic()-start>job['seconds'] or sum((directory/n).stat().st_size for n in ('stdout.log','stderr.log'))>1024**2:
                    timed_out=True;p.terminate()
                    try:p.wait(timeout=5)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
                    break
                time.sleep(.25)
        logs={}
        for name in ('stdout.log','stderr.log'):
            raw=(directory/name).read_bytes();need(len(raw)<=1024**2,'Local output exceeded safety bound')
            redacted=API.redact(raw,[control.token,results.token]);logs[name]={'text':redacted.decode(errors='replace'),
                'sha256':sha(redacted),'bytes':len(redacted),'redacted':redacted!=raw}
        report={'schema':1,'jobId':job_id,'jobSha256':sha(wire(job)),'identity':current,'exitCode':p.returncode,
            'state':'interrupted_outcome_requires_reconciliation' if timed_out else 'completed','logs':logs,'elapsedSeconds':time.monotonic()-start}
        save(result_path,report);save(state_path,{'state':'executed_upload_pending','exitCode':p.returncode})
        publish_report(results,node,job,report);save(state_path,{'state':'result_uploaded','exitCode':p.returncode})
        print('ROOT_TASK_RESULT_UPLOADED_EXIT='+str(p.returncode),flush=True)
        if p.returncode!=0:return


ADMISSION_SHA256='65dcffa76bf85dfeb8999f00c1267dacc9121fc3947260b8e2b83f8f60d692dc'
ADMISSION_B64='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'

"""Entry main and first enrollment, assembled with the existing private relay."""
import getpass
import grp
import ipaddress
import pwd
import ssl
import tempfile
import urllib.error
import urllib.request
import warnings

ALIASES = ('node-m', 'node-n')
HOST_HOME = ROOT.parent
ENTRY = STATE / 'entry.py'
CREDENTIALS = STATE / 'credentials.json'
ENROLLED = STATE / 'enrollment.json'
INTENT = STATE / 'enrollment-intent.json'
BOOT_LAUNCHER = ROOT / 'root-start.sh'
OLD_STATE = ROOT / 'relay'
OLD_SESSION = 'rust-demand-20261123-01'
OLD_PIN = '63e6c36880f2be5497d729cebb87f6ee4de01f18db9cd263dcd27d05ef483894'
OLD_LAUNCHER = (b'#!/bin/bash\nset -eu\numask 077\n'
                b'exec /usr/bin/python3 -I -B /home/jwk/root/relay/entry.py\n')
LAUNCHER = OLD_LAUNCHER.replace(b'/relay/entry.py', b'/relay-sp3-20261124/entry.py')
SP3_KERNEL = '6.6.0-145.3.34.165.oe2403sp3.aarch64'
HOST_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
JWK_UID = 1204
JWK_GID = 1205
WORKER_PREFIX = 'dev-relay/host-pmem/rust-demand-mn-sp3-20261124/'


def lexists(path):
    return os.path.lexists(path)


def directory(path, owner=0, group=None):
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and path.resolve() == path,
         'Redirected or non-directory path: ' + str(path))
    need(st.st_uid == owner and (group is None or st.st_gid == group)
         and not st.st_mode & 0o022, 'Directory ownership/writability differs: ' + str(path))


def binary(name):
    for folder in HOST_PATH.split(':'):
        path = Path(folder) / name
        if path.is_file() and os.access(path, os.X_OK):
            resolved = path.resolve(strict=True)
            need(resolved.stat().st_uid == 0 and not resolved.stat().st_mode & 0o022,
                 'Untrusted platform command: ' + name)
            return str(resolved)
    raise RuntimeError('Required platform command absent: ' + name)


def local_address(expected, peer):
    expected = str(ipaddress.IPv4Address(expected))
    peer = str(ipaddress.IPv4Address(peer))
    reply = subprocess.run([binary('ip'), '-j', '-4', 'address', 'show'],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=8, check=True, env={'PATH': HOST_PATH, 'LC_ALL': 'C'})
    need(len(reply.stdout) <= 1024 * 1024, 'Local network identity exceeds limits')
    rows = json.loads(reply.stdout)
    addresses = {addr['local'] for row in rows for addr in row.get('addr_info', ())
                 if addr.get('family') == 'inet' and addr.get('local')}
    need(expected in addresses and peer != expected and peer not in addresses,
         'Expected local IPv4 absent or the peer IPv4 is also configured locally')
    return expected, peer


def fresh_file(path, data, mode):
    if lexists(path):
        need(read(path, max(len(data), 1)) == data
             and stat.S_IMODE(path.stat().st_mode) == mode,
             'Existing installation differs and was preserved: ' + str(path))
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_file(path, limit):
    raw = read(path, limit)
    need(stat.S_IMODE(path.stat().st_mode) == 0o600,
         'Root-only file has unexpected permissions: ' + str(path))
    return raw


def named(lookup, key):
    try:
        return lookup(key)
    except KeyError:
        return None


def check_account():
    user = named(pwd.getpwnam, 'jwk')
    same_uid = named(pwd.getpwuid, JWK_UID)
    group = named(grp.getgrnam, 'jwk')
    same_gid = named(grp.getgrgid, JWK_GID)
    if user:
        need((user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell)
             == (JWK_UID, JWK_GID, str(HOST_HOME), '/bin/bash')
             and same_uid is not None and same_uid.pw_name == 'jwk',
             'Existing jwk account differs; preserved')
    else:
        need(same_uid is None, 'UID 1204 is already occupied; no account changed')
    if group:
        need(group.gr_gid == JWK_GID and same_gid is not None and same_gid.gr_name == 'jwk',
             'Existing jwk group differs; preserved')
    else:
        need(same_gid is None, 'GID 1205 is already occupied; no account changed')
    for path in (Path('/'), HOST_HOME.parent):
        directory(path)
    # A user-owned parent would let that user replace root-start.sh by renaming
    # its directory. Preserve existing homes and stop on incompatible ownership.
    for path in (HOST_HOME, ROOT, STATE):
        if lexists(path):
            directory(path)
    for path in (HOST_HOME / 'agent', HOST_HOME / '.ssh'):
        if lexists(path):
            directory(path, JWK_UID, JWK_GID)
    return user, group


def create_account():
    user, group = check_account()
    call = lambda *args: subprocess.run([binary(args[0]), *args[1:]],
                                        stdin=subprocess.DEVNULL, check=True, timeout=20,
                                        env={'PATH': HOST_PATH, 'LC_ALL': 'C'})
    if not group:
        call('groupadd', '--gid', str(JWK_GID), 'jwk')
    if not user:
        call('useradd', '--no-create-home', '--uid', str(JWK_UID), '--gid',
             str(JWK_GID), '--home-dir', str(HOST_HOME), '--shell', '/bin/bash', 'jwk')
    for folder in (HOST_HOME / 'agent', HOST_HOME / '.ssh'):
        if not lexists(folder):
            call('install', '-d', '-m', '0700', '-o', str(JWK_UID), '-g', str(JWK_GID), str(folder))
    user, group = check_account()
    need(user is not None and group is not None, 'Account creation not confirmed')


def credentials(enroll=False, retained=False):
    source = CREDENTIALS
    if not lexists(source) and enroll and retained and lexists(OLD_STATE / 'credentials.json'):
        source = OLD_STATE / 'credentials.json'
    if lexists(source):
        result = json.loads(private_file(source, 8192))
    else:
        need(enroll and sys.stdin.isatty() and sys.stderr.isatty(),
             'First enrollment needs a root terminal with hidden token input')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            result = {
                'controlToken': getpass.getpass('Private control repository read token: '),
                'resultToken': getpass.getpass('Private results repository write token: '),
            }
    need(set(result) == {'controlToken', 'resultToken'}
         and all(isinstance(token, str) and re.fullmatch('[A-Za-z0-9_-]{16,512}', token)
                 for token in result.values())
         and result['controlToken'] != result['resultToken'],
         'Expected separate control-read and result-write tokens')
    return result


def verified_clients(tokens):
    control = API.GitHub(tokens['controlToken'])
    results = API.GitHub(tokens['resultToken'])
    need(API.API == 'https://api.github.com', 'Unexpected GitHub API endpoint')
    # Match the approved Y compatibility mode for these two API clients only.
    # Use the system proxy. Never change the process's default TLS context or
    # task environments, and never reuse this opener for executable sources.
    compat = ssl.create_default_context()
    compat.check_hostname = False
    compat.verify_mode = ssl.CERT_NONE
    for client in (control, results):
        client.opener = urllib.request.build_opener(
            API.NoRedirect(), urllib.request.HTTPSHandler(context=compat))
    control.private_repo(CONTROL, 1438089258)
    results.private_repo(RESULTS, 1438089386)
    return control, results


def worker_address(entry):
    path = entry['path']
    name = path.removeprefix(WORKER_PREFIX)
    need(entry['repo'] == 'LittleFish-15/AgentENV' and path.startswith(WORKER_PREFIX)
         and re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]*\\.py', name)
         and not name.startswith('root_entry'),
         'Task source outside reviewed M/N worker source')
    need(re.fullmatch('[0-9a-f]{40}', entry['commit']), 'Invalid worker source commit')
    return ('https://raw.githubusercontent.com/LittleFish-15/AgentENV/'
            + entry['commit'] + '/' + path)


def fetch_worker(entry):
    need(type(entry['bytes']) is int and 0 < entry['bytes'] <= 256 * 1024,
         'Invalid worker source size')
    url = worker_address(entry)
    # Default HTTPS verification, bounded download, no redirects or tokens.
    opener = urllib.request.build_opener(API.NoRedirect())
    try:
        with opener.open(url, timeout=25) as response:
            need(response.status == 200, 'Pinned worker source returned unexpected status')
            return response.read(entry['bytes'] + 1)
    except (urllib.error.URLError, OSError) as error:
        raise RuntimeError('Pinned worker source unavailable over verified HTTPS') from error


def advisory_lock():
    return lock_state(STATE)


def lock_state(state):
    directory(state)
    fd = os.open(state / 'operation.lock',
                 os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600,
             'Untrusted operation lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def check_retained_entry(node, expected, peer):
    if lexists(BOOT_LAUNCHER):
        raw = read(BOOT_LAUNCHER, 512)
        need(stat.S_IMODE(BOOT_LAUNCHER.stat().st_mode) == 0o700
             and raw in (OLD_LAUNCHER, LAUNCHER), 'Unknown existing root launcher; preserved')
    else:
        raw = None
    if not lexists(OLD_STATE):
        need(raw != OLD_LAUNCHER, 'Existing launcher has no protected state; preserved')
        return False
    directory(OLD_STATE)
    old = json.loads(private_file(OLD_STATE / 'enrollment.json', 192 * 1024))
    need(old.get('node') == node and old.get('sessionId') == OLD_SESSION
         and old.get('entrySha256') == OLD_PIN
         and old.get('expectedAddress') == expected and old.get('peerAddress') == peer
         and sha(private_file(OLD_STATE / 'entry.py', 256 * 1024)) == OLD_PIN,
         'Retained entry does not match the former M/N binding')
    jobs = OLD_STATE / 'jobs'
    if lexists(jobs):
        directory(jobs)
        need(not any(jobs.iterdir()), 'Earlier M/N task state present; preserve old launcher')
    return True


def install_launcher(node, expected, peer, retained):
    if not retained or not lexists(BOOT_LAUNCHER) or read(BOOT_LAUNCHER, 512) == LAUNCHER:
        fresh_file(BOOT_LAUNCHER, LAUNCHER, 0o700)
        return
    old_lock = lock_state(OLD_STATE)
    try:
        check_retained_entry(node, expected, peer)
        fresh_file(STATE / 'previous-root-start.sh', OLD_LAUNCHER, 0o600)
        with tempfile.NamedTemporaryFile(dir=ROOT, prefix='.root-start-sp3-', delete=False) as temporary:
            path = Path(temporary.name)
            try:
                os.fchmod(temporary.fileno(), 0o700)
                temporary.write(LAUNCHER)
                temporary.flush()
                os.fsync(temporary.fileno())
                os.replace(path, BOOT_LAUNCHER)
            finally:
                path.unlink(missing_ok=True)
        fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(old_lock)


def admission(node, expected, peer):
    raw = zlib.decompress(base64.b64decode(ADMISSION_B64, validate=True))
    need(len(raw) <= 64 * 1024 and sha(raw) == ADMISSION_SHA256, 'Embedded admission source differs')
    probe = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', raw.decode('utf-8'),
                            '--expected-address', expected, '--peer-address', peer,
                            '--node-label', node],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=90, env=child_environment(os.environ))
    need(probe.returncode == 0 and 0 < len(probe.stdout) <= 128 * 1024,
         'Read-only admission probe failed or exceeded its output bound')
    obj = json.loads(probe.stdout)
    need(isinstance(obj, dict), 'Read-only admission returned an invalid report')
    return obj


def enroll(args, current, pin):
    need(args.node in ALIASES and args.expected_ip and args.peer_ip,
         'Use --enroll with --node, --expected-ip and --peer-ip')
    expected, peer = local_address(args.expected_ip, args.peer_ip)
    need((current.get('kernel'), current.get('architecture')) == (SP3_KERNEL, 'aarch64'),
         'Unexpected target kernel or architecture; no changes made')
    need(re.fullmatch('[0-9a-f]{32}', current['machineId'])
         and current['machineId'] != '0' * 32
         and re.fullmatch('[0-9a-f-]{36}', current['bootId'])
         and bool(current['hostname']), 'Target machine identity is incomplete')
    user, _ = check_account()
    retained = check_retained_entry(args.node, expected, peer)
    had_home = lexists(HOST_HOME)
    if had_home and user is None:
        need(retained or lexists(INTENT), 'Existing home without a matching account or enrollment intent; preserved')
    binding = {'schema': 1, 'sessionId': SESSION, 'node': args.node, 'identity': current,
               'entrySha256': pin, 'expectedAddress': expected, 'peerAddress': peer}
    remote_path = f'root-entry-v1/{SESSION}/enrollments/{args.node}.json'
    tokens = credentials(enroll=True, retained=retained)
    control, results = verified_clients(tokens)
    if retained:
        previous_queue = fetch(control, f'root-entry-v1/{OLD_SESSION}/queues/{args.node}.json')
        need(previous_queue.get('sessionId') == OLD_SESSION and previous_queue.get('node') == args.node
             and previous_queue.get('jobIds') == [], 'Former M/N queue is not empty; preserve old launcher')
    code, existing, _ = results.contents(RESULTS, remote_path, 'main')
    need(code in (200, 404), 'Enrollment repository unavailable')
    cached = private_file(ENROLLED, 192 * 1024) if lexists(ENROLLED) else None
    if code == 200 or cached is not None:
        if code == 200 and cached is not None:
            need(existing == cached, 'Local and remote enrollment differ')
        report = json.loads(cached if cached is not None else existing)
        need(set(report) == set(binding) | {'admission'}
             and all(report[k] == v for k, v in binding.items())
             and isinstance(report['admission'], dict), 'Enrollment identity already fixed; preserved')
    else:
        report = {**binding, 'admission': admission(args.node, expected, peer)}

    if not had_home:
        HOST_HOME.mkdir(mode=0o700)
        directory(HOST_HOME)
        # The account can traverse its home and own its worktree without being
        # able to rename the protected root launcher directory.
        HOST_HOME.chmod(0o755)
    directory(HOST_HOME)
    mkdir(ROOT)
    mkdir(STATE)
    fd = advisory_lock()
    try:
        fresh_file(INTENT, wire(binding), 0o600)
        create_account()
        mkdir(STATE / 'jobs')
        fresh_file(CREDENTIALS, wire(tokens), 0o600)
        fresh_file(ENROLLED, wire(report), 0o600)
        fresh_file(ENTRY, Path(__file__).read_bytes(), 0o600)
        put(results, remote_path, wire(report))
        install_launcher(args.node, expected, peer, retained)
        print('ROOT_RELAY_ENROLLED=' + args.node, flush=True)
        print('ROOT_FIXED_ENTRY_READY=bash /home/jwk/root/root-start.sh', flush=True)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--enroll', action='store_true')
    parser.add_argument('--node', choices=ALIASES)
    parser.add_argument('--expected-ip')
    parser.add_argument('--peer-ip')
    args = parser.parse_args()
    need(os.getuid() == os.geteuid() == 0 and platform.system() == 'Linux',
         'Use the designated node root terminal')
    os.umask(0o077)
    pin = sha(Path(__file__).read_bytes())
    current = identity()
    if args.enroll:
        enroll(args, current, pin)
        return
    need(not any((args.node, args.expected_ip, args.peer_ip)) and Path(__file__).resolve() == ENTRY,
         'Use the installed unified entry')
    for path in (Path('/'), HOST_HOME.parent, HOST_HOME, ROOT, STATE):
        directory(path)
    local = json.loads(private_file(ENROLLED, 192 * 1024))
    node = local['node']
    need(local['schema'] == 1 and node in ALIASES and local['sessionId'] == SESSION
         and local['entrySha256'] == pin, 'Local enrollment differs')
    local_address(local['expectedAddress'], local['peerAddress'])
    control, results = verified_clients(credentials())
    profile = fetch(control, f'root-entry-v1/{SESSION}/profiles/{node}.json')
    need(profile['schema'] == 1 and profile['node'] == node and profile['sessionId'] == SESSION
         and profile['mode'] == 'manual' and profile['entrySha256'] == pin
         and profile['rootArtifactDirectory'] == str(ROOT)
         and profile['expectedAddress'] == local['expectedAddress'], 'Pinned root profile differs')
    need(all(current[k] == profile['identity'][k] == local['identity'][k]
             for k in ('machineId', 'hostname', 'kernel', 'architecture')),
         'Different machine, kernel, or architecture')
    fd = advisory_lock()
    try:
        boot = {'node': node, 'identity': current, 'entrySha256': pin}
        save(STATE / 'current-boot.json', boot)
        put(results, f'root-entry-v1/{SESSION}/{node}/boots/{current["bootId"]}/{pin}.json', wire(boot))
        run_task(control, results, node, current, pin)
    finally:
        os.close(fd)



raw=zlib.decompress(base64.b64decode('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'))
need(sha(raw)=='b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd','Pinned transport differs')
API=types.ModuleType('root_transport');exec(compile(raw,'<root-transport>','exec'),API.__dict__)

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'ROOT_UNIFIED_ENTRY_STOPPED_PRESERVE_STATE','errorType':type(error).__name__,
            'reason':str(error)[:400] if isinstance(error,RuntimeError) else type(error).__name__}),flush=True)
        raise SystemExit(1)
