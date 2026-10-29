"""Bounded, ordinary-user GitHub relay. v1 executes only reviewed read-only operations."""
import argparse
import base64
import datetime as dt
import getpass
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = 'agentenv-readonly-relay-v1'
API = 'https://api.github.com'
SOURCE_REPO = 'LittleFish-15/AgentENV'
MAX_OUTPUT = 256 * 1024
MAX_ERROR = 64 * 1024
OPS = {
    'retained-inventory-v1': {
        'nodes': ('node-a', 'node-b'), 'seconds': 180,
        'blob': '040068bd8ef9e85f9fac8073eab3cc6c51557c8d',
        'sha256': 'b0788d2683d3038dc85fa9b3892f183d5eaf0ca8597a6fc715ee763db4319658',
        'bytes': 10656,
    },
    'identity-v1': {'nodes': ('node-a', 'node-b', 'node-c', 'node-d'), 'seconds': 15},
}


class Stop(RuntimeError):
    pass


class Network(RuntimeError):
    def __init__(self, status=0, retry_after=60):
        self.status = status
        self.retry_after = max(30, min(600, retry_after))
        super().__init__('GitHub request unavailable (HTTP ' + str(status) + ')')


def need(value, reason):
    if not value:
        raise Stop(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def timestamp(value):
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(result.tzinfo is not None, 'Timezone required')
    return result.timestamp()


def identifier(value):
    need(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value), 'Invalid identifier')
    return value


def repo_name(value):
    need(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value), 'Invalid repository')
    return value


def identity():
    need(sys.platform == 'linux' and os.getuid() == os.geteuid() == 1204,
         'Use ordinary jwk UID1204 on an enrolled experimental node')
    caps = {line.split(':', 1)[0]: int(line.split(':', 1)[1].strip(), 16)
            for line in Path('/proc/self/status').read_text().splitlines()
            if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:'))}
    need(len(caps) == 4 and not any(caps.values()), 'Relay requires zero process capabilities')
    return {'hostname': platform.node(), 'uid': os.getuid(), 'gid': os.getgid(),
            'machineId': Path('/etc/machine-id').read_text().strip(),
            'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'kernel': platform.release(), 'architecture': platform.machine()}


def secure_dir(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'Private directory path redirected')
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    need(path.resolve() == path and stat.S_ISDIR(info.st_mode) and
         info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077,
         'Private directory ownership or mode differs')
    return path


def atomic(path, value, replace=True):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + os.urandom(8).hex() + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded(value)); stream.flush(); os.fsync(stream.fileno())
    if not replace:
        try:
            os.link(temporary, path)
        finally:
            temporary.unlink()
    else:
        need(not path.is_symlink(), 'State file redirected')
        os.replace(temporary, path)
    if sys.platform == 'linux':
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def load(path, private=False):
    path = Path(path)
    info = path.lstat()
    need(not path.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_size <= 2 * 1024**2,
         'State file type/size differs')
    if private:
        need(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077,
             'Credential/config file permissions differ')
    return json.loads(path.read_bytes())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise Stop('Redirect refused; credentials stay on api.github.com')


class GitHub:
    def __init__(self, token=None):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, value=None, etag=None, limit=2 * 1024**2):
        need(path.startswith('/repos/') or path in ('/user', '/user/repos'), 'Unsupported API path')
        headers = {'Accept': 'application/vnd.github+json', 'User-Agent': VERSION,
                   'X-GitHub-Api-Version': '2022-11-28', 'Cache-Control': 'no-cache'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        if etag:
            headers['If-None-Match'] = etag
        raw = encoded(value) if value is not None else None
        if raw is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(API + path, data=raw, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=25) as response:
                data = response.read(limit + 1)
                need(len(data) <= limit, 'API response too large')
                return response.status, json.loads(data) if data else None, response.headers.get('ETag')
        except urllib.error.HTTPError as error:
            if error.code in (304, 404):
                return error.code, None, error.headers.get('ETag')
            try:
                pause = int(error.headers.get('Retry-After', '60'))
            except ValueError:
                pause = 60
            raise Network(error.code, pause) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Network() from None

    def private_repo(self, repo, expected_id=None):
        repo_name(repo)
        status, row, _ = self.request('GET', '/repos/' + repo)
        need(status == 200 and row.get('private') is True and row.get('full_name', '').lower() == repo.lower(),
             'Expected private repository; public/missing result channels are refused')
        if expected_id is not None:
            need(row['id'] == expected_id, 'Repository identity changed')
        return row

    def contents(self, repo, path, branch, etag=None):
        repo_name(repo)
        need(not path.startswith('/') and '..' not in Path(path).parts, 'Invalid repository path')
        url = '/repos/' + repo + '/contents/' + urllib.parse.quote(path, safe='/')
        url += '?ref=' + urllib.parse.quote(branch, safe='')
        status, value, tag = self.request('GET', url, etag=etag)
        if status != 200:
            return status, None, tag
        need(value.get('type') == 'file' and value.get('encoding') == 'base64', 'Expected bounded repository file')
        raw = base64.b64decode(''.join(value['content'].split()), validate=True)
        need(len(raw) == value['size'] and len(raw) <= 1024**2, 'Repository file size differs')
        return status, raw, tag

    def immutable_result(self, repo, repo_id, branch, path, raw):
        need(len(raw) <= 900 * 1024, 'Result exceeds relay upload bound')
        self.private_repo(repo, repo_id)
        status, current, _ = self.contents(repo, path, branch)
        if status == 200:
            need(current == raw, 'Existing result differs; preserved without overwrite')
            return
        need(status == 404, 'Cannot establish result absence')
        url = '/repos/' + repo + '/contents/' + urllib.parse.quote(path, safe='/')
        try:
            self.request('PUT', url, {'message': 'relay result ' + path, 'branch': branch,
                                     'content': base64.b64encode(raw).decode()})
        except Network as error:
            if error.status not in (409, 422):
                raise
            # A write conflict or lost prior ACK never repeats the underlying node operation.
        status, current, _ = self.contents(repo, path, branch)
        if status == 404:
            raise Network(409)
        need(status == 200 and current == raw, 'Result upload not confirmed byte-for-byte')

    def source(self, operation):
        status, row, _ = self.request('GET', '/repos/' + SOURCE_REPO + '/git/blobs/' + operation['blob'])
        need(status == 200 and row.get('sha') == operation['blob'] and row.get('encoding') == 'base64', 'Source blob differs')
        raw = base64.b64decode(''.join(row['content'].split()), validate=True)
        need(len(raw) == row['size'] == operation['bytes'] and digest(raw) == operation['sha256'], 'Source digest differs')
        return raw


def validate_profile(profile, current, runner_sha, now):
    need(profile.get('protocol') == VERSION and profile.get('node') in ('node-a', 'node-b', 'node-c', 'node-d'), 'Profile differs')
    identifier(profile['sessionId'])
    need(profile['uid'] == current['uid'] == 1204 and profile['gid'] == current['gid'] == 1205
         and profile['hostname'] == current['hostname'], 'Node/UID/GID differs')
    need(current['architecture'] == 'aarch64', 'This experimental cohort requires ARM64')
    need(not profile.get('machineId') or profile['machineId'] == current['machineId'], 'Machine identity differs')
    need(profile['runnerSha256'] == runner_sha, 'Runner version differs; explicit update needed')
    need(now < timestamp(profile['expiresAt']), 'Relay session expired')
    need(set(profile['allowedOperations']) <= {name for name, op in OPS.items() if profile['node'] in op['nodes']}, 'Unsupported operation scope')


def choose_node(session, current):
    need(session.get('protocol') == VERSION and isinstance(session.get('nodes'), list)
         and len(session['nodes']) <= 4, 'Session protocol or node list differs')
    matches = [row['node'] for row in session['nodes'] if row['uid'] == current['uid']
               and row['hostname'] == current['hostname']
               and (not row.get('machineId') or row['machineId'] == current['machineId'])]
    need(len(matches) == 1, 'Automatic node identity is ambiguous or unknown')
    return matches[0]


def validate_job(job, config, current, now):
    need(set(job) == {'schema', 'jobId', 'node', 'sessionId', 'kind', 'notBefore', 'expiresAt'}, 'Unexpected job fields; arbitrary commands are forbidden')
    need(job['schema'] == 1 and job['node'] == config['node'] and job['sessionId'] == config['sessionId'], 'Job identity differs')
    identifier(job['jobId'])
    need(job['kind'] in config['allowedOperations'] and job['kind'] in OPS, 'Operation not allowed')
    need(job['node'] in OPS[job['kind']]['nodes'], 'Operation not allowed on this node')
    need(timestamp(job['notBefore']) <= now < timestamp(job['expiresAt']) <= timestamp(config['expiresAt']), 'Job outside valid time window')
    need(current == config['identity'], 'Boot/machine/user identity changed; explicit reconciliation required')


def redact(raw, secrets):
    text = raw.decode('utf-8', 'replace')
    for secret in secrets:
        if secret:
            text = text.replace(secret, '[REDACTED]')
    text = re.sub(r'\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]+', '[REDACTED]', text)
    return re.sub(r'(?im)(authorization\s*[:=]\s*)(?:bearer|token)\s+\S+', r'\1[REDACTED]', text).encode()


def execute_readonly(argv, directory, seconds):
    stdout_path, stderr_path = directory / 'stdout.log', directory / 'stderr.log'
    env = {key: os.environ[key] for key in ('HOME', 'LANG', 'LC_ALL') if key in os.environ}
    env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', PYTHONDONTWRITEBYTECODE='1')
    reason = None
    with stdout_path.open('xb') as out, stderr_path.open('xb') as err:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                 cwd=directory, env=env, close_fds=True)
        deadline = time.monotonic() + seconds
        while child.poll() is None:
            if time.monotonic() >= deadline:
                reason = 'read_only_task_timeout'
            elif stdout_path.stat().st_size > MAX_OUTPUT or stderr_path.stat().st_size > MAX_ERROR:
                reason = 'read_only_task_output_limit'
            if reason:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
                break
            time.sleep(0.2)
    if stdout_path.stat().st_size > MAX_OUTPUT or stderr_path.stat().st_size > MAX_ERROR:
        reason = reason or 'read_only_task_output_limit'
    return {'returncode': child.returncode, 'stopReason': reason}


class Runner:
    def __init__(self, root, config, control, results, public=None, execute=execute_readonly, mkdir=secure_dir):
        self.root, self.config, self.control, self.results = Path(root), config, control, results
        self.public, self.execute, self.mkdir = public or GitHub(), execute, mkdir

    def upload(self, directory):
        state = load(directory / 'state.json')
        if state['state'] == 'uploaded':
            return
        if state['state'] == 'running':
            self.report_unknown(directory, state)
        need(state['state'] == 'upload_pending', 'Operation outcome unknown; do not rerun')
        raw = (directory / 'result.json').read_bytes()
        need(digest(raw) == state['resultSha256'], 'Local result changed')
        path = 'results/' + self.config['sessionId'] + '/' + self.config['node'] + '/' + state['jobId'] + '.json'
        self.results.immutable_result(self.config['resultRepo'], self.config['resultRepoId'],
                                      self.config['resultBranch'], path, raw)
        state.update(state='uploaded', resultPath=path)
        atomic(directory / 'state.json', state)

    def report_unknown(self, directory, state):
        report_path = directory / 'attention.json'
        if not report_path.exists():
            atomic(report_path, {'schema': 1, 'state': 'unknown_after_interruption',
                    'node': self.config['node'], 'sessionId': self.config['sessionId'],
                    'jobId': state['jobId'], 'jobSha256': state['jobSha256'],
                    'identity': state['identity'], 'startedAt': state['startedAt'],
                    'executionErrorType': state.get('executionErrorType'),
                    'replayed': False, 'resourceCleanupConfirmed': False}, replace=False)
        path = 'attention/' + self.config['sessionId'] + '/' + self.config['node'] + '/' + state['jobId'] + '.json'
        self.results.immutable_result(self.config['resultRepo'], self.config['resultRepoId'],
                                      self.config['resultBranch'], path, report_path.read_bytes())
        raise Stop('Unconfirmed job reported; preserved without replay')

    def run_job(self, job, current, now, secrets=()):
        validate_job(job, self.config, current, now)
        directory = self.root / 'jobs' / identifier(job['jobId'])
        job_sha = digest(encoded(job))
        if directory.exists():
            need(not directory.is_symlink() and directory.resolve() == directory, 'Job directory redirected')
            need((directory / 'state.json').is_file(), 'Partial local job preserved')
            state = load(directory / 'state.json')
            need(state['jobSha256'] == job_sha, 'Job ID reused with different payload')
            self.upload(directory)
            return
        operation = OPS[job['kind']]
        if job['kind'] == 'identity-v1':
            argv = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '_identity']
        else:
            cache = self.mkdir(self.root / 'cache') / (operation['sha256'] + '.py')
            if cache.exists():
                need(not cache.is_symlink() and digest(cache.read_bytes()) == operation['sha256'], 'Cached script changed')
            else:
                source = self.public.source(operation)
                need(len(source) == operation['bytes'] and digest(source) == operation['sha256'], 'Untrusted source')
                fd = os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o400)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(source); stream.flush(); os.fsync(stream.fileno())
            argv = [sys.executable, '-I', '-B', str(cache)]
        self.mkdir(directory)
        state = {'state': 'running', 'jobId': job['jobId'], 'jobSha256': job_sha,
                 'startedAt': utc(), 'identity': current}
        atomic(directory / 'state.json', state, replace=False)
        # Once running is journaled, any exception requires reconciliation, never blind replay.
        try:
            execution = self.execute(argv, directory, min(operation['seconds'], timestamp(job['expiresAt']) - now))
        except Exception as error:
            state['executionErrorType'] = type(error).__name__
            atomic(directory / 'state.json', state)
            self.report_unknown(directory, state)
        logs = {}
        for name, limit in (('stdout.log', MAX_OUTPUT), ('stderr.log', MAX_ERROR)):
            raw = (directory / name).read_bytes()
            safe = redact(raw[:limit], secrets)
            logs[name] = {'originalBytes': len(raw), 'originalSha256': digest(raw),
                          'truncated': len(raw) > limit, 'redacted': safe != raw[:limit],
                          'encoding': 'gzip+base64', 'content': base64.b64encode(gzip.compress(safe, mtime=0)).decode()}
        result = {'schema': 1, 'protocol': VERSION, 'node': self.config['node'],
                  'sessionId': self.config['sessionId'], 'jobId': job['jobId'], 'jobSha256': job_sha,
                  'operation': job['kind'], 'identity': current, 'startedAt': state['startedAt'],
                  'finishedAt': utc(), 'execution': execution, 'logs': logs,
                  'scope': 'read-only job result; no hardware/data-path/savings acceptance inferred',
                  'SDKCalledByRelay': False, 'rootOperationsSupported': False}
        atomic(directory / 'result.json', result, replace=False)
        state.update(state='upload_pending', resultSha256=digest(encoded(result)))
        atomic(directory / 'state.json', state)
        self.upload(directory)

    def flush(self):
        jobs = self.root / 'jobs'
        if jobs.is_dir():
            need(not jobs.is_symlink() and jobs.resolve() == jobs, 'Jobs root redirected')
            for directory in sorted(jobs.iterdir()):
                need(directory.is_dir() and not directory.is_symlink(), 'Job directory differs')
                self.upload(directory)


def prompt_tokens():
    control = getpass.getpass('Control repository read token (hidden): ').strip()
    result = getpass.getpass('Results repository write token (hidden): ').strip()
    need(control.startswith('github_pat_') and result.startswith('github_pat_') and control != result,
         'Use two distinct dedicated fine-grained tokens; do not use general desktop credentials')
    need(all(20 <= len(value) <= 512 and not any(c.isspace() for c in value) for value in (control, result)),
         'Invalid token format')
    return {'controlToken': control, 'resultToken': result}


def enroll(args, root):
    current = identity()
    if (root / 'config.json').exists():
        config = load(root / 'config.json', True)
        need(current == config['identity'], 'Existing enrollment identity changed')
        need(config['controlRepo'] == args.control_repo and config['resultRepo'] == args.result_repo,
             'Existing repository binding differs')
        print('ALREADY_ENROLLED_USE_RUN'); return
    need(not (root / 'credentials.json').exists(), 'Partial enrollment preserved; reconcile config before retry')
    tokens = prompt_tokens()
    control, results = GitHub(tokens['controlToken']), GitHub(tokens['resultToken'])
    c = control.private_repo(args.control_repo)
    r = results.private_repo(args.result_repo)
    need(c['id'] != r['id'], 'Task and result repositories must be separate')
    node = args.node
    if node == 'auto':
        code, raw, _ = control.contents(args.control_repo, 'session.json', c['default_branch'])
        need(code == 200, 'Relay session not prepared')
        session = json.loads(raw)
        node = choose_node(session, current)
    need(node in ('node-a', 'node-b', 'node-c', 'node-d'), 'Unknown node')
    code, raw, _ = control.contents(args.control_repo, 'profiles/' + node + '.json', c['default_branch'])
    need(code == 200, 'Node profile not prepared')
    profile = json.loads(raw)
    need(profile['node'] == node, 'Profile node differs')
    validate_profile(profile, current, digest(Path(__file__).read_bytes()), time.time())
    config = dict(profile, identity=current, controlRepo=args.control_repo, controlRepoId=c['id'],
                  controlBranch=c['default_branch'], resultRepo=args.result_repo,
                  resultRepoId=r['id'], resultBranch=r['default_branch'])
    secure_dir(root / 'jobs')
    atomic(root / 'credentials.json', tokens, replace=False)
    atomic(root / 'config.json', config, replace=False)
    print('RELAY_ENROLLED_NODE=' + config['node'])


def run(root, max_minutes):
    import fcntl
    current = identity()
    config = load(root / 'config.json', True)
    secrets = load(root / 'credentials.json', True)
    validate_profile(config, current, digest(Path(__file__).read_bytes()), time.time())
    need(current == config['identity'], 'Boot identity changed')
    control, results = GitHub(secrets['controlToken']), GitHub(secrets['resultToken'])
    lock_fd = os.open(root / 'runner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'a') as lock:
        info = os.fstat(lock.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and not stat.S_IMODE(info.st_mode) & 0o077, 'Runner lock identity differs')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stop('Another relay runner already holds this node lock') from None
        control.private_repo(config['controlRepo'], config['controlRepoId'])
        registration = {'protocol': VERSION, 'node': config['node'], 'sessionId': config['sessionId'],
                        'identity': current, 'runnerSha256': config['runnerSha256'],
                        'allowedOperations': config['allowedOperations']}
        runner = Runner(root, config, control, results)
        etag, queue = None, None
        registered = False
        deadline = min(time.monotonic() + max_minutes * 60,
                       time.monotonic() + timestamp(config['expiresAt']) - time.time())
        print('RELAY_RUNNING_' + config['node'], flush=True)
        while time.monotonic() < deadline and not (root / 'stop.request').exists():
            pause = 60
            try:
                need(identity() == current, 'Node identity changed')
                if not registered:
                    results.immutable_result(config['resultRepo'], config['resultRepoId'], config['resultBranch'],
                        'registrations/' + config['sessionId'] + '/' + config['node'] + '.json', encoded(registration))
                    registered = True
                runner.flush()
                code, raw, new_tag = control.contents(config['controlRepo'], 'queues/' + config['node'] + '.json',
                                                       config['controlBranch'], etag)
                if code == 200:
                    queue = json.loads(raw); etag = new_tag
                elif code != 304:
                    raise Network(code)
                queue_unchanged = code == 304
                need(isinstance(queue, dict) and queue.get('sessionId') == config['sessionId']
                     and queue.get('node') == config['node'] and queue.get('schema') == 1, 'Queue identity differs')
                if queue.get('stop') is True:
                    break
                jobs = queue.get('jobIds')
                need(isinstance(jobs, list) and len(jobs) <= 16 and len(set(jobs)) == len(jobs), 'Invalid queue')
                for job_id in jobs:
                    if (root / 'stop.request').exists():
                        break
                    identifier(job_id)
                    local_state = root / 'jobs' / job_id / 'state.json'
                    if queue_unchanged and local_state.exists() and load(local_state)['state'] == 'uploaded':
                        continue
                    code, raw, _ = control.contents(config['controlRepo'], 'jobs/' + job_id + '.json', config['controlBranch'])
                    if code != 200:
                        raise Network(code)
                    runner.run_job(json.loads(raw), current, time.time(), tuple(secrets.values()))
                atomic(root / 'status.json', {'state': 'polling', 'node': config['node'], 'lastPoll': utc()})
            except Network as error:
                pause = error.retry_after
                atomic(root / 'status.json', {'state': 'network_wait_results_preserved', 'httpStatus': error.status, 'at': utc()})
            until = min(time.monotonic() + pause, deadline)
            while time.monotonic() < until and not (root / 'stop.request').exists():
                time.sleep(min(1, max(0, until - time.monotonic())))
        atomic(root / 'status.json', {'state': 'stopped_or_session_expired', 'at': utc()})
        print('RELAY_STOPPED_NO_RESOURCE_CLEANUP', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, default=Path.home() / '.local/state/agentenv-github-relay')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('enroll')
    p.add_argument('--node', default='auto', choices=('auto', 'node-a', 'node-b', 'node-c', 'node-d'))
    p.add_argument('--control-repo', required=True); p.add_argument('--result-repo', required=True)
    p = sub.add_parser('run'); p.add_argument('--max-minutes', type=int, default=240)
    sub.add_parser('stop'); sub.add_parser('status'); sub.add_parser('_identity')
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == '_identity':
        print(json.dumps({'status': 'READ_ONLY_NODE_IDENTITY', 'identity': identity(), 'SDK_called': False})); return
    identity()
    root = args.state_dir.absolute()
    need(root.is_relative_to(Path.home().resolve()), 'State directory must remain within own home')
    secure_dir(root)
    if args.command == 'enroll':
        enroll(args, root)
    elif args.command == 'run':
        need(1 <= args.max_minutes <= 480, 'Run duration must be 1..480 minutes')
        run(root, args.max_minutes)
    elif args.command == 'stop':
        atomic(root / 'stop.request', {'requestedAt': utc()})
        print('STOP_REQUESTED_AFTER_CURRENT_READ_ONLY_TASK')
    else:
        print(json.dumps(load(root / 'status.json') if (root / 'status.json').exists() else {'state': 'not_started'}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Stop, Network) as error:
        print(json.dumps({'status': 'RELAY_STOPPED_PRESERVE_STATE', 'reason': str(error)}), file=sys.stderr)
        raise SystemExit(1)
    except Exception as error:
        # Never include credentials, request objects or arbitrary remote response bodies.
        print(json.dumps({'status': 'RELAY_STOPPED_PRESERVE_STATE', 'errorType': type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
