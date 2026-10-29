"""Manually invoked C/root relay. Only the explicitly approved fixed maintenance driver is executable."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import types
import zlib

API_SOURCE = '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'
API_SHA = 'b958c459c09db2fe72d508762e8bdab06bd642bfc2f33c6723462ac45353fdcd'
DRIVER_BLOB = 'db91ea60d2c92d40a67a8d7aa599d2fd723b10ec'
DRIVER_SHA = 'fb42a7da0a9e819d0f15ae5af1053134ab224f6ec7f45b7356a344730f5fc512'
DRIVER_BYTES = 22337
ROOT = Path('/var/lib/agentenv-root-relay')
CREDS = Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json')
CONTROL = 'LittleFish-15/AgentENV-relay-control'
RESULTS = 'LittleFish-15/AgentENV-relay-results'
SESSION = 'relay-20261029-0d032371'
APPROVAL = 'C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def identity():
    return {'machineId': Path('/etc/machine-id').read_text().strip(),
            'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'kernel': platform.release(), 'hostname': platform.node()}


def validate(job, expected, now):
    need(set(job) == {'schema','jobId','node','sessionId','identity','approval','action','notBefore','expiresAt','entry'}, 'Root job fields differ')
    need(job['schema'] == 1 and job['node'] == 'node-c' and job['sessionId'] == SESSION,
         'Root job node/session differs')
    need(re.fullmatch(r'[a-z0-9-]{1,64}', job['jobId']), 'Invalid root job identifier')
    need(job['identity'] == expected, 'Root job machine/boot/kernel identity differs')
    need(job['approval'] == APPROVAL and job['action'] in ('activate', 'restore'), 'Unapproved root operation refused')
    entry = job['entry']
    need(set(entry) == {'repo','path','commit','blob','sha256','bytes'}, 'Root driver descriptor differs')
    need(entry['repo'] == 'LittleFish-15/AgentENV'
         and re.fullmatch(r'dev-relay/host-pmem/cd-migration/C_run_maintenance_v[0-9]+\.py', entry['path']),
         'Only reviewed C maintenance driver versions are supported')
    need(re.fullmatch('[0-9a-f]{40}',entry['commit']) and re.fullmatch('[0-9a-f]{40}',entry['blob'])
         and re.fullmatch('[0-9a-f]{64}',entry['sha256']) and type(entry['bytes']) is int
         and 0 < entry['bytes'] <= 128 * 1024, 'Root driver identity/size differs')
    need(job['notBefore'] <= now < job['expiresAt'] and job['expiresAt'] - job['notBefore'] <= 90000,
         'Root job expired or approval window differs')


def api_module():
    raw = zlib.decompress(base64.b64decode(API_SOURCE, validate=True))
    need(hashlib.sha256(raw).hexdigest() == API_SHA, 'Embedded transport differs')
    module = types.ModuleType('pinned_transport')
    exec(compile(raw, '<pinned-transport>', 'exec'), module.__dict__)
    return module


def secret_clients(api):
    # Existing dedicated tokens are consumed in memory only. They are never copied to root state or sent to children.
    need(CREDS.resolve() == CREDS, 'Credential path redirected')
    fd = os.open(CREDS, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 1204 and not stat.S_IMODE(s.st_mode) & 0o077
             and s.st_size <= 8192, 'Existing token file owner/mode/size differs')
        row = json.loads(stream.read(8193))
    need(set(row) == {'controlToken','resultToken'} and all(isinstance(v,str) and 10 <= len(v) <= 1024 for v in row.values()),
         'Existing dedicated credential shape differs')
    return api.GitHub(row['controlToken']), api.GitHub(row['resultToken'])


def fetch_json(client, repo, path):
    code, raw, _ = client.contents(repo, path, 'main')
    need(code == 200, 'Approved root queue/job unavailable')
    return json.loads(raw)


def collect_driver_receipt(action):
    path = Path('/var/lib/agentenv-c-rootfs-preflight-v1') / ('maintenance-' + action + '-v1.json')
    if not path.exists():
        return None
    need(path.resolve() == path and path.stat().st_uid == 0 and path.stat().st_size <= 512 * 1024,
         'Driver report redirected or oversized')
    return json.loads(path.read_bytes())


def run(api):
    import time
    current = identity()
    preflight = Path('/var/lib/agentenv-c-rootfs-preflight-v1/receipt.json')
    need(preflight.resolve() == preflight and preflight.stat().st_uid == 0, 'C approved preflight missing')
    expected = json.loads(preflight.read_bytes())
    need(all(current[k] == expected[k] for k in ('machineId','bootId','kernel')), 'C preflight identity changed')
    control, results = secret_clients(api)
    control.private_repo(CONTROL, 1438089258); results.private_repo(RESULTS, 1438089386)
    queue = fetch_json(control, CONTROL, 'root-queues/' + SESSION + '/node-c.json')
    need(queue.get('sessionId') == SESSION and queue.get('node') == 'node-c' and queue.get('stop') is False,
         'Root queue stopped or differs')
    need(isinstance(queue.get('jobIds'), list) and len(queue['jobIds']) <= 1, 'Only one approved root action per invocation')
    if not queue['jobIds']:
        print('ROOT_RELAY_NO_APPROVED_TASK'); return
    job_id = queue['jobIds'][0]
    need(isinstance(job_id,str) and re.fullmatch('[a-z0-9-]{1,64}', job_id), 'Invalid queue job')
    directory = api.secure_dir(ROOT / 'jobs' / job_id)
    report_path = directory / 'result.json'
    state_path = directory / 'state.json'
    result_key = 'root-results/' + SESSION + '/' + job_id + '.json'
    if report_path.exists():
        raw = report_path.read_bytes()
        results.immutable_result(RESULTS, 1438089386, 'main', result_key, raw)
        print('ROOT_RELAY_RESULT_ALREADY_DONE_OR_RESENT_NO_ACTION'); return
    if state_path.exists():
        attention = directory / 'attention.json'
        if not attention.exists():
            api.atomic(attention, {'status':'ROOT_PRIOR_EXECUTION_OUTCOME_UNKNOWN_NO_RETRY',
                'sessionId':SESSION,'jobId':job_id,'identity':current,'previousState':api.load(state_path)}, replace=False)
        results.immutable_result(RESULTS,1438089386,'main','root-attention/' + SESSION + '/' + job_id + '.json', attention.read_bytes())
        print('ROOT_PRIOR_EXECUTION_OUTCOME_UNKNOWN_NO_RETRY'); return
    job = fetch_json(control, CONTROL, 'root-jobs/' + SESSION + '/' + job_id + '.json')
    validate(job, current, time.time())
    need(job['jobId'] == job_id, 'Root job ID differs from queue')
    approved_entry = job['entry']
    code, raw, _ = control.contents(approved_entry['repo'], approved_entry['path'], approved_entry['commit'])
    need(code == 200 and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == approved_entry['blob'],
         'Approved driver commit/path/blob binding differs')
    need(len(raw) == approved_entry['bytes'] and hashlib.sha256(raw).hexdigest() == approved_entry['sha256'], 'Root driver digest differs')
    driver = directory / 'driver.py'
    fd = os.open(driver, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    api.atomic(state_path, {'state':'running','job':job,'startedAt':api.utc()}, replace=False)
    print('ROOT_APPROVED_TASK_STARTED=' + job_id, flush=True)
    with (directory / 'stdout.log').open('xb') as out, (directory / 'stderr.log').open('xb') as err:
        rc = subprocess.run(['/usr/bin/python3','-I','-B',str(driver),job['action'],'--approval',APPROVAL],
                            stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}).returncode
    logs = {}
    for name in ('stdout.log','stderr.log'):
        path = directory / name
        need(path.stat().st_size <= 256 * 1024, 'Root output exceeded bound; preserve local logs')
        raw_log = path.read_bytes()
        logs[name] = {'bytes':len(raw_log),'sha256':hashlib.sha256(raw_log).hexdigest(),
                      'zlibBase64':base64.b64encode(zlib.compress(raw_log,9)).decode()}
    report = {'schema':1,'sessionId':SESSION,'jobId':job_id,'identity':current,'approval':APPROVAL,
              'action':job['action'],'jobSha256':api.digest(api.encoded(job)), 'exitCode':rc,
              'driverSha256':approved_entry['sha256'],'logs':logs,'driverReceipt':collect_driver_receipt(job['action']),
              'finishedAt':api.utc(), 'hardwareAcceptanceInferred':False}
    api.atomic(report_path, report, replace=False)
    api.atomic(state_path, {'state':'upload_pending','exitCode':rc})
    results.immutable_result(RESULTS,1438089386,'main',result_key,report_path.read_bytes())
    api.atomic(state_path, {'state':'uploaded','exitCode':rc})
    print('ROOT_TASK_RESULT_UPLOADED_EXIT=' + str(rc))
    raise SystemExit(rc)


def main():
    import fcntl
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('install','run','install-run','upgrade-run'), nargs='?', default='run')
    args = parser.parse_args()
    need(os.getuid() == os.geteuid() == 0 and platform.system() == 'Linux', 'Invoke manually in C root terminal')
    os.umask(0o077)
    preflight = Path('/var/lib/agentenv-c-rootfs-preflight-v1/receipt.json')
    need(preflight.resolve() == preflight and preflight.stat().st_uid == 0, 'C root preflight required')
    expected = json.loads(preflight.read_bytes())
    need(all(identity()[key] == expected[key] for key in ('machineId','bootId','kernel')), 'Wrong C identity')
    api = api_module()
    api.secure_dir(ROOT)
    if args.action in ('install','install-run','upgrade-run'):
        target = ROOT / 'root-relay.py'; raw = Path(__file__).read_bytes()
        launcher = ROOT / 'root-start.sh'
        body = b'#!/bin/bash\nset -eu\numask 077\nexec /usr/bin/python3 -I -B /var/lib/agentenv-root-relay/root-relay.py run\n'
        for path,data,mode in ((target,raw,0o600),(launcher,body,0o700)):
            if path.exists():
                need(path.stat().st_uid == 0 and not path.is_symlink(), 'Existing root entry owner/path differs')
                previous = path.read_bytes()
                if previous != data:
                    need(args.action == 'upgrade-run' and path == target
                         and hashlib.sha256(previous).hexdigest() == '6e2099421ccb151cb0c81fb3002b40cd39d3e5a1cc74dcb7ce659d2dea42b7fd',
                         'Unknown previous root entry preserved; upgrade refused')
                    backup = ROOT / 'root-relay-v1.backup.py'
                    need(not backup.exists(), 'Previous upgrade backup preserved')
                    with backup.open('xb') as stream:
                        stream.write(previous); stream.flush(); os.fsync(stream.fileno())
                    temporary = ROOT / 'root-relay-v2.next.py'
                    with temporary.open('xb') as stream:
                        stream.write(data); stream.flush(); os.fsync(stream.fileno())
                    os.replace(temporary, target)
            else:
                fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
                with os.fdopen(fd,'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
        print('ROOT_FIXED_COMMAND_READY=bash ' + str(launcher), flush=True)
        if args.action == 'install': return
    root_info = ROOT.stat()
    need(ROOT.resolve() == ROOT and root_info.st_uid == 0 and not stat.S_IMODE(root_info.st_mode) & 0o077,
         'Root relay directory untrusted')
    fd = os.open(ROOT / 'operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        run(api)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never emit network requests or arbitrary exception strings containing credentials.
        print(json.dumps({'status':'ROOT_RELAY_STOPPED_PRESERVE_STATE','errorType':type(error).__name__}),flush=True)
        raise SystemExit(1)
