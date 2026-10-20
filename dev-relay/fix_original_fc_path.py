"""A original experimental Runtime only. Default prepares; --apply-reviewed requires approval."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time

ROOT = Path('/home/jwk/agent')
BASE = ROOT / 'deployments/agentenv-ae9c626-baseline'
CONFIG = BASE / 'config/runtime.toml'
UNIT = 'jwk-aenv-ae9c626-node-a.service'
SHORT = ROOT / 'r/fc-a-base'
SERIAL = BASE / 'logs/firecracker'
MODIFIED_UNIT = 'jwk-aenv-ub-b019f27-node-a.service'
MARKER = ROOT / 'relay/a-original-fc-path-fix.json'


def need(ok, why):
    if not ok:
        raise RuntimeError(why)


def read(path):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True) == path, 'Redirected input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and m.st_size <= 65536, 'Unexpected input metadata')
        data = f.read(65537)
        need(len(data) <= 65536, 'Input grew')
        return data


def updated_config(raw):
    text = raw.decode('utf-8')
    matches = list(re.finditer(r'(?ms)^(\[firecracker\][ \t]*\r?\n)(.*?)(?=^\[|\Z)', text))
    need(len(matches) == 1, 'Expected one firecracker config section')
    m = matches[0]
    body = m[2]
    values = {'work_dir': str(SHORT), 'serial_dir': str(SERIAL), 'log_level': 'Info'}
    insert = []
    for key, value in values.items():
        lines = re.findall(r'(?m)^' + key + r'\s*=\s*(.*?)\s*$', body)
        need(len(lines) <= 1, 'Duplicate existing setting: ' + key)
        if lines:
            need(lines[0] == json.dumps(value), 'Existing custom setting preserved: ' + key)
        else:
            insert.append(key + ' = ' + json.dumps(value) + '\n')
    return (text[:m.end(1)] + ''.join(insert) + text[m.end(1):]).encode()


def state(unit=UNIT):
    r = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,MainPID,User,Group'],
                       capture_output=True, text=True, timeout=10, check=True)
    s = dict(x.split('=', 1) for x in r.stdout.splitlines() if '=' in x)
    need(s.get('ActiveState') == 'active' and s.get('User') == s.get('Group') == 'jwk', 'Unexpected unit state')
    need(int(s.get('MainPID', 0)) > 1, 'No original main PID')
    s['start_ticks'] = Path('/proc/'+s['MainPID']+'/stat').read_text().rsplit(')',1)[1].split()[19]
    return s


def health(port):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        c.request('GET', '/health')
        r = c.getresponse()
        need(r.status == 204, 'Health endpoint did not return 204')
        r.read(1024)
        return r.status
    finally:
        c.close()


def verify(result):
    marker = json.loads(read(MARKER))
    need(marker.get('status') == 'A_ORIGINAL_FC_PATH_CONFIG_APPLIED_RESTART_REQUIRED'
         and marker.get('unit') == UNIT, 'Unexpected repair receipt')
    need(hashlib.sha256(read(CONFIG)).hexdigest() == marker['new_config_sha256'], 'Config changed after repair')
    need(updated_config(read(CONFIG)) == read(CONFIG), 'Expected settings are missing')
    original = state()
    need(original != marker['original_process_before'], 'Original runtime has not restarted')
    need(state(MODIFIED_UNIT) == marker['modified_process_before'], 'Modified runtime identity changed')
    checks = []
    deadline = time.monotonic() + 45
    while len(checks) < 3 and time.monotonic() < deadline:
        try:
            checks.append({'original': health(18080), 'modified': health(18081)})
        except (OSError, http.client.HTTPException, RuntimeError):
            checks.clear()
        time.sleep(1)
    need(len(checks) == 3, 'Health verification timed out; do not repeat restart')
    empty_runtime()
    need(state() == original, 'Original identity changed during health check')
    need(state(MODIFIED_UNIT) == marker['modified_process_before'], 'Modified identity changed during health check')
    result.update(status='A_ORIGINAL_FC_PATH_RESTART_VERIFIED', original_process_after=original,
                  modified_main_process_unchanged=True, health_checks=checks,
                  empty_sandbox_inventory=True, repair_report_directory=marker['report_directory'],
                  settings=marker['settings'], parent_create_retried=False,
                  pending_receipt_modified=False, Guest_or_CoW_tests_executed=False)


def empty_runtime():
    key = read(BASE / 'config/api-key').decode().strip()
    need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+', key), 'Unexpected key format; value withheld')
    c = http.client.HTTPConnection('127.0.0.1', 18080, timeout=10)
    try:
        c.request('GET', '/v2/sandboxes?limit=1', headers={'X-API-Key': key})
        r = c.getresponse()
        data = r.read(65537)
        need(r.status == 200 and len(data) <= 65536 and json.loads(data) == []
             and not r.getheader('x-next-token'), 'Runtime has sandboxes or inventory is uncertain; no change')
    finally:
        c.close()


def root_restart_text(config_hash, pid, ticks):
    return '''/usr/bin/python3 -I -B - <<'A_ORIGINAL_REVIEWED_RESTART'
import hashlib,http.client,json,os,pathlib,re,stat,subprocess
def need(ok,why):
    if not ok: raise SystemExit('STOP: '+why)
need(os.geteuid()==0 and os.uname().nodename=='server1','A/root only')
base=pathlib.Path('/home/jwk/agent/deployments/agentenv-ae9c626-baseline')
def owned(rel):
    p=base/rel
    need(p.resolve(strict=True)==p,'Redirected input')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        m=os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid==1204 and m.st_size<65536,'Unexpected input')
        data=f.read(65537)
        need(len(data)<65536,'Input grew')
        return data
need(hashlib.sha256(owned('config/runtime.toml')).hexdigest()=='CONFIG_HASH','Config changed')
key=owned('config/api-key').decode().strip()
need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+',key),'Unexpected key format; value withheld')
unit='jwk-aenv-ae9c626-node-a.service'
r=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=MainPID,User,Group,PrivateNetwork,PrivateMounts'],capture_output=True,text=True,check=True)
s=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
need(s.get('MainPID')=='EXPECTED_PID' and s.get('User')==s.get('Group')=='jwk' and s.get('PrivateNetwork')==s.get('PrivateMounts')=='yes','Unit changed')
need(pathlib.Path('/proc/EXPECTED_PID/stat').read_text().rsplit(')',1)[1].split()[19]=='EXPECTED_TICKS','PID identity changed')
c=http.client.HTTPConnection('127.0.0.1',18080,timeout=10)
try:
    c.request('GET','/v2/sandboxes?limit=1',headers={'X-API-Key':key})
    r=c.getresponse(); data=r.read(65537)
    need(r.status==200 and len(data)<=65536 and json.loads(data)==[] and not r.getheader('x-next-token'),'Runtime not empty; no restart')
finally: c.close()
subprocess.run(['/usr/bin/systemctl','restart',unit],check=True)
print('A_ORIGINAL_RESTART_SUBMITTED_RUN_JWK_HEALTH')
A_ORIGINAL_REVIEWED_RESTART'''.replace('CONFIG_HASH', config_hash).replace('EXPECTED_PID', str(pid)).replace('EXPECTED_TICKS', str(ticks))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--apply-reviewed', action='store_true')
    modes.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    need(os.getuid() == os.geteuid() == 1204 and os.getgid() == os.getegid() == 1205 and socket.gethostname() == 'server1', 'A ordinary jwk only')
    caps = re.findall(r'^(Cap(?:Inh|Prm|Eff|Amb)):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    need(len(caps)==4 and all(int(v,16)==0 for k,v in caps),'Ordinary capability-free session required')
    os.umask(0o077)
    import fcntl
    lock = ROOT/'relay/a-original-fc-path-fix.lock'
    need(lock.resolve() == lock, 'Redirected repair lock')
    lock_fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    lock_meta = os.fstat(lock_fd)
    need(stat.S_ISREG(lock_meta.st_mode) and lock_meta.st_uid == 1204, 'Unexpected repair lock')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    work = Path(tempfile.mkdtemp(prefix='node-a-fc-path-fix-', dir=ROOT/'relay/reports'))
    result = {'revision':'a-original-fc-path-fix-v1','report_directory':str(work),
              'unit':UNIT,'services_restarted':False,'configuration_modified':False,'SDK_called':False}
    try:
        if args.verify:
            verify(result)
            (work/'return.json').write_text(json.dumps(result,indent=2)+'\n')
            print('BEGIN_RETURN_REPORT');print(json.dumps(result,indent=2));print('END_RETURN_REPORT')
            return 0
        need(not MARKER.exists(), 'Repair receipt already exists; use --verify, do not apply or restart again')
        before_state = state()
        result['original_process_before'] = before_state
        result['modified_process_before'] = state(MODIFIED_UNIT)
        health(18080); health(18081)
        empty_runtime()
        raw = read(CONFIG)
        updated = updated_config(raw)
        fc = BASE/'deps/firecracker/1.15.1-patch-v3/firecracker'
        env = dict(os.environ, LD_LIBRARY_PATH=str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib'))
        help_result = subprocess.run([str(fc),'--help'],capture_output=True,timeout=10,env=env)
        help_text = (help_result.stdout + help_result.stderr).decode(errors='replace')
        (work/'firecracker-help.txt').write_text(help_text[:20000])
        flags = ('--api-sock','--mmds-size-limit','--http-api-max-payload-size')
        result['firecracker_cli'] = {'exit_code':help_result.returncode, 'required_flags':{x:x in help_text for x in flags}}
        need(help_result.returncode == 0 and all(x in help_text for x in flags), 'Installed FC CLI differs; do not apply config change')
        result['old_example_socket_bytes'] = len(str(BASE/'state/firecracker-work/agentenv-fc-wIpjK3/firecracker.socket').encode())
        result['new_example_socket_bytes'] = len(str(SHORT/'agentenv-fc-XXXXXX/firecracker.socket').encode())
        need(result['new_example_socket_bytes'] < 100, 'New socket path still too long')
        result['settings'] = {'work_dir':str(SHORT),'serial_dir':str(SERIAL),'log_level':'Info'}
        result['old_config_sha256'] = hashlib.sha256(raw).hexdigest()
        result['new_config_sha256'] = hashlib.sha256(updated).hexdigest()
        (work/'runtime-before.toml').write_bytes(raw)
        (work/'runtime-proposed.toml').write_bytes(updated)
        result['status'] = 'A_ORIGINAL_FC_PATH_FIX_PREPARED_NO_CHANGE'
        if args.apply_reviewed:
            need(state() == before_state, 'Unit changed while preparing')
            empty_runtime()
            need(read(CONFIG) == raw, 'Config changed concurrently')
            for path in (SHORT, SERIAL):
                need(path.resolve() == path and path.is_relative_to(ROOT), 'Redirected output path')
                if path.exists():
                    need(path.stat().st_uid == 1204 and path.is_dir(), 'Unexpected output directory')
                else:
                    path.mkdir(parents=True, mode=0o700)
            temp = CONFIG.with_name('runtime-fc-path-' + work.name + '.tmp')
            with temp.open('xb') as f:
                f.write(updated);f.flush();os.fsync(f.fileno())
            need(read(CONFIG) == raw, 'Config changed before replacement')
            os.replace(temp, CONFIG)
            result.update(configuration_modified=True, status='A_ORIGINAL_FC_PATH_CONFIG_APPLIED_RESTART_REQUIRED')
            (work/'restart-review.txt').write_text(root_restart_text(result['new_config_sha256'],before_state['MainPID'],before_state['start_ticks']))
            marker_temp = work/'path-fix-marker.json'
            marker_temp.write_text(json.dumps(result,indent=2)+'\n')
            os.replace(marker_temp,MARKER)
    except Exception as e:
        result.update(status='STOPPED_A_ORIGINAL_FC_PATH_FIX', error_type=type(e).__name__,
                      error=str(e) if type(e) is RuntimeError else 'See failure type; no service restart performed')
    (work/'return.json').write_text(json.dumps(result,indent=2)+'\n')
    print('BEGIN_RETURN_REPORT');print(json.dumps(result,indent=2));print('END_RETURN_REPORT')
    if result['status']=='A_ORIGINAL_FC_PATH_CONFIG_APPLIED_RESTART_REQUIRED':
        print('BEGIN_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY')
        print((work/'restart-review.txt').read_text())
        print('END_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY')
    return 1 if result['status'].startswith('STOPPED') else 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as e:
        print(json.dumps({'status':'STOPPED_ENTRY','type':type(e).__name__}))
        raise SystemExit(1)
